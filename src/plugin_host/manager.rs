//! Plugin manager: registration, lifecycle, admission, dispatch, prompts,
//! failure isolation, and shutdown.
//!
//! The manager is the single owner of plugin lifecycle transitions. It never
//! holds a lock while plugin code runs and has no timers or deadlines of its
//! own: every wait ends on observed completion, explicit cancellation, or
//! explicit escalation. Hosts that want time limits apply them by calling
//! [`PluginManager::begin_shutdown`] and [`PluginManager::escalate`] under
//! their own policy.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::runtime::Handle;
use tokio::sync::{oneshot, watch, Notify};

use super::lifecycle::{
    bounded_text, ActivationError, DispatchReport, FailureCause, FailurePhase, HostPhase,
    LifecycleError, PluginFailure, PluginHostOptions, PluginRegistrationError, PluginStartOutcome,
    PluginState, PluginStopReport, PromptError, QuiescePhase, Rejection, ShutdownMode,
    ShutdownReport, StartPolicy, StartReport, StartResult, StopResult,
};
use super::runtime::{
    CallError, Completion, HostServices, JobId, JobResult, NativeRegistration, PluginAdapter,
    PluginDescriptor, PluginEndpoint, RuntimeSource,
};
use super::{Plugin, PluginContext};
use crate::config::ConfigDefaults;
use crate::events::dispatcher::{self, EventDispatcher};
use crate::events::model::{LogEvent, LogLevel, PluginEvent, SystemEvent};
use crate::network::delivery::{
    DeliveryFailureReason, DeliveryOptions, DeliveryOutcome, DeliveryRuntime,
};
use crate::network::message::{Message, MessageType};

/// Registration interface for statically linked (CAL) plugins.
pub trait PluginRegistrar {
    /// Register a plugin that runs on the host runtime. Registration fails for
    /// invalid or duplicate IDs, duplicate prompt prefixes, conflicting
    /// configuration defaults, or after startup has begun.
    fn register_handler(&mut self, plugin: Box<dyn Plugin>) -> Result<(), PluginRegistrationError>;
}

/// IDs, prompt prefixes, and configuration defaults claimed by registered plugins.
#[derive(Clone, Default)]
pub(crate) struct RegistrationIndex {
    ids: HashSet<String>,
    prompt_prefixes: HashSet<String>,
    defaults: Vec<(String, ConfigDefaults)>,
}

impl RegistrationIndex {
    pub(crate) fn check(
        &self,
        descriptor: &PluginDescriptor,
    ) -> Result<(), PluginRegistrationError> {
        if let Err(error) = PluginContext::validate_plugin_id(&descriptor.id) {
            return Err(PluginRegistrationError::InvalidId {
                plugin_id: descriptor.id.clone(),
                reason: error.to_string(),
            });
        }
        if self.ids.contains(&descriptor.id) {
            return Err(PluginRegistrationError::DuplicateId {
                plugin_id: descriptor.id.clone(),
            });
        }
        if let Some(prefix) = &descriptor.prompt_prefix {
            if self.prompt_prefixes.contains(prefix) {
                return Err(PluginRegistrationError::DuplicatePromptPrefix {
                    plugin_id: descriptor.id.clone(),
                    prefix: prefix.clone(),
                });
            }
        }
        if descriptor.task_limit == 0 {
            return Err(PluginRegistrationError::InvalidRuntimeConfig(format!(
                "plugin '{}' declares a managed task limit of 0",
                descriptor.id
            )));
        }
        if let Some(defaults) = &descriptor.defaults {
            for (other_plugin_id, other) in &self.defaults {
                if let Some(field) = conflicting_field(defaults, other) {
                    return Err(PluginRegistrationError::ConflictingDefaults {
                        plugin_id: descriptor.id.clone(),
                        other_plugin_id: other_plugin_id.clone(),
                        field,
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn insert(&mut self, descriptor: &PluginDescriptor) {
        self.ids.insert(descriptor.id.clone());
        if let Some(prefix) = &descriptor.prompt_prefix {
            self.prompt_prefixes.insert(prefix.clone());
        }
        if let Some(defaults) = &descriptor.defaults {
            self.defaults
                .push((descriptor.id.clone(), defaults.clone()));
        }
    }
}

/// Single-valued default fields that two plugins set to different values.
/// `bootstrap_nodes_extend` is additive and never conflicts.
fn conflicting_field(a: &ConfigDefaults, b: &ConfigDefaults) -> Option<&'static str> {
    fn differs<T: Debug>(a: &Option<T>, b: &Option<T>) -> bool {
        match (a, b) {
            (Some(a), Some(b)) => format!("{a:?}") != format!("{b:?}"),
            _ => false,
        }
    }
    if differs(&a.port, &b.port) {
        return Some("port");
    }
    if differs(&a.realm, &b.realm) {
        return Some("realm");
    }
    if differs(&a.app_name, &b.app_name) {
        return Some("app_name");
    }
    if differs(&a.encryption, &b.encryption) {
        return Some("encryption");
    }
    if differs(&a.bootstrap_nodes, &b.bootstrap_nodes) {
        return Some("bootstrap_nodes");
    }
    if differs(&a.logging, &b.logging) {
        return Some("logging");
    }
    if differs(&a.node, &b.node) {
        return Some("node");
    }
    if differs(&a.discovery, &b.discovery) {
        return Some("discovery");
    }
    None
}

/// Bounded FIFO inbox with a single consumer.
struct Inbox {
    state: Mutex<InboxState>,
    notify: Notify,
}

struct InboxState {
    capacity: usize,
    queue: VecDeque<Message>,
    in_progress: bool,
    accepting: bool,
    gate_open: bool,
    closed: Option<Rejection>,
    drain: bool,
    discarded: u64,
    overloaded: bool,
    rejected_while_overloaded: u64,
}

enum Admission {
    Admitted {
        recovered_after: Option<u64>,
    },
    Rejected {
        reason: Rejection,
        entered_overload: bool,
    },
}

impl Inbox {
    fn new() -> Self {
        Self {
            state: Mutex::new(InboxState {
                capacity: 1,
                queue: VecDeque::new(),
                in_progress: false,
                accepting: false,
                gate_open: false,
                closed: None,
                drain: false,
                discarded: 0,
                overloaded: false,
                rejected_while_overloaded: 0,
            }),
            notify: Notify::new(),
        }
    }

    /// Start admitting messages. They are consumed only after `open_gate`.
    fn open_admission(&self, capacity: usize) {
        let mut state = self.state.lock();
        state.capacity = capacity;
        state.accepting = true;
    }

    fn open_gate(&self) {
        self.state.lock().gate_open = true;
        self.notify.notify_one();
    }

    fn admit(&self, message: &Message) -> Admission {
        let mut state = self.state.lock();
        if let Some(reason) = state.closed {
            return Admission::Rejected {
                reason,
                entered_overload: false,
            };
        }
        if !state.accepting {
            return Admission::Rejected {
                reason: Rejection::NotReady,
                entered_overload: false,
            };
        }
        if state.queue.len() + usize::from(state.in_progress) >= state.capacity {
            state.rejected_while_overloaded += 1;
            let entered_overload = !state.overloaded;
            state.overloaded = true;
            return Admission::Rejected {
                reason: Rejection::Overloaded,
                entered_overload,
            };
        }
        state.queue.push_back(message.clone());
        let recovered_after = if state.overloaded {
            state.overloaded = false;
            Some(std::mem::take(&mut state.rejected_while_overloaded))
        } else {
            None
        };
        drop(state);
        self.notify.notify_one();
        Admission::Admitted { recovered_after }
    }

    /// Refuse new messages. With `drain` (only honored after activation) the
    /// consumer finishes queued messages; otherwise they are discarded.
    fn close(&self, drain: bool, reason: Rejection) {
        let mut state = self.state.lock();
        if state.closed.is_none() {
            state.closed = Some(reason);
            state.drain = drain && state.gate_open;
        } else if !drain {
            state.drain = false;
        }
        if !state.drain {
            state.discarded += state.queue.len() as u64;
            state.queue.clear();
        }
        drop(state);
        self.notify.notify_one();
    }

    async fn next(&self) -> Option<Message> {
        loop {
            {
                let mut state = self.state.lock();
                if state.closed.is_some() && !state.drain {
                    return None;
                }
                if state.gate_open {
                    if let Some(message) = state.queue.pop_front() {
                        state.in_progress = true;
                        return Some(message);
                    }
                }
                if state.closed.is_some() {
                    return None;
                }
            }
            self.notify.notified().await;
        }
    }

    fn finish(&self) {
        self.state.lock().in_progress = false;
    }

    fn discarded(&self) -> u64 {
        self.state.lock().discarded
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobKind {
    Start,
    Message,
    Prompt,
    Stop,
}

struct JobEntry {
    kind: JobKind,
    started: bool,
    cancel_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cleanup {
    Pending,
    Owned,
    Done,
}

struct SlotState {
    state: PluginState,
    start_entered: bool,
    failure: Option<PluginFailure>,
    acknowledged: bool,
    cleanup: Cleanup,
    stop: Option<StopResult>,
    jobs: HashMap<JobId, JobEntry>,
    aborted_tasks: usize,
}

struct PluginSlot {
    index: usize,
    id: String,
    subscriptions: Option<Vec<String>>,
    prompt_prefix: Option<String>,
    library: Option<usize>,
    endpoint: Box<dyn PluginEndpoint>,
    inbox: Inbox,
    state: Mutex<SlotState>,
    jobs_live: watch::Sender<usize>,
    consumer_done: watch::Sender<bool>,
    cleanup_done: watch::Sender<bool>,
}

impl PluginSlot {
    fn accepts(&self, message: &Message) -> bool {
        match &message.msg_type {
            MessageType::Extension { kind } => match &self.subscriptions {
                Some(kinds) => kinds.iter().any(|subscribed| subscribed == kind),
                None => true,
            },
            _ => true,
        }
    }

    fn begin_job(self: &Arc<Self>, job: JobId, kind: JobKind) -> JobTracker {
        self.state.lock().jobs.insert(
            job,
            JobEntry {
                kind,
                started: false,
                cancel_requested: false,
            },
        );
        self.jobs_live.send_modify(|live| *live += 1);
        JobTracker {
            slot: self.clone(),
            job,
        }
    }

    /// Mark a job as handed to the endpoint. Returns whether cancellation was
    /// requested before the endpoint could act on it.
    fn job_started(&self, job: JobId) -> bool {
        let mut state = self.state.lock();
        match state.jobs.get_mut(&job) {
            Some(entry) => {
                entry.started = true;
                entry.cancel_requested
            }
            None => false,
        }
    }

    /// Request cancellation of live jobs of the given kinds. Stop jobs are
    /// never cancelled implicitly: a running cleanup is joined, not aborted.
    fn cancel_jobs(&self, kinds: &[JobKind]) {
        let started: Vec<JobId> = {
            let mut state = self.state.lock();
            state
                .jobs
                .iter_mut()
                .filter(|(_, entry)| kinds.contains(&entry.kind))
                .filter_map(|(job, entry)| {
                    if entry.started {
                        Some(*job)
                    } else {
                        entry.cancel_requested = true;
                        None
                    }
                })
                .collect()
        };
        for job in started {
            self.endpoint.cancel(job);
        }
    }
}

/// Accounts for one callback job until its completion sink runs or is dropped.
struct JobTracker {
    slot: Arc<PluginSlot>,
    job: JobId,
}

impl Drop for JobTracker {
    fn drop(&mut self) {
        self.slot.state.lock().jobs.remove(&self.job);
        self.slot
            .jobs_live
            .send_modify(|live| *live = live.saturating_sub(1));
    }
}

/// Requests cancellation of a job if its host-side waiter is dropped. The job
/// stays tracked until its completion is observed.
struct CancelOnDrop {
    slot: Arc<PluginSlot>,
    job: JobId,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.slot.endpoint.cancel(self.job);
        }
    }
}

enum Invoked<T> {
    Completed(T),
    Panicked(String),
    Cancelled,
    Unavailable(String),
}

async fn invoke<T, C>(slot: &Arc<PluginSlot>, tracker: JobTracker, call: C) -> Invoked<T>
where
    T: Send + 'static,
    C: FnOnce(&dyn PluginEndpoint, Completion<JobResult<T>>) -> Result<(), CallError>,
{
    let job = tracker.job;
    let (tx, rx) = oneshot::channel();
    let done: Completion<JobResult<T>> = Box::new(move |result| {
        let _ = tx.send(result);
        drop(tracker);
    });
    if let Err(error) = call(slot.endpoint.as_ref(), done) {
        return match error {
            CallError::Panicked(message) => Invoked::Panicked(message),
            CallError::Unavailable(reason) => Invoked::Unavailable(reason),
        };
    }
    if slot.job_started(job) {
        slot.endpoint.cancel(job);
    }
    let mut guard = CancelOnDrop {
        slot: slot.clone(),
        job,
        armed: true,
    };
    let result = rx.await;
    guard.armed = false;
    match result {
        Ok(JobResult::Completed(value)) => Invoked::Completed(value),
        Ok(JobResult::Panicked(message)) => Invoked::Panicked(message),
        Ok(JobResult::Cancelled) => Invoked::Cancelled,
        Err(_) => Invoked::Unavailable("plugin runtime dropped the job".to_string()),
    }
}

async fn wait_true(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_zero(mut rx: watch::Receiver<usize>) {
    loop {
        if *rx.borrow_and_update() == 0 {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_report<T: Clone>(rx: &mut watch::Receiver<Option<T>>) -> Option<T> {
    loop {
        if let Some(value) = rx.borrow_and_update().clone() {
            return Some(value);
        }
        if rx.changed().await.is_err() {
            return rx.borrow().clone();
        }
    }
}

/// Run `future` unless escalation is (or becomes) requested. `None` means the
/// host stopped waiting; the work was not observed to complete.
async fn until<F: Future>(escalation: &watch::Receiver<bool>, future: F) -> Option<F::Output> {
    let escalated = wait_true(escalation.clone());
    tokio::select! {
        biased;
        _ = escalated => None,
        output = future => Some(output),
    }
}

fn plugin_event(level: LogLevel, plugin_id: &str, action: &str, detail: String) {
    let mut meta = dispatcher::meta("plugin_host", level);
    meta.corr_id = Some(dispatcher::correlation_id());
    dispatcher::emit(LogEvent::Plugin(PluginEvent {
        meta,
        plugin: plugin_id.to_string(),
        action: action.to_string(),
        detail: Some(detail),
    }));
}

fn system_event(level: LogLevel, action: &str, detail: String) {
    let mut meta = dispatcher::meta("plugin_host", level);
    meta.corr_id = Some(dispatcher::correlation_id());
    dispatcher::emit(LogEvent::System(SystemEvent {
        meta,
        action: action.to_string(),
        detail: Some(detail),
    }));
}

fn waiting_event(plugin_id: &str, phase: QuiescePhase) {
    plugin_event(
        LogLevel::Info,
        plugin_id,
        "plugin_waiting",
        format!("phase={}", phase.as_str()),
    );
}

fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

/// Selected prompt plugin. Holding a target does not keep the plugin
/// executable; every dispatch is checked against the current lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptTarget {
    index: usize,
    plugin_id: String,
    prefix: String,
}

impl PromptTarget {
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

/// Receives every plugin failure, including those recorded before subscribing.
///
/// Failures are retained by the manager, so the number of notifications is
/// bounded by the number of plugins. This path is independent of event sinks.
pub struct PluginFailureSubscription {
    rx: watch::Receiver<Vec<PluginFailure>>,
    next: usize,
}

impl PluginFailureSubscription {
    /// Next failure, or `None` once the manager has been dropped.
    pub async fn recv(&mut self) -> Option<PluginFailure> {
        loop {
            {
                let failures = self.rx.borrow_and_update();
                if self.next < failures.len() {
                    let failure = failures[self.next].clone();
                    self.next += 1;
                    return Some(failure);
                }
            }
            if self.rx.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// Waits for the outcome of a shutdown that has already begun. Dropping the
/// handle does not abandon the shutdown.
pub struct ShutdownHandle {
    rx: watch::Receiver<Option<ShutdownReport>>,
}

impl ShutdownHandle {
    pub async fn wait(mut self) -> Result<ShutdownReport, LifecycleError> {
        wait_report(&mut self.rx)
            .await
            .ok_or(LifecycleError::Interrupted)
    }
}

struct NativeLibrary {
    path: PathBuf,
    slots: Vec<usize>,
}

struct Lifecycle {
    phase: HostPhase,
    outbound_open: bool,
    start: Option<watch::Receiver<Option<StartReport>>>,
    shutdown: Option<watch::Receiver<Option<ShutdownReport>>>,
    start_order: Vec<usize>,
}

enum FailureAction {
    Isolate,
    CancelStart,
    CancelWork,
    None,
}

/// Owns registered plugins and their lifecycle.
///
/// Typical host sequence: register plugins, set the final context, wrap the
/// manager in an `Arc`, call [`start_all`](Self::start_all), bind required
/// listeners, call [`activate`](Self::activate), and finally
/// [`shutdown`](Self::shutdown). Hosts must call `shutdown`; dropping the
/// manager only closes inboxes.
pub struct PluginManager {
    plugins: Vec<Arc<PluginSlot>>,
    prompt_map: HashMap<String, usize>,
    index: RegistrationIndex,
    libraries: Vec<NativeLibrary>,
    /// Host base context. Plugin-bound contexts are derived from it when
    /// startup begins, so it must hold the final configuration by then.
    pub context: Option<PluginContext>,
    options: PluginHostOptions,
    host_runtime: Arc<OnceLock<Handle>>,
    self_ref: OnceLock<Weak<PluginManager>>,
    lifecycle: Mutex<Lifecycle>,
    failures: watch::Sender<Vec<PluginFailure>>,
    escalation: watch::Sender<bool>,
    shutdown_signal: watch::Sender<bool>,
    next_job: Arc<AtomicU64>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        for slot in &self.plugins {
            slot.inbox.close(false, Rejection::Unavailable);
        }
    }
}

impl PluginRegistrar for PluginManager {
    fn register_handler(&mut self, plugin: Box<dyn Plugin>) -> Result<(), PluginRegistrationError> {
        if !self.registration_open() {
            return Err(PluginRegistrationError::RegistrationClosed);
        }
        let plugin: Arc<dyn Plugin> = Arc::from(plugin);
        let descriptor = PluginDescriptor::read(plugin.as_ref());
        self.index.check(&descriptor)?;
        let endpoint = PluginAdapter::new(
            plugin,
            &descriptor,
            RuntimeSource::Host(self.host_runtime.clone()),
        );
        println!("🔧 Registering plugin: {}.", descriptor.id);
        self.push_slot(descriptor, Box::new(endpoint), None);
        Ok(())
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            prompt_map: HashMap::new(),
            index: RegistrationIndex::default(),
            libraries: Vec::new(),
            context: None,
            options: PluginHostOptions::default(),
            host_runtime: Arc::new(OnceLock::new()),
            self_ref: OnceLock::new(),
            lifecycle: Mutex::new(Lifecycle {
                phase: HostPhase::Registering,
                outbound_open: false,
                start: None,
                shutdown: None,
                start_order: Vec::new(),
            }),
            failures: watch::channel(Vec::new()).0,
            escalation: watch::channel(false).0,
            shutdown_signal: watch::channel(false).0,
            next_job: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn with_context(context: PluginContext) -> Self {
        let mut manager = Self::new();
        manager.context = Some(context);
        manager
    }

    /// Replace the host base context, for example after plugin-supplied
    /// configuration defaults have been applied.
    pub fn set_context(&mut self, context: PluginContext) {
        self.context = Some(context);
    }

    pub fn options(&self) -> &PluginHostOptions {
        &self.options
    }

    /// Set host options. Only allowed before startup begins.
    pub fn set_options(&mut self, options: PluginHostOptions) -> Result<(), LifecycleError> {
        options.validate()?;
        let phase = self.phase();
        if phase != HostPhase::Registering {
            return Err(LifecycleError::InvalidState {
                phase,
                operation: "change host options",
            });
        }
        self.options = options;
        Ok(())
    }

    pub fn phase(&self) -> HostPhase {
        self.lifecycle.lock().phase
    }

    pub(crate) fn registration_open(&self) -> bool {
        self.phase() == HostPhase::Registering
    }

    pub(crate) fn registration_index(&self) -> &RegistrationIndex {
        &self.index
    }

    fn push_slot(
        &mut self,
        descriptor: PluginDescriptor,
        endpoint: Box<dyn PluginEndpoint>,
        library: Option<usize>,
    ) -> usize {
        self.index.insert(&descriptor);
        let index = self.plugins.len();
        if let Some(prefix) = &descriptor.prompt_prefix {
            self.prompt_map.insert(prefix.clone(), index);
        }
        self.plugins.push(Arc::new(PluginSlot {
            index,
            id: descriptor.id,
            subscriptions: descriptor.subscriptions,
            prompt_prefix: descriptor.prompt_prefix,
            library,
            endpoint,
            inbox: Inbox::new(),
            state: Mutex::new(SlotState {
                state: PluginState::Registered,
                start_entered: false,
                failure: None,
                acknowledged: false,
                cleanup: Cleanup::Pending,
                stop: None,
                jobs: HashMap::new(),
                aborted_tasks: 0,
            }),
            jobs_live: watch::channel(0).0,
            consumer_done: watch::channel(true).0,
            cleanup_done: watch::channel(false).0,
        }));
        index
    }

    /// Commit a native library's staged registrations as one unit.
    pub(crate) fn commit_native(
        &mut self,
        path: &Path,
        staged: Vec<NativeRegistration>,
    ) -> Result<Vec<String>, PluginRegistrationError> {
        if !self.registration_open() {
            return Err(PluginRegistrationError::RegistrationClosed);
        }
        let mut check = self.index.clone();
        for registration in &staged {
            check.check(&registration.descriptor)?;
            check.insert(&registration.descriptor);
        }
        let library = self.libraries.len();
        let mut slots = Vec::with_capacity(staged.len());
        let mut ids = Vec::with_capacity(staged.len());
        for registration in staged {
            ids.push(registration.descriptor.id.clone());
            slots.push(self.push_slot(
                registration.descriptor,
                registration.endpoint,
                Some(library),
            ));
        }
        self.libraries.push(NativeLibrary {
            path: path.to_path_buf(),
            slots,
        });
        Ok(ids)
    }

    /// Paths of native libraries with registered handlers, in load order.
    pub fn native_libraries(&self) -> Vec<PathBuf> {
        self.libraries
            .iter()
            .map(|library| library.path.clone())
            .collect()
    }

    /// Registered plugin IDs in registration order.
    pub fn plugin_ids(&self) -> Vec<String> {
        self.plugins.iter().map(|slot| slot.id.clone()).collect()
    }

    pub fn plugin_state(&self, plugin_id: &str) -> Option<PluginState> {
        self.plugins
            .iter()
            .find(|slot| slot.id == plugin_id)
            .map(|slot| slot.state.lock().state)
    }

    /// Every failure recorded so far, in order.
    pub fn failures(&self) -> Vec<PluginFailure> {
        self.failures.borrow().clone()
    }

    pub fn subscribe_failures(&self) -> PluginFailureSubscription {
        PluginFailureSubscription {
            rx: self.failures.subscribe(),
            next: 0,
        }
    }

    pub fn all_prompt_prefixes(&self) -> Vec<String> {
        let mut prefixes: Vec<String> = self.prompt_map.keys().cloned().collect();
        prefixes.sort();
        prefixes
    }

    /// Resolve a prompt prefix to its plugin. Execution goes through
    /// [`dispatch_prompt`](Self::dispatch_prompt).
    pub fn resolve_prompt(&self, prefix: &str) -> Option<PromptTarget> {
        let index = *self.prompt_map.get(prefix)?;
        let slot = self.plugins.get(index)?;
        Some(PromptTarget {
            index,
            plugin_id: slot.id.clone(),
            prefix: slot.prompt_prefix.clone().unwrap_or_default(),
        })
    }

    /// Merge configuration defaults from all plugins. Conflicting single-valued
    /// fields are rejected at registration; `bootstrap_nodes_extend` lists are
    /// concatenated without duplicates.
    pub fn collect_config_defaults(&self) -> ConfigDefaults {
        let mut merged = ConfigDefaults::default();
        for (_, defaults) in &self.index.defaults {
            let defaults = defaults.clone();
            merged.port = merged.port.or(defaults.port);
            merged.realm = merged.realm.or(defaults.realm);
            merged.app_name = merged.app_name.or(defaults.app_name);
            merged.encryption = merged.encryption.or(defaults.encryption);
            merged.bootstrap_nodes = merged.bootstrap_nodes.or(defaults.bootstrap_nodes);
            merged.logging = merged.logging.or(defaults.logging);
            merged.node = merged.node.or(defaults.node);
            merged.discovery = merged.discovery.or(defaults.discovery);
            if let Some(extra) = defaults.bootstrap_nodes_extend {
                let list = merged.bootstrap_nodes_extend.get_or_insert_with(Vec::new);
                for entry in extra {
                    if !list.contains(&entry) {
                        list.push(entry);
                    }
                }
            }
        }
        merged
    }

    fn next_job(&self) -> JobId {
        self.next_job.fetch_add(1, Ordering::Relaxed)
    }

    /// Start every registered plugin in registration order.
    ///
    /// Each plugin's `on_start` runs to completion before the next one starts;
    /// there is no startup deadline. A plugin that fails is rolled back on its
    /// own and reported. Repeated or concurrent calls join the same startup and
    /// return its report. Cancelling the returned future does not abandon
    /// startup.
    pub async fn start_all(
        self: &Arc<Self>,
        policy: StartPolicy,
    ) -> Result<StartReport, LifecycleError> {
        let mut rx = {
            let mut lifecycle = self.lifecycle.lock();
            match lifecycle.phase {
                HostPhase::Registering => {
                    self.options.validate()?;
                    if !self.plugins.is_empty() && self.context.is_none() {
                        return Err(LifecycleError::MissingContext);
                    }
                    let handle = Handle::try_current().map_err(|_| LifecycleError::NoRuntime)?;
                    let _ = self.host_runtime.set(handle.clone());
                    let _ = self.self_ref.set(Arc::downgrade(self));
                    lifecycle.phase = HostPhase::Starting;
                    let (tx, rx) = watch::channel(None);
                    lifecycle.start = Some(rx.clone());
                    let manager = self.clone();
                    handle.spawn(async move { manager.run_start(policy, tx).await });
                    rx
                }
                HostPhase::Stopping | HostPhase::Stopped => {
                    return Err(LifecycleError::InvalidState {
                        phase: lifecycle.phase,
                        operation: "start plugins",
                    })
                }
                _ => lifecycle.start.clone().ok_or(LifecycleError::Interrupted)?,
            }
        };
        wait_report(&mut rx)
            .await
            .ok_or(LifecycleError::Interrupted)
    }

    fn services_for(&self, slot: &Arc<PluginSlot>, handle: &Handle) -> Arc<dyn HostServices> {
        Arc::new(PluginHostServices {
            manager: self.self_ref.get().cloned().unwrap_or_default(),
            index: slot.index,
            plugin_id: slot.id.clone(),
            handle: handle.clone(),
        })
    }

    fn spawn_consumer(self: &Arc<Self>, slot: &Arc<PluginSlot>, handle: &Handle) {
        slot.consumer_done.send_replace(false);
        let manager = Arc::downgrade(self);
        let slot = slot.clone();
        let next_job = self.next_job.clone();
        handle.spawn(run_consumer(manager, slot, next_job));
    }

    async fn run_start(
        self: Arc<Self>,
        policy: StartPolicy,
        tx: watch::Sender<Option<StartReport>>,
    ) {
        let handle = self
            .host_runtime
            .get()
            .cloned()
            .expect("host runtime is bound before startup");
        let shutdown = self.shutdown_signal.subscribe();
        let escalation = self.escalation.subscribe();
        let mut outcomes = Vec::with_capacity(self.plugins.len());
        let mut halted = false;

        for slot in &self.plugins {
            if halted || *shutdown.borrow() {
                outcomes.push(PluginStartOutcome {
                    plugin_id: slot.id.clone(),
                    result: StartResult::NotStarted,
                    elapsed: None,
                });
                continue;
            }
            let Some(base) = self.context.as_ref() else {
                break;
            };
            let ctx = base.bind(
                &slot.id,
                self.services_for(slot, &handle),
                slot.library.is_some(),
            );
            {
                let mut state = slot.state.lock();
                state.state = PluginState::Starting;
                state.start_entered = true;
            }
            self.lifecycle.lock().start_order.push(slot.index);
            slot.inbox.open_admission(self.options.inbox_capacity);
            self.spawn_consumer(slot, &handle);

            plugin_event(
                LogLevel::Info,
                &slot.id,
                "plugin_starting",
                "phase=start".into(),
            );
            waiting_event(&slot.id, QuiescePhase::Start);
            let started_at = Instant::now();
            let job = self.next_job();
            let tracker = slot.begin_job(job, JobKind::Start);
            let invocation = invoke(slot, tracker, |endpoint, done| {
                endpoint.start(job, ctx, done)
            });
            tokio::pin!(invocation);
            let observed = tokio::select! {
                result = &mut invocation => Some(result),
                _ = wait_true(shutdown.clone()) => {
                    slot.cancel_jobs(&[JobKind::Start]);
                    until(&escalation, &mut invocation).await
                }
            };
            let elapsed = started_at.elapsed();

            let Some(result) = observed else {
                // Escalated while waiting on a cancelled start hook. The hook
                // was not observed to end; record that before the report,
                // which shutdown would otherwise take as proof that start
                // hooks have returned.
                slot.state.lock().stop = Some(StopResult::FailedToQuiesce(QuiescePhase::Start));
                outcomes.push(PluginStartOutcome {
                    plugin_id: slot.id.clone(),
                    result: StartResult::Cancelled,
                    elapsed: Some(elapsed),
                });
                halted = true;
                continue;
            };

            let recorded = slot.state.lock().failure.clone();
            let result = match (recorded, result) {
                (Some(failure), _) => StartResult::Failed(failure),
                (None, Invoked::Completed(Ok(()))) => {
                    let mut state = slot.state.lock();
                    if state.failure.is_none() {
                        state.state = PluginState::Running;
                        StartResult::Started
                    } else {
                        StartResult::Failed(state.failure.clone().expect("checked above"))
                    }
                }
                (None, Invoked::Cancelled) if *shutdown.borrow() => StartResult::Cancelled,
                (None, other) => {
                    let cause = match other {
                        Invoked::Completed(Err(error)) => {
                            FailureCause::Error(bounded_text(error.message()))
                        }
                        Invoked::Panicked(message) => FailureCause::Panic(message),
                        Invoked::Cancelled => FailureCause::Error("start was cancelled".into()),
                        Invoked::Unavailable(reason) => FailureCause::Unavailable(reason),
                        Invoked::Completed(Ok(())) => unreachable!("handled above"),
                    };
                    StartResult::Failed(self.record_failure(slot, FailurePhase::Start, cause))
                }
            };

            match &result {
                StartResult::Started => plugin_event(
                    LogLevel::Info,
                    &slot.id,
                    "plugin_started",
                    format!("phase=start result=ok elapsed_ms={}", elapsed.as_millis()),
                ),
                StartResult::Failed(failure) => {
                    plugin_event(
                        LogLevel::Error,
                        &slot.id,
                        "plugin_start_failed",
                        format!(
                            "phase=start result={} elapsed_ms={}",
                            failure.cause.category(),
                            elapsed.as_millis()
                        ),
                    );
                    // The start hook was entered, so roll this plugin back now.
                    if self.isolate(slot).await {
                        slot.cleanup_done.send_replace(true);
                    }
                    if policy == StartPolicy::StopOnFirstFailure {
                        halted = true;
                    }
                }
                StartResult::Cancelled | StartResult::NotStarted => {}
            }
            outcomes.push(PluginStartOutcome {
                plugin_id: slot.id.clone(),
                result,
                elapsed: Some(elapsed),
            });
        }

        {
            let mut lifecycle = self.lifecycle.lock();
            if lifecycle.phase == HostPhase::Starting {
                lifecycle.phase = HostPhase::Ready;
            }
        }
        // Release this task's manager reference before waiters observe the
        // result, so the host's own references decide the manager's lifetime.
        drop(self);
        let _ = tx.send(Some(StartReport { outcomes }));
    }

    /// Acknowledge a failed plugin so the host can activate without it. The
    /// plugin stays failed and its messages receive an unavailable outcome.
    pub fn acknowledge_failure(&self, plugin_id: &str) -> Result<(), LifecycleError> {
        let slot = self
            .plugins
            .iter()
            .find(|slot| slot.id == plugin_id)
            .ok_or_else(|| LifecycleError::UnknownPlugin(plugin_id.to_string()))?;
        // Lock order is lifecycle before slot state.
        let phase = self.phase();
        let mut state = slot.state.lock();
        if state.failure.is_none() {
            return Err(LifecycleError::InvalidState {
                phase,
                operation: "acknowledge a plugin that has not failed",
            });
        }
        state.acknowledged = true;
        Ok(())
    }

    /// Open normal plugin admission. Requires every start hook to have
    /// returned and every failure to be acknowledged. Call it after required
    /// local listeners are bound.
    pub fn activate(&self) -> Result<(), ActivationError> {
        let running: Vec<Arc<PluginSlot>> = {
            let mut lifecycle = self.lifecycle.lock();
            if lifecycle.phase != HostPhase::Ready {
                return Err(ActivationError::InvalidState(lifecycle.phase));
            }
            let unacknowledged: Vec<String> = self
                .plugins
                .iter()
                .filter(|slot| {
                    let state = slot.state.lock();
                    state.failure.is_some() && !state.acknowledged
                })
                .map(|slot| slot.id.clone())
                .collect();
            if !unacknowledged.is_empty() {
                return Err(ActivationError::UnacknowledgedFailures(unacknowledged));
            }
            lifecycle.phase = HostPhase::Active;
            lifecycle.outbound_open = true;
            self.plugins
                .iter()
                .filter(|slot| slot.state.lock().state == PluginState::Running)
                .cloned()
                .collect()
        };
        for slot in &running {
            slot.inbox.open_gate();
            slot.endpoint.activate();
        }
        system_event(
            LogLevel::Info,
            "plugins_activated",
            format!("running={}", running.len()),
        );
        Ok(())
    }

    /// Offer a message to every subscribed plugin without waiting for it to be
    /// handled. Each plugin has a bounded FIFO inbox; a full inbox rejects the
    /// message with an overload outcome while other plugins continue.
    pub fn dispatch_message(&self, message: &Message) -> DispatchReport {
        let mut report = DispatchReport::default();
        for slot in &self.plugins {
            if !slot.accepts(message) {
                continue;
            }
            match slot.inbox.admit(message) {
                Admission::Admitted { recovered_after } => {
                    report.admitted += 1;
                    if let Some(rejected) = recovered_after {
                        plugin_event(
                            LogLevel::Info,
                            &slot.id,
                            "plugin_admission_rejected",
                            format!("state=recovered rejected={rejected}"),
                        );
                    }
                }
                Admission::Rejected {
                    reason,
                    entered_overload,
                } => {
                    if entered_overload {
                        plugin_event(
                            LogLevel::Warn,
                            &slot.id,
                            "plugin_admission_rejected",
                            "state=overloaded".into(),
                        );
                    }
                    report.rejected.push((slot.id.clone(), reason));
                }
            }
        }
        report
    }

    /// Run a plugin's `on_prompt` through managed admission. No deadline
    /// applies; dropping the returned future requests cancellation, and the
    /// call stays accounted for until its completion is observed.
    pub async fn dispatch_prompt(
        self: &Arc<Self>,
        target: &PromptTarget,
        input: &str,
    ) -> Result<Option<String>, PromptError> {
        let slot = self
            .plugins
            .get(target.index)
            .filter(|slot| slot.id == target.plugin_id)
            .cloned()
            .ok_or(PromptError::Rejected(Rejection::Unavailable))?;
        let job = self.next_job();
        let tracker = {
            let lifecycle = self.lifecycle.lock();
            match lifecycle.phase {
                HostPhase::Active => {}
                HostPhase::Stopping | HostPhase::Stopped => {
                    return Err(PromptError::Rejected(Rejection::Stopping))
                }
                _ => return Err(PromptError::Rejected(Rejection::NotReady)),
            }
            {
                let state = slot.state.lock();
                match state.state {
                    PluginState::Running => {}
                    PluginState::Failed => {
                        return Err(PromptError::Rejected(Rejection::Unavailable))
                    }
                    PluginState::Stopping | PluginState::Stopped => {
                        return Err(PromptError::Rejected(Rejection::Stopping))
                    }
                    PluginState::Registered | PluginState::Starting => {
                        return Err(PromptError::Rejected(Rejection::NotReady))
                    }
                }
                let prompts = state
                    .jobs
                    .values()
                    .filter(|entry| entry.kind == JobKind::Prompt)
                    .count();
                if prompts >= self.options.prompt_capacity {
                    return Err(PromptError::Rejected(Rejection::Overloaded));
                }
            }
            slot.begin_job(job, JobKind::Prompt)
        };
        let input = input.to_string();
        match invoke(&slot, tracker, |endpoint, done| {
            endpoint.prompt(job, input, done)
        })
        .await
        {
            Invoked::Completed(reply) => Ok(reply),
            Invoked::Cancelled => Err(PromptError::Cancelled),
            Invoked::Panicked(message) => Err(PromptError::Failed(self.record_failure(
                &slot,
                FailurePhase::Prompt,
                FailureCause::Panic(message),
            ))),
            Invoked::Unavailable(_) => Err(PromptError::Rejected(Rejection::Unavailable)),
        }
    }

    fn record_failure(
        self: &Arc<Self>,
        slot: &Arc<PluginSlot>,
        phase: FailurePhase,
        cause: FailureCause,
    ) -> PluginFailure {
        let (failure, action) = {
            let lifecycle = self.lifecycle.lock();
            let mut state = slot.state.lock();
            if let Some(existing) = &state.failure {
                return existing.clone();
            }
            let failure = PluginFailure {
                plugin_id: slot.id.clone(),
                phase,
                cause,
            };
            state.failure = Some(failure.clone());
            let previous = state.state;
            state.state = PluginState::Failed;
            let action = match previous {
                PluginState::Running if lifecycle.phase < HostPhase::Stopping => {
                    FailureAction::Isolate
                }
                PluginState::Starting => FailureAction::CancelStart,
                // Shutdown owns this plugin's cleanup, but its in-flight
                // callbacks and tasks must stop now: a drain must not wait on
                // work that depended on the failed part.
                PluginState::Running | PluginState::Stopping => FailureAction::CancelWork,
                _ => FailureAction::None,
            };
            (failure, action)
        };

        let action_name = match phase {
            FailurePhase::Task => "plugin_task_failed",
            FailurePhase::Start => "plugin_start_failed",
            FailurePhase::Stop => "plugin_stop_failed",
            FailurePhase::Message | FailurePhase::Prompt => "plugin_failed",
        };
        if !matches!(phase, FailurePhase::Start | FailurePhase::Stop) {
            plugin_event(
                LogLevel::Error,
                &slot.id,
                action_name,
                format!(
                    "phase={} result={}",
                    phase.as_str(),
                    failure.cause.category()
                ),
            );
        }
        self.failures
            .send_modify(|failures| failures.push(failure.clone()));

        slot.inbox.close(false, Rejection::Unavailable);
        match action {
            FailureAction::Isolate => {
                if let Some(handle) = self.host_runtime.get() {
                    let manager = self.clone();
                    let slot = slot.clone();
                    handle.spawn(async move {
                        let ran = manager.isolate(&slot).await;
                        drop(manager);
                        if ran {
                            slot.cleanup_done.send_replace(true);
                        }
                    });
                }
            }
            FailureAction::CancelStart => slot.cancel_jobs(&[JobKind::Start]),
            FailureAction::CancelWork => {
                slot.endpoint.cancel_tasks();
                slot.cancel_jobs(&[JobKind::Message, JobKind::Prompt]);
            }
            FailureAction::None => {}
        }
        failure
    }

    /// Roll back one plugin: close admission, cancel its work, observe
    /// completion, run its cleanup, and abort remaining managed tasks.
    /// Returns false if another path already owns the plugin's cleanup. The
    /// caller signals `cleanup_done` after releasing its manager reference.
    async fn isolate(self: &Arc<Self>, slot: &Arc<PluginSlot>) -> bool {
        let start_entered = {
            let mut state = slot.state.lock();
            if state.cleanup != Cleanup::Pending {
                return false;
            }
            state.cleanup = Cleanup::Owned;
            state.start_entered
        };
        let escalation = self.escalation.subscribe();
        slot.inbox.close(false, Rejection::Unavailable);
        slot.endpoint.cancel_tasks();
        slot.cancel_jobs(&[JobKind::Start, JobKind::Message, JobKind::Prompt]);

        let stop = 'cleanup: {
            if !*slot.consumer_done.borrow() {
                waiting_event(&slot.id, QuiescePhase::Drain);
            }
            if until(&escalation, wait_true(slot.consumer_done.subscribe()))
                .await
                .is_none()
            {
                break 'cleanup StopResult::FailedToQuiesce(QuiescePhase::Drain);
            }
            if *slot.jobs_live.borrow() > 0 {
                waiting_event(&slot.id, QuiescePhase::Callbacks);
            }
            if until(&escalation, wait_zero(slot.jobs_live.subscribe()))
                .await
                .is_none()
            {
                break 'cleanup StopResult::FailedToQuiesce(QuiescePhase::Callbacks);
            }
            let stop = if start_entered {
                self.run_stop_hook(slot, &escalation).await
            } else {
                StopResult::NotStarted
            };
            if matches!(stop, StopResult::FailedToQuiesce(_)) {
                break 'cleanup stop;
            }
            match self.abort_slot_tasks(slot, &escalation).await {
                Some(_) => stop,
                None => StopResult::FailedToQuiesce(QuiescePhase::Tasks),
            }
        };
        if let StopResult::FailedToQuiesce(phase) = stop {
            plugin_event(
                LogLevel::Error,
                &slot.id,
                "plugin_failed_to_quiesce",
                format!("phase={}", phase.as_str()),
            );
        }
        {
            let mut state = slot.state.lock();
            state.stop = Some(stop);
            state.cleanup = Cleanup::Done;
        }
        true
    }

    async fn run_stop_hook(
        self: &Arc<Self>,
        slot: &Arc<PluginSlot>,
        escalation: &watch::Receiver<bool>,
    ) -> StopResult {
        plugin_event(
            LogLevel::Info,
            &slot.id,
            "plugin_stopping",
            "phase=stop".into(),
        );
        waiting_event(&slot.id, QuiescePhase::Stop);
        let started_at = Instant::now();
        let job = self.next_job();
        let tracker = slot.begin_job(job, JobKind::Stop);
        let invocation = invoke(slot, tracker, |endpoint, done| endpoint.stop(job, done));
        let Some(result) = until(escalation, invocation).await else {
            return StopResult::FailedToQuiesce(QuiescePhase::Stop);
        };
        let (stop, category) = match result {
            Invoked::Completed(Ok(())) => (StopResult::Stopped, "ok"),
            Invoked::Completed(Err(error)) => (
                StopResult::HookFailed(bounded_text(error.message())),
                "error",
            ),
            Invoked::Panicked(message) => (StopResult::Panicked(message), "panic"),
            Invoked::Cancelled => (StopResult::Cancelled, "cancelled"),
            Invoked::Unavailable(reason) => (StopResult::HookFailed(reason), "unavailable"),
        };
        let action = if stop == StopResult::Stopped {
            "plugin_stopped"
        } else {
            "plugin_stop_failed"
        };
        plugin_event(
            if stop == StopResult::Stopped {
                LogLevel::Info
            } else {
                LogLevel::Error
            },
            &slot.id,
            action,
            format!(
                "phase=stop result={category} elapsed_ms={}",
                elapsed_ms(started_at)
            ),
        );
        stop
    }

    /// Abort a plugin's remaining managed tasks and observe their completion.
    async fn abort_slot_tasks(
        &self,
        slot: &Arc<PluginSlot>,
        escalation: &watch::Receiver<bool>,
    ) -> Option<usize> {
        waiting_event(&slot.id, QuiescePhase::Tasks);
        let (tx, rx) = oneshot::channel();
        let call = slot.endpoint.abort_tasks(Box::new(move |aborted| {
            let _ = tx.send(aborted);
        }));
        let aborted = match call {
            Ok(()) => until(escalation, rx).await?.unwrap_or(0),
            Err(_) => 0,
        };
        slot.state.lock().aborted_tasks += aborted;
        Some(aborted)
    }

    /// Request escalation: stop waiting on uncooperative plugin work. Pending
    /// and future shutdown steps record failed quiescence instead of waiting.
    /// Escalation is sticky and cannot preempt native code that does not yield.
    pub fn escalate(&self) {
        if !self.escalation.send_replace(true) {
            system_event(
                LogLevel::Warn,
                "plugin_shutdown_escalated",
                format!("phase={:?}", self.phase()),
            );
        }
    }

    /// Begin the common cleanup path and return a handle to its report.
    ///
    /// Admission of new inbound messages and prompts closes before this
    /// returns. Repeated calls return the recorded outcome without rerunning
    /// stop hooks; a call during startup cancels initialization and joins the
    /// cleanup path.
    pub fn begin_shutdown(self: &Arc<Self>, mode: ShutdownMode) -> ShutdownHandle {
        let (tx, rx, prior) = {
            let mut lifecycle = self.lifecycle.lock();
            if let Some(rx) = &lifecycle.shutdown {
                return ShutdownHandle { rx: rx.clone() };
            }
            let prior = lifecycle.phase;
            lifecycle.phase = HostPhase::Stopping;
            let (tx, rx) = watch::channel(None);
            lifecycle.shutdown = Some(rx.clone());
            (tx, rx, prior)
        };
        let drain = mode == ShutdownMode::Drain && prior == HostPhase::Active;
        for slot in &self.plugins {
            slot.inbox.close(drain, Rejection::Stopping);
        }
        self.shutdown_signal.send_replace(true);
        system_event(
            LogLevel::Info,
            "plugin_shutdown_started",
            format!("mode={mode:?} prior_phase={prior:?}"),
        );

        let handle = self
            .host_runtime
            .get()
            .cloned()
            .or_else(|| Handle::try_current().ok());
        match handle {
            Some(handle) => {
                let manager = self.clone();
                handle.spawn(async move { manager.run_shutdown(mode, tx).await });
            }
            None => {
                // Without any runtime nothing was ever started.
                let report = self.build_report(mode, false, 0, 0, Duration::ZERO);
                self.lifecycle.lock().phase = HostPhase::Stopped;
                let _ = tx.send(Some(report));
            }
        }
        ShutdownHandle { rx }
    }

    /// Run the common cleanup path and wait for its report. Waits on observed
    /// completion only; use [`escalate`](Self::escalate) to stop waiting.
    pub async fn shutdown(
        self: &Arc<Self>,
        mode: ShutdownMode,
    ) -> Result<ShutdownReport, LifecycleError> {
        self.begin_shutdown(mode).wait().await
    }

    async fn run_shutdown(
        self: Arc<Self>,
        mode: ShutdownMode,
        tx: watch::Sender<Option<ShutdownReport>>,
    ) {
        let started_at = Instant::now();
        let escalation = self.escalation.subscribe();
        let mut escalated_at: Option<QuiescePhase> = None;

        // Join a running startup; it observes the shutdown signal and cancels
        // the start hook in progress.
        let start = self.lifecycle.lock().start.clone();
        if let Some(mut start) = start {
            let joined = until(&escalation, wait_report(&mut start)).await.is_some();
            // Startup also reports once it stops waiting on a start hook, and
            // `until` may return that report even after escalation, so a
            // report does not show that every start hook returned.
            let start_unobserved = self.plugins.iter().any(|slot| {
                slot.state.lock().stop == Some(StopResult::FailedToQuiesce(QuiescePhase::Start))
            });
            if !joined || start_unobserved {
                escalated_at = Some(QuiescePhase::Start);
            }
        }

        let started: Vec<Arc<PluginSlot>> = self
            .plugins
            .iter()
            .filter(|slot| slot.state.lock().start_entered)
            .cloned()
            .collect();

        // Drain or discard admitted messages.
        if escalated_at.is_none() {
            for slot in &started {
                if !slot.inbox.state.lock().drain {
                    slot.cancel_jobs(&[JobKind::Message]);
                }
            }
            for slot in &started {
                if !*slot.consumer_done.borrow() {
                    waiting_event(&slot.id, QuiescePhase::Drain);
                }
                if until(&escalation, wait_true(slot.consumer_done.subscribe()))
                    .await
                    .is_none()
                {
                    escalated_at = Some(QuiescePhase::Drain);
                    break;
                }
            }
        }
        self.lifecycle.lock().outbound_open = false;

        // Cancel task scopes and in-flight callbacks; observe completion.
        // A plugin whose isolation cleanup is already running is joined below,
        // never cancelled here.
        if escalated_at.is_none() {
            for slot in &started {
                if slot.state.lock().cleanup == Cleanup::Owned {
                    continue;
                }
                slot.endpoint.cancel_tasks();
                slot.cancel_jobs(&[JobKind::Message, JobKind::Prompt]);
            }
            for slot in &started {
                if slot.state.lock().cleanup == Cleanup::Owned {
                    continue;
                }
                if *slot.jobs_live.borrow() > 0 {
                    waiting_event(&slot.id, QuiescePhase::Callbacks);
                }
                if until(&escalation, wait_zero(slot.jobs_live.subscribe()))
                    .await
                    .is_none()
                {
                    escalated_at = Some(QuiescePhase::Callbacks);
                    break;
                }
            }
        }

        // Wait for isolation cleanups that are already running.
        if escalated_at.is_none() {
            for slot in &started {
                if slot.state.lock().cleanup != Cleanup::Owned {
                    continue;
                }
                waiting_event(&slot.id, QuiescePhase::Cleanup);
                if until(&escalation, wait_true(slot.cleanup_done.subscribe()))
                    .await
                    .is_none()
                {
                    escalated_at = Some(QuiescePhase::Cleanup);
                    break;
                }
            }
        }

        // Stop hooks in reverse start order, one after another.
        let mut stopping: Vec<Arc<PluginSlot>> = Vec::new();
        if escalated_at.is_none() {
            let order = self.lifecycle.lock().start_order.clone();
            for index in order.iter().rev() {
                let slot = &self.plugins[*index];
                {
                    let mut state = slot.state.lock();
                    if state.cleanup != Cleanup::Pending {
                        continue;
                    }
                    state.cleanup = Cleanup::Owned;
                    if state.state != PluginState::Failed {
                        state.state = PluginState::Stopping;
                    }
                }
                stopping.push(slot.clone());
                let stop = self.run_stop_hook(slot, &escalation).await;
                match &stop {
                    StopResult::HookFailed(text) => {
                        self.record_failure(
                            slot,
                            FailurePhase::Stop,
                            FailureCause::Error(text.clone()),
                        );
                    }
                    StopResult::Panicked(text) => {
                        self.record_failure(
                            slot,
                            FailurePhase::Stop,
                            FailureCause::Panic(text.clone()),
                        );
                    }
                    _ => {}
                }
                let quiesce = match &stop {
                    StopResult::FailedToQuiesce(phase) => Some(*phase),
                    _ => None,
                };
                slot.state.lock().stop = Some(stop);
                if let Some(phase) = quiesce {
                    escalated_at = Some(phase);
                    break;
                }
            }
        }

        // Abort remaining managed tasks and observe their completion.
        if escalated_at.is_none() {
            for slot in &stopping {
                if self.abort_slot_tasks(slot, &escalation).await.is_none() {
                    slot.state.lock().stop = Some(StopResult::FailedToQuiesce(QuiescePhase::Tasks));
                    escalated_at = Some(QuiescePhase::Tasks);
                    break;
                }
                slot.state.lock().cleanup = Cleanup::Done;
                slot.cleanup_done.send_replace(true);
            }
        }

        // Record work not observed to complete. Its code and runtime stay.
        if let Some(phase) = escalated_at {
            for slot in &started {
                let recorded = {
                    let mut state = slot.state.lock();
                    match &state.stop {
                        _ if state.cleanup == Cleanup::Done => None,
                        Some(StopResult::FailedToQuiesce(recorded)) => Some(*recorded),
                        // The stop hook returned, but managed tasks were not
                        // aborted and observed.
                        Some(_) => {
                            state.stop = Some(StopResult::FailedToQuiesce(QuiescePhase::Tasks));
                            Some(QuiescePhase::Tasks)
                        }
                        None => {
                            state.stop = Some(StopResult::FailedToQuiesce(phase));
                            Some(phase)
                        }
                    }
                };
                if let Some(recorded) = recorded {
                    plugin_event(
                        LogLevel::Error,
                        &slot.id,
                        "plugin_failed_to_quiesce",
                        format!("phase={}", recorded.as_str()),
                    );
                }
            }
        }

        let (released, retained) = self.release_runtimes();
        for slot in &self.plugins {
            let mut state = slot.state.lock();
            let quiesced = !matches!(state.stop, Some(StopResult::FailedToQuiesce(_)));
            if state.state != PluginState::Failed && state.start_entered && quiesced {
                state.state = PluginState::Stopped;
            }
        }
        let escalated = escalated_at.is_some();
        let report = self.build_report(mode, escalated, released, retained, started_at.elapsed());
        self.lifecycle.lock().phase = HostPhase::Stopped;
        system_event(
            if report.is_clean() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            "plugin_shutdown_complete",
            format!(
                "clean={} escalated={} elapsed_ms={}",
                report.is_clean(),
                escalated,
                report.elapsed.as_millis()
            ),
        );
        drop(self);
        let _ = tx.send(Some(report));
    }

    /// Release native library runtimes whose handlers were all observed to
    /// stop. Release does not wait for threads outside the managed scope.
    fn release_runtimes(&self) -> (usize, usize) {
        let mut released = 0;
        let mut retained = 0;
        for library in &self.libraries {
            let slots: Vec<&Arc<PluginSlot>> = library
                .slots
                .iter()
                .map(|index| &self.plugins[*index])
                .collect();
            if !slots.iter().any(|slot| slot.state.lock().start_entered) {
                continue;
            }
            let quiesced = slots.iter().all(|slot| {
                let state = slot.state.lock();
                !state.start_entered
                    || (state.cleanup == Cleanup::Done
                        && !matches!(state.stop, Some(StopResult::FailedToQuiesce(_))))
            });
            if quiesced {
                if slots[0].endpoint.release_runtime() {
                    released += 1;
                }
            } else {
                retained += 1;
            }
        }
        (released, retained)
    }

    fn build_report(
        &self,
        mode: ShutdownMode,
        escalated: bool,
        runtimes_released: usize,
        runtimes_retained: usize,
        elapsed: Duration,
    ) -> ShutdownReport {
        let plugins = self
            .plugins
            .iter()
            .map(|slot| {
                let state = slot.state.lock();
                PluginStopReport {
                    plugin_id: slot.id.clone(),
                    final_state: state.state,
                    failure: state.failure.clone(),
                    stop: state.stop.clone().unwrap_or(StopResult::NotStarted),
                    discarded_messages: slot.inbox.discarded(),
                    aborted_tasks: state.aborted_tasks,
                }
            })
            .collect();
        ShutdownReport {
            mode,
            plugins,
            escalated,
            runtimes_released,
            runtimes_retained,
            elapsed,
        }
    }

    /// Whether a plugin may use outbound host services now.
    fn outbound_permission(&self, index: usize) -> Result<(), Rejection> {
        let lifecycle = self.lifecycle.lock();
        let state = self.plugins[index].state.lock().state;
        match state {
            PluginState::Failed => return Err(Rejection::Unavailable),
            PluginState::Registered => return Err(Rejection::NotReady),
            _ => {}
        }
        if lifecycle.outbound_open {
            Ok(())
        } else if lifecycle.phase < HostPhase::Active {
            Err(Rejection::NotReady)
        } else {
            Err(Rejection::Stopping)
        }
    }

    fn delivery_runtime(self: &Arc<Self>) -> Option<DeliveryRuntime> {
        let base = self.context.as_ref()?;
        let objects = base.host_objects.as_ref()?;
        Some(DeliveryRuntime::new(
            (*objects.peer_manager).clone(),
            self.clone(),
            base.config.clone(),
            base.local_node_id.clone(),
            Some(objects.peer_store.clone()),
            base.allow_console,
        ))
    }
}

async fn run_consumer(
    manager: Weak<PluginManager>,
    slot: Arc<PluginSlot>,
    next_job: Arc<AtomicU64>,
) {
    struct Done<'a>(&'a watch::Sender<bool>);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.send_replace(true);
        }
    }
    let _done = Done(&slot.consumer_done);

    loop {
        // Register the job before taking a message, so a shutdown that
        // discards admitted messages can always cancel the one in progress.
        let job = next_job.fetch_add(1, Ordering::Relaxed);
        let tracker = slot.begin_job(job, JobKind::Message);
        let Some(message) = slot.inbox.next().await else {
            break;
        };
        let result = invoke(&slot, tracker, |endpoint, done| {
            endpoint.message(job, message, done)
        })
        .await;
        slot.inbox.finish();
        let cause = match result {
            Invoked::Completed(()) | Invoked::Cancelled => None,
            Invoked::Panicked(message) => Some(FailureCause::Panic(message)),
            Invoked::Unavailable(reason) => Some(FailureCause::Unavailable(reason)),
        };
        if let Some(cause) = cause {
            if let Some(manager) = manager.upgrade() {
                manager.record_failure(&slot, FailurePhase::Message, cause);
            }
        }
    }
}

fn event_meta_mut(event: &mut LogEvent) -> &mut crate::events::model::EventMeta {
    match event {
        LogEvent::TrustDecision(event) => &mut event.meta,
        LogEvent::Promotion(event) => &mut event.meta,
        LogEvent::Network(event) => &mut event.meta,
        LogEvent::Plugin(event) => &mut event.meta,
        LogEvent::System(event) => &mut event.meta,
    }
}

/// Host services for one plugin. Holds only a weak manager reference, so
/// contexts retained by plugin code cannot keep the host alive or revive it.
struct PluginHostServices {
    manager: Weak<PluginManager>,
    index: usize,
    plugin_id: String,
    handle: Handle,
}

fn delivery_failed(reason: DeliveryFailureReason) -> DeliveryOutcome {
    DeliveryOutcome::DeliveryFailed { reason }
}

fn rejection_reason(rejection: Rejection) -> DeliveryFailureReason {
    match rejection {
        Rejection::NotReady => DeliveryFailureReason::NotReady,
        Rejection::Stopping => DeliveryFailureReason::Stopping,
        Rejection::Overloaded | Rejection::Unavailable => DeliveryFailureReason::Unavailable,
    }
}

impl HostServices for PluginHostServices {
    fn deliver(
        &self,
        message: Message,
        options: DeliveryOptions,
        done: Completion<DeliveryOutcome>,
    ) {
        let mut done = Some(done);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let manager = self
                .manager
                .upgrade()
                .ok_or(DeliveryFailureReason::Unavailable)?;
            manager
                .outbound_permission(self.index)
                .map_err(rejection_reason)?;
            let runtime = manager
                .delivery_runtime()
                .ok_or(DeliveryFailureReason::Unavailable)?;
            if let Some(done) = done.take() {
                let plugin_id = self.plugin_id.clone();
                self.handle.spawn(async move {
                    let outcome = runtime.deliver_message(message, options).await;
                    if matches!(
                        outcome,
                        DeliveryOutcome::DeliveryFailed { .. }
                            | DeliveryOutcome::Expired
                            | DeliveryOutcome::UnsupportedOnPath
                    ) {
                        let mut meta = dispatcher::meta("plugin_host", LogLevel::Debug);
                        meta.suppress_console = true;
                        dispatcher::emit(LogEvent::Plugin(PluginEvent {
                            meta,
                            plugin: plugin_id,
                            action: "plugin_send_failed".to_string(),
                            detail: Some(format!("outcome={outcome:?}")),
                        }));
                    }
                    done(outcome);
                });
            }
            Ok(())
        }));
        let reason = match outcome {
            Ok(Ok(())) => return,
            Ok(Err(reason)) => reason,
            Err(_) => DeliveryFailureReason::Unavailable,
        };
        if let Some(done) = done.take() {
            done(delivery_failed(reason));
        }
    }

    fn broadcast(&self, message: Message, done: Completion<Result<(), Rejection>>) {
        let mut done = Some(done);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let manager = self.manager.upgrade().ok_or(Rejection::Unavailable)?;
            manager.outbound_permission(self.index)?;
            let peer_manager = manager
                .context
                .as_ref()
                .and_then(|ctx| ctx.peer_manager().cloned())
                .ok_or(Rejection::Unavailable)?;
            if let Some(done) = done.take() {
                self.handle.spawn(async move {
                    peer_manager.broadcast(&message).await;
                    done(Ok(()));
                });
            }
            Ok(())
        }));
        let rejection = match outcome {
            Ok(Ok(())) => return,
            Ok(Err(rejection)) => rejection,
            Err(_) => Rejection::Unavailable,
        };
        if let Some(done) = done.take() {
            done(Err(rejection));
        }
    }

    fn connected_peer_ids(&self, done: Completion<Result<Vec<String>, Rejection>>) {
        let mut done = Some(done);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let manager = self.manager.upgrade().ok_or(Rejection::Unavailable)?;
            if manager.plugins[self.index].state.lock().state == PluginState::Failed {
                return Err(Rejection::Unavailable);
            }
            let peer_manager = manager
                .context
                .as_ref()
                .and_then(|ctx| ctx.peer_manager().cloned())
                .ok_or(Rejection::Unavailable)?;
            if let Some(done) = done.take() {
                self.handle.spawn(async move {
                    done(Ok(peer_manager.list_node_ids().await));
                });
            }
            Ok(())
        }));
        let rejection = match outcome {
            Ok(Ok(())) => return,
            Ok(Err(rejection)) => rejection,
            Err(_) => Rejection::Unavailable,
        };
        if let Some(done) = done.take() {
            done(Err(rejection));
        }
    }

    fn submit_event(&self, mut event: LogEvent) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(dispatcher) = EventDispatcher::global() {
                let meta = event_meta_mut(&mut event);
                meta.session_id = dispatcher.session_id.clone();
                meta.policy_checksum = dispatcher.policy_checksum();
            }
            dispatcher::emit(event);
        }));
    }

    fn session_id(&self) -> Option<String> {
        catch_unwind(|| EventDispatcher::global().map(|dispatcher| dispatcher.session_id.clone()))
            .ok()
            .flatten()
    }

    fn report_failure(&self, phase: FailurePhase, cause: FailureCause) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(manager) = self.manager.upgrade() {
                let slot = manager.plugins[self.index].clone();
                manager.record_failure(&slot, phase, cause);
            }
        }));
    }
}
