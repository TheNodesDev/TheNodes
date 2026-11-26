//! Managed plugin execution.
//!
//! The plugin manager drives every plugin through a [`PluginEndpoint`]. Endpoint
//! methods are synchronous: each call carries owned data and a completion sink
//! and returns at once. The [`PluginAdapter`] that implements the endpoint runs
//! the plugin's async callbacks as tasks on the runtime that belongs to the
//! plugin's own code copy and catches panics there. No future, waker-bound
//! object, or runtime handle crosses between the host and a native library.
//!
//! A native library links its own copy of TheNodes, Tokio, and std. Its adapter
//! is compiled into that copy and runs on a [`LibraryRuntime`] shared by every
//! handler the library registers. A statically linked (CAL) plugin uses the same
//! adapter compiled into the host and runs on the host runtime.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinError};

use super::lifecycle::{
    bounded_text, FailureCause, FailurePhase, PluginError, Rejection, SpawnError, TaskCancelled,
    TaskExit,
};
use super::{Plugin, PluginContext};
use crate::config::ConfigDefaults;
use crate::events::model::LogEvent;
use crate::network::delivery::{DeliveryOptions, DeliveryOutcome};
use crate::network::message::Message;

/// One-shot completion sink. Its code belongs to the side that created it and
/// needs no runtime context on the calling thread.
pub(crate) type Completion<T> = Box<dyn FnOnce(T) + Send + 'static>;

/// Host-assigned identifier of one callback invocation.
pub(crate) type JobId = u64;

/// Observed end of one callback job.
#[derive(Debug)]
pub(crate) enum JobResult<T> {
    Completed(T),
    Panicked(String),
    Cancelled,
}

/// Immediate refusal of an endpoint call. When a call returns an error its
/// completion sink is never invoked.
#[derive(Debug)]
pub(crate) enum CallError {
    Panicked(String),
    Unavailable(String),
}

/// Plugin metadata read once, inside the plugin's code copy, at registration.
pub(crate) struct PluginDescriptor {
    pub(crate) id: String,
    pub(crate) subscriptions: Option<Vec<String>>,
    pub(crate) prompt_prefix: Option<String>,
    pub(crate) defaults: Option<ConfigDefaults>,
    pub(crate) task_limit: usize,
}

impl PluginDescriptor {
    pub(crate) fn read(plugin: &dyn Plugin) -> Self {
        Self {
            id: plugin.plugin_id().to_string(),
            subscriptions: plugin
                .subscribed_extension_kinds()
                .map(|kinds| kinds.iter().map(|kind| kind.to_string()).collect()),
            prompt_prefix: plugin.prompt_prefix().map(str::to_string),
            defaults: plugin.early_config_defaults(),
            task_limit: plugin.max_managed_tasks(),
        }
    }
}

/// Synchronous execution boundary for one registered plugin.
///
/// Every method that takes a completion sink either returns an error and drops
/// the sink, or returns `Ok` and later invokes the sink exactly once. A sink is
/// only dropped without being invoked if the runtime executing the job is torn
/// down first.
pub(crate) trait PluginEndpoint: Send + Sync {
    fn start(
        &self,
        job: JobId,
        ctx: PluginContext,
        done: Completion<JobResult<Result<(), PluginError>>>,
    ) -> Result<(), CallError>;

    fn message(
        &self,
        job: JobId,
        message: Message,
        done: Completion<JobResult<()>>,
    ) -> Result<(), CallError>;

    fn prompt(
        &self,
        job: JobId,
        input: String,
        done: Completion<JobResult<Option<String>>>,
    ) -> Result<(), CallError>;

    fn stop(
        &self,
        job: JobId,
        done: Completion<JobResult<Result<(), PluginError>>>,
    ) -> Result<(), CallError>;

    /// Request cancellation of a job. A no-op for jobs that already ended.
    fn cancel(&self, job: JobId);

    /// Notify managed tasks waiting for host activation.
    fn activate(&self);

    /// Signal cooperative cancellation to the task scope and refuse new tasks.
    fn cancel_tasks(&self);

    /// Abort remaining managed tasks; `done` receives the number aborted once
    /// every task's completion has been observed.
    fn abort_tasks(&self, done: Completion<usize>) -> Result<(), CallError>;

    /// Shut down the library runtime without blocking. Returns whether a
    /// runtime was released.
    fn release_runtime(&self) -> bool;
}

/// Native plugin registration transferred to the host as owned data.
pub(crate) struct NativeRegistration {
    pub(crate) descriptor: PluginDescriptor,
    pub(crate) endpoint: Box<dyn PluginEndpoint>,
}

/// Host operations available to plugin code through `PluginContext`.
///
/// The host implements this trait. Its methods run host code: they spawn host
/// work through a host runtime handle captured by the host and report results
/// through completion sinks created by the caller.
pub(crate) trait HostServices: Send + Sync {
    fn deliver(
        &self,
        message: Message,
        options: DeliveryOptions,
        done: Completion<DeliveryOutcome>,
    );
    fn broadcast(&self, message: Message, done: Completion<Result<(), Rejection>>);
    fn connected_peer_ids(&self, done: Completion<Result<Vec<String>, Rejection>>);
    fn submit_event(&self, event: LogEvent);
    fn session_id(&self) -> Option<String>;
    fn report_failure(&self, phase: FailurePhase, cause: FailureCause);
}

/// Extract a bounded message from a panic payload. Must run in the code copy
/// that raised the panic.
pub(crate) fn panic_message(payload: Box<dyn Any + Send>) -> String {
    let text = if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    };
    bounded_text(&text)
}

fn guarded(call: impl FnOnce() -> Result<(), CallError>) -> Result<(), CallError> {
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(result) => result,
        Err(payload) => Err(CallError::Panicked(panic_message(payload))),
    }
}

fn guarded_unit(call: impl FnOnce()) {
    let _ = catch_unwind(AssertUnwindSafe(call));
}

fn job_result<T>(result: Result<T, JoinError>) -> JobResult<T> {
    match result {
        Ok(value) => JobResult::Completed(value),
        Err(error) if error.is_panic() => JobResult::Panicked(panic_message(error.into_panic())),
        Err(_) => JobResult::Cancelled,
    }
}

/// One Tokio runtime per loaded native library, shared by all of its handlers.
///
/// The runtime is created when the first handler starts and is released with
/// a non-blocking shutdown after the host observed every handler stop.
pub(crate) struct LibraryRuntime {
    workers: usize,
    state: Mutex<LibraryRuntimeState>,
}

#[derive(Default)]
struct LibraryRuntimeState {
    runtime: Option<Runtime>,
    released: bool,
}

impl LibraryRuntime {
    pub(crate) fn new(workers: usize) -> Self {
        Self {
            workers,
            state: Mutex::new(LibraryRuntimeState::default()),
        }
    }

    fn handle(&self) -> Result<Handle, String> {
        let mut state = self.state.lock();
        if state.released {
            return Err("plugin runtime was released".to_string());
        }
        if let Some(runtime) = &state.runtime {
            return Ok(runtime.handle().clone());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(self.workers)
            .thread_name("thenodes-plugin")
            .enable_all()
            .build()
            .map_err(|error| format!("failed to create plugin runtime: {error}"))?;
        let handle = runtime.handle().clone();
        state.runtime = Some(runtime);
        Ok(handle)
    }

    fn release(&self) -> bool {
        let runtime = {
            let mut state = self.state.lock();
            state.released = true;
            state.runtime.take()
        };
        match runtime {
            Some(runtime) => {
                runtime.shutdown_background();
                true
            }
            None => false,
        }
    }
}

impl Drop for LibraryRuntime {
    fn drop(&mut self) {
        // Never block on worker threads, even if the last reference is dropped
        // inside an async context.
        if let Some(runtime) = self.state.get_mut().runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Runtime on which an adapter executes plugin code.
pub(crate) enum RuntimeSource {
    /// The host runtime, bound by the manager when startup begins (CAL).
    Host(Arc<OnceLock<Handle>>),
    /// The native library's own runtime.
    Library(Arc<LibraryRuntime>),
}

impl RuntimeSource {
    fn handle(&self) -> Result<Handle, String> {
        match self {
            RuntimeSource::Host(handle) => handle
                .get()
                .cloned()
                .ok_or_else(|| "host runtime is not bound".to_string()),
            RuntimeSource::Library(library) => library.handle(),
        }
    }
}

#[derive(Default)]
struct AdapterState {
    ctx: Option<PluginContext>,
    scope: Option<Arc<TaskScope>>,
}

/// Endpoint implementation wrapping an async [`Plugin`].
pub(crate) struct PluginAdapter {
    /// Dropped explicitly so a panicking plugin destructor is caught in this
    /// code copy even when the host drops the endpoint.
    plugin: ManuallyDrop<Arc<dyn Plugin>>,
    plugin_id: String,
    task_limit: usize,
    runtime: RuntimeSource,
    state: Mutex<AdapterState>,
    jobs: Arc<Mutex<HashMap<JobId, AbortHandle>>>,
}

impl PluginAdapter {
    pub(crate) fn new(
        plugin: Arc<dyn Plugin>,
        descriptor: &PluginDescriptor,
        runtime: RuntimeSource,
    ) -> Self {
        Self {
            plugin: ManuallyDrop::new(plugin),
            plugin_id: descriptor.id.clone(),
            task_limit: descriptor.task_limit,
            runtime,
            state: Mutex::new(AdapterState::default()),
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn bound(&self) -> Result<(Handle, PluginContext), CallError> {
        let ctx = self
            .state
            .lock()
            .ctx
            .clone()
            .ok_or_else(|| CallError::Unavailable("plugin was not started".to_string()))?;
        let handle = self.runtime.handle().map_err(CallError::Unavailable)?;
        Ok((handle, ctx))
    }

    fn scope(&self) -> Option<Arc<TaskScope>> {
        self.state.lock().scope.clone()
    }

    fn spawn_job<T, F>(
        &self,
        handle: &Handle,
        job: JobId,
        future: F,
        done: Completion<JobResult<T>>,
    ) where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let task = handle.spawn(future);
        self.jobs.lock().insert(job, task.abort_handle());
        let jobs = self.jobs.clone();
        handle.spawn(async move {
            // Completion of the join handle is observed only after the job's
            // future has been dropped.
            let result = task.await;
            jobs.lock().remove(&job);
            done(job_result(result));
        });
    }
}

impl Drop for PluginAdapter {
    fn drop(&mut self) {
        // SAFETY: `plugin` is taken exactly once, here, and never used again.
        let plugin = unsafe { ManuallyDrop::take(&mut self.plugin) };
        let _ = catch_unwind(AssertUnwindSafe(move || drop(plugin)));
    }
}

impl PluginEndpoint for PluginAdapter {
    fn start(
        &self,
        job: JobId,
        mut ctx: PluginContext,
        done: Completion<JobResult<Result<(), PluginError>>>,
    ) -> Result<(), CallError> {
        guarded(|| {
            let handle = self.runtime.handle().map_err(CallError::Unavailable)?;
            let scope = Arc::new(TaskScope::new(
                self.plugin_id.clone(),
                handle.clone(),
                self.task_limit,
                ctx.services.clone(),
            ));
            ctx.scope = Some(scope.clone());
            {
                let mut state = self.state.lock();
                state.ctx = Some(ctx.clone());
                state.scope = Some(scope);
            }
            let plugin = Arc::clone(&self.plugin);
            self.spawn_job(
                &handle,
                job,
                async move { plugin.on_start(&ctx).await },
                done,
            );
            Ok(())
        })
    }

    fn message(
        &self,
        job: JobId,
        message: Message,
        done: Completion<JobResult<()>>,
    ) -> Result<(), CallError> {
        guarded(|| {
            let (handle, ctx) = self.bound()?;
            let plugin = Arc::clone(&self.plugin);
            self.spawn_job(
                &handle,
                job,
                async move { plugin.on_message(&message, &ctx).await },
                done,
            );
            Ok(())
        })
    }

    fn prompt(
        &self,
        job: JobId,
        input: String,
        done: Completion<JobResult<Option<String>>>,
    ) -> Result<(), CallError> {
        guarded(|| {
            let (handle, ctx) = self.bound()?;
            let plugin = Arc::clone(&self.plugin);
            self.spawn_job(
                &handle,
                job,
                async move { plugin.on_prompt(&input, &ctx).await },
                done,
            );
            Ok(())
        })
    }

    fn stop(
        &self,
        job: JobId,
        done: Completion<JobResult<Result<(), PluginError>>>,
    ) -> Result<(), CallError> {
        guarded(|| {
            let (handle, ctx) = self.bound()?;
            let plugin = Arc::clone(&self.plugin);
            self.spawn_job(
                &handle,
                job,
                async move { plugin.on_stop(&ctx).await },
                done,
            );
            Ok(())
        })
    }

    fn cancel(&self, job: JobId) {
        guarded_unit(|| {
            if let Some(task) = self.jobs.lock().get(&job) {
                task.abort();
            }
        });
    }

    fn activate(&self) {
        guarded_unit(|| {
            if let Some(scope) = self.scope() {
                scope.activate();
            }
        });
    }

    fn cancel_tasks(&self) {
        guarded_unit(|| {
            if let Some(scope) = self.scope() {
                scope.cancel();
            }
        });
    }

    fn abort_tasks(&self, done: Completion<usize>) -> Result<(), CallError> {
        guarded(|| {
            match self.scope() {
                Some(scope) => scope.abort_all(done),
                None => done(0),
            }
            Ok(())
        })
    }

    fn release_runtime(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| match &self.runtime {
            RuntimeSource::Library(library) => library.release(),
            RuntimeSource::Host(_) => false,
        }))
        .unwrap_or(false)
    }
}

#[derive(Default)]
struct ScopeInner {
    tasks: HashMap<u64, AbortHandle>,
    next_id: u64,
    reserved: usize,
    closed: bool,
    aborting: bool,
}

/// Tracked background tasks of one plugin.
///
/// Every task stays accounted for until its completion has been observed.
/// Dropping a [`TaskHandle`] does not detach the task.
pub(crate) struct TaskScope {
    plugin_id: String,
    handle: Handle,
    limit: usize,
    services: Option<Arc<dyn HostServices>>,
    inner: Mutex<ScopeInner>,
    live: watch::Sender<usize>,
    cancel: watch::Sender<bool>,
    activated: watch::Sender<bool>,
}

impl TaskScope {
    fn new(
        plugin_id: String,
        handle: Handle,
        limit: usize,
        services: Option<Arc<dyn HostServices>>,
    ) -> Self {
        Self {
            plugin_id,
            handle,
            limit,
            services,
            inner: Mutex::new(ScopeInner::default()),
            live: watch::channel(0).0,
            cancel: watch::channel(false).0,
            activated: watch::channel(false).0,
        }
    }

    pub(crate) fn spawn<F, Fut>(
        self: &Arc<Self>,
        name: &str,
        task: F,
    ) -> Result<TaskHandle, SpawnError>
    where
        F: FnOnce(TaskContext) -> Fut,
        Fut: Future<Output = Result<(), PluginError>> + Send + 'static,
    {
        let id = {
            let mut inner = self.inner.lock();
            if inner.closed {
                return Err(SpawnError::Stopping);
            }
            if inner.reserved >= self.limit {
                return Err(SpawnError::Overloaded { limit: self.limit });
            }
            inner.reserved += 1;
            inner.next_id += 1;
            inner.next_id
        };
        self.live.send_modify(|live| *live += 1);
        let reservation = Reservation {
            scope: self,
            armed: true,
        };

        let task_ctx = TaskContext {
            cancel: self.cancel.subscribe(),
            activated: self.activated.subscribe(),
        };
        let future = task(task_ctx);
        let joined = self.handle.spawn(future);
        let abort = joined.abort_handle();
        let abort_now = {
            let mut inner = self.inner.lock();
            inner.tasks.insert(id, abort.clone());
            inner.aborting
        };
        if abort_now {
            abort.abort();
        }

        let (exit_tx, exit_rx) = watch::channel(None);
        let scope = self.clone();
        reservation.disarm();
        self.handle.spawn(async move {
            let exit = match joined.await {
                Ok(Ok(())) => TaskExit::Completed,
                Ok(Err(error)) => TaskExit::Failed(error),
                Err(error) if error.is_panic() => {
                    TaskExit::Panicked(panic_message(error.into_panic()))
                }
                Err(_) => TaskExit::Cancelled,
            };
            scope.finish(id, &exit);
            let _ = exit_tx.send(Some(exit));
        });

        Ok(TaskHandle {
            id,
            name: name.to_string(),
            abort,
            exit: exit_rx,
        })
    }

    fn finish(&self, id: u64, exit: &TaskExit) {
        {
            let mut inner = self.inner.lock();
            inner.tasks.remove(&id);
            inner.reserved = inner.reserved.saturating_sub(1);
        }
        self.live.send_modify(|live| *live = live.saturating_sub(1));
        let cause = match exit {
            TaskExit::Failed(error) => FailureCause::Error(bounded_text(error.message())),
            TaskExit::Panicked(message) => FailureCause::Panic(message.clone()),
            TaskExit::Completed | TaskExit::Cancelled => return,
        };
        match &self.services {
            Some(services) => services.report_failure(FailurePhase::Task, cause),
            None => log::warn!(
                "managed task of plugin '{}' failed without a host to notify",
                self.plugin_id
            ),
        }
    }

    fn activate(&self) {
        self.activated.send_replace(true);
    }

    fn cancel(&self) {
        self.inner.lock().closed = true;
        self.cancel.send_replace(true);
    }

    fn abort_all(&self, done: Completion<usize>) {
        let handles: Vec<AbortHandle> = {
            let mut inner = self.inner.lock();
            inner.closed = true;
            inner.aborting = true;
            inner.tasks.values().cloned().collect()
        };
        self.cancel.send_replace(true);
        let aborted = handles.len();
        for handle in &handles {
            handle.abort();
        }
        let mut live = self.live.subscribe();
        self.handle.spawn(async move {
            loop {
                if *live.borrow_and_update() == 0 {
                    break;
                }
                if live.changed().await.is_err() {
                    break;
                }
            }
            done(aborted);
        });
    }
}

struct Reservation<'a> {
    scope: &'a TaskScope,
    armed: bool,
}

impl Reservation<'_> {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.armed {
            {
                let mut inner = self.scope.inner.lock();
                inner.reserved = inner.reserved.saturating_sub(1);
            }
            self.scope
                .live
                .send_modify(|live| *live = live.saturating_sub(1));
        }
    }
}

/// Context passed to a managed task.
pub struct TaskContext {
    cancel: watch::Receiver<bool>,
    activated: watch::Receiver<bool>,
}

impl TaskContext {
    /// True once the plugin's task scope has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    /// Resolves when the plugin's task scope is cancelled.
    pub async fn cancelled(&self) {
        let mut cancel = self.cancel.clone();
        loop {
            if *cancel.borrow_and_update() {
                return;
            }
            if cancel.changed().await.is_err() {
                return;
            }
        }
    }

    /// Wait until the host activates normal plugin operation.
    ///
    /// Returns an error if the task scope is cancelled first. Plugin message
    /// sends before activation return a not-ready outcome, so tasks started
    /// from `on_start` wait here before sending.
    pub async fn activated(&self) -> Result<(), TaskCancelled> {
        let mut activated = self.activated.clone();
        loop {
            if self.is_cancelled() {
                return Err(TaskCancelled);
            }
            if *activated.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                changed = activated.changed() => {
                    if changed.is_err() {
                        return Err(TaskCancelled);
                    }
                }
                _ = self.cancelled() => return Err(TaskCancelled),
            }
        }
    }
}

/// Handle to a managed task. Dropping it does not detach or cancel the task;
/// the task stays in its plugin's scope until it completes or the plugin stops.
pub struct TaskHandle {
    id: u64,
    name: String,
    abort: AbortHandle,
    exit: watch::Receiver<Option<TaskExit>>,
}

impl TaskHandle {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Request cancellation. Completion is only known once `join` returns.
    pub fn cancel(&self) {
        self.abort.abort();
    }

    /// True once the task's completion has been observed.
    pub fn is_finished(&self) -> bool {
        self.exit.borrow().is_some()
    }

    /// Wait for the task's observed completion.
    pub async fn join(mut self) -> TaskExit {
        loop {
            if let Some(exit) = self.exit.borrow_and_update().clone() {
                return exit;
            }
            if self.exit.changed().await.is_err() {
                return TaskExit::Cancelled;
            }
        }
    }
}
