//! Plugin lifecycle integration tests.
//!
//! Statically registered (CAL) scenarios run in this process. Native scenarios
//! load real `cdylib` fixtures from `tests/fixtures/`, built by this harness
//! with the same Cargo, lockfile, profile, and TheNodes features as this test
//! binary. Each native scenario runs in a child process so a plugin failure,
//! fixture mode, or hang cannot affect other tests. Standalone host scenarios
//! run the real `thenodes` binary.
//!
//! Outcomes are decided by observed events and reports. Time limits exist only
//! as a harness watchdog that turns a missing event into a failed test.

use std::collections::HashSet;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use thenodes::config::{Config, ConfigDefaults, NodeConfig};
use thenodes::events::model::LogEvent;
use thenodes::events::sink::LogSink;
use thenodes::network::delivery::{DeliveryClass, DeliveryFailureReason, DeliveryOptions};
use thenodes::network::message::{Message, MessageType, Payload};
use thenodes::network::{
    bind_listener, connect_to_peer, run_listener, transport::ConnectToPeerParams, DeliveryOutcome,
    Peer, PeerManager, PeerStore,
};
use thenodes::plugin_host::{
    pinned_library_count, ActivationError, FailureCause, FailurePhase, LifecycleError, Plugin,
    PluginContext, PluginError, PluginHostOptions, PluginLoadError, PluginLoader, PluginManager,
    PluginRegistrar, PluginRegistrationError, PluginState, PromptError, QuiescePhase,
    RegistrationStatus, Rejection, ShutdownMode, SpawnError, StartPolicy, StartResult, StopResult,
    PLUGIN_ABI_VERSION,
};
use thenodes::realms::RealmInfo;
use tokio::sync::{mpsc, Notify};

const ALPHA: &str = "fixture.alpha";
const BETA: &str = "fixture.beta";

// ---------------------------------------------------------------------------
// Event capture and hang guards
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Captured {
    plugin: Option<String>,
    action: String,
    detail: String,
}

static SUBSCRIBERS: Mutex<Vec<mpsc::UnboundedSender<Captured>>> = Mutex::new(Vec::new());
static EVENTS_READY: OnceLock<()> = OnceLock::new();

struct CaptureSink;

#[async_trait]
impl LogSink for CaptureSink {
    async fn handle(&self, event: &LogEvent) {
        let captured = match event {
            LogEvent::Plugin(event) => Captured {
                plugin: Some(event.plugin.clone()),
                action: event.action.clone(),
                detail: event.detail.clone().unwrap_or_default(),
            },
            LogEvent::System(event) => Captured {
                plugin: None,
                action: event.action.clone(),
                detail: event.detail.clone().unwrap_or_default(),
            },
            _ => return,
        };
        SUBSCRIBERS
            .lock()
            .unwrap()
            .retain(|subscriber| subscriber.send(captured.clone()).is_ok());
    }
}

/// Subscribe to host events. The process-wide dispatcher runs on its own
/// runtime thread so it outlives every test runtime.
fn events() -> EventLog {
    EVENTS_READY.get_or_init(|| {
        let (ready_tx, ready_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("event runtime");
            runtime.block_on(async {
                thenodes::events::init_events(vec![Arc::new(CaptureSink)], 8192).await;
                ready_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            });
        });
        ready_rx.recv().expect("event dispatcher initialized");
    });
    let (tx, rx) = mpsc::unbounded_channel();
    SUBSCRIBERS.lock().unwrap().push(tx);
    EventLog {
        rx,
        seen: Vec::new(),
    }
}

struct EventLog {
    rx: mpsc::UnboundedReceiver<Captured>,
    seen: Vec<Captured>,
}

impl EventLog {
    fn matches(event: &Captured, plugin: Option<&str>, action: &str) -> bool {
        event.plugin.as_deref() == plugin && event.action == action
    }

    async fn wait_for(&mut self, plugin: Option<&str>, action: &str) -> Captured {
        self.wait_for_detail(plugin, action, "").await
    }

    async fn wait_for_detail(
        &mut self,
        plugin: Option<&str>,
        action: &str,
        detail: &str,
    ) -> Captured {
        if let Some(event) = self
            .seen
            .iter()
            .find(|event| Self::matches(event, plugin, action) && event.detail.contains(detail))
        {
            return event.clone();
        }
        loop {
            let event = within(self.rx.recv())
                .await
                .expect("event stream stays open");
            self.seen.push(event.clone());
            if Self::matches(&event, plugin, action) && event.detail.contains(detail) {
                return event;
            }
        }
    }

    fn index_of(&self, plugin: Option<&str>, action: &str) -> Option<usize> {
        self.seen
            .iter()
            .position(|event| Self::matches(event, plugin, action))
    }

    fn drain_now(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            self.seen.push(event);
        }
    }

    fn mentions(&self, plugin: &str, needle: &str) -> bool {
        self.seen.iter().any(|event| {
            event.plugin.as_deref() == Some(plugin)
                && (event.detail.contains(needle) || event.action.contains(needle))
        })
    }
}

/// Harness hang guard. It never decides a pass; a missing notification fails.
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), future)
        .await
        .expect("expected notification did not arrive (harness watchdog)")
}

fn temp_config(dir: &Path, node_id: &str) -> Config {
    let mut config = Config {
        port: 0,
        app_name: Some("final-app".to_string()),
        ..Config::default()
    };
    let node = config.node.get_or_insert_with(NodeConfig::default);
    node.state_dir = Some(dir.join("state").display().to_string());
    node.id = Some(node_id.to_string());
    config
}

fn host_context(config: &Config, node_id: &str) -> (PluginContext, Arc<PeerManager>) {
    let peer_manager = Arc::new(PeerManager::new());
    let ctx = PluginContext::new(
        peer_manager.clone(),
        PeerStore::new(),
        thenodes::events::dispatcher::handle(),
        node_id.to_string(),
        config.clone(),
        false,
    );
    (ctx, peer_manager)
}

fn extension(kind: &str, payload: Option<serde_json::Value>) -> Message {
    Message::new(
        "peer-a",
        "local-node",
        MessageType::Extension {
            kind: kind.to_string(),
        },
        payload.map(Payload::Json),
        None,
    )
}

fn text(body: &str) -> Message {
    Message::new(
        "peer-a",
        "local-node",
        MessageType::Text(body.to_string()),
        None,
        None,
    )
}

// ---------------------------------------------------------------------------
// CAL scenarios (in process)
// ---------------------------------------------------------------------------

struct OrderedPlugin {
    id: &'static str,
    log: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for OrderedPlugin {
    fn plugin_id(&self) -> &'static str {
        self.id
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        // Final configuration, identity, stores, and plugin ID are visible.
        assert_eq!(ctx.config.app_name.as_deref(), Some("final-app"));
        assert_eq!(ctx.local_node_id, "final-node");
        assert_eq!(ctx.plugin_id(), Some(self.id));
        assert!(
            ctx.peer_store().is_some(),
            "CAL contexts keep low-level access"
        );
        let dir = ctx.plugin_data_dir().await?;
        assert!(dir.ends_with(self.id));
        self.log.lock().unwrap().push(format!("start:{}", self.id));
        let thread = std::thread::current().name().unwrap_or("").to_string();
        assert!(
            !thread.starts_with("thenodes-plugin"),
            "CAL plugins run on the host runtime, not a plugin runtime"
        );
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}

    async fn on_stop(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.log.lock().unwrap().push(format!("stop:{}", self.id));
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_start_runs_once_in_order_and_stop_runs_in_reverse() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut manager = PluginManager::new();
    for id in ["cal.order.a", "cal.order.b", "cal.order.c"] {
        manager
            .register_handler(Box::new(OrderedPlugin {
                id,
                log: log.clone(),
            }))
            .unwrap();
    }
    // The context is finalized after registration, before startup.
    let (ctx, _peer_manager) = host_context(&temp_config(dir.path(), "final-node"), "final-node");
    manager.set_context(ctx);
    let manager = Arc::new(manager);

    let (first, second) = tokio::join!(
        manager.start_all(StartPolicy::StopOnFirstFailure),
        manager.start_all(StartPolicy::StopOnFirstFailure)
    );
    assert_eq!(first.as_ref().unwrap(), second.as_ref().unwrap());
    assert!(first.unwrap().all_started());
    let again = manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    assert!(again.all_started());
    manager.activate().unwrap();

    let (report_a, report_b) = tokio::join!(
        manager.shutdown(ShutdownMode::Drain),
        manager.shutdown(ShutdownMode::Drain)
    );
    assert_eq!(report_a.as_ref().unwrap(), report_b.as_ref().unwrap());
    assert!(report_a.unwrap().is_clean());
    let repeated = manager.shutdown(ShutdownMode::Discard).await.unwrap();
    assert_eq!(
        repeated.mode,
        ShutdownMode::Drain,
        "recorded outcome is returned"
    );

    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "start:cal.order.a",
            "start:cal.order.b",
            "start:cal.order.c",
            "stop:cal.order.c",
            "stop:cal.order.b",
            "stop:cal.order.a",
        ]
    );
    assert!(matches!(
        manager.start_all(StartPolicy::StopOnFirstFailure).await,
        Err(LifecycleError::InvalidState { .. })
    ));
    assert_eq!(
        manager.plugin_state("cal.order.a"),
        Some(PluginState::Stopped)
    );
}

struct GatedStartPlugin {
    id: &'static str,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    log: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for GatedStartPlugin {
    fn plugin_id(&self) -> &'static str {
        self.id
    }

    async fn on_start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.log.lock().unwrap().push(format!("start:{}", self.id));
        self.entered.notify_one();
        self.release.notified().await;
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}

    async fn on_stop(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.log.lock().unwrap().push(format!("stop:{}", self.id));
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_shutdown_racing_startup_cancels_initialization() {
    let dir = tempfile::tempdir().unwrap();
    let entered = Arc::new(Notify::new());
    let log = Arc::new(Mutex::new(Vec::new()));
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "race-node"), "race-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(GatedStartPlugin {
            id: "cal.race.slow",
            entered: entered.clone(),
            release: Arc::new(Notify::new()),
            log: log.clone(),
        }))
        .unwrap();
    manager
        .register_handler(Box::new(OrderedPlugin {
            id: "cal.race.next",
            log: log.clone(),
        }))
        .unwrap();
    let manager = Arc::new(manager);

    let start = tokio::spawn({
        let manager = manager.clone();
        async move { manager.start_all(StartPolicy::StopOnFirstFailure).await }
    });
    within(entered.notified()).await;
    let report = within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();
    let start = start.await.unwrap().unwrap();

    assert_eq!(start.outcomes[0].result, StartResult::Cancelled);
    assert_eq!(start.outcomes[1].result, StartResult::NotStarted);
    // The cancelled start hook was entered, so cleanup still runs; the plugin
    // that never started gets no stop hook.
    assert_eq!(
        *log.lock().unwrap(),
        vec!["start:cal.race.slow", "stop:cal.race.slow"]
    );
    assert_eq!(report.plugins[0].stop, StopResult::Stopped);
    assert_eq!(report.plugins[1].stop, StopResult::NotStarted);
    assert_eq!(report.plugins[1].final_state, PluginState::Registered);
    assert!(report.is_clean(), "{report:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_dropped_start_waiter_does_not_abandon_startup() {
    let dir = tempfile::tempdir().unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "drop-node"), "drop-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(GatedStartPlugin {
            id: "cal.drop.slow",
            entered: entered.clone(),
            release: release.clone(),
            log: Arc::new(Mutex::new(Vec::new())),
        }))
        .unwrap();
    let manager = Arc::new(manager);

    let waiter = tokio::spawn({
        let manager = manager.clone();
        async move { manager.start_all(StartPolicy::StopOnFirstFailure).await }
    });
    within(entered.notified()).await;
    waiter.abort();
    let _ = waiter.await;
    release.notify_one();

    let report = within(manager.start_all(StartPolicy::StopOnFirstFailure))
        .await
        .unwrap();
    assert!(report.all_started());
    assert_eq!(
        manager.plugin_state("cal.drop.slow"),
        Some(PluginState::Running)
    );
    within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();
}

struct FailingStartPlugin;

#[async_trait]
impl Plugin for FailingStartPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.failing"
    }

    async fn on_start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Err(PluginError::new("credential secret-token-123 rejected"))
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

struct CountingPlugin {
    id: &'static str,
    handled: mpsc::UnboundedSender<String>,
}

#[async_trait]
impl Plugin for CountingPlugin {
    fn plugin_id(&self) -> &'static str {
        self.id
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        if let MessageType::Text(body) = &message.msg_type {
            if body == "panic" {
                panic!("counting plugin panic");
            }
            let _ = self.handled.send(body.clone());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_failed_plugin_requires_acknowledgement_and_is_isolated() {
    let mut events = events();
    let dir = tempfile::tempdir().unwrap();
    let (handled_tx, mut handled_rx) = mpsc::unbounded_channel();
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "ack-node"), "ack-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(FailingStartPlugin))
        .unwrap();
    manager
        .register_handler(Box::new(CountingPlugin {
            id: "cal.healthy",
            handled: handled_tx,
        }))
        .unwrap();
    let manager = Arc::new(manager);
    let mut failures = manager.subscribe_failures();

    let start = manager
        .start_all(StartPolicy::ContinueOnFailure)
        .await
        .unwrap();
    let StartResult::Failed(failure) = &start.outcomes[0].result else {
        panic!("failing plugin must fail: {start:?}");
    };
    assert_eq!(failure.phase, FailurePhase::Start);
    assert!(matches!(&failure.cause, FailureCause::Error(text) if text.contains("rejected")));
    assert_eq!(start.outcomes[1].result, StartResult::Started);
    assert_eq!(within(failures.recv()).await.as_ref(), Some(failure));

    assert_eq!(
        manager.activate(),
        Err(ActivationError::UnacknowledgedFailures(vec![
            "cal.failing".to_string()
        ]))
    );
    manager.acknowledge_failure("cal.failing").unwrap();
    manager.activate().unwrap();

    let report = manager.dispatch_message(&text("hello"));
    assert_eq!(report.admitted, 1);
    assert_eq!(
        report.rejected,
        vec![("cal.failing".to_string(), Rejection::Unavailable)]
    );
    assert_eq!(within(handled_rx.recv()).await.as_deref(), Some("hello"));

    // An execution failure after activation isolates only that plugin.
    manager.dispatch_message(&text("panic"));
    let failure = within(failures.recv()).await.unwrap();
    assert_eq!(failure.plugin_id, "cal.healthy");
    assert_eq!(failure.phase, FailurePhase::Message);
    assert!(matches!(failure.cause, FailureCause::Panic(_)));
    events.wait_for(Some("cal.healthy"), "plugin_failed").await;

    let report = within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.plugins[0].final_state, PluginState::Failed);
    assert_eq!(
        report.plugins[0].stop,
        StopResult::Stopped,
        "cleanup ran after the failed start"
    );
    assert_eq!(report.plugins[1].final_state, PluginState::Failed);

    // Lifecycle events carry categories, never hook error text.
    events.drain_now();
    events
        .wait_for(Some("cal.failing"), "plugin_start_failed")
        .await;
    assert!(!events.mentions("cal.failing", "secret-token-123"));
}

struct StalePlugin {
    captured: Arc<OnceLock<PluginContext>>,
}

#[async_trait]
impl Plugin for StalePlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.stale"
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some("stale")
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        let _ = self.captured.set(ctx.clone());
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}

    async fn on_prompt(&self, input: &str, _ctx: &PluginContext) -> Option<String> {
        Some(format!("echo:{input}"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_stale_context_and_prompt_selection_cannot_revive_execution() {
    let dir = tempfile::tempdir().unwrap();
    let captured = Arc::new(OnceLock::new());
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "stale-node"), "stale-node");
    let unbound = ctx.for_plugin("cal.stale").unwrap();
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(StalePlugin {
            captured: captured.clone(),
        }))
        .unwrap();
    let manager = Arc::new(manager);
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    let target = manager.resolve_prompt("stale").unwrap();
    assert_eq!(
        manager.dispatch_prompt(&target, "early").await,
        Err(PromptError::Rejected(Rejection::NotReady))
    );
    manager.activate().unwrap();
    assert_eq!(
        manager.dispatch_prompt(&target, "hi").await,
        Ok(Some("echo:hi".to_string()))
    );
    let plugin_ctx = captured.get().unwrap().clone();
    assert!(matches!(
        unbound.spawn_task("never", |_| async { Ok(()) }),
        Err(SpawnError::NotReady)
    ));

    within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();

    assert_eq!(
        manager.dispatch_prompt(&target, "late").await,
        Err(PromptError::Rejected(Rejection::Stopping))
    );
    assert_eq!(
        manager.dispatch_message(&text("late")).rejected,
        vec![("cal.stale".to_string(), Rejection::Stopping)]
    );
    assert!(matches!(
        plugin_ctx.spawn_task("late", |_| async { Ok(()) }),
        Err(SpawnError::Stopping)
    ));
    assert_eq!(
        plugin_ctx
            .send_message(
                "peer",
                text("late"),
                DeliveryOptions::new(DeliveryClass::FireAndForget)
            )
            .await,
        DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::Stopping
        }
    );

    // Contexts hold only a weak manager reference: once the host drops the
    // manager, a retained context cannot keep it alive or reach it.
    let weak = Arc::downgrade(&manager);
    drop(manager);
    within(async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        plugin_ctx
            .send_message(
                "peer",
                text("gone"),
                DeliveryOptions::new(DeliveryClass::FireAndForget)
            )
            .await,
        DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::Unavailable
        }
    );
    assert_eq!(
        plugin_ctx.connected_peer_ids().await,
        Err(Rejection::Unavailable)
    );
}

struct TaskLimitPlugin {
    activated: mpsc::UnboundedSender<&'static str>,
    third: Arc<Mutex<Option<SpawnError>>>,
}

#[async_trait]
impl Plugin for TaskLimitPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.tasks"
    }

    fn max_managed_tasks(&self) -> usize {
        2
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        for name in ["first", "second"] {
            let activated = self.activated.clone();
            ctx.spawn_task(name, move |task| async move {
                if task.activated().await.is_ok() {
                    let _ = activated.send(name);
                    task.cancelled().await;
                }
                Ok(())
            })
            .map_err(|error| PluginError::new(error.to_string()))?;
        }
        let third = ctx.spawn_task("third", |_| async { Ok(()) });
        *self.third.lock().unwrap() = third.err();
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_managed_tasks_are_bounded_and_wait_for_activation() {
    let dir = tempfile::tempdir().unwrap();
    let (activated_tx, mut activated_rx) = mpsc::unbounded_channel();
    let third = Arc::new(Mutex::new(None));
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "task-node"), "task-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(TaskLimitPlugin {
            activated: activated_tx,
            third: third.clone(),
        }))
        .unwrap();
    let manager = Arc::new(manager);
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    assert_eq!(
        *third.lock().unwrap(),
        Some(SpawnError::Overloaded { limit: 2 })
    );
    assert!(
        activated_rx.try_recv().is_err(),
        "tasks wait for activation"
    );

    manager.activate().unwrap();
    let mut names = HashSet::new();
    names.insert(within(activated_rx.recv()).await.unwrap());
    names.insert(within(activated_rx.recv()).await.unwrap());
    assert_eq!(names, HashSet::from(["first", "second"]));

    let report = within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();
    assert!(report.is_clean(), "{report:?}");
}

/// Each message is completed by a managed worker task, so draining needs the
/// task scope to keep running until the inbox is empty.
struct WorkerBackedPlugin {
    requests: Mutex<Option<mpsc::UnboundedSender<tokio::sync::oneshot::Sender<()>>>>,
    processed: Arc<AtomicUsize>,
}

#[async_trait]
impl Plugin for WorkerBackedPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.drain"
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        let (tx, mut rx) = mpsc::unbounded_channel::<tokio::sync::oneshot::Sender<()>>();
        *self.requests.lock().unwrap() = Some(tx);
        ctx.spawn_task("worker", move |task| async move {
            loop {
                tokio::select! {
                    request = rx.recv() => match request {
                        Some(reply) => { let _ = reply.send(()); }
                        None => break,
                    },
                    _ = task.cancelled() => break,
                }
            }
            Ok(())
        })
        .map_err(|error| PluginError::new(error.to_string()))?;
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let sender = self.requests.lock().unwrap().clone();
        if let Some(sender) = sender {
            let _ = sender.send(reply_tx);
            if reply_rx.await.is_ok() {
                self.processed.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_drain_finishes_admitted_messages_before_scope_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let processed = Arc::new(AtomicUsize::new(0));
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "drain-node"), "drain-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(WorkerBackedPlugin {
            requests: Mutex::new(None),
            processed: processed.clone(),
        }))
        .unwrap();
    let manager = Arc::new(manager);
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    manager.activate().unwrap();

    for index in 0..3 {
        assert_eq!(
            manager.dispatch_message(&text(&index.to_string())).admitted,
            1
        );
    }
    let shutdown = manager.begin_shutdown(ShutdownMode::Drain);
    // No new inbound work is admitted once stopping begins.
    assert_eq!(
        manager.dispatch_message(&text("late")).rejected,
        vec![("cal.drain".to_string(), Rejection::Stopping)]
    );
    let report = within(shutdown.wait()).await.unwrap();
    assert_eq!(processed.load(Ordering::SeqCst), 3);
    assert_eq!(report.plugins[0].discarded_messages, 0);
    assert!(report.is_clean(), "{report:?}");
}

struct WaitingPromptPlugin {
    entered: Arc<Notify>,
}

#[async_trait]
impl Plugin for WaitingPromptPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.prompt"
    }

    fn prompt_prefix(&self) -> Option<&str> {
        Some("waiting")
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}

    async fn on_prompt(&self, _input: &str, _ctx: &PluginContext) -> Option<String> {
        self.entered.notify_one();
        std::future::pending::<()>().await;
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_prompts_are_bounded_and_cancelled_by_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let entered = Arc::new(Notify::new());
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "prompt-node"), "prompt-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .set_options(PluginHostOptions {
            prompt_capacity: 1,
            ..PluginHostOptions::default()
        })
        .unwrap();
    manager
        .register_handler(Box::new(WaitingPromptPlugin {
            entered: entered.clone(),
        }))
        .unwrap();
    let manager = Arc::new(manager);
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    manager.activate().unwrap();
    let target = manager.resolve_prompt("waiting").unwrap();

    let first = tokio::spawn({
        let manager = manager.clone();
        let target = target.clone();
        async move { manager.dispatch_prompt(&target, "one").await }
    });
    within(entered.notified()).await;
    assert_eq!(
        manager.dispatch_prompt(&target, "two").await,
        Err(PromptError::Rejected(Rejection::Overloaded))
    );

    let report = within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();
    assert_eq!(first.await.unwrap(), Err(PromptError::Cancelled));
    assert!(report.is_clean(), "{report:?}");
}

struct HungStopPlugin;

#[async_trait]
impl Plugin for HungStopPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.hung-stop"
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}

    async fn on_stop(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_escalation_records_failed_quiescence() {
    let mut events = events();
    let dir = tempfile::tempdir().unwrap();
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "hung-node"), "hung-node");
    let mut manager = PluginManager::with_context(ctx);
    manager.register_handler(Box::new(HungStopPlugin)).unwrap();
    let manager = Arc::new(manager);
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    manager.activate().unwrap();

    let shutdown = manager.begin_shutdown(ShutdownMode::Drain);
    // No deadline: the host reports where it waits, and the application decides.
    events
        .wait_for_detail(Some("cal.hung-stop"), "plugin_waiting", "phase=stop")
        .await;
    manager.escalate();
    let report = within(shutdown.wait()).await.unwrap();
    assert!(report.escalated);
    assert_eq!(
        report.plugins[0].stop,
        StopResult::FailedToQuiesce(QuiescePhase::Stop)
    );
    assert_eq!(report.plugins[0].final_state, PluginState::Stopping);
    events
        .wait_for_detail(
            Some("cal.hung-stop"),
            "plugin_failed_to_quiesce",
            "phase=stop",
        )
        .await;
}

struct DefaultsPlugin {
    id: &'static str,
    realm: &'static str,
    prefix: Option<&'static str>,
}

#[async_trait]
impl Plugin for DefaultsPlugin {
    fn plugin_id(&self) -> &'static str {
        self.id
    }

    fn prompt_prefix(&self) -> Option<&str> {
        self.prefix
    }

    fn early_config_defaults(&self) -> Option<ConfigDefaults> {
        Some(ConfigDefaults {
            realm: Some(RealmInfo::new(self.realm, "1")),
            bootstrap_nodes_extend: Some(vec![format!("{}.invalid:1", self.id)]),
            ..Default::default()
        })
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

#[test]
fn cal_registration_rejects_conflicts_and_invalid_ids() {
    let mut manager = PluginManager::new();
    manager
        .register_handler(Box::new(DefaultsPlugin {
            id: "cal.defaults.a",
            realm: "shared",
            prefix: Some("shared"),
        }))
        .unwrap();
    // Same value for a single-valued field and additive lists merge.
    manager
        .register_handler(Box::new(DefaultsPlugin {
            id: "cal.defaults.b",
            realm: "shared",
            prefix: None,
        }))
        .unwrap();
    assert_eq!(
        manager.register_handler(Box::new(DefaultsPlugin {
            id: "cal.defaults.c",
            realm: "different",
            prefix: None,
        })),
        Err(PluginRegistrationError::ConflictingDefaults {
            plugin_id: "cal.defaults.c".to_string(),
            other_plugin_id: "cal.defaults.a".to_string(),
            field: "realm",
        })
    );
    assert!(matches!(
        manager.register_handler(Box::new(DefaultsPlugin {
            id: "cal.defaults.d",
            realm: "shared",
            prefix: Some("shared"),
        })),
        Err(PluginRegistrationError::DuplicatePromptPrefix { .. })
    ));
    assert!(matches!(
        manager.register_handler(Box::new(DefaultsPlugin {
            id: "../escape",
            realm: "shared",
            prefix: None,
        })),
        Err(PluginRegistrationError::InvalidId { .. })
    ));
    let merged = manager.collect_config_defaults();
    assert_eq!(
        merged.realm.map(|realm| realm.name),
        Some("shared".to_string())
    );
    assert_eq!(
        merged.bootstrap_nodes_extend,
        Some(vec![
            "cal.defaults.a.invalid:1".to_string(),
            "cal.defaults.b.invalid:1".to_string()
        ])
    );
    assert_eq!(
        manager.plugin_ids(),
        vec!["cal.defaults.a".to_string(), "cal.defaults.b".to_string()]
    );
}

#[tokio::test]
async fn cal_shutdown_before_start_reports_not_started() {
    let mut manager = PluginManager::new();
    manager
        .register_handler(Box::new(DefaultsPlugin {
            id: "cal.unstarted",
            realm: "shared",
            prefix: None,
        }))
        .unwrap();
    let manager = Arc::new(manager);
    let report = within(manager.shutdown(ShutdownMode::Drain)).await.unwrap();
    assert_eq!(report.plugins[0].stop, StopResult::NotStarted);
    assert_eq!(report.plugins[0].final_state, PluginState::Registered);
    assert!(report.is_clean());
}

/// Fails on any message and takes its time to clean up.
struct SlowCleanupPlugin {
    stop_entered: Arc<Notify>,
    release: Arc<Notify>,
    stopped: Arc<AtomicUsize>,
}

#[async_trait]
impl Plugin for SlowCleanupPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.slow-cleanup"
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {
        panic!("slow cleanup plugin fails");
    }

    async fn on_stop(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.stop_entered.notify_one();
        self.release.notified().await;
        self.stopped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_shutdown_joins_a_running_isolation_cleanup() {
    let mut events = events();
    let dir = tempfile::tempdir().unwrap();
    let stop_entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let stopped = Arc::new(AtomicUsize::new(0));
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "join-node"), "join-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(SlowCleanupPlugin {
            stop_entered: stop_entered.clone(),
            release: release.clone(),
            stopped: stopped.clone(),
        }))
        .unwrap();
    let manager = Arc::new(manager);
    let mut failures = manager.subscribe_failures();
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    manager.activate().unwrap();

    manager.dispatch_message(&text("fail"));
    let failure = within(failures.recv()).await.unwrap();
    assert_eq!(failure.phase, FailurePhase::Message);
    // The isolation cleanup is running the stop hook when shutdown begins.
    within(stop_entered.notified()).await;
    let shutdown = manager.begin_shutdown(ShutdownMode::Drain);
    events
        .wait_for_detail(Some("cal.slow-cleanup"), "plugin_waiting", "phase=cleanup")
        .await;
    release.notify_one();

    let report = within(shutdown.wait()).await.unwrap();
    assert!(!report.escalated, "{report:?}");
    assert_eq!(report.plugins[0].stop, StopResult::Stopped, "{report:?}");
    assert_eq!(report.plugins[0].failure.as_ref(), Some(&failure));
    assert_eq!(
        stopped.load(Ordering::SeqCst),
        1,
        "the stop hook ran once, to completion"
    );
}

/// The message handler waits for work that its managed worker task would
/// complete; the worker fails instead.
struct DependentWorkPlugin {
    fail_worker: Arc<Notify>,
    handler_waiting: Arc<Notify>,
    never_completed: Arc<Notify>,
}

#[async_trait]
impl Plugin for DependentWorkPlugin {
    fn plugin_id(&self) -> &'static str {
        "cal.dependent"
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        let fail_worker = self.fail_worker.clone();
        ctx.spawn_task("worker", move |_task| async move {
            fail_worker.notified().await;
            Err(PluginError::new("worker failed"))
        })
        .map_err(|error| PluginError::new(error.to_string()))?;
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {
        self.handler_waiting.notify_one();
        self.never_completed.notified().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cal_task_failure_during_drain_cancels_dependent_callbacks() {
    let dir = tempfile::tempdir().unwrap();
    let fail_worker = Arc::new(Notify::new());
    let handler_waiting = Arc::new(Notify::new());
    let (ctx, _pm) = host_context(&temp_config(dir.path(), "dependent-node"), "dependent-node");
    let mut manager = PluginManager::with_context(ctx);
    manager
        .register_handler(Box::new(DependentWorkPlugin {
            fail_worker: fail_worker.clone(),
            handler_waiting: handler_waiting.clone(),
            never_completed: Arc::new(Notify::new()),
        }))
        .unwrap();
    let manager = Arc::new(manager);
    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    manager.activate().unwrap();

    assert_eq!(manager.dispatch_message(&text("work")).admitted, 1);
    within(handler_waiting.notified()).await;
    // Draining waits for the handler; the worker it depends on then fails.
    let shutdown = manager.begin_shutdown(ShutdownMode::Drain);
    fail_worker.notify_one();

    let report = within(shutdown.wait()).await.unwrap();
    assert!(!report.escalated, "{report:?}");
    let plugin = &report.plugins[0];
    assert_eq!(plugin.final_state, PluginState::Failed);
    assert_eq!(
        plugin.failure.as_ref().map(|failure| failure.phase),
        Some(FailurePhase::Task)
    );
    assert_eq!(plugin.stop, StopResult::Stopped);
}

// ---------------------------------------------------------------------------
// Native fixtures
// ---------------------------------------------------------------------------

struct Fixtures {
    lifecycle: PathBuf,
    kvstore: PathBuf,
    legacy_no_version: PathBuf,
    legacy_abi3: PathBuf,
}

static FIXTURES: OnceLock<Result<Fixtures, String>> = OnceLock::new();

/// TheNodes features of this test binary. Fixtures are built with the same set.
fn host_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "noise") {
        features.push("noise");
    }
    if cfg!(feature = "upnp") {
        features.push("upnp");
    }
    features
}

fn fixture_root() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let features = host_features();
    let key = if features.is_empty() {
        "default".to_string()
    } else {
        features.join("-")
    };
    // Keep fixtures next to this test binary's target directory and separate
    // them per Cargo toolchain, so runs with another toolchain or target
    // directory never load each other's artifacts.
    let exe = std::env::current_exe().expect("test binary path");
    let target = exe
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("test binary lives in <target>/<profile>/deps");
    let mut toolchain = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(env!("CARGO"), &mut toolchain);
    target.join("plugin-fixtures").join(format!(
        "{profile}-{key}-{:016x}",
        std::hash::Hasher::finish(&toolchain)
    ))
}

fn build_package(package: &str, features: &[&str]) -> Result<PathBuf, String> {
    let target_dir = fixture_root();
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["build", "--locked", "--package", package, "--target-dir"])
        .arg(&target_dir);
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    if !features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to run cargo for {package}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "building fixture {package} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let artifact = target_dir.join(profile).join(format!(
        "{}{}{}",
        std::env::consts::DLL_PREFIX,
        package.replace('-', "_"),
        std::env::consts::DLL_SUFFIX
    ));
    if !artifact.is_file() {
        return Err(format!("fixture artifact missing: {}", artifact.display()));
    }
    Ok(artifact)
}

/// Copy an artifact to a stable name so later builds cannot replace it.
fn keep(artifact: &Path, name: &str) -> Result<PathBuf, String> {
    let dir = fixture_root().join("artifacts");
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let target = dir.join(format!(
        "{}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    std::fs::copy(artifact, &target).map_err(|error| error.to_string())?;
    Ok(target)
}

fn build_fixtures() -> Result<Fixtures, String> {
    let features = host_features();
    println!(
        "building native fixtures with cargo={} features={:?} target={}",
        env!("CARGO"),
        features,
        fixture_root().display()
    );
    let lifecycle = keep(
        &build_package("thenodes-plugin-lifecycle-fixture", &features)?,
        "lifecycle_fixture",
    )?;
    let kvstore = keep(
        &build_package("kvstore_plugin", &features)?,
        "kvstore_plugin",
    )?;
    let legacy_no_version = keep(
        &build_package("thenodes-plugin-legacy-fixture", &[])?,
        "legacy_no_version",
    )?;
    let legacy_abi3 = keep(
        &build_package("thenodes-plugin-legacy-fixture", &["version-export"])?,
        "legacy_abi3",
    )?;
    Ok(Fixtures {
        lifecycle,
        kvstore,
        legacy_no_version,
        legacy_abi3,
    })
}

fn fixtures() -> &'static Fixtures {
    match FIXTURES.get_or_init(build_fixtures) {
        Ok(fixtures) => fixtures,
        Err(error) => panic!("{error}"),
    }
}

// ---------------------------------------------------------------------------
// Child processes and the harness watchdog
// ---------------------------------------------------------------------------

const CHILD_SCENARIO: &str = "THENODES_LIFECYCLE_SCENARIO";
const WATCHDOG: Duration = Duration::from_secs(180);

fn kill_process(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status();
}

/// Kills `pid` if `done` is not signalled before the watchdog limit. Returns
/// whether it fired.
fn watchdog(pid: u32) -> (std_mpsc::Sender<()>, std::thread::JoinHandle<bool>) {
    let (done_tx, done_rx) = std_mpsc::channel::<()>();
    let handle = std::thread::spawn(move || match done_rx.recv_timeout(WATCHDOG) {
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            kill_process(pid);
            true
        }
        _ => false,
    });
    (done_tx, handle)
}

fn describe(output: &Output) -> String {
    format!(
        "status: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Run one scenario of this test binary in a child process.
fn run_child(scenario: &str, envs: &[(&str, &Path)], mode: &str) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "child_entry",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_SCENARIO, scenario)
        .env("FIXTURE_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let child = command.spawn().expect("child process starts");
    let (done, guard) = watchdog(child.id());
    let output = child.wait_with_output().expect("child output");
    let _ = done.send(());
    let hung = guard.join().unwrap();
    assert!(
        !hung,
        "scenario {scenario} ({mode}) hung and was killed by the harness watchdog\n{}",
        describe(&output)
    );
    assert!(
        output.status.success(),
        "scenario {scenario} ({mode}) failed\n{}",
        describe(&output)
    );
}

/// Entry point for child processes; a no-op in the normal test run.
#[test]
fn child_entry() {
    let Ok(scenario) = std::env::var(CHILD_SCENARIO) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("host-runtime")
        .enable_all()
        .build()
        .unwrap();
    let mode = std::env::var("FIXTURE_MODE").unwrap_or_default();
    runtime.block_on(async move {
        match scenario.as_str() {
            "native_runtime_proof" => native_runtime_proof().await,
            "native_start_failure" => native_start_failure(&mode).await,
            "native_execution_failure" => native_execution_failure(&mode).await,
            "native_stop_failure" => native_stop_failure(&mode).await,
            "native_registration_failure" => native_registration_failure(&mode),
            "native_abi_rejection" => native_abi_rejection(),
            "native_delivery" => native_delivery().await,
            "native_kvstore" => native_kvstore().await,
            other => panic!("unknown scenario {other}"),
        }
    });
}

fn fixture_env(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by the parent")))
}

struct NativeHost {
    manager: Arc<PluginManager>,
    peer_manager: Arc<PeerManager>,
    config: Config,
    _dir: tempfile::TempDir,
}

/// Load a native library into a fresh manager with a finalized context.
fn native_host(library: &Path, node_id: &str, cal: Option<Box<dyn Plugin>>) -> NativeHost {
    let dir = tempfile::tempdir().unwrap();
    let config = temp_config(dir.path(), node_id);
    let mut manager = PluginManager::new();
    if let Some(plugin) = cal {
        manager.register_handler(plugin).unwrap();
    }
    let before = pinned_library_count();
    PluginLoader::new()
        .load_library(library, &mut manager)
        .expect("fixture library loads");
    assert_eq!(pinned_library_count(), before + 1, "loaded code is pinned");
    let (ctx, peer_manager) = host_context(&config, node_id);
    manager.set_context(ctx);
    NativeHost {
        manager: Arc::new(manager),
        peer_manager,
        config,
        _dir: dir,
    }
}

async fn start_and_activate(host: &NativeHost) {
    let report = within(host.manager.start_all(StartPolicy::StopOnFirstFailure))
        .await
        .unwrap();
    assert!(report.all_started(), "{report:?}");
    host.manager.activate().unwrap();
}

/// CAL handler registered next to a native library (hybrid host).
struct HybridProbe {
    thread: mpsc::UnboundedSender<String>,
}

#[async_trait]
impl Plugin for HybridProbe {
    fn plugin_id(&self) -> &'static str {
        "hybrid.cal"
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&[])
    }

    async fn on_start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        let name = std::thread::current().name().unwrap_or("").to_string();
        let _ = self.thread.send(name);
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

async fn native_runtime_proof() {
    let mut events = events();
    let (thread_tx, mut thread_rx) = mpsc::unbounded_channel();
    let host = native_host(
        &fixture_env("FIXTURE_LIB"),
        "native-node",
        Some(Box::new(HybridProbe { thread: thread_tx })),
    );
    assert_eq!(
        host.manager.plugin_ids(),
        vec![
            "hybrid.cal".to_string(),
            ALPHA.to_string(),
            BETA.to_string()
        ]
    );
    start_and_activate(&host).await;

    // The CAL handler runs on the host runtime; native handlers on the
    // library runtime, with only data and host services in their context.
    let cal_thread = within(thread_rx.recv()).await.unwrap();
    assert_eq!(cal_thread, "host-runtime");
    let proof = events.wait_for(Some(ALPHA), "fixture_runtime_proof").await;
    assert!(proof.detail.contains("thread=thenodes-plugin"), "{proof:?}");
    assert!(
        proof
            .detail
            .contains("timer=ok interval=ok fs=true udp=true low_level=false"),
        "{proof:?}"
    );
    assert!(
        proof
            .detail
            .contains("node_id=native-node plugin_id=fixture.alpha"),
        "{proof:?}"
    );
    let activated = events.wait_for(Some(ALPHA), "fixture_task_activated").await;
    assert!(activated.detail.contains("thread=thenodes-plugin"));

    let target = host.manager.resolve_prompt("alpha").unwrap();
    let reply = within(host.manager.dispatch_prompt(&target, "echo"))
        .await
        .unwrap()
        .unwrap();
    assert!(
        reply.starts_with("alpha:echo thread=thenodes-plugin"),
        "{reply}"
    );

    // A cooperative stall in one handler does not delay another handler of
    // the same library.
    assert_eq!(
        host.manager
            .dispatch_message(&extension("fixture.stall", None))
            .admitted,
        1
    );
    events.wait_for(Some(ALPHA), "fixture_stalled").await;
    assert_eq!(
        host.manager
            .dispatch_message(&extension("fixture.ping", None))
            .admitted,
        1
    );
    let pong = events.wait_for(Some(BETA), "fixture_pong").await;
    assert!(pong.detail.contains("thread=thenodes-plugin"));

    // Dropping a host-side waiter cancels the plugin-side job, and the job's
    // future is destroyed on the plugin runtime.
    let waiter = tokio::spawn({
        let manager = host.manager.clone();
        let target = target.clone();
        async move { manager.dispatch_prompt(&target, "wait").await }
    });
    events.wait_for(Some(ALPHA), "fixture_prompt_waiting").await;
    waiter.abort();
    let _ = waiter.await;
    events.wait_for(Some(ALPHA), "fixture_prompt_dropped").await;

    let report = within(host.manager.shutdown(ShutdownMode::Discard))
        .await
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.runtimes_released, 1);
    assert_eq!(report.runtimes_retained, 0);
    events.wait_for(Some(ALPHA), "fixture_stall_dropped").await;
    events.wait_for(Some(ALPHA), "fixture_task_cancelled").await;
    events.wait_for(Some(ALPHA), "fixture_stopped").await;
    events.wait_for(Some(BETA), "fixture_stopped").await;
    assert!(
        events.index_of(Some(BETA), "fixture_stopped")
            < events.index_of(Some(ALPHA), "fixture_stopped"),
        "stop hooks run in reverse start order"
    );
}

async fn native_start_failure(mode: &str) {
    let mut events = events();
    let host = native_host(&fixture_env("FIXTURE_LIB"), "native-node", None);
    let mut failures = host.manager.subscribe_failures();
    let report = within(host.manager.start_all(StartPolicy::ContinueOnFailure))
        .await
        .unwrap();
    let StartResult::Failed(failure) = &report.outcomes[0].result else {
        panic!("{ALPHA} must fail to start: {report:?}");
    };
    match mode {
        "start-panic" => {
            assert_eq!(
                failure.cause,
                FailureCause::Panic("fixture start panic".to_string())
            )
        }
        "start-error" => {
            assert_eq!(
                failure.cause,
                FailureCause::Error("fixture start error".to_string())
            )
        }
        other => panic!("unexpected mode {other}"),
    }
    assert_eq!(report.outcomes[1].result, StartResult::Started);
    assert_eq!(within(failures.recv()).await.as_ref(), Some(failure));
    // The failed plugin was rolled back on its own: its cleanup ran.
    events.wait_for(Some(ALPHA), "fixture_stopped").await;

    assert_eq!(
        host.manager.activate(),
        Err(ActivationError::UnacknowledgedFailures(vec![
            ALPHA.to_string()
        ]))
    );
    host.manager.acknowledge_failure(ALPHA).unwrap();
    host.manager.activate().unwrap();
    assert_eq!(
        host.manager
            .dispatch_message(&extension("fixture.stall", None))
            .rejected,
        vec![(ALPHA.to_string(), Rejection::Unavailable)]
    );
    host.manager
        .dispatch_message(&extension("fixture.ping", None));
    events.wait_for(Some(BETA), "fixture_pong").await;

    let report = within(host.manager.shutdown(ShutdownMode::Drain))
        .await
        .unwrap();
    assert_eq!(report.plugins[0].final_state, PluginState::Failed);
    assert_eq!(report.plugins[0].stop, StopResult::Stopped);
    assert_eq!(report.plugins[1].final_state, PluginState::Stopped);
    assert_eq!(report.runtimes_released, 1);
}

async fn native_execution_failure(mode: &str) {
    let mut events = events();
    let host = native_host(&fixture_env("FIXTURE_LIB"), "native-node", None);
    let mut failures = host.manager.subscribe_failures();
    start_and_activate(&host).await;
    events.wait_for(Some(ALPHA), "fixture_task_activated").await;

    let (phase, cause) = match mode {
        "message-panic" => {
            host.manager
                .dispatch_message(&extension("fixture.panic", None));
            (
                FailurePhase::Message,
                FailureCause::Panic("fixture message panic".to_string()),
            )
        }
        "prompt-panic" => {
            let target = host.manager.resolve_prompt("alpha").unwrap();
            let result = within(host.manager.dispatch_prompt(&target, "panic")).await;
            assert!(matches!(result, Err(PromptError::Failed(_))), "{result:?}");
            (
                FailurePhase::Prompt,
                FailureCause::Panic("fixture prompt panic".to_string()),
            )
        }
        "task-panic" => (
            FailurePhase::Task,
            FailureCause::Panic("fixture task panic".to_string()),
        ),
        "task-error" => (
            FailurePhase::Task,
            FailureCause::Error("fixture task error".to_string()),
        ),
        other => panic!("unexpected mode {other}"),
    };
    // The panic was caught in the plugin's code copy and arrives as data.
    let failure = within(failures.recv()).await.unwrap();
    assert_eq!(failure.plugin_id, ALPHA);
    assert_eq!(failure.phase, phase);
    assert_eq!(failure.cause, cause);

    // Only the failed plugin is isolated; its cleanup runs.
    events.wait_for(Some(ALPHA), "fixture_stopped").await;
    assert_eq!(host.manager.plugin_state(ALPHA), Some(PluginState::Failed));
    assert_eq!(
        host.manager
            .dispatch_message(&extension("fixture.stall", None))
            .rejected,
        vec![(ALPHA.to_string(), Rejection::Unavailable)]
    );
    host.manager
        .dispatch_message(&extension("fixture.ping", None));
    events.wait_for(Some(BETA), "fixture_pong").await;

    let report = within(host.manager.shutdown(ShutdownMode::Drain))
        .await
        .unwrap();
    assert_eq!(report.plugins[0].failure.as_ref(), Some(&failure));
    assert_eq!(report.plugins[0].stop, StopResult::Stopped);
    assert_eq!(report.plugins[1].stop, StopResult::Stopped);
    assert_eq!(report.runtimes_released, 1);
}

async fn native_stop_failure(mode: &str) {
    let host = native_host(&fixture_env("FIXTURE_LIB"), "native-node", None);
    start_and_activate(&host).await;
    let report = within(host.manager.shutdown(ShutdownMode::Drain))
        .await
        .unwrap();
    let alpha = &report.plugins[0];
    match mode {
        "stop-panic" => {
            assert_eq!(
                alpha.stop,
                StopResult::Panicked("fixture stop panic".to_string())
            )
        }
        "stop-error" => assert_eq!(
            alpha.stop,
            StopResult::HookFailed("fixture stop error".to_string())
        ),
        other => panic!("unexpected mode {other}"),
    }
    assert_eq!(alpha.final_state, PluginState::Failed);
    assert_eq!(
        alpha.failure.as_ref().map(|failure| failure.phase),
        Some(FailurePhase::Stop)
    );
    assert_eq!(report.plugins[1].stop, StopResult::Stopped);
    assert!(!report.is_clean());
    assert_eq!(report.runtimes_released, 1);
}

fn native_registration_failure(mode: &str) {
    let mut manager = PluginManager::new();
    let error = PluginLoader::new()
        .load_library(fixture_env("FIXTURE_LIB"), &mut manager)
        .expect_err("registration must fail");
    let PluginLoadError::Registration { error, .. } = error else {
        panic!("expected a registration error, got {error:?}");
    };
    match mode {
        "duplicate-id" => assert_eq!(
            error,
            PluginRegistrationError::DuplicateId {
                plugin_id: ALPHA.to_string()
            }
        ),
        "invalid-id" | "partial" => assert!(
            matches!(&error, PluginRegistrationError::InvalidId { plugin_id, .. } if plugin_id == "fixture/invalid"),
            "{error:?}"
        ),
        "empty" => assert_eq!(error, PluginRegistrationError::NoPlugins),
        "register-panic" => assert_eq!(
            error,
            PluginRegistrationError::Native(RegistrationStatus::Panicked)
        ),
        "register-error" => assert_eq!(
            error,
            PluginRegistrationError::Native(RegistrationStatus::PluginError)
        ),
        "zero-workers" => assert_eq!(
            error,
            PluginRegistrationError::Native(RegistrationStatus::InvalidRuntimeConfig)
        ),
        "conflicting-defaults" => assert_eq!(
            error,
            PluginRegistrationError::ConflictingDefaults {
                plugin_id: BETA.to_string(),
                other_plugin_id: ALPHA.to_string(),
                field: "realm",
            }
        ),
        other => panic!("unexpected mode {other}"),
    }
    // No partial registration becomes host configuration, and the library
    // stays pinned because its initialization already ran.
    assert!(manager.plugin_ids().is_empty());
    assert!(manager.native_libraries().is_empty());
    assert_eq!(pinned_library_count(), 1);
}

fn native_abi_rejection() {
    let mut manager = PluginManager::new();
    let mut loader = PluginLoader::new();
    // A library without the version query is rejected before `register_plugin`
    // runs; calling it would abort this process.
    let error = loader
        .load_library(fixture_env("LEGACY_NO_VERSION"), &mut manager)
        .unwrap_err();
    assert!(
        matches!(
            error,
            PluginLoadError::MissingSymbol {
                symbol: "thenodes_plugin_abi_version",
                ..
            }
        ),
        "{error:?}"
    );
    let error = loader
        .load_library(fixture_env("LEGACY_ABI3"), &mut manager)
        .unwrap_err();
    assert!(
        matches!(error, PluginLoadError::AbiMismatch { expected, found: 3, .. } if expected == PLUGIN_ABI_VERSION),
        "{error:?}"
    );
    let error = loader
        .load_library(fixture_env("FIXTURE_DIR").join("missing.so"), &mut manager)
        .unwrap_err();
    assert!(matches!(error, PluginLoadError::Open { .. }), "{error:?}");
    assert!(manager.plugin_ids().is_empty());
    assert_eq!(pinned_library_count(), 2);
}

struct Recorder {
    received: mpsc::UnboundedSender<Message>,
}

#[async_trait]
impl Plugin for Recorder {
    fn plugin_id(&self) -> &'static str {
        "peer.recorder"
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        Some(&["fixture.hello"])
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        if matches!(&message.msg_type, MessageType::Extension { kind } if kind == "fixture.hello") {
            let _ = self.received.send(message.clone());
        }
    }
}

async fn native_delivery() {
    let mut events = events();
    let realm = RealmInfo::new("fixture-realm", "1");

    // Node B: a statically linked host with a recording plugin.
    let b_dir = tempfile::tempdir().unwrap();
    let mut b_config = temp_config(b_dir.path(), "node-b");
    b_config.realm = Some(realm.clone());
    let listener = bind_listener(0, false).await.unwrap();
    let b_port = listener.local_addr().unwrap().port();
    b_config.port = b_port;
    let (received_tx, mut received_rx) = mpsc::unbounded_channel();
    let (b_ctx, b_peer_manager) = host_context(&b_config, "node-b");
    let mut b_manager = PluginManager::with_context(b_ctx);
    b_manager
        .register_handler(Box::new(Recorder {
            received: received_tx,
        }))
        .unwrap();
    let b_manager = Arc::new(b_manager);
    within(b_manager.start_all(StartPolicy::StopOnFirstFailure))
        .await
        .unwrap();
    b_manager.activate().unwrap();
    let b_listener = tokio::spawn({
        let peer_manager = (*b_peer_manager).clone();
        let manager = b_manager.clone();
        let config = b_config.clone();
        let realm = realm.clone();
        async move {
            let _ = run_listener(
                listener,
                realm,
                peer_manager,
                manager,
                &config,
                "node-b".to_string(),
                PeerStore::new(),
                false,
            )
            .await;
        }
    });

    // Node A: the native fixture.
    let mut host = native_host(&fixture_env("FIXTURE_LIB"), "node-a", None);
    host.config.realm = Some(realm.clone());
    start_and_activate(&host).await;
    let connection = tokio::spawn({
        let peer_manager = (*host.peer_manager).clone();
        let manager = host.manager.clone();
        let config = host.config.clone();
        let realm = realm.clone();
        async move {
            let peer = Peer::new("node-b".to_string(), format!("127.0.0.1:{b_port}"));
            connect_to_peer(ConnectToPeerParams {
                peer: &peer,
                our_realm: realm,
                our_port: 0,
                peer_manager,
                plugin_manager: manager,
                allow_console: false,
                config,
                local_node_id: "node-a".to_string(),
                peer_store: Some(PeerStore::new()),
            })
            .await
            .map_err(|error| error.to_string())
        }
    });
    within(async {
        while !host.peer_manager.has_node_id("node-b").await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    // Native code builds the message; delivery runs through host services.
    host.manager
        .dispatch_message(&extension("fixture.send", Some(json!({ "to": "node-b" }))));
    let outcome = events.wait_for(Some(ALPHA), "fixture_send_outcome").await;
    assert!(outcome.detail.contains("LocalAccepted"), "{outcome:?}");
    let hello = within(received_rx.recv()).await.unwrap();
    assert_eq!(hello.from, "node-a");
    let Some(Payload::Json(payload)) = &hello.payload else {
        panic!("hello carries a payload: {hello:?}");
    };
    assert!(payload["thread"]
        .as_str()
        .unwrap()
        .starts_with("thenodes-plugin"));

    // A reliable send keeps retrying on the host runtime after the plugin's
    // waiter is cancelled and its runtime is released.
    host.manager.dispatch_message(&extension(
        "fixture.send-reliable",
        Some(json!({ "to": "node-missing" })),
    ));
    events.wait_for(Some(ALPHA), "fixture_send_started").await;
    let report = within(host.manager.shutdown(ShutdownMode::Discard))
        .await
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.runtimes_released, 1);
    events.wait_for(None, "plugin_shutdown_complete").await;
    events.wait_for(Some(ALPHA), "plugin_send_failed").await;
    assert!(
        events.index_of(None, "plugin_shutdown_complete")
            < events.index_of(Some(ALPHA), "plugin_send_failed"),
        "delivery completed after the plugin runtime was released"
    );
    assert_eq!(events.index_of(Some(ALPHA), "fixture_send_finished"), None);

    within(b_manager.shutdown(ShutdownMode::Drain))
        .await
        .unwrap();
    b_listener.abort();
    connection.abort();
}

async fn native_kvstore() {
    let host = native_host(&fixture_env("FIXTURE_LIB"), "kv-node", None);
    start_and_activate(&host).await;
    let target = host.manager.resolve_prompt("kvstore").unwrap();
    assert_eq!(
        within(host.manager.dispatch_prompt(&target, "put color blue")).await,
        Ok(Some("📝 Stored and broadcast: color = blue".to_string()))
    );
    assert_eq!(
        within(host.manager.dispatch_prompt(&target, "get color")).await,
        Ok(Some("🔍 Result: Some(\"blue\")".to_string()))
    );
    let report = within(host.manager.shutdown(ShutdownMode::Drain))
        .await
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.runtimes_released, 1);
}

// ---------------------------------------------------------------------------
// Native scenario drivers (parent side)
// ---------------------------------------------------------------------------

#[test]
fn native_runtime_executes_plugin_callbacks_on_library_runtime() {
    let fixtures = fixtures();
    run_child(
        "native_runtime_proof",
        &[("FIXTURE_LIB", &fixtures.lifecycle)],
        "normal",
    );
}

#[test]
fn native_start_failures_are_isolated_and_reported() {
    let fixtures = fixtures();
    for mode in ["start-panic", "start-error"] {
        run_child(
            "native_start_failure",
            &[("FIXTURE_LIB", &fixtures.lifecycle)],
            mode,
        );
    }
}

#[test]
fn native_execution_panics_are_reported_as_data() {
    let fixtures = fixtures();
    for mode in ["message-panic", "prompt-panic", "task-panic", "task-error"] {
        run_child(
            "native_execution_failure",
            &[("FIXTURE_LIB", &fixtures.lifecycle)],
            mode,
        );
    }
}

#[test]
fn native_stop_failures_are_reported() {
    let fixtures = fixtures();
    for mode in ["stop-panic", "stop-error"] {
        run_child(
            "native_stop_failure",
            &[("FIXTURE_LIB", &fixtures.lifecycle)],
            mode,
        );
    }
}

#[test]
fn native_registration_failures_are_authoritative() {
    let fixtures = fixtures();
    for mode in [
        "duplicate-id",
        "invalid-id",
        "partial",
        "empty",
        "register-panic",
        "register-error",
        "zero-workers",
        "conflicting-defaults",
    ] {
        run_child(
            "native_registration_failure",
            &[("FIXTURE_LIB", &fixtures.lifecycle)],
            mode,
        );
    }
}

#[test]
fn native_loader_rejects_incompatible_libraries_before_registration() {
    let fixtures = fixtures();
    let dir = tempfile::tempdir().unwrap();
    run_child(
        "native_abi_rejection",
        &[
            ("LEGACY_NO_VERSION", &fixtures.legacy_no_version),
            ("LEGACY_ABI3", &fixtures.legacy_abi3),
            ("FIXTURE_DIR", dir.path()),
        ],
        "normal",
    );
}

#[test]
fn native_delivery_runs_on_host_runtime() {
    let fixtures = fixtures();
    run_child(
        "native_delivery",
        &[("FIXTURE_LIB", &fixtures.lifecycle)],
        "normal",
    );
}

#[test]
fn kvstore_example_runs_as_native_library() {
    let fixtures = fixtures();
    run_child(
        "native_kvstore",
        &[("FIXTURE_LIB", &fixtures.kvstore)],
        "normal",
    );
}

// ---------------------------------------------------------------------------
// Standalone host (real `thenodes` binary)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod standalone {
    use super::*;
    use std::process::Child;

    struct HostProcess {
        child: Child,
        lines: std_mpsc::Receiver<String>,
        received: Vec<String>,
        transcript: Arc<Mutex<Vec<String>>>,
        done: std_mpsc::Sender<()>,
        watchdog: std::thread::JoinHandle<bool>,
        _dir: tempfile::TempDir,
    }

    impl HostProcess {
        fn start(mode: &str) -> Self {
            let fixtures = fixtures();
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("plugins")).unwrap();
            std::fs::copy(
                &fixtures.lifecycle,
                dir.path().join("plugins").join(
                    fixtures
                        .lifecycle
                        .file_name()
                        .expect("fixture has a file name"),
                ),
            )
            .unwrap();
            std::fs::write(
                dir.path().join("config.toml"),
                "port = 0\n\n[node]\nid = \"standalone-node\"\nstate_dir = \"data\"\n",
            )
            .unwrap();

            let mut child = Command::new(env!("CARGO_BIN_EXE_thenodes"))
                .current_dir(dir.path())
                .env("FIXTURE_MODE", mode)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("host starts");
            let (tx, lines) = std_mpsc::channel();
            let transcript = Arc::new(Mutex::new(Vec::new()));
            for stream in [
                Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
                Box::new(child.stderr.take().unwrap()),
            ] {
                let tx = tx.clone();
                let transcript = transcript.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(stream).lines().map_while(Result::ok) {
                        transcript.lock().unwrap().push(line.clone());
                        let _ = tx.send(line);
                    }
                });
            }
            let (done, watchdog) = watchdog(child.id());
            Self {
                child,
                lines,
                received: Vec::new(),
                transcript,
                done,
                watchdog,
                _dir: dir,
            }
        }

        fn transcript(&self) -> String {
            self.transcript.lock().unwrap().join("\n")
        }

        /// Wait for an output line containing every needle, including lines
        /// that arrived earlier.
        fn wait_line(&mut self, needles: &[&str]) -> String {
            let matches = |line: &String| needles.iter().all(|needle| line.contains(needle));
            if let Some(line) = self.received.iter().find(|line| matches(line)) {
                return line.clone();
            }
            loop {
                match self.lines.recv() {
                    Ok(line) => {
                        self.received.push(line.clone());
                        if matches(&line) {
                            return line;
                        }
                    }
                    Err(_) => panic!(
                        "host output ended before a line containing {needles:?}\n{}",
                        self.transcript()
                    ),
                }
            }
        }

        fn interrupt(&self) {
            let status = Command::new("kill")
                .args(["-INT", &self.child.id().to_string()])
                .status()
                .unwrap();
            assert!(status.success());
        }

        fn finish(mut self) -> (std::process::ExitStatus, String) {
            let status = self.child.wait().unwrap();
            let _ = self.done.send(());
            // Let the reader threads flush the remaining output.
            while self.lines.recv().is_ok() {}
            let transcript = self.transcript();
            let hung = self.watchdog.join().unwrap();
            assert!(
                !hung,
                "host hung; killed by the harness watchdog\n{transcript}"
            );
            (status, transcript)
        }
    }

    #[test]
    fn standalone_host_starts_activates_and_stops_cleanly() {
        let mut host = HostProcess::start("normal");
        host.wait_line(&["is running"]);
        host.wait_line(&["fixture.alpha", "fixture_task_activated"]);
        host.interrupt();
        let (status, transcript) = host.finish();
        assert_eq!(status.code(), Some(0), "{transcript}");
        assert!(transcript.contains("clean=true"), "{transcript}");
        assert!(
            transcript.contains("plugin=fixture.alpha state=Stopped stop=Stopped"),
            "{transcript}"
        );
    }

    #[test]
    fn standalone_host_fails_startup_when_a_plugin_fails_to_start() {
        let host = HostProcess::start("start-error");
        let (status, transcript) = host.finish();
        assert_eq!(status.code(), Some(1), "{transcript}");
        assert!(transcript.contains("startup failed"), "{transcript}");
        assert!(transcript.contains("fixture start error"), "{transcript}");
        assert!(!transcript.contains("is running"), "{transcript}");
    }

    #[test]
    fn standalone_host_shuts_down_on_plugin_failure() {
        let host = HostProcess::start("task-panic");
        let (status, transcript) = host.finish();
        assert_eq!(status.code(), Some(1), "{transcript}");
        assert!(transcript.contains("is running"), "{transcript}");
        assert!(
            transcript.contains("plugin 'fixture.alpha' failed during task (panic)"),
            "{transcript}"
        );
    }

    #[test]
    fn standalone_host_shuts_down_when_a_task_fails_during_startup() {
        // fixture.alpha has started; its task fails while fixture.beta's start
        // hook is still running. The host must not wait for startup to finish.
        let host = HostProcess::start("start-task-panic");
        let (status, transcript) = host.finish();
        assert_eq!(status.code(), Some(1), "{transcript}");
        assert!(!transcript.contains("is running"), "{transcript}");
        assert!(transcript.contains("startup failed"), "{transcript}");
        assert!(
            transcript.contains("plugin 'fixture.alpha' failed during task (panic)"),
            "{transcript}"
        );
        assert!(
            transcript.contains("plugin=fixture.alpha state=Failed stop=Stopped"),
            "{transcript}"
        );
        assert!(
            transcript.contains("plugin=fixture.beta state=Stopped stop=Stopped"),
            "{transcript}"
        );
    }

    fn escalate_hung_stop(mode: &str) {
        let mut host = HostProcess::start(mode);
        host.wait_line(&["is running"]);
        host.interrupt();
        // No deadline: the host reports what it waits for.
        host.wait_line(&["fixture.alpha", "plugin_waiting", "phase=stop"]);
        host.interrupt();
        let (status, transcript) = host.finish();
        assert_eq!(status.code(), Some(1), "{transcript}");
        assert!(transcript.contains("escalated=true"), "{transcript}");
        assert!(
            transcript.contains("plugin=fixture.alpha state=Stopping stop=FailedToQuiesce(Stop)"),
            "{transcript}"
        );
    }

    #[test]
    fn standalone_host_escalates_non_yielding_stop_on_second_request() {
        escalate_hung_stop("hang-stop-spin");
    }

    #[test]
    fn standalone_host_escalates_blocking_stop_on_second_request() {
        escalate_hung_stop("hang-stop-block");
    }

    #[test]
    fn standalone_host_escalates_hung_startup_on_second_request() {
        let mut host = HostProcess::start("hang-start-spin");
        // Wait until the start hook is running, not merely scheduled.
        host.wait_line(&["fixture.alpha", "fixture_start_spinning"]);
        host.interrupt();
        host.wait_line(&["Shutting down"]);
        host.interrupt();
        let (status, transcript) = host.finish();
        assert_eq!(status.code(), Some(1), "{transcript}");
        assert!(!transcript.contains("is running"), "{transcript}");
        assert!(transcript.contains("escalated=true"), "{transcript}");
        assert!(
            transcript.contains("plugin=fixture.alpha state=Starting stop=FailedToQuiesce(Start)"),
            "{transcript}"
        );
        assert!(
            transcript.contains("plugin=fixture.beta state=Registered stop=NotStarted"),
            "{transcript}"
        );
    }
}
