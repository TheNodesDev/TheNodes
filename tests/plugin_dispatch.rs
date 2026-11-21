use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use thenodes::network::message::{Message, MessageType};
use thenodes::plugin_host::{
    Plugin, PluginContext, PluginHostOptions, PluginManager, PluginRegistrar,
    PluginRegistrationError, Rejection, ShutdownMode, StartPolicy, StopResult,
};
use tokio::sync::{mpsc, Notify};

fn plugin_context() -> PluginContext {
    PluginContext::new(
        Arc::new(thenodes::network::PeerManager::new()),
        thenodes::network::PeerStore::new(),
        thenodes::events::dispatcher::handle(),
        "local-node".to_string(),
        thenodes::config::Config::default(),
        false,
    )
}

/// Hang guard only: tests decide their outcome from notifications, and this
/// bound turns a lost notification into a failure instead of a stuck suite.
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("expected notification did not arrive")
}

async fn start_and_activate(manager: PluginManager) -> Arc<PluginManager> {
    let manager = Arc::new(manager);
    let report = manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .expect("startup should report");
    assert!(report.all_started(), "{report:?}");
    manager.activate().expect("activation should succeed");
    manager
}

fn extension(kind: &str) -> Message {
    Message::new(
        "peer-a",
        "local-node",
        MessageType::Extension {
            kind: kind.to_string(),
        },
        None,
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

struct AwaitingPlugin {
    started: Arc<Notify>,
    release: Arc<Notify>,
    completed: Arc<AtomicBool>,
    done: Arc<Notify>,
}

#[async_trait]
impl Plugin for AwaitingPlugin {
    fn plugin_id(&self) -> &'static str {
        "awaiting-plugin"
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {
        self.started.notify_one();
        self.release.notified().await;
        self.completed.store(true, Ordering::SeqCst);
        self.done.notify_one();
    }
}

#[tokio::test]
async fn dispatch_admits_without_waiting_for_plugin_completion() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let completed = Arc::new(AtomicBool::new(false));
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .register_handler(Box::new(AwaitingPlugin {
            started: started.clone(),
            release: release.clone(),
            completed: completed.clone(),
            done: done.clone(),
        }))
        .expect("plugin should register");
    let manager = start_and_activate(manager).await;

    let report = manager.dispatch_message(&Message::new(
        "peer-a",
        "local-node",
        MessageType::Heartbeat,
        None,
        None,
    ));
    assert_eq!(report.admitted, 1);
    assert!(report.rejected.is_empty());

    within(started.notified()).await;
    assert!(!completed.load(Ordering::SeqCst));
    release.notify_one();
    within(done.notified()).await;
    assert!(completed.load(Ordering::SeqCst));

    let report = within(manager.shutdown(ShutdownMode::Drain))
        .await
        .expect("shutdown should report");
    assert!(report.is_clean(), "{report:?}");
}

struct RecordingPlugin {
    plugin_id: &'static str,
    subscribed_kinds: Option<&'static [&'static str]>,
    received: mpsc::UnboundedSender<(String, String)>,
}

#[async_trait]
impl Plugin for RecordingPlugin {
    fn plugin_id(&self) -> &'static str {
        self.plugin_id
    }

    async fn on_message(&self, message: &Message, ctx: &PluginContext) {
        let description = match &message.msg_type {
            MessageType::Extension { kind } => kind.clone(),
            MessageType::Text(body) => body.clone(),
            _ => "other".to_string(),
        };
        let bound = ctx
            .plugin_id()
            .expect("plugin manager should bind plugin context")
            .to_string();
        assert_eq!(bound, self.plugin_id);
        let _ = self.received.send((bound, description));
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        self.subscribed_kinds
    }
}

#[tokio::test]
async fn dispatch_filters_extension_kinds_per_plugin() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut manager = PluginManager::with_context(plugin_context());
    for (plugin_id, kinds) in [
        (
            "records-updated-plugin",
            Some(&["records.updated"] as &'static [&'static str]),
        ),
        ("records-deleted-plugin", Some(&["records.deleted"] as _)),
        ("records-all-plugin", None),
    ] {
        manager
            .register_handler(Box::new(RecordingPlugin {
                plugin_id,
                subscribed_kinds: kinds,
                received: tx.clone(),
            }))
            .expect("plugin should register");
    }
    let manager = start_and_activate(manager).await;

    let report = manager.dispatch_message(&extension("records.updated"));
    assert_eq!(report.admitted, 2, "only subscribed plugins are offered");
    let report = manager.dispatch_message(&text("hello"));
    assert_eq!(
        report.admitted, 3,
        "non-extension messages reach every plugin"
    );

    let mut received = Vec::new();
    for _ in 0..5 {
        received.push(within(rx.recv()).await.expect("message handled"));
    }
    received.sort();
    assert_eq!(
        received,
        vec![
            ("records-all-plugin".to_string(), "hello".to_string()),
            (
                "records-all-plugin".to_string(),
                "records.updated".to_string()
            ),
            ("records-deleted-plugin".to_string(), "hello".to_string()),
            ("records-updated-plugin".to_string(), "hello".to_string()),
            (
                "records-updated-plugin".to_string(),
                "records.updated".to_string()
            ),
        ]
    );
    let report = within(manager.shutdown(ShutdownMode::Drain))
        .await
        .expect("shutdown should report");
    assert!(report.is_clean(), "{report:?}");
}

#[tokio::test]
async fn each_plugin_handles_its_messages_in_admission_order() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .register_handler(Box::new(RecordingPlugin {
            plugin_id: "ordered-plugin",
            subscribed_kinds: None,
            received: tx,
        }))
        .expect("plugin should register");
    let manager = start_and_activate(manager).await;

    for index in 0..20 {
        assert_eq!(
            manager.dispatch_message(&text(&index.to_string())).admitted,
            1
        );
    }
    for index in 0..20 {
        let (_, body) = within(rx.recv()).await.expect("message handled");
        assert_eq!(body, index.to_string());
    }
    within(manager.shutdown(ShutdownMode::Drain))
        .await
        .expect("shutdown should report");
}

#[tokio::test]
async fn register_handler_refuses_duplicate_plugin_ids() {
    // Two plugins sharing the same `plugin_id()` would otherwise silently share the
    // same isolated `plugin_data_dir()`, letting one clobber the other's on-disk
    // state. The second registration must be rejected and reported.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .register_handler(Box::new(RecordingPlugin {
            plugin_id: "duplicate-plugin",
            subscribed_kinds: None,
            received: tx.clone(),
        }))
        .expect("first registration succeeds");
    let error = manager
        .register_handler(Box::new(RecordingPlugin {
            plugin_id: "duplicate-plugin",
            subscribed_kinds: None,
            received: tx,
        }))
        .expect_err("duplicate registration must fail");
    assert_eq!(
        error,
        PluginRegistrationError::DuplicateId {
            plugin_id: "duplicate-plugin".to_string()
        }
    );
    assert_eq!(manager.plugin_ids(), vec!["duplicate-plugin".to_string()]);

    let manager = start_and_activate(manager).await;
    assert_eq!(manager.dispatch_message(&text("only-once")).admitted, 1);
    assert_eq!(within(rx.recv()).await.expect("handled").1, "only-once");
    within(manager.shutdown(ShutdownMode::Drain))
        .await
        .expect("shutdown should report");
}

#[tokio::test]
async fn messages_are_not_handled_before_activation() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .register_handler(Box::new(RecordingPlugin {
            plugin_id: "gated-plugin",
            subscribed_kinds: None,
            received: tx,
        }))
        .expect("plugin should register");
    let manager = Arc::new(manager);

    // Before startup the plugin is not ready to admit anything.
    let report = manager.dispatch_message(&text("too-early"));
    assert_eq!(
        report.rejected,
        vec![("gated-plugin".to_string(), Rejection::NotReady)]
    );

    manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .expect("startup should report");
    // Started but not activated: admitted to the inbox, not consumed.
    assert_eq!(manager.dispatch_message(&text("queued")).admitted, 1);
    assert!(rx.try_recv().is_err());

    manager.activate().expect("activation should succeed");
    assert_eq!(within(rx.recv()).await.expect("handled").1, "queued");
    within(manager.shutdown(ShutdownMode::Drain))
        .await
        .expect("shutdown should report");
}

struct StallingPlugin {
    entered: Arc<Notify>,
}

#[async_trait]
impl Plugin for StallingPlugin {
    fn plugin_id(&self) -> &'static str {
        "stalling-plugin"
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {
        self.entered.notify_one();
        // Cooperative stall: waits until cancelled by shutdown.
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
async fn full_inbox_rejects_with_overload_and_other_plugins_continue() {
    let entered = Arc::new(Notify::new());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .set_options(PluginHostOptions {
            inbox_capacity: 2,
            ..PluginHostOptions::default()
        })
        .expect("options are valid");
    manager
        .register_handler(Box::new(StallingPlugin {
            entered: entered.clone(),
        }))
        .expect("plugin should register");
    manager
        .register_handler(Box::new(RecordingPlugin {
            plugin_id: "healthy-plugin",
            subscribed_kinds: None,
            received: tx,
        }))
        .expect("plugin should register");
    let manager = start_and_activate(manager).await;

    assert_eq!(manager.dispatch_message(&text("1")).admitted, 2);
    within(entered.notified()).await;
    // The capacity includes the message in progress.
    assert_eq!(manager.dispatch_message(&text("2")).admitted, 2);
    let report = manager.dispatch_message(&text("3"));
    assert_eq!(report.admitted, 1);
    assert_eq!(
        report.rejected,
        vec![("stalling-plugin".to_string(), Rejection::Overloaded)]
    );

    for expected in ["1", "2", "3"] {
        assert_eq!(within(rx.recv()).await.expect("handled").1, expected);
    }

    // Discard cancels the stalled message in progress and drops the queued one.
    let report = within(manager.shutdown(ShutdownMode::Discard))
        .await
        .expect("shutdown should report");
    let stalling = report
        .plugins
        .iter()
        .find(|plugin| plugin.plugin_id == "stalling-plugin")
        .expect("report covers every plugin");
    assert_eq!(stalling.discarded_messages, 1);
    assert_eq!(stalling.stop, StopResult::Stopped);
    assert!(report.is_clean(), "{report:?}");
}

/// Waits for a reply inside `on_message`. With one consumer per plugin the
/// reply can never be handled while this handler waits on it.
struct SelfWaitingPlugin {
    waiting: Arc<Notify>,
    reply_seen: Arc<AtomicBool>,
    replies: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

#[async_trait]
impl Plugin for SelfWaitingPlugin {
    fn plugin_id(&self) -> &'static str {
        "self-waiting-plugin"
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        match &message.msg_type {
            MessageType::Text(body) if body == "request" => {
                let reply = self.replies.lock().unwrap().take();
                self.waiting.notify_one();
                if let Some(reply) = reply {
                    let _ = reply.await;
                }
            }
            MessageType::Text(body) if body == "reply" => {
                self.reply_seen.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn handler_waiting_on_its_own_inbox_never_receives_the_reply() {
    let waiting = Arc::new(Notify::new());
    let reply_seen = Arc::new(AtomicBool::new(false));
    let (_never_sent, reply_rx) = tokio::sync::oneshot::channel();
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .register_handler(Box::new(SelfWaitingPlugin {
            waiting: waiting.clone(),
            reply_seen: reply_seen.clone(),
            replies: Mutex::new(Some(reply_rx)),
        }))
        .expect("plugin should register");
    let manager = start_and_activate(manager).await;

    assert_eq!(manager.dispatch_message(&text("request")).admitted, 1);
    within(waiting.notified()).await;
    assert_eq!(manager.dispatch_message(&text("reply")).admitted, 1);

    // The reply stays queued behind the waiting handler; discard proves it was
    // never consumed.
    let report = within(manager.shutdown(ShutdownMode::Discard))
        .await
        .expect("shutdown should report");
    assert!(!reply_seen.load(Ordering::SeqCst));
    assert_eq!(report.plugins[0].discarded_messages, 1);
}

/// Correct pattern: the request handler starts a managed task that waits for
/// the reply; the reply handler forwards it.
struct ForwardingPlugin {
    replies: Arc<Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
    completed: mpsc::UnboundedSender<String>,
}

#[async_trait]
impl Plugin for ForwardingPlugin {
    fn plugin_id(&self) -> &'static str {
        "forwarding-plugin"
    }

    async fn on_message(&self, message: &Message, ctx: &PluginContext) {
        match &message.msg_type {
            MessageType::Text(body) if body == "request" => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                *self.replies.lock().unwrap() = Some(tx);
                let completed = self.completed.clone();
                ctx.spawn_task("await-reply", move |task| async move {
                    tokio::select! {
                        reply = rx => {
                            if let Ok(reply) = reply {
                                let _ = completed.send(reply);
                            }
                        }
                        _ = task.cancelled() => {}
                    }
                    Ok(())
                })
                .expect("managed task should spawn");
            }
            MessageType::Text(body) if body.starts_with("reply:") => {
                if let Some(tx) = self.replies.lock().unwrap().take() {
                    let _ = tx.send(body.trim_start_matches("reply:").to_string());
                }
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn request_reply_waits_belong_in_managed_tasks() {
    let (completed_tx, mut completed_rx) = mpsc::unbounded_channel();
    let mut manager = PluginManager::with_context(plugin_context());
    manager
        .register_handler(Box::new(ForwardingPlugin {
            replies: Arc::new(Mutex::new(None)),
            completed: completed_tx,
        }))
        .expect("plugin should register");
    let manager = start_and_activate(manager).await;

    manager.dispatch_message(&text("request"));
    manager.dispatch_message(&text("reply:pong"));
    assert_eq!(within(completed_rx.recv()).await.as_deref(), Some("pong"));
    let report = within(manager.shutdown(ShutdownMode::Drain))
        .await
        .expect("shutdown should report");
    assert!(report.is_clean(), "{report:?}");
}
