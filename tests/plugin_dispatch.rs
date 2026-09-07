use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use thenodes::network::message::{Message, MessageType};
use thenodes::plugin_host::{Plugin, PluginContext, PluginManager, PluginRegistrar};
use tokio::sync::Notify;

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

struct AwaitingPlugin {
    started: Arc<Notify>,
    release: Arc<Notify>,
    completed: Arc<AtomicBool>,
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
    }
}

#[tokio::test]
async fn dispatch_waits_for_async_plugin_work() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let completed = Arc::new(AtomicBool::new(false));
    let mut manager = PluginManager::with_context(plugin_context());
    manager.register_handler(Box::new(AwaitingPlugin {
        started: started.clone(),
        release: release.clone(),
        completed: completed.clone(),
    }));
    let manager = Arc::new(manager);
    let message = Message::new("peer-a", "local-node", MessageType::Heartbeat, None, None);

    let dispatch = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager.dispatch_message(&message).await;
        }
    });

    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("plugin should start");
    assert!(!completed.load(Ordering::SeqCst));

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), dispatch)
        .await
        .expect("dispatch should finish after plugin work is released")
        .expect("dispatch task should succeed");
    assert!(completed.load(Ordering::SeqCst));
}

struct RecordingPlugin {
    plugin_id: &'static str,
    subscribed_kinds: Option<&'static [&'static str]>,
    received: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for RecordingPlugin {
    fn plugin_id(&self) -> &'static str {
        self.plugin_id
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        let description = match &message.msg_type {
            MessageType::Extension { kind } => kind.clone(),
            _ => "non-extension".to_string(),
        };
        self.received
            .lock()
            .expect("recording lock should not be poisoned")
            .push(description);
    }

    fn subscribed_extension_kinds(&self) -> Option<&[&str]> {
        self.subscribed_kinds
    }
}

struct BoundContextPlugin {
    plugin_id: &'static str,
    seen_plugin_ids: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for BoundContextPlugin {
    fn plugin_id(&self) -> &'static str {
        self.plugin_id
    }

    async fn on_message(&self, _message: &Message, ctx: &PluginContext) {
        self.seen_plugin_ids
            .lock()
            .expect("context lock should not be poisoned")
            .push(
                ctx.plugin_id()
                    .expect("plugin manager should bind plugin context")
                    .to_string(),
            );
    }
}

#[tokio::test]
async fn dispatch_filters_extension_kinds_per_plugin() {
    let matching = Arc::new(Mutex::new(Vec::new()));
    let non_matching = Arc::new(Mutex::new(Vec::new()));
    let receives_all = Arc::new(Mutex::new(Vec::new()));
    let mut manager = PluginManager::with_context(plugin_context());
    manager.register_handler(Box::new(RecordingPlugin {
        plugin_id: "records-updated-plugin",
        subscribed_kinds: Some(&["records.updated"]),
        received: matching.clone(),
    }));
    manager.register_handler(Box::new(RecordingPlugin {
        plugin_id: "records-deleted-plugin",
        subscribed_kinds: Some(&["records.deleted"]),
        received: non_matching.clone(),
    }));
    manager.register_handler(Box::new(RecordingPlugin {
        plugin_id: "records-all-plugin",
        subscribed_kinds: None,
        received: receives_all.clone(),
    }));

    let extension = Message::new(
        "peer-a",
        "local-node",
        MessageType::Extension {
            kind: "records.updated".to_string(),
        },
        None,
        None,
    );
    manager.dispatch_message(&extension).await;

    assert_eq!(
        *matching
            .lock()
            .expect("matching lock should not be poisoned"),
        vec!["records.updated"]
    );
    assert!(
        non_matching
            .lock()
            .expect("non-matching lock should not be poisoned")
            .is_empty(),
        "non-subscribing plugin must not receive the extension"
    );
    assert_eq!(
        *receives_all
            .lock()
            .expect("default subscription lock should not be poisoned"),
        vec!["records.updated"]
    );

    let text = Message::new(
        "peer-a",
        "local-node",
        MessageType::Text("hello".to_string()),
        None,
        None,
    );
    manager.dispatch_message(&text).await;

    assert_eq!(
        *non_matching
            .lock()
            .expect("non-matching lock should not be poisoned"),
        vec!["non-extension"]
    );
}

#[tokio::test]
async fn dispatch_binds_each_plugin_context_to_its_registered_id() {
    let seen_plugin_ids = Arc::new(Mutex::new(Vec::new()));
    let mut manager = PluginManager::with_context(plugin_context());
    manager.register_handler(Box::new(BoundContextPlugin {
        plugin_id: "bound-plugin-a",
        seen_plugin_ids: seen_plugin_ids.clone(),
    }));
    manager.register_handler(Box::new(BoundContextPlugin {
        plugin_id: "bound-plugin-b",
        seen_plugin_ids: seen_plugin_ids.clone(),
    }));

    let message = Message::new("peer-a", "local-node", MessageType::Heartbeat, None, None);
    manager.dispatch_message(&message).await;

    assert_eq!(
        *seen_plugin_ids
            .lock()
            .expect("context lock should not be poisoned"),
        vec!["bound-plugin-a".to_string(), "bound-plugin-b".to_string()]
    );
}

#[tokio::test]
async fn register_handler_refuses_duplicate_plugin_ids() {
    // Two plugins sharing the same `plugin_id()` would otherwise silently share the
    // same isolated `plugin_data_dir()`, letting one clobber the other's on-disk
    // state. The second registration must be rejected and dispatch must still only
    // reach the first plugin.
    let seen_plugin_ids = Arc::new(Mutex::new(Vec::new()));
    let mut manager = PluginManager::with_context(plugin_context());
    manager.register_handler(Box::new(BoundContextPlugin {
        plugin_id: "duplicate-plugin",
        seen_plugin_ids: seen_plugin_ids.clone(),
    }));
    manager.register_handler(Box::new(BoundContextPlugin {
        plugin_id: "duplicate-plugin",
        seen_plugin_ids: seen_plugin_ids.clone(),
    }));

    let message = Message::new("peer-a", "local-node", MessageType::Heartbeat, None, None);
    manager.dispatch_message(&message).await;

    assert_eq!(
        *seen_plugin_ids
            .lock()
            .expect("context lock should not be poisoned"),
        vec!["duplicate-plugin".to_string()],
        "dispatch must only reach the first registration of a duplicate plugin id"
    );
}
