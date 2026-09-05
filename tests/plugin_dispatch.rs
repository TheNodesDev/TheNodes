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
    subscribed_kinds: Option<&'static [&'static str]>,
    received: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for RecordingPlugin {
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

#[tokio::test]
async fn dispatch_filters_extension_kinds_per_plugin() {
    let matching = Arc::new(Mutex::new(Vec::new()));
    let non_matching = Arc::new(Mutex::new(Vec::new()));
    let receives_all = Arc::new(Mutex::new(Vec::new()));
    let mut manager = PluginManager::with_context(plugin_context());
    manager.register_handler(Box::new(RecordingPlugin {
        subscribed_kinds: Some(&["records.updated"]),
        received: matching.clone(),
    }));
    manager.register_handler(Box::new(RecordingPlugin {
        subscribed_kinds: Some(&["records.deleted"]),
        received: non_matching.clone(),
    }));
    manager.register_handler(Box::new(RecordingPlugin {
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
