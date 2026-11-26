use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use thenodes::network::delivery::{DeliveryClass, DeliveryFailureReason, DeliveryOptions};
use thenodes::network::message::{DeliveryMetadata, Message, MessageType};
use thenodes::network::DeliveryOutcome;
use thenodes::plugin_host::{
    Plugin, PluginContext, PluginError, PluginManager, PluginRegistrar, ShutdownMode, StartPolicy,
};

/// Keeps the plugin-bound context it receives at startup so the test can use
/// the official send path.
struct ContextCapturingPlugin {
    ctx: Arc<OnceLock<PluginContext>>,
}

#[async_trait]
impl Plugin for ContextCapturingPlugin {
    fn plugin_id(&self) -> &'static str {
        "delivery-test-plugin"
    }

    async fn on_start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        let _ = self.ctx.set(ctx.clone());
        Ok(())
    }

    async fn on_message(&self, _message: &Message, _ctx: &PluginContext) {}
}

#[tokio::test]
async fn plugin_context_delivery_api_sends_reliably_to_connected_peer() {
    let peer_manager = Arc::new(thenodes::network::PeerManager::new());
    let peer_store = thenodes::network::PeerStore::new();
    let ctx = PluginContext::new(
        peer_manager.clone(),
        peer_store,
        thenodes::events::dispatcher::handle(),
        "node-a".to_string(),
        thenodes::config::Config::default(),
        false,
    );
    let captured = Arc::new(OnceLock::new());
    let mut plugin_manager = PluginManager::with_context(ctx.clone());
    plugin_manager
        .register_handler(Box::new(ContextCapturingPlugin {
            ctx: captured.clone(),
        }))
        .expect("plugin should register");
    let plugin_manager = Arc::new(plugin_manager);
    plugin_manager
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .expect("plugins should start");
    let plugin_ctx = captured.get().expect("on_start received a context").clone();

    // The host base context has no host services and cannot send.
    assert_eq!(
        ctx.send_message(
            "node-b",
            Message::new("ignored", "ignored", MessageType::Heartbeat, None, None),
            DeliveryOptions::new(DeliveryClass::FireAndForget),
        )
        .await,
        DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::Unavailable
        }
    );
    // Plugin sends before activation are refused, not buffered.
    assert_eq!(
        plugin_ctx
            .send_message(
                "node-b",
                Message::new("ignored", "ignored", MessageType::Heartbeat, None, None),
                DeliveryOptions::new(DeliveryClass::FireAndForget),
            )
            .await,
        DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::NotReady
        }
    );
    plugin_manager
        .activate()
        .expect("activation should succeed");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(4);
    let addr: std::net::SocketAddr = "127.0.0.1:9101".parse().unwrap();
    peer_manager
        .add_peer(addr, tx, "node-b".to_string())
        .await
        .expect("peer should register");

    let pm_for_ack = peer_manager.clone();
    tokio::spawn(async move {
        if let Some(outbound) = rx.recv().await {
            let message_id = outbound
                .delivery
                .as_ref()
                .map(|delivery| delivery.message_id.clone())
                .expect("delivery metadata present");
            pm_for_ack
                .set_delivery_outcome(&message_id, DeliveryOutcome::AcknowledgedByPeer)
                .await;
        }
    });

    let outcome = plugin_ctx
        .send_message(
            "node-b",
            Message::new("ignored", "ignored", MessageType::Heartbeat, None, None),
            DeliveryOptions::new(DeliveryClass::Reliable),
        )
        .await;

    assert_eq!(outcome, DeliveryOutcome::AcknowledgedByPeer);

    let report = plugin_manager
        .shutdown(ShutdownMode::Drain)
        .await
        .expect("shutdown should report");
    assert!(report.is_clean(), "{report:?}");

    // A retained context cannot send after shutdown.
    assert_eq!(
        plugin_ctx
            .send_message(
                "node-b",
                Message::new("ignored", "ignored", MessageType::Heartbeat, None, None),
                DeliveryOptions::new(DeliveryClass::FireAndForget),
            )
            .await,
        DeliveryOutcome::DeliveryFailed {
            reason: DeliveryFailureReason::Stopping
        }
    );
}

#[test]
fn ordered_reliable_options_require_ordering_key() {
    let options = DeliveryOptions::new(DeliveryClass::OrderedReliable);

    assert!(options.validate().is_err());
}

#[test]
fn fire_and_forget_options_reject_ordering_key() {
    let options = DeliveryOptions::new(DeliveryClass::FireAndForget).with_ordering_key("lane-a");

    assert!(options.validate().is_err());
}

#[test]
fn message_json_with_invalid_delivery_metadata_is_rejected() {
    let invalid = r#"{"from":"a","to":"b","msg_type":"HEARTBEAT","payload":null,"realm":null,"delivery":{"message_id":"00000000-0000-7000-8000-000000000000","class":"ordered_reliable"}}"#;

    assert!(Message::from_json(invalid).is_none());
}

#[test]
fn message_accepts_valid_ordered_delivery_metadata() {
    let message = Message::new("a", "b", MessageType::Heartbeat, None, None)
        .with_delivery(
            DeliveryMetadata::new(DeliveryClass::OrderedReliable).with_ordering_key("lane-a"),
        )
        .expect("valid ordered delivery metadata");

    assert_eq!(
        message
            .delivery
            .as_ref()
            .and_then(|metadata| metadata.ordering_key.as_deref()),
        Some("lane-a")
    );
}
