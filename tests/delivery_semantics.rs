use thenodes::network::delivery::{DeliveryClass, DeliveryOptions};
use thenodes::network::message::{DeliveryMetadata, Message, MessageType};
use thenodes::plugin_host::{PluginContext, PluginManager};

#[tokio::test]
async fn plugin_context_delivery_api_sends_reliably_to_connected_peer() {
    let peer_manager = std::sync::Arc::new(thenodes::network::PeerManager::new());
    let peer_store = thenodes::network::PeerStore::new();
    let ctx = PluginContext::new(
        peer_manager.clone(),
        peer_store,
        thenodes::events::dispatcher::handle(),
        "node-a".to_string(),
        thenodes::config::Config::default(),
        false,
    );
    let plugin_manager = std::sync::Arc::new(PluginManager::with_context(ctx.clone()));
    ctx.set_plugin_manager(plugin_manager).await;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(4);
    let addr: std::net::SocketAddr = "127.0.0.1:9101".parse().unwrap();
    peer_manager
        .add_peer(addr, tx, "node-b".to_string())
        .await
        .expect("peer should register");

    let pm_for_ack = peer_manager.clone();
    tokio::spawn(async move {
        if let Some(json) = rx.recv().await {
            let outbound = Message::from_json(&json).expect("valid outbound message");
            let message_id = outbound
                .delivery
                .as_ref()
                .map(|delivery| delivery.message_id.clone())
                .expect("delivery metadata present");
            pm_for_ack
                .set_delivery_outcome(
                    &message_id,
                    thenodes::network::DeliveryOutcome::AcknowledgedByPeer,
                )
                .await;
        }
    });

    let outcome = ctx
        .send_message(
            "node-b",
            Message::new("ignored", "ignored", MessageType::Heartbeat, None, None),
            DeliveryOptions::new(DeliveryClass::Reliable),
        )
        .await;

    assert_eq!(
        outcome,
        thenodes::network::DeliveryOutcome::AcknowledgedByPeer
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
