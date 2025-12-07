use std::net::SocketAddr;
use thenodes::network::{
    message::{Message, MessageType},
    peer_manager::PeerManager,
};

fn addr_local() -> SocketAddr {
    "127.0.0.1:5000".parse().unwrap()
}

#[tokio::test]
async fn relay_bind_denies_overload() {
    let pm = PeerManager::new();
    // Simulate full capacity by pre-filling queue caps per target and global
    let target = "node-b";
    for _ in 0..1024 {
        pm.enqueue_store_forward(target, "frame".into(), None, false, false, None)
            .await;
    }
    let msg = Message::new(
        "node-a",
        "node-a",
        MessageType::RelayBind {
            target: target.to_string(),
            want_store_forward: Some(true),
            qos: None,
            nonce: Some(1),
            expires_at: None,
        },
        None,
        None,
    );
    // Also exercise builder send path for coverage
    thenodes::network::relay::RelayBindBuilder::new("node-a", target)
        .store_forward(true)
        .ttl(30)
        .send(&pm, &addr_local(), None)
        .await;
    thenodes::network::relay::handle_bind(&msg, &addr_local(), &pm, true, true, true).await;
    // No panic; ack and overload notify are sent via peer channel (not connected here)
    assert!(!(pm.is_bound("node-a", target).await));
}

#[tokio::test]
async fn relay_forward_timeout_when_store_forward_disabled() {
    let pm = PeerManager::new();
    // Use builder to send a forward
    thenodes::network::relay::RelayForwardBuilder::new("node-a", "node-b")
        .sequence(1)
        .payload_text("payload")
        .send(&pm, &addr_local(), None)
        .await;
    let msg = Message::new(
        "node-a",
        "node-a",
        MessageType::RelayForward {
            to: "node-b".to_string(),
            from: "node-a".to_string(),
            sequence: Some(1),
        },
        Some(thenodes::network::message::Payload::Text("payload".into())),
        None,
    );
    thenodes::network::relay::handle_forward(&msg, &addr_local(), &pm, true, false, false, true)
        .await;
    // Since store-forward disabled and target absent, it should not enqueue
    assert!(pm.can_enqueue_store_forward("node-b").await);
}
