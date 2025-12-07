use std::net::SocketAddr;
use thenodes::network::{
    message::{Message, MessageType},
    peer_manager::PeerManager,
};

fn addr_local() -> SocketAddr {
    "127.0.0.1:5001".parse().unwrap()
}

#[tokio::test]
async fn relay_forward_ttl_expired_does_not_enqueue() {
    let pm = PeerManager::new();
    // Create a binding with store_forward and expired TTL
    pm.set_binding("node-a", "node-b", true, Some(0), None)
        .await; // 0 <= now
    let before_ok = pm.can_enqueue_store_forward("node-b").await;
    thenodes::network::relay::RelayForwardBuilder::new("node-a", "node-b")
        .sequence(1)
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
        None,
        None,
    );
    thenodes::network::relay::handle_forward(&msg, &addr_local(), &pm, true, true, false, true)
        .await;
    // Capacity should remain available; no enqueue when TTL expired
    let after_ok = pm.can_enqueue_store_forward("node-b").await;
    assert!(before_ok && after_ok);
}

#[tokio::test]
async fn relay_unbind_removes_binding() {
    let pm = PeerManager::new();
    pm.set_binding("node-a", "node-b", true, None, None).await;
    pm.add_binding_id("bind:node-a:node-b:1", "node-a", "node-b")
        .await;
    assert!(pm.is_bound("node-a", "node-b").await);
    let msg = Message::new(
        "node-a",
        "node-a",
        MessageType::RelayUnbind {
            binding_id: "bind:node-a:node-b:1".to_string(),
        },
        None,
        None,
    );
    thenodes::network::relay::handle_unbind(&msg, &addr_local(), &pm, true).await;
    assert!(!pm.is_bound("node-a", "node-b").await);
}
