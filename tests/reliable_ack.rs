use std::net::SocketAddr;
use thenodes::network::message::{Message, MessageType};
use thenodes::network::peer_manager::PeerManager;

#[tokio::test]
async fn ack_cancels_inflight_retry() {
    let pm = PeerManager::new();
    // Add a reliable binding
    pm.set_binding("fromA", "toB", true, None, Some("reliable".into()))
        .await;
    // Simulate forwarding with sequence
    let seq = 42u64;
    pm.add_inflight("fromA", "toB", seq).await;
    // Send ACK
    let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let ack = Message::new(
        &addr.to_string(),
        &addr.to_string(),
        MessageType::Ack {
            to: "toB".into(),
            from: "fromA".into(),
            sequence: seq,
            status: Some("ok".into()),
        },
        None,
        None,
    );
    thenodes::network::relay::handle_ack(&ack, &addr, &pm).await;
    assert!(!pm.is_inflight("fromA", "toB", seq).await);
}
