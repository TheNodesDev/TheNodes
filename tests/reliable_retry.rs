use std::net::SocketAddr;
use thenodes::network::message::{Message, MessageType, Payload};
use thenodes::network::peer_manager::PeerManager;
use tokio::sync::mpsc;

#[tokio::test]
async fn delayed_retry_cancelled_by_ack() {
    let pm = PeerManager::new();
    // Reliable binding
    pm.set_binding("fromA", "toB", true, None, Some("reliable".into()))
        .await;

    // Connect destination peer to capture sends
    let (tx, mut rx) = mpsc::channel::<String>(16);
    let addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
    pm.add_peer(addr, tx, "toB".into()).await.unwrap();

    // Craft forward with sequence
    let seq = 7u64;
    let fwd = Message::new(
        "fromA",
        "toB",
        MessageType::RelayForward {
            to: "toB".into(),
            from: "fromA".into(),
            sequence: Some(seq),
        },
        Some(Payload::Text("hello".into())),
        None,
    );

    // Invoke handler: schedules delayed retry for reliable
    thenodes::network::relay::handle_forward(
        &fwd, &addr, &pm, /* relay_enabled */ true,
        /* relay_store_forward_enabled */ true, /* relay_selection_enabled */ false,
        /* allow_console */ true,
    )
    .await;

    // First send should be delivered immediately
    let first = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
    assert!(matches!(first, Ok(Some(_))), "expected initial delivery");

    // Send ACK before 500ms to cancel retry
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

    // Wait past retry delay; no second message should arrive
    let second = tokio::time::timeout(std::time::Duration::from_millis(600), rx.recv()).await;
    assert!(
        second.is_err() || matches!(second, Ok(None)),
        "unexpected retry delivery after ACK"
    );
}
