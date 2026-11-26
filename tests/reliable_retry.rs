use std::net::SocketAddr;
use thenodes::network::message::{
    decode_relay_opaque_payload_utf8, encode_relay_opaque_payload, Message, MessageType,
};
use thenodes::network::peer_manager::PeerManager;
use tokio::sync::mpsc;

#[tokio::test]
async fn delayed_retry_cancelled_by_ack() {
    let pm = PeerManager::new();
    // Reliable binding
    pm.set_binding("fromA", "toB", true, None, Some("reliable".into()))
        .await;

    // Connect destination peer to capture sends
    let (tx, mut rx) = mpsc::channel::<Message>(16);
    let addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
    pm.add_peer(addr, tx, "toB".into()).await.unwrap();

    // Craft forward with sequence
    let seq = 7u64;
    let opaque_payload_b64 = encode_relay_opaque_payload("hello");
    let fwd = Message::new(
        "fromA",
        "toB",
        MessageType::RelayForward {
            to: "toB".into(),
            from: "fromA".into(),
            sequence: Some(seq),
            opaque_payload_b64: opaque_payload_b64.clone(),
        },
        None,
        None,
    );

    // Invoke handler: schedules delayed retry for reliable
    thenodes::network::relay::handle_forward(
        &fwd, &addr, &pm, /* relay_enabled */ true,
        /* relay_store_forward_enabled */ true, /* allow_console */ true,
    )
    .await;

    // First send should be delivered immediately
    let first = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
        .await
        .expect("expected initial delivery timeout to succeed")
        .expect("expected initial delivery");
    match &first.msg_type {
        MessageType::RelayForward {
            to,
            from,
            sequence,
            opaque_payload_b64: forwarded_payload,
        } => {
            assert_eq!(to, "toB");
            assert_eq!(from, "fromA");
            assert_eq!(sequence, &Some(seq));
            assert_eq!(forwarded_payload, &opaque_payload_b64);
            assert_eq!(
                decode_relay_opaque_payload_utf8(forwarded_payload).as_deref(),
                Some("hello")
            );
        }
        _ => panic!("expected forwarded relay frame"),
    }
    assert!(first.payload.is_none());

    // The target sends ACK before 500ms to cancel retry
    let ack = Message::new(
        "toB",
        "relay",
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

#[tokio::test]
async fn retry_is_sent_once_and_releases_the_inflight_entry() {
    let pm = PeerManager::new();
    pm.set_binding("fromA", "toB", true, None, Some("reliable".into()))
        .await;
    let (tx, mut rx) = mpsc::channel::<Message>(16);
    let addr: SocketAddr = "127.0.0.1:9101".parse().unwrap();
    pm.add_peer(addr, tx, "toB".into()).await.unwrap();

    let fwd = Message::new(
        "fromA",
        "relay",
        MessageType::RelayForward {
            to: "toB".into(),
            from: "fromA".into(),
            sequence: Some(3),
            opaque_payload_b64: encode_relay_opaque_payload("hello"),
        },
        None,
        None,
    );
    thenodes::network::relay::handle_forward(&fwd, &addr, &pm, true, true, true).await;
    rx.recv().await.expect("initial delivery");
    tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("retry after the ACK timeout")
        .expect("retried frame");

    // No ACK came, and none can cancel anything now.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while pm.is_inflight("fromA", "toB", 3).await {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("in-flight entry should be released after the retry");
    let extra = tokio::time::timeout(std::time::Duration::from_millis(700), rx.recv()).await;
    assert!(extra.is_err(), "a second retry was sent");
}
