#![cfg(feature = "noise")]

use std::sync::Arc;
use std::time::Duration;

use thenodes::network::message::{Message, MessageType};
use thenodes::network::nat_traversal::{handle_observe_req, handle_punch_ready, NatState};
use thenodes::network::udp_session::{parse_tncf_frame, tncf_type};
use thenodes::network::PeerManager;
use tokio::net::UdpSocket;

fn observe_req_body() -> [u8; 9] {
    [0u8; 9]
}

fn nat_state(serve: bool) -> NatState {
    NatState {
        cookie_secret: [7u8; 32],
        cookie_ttl_secs: 30,
        probe_count: 6,
        probe_interval_ms: 100,
        serve,
        refresh_secs: 300,
        observed_sources: Default::default(),
        allowed_rendezvous: None,
    }
}

#[tokio::test]
async fn observe_req_requires_serve_role() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    handle_observe_req(
        &nat_state(false),
        &server,
        client.local_addr().unwrap(),
        &observe_req_body(),
    )
    .await;

    let mut buf = [0u8; 128];
    let recv = tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
    assert!(recv.is_err());
}

#[tokio::test]
async fn observe_req_returns_cookie_challenge_when_serving() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    handle_observe_req(
        &nat_state(true),
        &server,
        client.local_addr().unwrap(),
        &observe_req_body(),
    )
    .await;

    let mut buf = [0u8; 128];
    let (n, _src) = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (frame_type, body) = parse_tncf_frame(&buf[..n]).unwrap();

    assert_eq!(frame_type, tncf_type::COOKIE_CHALLENGE);
    assert_eq!(body.len(), 25);
    assert_eq!(body[8], 16);
}

/// Answer one `OBSERVE_REQ` from `client` and return the reply's TNCF type
/// and body.
async fn observe(
    nat: &NatState,
    server: &Arc<UdpSocket>,
    client: &UdpSocket,
    body: &[u8],
) -> (u8, Vec<u8>) {
    handle_observe_req(nat, server, client.local_addr().unwrap(), body).await;
    let mut buf = [0u8; 128];
    let (n, _) = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (frame_type, body) = parse_tncf_frame(&buf[..n]).unwrap();
    (frame_type, body.to_vec())
}

#[tokio::test]
async fn only_a_cookie_verified_observation_records_its_source() {
    let nat = nat_state(true);
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = client.local_addr().unwrap();

    let (frame_type, challenge) = observe(&nat, &server, &client, &observe_req_body()).await;
    assert_eq!(frame_type, tncf_type::COOKIE_CHALLENGE);
    assert!(!nat
        .observed_sources
        .is_fresh(source, nat.observation_max_age()));

    let (frame_type, _) = observe(&nat, &server, &client, &challenge).await;
    assert_eq!(frame_type, tncf_type::OBSERVE_RESP);
    assert!(nat
        .observed_sources
        .is_fresh(source, nat.observation_max_age()));
}

fn punch_go_count(receiver: &mut tokio::sync::mpsc::Receiver<Message>) -> usize {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|message| matches!(message.msg_type, MessageType::PunchGo { .. }))
        .count()
}

/// Regression test: a rendezvous used to pass on the UDP addresses peers
/// claimed in HELLO, so a peer could make two honest nodes probe any victim.
#[tokio::test]
async fn rendezvous_hands_out_only_addresses_it_observed() {
    let pm = PeerManager::new();
    let nat = nat_state(true);
    let (to_a, mut at_a) = tokio::sync::mpsc::channel(8);
    let (to_c, mut at_c) = tokio::sync::mpsc::channel(8);
    pm.add_peer("127.0.0.1:41001".parse().unwrap(), to_a, "node-a".into())
        .await
        .unwrap();
    pm.add_peer("127.0.0.1:41003".parse().unwrap(), to_c, "node-c".into())
        .await
        .unwrap();
    let (addr_a, addr_c) = ("198.51.100.1:4000", "198.51.100.3:4000");
    pm.add_udp_observed_addr("node-a", addr_a, None, None).await;
    pm.add_udp_observed_addr("node-c", addr_c, None, None).await;
    assert!(
        pm.add_pending_punch("attempt-1", "node-c", "node-a", 5000)
            .await
    );

    handle_punch_ready(&pm, &nat, "attempt-1", "node-c", "node-a", true).await;
    assert_eq!(punch_go_count(&mut at_a) + punch_go_count(&mut at_c), 0);
    assert!(
        pm.get_pending_punch("attempt-1").await.is_none(),
        "the answer settled the attempt"
    );

    for addr in [addr_a, addr_c] {
        nat.observed_sources
            .record(addr.parse().unwrap(), nat.observation_max_age());
    }
    assert!(
        pm.add_pending_punch("attempt-2", "node-c", "node-a", 5000)
            .await
    );
    handle_punch_ready(&pm, &nat, "attempt-2", "node-c", "node-a", true).await;
    assert_eq!(punch_go_count(&mut at_a), 1);
    assert_eq!(punch_go_count(&mut at_c), 1);
}

/// Only the invited responder settles a punch; another peer's `PUNCH_READY`
/// neither cancels nor completes it.
#[tokio::test]
async fn only_the_invited_responder_settles_a_punch() {
    let pm = PeerManager::new();
    let nat = nat_state(true);
    let (to_a, mut at_a) = tokio::sync::mpsc::channel(8);
    pm.add_peer("127.0.0.1:41001".parse().unwrap(), to_a, "node-a".into())
        .await
        .unwrap();
    assert!(
        pm.add_pending_punch("attempt-1", "node-c", "node-a", 5000)
            .await
    );

    for ok in [false, true] {
        handle_punch_ready(&pm, &nat, "attempt-1", "node-x", "node-a", ok).await;
        handle_punch_ready(&pm, &nat, "attempt-1", "node-c", "node-b", ok).await;
    }
    assert!(pm.get_pending_punch("attempt-1").await.is_some());
    assert!(at_a.try_recv().is_err());

    handle_punch_ready(&pm, &nat, "attempt-1", "node-c", "node-a", false).await;
    assert!(pm.get_pending_punch("attempt-1").await.is_none());
    assert!(matches!(
        at_a.try_recv().unwrap().msg_type,
        MessageType::PunchAbort { .. }
    ));
}
