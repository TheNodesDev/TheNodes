#![cfg(feature = "noise")]

use std::sync::Arc;
use std::time::Duration;

use thenodes::network::nat_traversal::{handle_observe_req, NatState};
use thenodes::network::udp_session::{parse_tncf_frame, tncf_type};
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
