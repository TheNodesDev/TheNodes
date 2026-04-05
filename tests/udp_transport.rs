#![cfg(feature = "noise")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use thenodes::network::udp_listener::{send_udp, UdpSessions};
use thenodes::network::udp_session::{
    has_reserved_tncf_prefix, NoiseUdpSession, MAX_APP_PAYLOAD_BYTES, SESSION_ID_LEN, TNCF_MAGIC,
};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

fn generate_noise_private_key() -> Vec<u8> {
    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let builder = snow::Builder::new(params);
    builder.generate_keypair().unwrap().private
}

#[test]
fn reserved_tncf_prefix_detection_works() {
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id[..4].copy_from_slice(&TNCF_MAGIC);
    assert!(has_reserved_tncf_prefix(&session_id));

    session_id[0] ^= 0x01;
    assert!(!has_reserved_tncf_prefix(&session_id));
}

#[test]
fn initiator_session_ids_never_use_reserved_prefix() {
    let private_key = generate_noise_private_key();
    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

    for _ in 0..256 {
        let (session, msg1) =
            NoiseUdpSession::new_initiator(peer_addr, &private_key).expect("initiator session");
        assert!(!has_reserved_tncf_prefix(&session.session_id));
        assert!(!msg1.is_empty());
    }
}

#[tokio::test]
async fn send_udp_rejects_plaintext_over_limit() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
    let session_id = [1u8; SESSION_ID_LEN];
    let payload = vec![0u8; MAX_APP_PAYLOAD_BYTES + 1];

    let err = send_udp(&session_id, &payload, &socket, &sessions)
        .await
        .expect_err("oversized UDP payload must fail");

    assert!(err.to_string().contains("too large"));
}
