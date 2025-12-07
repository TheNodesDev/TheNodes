// tests/mtls.rs
// Minimal integration test for mTLS handshake in open mode.
// This test spins up a listener with mTLS enabled and connects a client using the public APIs.
// It requires test certificates to be present. To avoid external tooling, it will skip if
// the expected cert/key files are missing.

use std::sync::Arc;
use std::time::Duration;
use thenodes::config::{
    Config, EncryptionConfig, EncryptionPaths, TrustPolicyConfig, TrustPolicyPathsConfig,
};
use thenodes::network::peer::Peer;
use thenodes::network::peer_manager::PeerManager;
use thenodes::network::peer_store::PeerStore;
use thenodes::plugin_host::manager::PluginManager;
use thenodes::realms::RealmInfo;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_open_mode_basic_handshake() {
    // Arrange config with mTLS enabled and open trust policy.
    // Expect test certs at pki/own/cert.pem and pki/own/key.pem; skip if missing.
    let cert_path = "pki/own/cert.pem";
    let key_path = "pki/own/key.pem";
    if !(std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists()) {
        eprintln!("Skipping mTLS test: missing test certificate or key");
        return; // graceful skip
    }

    let cfg = Config {
        encryption: Some(EncryptionConfig {
            enabled: true,
            mtls: Some(true),
            accept_self_signed: Some(true), // legacy still honored; permissive for test
            paths: Some(EncryptionPaths {
                own_certificate: Some(cert_path.to_string()),
                own_private_key: Some(key_path.to_string()),
                trusted_cert_dir: Some("pki/trusted/certs".to_string()),
                trusted_crl_dir: None,
                rejected_dir: None,
                issuer_cert_dir: None,
                issuer_crl_dir: None,
            }),
            trust_policy: Some(TrustPolicyConfig {
                mode: Some("open".to_string()),
                accept_self_signed: Some(true),
                store_new_certs: Some("none".to_string()),
                reject_expired: Some(false),
                reject_before_valid: Some(false),
                enforce_ca_chain: Some(false),
                pin_subjects: Some(vec![]),
                pin_fingerprints: Some(vec![]),
                pin_fp_algo: Some("sha256".to_string()),
                realm_subject_binding: Some(false),
                paths: Some(TrustPolicyPathsConfig {
                    observed_dir: Some("pki/observed/certs".to_string()),
                }),
            }),
        }),
        ..Default::default()
    };

    let realm = RealmInfo::new("test", "1.0");
    let peer_manager = PeerManager::new();
    let plugin_manager = Arc::new(PluginManager::new());

    // Fixed test port (avoid dynamic discovery for simplicity)

    // Spawn listener
    let realm_listener = realm.clone();
    let pm_listener = peer_manager.clone();
    let pm_plugins = plugin_manager.clone();
    let cfg_clone = cfg.clone();
    let peer_store = PeerStore::new();
    let listener_handle = tokio::spawn(async move {
        // Bind to ephemeral port by first creating a TcpListener? Reuse existing API that expects port.
        // For simplicity, choose fixed port 38123; if busy, test may fail.
        let port = 38123u16;
        if let Err(e) = thenodes::network::listener::start_listener(
            port,
            realm_listener,
            pm_listener,
            pm_plugins,
            &cfg_clone,
            "srv-node".to_string(),
            peer_store,
            true,
        )
        .await
        {
            eprintln!("Listener error: {}", e);
        }
    });

    // Allow listener to start
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Act: connect client
    let peer = Peer {
        id: "peer-test".into(),
        address: "127.0.0.1:38123".into(),
        capabilities: None,
    };
    // Use handshake-only variant to avoid entering infinite receive loop during the test
    let connect_res = tokio::time::timeout(
        Duration::from_secs(10),
        thenodes::network::transport::connect_to_peer_handshake_only(
            &peer,
            realm.clone(),
            38123,
            false,
            &cfg,
            "cli-node".to_string(),
        ),
    )
    .await
    .expect("handshake timed out");

    // Assert
    assert!(
        connect_res.is_ok(),
        "mTLS open mode handshake failed: {:?}",
        connect_res.err()
    );

    // Cleanup
    // We don't have a shutdown signal for listener yet; detach handle.
    listener_handle.abort();
}
