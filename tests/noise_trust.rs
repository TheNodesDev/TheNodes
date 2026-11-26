#![cfg(feature = "noise")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use thenodes::config::{
    Config, EncryptionConfig, EncryptionNoiseConfig, NoisePaths, NoiseTrustPolicyConfig,
};
use thenodes::network::udp_session::load_or_generate_static_keypair;
use thenodes::realms::RealmInfo;
use thenodes::security::secure_channel::{
    validate_authenticated_node_id, AuthSummary, NoiseSecureChannel, SecureChannel, SecurityBackend,
};
use thenodes::security::trust::sha256_fingerprint_hex;
use tokio::net::{TcpListener, TcpStream};

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-artifacts")
            .join("noise-trust");
        let unique = format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
                + SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64
        );
        let path = root.join(unique);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn join(&self, child: &str) -> PathBuf {
        self.path.join(child)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn policy(mode: &str) -> NoiseTrustPolicyConfig {
    NoiseTrustPolicyConfig {
        mode: Some(mode.to_string()),
        ..Default::default()
    }
}

fn config(static_key_path: &Path, trust_policy: NoiseTrustPolicyConfig) -> Config {
    let node_id = if static_key_path.to_string_lossy().contains("client") {
        "noise-client"
    } else {
        "noise-server"
    };
    Config {
        encryption: Some(EncryptionConfig {
            enabled: true,
            backend: Some("noise".to_string()),
            noise: Some(EncryptionNoiseConfig {
                paths: Some(NoisePaths {
                    static_key: Some(static_key_path.to_string_lossy().into_owned()),
                    ..Default::default()
                }),
                trust_policy: Some(trust_policy),
                ..Default::default()
            }),
            ..Default::default()
        }),
        node: Some(thenodes::config::NodeConfig {
            id: Some(node_id.to_string()),
            ..Default::default()
        }),
        realm: Some(RealmInfo::new("noise-trust", "1.0")),
        ..Default::default()
    }
}

/// Set the trusted and rejected key directories of a node's config.
fn with_stores(mut config: Config, trusted: Option<&Path>, rejected: Option<&Path>) -> Config {
    let paths = config
        .encryption
        .as_mut()
        .and_then(|encryption| encryption.noise.as_mut())
        .and_then(|noise| noise.paths.as_mut())
        .unwrap();
    paths.trusted_dir = trusted.map(|dir| dir.to_string_lossy().into_owned());
    paths.rejected_dir = rejected.map(|dir| dir.to_string_lossy().into_owned());
    config
}

fn fingerprint_for(path: &Path) -> String {
    let (_, public) = load_or_generate_static_keypair(path).unwrap();
    sha256_fingerprint_hex(&public)
}

async fn handshake_round(
    listener: Arc<TcpListener>,
    client_config: Config,
    server_config: Config,
) -> (
    anyhow::Result<thenodes::security::secure_channel::Channel>,
    anyhow::Result<thenodes::security::secure_channel::Channel>,
) {
    let addr = listener.local_addr().unwrap();
    let realm = RealmInfo::new("noise-trust", "1.0");
    let server_realm = realm.clone();
    let server_listener = listener.clone();
    let server = tokio::spawn(async move {
        let (stream, peer_addr) = server_listener.accept().await.unwrap();
        NoiseSecureChannel::new()
            .accept(stream, peer_addr, &server_realm, &server_config, false)
            .await
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let client = NoiseSecureChannel::new()
        .connect(stream, addr, &realm, &client_config, false)
        .await;
    let server = server.await.unwrap();
    (client, server)
}

#[tokio::test]
async fn noise_allowlist_accepts_on_both_sides() {
    let dir = TestDir::new("allowlist-accept");
    let client_key = dir.join("client/static.key");
    let server_key = dir.join("server/static.key");
    let client_fp = fingerprint_for(&client_key);
    let server_fp = fingerprint_for(&server_key);

    let mut client_policy = policy("allowlist");
    client_policy.allowlist_fingerprints = Some(vec![server_fp.clone()]);
    let mut server_policy = policy("allowlist");
    server_policy.allowlist_fingerprints = Some(vec![client_fp.clone()]);

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let (client, server) = handshake_round(
        listener,
        config(&client_key, client_policy),
        config(&server_key, server_policy),
    )
    .await;

    let client = client.expect("client allowlist should accept");
    let server = server.expect("server allowlist should accept");
    assert_eq!(client.auth.fingerprint.as_deref(), Some(server_fp.as_str()));
    assert_eq!(server.auth.fingerprint.as_deref(), Some(client_fp.as_str()));
    assert_eq!(client.auth.subject.as_deref(), Some("noise-server"));
    assert_eq!(server.auth.subject.as_deref(), Some("noise-client"));
    validate_authenticated_node_id(&client.auth, "noise-server").unwrap();
    assert!(validate_authenticated_node_id(&client.auth, "different-server").is_err());
}

#[test]
fn noise_hello_rejects_missing_handshake_identity() {
    let auth = AuthSummary {
        backend: SecurityBackend::Noise,
        fingerprint: Some("fingerprint".to_string()),
        subject: None,
        decision: "Accept".to_string(),
        reason: "test".to_string(),
        chain_valid: None,
        time_valid: None,
        node_names: Vec::new(),
        node_names_certified: false,
        pending_trust: None,
    };

    assert!(validate_authenticated_node_id(&auth, "claimed-node").is_err());
}

#[tokio::test]
async fn noise_allowlist_rejects_when_accept_side_has_no_match() {
    let dir = TestDir::new("allowlist-reject");
    let client_key = dir.join("client/static.key");
    let server_key = dir.join("server/static.key");
    let _client_fp = fingerprint_for(&client_key);
    let _server_fp = fingerprint_for(&server_key);

    let client_policy = policy("open");
    let mut server_policy = policy("allowlist");
    server_policy.allowlist_fingerprints = Some(vec!["deadbeef".to_string()]);

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let (client, server) = handshake_round(
        listener,
        config(&client_key, client_policy),
        config(&server_key, server_policy),
    )
    .await;

    assert!(client.is_ok(), "outbound open policy should accept");
    assert!(server.is_err(), "inbound allowlist should reject mismatch");
}

/// TOFU accepts a new key and trusts it once the connection is admitted,
/// which writes it to the trusted directory (ADR-0016). Which node ID a key
/// may use is the node identity binding's decision, made after the channel.
#[tokio::test]
async fn noise_tofu_trusts_a_new_key_once_it_is_admitted() {
    let dir = TestDir::new("tofu");
    let client_key = dir.join("client/static.key");
    let server_key_one = dir.join("server-one/static.key");
    let server_key_two = dir.join("server-two/static.key");
    let first_server_fp = fingerprint_for(&server_key_one);
    let second_server_fp = fingerprint_for(&server_key_two);
    assert_ne!(first_server_fp, second_server_fp);

    let trusted_dir = dir.join("trusted");
    let client_config = with_stores(
        config(&client_key, policy("tofu")),
        Some(&trusted_dir),
        None,
    );
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let (first_client, first_server) = handshake_round(
        listener.clone(),
        client_config.clone(),
        config(&server_key_one, policy("open")),
    )
    .await;
    let first_client = first_client.expect("first TOFU connection should accept");
    first_server.expect("server should accept first TOFU connection");
    assert_eq!(first_client.auth.reason, "new-tofu");
    assert_eq!(
        first_client.auth.fingerprint.as_deref(),
        Some(first_server_fp.as_str())
    );
    let pending = first_client.auth.pending_trust.expect("first use");
    let trusted_file = trusted_dir.join(format!("{first_server_fp}.noise"));
    assert_eq!(pending.path(), trusted_file);
    assert!(!trusted_file.exists(), "trusted only once admitted");
    pending.persist().unwrap();
    let record = fs::read_to_string(&trusted_file).unwrap();
    assert!(record.contains("claimed_identity=node:noise-server\n"));

    let (again_client, again_server) = handshake_round(
        listener.clone(),
        client_config.clone(),
        config(&server_key_one, policy("open")),
    )
    .await;
    let again_client = again_client.expect("a trusted key connects");
    again_server.expect("server should accept the client");
    assert_eq!(again_client.auth.reason, "seen-before");
    assert!(again_client.auth.pending_trust.is_none());

    let (other_client, other_server) = handshake_round(
        listener,
        client_config,
        config(&server_key_two, policy("open")),
    )
    .await;
    assert_eq!(
        other_client.expect("another new key").auth.reason,
        "new-tofu"
    );
    other_server.expect("server should still accept the client");
}

#[tokio::test]
async fn noise_tofu_rejects_without_a_trusted_directory() {
    let dir = TestDir::new("tofu-no-storage");
    let client_key = dir.join("client/static.key");
    let server_key = dir.join("server/static.key");

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let (client, server) = handshake_round(
        listener,
        config(&client_key, policy("tofu")),
        config(&server_key, policy("open")),
    )
    .await;

    assert!(
        client.is_err(),
        "TOFU without a trusted directory must reject"
    );
    server.expect("server open policy should accept");
}

#[tokio::test]
async fn noise_observe_rejects_and_keeps_the_remote_static_key() {
    let dir = TestDir::new("observe");
    let client_key = dir.join("client/static.key");
    let server_key = dir.join("server/static.key");
    let server_fp = fingerprint_for(&server_key);
    let trusted_dir = dir.join("trusted");
    let rejected_dir = dir.join("rejected");

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let (client, server) = handshake_round(
        listener,
        with_stores(
            config(&client_key, policy("observe")),
            Some(&trusted_dir),
            Some(&rejected_dir),
        ),
        config(&server_key, policy("open")),
    )
    .await;

    assert!(client.is_err(), "observe mode must reject");
    server.expect("server open policy should accept");
    let record = fs::read_to_string(rejected_dir.join(format!("{server_fp}.noise"))).unwrap();
    assert!(record.contains("claimed_identity=node:noise-server\n"));
    // Observing a key never trusts it: a later switch to TOFU sees it as new.
    assert!(!trusted_dir.exists());
}

#[tokio::test]
async fn noise_trusted_directory_accepts_a_key_file() {
    let dir = TestDir::new("allowlist-directory");
    let client_key = dir.join("client/static.key");
    let server_key = dir.join("server/static.key");
    let server_fp = fingerprint_for(&server_key);
    let trusted_dir = dir.join("trusted");
    fs::create_dir_all(&trusted_dir).unwrap();
    fs::write(
        trusted_dir.join(format!("{server_fp}.noise")),
        format!("kind=noise-static-key\nfingerprint_sha256={server_fp}\n"),
    )
    .unwrap();

    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let (client, server) = handshake_round(
        listener,
        with_stores(
            config(&client_key, policy("allowlist")),
            Some(&trusted_dir),
            None,
        ),
        config(&server_key, policy("open")),
    )
    .await;

    assert_eq!(
        client
            .expect("trusted directory should accept")
            .auth
            .fingerprint
            .as_deref(),
        Some(server_fp.as_str())
    );
    server.expect("server should accept client");
}

#[tokio::test]
async fn noise_pin_accepts_then_rejects_mismatch() {
    let dir = TestDir::new("pin");
    let client_key = dir.join("client/static.key");
    let server_key = dir.join("server/static.key");
    let server_fp = fingerprint_for(&server_key);
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());

    let mut pin_match = policy("open");
    pin_match.pin_fingerprints = Some(vec![server_fp.clone()]);
    let (accepted_client, accepted_server) = handshake_round(
        listener.clone(),
        config(&client_key, pin_match),
        config(&server_key, policy("open")),
    )
    .await;
    let accepted_client = accepted_client.expect("matching pin should accept");
    accepted_server.expect("server should accept matching pin connection");
    assert_eq!(
        accepted_client.auth.fingerprint.as_deref(),
        Some(server_fp.as_str())
    );

    let mut pin_mismatch = policy("open");
    pin_mismatch.pin_fingerprints = Some(vec!["deadbeef".to_string()]);
    let (rejected_client, rejected_server) = handshake_round(
        listener,
        config(&client_key, pin_mismatch),
        config(&server_key, policy("open")),
    )
    .await;
    assert!(rejected_client.is_err(), "mismatched pin should reject");
    rejected_server.expect("server should accept the client");
}
