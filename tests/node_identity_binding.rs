//! Integration tests for node identity binding (ADR-0012):
//! the node ID a peer claims in HELLO must match the TLS certificate key that
//! authenticated its connection.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use thenodes::config::{
    Config, EncryptionConfig, EncryptionTlsConfig, NodeIdentityConfig, TlsPaths,
    TlsTrustPolicyConfig,
};
use thenodes::network::message::{Message, MessageType};
use thenodes::network::peer::Peer;
use thenodes::network::{bind_listener, run_listener, PeerManager, PeerStore};
use thenodes::plugin_host::manager::PluginManager;
use thenodes::realms::RealmInfo;
use thenodes::security::node_identity::{node_name_uri, IdentityKind};
use thenodes::security::secure_channel::{Channel, SecureChannel, TlsSecureChannel};
use thenodes::security::trust::spki_fingerprint_from_pem_bytes;

fn realm() -> RealmInfo {
    RealmInfo::new("binding", "1")
}

struct Authority {
    certificate: Certificate,
    key: KeyPair,
}

fn authority(dir: &Path) -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "binding test CA");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2040, 1, 1);
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("ca.pem"), certificate.pem()).unwrap();
    Authority { certificate, key }
}

/// A TLS identity on disk and the SPKI fingerprint peers see for it.
struct Identity {
    cert: String,
    key: String,
    fingerprint: String,
}

/// A certificate for `name`, naming `node_name` in the test realm.
fn identity(
    dir: &Path,
    name: &str,
    node_name: Option<&str>,
    issuer: Option<&Authority>,
) -> Identity {
    let uri = node_name.map(|node_id| node_name_uri(&realm().canonical_code(), node_id));
    identity_with_uri(dir, name, uri.as_deref(), issuer)
}

fn identity_with_uri(
    dir: &Path,
    name: &str,
    node_name_uri: Option<&str>,
    issuer: Option<&Authority>,
) -> Identity {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2040, 1, 1);
    if let Some(uri) = node_name_uri {
        params
            .subject_alt_names
            .push(SanType::URI(uri.try_into().unwrap()));
    }
    let key = KeyPair::generate().unwrap();
    let certificate = match issuer {
        Some(ca) => params.signed_by(&key, &ca.certificate, &ca.key).unwrap(),
        None => params.self_signed(&key).unwrap(),
    };
    let cert = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}.key.pem"));
    std::fs::write(&cert, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    Identity {
        cert: cert.display().to_string(),
        key: key_path.display().to_string(),
        fingerprint: spki_fingerprint_from_pem_bytes(certificate.pem().as_bytes()).unwrap(),
    }
}

/// mTLS with an open trust policy, so only node identity binding decides.
/// With `ca_dir`, chains must validate against that CA (self-signed
/// certificates are still accepted through the self-signed override).
fn tls_config(identity: &Identity, binding: NodeIdentityConfig, ca_dir: Option<&Path>) -> Config {
    Config {
        realm: Some(realm()),
        encryption: Some(EncryptionConfig {
            enabled: true,
            backend: Some("tls".to_string()),
            tls: Some(EncryptionTlsConfig {
                mtls: Some(true),
                paths: Some(TlsPaths {
                    own_certificate: Some(identity.cert.clone()),
                    own_private_key: Some(identity.key.clone()),
                    issuer_cert_dir: ca_dir.map(|dir| dir.display().to_string()),
                    ..Default::default()
                }),
                trust_policy: Some(TlsTrustPolicyConfig {
                    mode: Some("open".to_string()),
                    accept_self_signed: Some(true),
                    enforce_ca_chain: Some(ca_dir.is_some()),
                    ..Default::default()
                }),
            }),
            node_identity: Some(binding),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn binding(mode: &str, pins: &[(&str, &str)]) -> NodeIdentityConfig {
    NodeIdentityConfig {
        mode: Some(mode.to_string()),
        pins: Some(
            pins.iter()
                .map(|(node_id, fingerprint)| (node_id.to_string(), vec![fingerprint.to_string()]))
                .collect::<HashMap<_, _>>(),
        ),
        ..Default::default()
    }
}

async fn spawn_server(config: Config, node_id: &str) -> (u16, PeerManager) {
    let listener = bind_listener(0, false).await.expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let peer_manager = PeerManager::new();
    let server_manager = peer_manager.clone();
    let node_id = node_id.to_string();
    tokio::spawn(async move {
        let config = config;
        let _ = run_listener(
            listener,
            realm(),
            server_manager,
            Arc::new(PluginManager::new()),
            &config,
            node_id,
            PeerStore::new(),
            false,
        )
        .await;
    });
    (port, peer_manager)
}

/// Open an mTLS connection, read the server's HELLO and answer as `node_id`.
/// The returned channel keeps the connection open.
async fn tls_hello(port: u16, config: &Config, node_id: &str) -> Channel {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let addr = stream.peer_addr().unwrap();
    let mut channel = TlsSecureChannel::new()
        .connect(stream, addr, &realm(), config, false)
        .await
        .expect("TLS handshake");
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), channel.reader.read_line(&mut line))
        .await
        .expect("server HELLO")
        .unwrap();
    let hello = Message::new(
        node_id,
        "server",
        MessageType::Hello {
            node_id: node_id.to_string(),
            listen_addr: None,
            protocol: Some("TheNodes".to_string()),
            version: Some("1".to_string()),
            node_type: Some("daemon".to_string()),
            capabilities: None,
            udp_listen_addr: None,
            udp_observed_addr: None,
        },
        None,
        Some(realm()),
    );
    channel
        .writer
        .write_all(format!("{}\n", hello.as_json()).as_bytes())
        .await
        .unwrap();
    channel.writer.flush().await.unwrap();
    channel
}

async fn expect_closed(channel: &mut Channel) {
    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(3), channel.reader.read_line(&mut line))
        .await
        .expect("server neither closed the connection nor sent anything");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "expected the server to close the connection, got {read:?} {line:?}"
    );
}

async fn wait_until<F, Fut>(what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if condition().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tofu_keeps_a_node_id_bound_to_its_first_key() {
    let dir = TempDir::new().unwrap();
    let server_identity = identity(dir.path(), "server", None, None);
    let owner = identity(dir.path(), "owner", None, None);
    let squatter = identity(dir.path(), "squatter", None, None);
    let server_config = tls_config(&server_identity, NodeIdentityConfig::default(), None);
    let (port, server) = spawn_server(server_config.clone(), "server").await;
    let owner_config = tls_config(&owner, NodeIdentityConfig::default(), None);

    let owner_channel = tls_hello(port, &owner_config, "node-x").await;
    wait_until("owner registered", || server.has_node_id("node-x")).await;
    let registry = server.node_identity(&server_config);
    wait_until("owner binding recorded", || async {
        !registry.bindings().is_empty()
    })
    .await;
    let bindings = registry.bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].node_id, "node-x");
    assert_eq!(bindings[0].kind, IdentityKind::Tls);
    assert_eq!(bindings[0].fingerprint, owner.fingerprint);
    drop(owner_channel);
    wait_until("owner released", || async {
        !server.has_node_id("node-x").await
    })
    .await;

    // Before ADR-0012, the first claimant of a free node ID got it.
    let mut squatter_channel = tls_hello(
        port,
        &tls_config(&squatter, NodeIdentityConfig::default(), None),
        "node-x",
    )
    .await;
    expect_closed(&mut squatter_channel).await;
    assert!(!server.has_node_id("node-x").await);

    let _owner_again = tls_hello(port, &owner_config, "node-x").await;
    wait_until("owner registered again", || server.has_node_id("node-x")).await;
}

/// Transport TOFU trusts a new certificate, writing it to the trusted
/// directory, only once its connection is admitted (ADR-0016). A key the node
/// identity binding refuses is new to TOFU too, but never becomes trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tofu_trusts_a_certificate_only_once_its_connection_is_admitted() {
    let dir = TempDir::new().unwrap();
    let trusted = dir.path().join("trusted");
    let server_identity = identity(dir.path(), "server", None, None);
    let owner = identity(dir.path(), "owner", None, None);
    let squatter = identity(dir.path(), "squatter", None, None);
    let mut server_config = tls_config(&server_identity, NodeIdentityConfig::default(), None);
    {
        let tls = server_config
            .encryption
            .as_mut()
            .and_then(|encryption| encryption.tls.as_mut())
            .unwrap();
        tls.trust_policy.as_mut().unwrap().mode = Some("tofu".to_string());
        tls.paths.as_mut().unwrap().trusted_cert_dir = Some(trusted.display().to_string());
    }
    let (port, server) = spawn_server(server_config, "server").await;

    let _owner = tls_hello(
        port,
        &tls_config(&owner, NodeIdentityConfig::default(), None),
        "node-x",
    )
    .await;
    wait_until("owner registered", || server.has_node_id("node-x")).await;
    assert!(trusted.join(format!("{}.pem", owner.fingerprint)).exists());

    let mut squatter_channel = tls_hello(
        port,
        &tls_config(&squatter, NodeIdentityConfig::default(), None),
        "node-x",
    )
    .await;
    expect_closed(&mut squatter_channel).await;
    assert!(!trusted
        .join(format!("{}.pem", squatter.fingerprint))
        .exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_mode_accepts_only_pinned_keys_for_their_node_ids() {
    let dir = TempDir::new().unwrap();
    let server_identity = identity(dir.path(), "server", None, None);
    let owner = identity(dir.path(), "owner", None, None);
    let other = identity(dir.path(), "other", None, None);
    let server_config = tls_config(
        &server_identity,
        binding("pinned", &[("node-x", &owner.fingerprint)]),
        None,
    );
    let (port, server) = spawn_server(server_config, "server").await;
    let owner_config = tls_config(&owner, NodeIdentityConfig::default(), None);
    let other_config = tls_config(&other, NodeIdentityConfig::default(), None);

    for (config, node_id) in [
        (&other_config, "node-x"), // node-pin-mismatch
        (&owner_config, "node-y"), // fingerprint-pinned-to-other-node
        (&other_config, "node-z"), // node-not-pinned
    ] {
        let mut channel = tls_hello(port, config, node_id).await;
        expect_closed(&mut channel).await;
        assert!(!server.has_node_id(node_id).await, "{node_id} registered");
    }

    let _owner = tls_hello(port, &owner_config, "node-x").await;
    wait_until("pinned owner registered", || server.has_node_id("node-x")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_mode_requires_a_ca_certified_node_name() {
    let dir = TempDir::new().unwrap();
    let ca_dir = dir.path().join("ca");
    let ca = authority(&ca_dir);
    let server_identity = identity(dir.path(), "server", Some("server"), Some(&ca));
    let certified = identity(dir.path(), "certified", Some("node-x"), Some(&ca));
    let self_named = identity(dir.path(), "self-named", Some("node-x"), None);
    // The same CA names node-x in another realm's namespace.
    let other_realm = identity_with_uri(
        dir.path(),
        "other-realm",
        Some(&node_name_uri("other-realm", "node-x")),
        Some(&ca),
    );
    let server_config = tls_config(&server_identity, binding("certificate", &[]), Some(&ca_dir));
    let (port, server) = spawn_server(server_config, "server").await;
    let certified_config = tls_config(&certified, NodeIdentityConfig::default(), Some(&ca_dir));
    let self_named_config = tls_config(&self_named, NodeIdentityConfig::default(), Some(&ca_dir));
    let other_realm_config = tls_config(&other_realm, NodeIdentityConfig::default(), Some(&ca_dir));

    // The CA names node-x, so node-y is a mismatch.
    let mut channel = tls_hello(port, &certified_config, "node-y").await;
    expect_closed(&mut channel).await;
    // A self-signed certificate can name any node; only a CA can certify one.
    let mut channel = tls_hello(port, &self_named_config, "node-x").await;
    expect_closed(&mut channel).await;
    // Each realm is its own namespace: a name in another realm certifies
    // nothing here.
    let mut channel = tls_hello(port, &other_realm_config, "node-x").await;
    expect_closed(&mut channel).await;
    assert!(!server.has_node_id("node-x").await);

    let _certified = tls_hello(port, &certified_config, "node-x").await;
    wait_until("certified node registered", || server.has_node_id("node-x")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_connection_checks_the_server_node_id() {
    let dir = TempDir::new().unwrap();
    let ca_dir = dir.path().join("ca");
    let ca = authority(&ca_dir);
    let server_identity = identity(dir.path(), "server", Some("server"), Some(&ca));
    let client = identity(dir.path(), "client", Some("client"), Some(&ca));
    let server_config = tls_config(&server_identity, binding("certificate", &[]), Some(&ca_dir));

    let handshake = |port: u16, client_config: Config| async move {
        let peer = Peer {
            id: "server".into(),
            address: format!("127.0.0.1:{port}"),
            capabilities: None,
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            thenodes::network::transport::connect_to_peer_handshake_only(
                &peer,
                realm(),
                0,
                false,
                &client_config,
                "client".to_string(),
            ),
        )
        .await
        .expect("handshake timed out")
        .map_err(|error| error.to_string())
    };

    let (honest_port, _honest) = spawn_server(server_config.clone(), "server").await;
    let (impostor_port, _impostor) = spawn_server(server_config, "impostor").await;
    let certificate_client = tls_config(&client, binding("certificate", &[]), Some(&ca_dir));
    handshake(honest_port, certificate_client.clone())
        .await
        .expect("certified server accepted");
    let error = handshake(impostor_port, certificate_client)
        .await
        .expect_err("server claiming another node's certificate");
    assert!(error.contains("node-name-mismatch"), "{error}");

    let wrong_pin = "f".repeat(64);
    let error = handshake(
        honest_port,
        tls_config(
            &client,
            binding("pinned", &[("server", &wrong_pin)]),
            Some(&ca_dir),
        ),
    )
    .await
    .expect_err("pinned to another key");
    assert!(error.contains("node-pin-mismatch"), "{error}");
}
