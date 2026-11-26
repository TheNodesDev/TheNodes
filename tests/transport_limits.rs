//! Integration tests for `[network.limits]`: frame-size bounds, handshake and idle
//! timeouts, inbound connection caps, and the outbound connect timeout.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use thenodes::config::{Config, ConnectionPolicyConfig, NetworkLimitsConfig};
use thenodes::network::peer::Peer;
use thenodes::network::peer_manager::PeerManager;
use thenodes::network::peer_store::PeerStore;
use thenodes::network::{bind_listener, run_listener, NetworkLimits};
use thenodes::plugin_host::manager::PluginManager;
use thenodes::realms::RealmInfo;

const REALM_JSON: &str = r#"{"name":"limits","code":"limits","version":"1"}"#;

struct Node {
    port: u16,
    peer_manager: PeerManager,
}

async fn spawn_node(limits: NetworkLimitsConfig) -> Node {
    let realm = RealmInfo::new("limits", "1");
    let mut config = Config {
        realm: Some(realm.clone()),
        ..Default::default()
    };
    config.network.as_mut().unwrap().limits = Some(limits);
    let listener = bind_listener(0, false).await.expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let peer_manager = PeerManager::new();
    {
        let peer_manager = peer_manager.clone();
        tokio::spawn(async move {
            let config = config;
            let _ = run_listener(
                listener,
                realm,
                peer_manager,
                Arc::new(PluginManager::new()),
                &config,
                "node-under-test".to_string(),
                PeerStore::new(),
                false,
            )
            .await;
        });
    }
    Node { port, peer_manager }
}

struct RawClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RawClient {
    async fn connect(port: u16) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (r, writer) = stream.into_split();
        Self {
            reader: BufReader::new(r),
            writer,
        }
    }

    /// Read one line; `Ok(0)` means the server closed the connection.
    async fn read_line(&mut self) -> std::io::Result<usize> {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
            .await
            .expect("server did not respond or close within 3s")
    }

    async fn expect_server_hello(&mut self) {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
            .await
            .expect("timed out waiting for server HELLO")
            .unwrap();
        assert!(
            n > 0 && line.contains("\"HELLO\""),
            "expected HELLO, got {line:?}"
        );
    }

    async fn expect_closed(&mut self) {
        let n = self.read_line().await.unwrap_or(0);
        assert_eq!(n, 0, "expected the server to close the connection");
    }

    async fn send_hello(&mut self, node_id: &str) {
        let hello = format!(
            r#"{{"from":"{node_id}","to":"node-under-test","msg_type":{{"HELLO":{{"node_id":"{node_id}","listen_addr":null,"protocol":"TheNodes","version":"1","node_type":"daemon","capabilities":null}}}},"payload":null,"realm":{REALM_JSON}}}"#
        );
        self.writer.write_all(hello.as_bytes()).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
    }

    async fn write_raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await
    }
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
    panic!("timed out waiting for {what}");
}

fn limits_with(mutate: impl FnOnce(&mut NetworkLimitsConfig)) -> NetworkLimitsConfig {
    let mut limits = NetworkLimitsConfig::default();
    mutate(&mut limits);
    limits
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_hello_is_rejected_before_registration() {
    let node = spawn_node(NetworkLimitsConfig::default()).await;
    let mut client = RawClient::connect(node.port).await;
    client.expect_server_hello().await;

    // More than MAX_HELLO_FRAME_BYTES without a newline: the server must stop reading
    // and close instead of buffering indefinitely.
    let payload = vec![b'a'; NetworkLimits::MAX_HELLO_FRAME_BYTES + 4096];
    let _ = client.write_raw(&payload).await;

    client.expect_closed().await;
    assert!(node.peer_manager.list_peers().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_hello_first_frame_closes_connection() {
    let node = spawn_node(NetworkLimitsConfig::default()).await;

    let mut garbage = RawClient::connect(node.port).await;
    garbage.expect_server_hello().await;
    garbage.write_raw(b"not json at all\n").await.unwrap();
    garbage.expect_closed().await;

    let mut wrong_type = RawClient::connect(node.port).await;
    wrong_type.expect_server_hello().await;
    let text = format!(
        r#"{{"from":"x","to":"node-under-test","msg_type":{{"TEXT":"hi"}},"payload":null,"realm":{REALM_JSON}}}"#
    );
    wrong_type.write_raw(text.as_bytes()).await.unwrap();
    wrong_type.write_raw(b"\n").await.unwrap();
    wrong_type.expect_closed().await;

    assert!(node.peer_manager.list_peers().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_after_hello_disconnects_and_deregisters_peer() {
    let node = spawn_node(limits_with(|l| l.max_frame_bytes = Some(4096))).await;
    let mut client = RawClient::connect(node.port).await;
    client.expect_server_hello().await;
    client.send_hello("big-frame").await;
    let pm = node.peer_manager.clone();
    wait_until("peer registration", || {
        let pm = pm.clone();
        async move { pm.has_node_id("big-frame").await }
    })
    .await;

    let payload = vec![b'x'; 8192];
    let _ = client.write_raw(&payload).await;

    client.expect_closed().await;
    let pm = node.peer_manager.clone();
    wait_until("peer deregistration", || {
        let pm = pm.clone();
        async move { !pm.has_node_id("big-frame").await }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frame_at_the_limit_is_still_accepted() {
    let node = spawn_node(limits_with(|l| l.max_frame_bytes = Some(512))).await;
    let mut client = RawClient::connect(node.port).await;
    client.expect_server_hello().await;
    client.send_hello("exact-frame").await;
    let pm = node.peer_manager.clone();
    wait_until("peer registration", || {
        let pm = pm.clone();
        async move { pm.has_node_id("exact-frame").await }
    })
    .await;

    let prefix = r#"{"from":"exact-frame","to":"node-under-test","msg_type":{"TEXT":""#;
    let suffix = "\"},\"payload\":null,\"realm\":null}\n";
    let filler = "y".repeat(512 - prefix.len() - suffix.len());
    let frame = format!("{prefix}{filler}{suffix}");
    assert_eq!(frame.len(), 512);
    client.write_raw(frame.as_bytes()).await.unwrap();

    // Still connected: a second, small frame is accepted and the peer stays registered.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(node.peer_manager.has_node_id("exact-frame").await);
    client
        .write_raw(
            br#"{"from":"exact-frame","to":"node-under-test","msg_type":"HEARTBEAT","payload":null,"realm":null}
"#,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(node.peer_manager.has_node_id("exact-frame").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_client_is_closed_after_handshake_timeout() {
    let node = spawn_node(limits_with(|l| l.handshake_timeout_ms = Some(300))).await;
    let started = Instant::now();
    let mut client = RawClient::connect(node.port).await;
    client.expect_server_hello().await;

    client.expect_closed().await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3),
        "closed after {elapsed:?}"
    );
    assert!(node.peer_manager.list_peers().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_registered_peer_is_closed_and_deregistered() {
    let node = spawn_node(limits_with(|l| l.idle_timeout_ms = Some(300))).await;
    let mut client = RawClient::connect(node.port).await;
    client.expect_server_hello().await;
    client.send_hello("idle-peer").await;
    let pm = node.peer_manager.clone();
    wait_until("peer registration", || {
        let pm = pm.clone();
        async move { pm.has_node_id("idle-peer").await }
    })
    .await;

    client.expect_closed().await;
    let pm = node.peer_manager.clone();
    wait_until("peer deregistration", || {
        let pm = pm.clone();
        async move { !pm.has_node_id("idle-peer").await }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_zero_keeps_quiet_peer_connected() {
    let node = spawn_node(limits_with(|l| l.idle_timeout_ms = Some(0))).await;
    let mut client = RawClient::connect(node.port).await;
    client.expect_server_hello().await;
    client.send_hello("quiet-peer").await;
    let pm = node.peer_manager.clone();
    wait_until("peer registration", || {
        let pm = pm.clone();
        async move { pm.has_node_id("quiet-peer").await }
    })
    .await;

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(node.peer_manager.has_node_id("quiet-peer").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_ip_cap_rejects_and_releases_slots() {
    let node = spawn_node(limits_with(|l| {
        l.max_inbound_connections = Some(10);
        l.max_inbound_connections_per_ip = Some(2);
    }))
    .await;

    let mut first = RawClient::connect(node.port).await;
    first.expect_server_hello().await;
    let mut second = RawClient::connect(node.port).await;
    second.expect_server_hello().await;

    // Third connection from the same IP is dropped without a HELLO.
    let mut third = RawClient::connect(node.port).await;
    third.expect_closed().await;

    // Releasing one slot admits a new connection.
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut retry = RawClient::connect(node.port).await;
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(3), retry.reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap_or(0);
        if n > 0 {
            assert!(line.contains("\"HELLO\""));
            break;
        }
        assert!(Instant::now() < deadline, "slot was never released");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_cap_rejects_excess_connections() {
    let node = spawn_node(limits_with(|l| {
        l.max_inbound_connections = Some(1);
        l.max_inbound_connections_per_ip = Some(10);
    }))
    .await;

    let mut first = RawClient::connect(node.port).await;
    first.expect_server_hello().await;

    let mut second = RawClient::connect(node.port).await;
    second.expect_closed().await;
    drop(first);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_connect_honours_direct_tcp_timeout() {
    let mut config = Config::default();
    config.network.as_mut().unwrap().connection_policy = Some(ConnectionPolicyConfig {
        direct_tcp_timeout_ms: Some(200),
        ..ConnectionPolicyConfig::default()
    });
    // TEST-NET-1 is unroutable: the SYN is dropped and only the timeout can end the dial.
    let peer = Peer::new("blackhole".to_string(), "192.0.2.1:9".to_string());

    let started = Instant::now();
    let result = thenodes::network::transport::connect_to_peer_handshake_only(
        &peer,
        RealmInfo::new("limits", "1"),
        0,
        false,
        &config,
        "dialer".to_string(),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(result.is_err());
    assert!(elapsed < Duration::from_secs(5), "dial took {elapsed:?}");
}

/// Regression test: a node checked the realm of nodes that connected to
/// it, but not of nodes it dialled, so gossip or a reconnect could connect it
/// into another realm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_connect_refuses_a_server_of_another_realm() {
    let node = spawn_node(NetworkLimitsConfig::default()).await;
    let peer = Peer::new(
        "node-under-test".to_string(),
        format!("127.0.0.1:{}", node.port),
    );
    let config = Config::default();
    for (realm, accepted) in [
        (RealmInfo::new("other", "1"), false),
        (RealmInfo::new("limits", "1"), true),
    ] {
        let result = thenodes::network::transport::connect_to_peer_handshake_only(
            &peer,
            realm,
            0,
            false,
            &config,
            "dialer".to_string(),
        )
        .await;
        match result {
            Ok(()) => assert!(accepted, "connected into another realm"),
            Err(err) => {
                assert!(!accepted, "{err}");
                assert!(err.to_string().contains("realm"), "{err}");
            }
        }
    }
}
