//! Regression tests for frame addressing and sender attribution (ADR-0012):
//! a frame must name the node bound to its connection and the local node, and
//! a relay tunnel carries only application messages, marked as relayed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use thenodes::config::Config;
use thenodes::network::message::{encode_relay_opaque_payload, Message, MessageType};
use thenodes::network::{bind_listener, run_listener, PeerManager, PeerStore};
use thenodes::plugin_host::{Plugin, PluginContext, PluginManager, PluginRegistrar, StartPolicy};
use thenodes::realms::RealmInfo;

const LOCAL_NODE: &str = "node-a";

struct Capture {
    seen: Arc<Mutex<Vec<Message>>>,
}

#[async_trait]
impl Plugin for Capture {
    fn plugin_id(&self) -> &'static str {
        "capture"
    }

    async fn on_message(&self, message: &Message, _ctx: &PluginContext) {
        self.seen.lock().push(message.clone());
    }
}

struct Node {
    port: u16,
    peer_manager: PeerManager,
    peer_store: PeerStore,
    seen: Arc<Mutex<Vec<Message>>>,
}

fn realm() -> RealmInfo {
    RealmInfo::new("sender", "1")
}

async fn spawn_node() -> Node {
    let config = Config {
        realm: Some(realm()),
        ..Default::default()
    };
    let peer_manager = PeerManager::new();
    let peer_store = PeerStore::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ctx = PluginContext::new(
        Arc::new(peer_manager.clone()),
        peer_store.clone(),
        thenodes::events::dispatcher::handle(),
        LOCAL_NODE.to_string(),
        config.clone(),
        false,
    );
    let mut plugins = PluginManager::with_context(ctx);
    plugins
        .register_handler(Box::new(Capture { seen: seen.clone() }))
        .unwrap();
    let plugins = Arc::new(plugins);
    plugins
        .start_all(StartPolicy::StopOnFirstFailure)
        .await
        .unwrap();
    plugins.activate().unwrap();

    let listener = bind_listener(0, false).await.expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let store = peer_store.clone();
    let node_peer_manager = peer_manager.clone();
    tokio::spawn(async move {
        let config = config;
        let _ = run_listener(
            listener,
            realm(),
            peer_manager,
            plugins,
            &config,
            LOCAL_NODE.to_string(),
            store,
            false,
        )
        .await;
    });
    Node {
        port,
        peer_manager: node_peer_manager,
        peer_store,
        seen,
    }
}

struct RawPeer {
    /// This peer's address as the node sees it.
    addr: SocketAddr,
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RawPeer {
    /// Connect over plaintext and complete HELLO as `node_id`.
    async fn connect(port: u16, node_id: &str) -> Self {
        Self::connect_as(port, node_id, node_id).await
    }

    /// Connect over plaintext and send a HELLO announcing `node_id` with
    /// `hello_from` in its `from` field.
    async fn connect_as(port: u16, node_id: &str, hello_from: &str) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let addr = stream.local_addr().unwrap();
        let (r, writer) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut server_hello = String::new();
        tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut server_hello))
            .await
            .expect("server HELLO")
            .unwrap();
        let mut peer = Self {
            addr,
            reader,
            writer,
        };
        peer.send(&Message::new(
            hello_from,
            LOCAL_NODE,
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
        ))
        .await;
        peer
    }

    async fn send(&mut self, message: &Message) {
        self.writer
            .write_all(format!("{}\n", message.as_json()).as_bytes())
            .await
            .unwrap();
    }
}

fn text(from: &str, to: &str, body: &str) -> Message {
    Message::new(from, to, MessageType::Text(body.to_string()), None, None)
}

/// A `RELAY_FWD` frame addressed to this node carrying `inner`, as the relay
/// `relay-1` would deliver it.
fn tunnel(inner: &Message) -> Message {
    Message::new(
        "relay-1",
        LOCAL_NODE,
        MessageType::RelayForward {
            to: LOCAL_NODE.to_string(),
            from: inner.from.clone(),
            sequence: None,
            opaque_payload_b64: encode_relay_opaque_payload(inner.as_json()),
        },
        None,
        None,
    )
}

fn find_text(seen: &Mutex<Vec<Message>>, body: &str) -> Option<Message> {
    seen.lock()
        .iter()
        .find(|message| matches!(&message.msg_type, MessageType::Text(t) if t == body))
        .cloned()
}

async fn wait_for_text(seen: &Mutex<Vec<Message>>, body: &str) -> Message {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(message) = find_text(seen, body) {
            return message;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("plugin never received TEXT {body:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frames_must_name_both_ends_of_the_connection() {
    let node = spawn_node().await;
    let mut peer = RawPeer::connect(node.port, "peer-x").await;

    peer.send(&text("trusted-admin", LOCAL_NODE, "claims-another-sender"))
        .await;
    peer.send(&text("peer-x", "node-z", "addressed-elsewhere"))
        .await;
    // Frames on one connection are handled in order, so once this arrives the
    // frames above have been processed.
    peer.send(&text("peer-x", LOCAL_NODE, "marker")).await;

    let received = wait_for_text(&node.seen, "marker").await;
    assert!(find_text(&node.seen, "claims-another-sender").is_none());
    assert!(find_text(&node.seen, "addressed-elsewhere").is_none());
    assert_eq!(received.from, "peer-x");
    let origin = received
        .origin()
        .expect("received messages carry an origin");
    assert_eq!(origin.peer, "peer-x");
    assert_eq!(origin.relayed_from, None);
    // Plaintext proves no transport identity, so nobody is authenticated.
    assert_eq!(origin.peer_fingerprint, None);
    assert_eq!(origin.authenticated_sender(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_from_must_be_its_node_id() {
    let node = spawn_node().await;
    // Earlier versions wrote "TheNodes" into HELLO's `from`.
    let mut peer = RawPeer::connect_as(node.port, "peer-y", "TheNodes").await;

    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(3), peer.reader.read_line(&mut line))
        .await
        .expect("listener should close the connection");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "connection stayed open: {line:?}"
    );
    assert!(node.seen.lock().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_tunnel_carries_only_application_messages() {
    let node = spawn_node().await;
    let mut relay = RawPeer::connect(node.port, "relay-1").await;

    let peer_list = Message::new(
        "ceo",
        LOCAL_NODE,
        MessageType::PeerList {
            peers: vec!["10.0.0.5:22".to_string()],
        },
        None,
        None,
    );
    let mut nested = tunnel(&text("ceo", LOCAL_NODE, "nested"));
    nested.from = "ceo".to_string();
    relay.send(&tunnel(&peer_list)).await;
    relay.send(&tunnel(&nested)).await;
    relay
        .send(&tunnel(&text("ceo", LOCAL_NODE, "via-tunnel")))
        .await;
    // Frames on one connection are handled in order, so once this arrives the
    // tunnels above have been processed.
    relay.send(&text("relay-1", LOCAL_NODE, "marker")).await;
    wait_for_text(&node.seen, "marker").await;

    let relayed = find_text(&node.seen, "via-tunnel").expect("tunneled TEXT delivered");
    assert_eq!(relayed.from, "ceo");
    let origin = relayed.origin().unwrap();
    assert_eq!(origin.peer, "relay-1");
    assert_eq!(origin.relayed_from.as_deref(), Some("ceo"));
    assert_eq!(origin.authenticated_sender(), None);

    assert!(find_text(&node.seen, "nested").is_none());
    assert!(!node.seen.lock().iter().any(|message| matches!(
        message.msg_type,
        MessageType::PeerList { .. } | MessageType::RelayForward { .. }
    )));
    let stored = node.peer_store.all().await;
    assert!(
        !stored.iter().any(|addr| addr.to_string() == "10.0.0.5:22"),
        "tunneled PEER_LIST reached the peer store: {stored:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deregistered_connection_is_closed_on_its_next_frame() {
    let node = spawn_node().await;
    let mut peer = RawPeer::connect(node.port, "peer-z").await;
    peer.send(&text("peer-z", LOCAL_NODE, "registered")).await;
    wait_for_text(&node.seen, "registered").await;

    // As the liveness monitor does for a peer that stopped answering.
    node.peer_manager.remove_peer(&peer.addr).await;
    peer.send(&text("peer-z", LOCAL_NODE, "after-removal"))
        .await;

    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(3), peer.reader.read_line(&mut line))
        .await
        .expect("node should close the connection");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "connection stayed open: {line:?}"
    );
    assert!(find_text(&node.seen, "after-removal").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_list_adds_a_capped_set_of_unverified_candidates() {
    let node = spawn_node().await;
    let mut peer = RawPeer::connect(node.port, "peer-g").await;
    let peers: Vec<String> = (1..=100).map(|i| format!("203.0.113.{i}:5000")).collect();
    peer.send(&Message::new(
        "peer-g",
        LOCAL_NODE,
        MessageType::PeerList { peers },
        None,
        None,
    ))
    .await;
    peer.send(&text("peer-g", LOCAL_NODE, "marker")).await;
    wait_for_text(&node.seen, "marker").await;

    assert_eq!(node.peer_store.all().await.len(), 64);
    // Candidates are not passed on to other peers until this node reaches them.
    assert!(node
        .peer_store
        .sample(100, &Default::default())
        .await
        .is_empty());
}
