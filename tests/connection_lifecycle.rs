use std::sync::Arc;
use std::time::Duration;

use thenodes::config::{Config, ConnectionPolicyConfig};
use thenodes::network::delivery::{process_incoming_message, IncomingMessageDisposition};
use thenodes::network::message::{MessageType, Payload};
use thenodes::network::{Message, MessageOrigin, PeerManager, PeerStore, RouteHealth, RouteKind};
use thenodes::plugin_host::manager::PluginManager;

/// A peer manager whose liveness monitor probes every 10 ms and gives up on a
/// peer silent for 30 ms, with one registered peer whose outbound frames land
/// in the returned receiver.
async fn monitored_peer(
    node_id: &str,
    port: u16,
) -> (PeerManager, tokio::sync::mpsc::Receiver<Message>) {
    let mut config = Config::default();
    config
        .network
        .as_mut()
        .expect("default network config")
        .connection_policy = Some(ConnectionPolicyConfig {
        heartbeat_interval_ms: Some(10),
        heartbeat_timeout_ms: Some(30),
        reconnect_max_attempts: Some(0),
        ..ConnectionPolicyConfig::default()
    });

    let peer_manager = PeerManager::new();
    let plugin_manager = Arc::new(PluginManager::new());
    peer_manager
        .configure_connection_lifecycle(
            config,
            "local-node".to_string(),
            &plugin_manager,
            PeerStore::new(),
            false,
        )
        .await;

    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    peer_manager
        .add_peer(addr, sender, node_id.to_string())
        .await
        .unwrap();
    (peer_manager, receiver)
}

// Paused time: the clock advances only when the runtime is idle, so machine
// load cannot make the monitor's first tick late.
#[tokio::test(start_paused = true)]
async fn heartbeat_timeout_marks_silent_peer_unresponsive() {
    let (peer_manager, mut heartbeat_receiver) = monitored_peer("silent-peer", 42999).await;

    let heartbeat = tokio::time::timeout(Duration::from_millis(30), heartbeat_receiver.recv())
        .await
        .expect("heartbeat should be scheduled")
        .expect("heartbeat channel should remain open");
    assert!(matches!(heartbeat.msg_type, MessageType::Heartbeat));

    tokio::time::timeout(Duration::from_millis(150), async {
        while peer_manager.has_node_id("silent-peer").await {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("silent peer should time out");

    assert_eq!(
        peer_manager
            .route_health("silent-peer", RouteKind::Tcp)
            .await,
        RouteHealth::Unresponsive
    );
}

/// Regression test: a node that was itself stalled for longer than the
/// heartbeat timeout used to drop every peer on its first tick afterwards,
/// before reading what they had sent. It now probes first.
#[tokio::test(start_paused = true)]
async fn stalled_node_probes_before_dropping_a_peer() {
    let (peer_manager, mut heartbeat_receiver) = monitored_peer("answering-peer", 43021).await;
    heartbeat_receiver.recv().await.expect("first probe");
    peer_manager
        .record_peer_activity_on_preferred_route("answering-peer")
        .await;

    // This node stalls for more than three heartbeat timeouts.
    tokio::time::advance(Duration::from_millis(100)).await;

    let probe = tokio::time::timeout(Duration::from_millis(5), heartbeat_receiver.recv())
        .await
        .expect("a probe right after the stall")
        .expect("peer should still be connected");
    assert!(matches!(probe.msg_type, MessageType::Heartbeat));
    assert!(peer_manager.has_node_id("answering-peer").await);

    // The peer answers once this node reads again, and stays.
    peer_manager
        .record_peer_activity_on_preferred_route("answering-peer")
        .await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(peer_manager.has_node_id("answering-peer").await);
}

#[tokio::test]
async fn indirect_activity_does_not_credit_a_direct_route() {
    let peer_manager = PeerManager::new();

    peer_manager
        .record_peer_activity_on_preferred_route("indirect-peer")
        .await;

    assert_eq!(
        peer_manager
            .route_health("indirect-peer", RouteKind::Udp)
            .await,
        RouteHealth::Unknown
    );
    assert_eq!(
        peer_manager
            .route_health("indirect-peer", RouteKind::Tcp)
            .await,
        RouteHealth::Unknown
    );
}

/// A connected peer must not be able to refresh another peer's liveness deadline (or
/// receive a heartbeat reply meant for someone else) by forging `Message::from`.
#[tokio::test]
async fn spoofed_heartbeat_sender_is_ignored() {
    let peer_manager = PeerManager::new();

    let addr_a: std::net::SocketAddr = "127.0.0.1:43001".parse().unwrap();
    let (sender_a, _receiver_a) = tokio::sync::mpsc::channel(8);
    peer_manager
        .add_peer(addr_a, sender_a, "peer-a".to_string())
        .await
        .unwrap();

    let addr_b: std::net::SocketAddr = "127.0.0.1:43002".parse().unwrap();
    let (sender_b, mut receiver_b) = tokio::sync::mpsc::channel(8);
    peer_manager
        .add_peer(addr_b, sender_b, "peer-b".to_string())
        .await
        .unwrap();

    // Delivered on peer-a's connection but claims to be from peer-b.
    let spoofed = Message::new(
        "peer-b",
        "local-node",
        MessageType::Heartbeat,
        Some(Payload::Text("liveness_probe_v1".to_string())),
        None,
    );
    let disposition = process_incoming_message(
        &peer_manager,
        "local-node",
        MessageOrigin::direct("peer-a", None),
        spoofed,
    )
    .await;
    assert!(matches!(disposition, IncomingMessageDisposition::Consumed));

    // peer-b never sent anything, so it must not receive a heartbeat reply.
    assert!(receiver_b.try_recv().is_err());

    // A genuine heartbeat from peer-b (verified sender matches `from`) does get a reply.
    let genuine = Message::new(
        "peer-b",
        "local-node",
        MessageType::Heartbeat,
        Some(Payload::Text("liveness_probe_v1".to_string())),
        None,
    );
    let disposition = process_incoming_message(
        &peer_manager,
        "local-node",
        MessageOrigin::direct("peer-b", None),
        genuine,
    )
    .await;
    assert!(matches!(disposition, IncomingMessageDisposition::Consumed));
    assert!(receiver_b.try_recv().is_ok());
}

/// Once the liveness monitor excludes a route as `Unresponsive`, an ordinary later
/// delivery failure must not downgrade it back to `Suspect` (which would make
/// `connect_with_policy` treat it as usable again).
#[tokio::test]
async fn unresponsive_route_is_not_downgraded_by_later_failure() {
    let peer_manager = PeerManager::new();

    peer_manager
        .mark_route_unresponsive("gone-peer", RouteKind::Tcp)
        .await;
    peer_manager
        .mark_route_failure("gone-peer", RouteKind::Tcp)
        .await;

    assert_eq!(
        peer_manager.route_health("gone-peer", RouteKind::Tcp).await,
        RouteHealth::Unresponsive
    );

    peer_manager
        .mark_route_success("gone-peer", RouteKind::Tcp)
        .await;

    assert_eq!(
        peer_manager.route_health("gone-peer", RouteKind::Tcp).await,
        RouteHealth::Healthy
    );
}

/// Regression test: `broadcast` used to await each send
/// while holding the `peers` lock, so one peer that stopped reading froze every
/// peer operation on the node.
#[tokio::test]
async fn broadcast_does_not_block_on_a_stalled_peer() {
    let peer_manager = PeerManager::new();

    let stalled_addr: std::net::SocketAddr = "127.0.0.1:43011".parse().unwrap();
    let (stalled, _stalled_receiver) = tokio::sync::mpsc::channel(1);
    peer_manager
        .add_peer(stalled_addr, stalled.clone(), "stalled".to_string())
        .await
        .unwrap();
    let probe = || Message::outbound(MessageType::Heartbeat, None, None);
    stalled.try_send(probe()).unwrap();

    let healthy_addr: std::net::SocketAddr = "127.0.0.1:43012".parse().unwrap();
    let (healthy, mut healthy_receiver) = tokio::sync::mpsc::channel(8);
    peer_manager
        .add_peer(healthy_addr, healthy, "healthy".to_string())
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(1), peer_manager.broadcast(&probe()))
        .await
        .expect("broadcast blocked on the stalled peer");
    assert!(matches!(
        healthy_receiver.try_recv().unwrap().msg_type,
        MessageType::Heartbeat
    ));
    tokio::time::timeout(Duration::from_secs(1), peer_manager.list_peers())
        .await
        .expect("peers lock still held after broadcast");
}
