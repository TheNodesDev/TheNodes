use std::sync::Arc;
use std::time::Duration;

use thenodes::config::{Config, ConnectionPolicyConfig};
use thenodes::network::delivery::{process_incoming_message, IncomingMessageDisposition};
use thenodes::network::message::{MessageType, Payload};
use thenodes::network::{Message, PeerManager, PeerStore, RouteHealth, RouteKind};
use thenodes::plugin_host::manager::PluginManager;

#[tokio::test]
async fn heartbeat_timeout_marks_silent_peer_unresponsive() {
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

    let addr = "127.0.0.1:42999".parse().unwrap();
    let (sender, mut heartbeat_receiver) = tokio::sync::mpsc::channel(8);
    peer_manager
        .add_peer(addr, sender, "silent-peer".to_string())
        .await
        .unwrap();

    let heartbeat = tokio::time::timeout(Duration::from_millis(30), heartbeat_receiver.recv())
        .await
        .expect("heartbeat should be scheduled")
        .expect("heartbeat channel should remain open");
    assert!(heartbeat.contains("\"HEARTBEAT\""));

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
    let disposition =
        process_incoming_message(&peer_manager, "local-node", Some("peer-a"), spoofed).await;
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
    let disposition =
        process_incoming_message(&peer_manager, "local-node", Some("peer-b"), genuine).await;
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
