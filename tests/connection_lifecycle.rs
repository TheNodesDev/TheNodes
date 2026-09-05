use std::sync::Arc;
use std::time::Duration;

use thenodes::config::{Config, ConnectionPolicyConfig};
use thenodes::network::{PeerManager, PeerStore, RouteHealth, RouteKind};
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
