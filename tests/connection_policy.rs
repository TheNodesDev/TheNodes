use thenodes::config::{ConnectionPolicyConfig, NetworkConfig};
use thenodes::network::{
    connect_with_policy, ConnectionOutcome, ConnectionPolicy, ConnectionStrategy, PeerManager,
};

fn make_policy(strategy: &str) -> ConnectionPolicy {
    ConnectionPolicy::from_config(&ConnectionPolicyConfig {
        strategy: Some(strategy.to_string()),
        direct_tcp_timeout_ms: None,
        direct_udp_timeout_ms: None,
        punch_timeout_ms: None,
    })
}

fn minimal_config() -> thenodes::config::Config {
    thenodes::config::Config {
        port: 40000,
        encryption: None,
        bootstrap_nodes: None,
        realm: None,
        app_name: None,
        logging: None,
        node: None,
        discovery: None,
        realm_access: None,
        network: Some(NetworkConfig {
            persistence: None,
            relay: None,
            udp: None,
            connection_policy: None,
            nat_traversal: None,
            delivery: None,
        }),
    }
}

#[cfg(feature = "noise")]
fn punch_enabled_config(refresh_secs: u64) -> thenodes::config::Config {
    let mut cfg = minimal_config();
    if let Some(network) = cfg.network.as_mut() {
        network.udp = Some(thenodes::config::UdpConfig {
            enabled: Some(true),
            listen_port: Some(41000),
            max_datagram_bytes: Some(1200),
            max_app_payload_bytes: Some(1176),
        });
        network.nat_traversal = Some(thenodes::config::NatTraversalConfig {
            enabled: Some(true),
            serve: Some(false),
            refresh_secs: Some(refresh_secs),
            cookie_ttl_secs: Some(30),
            probe_count: Some(6),
            probe_interval_ms: Some(100),
        });
    }
    cfg
}

#[tokio::test]
async fn strategy_parsing() {
    assert_eq!(
        make_policy("direct_only").strategy,
        ConnectionStrategy::DirectOnly
    );
    assert_eq!(
        make_policy("relay_only").strategy,
        ConnectionStrategy::RelayOnly
    );
    assert_eq!(
        make_policy("direct_then_udp_then_relay").strategy,
        ConnectionStrategy::DirectThenUdpThenRelay
    );
    assert_eq!(
        make_policy("unknown_string").strategy,
        ConnectionStrategy::DirectThenRelay
    );
}

#[tokio::test]
async fn no_route_when_no_peers() {
    let pm = PeerManager::new();
    let policy = make_policy("direct_then_relay");
    let cfg = minimal_config();
    let outcome = connect_with_policy("non-existent-node", &policy, &pm, &cfg).await;
    assert!(matches!(outcome, ConnectionOutcome::NoRoute { .. }));
}

#[tokio::test]
async fn relay_only_no_relay() {
    let pm = PeerManager::new();
    let policy = make_policy("relay_only");
    let cfg = minimal_config();
    let outcome = connect_with_policy("some-node", &policy, &pm, &cfg).await;
    assert!(matches!(outcome, ConnectionOutcome::NoRoute { .. }));
}

#[tokio::test]
async fn default_policy_from_config_without_section() {
    let cfg = minimal_config();
    let policy = ConnectionPolicy::from_network_config(&cfg);
    assert_eq!(policy.strategy, ConnectionStrategy::DirectThenRelay);
}

#[cfg(feature = "noise")]
#[tokio::test]
async fn punch_strategy_uses_fresh_observed_addr_with_rendezvous() {
    let pm = PeerManager::new();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    pm.add_peer(
        "127.0.0.1:41001".parse().unwrap(),
        tx,
        "rendezvous-node".to_string(),
    )
    .await
    .unwrap();
    pm.set_peer_capabilities(
        "rendezvous-node",
        Some(vec!["relay".to_string(), "punch_rendezvous".to_string()]),
    )
    .await;
    pm.set_peer_capabilities("target-node", Some(vec!["punch".to_string()]))
        .await;
    pm.add_udp_observed_addr("target-node", "203.0.113.10:5001", Some("observer-1"), None)
        .await;

    let policy = make_policy("direct_then_punch_then_relay");
    let cfg = punch_enabled_config(300);
    let outcome = connect_with_policy("target-node", &policy, &pm, &cfg).await;

    assert!(matches!(
        outcome,
        ConnectionOutcome::HolePunchUdp {
            relay_node_id,
            addr,
        } if relay_node_id == "rendezvous-node" && addr == "203.0.113.10:5001".parse().unwrap()
    ));
}

#[cfg(feature = "noise")]
#[tokio::test]
async fn punch_strategy_falls_back_when_observed_addr_is_stale() {
    let pm = PeerManager::new();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    pm.add_peer(
        "127.0.0.1:41002".parse().unwrap(),
        tx,
        "relay-node".to_string(),
    )
    .await
    .unwrap();
    pm.set_peer_capabilities(
        "relay-node",
        Some(vec!["relay".to_string(), "punch_rendezvous".to_string()]),
    )
    .await;
    pm.set_peer_capabilities("target-node", Some(vec!["punch".to_string()]))
        .await;
    pm.add_udp_observed_addr("target-node", "203.0.113.11:5002", Some("observer-1"), None)
        .await;

    let policy = make_policy("direct_then_punch_then_relay");
    let cfg = punch_enabled_config(0);
    let outcome = connect_with_policy("target-node", &policy, &pm, &cfg).await;

    assert!(matches!(
        outcome,
        ConnectionOutcome::ViaRelay { relay_node_id } if relay_node_id == "relay-node"
    ));
}
