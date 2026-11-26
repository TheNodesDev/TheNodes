use thenodes::config::{ConnectionPolicyConfig, NetworkConfig};
use thenodes::network::{
    connect_with_policy, ConnectionOutcome, ConnectionPolicy, ConnectionStrategy, PeerManager,
    RouteKind,
};

fn make_policy(strategy: &str) -> ConnectionPolicy {
    ConnectionPolicy::from_config(&ConnectionPolicyConfig {
        strategy: Some(strategy.to_string()),
        direct_tcp_timeout_ms: None,
        direct_udp_timeout_ms: None,
        punch_timeout_ms: None,
        ..ConnectionPolicyConfig::default()
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
            bind_ip: None,
            persistence: None,
            relay: None,
            nat: None,
            udp: None,
            connection_policy: None,
            nat_traversal: None,
            delivery: None,
            limits: None,
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
            max_app_payload_bytes: Some(1168),
        });
        network.nat_traversal = Some(thenodes::config::NatTraversalConfig {
            enabled: Some(true),
            serve: Some(false),
            refresh_secs: Some(refresh_secs),
            cookie_ttl_secs: Some(30),
            probe_count: Some(6),
            probe_interval_ms: Some(100),
            allowed_rendezvous: None,
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

#[test]
fn reconnect_backoff_progresses_exponentially_and_caps() {
    let policy = ConnectionPolicy::from_config(&ConnectionPolicyConfig {
        reconnect_base_delay_ms: Some(100),
        reconnect_multiplier: Some(2.0),
        reconnect_max_delay_ms: Some(450),
        reconnect_jitter_ratio: Some(0.25),
        ..ConnectionPolicyConfig::default()
    });

    let delays: Vec<u128> = (1..=5)
        .map(|attempt| policy.reconnect_delay(attempt, 0.0).as_millis())
        .collect();
    assert_eq!(delays, vec![100, 200, 400, 450, 450]);
    assert_eq!(policy.reconnect_delay(3, -1.0).as_millis(), 300);
    assert_eq!(policy.reconnect_delay(3, 1.0).as_millis(), 500);
}

#[tokio::test]
async fn healthy_relay_is_preferred_over_suspect_direct_route() {
    let pm = PeerManager::new();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    pm.add_peer(
        "127.0.0.1:42001".parse().unwrap(),
        tx,
        "relay-node".to_string(),
    )
    .await
    .unwrap();
    pm.set_peer_capabilities("relay-node", Some(vec!["relay".to_string()]))
        .await;
    pm.add_listen_addr("127.0.0.1:42002", "target-node").await;
    pm.mark_route_failure("target-node", RouteKind::Tcp).await;
    pm.mark_route_success("relay-node", RouteKind::Relay).await;

    let outcome = connect_with_policy(
        "target-node",
        &make_policy("direct_then_relay"),
        &pm,
        &minimal_config(),
    )
    .await;

    assert!(matches!(
        outcome,
        ConnectionOutcome::ViaRelay { relay_node_id } if relay_node_id == "relay-node"
    ));
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
    pm.mark_route_unresponsive("target-node", RouteKind::Udp)
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

/// Any peer that announced `relay` could be chosen as relay; with
/// `[network.relay] allowed_relays` set, only the peers it names are.
#[tokio::test]
async fn only_allowed_relays_are_chosen() {
    let pm = PeerManager::new();
    let mut receivers = Vec::new();
    for (port, node_id) in [(42011, "relay-a"), (42012, "relay-b")] {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        receivers.push(rx);
        pm.add_peer(
            format!("127.0.0.1:{port}").parse().unwrap(),
            tx,
            node_id.to_string(),
        )
        .await
        .unwrap();
        pm.set_peer_capabilities(node_id, Some(vec!["relay".to_string()]))
            .await;
    }
    let route = |allowed: Option<Vec<String>>| {
        let mut cfg = minimal_config();
        cfg.network.as_mut().unwrap().relay = Some(thenodes::config::RelayConfig {
            allowed_relays: allowed,
            ..Default::default()
        });
        let pm = pm.clone();
        async move { connect_with_policy("target-node", &make_policy("relay_only"), &pm, &cfg).await }
    };

    assert!(matches!(
        route(None).await,
        ConnectionOutcome::ViaRelay { .. }
    ));
    assert!(matches!(
        route(Some(vec!["relay-b".into()])).await,
        ConnectionOutcome::ViaRelay { relay_node_id } if relay_node_id == "relay-b"
    ));
    assert!(matches!(
        route(Some(Vec::new())).await,
        ConnectionOutcome::NoRoute { .. }
    ));
}

/// A rendezvous outside `[network.nat_traversal] allowed_rendezvous` is
/// not used for hole punching.
#[cfg(feature = "noise")]
#[tokio::test]
async fn only_an_allowed_rendezvous_coordinates_a_punch() {
    let pm = PeerManager::new();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    pm.add_peer(
        "127.0.0.1:41003".parse().unwrap(),
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
    pm.add_udp_observed_addr("target-node", "203.0.113.12:5003", Some("observer-1"), None)
        .await;
    pm.mark_route_unresponsive("target-node", RouteKind::Udp)
        .await;

    let mut cfg = punch_enabled_config(300);
    let nat = cfg
        .network
        .as_mut()
        .unwrap()
        .nat_traversal
        .as_mut()
        .unwrap();
    nat.allowed_rendezvous = Some(vec!["other-node".to_string()]);
    let outcome = connect_with_policy(
        "target-node",
        &make_policy("direct_then_punch_then_relay"),
        &pm,
        &cfg,
    )
    .await;
    assert!(matches!(
        outcome,
        ConnectionOutcome::ViaRelay { relay_node_id } if relay_node_id == "rendezvous-node"
    ));
}
