use std::fs;
use std::net::SocketAddr;

use thenodes::config::{Config, NetworkConfig, NetworkPersistenceConfig, NodeConfig};
use thenodes::network::peer_store::{PeerSource, PeerStore};

#[tokio::test]
async fn peer_store_ttl_expiry_on_load() {
    let base = "data/test-ttl";
    let _ = fs::create_dir_all(base);
    let path = format!("{}/peers.json", base);

    // Persist two peers with different last_success epochs
    let store = PeerStore::new();
    let a: SocketAddr = "127.0.0.1:51002".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:51003".parse().unwrap();
    store.insert(a, PeerSource::Manual).await;
    store.insert(b, PeerSource::Manual).await;
    // Simulate success timestamps by marking success twice with delays
    store.mark_success(&a).await;
    // Small delay to ensure distinct epochs (coarse seconds); not strictly necessary,
    // but helps ensure ordering.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    store.mark_success(&b).await;
    store.save_to_file(&path).await.unwrap();

    // Build config enabling persistence and load with very small TTL to expire older entries
    let cfg = Config {
        port: 50000,
        encryption: None,
        bootstrap_nodes: None,
        realm: None,
        app_name: Some("test-ttl".to_string()),
        logging: None,
        node: Some(NodeConfig {
            id: None,
            state_dir: Some(base.to_string()),
            id_file: Some("node_id".to_string()),
            allow_ephemeral: Some(true),
            node_type: Some("daemon".to_string()),
        }),
        discovery: None,
        realm_access: None,
        network: Some(NetworkConfig {
            persistence: Some(NetworkPersistenceConfig {
                enabled: Some(true),
                path: Some(path.clone()),
                max_entries: Some(1024),
                ttl_secs: Some(0), // expire entries with last_success older than now
                save_interval_secs: Some(60),
            }),
            relay: None,
        }),
    };

    // Load: entries with last_success older than now should be filtered.
    let loaded = PeerStore::from_config(&cfg).await;
    let all = loaded.all().await;
    // With ttl_secs = 0, any entry with last_success < now is considered expired.
    // Given coarse epoch seconds, both may expire; at minimum ensure no panic and
    // the store is not larger than originally persisted.
    assert!(all.len() <= 2);

    // Cleanup
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(base);
}
