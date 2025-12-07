use std::fs;
use std::net::SocketAddr;

use thenodes::config::{Config, NetworkConfig, NetworkPersistenceConfig, NodeConfig};
use thenodes::network::peer_store::{PeerSource, PeerStore};

#[tokio::test]
async fn peer_store_persist_roundtrip() {
    // Create a temp directory under data/test-app
    let base = "data/test-app";
    let _ = fs::create_dir_all(base);
    let path = format!("{}/peers.json", base);

    // Build config enabling persistence
    let cfg = Config {
        port: 50000,
        encryption: None,
        bootstrap_nodes: None,
        realm: None,
        app_name: Some("test-app".to_string()),
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
                path: None, // derive from state_dir
                max_entries: Some(1024),
                ttl_secs: Some(7 * 24 * 3600),
                save_interval_secs: Some(60),
            }),
            relay: None,
        }),
    };

    // Initialize from config
    let store = PeerStore::from_config(&cfg).await;

    // Insert a couple peers and mark success
    let a: SocketAddr = "127.0.0.1:50002".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:50003".parse().unwrap();
    store.insert(a, PeerSource::Manual).await;
    store.mark_success(&a).await;
    store.insert(b, PeerSource::Gossip).await;
    store.mark_success(&b).await;

    // Save now using config-derived path
    store.save_if_enabled(&cfg).await;

    // Load new store from file; expect entries present
    let loaded = PeerStore::load_from_file(&path, 7 * 24 * 3600, 1024).await;
    let all = loaded.all().await;
    assert!(all.contains(&a));
    assert!(all.contains(&b));

    // Cleanup
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(base);
}
