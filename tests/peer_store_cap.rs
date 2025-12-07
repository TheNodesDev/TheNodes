use std::fs;
use std::net::SocketAddr;

use thenodes::config::{Config, NetworkConfig, NetworkPersistenceConfig, NodeConfig};
use thenodes::network::peer_store::{PeerSource, PeerStore};

#[tokio::test]
async fn peer_store_cap_enforcement_on_load() {
    let base = "data/test-cap";
    let _ = fs::create_dir_all(base);
    let path = format!("{}/peers.json", base);

    // Persist many peers
    let store = PeerStore::new();
    for i in 0..50u16 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 52000 + i).parse().unwrap();
        store.insert(addr, PeerSource::Gossip).await;
        store.mark_success(&addr).await;
    }
    store.save_to_file(&path).await.unwrap();

    // Load with max_entries small to enforce cap
    let cfg = Config {
        port: 50000,
        encryption: None,
        bootstrap_nodes: None,
        realm: None,
        app_name: Some("test-cap".to_string()),
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
                max_entries: Some(10), // cap to 10
                ttl_secs: Some(7 * 24 * 3600),
                save_interval_secs: Some(60),
            }),
            relay: None,
        }),
    };

    let loaded = PeerStore::from_config(&cfg).await;
    let all = loaded.all().await;
    assert_eq!(all.len(), 10);

    // Cleanup
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(base);
}
