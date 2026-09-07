use std::sync::Arc;
use std::time::Duration;

use thenodes::config::{Config, RelayConfig};
use thenodes::network::message::{
    decode_relay_opaque_payload_utf8, encode_relay_opaque_payload, Message, MessageType,
};
use thenodes::network::peer::Peer;
use thenodes::network::peer_manager::PeerManager;
use thenodes::network::peer_store::PeerStore;
use thenodes::network::transport::{connect_to_peer, ConnectToPeerParams};
use thenodes::plugin_host::manager::PluginManager;
use thenodes::realms::RealmInfo;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_bind_and_forward_cross_a_real_two_node_connection() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let realm = RealmInfo::new("relay-smoke", "1.0");
    let mut relay_config = Config {
        port,
        realm: Some(realm.clone()),
        ..Default::default()
    };
    relay_config.network.as_mut().unwrap().relay = Some(RelayConfig {
        enabled: Some(true),
        store_forward: Some(true),
        queue_max_per_target: Some(16),
        queue_max_global: Some(32),
        selection: Some("none".to_string()),
    });

    let relay_manager = PeerManager::new();
    let relay_listener = {
        let relay_manager = relay_manager.clone();
        let relay_config = relay_config.clone();
        let realm = realm.clone();
        tokio::spawn(async move {
            if let Err(error) = thenodes::network::listener::start_listener(
                port,
                realm,
                relay_manager,
                Arc::new(PluginManager::new()),
                &relay_config,
                "relay-node".to_string(),
                PeerStore::new(),
                false,
            )
            .await
            {
                panic!("relay listener failed: {error}");
            }
        })
    };

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_manager = PeerManager::new();
    let peer = Peer::new("relay-node".to_string(), format!("127.0.0.1:{port}"));
    let client_connection = {
        let client_manager = client_manager.clone();
        let client_config = relay_config.clone();
        let realm = realm.clone();
        tokio::spawn(async move {
            connect_to_peer(ConnectToPeerParams {
                peer: &peer,
                our_realm: realm,
                our_port: 0,
                peer_manager: client_manager,
                plugin_manager: Arc::new(PluginManager::new()),
                allow_console: false,
                config: client_config,
                local_node_id: "client-node".to_string(),
                peer_store: Some(PeerStore::new()),
            })
            .await
        })
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        while !client_manager.has_node_id("relay-node").await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("client did not register relay node");

    let bind = Message::new(
        "client-node",
        "relay-node",
        MessageType::RelayBind {
            target: "offline-target".to_string(),
            want_store_forward: Some(true),
            qos: Some("reliable".to_string()),
            nonce: Some(7),
            expires_at: None,
        },
        None,
        Some(realm.clone()),
    );
    client_manager
        .send_to_node_id("relay-node", bind.as_json())
        .await
        .expect("send relay bind");

    tokio::time::timeout(Duration::from_secs(5), async {
        while !relay_manager
            .is_bound("client-node", "offline-target")
            .await
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("relay binding was not registered");

    let payload = "real two-node relay payload";
    let forward = Message::new(
        "client-node",
        "relay-node",
        MessageType::RelayForward {
            to: "offline-target".to_string(),
            from: "client-node".to_string(),
            sequence: Some(1),
            opaque_payload_b64: encode_relay_opaque_payload(payload),
        },
        None,
        Some(realm),
    );
    client_manager
        .send_to_node_id("relay-node", forward.as_json())
        .await
        .expect("send relay forward");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let queue = relay_manager.test_get_queue_for("offline-target").await;
            if let Some((wire, ..)) = queue.first() {
                let queued = Message::from_json(wire).expect("queued relay frame");
                if let MessageType::RelayForward {
                    opaque_payload_b64, ..
                } = queued.msg_type
                {
                    assert_eq!(
                        decode_relay_opaque_payload_utf8(&opaque_payload_b64).as_deref(),
                        Some(payload)
                    );
                    assert!(queued.payload.is_none());
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("relay frame was not queued");

    client_connection.abort();
    relay_listener.abort();
}
