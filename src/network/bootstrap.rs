// src/network/bootstrap.rs

use super::{Peer, PeerSource, PeerStore};
use crate::config::Config;
use crate::events::model::LogLevel;
use crate::network::events::emit_network_event;
use crate::network::peer_manager::PeerManager;
use crate::network::transport::connect_to_peer;
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

#[allow(clippy::too_many_arguments)]
pub async fn connect_to_bootstrap_nodes(
    config: &Config,
    realm: RealmInfo,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    error_buffer: Arc<TokioMutex<Vec<String>>>,
    allow_console: bool,
    local_node_id: String,
    peer_store: PeerStore,
) {
    if let Some(peers) = &config.bootstrap_nodes {
        let node_id_arc = Arc::new(local_node_id);
        for addr in peers {
            let peer = Peer::new("bootstrap", addr);
            let realm_clone = realm.clone();
            let addr_clone = addr.clone();
            let peer_manager_clone = peer_manager.clone();
            let port = config.port;
            let plugin_manager_clone = plugin_manager.clone();
            let error_buffer = error_buffer.clone();
            let config_clone = config.clone();
            let node_id_for_task = node_id_arc.clone();
            let peer_store_clone = peer_store.clone();
            // Seed into store
            if let Ok(sock) = addr.parse() {
                peer_store_clone.insert(sock, PeerSource::Bootstrap).await;
            }
            tokio::spawn(async move {
                loop {
                    // Suppress outbound dial if we already have a peer advertising this listen address
                    if peer_manager_clone.has_listen_addr(&addr_clone).await {
                        // Longer backoff when suppressed
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        continue;
                    }
                    match connect_to_peer(crate::network::transport::ConnectToPeerParams {
                        peer: &peer,
                        our_realm: realm_clone.clone(),
                        our_port: port,
                        peer_manager: peer_manager_clone.clone(),
                        plugin_manager: plugin_manager_clone.clone(),
                        allow_console,
                        config: config_clone.clone(),
                        local_node_id: (*node_id_for_task).clone(),
                    })
                    .await
                    {
                        Ok(_) => {
                            emit_network_event(
                                "bootstrap",
                                LogLevel::Info,
                                "bootstrap_connect_success",
                                Some(addr_clone.clone()),
                                None,
                                allow_console,
                            );
                        }
                        Err(e) => {
                            emit_network_event(
                                "bootstrap",
                                LogLevel::Warn,
                                "bootstrap_connect_failed",
                                Some(addr_clone.clone()),
                                Some(e.to_string()),
                                allow_console,
                            );
                            let msg = format!("❌ Failed to connect to {}: {}", addr_clone, e);
                            #[allow(unused_must_use)]
                            {
                                error_buffer.lock().await.push(msg);
                            }
                        }
                    }
                    // Wait before retrying
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    // Optionally buffer retry message as well
                }
            });
        }
    } else {
        emit_network_event(
            "bootstrap",
            LogLevel::Info,
            "bootstrap_nodes_missing",
            None,
            Some("source=config".to_string()),
            allow_console,
        );
    }
}
