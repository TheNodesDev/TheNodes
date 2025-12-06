// src/network/peer_manager.rs

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::network::{Peer, PeerStore};
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;

#[derive(Clone)]
pub struct PeerManager {
    peers: Arc<Mutex<HashMap<SocketAddr, Sender<String>>>>,
    node_ids: Arc<Mutex<HashMap<String, SocketAddr>>>, // node_id -> addr
    // Mapping of a peer's advertised listening address (host:port) -> node_id.
    // Lets us suppress redundant outbound dials when an inbound connection already exists.
    listen_addrs: Arc<Mutex<HashMap<String, String>>>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            node_ids: Arc::new(Mutex::new(HashMap::new())),
            listen_addrs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns a list of currently connected peer addresses
    pub async fn list_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.lock().await;
        peers.keys().cloned().collect()
    }

    /// Add a peer with its message sender channel
    pub async fn add_peer(
        &self,
        addr: SocketAddr,
        sender: Sender<String>,
        node_id: String,
    ) -> Result<(), String> {
        // Prevent duplicate node IDs
        {
            let ids = self.node_ids.lock().await;
            if ids.contains_key(&node_id) {
                return Err(format!("duplicate node id {} already connected", node_id));
            }
        }
        self.peers.lock().await.insert(addr, sender);
        self.node_ids.lock().await.insert(node_id, addr);
        Ok(())
    }

    /// Check if a node id already exists among connected peers
    pub async fn has_node_id(&self, node_id: &str) -> bool {
        self.node_ids.lock().await.contains_key(node_id)
    }

    /// Check if an address is already connected
    pub async fn has_addr(&self, addr: &SocketAddr) -> bool {
        self.peers.lock().await.contains_key(addr)
    }

    /// Remove peer by address (cleanup node_id mapping)
    pub async fn remove_peer(&self, addr: &SocketAddr) {
        let mut peers = self.peers.lock().await;
        if peers.remove(addr).is_some() {
            let mut ids = self.node_ids.lock().await;
            let remove_key: Option<String> =
                ids.iter()
                    .find_map(|(k, v)| if v == addr { Some(k.clone()) } else { None });
            if let Some(ref k) = remove_key {
                ids.remove(k);
            }
            // Also purge any listen_addr entries pointing to this node id
            if let Some(ref dup_node_id) = remove_key {
                let mut listen_map = self.listen_addrs.lock().await;
                let to_remove: Vec<String> = listen_map
                    .iter()
                    .filter_map(|(la, nid)| {
                        if nid == dup_node_id {
                            Some(la.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                for la in to_remove {
                    listen_map.remove(&la);
                }
            }
        }
    }

    pub async fn broadcast(&self, message: &str) {
        let peers = self.peers.lock().await;
        for (addr, sender) in peers.iter() {
            if let Err(e) = sender.send(message.to_string()).await {
                eprintln!("❌ Failed to send to {}: {}", addr, e);
            }
        }
    }

    /// Record a peer's advertised listening address (from its HELLO) for suppression logic.
    pub async fn add_listen_addr(&self, listen_addr: &str, node_id: &str) {
        self.listen_addrs
            .lock()
            .await
            .insert(listen_addr.to_string(), node_id.to_string());
    }

    /// Returns true if we already have a peer whose advertised listening address matches.
    pub async fn has_listen_addr(&self, listen_addr: &str) -> bool {
        self.listen_addrs.lock().await.contains_key(listen_addr)
    }

    pub async fn reconnect_known_peers(
        &self,
        plugin_manager: Arc<PluginManager>,
        peer_store: PeerStore,
        config: &Config,
    ) {
        let mut targets: BTreeSet<SocketAddr> = peer_store.all().await.into_iter().collect();
        let mut parse_failures: Vec<String> = Vec::new();

        if let Some(bootstrap) = &config.bootstrap_nodes {
            for entry in bootstrap {
                match entry.parse::<SocketAddr>() {
                    Ok(addr) => {
                        targets.insert(addr);
                    }
                    Err(err) => parse_failures.push(format!("{} ({})", entry, err)),
                }
            }
        }

        if targets.is_empty() {
            println!(
                "{}No stored peer addresses to retry after promotion.",
                crate::constants::ICON_PLACEHOLDER
            );
            return;
        }

        let total_candidates = targets.len();
        let connected: HashSet<SocketAddr> = self.list_peers().await.into_iter().collect();

        let realm = config.realm.clone().unwrap_or_else(RealmInfo::default);
        let local_node_id = config
            .node
            .as_ref()
            .map(|n| n.resolve_node_id())
            .unwrap_or_else(|| "unknown-node".to_string());

        let mut attempted = 0usize;
        let mut succeeded = 0usize;
        let mut skipped_connected = 0usize;

        println!(
            "{}Retrying {} known peer(s)...",
            crate::constants::ICON_PLACEHOLDER,
            total_candidates
        );

        let peer_manager = self.clone();
        for addr in targets {
            if connected.contains(&addr) {
                skipped_connected += 1;
                continue;
            }
            attempted += 1;
            let addr_str = addr.to_string();
            let peer = Peer::new(&format!("retry-{}", addr_str), &addr_str);
            match crate::network::transport::connect_to_peer(
                crate::network::transport::ConnectToPeerParams {
                    peer: &peer,
                    our_realm: realm.clone(),
                    our_port: config.port,
                    peer_manager: peer_manager.clone(),
                    plugin_manager: plugin_manager.clone(),
                    allow_console: true,
                    config: config.clone(),
                    local_node_id: local_node_id.clone(),
                },
            )
            .await
            {
                Ok(()) => {
                    succeeded += 1;
                    println!(
                        "{}Connected to {}",
                        crate::constants::ICON_PLACEHOLDER,
                        addr
                    );
                }
                Err(err) => {
                    println!(
                        "{}Failed to connect to {}: {}",
                        crate::constants::ICON_PLACEHOLDER,
                        addr,
                        err
                    );
                }
            }
        }

        println!(
            "{}Reconnect summary: {} candidate(s), {} attempted, {} succeeded, {} already connected.",
            crate::constants::ICON_PLACEHOLDER,
            total_candidates,
            attempted,
            succeeded,
            skipped_connected
        );

        if !parse_failures.is_empty() {
            println!(
                "{}Skipped invalid addresses:",
                crate::constants::ICON_PLACEHOLDER
            );
            for detail in parse_failures {
                println!("  {}", detail);
            }
        }
    }
}
