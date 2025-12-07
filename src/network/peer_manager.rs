// src/network/peer_manager.rs

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::network::{Peer, PeerStore};
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct PeerManager {
    peers: Arc<Mutex<HashMap<SocketAddr, Sender<String>>>>,
    node_ids: Arc<Mutex<HashMap<String, SocketAddr>>>, // node_id -> addr
    // Mapping of a peer's advertised listening address (host:port) -> node_id.
    // Lets us suppress redundant outbound dials when an inbound connection already exists.
    listen_addrs: Arc<Mutex<HashMap<String, String>>>,
    // Relay stats
    relay_forwarded: Arc<AtomicU64>,
    relay_dropped: Arc<AtomicU64>,
    // Relay bindings: (from_node_id, to_node_id) -> BindingPrefs
    relay_bindings: Arc<Mutex<HashMap<(String, String), BindingPrefs>>>,
    // Store-and-forward queue: to_node_id -> Vec<(serialized_message_json, Option<u64>, Option<String /*origin*/>)>
    relay_queue: Arc<Mutex<HashMap<String, Vec<(String, Option<u64>, Option<String>)>>>>,
    // Track last seen sequence per (from,to) for ordering/dedup
    relay_last_sequence: Arc<Mutex<HashMap<(String, String), u64>>>,
    capabilities_by_node: Arc<Mutex<HashMap<String, Vec<String>>>>,
    // Map binding_id -> (from,to)
    relay_binding_ids: Arc<Mutex<HashMap<String, (String, String)>>>,
    // In-flight reliable forwards keyed by (from,to,sequence)
    reliable_inflight: Arc<Mutex<HashSet<(String, String, u64)>>>,
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
            capabilities_by_node: Arc::new(Mutex::new(HashMap::new())),
            relay_forwarded: Arc::new(AtomicU64::new(0)),
            relay_dropped: Arc::new(AtomicU64::new(0)),
            relay_bindings: Arc::new(Mutex::new(HashMap::new())),
            relay_queue: Arc::new(Mutex::new(HashMap::new())),
            relay_binding_ids: Arc::new(Mutex::new(HashMap::new())),
            relay_last_sequence: Arc::new(Mutex::new(HashMap::new())),
            reliable_inflight: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Returns a list of currently connected peer addresses
    pub async fn list_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.lock().await;
        peers.keys().cloned().collect()
    }

    /// Returns a list of currently connected peer node IDs
    pub async fn list_node_ids(&self) -> Vec<String> {
        let ids = self.node_ids.lock().await;
        ids.keys().cloned().collect()
    }

    // Capability registry keyed by node id
    pub async fn set_peer_capabilities(&self, node_id: &str, caps: Option<Vec<String>>) {
        let mut map = self.capabilities_by_node.lock().await;
        match caps {
            Some(v) => {
                map.insert(node_id.to_string(), v);
            }
            None => {
                map.remove(node_id);
            }
        }
    }

    pub async fn peer_has_capability(&self, node_id: &str, cap: &str) -> bool {
        let map = self.capabilities_by_node.lock().await;
        map.get(node_id)
            .map(|v| v.iter().any(|c| c == cap))
            .unwrap_or(false)
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
        self.node_ids.lock().await.insert(node_id.clone(), addr);
        // Drain any queued store-and-forward frames for this node_id
        let queued = {
            let mut q = self.relay_queue.lock().await;
            // Purge expired before removing
            if let Some(v) = q.get_mut(&node_id) {
                v.retain(|(_, exp, _)| exp.map(|e| e > current_unix_ts()).unwrap_or(true));
            }
            q.remove(&node_id)
        };
        if let Some(frames) = queued {
            if let Some(sndr) = self.peers.lock().await.get(&addr).cloned() {
                for (frame, _exp, _origin) in frames {
                    // Use try_send to avoid blocking if receiver is slow; drop frame on backpressure
                    let _ = sndr.try_send(frame);
                }
            }
        }
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

    /// Remove peer by address (cleanup node_id mapping) and return node_id if found
    pub async fn remove_peer(&self, addr: &SocketAddr) -> Option<String> {
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
            return remove_key;
        }
        None
    }

    pub async fn broadcast(&self, message: &str) {
        let peers = self.peers.lock().await;
        for (addr, sender) in peers.iter() {
            if let Err(e) = sender.send(message.to_string()).await {
                eprintln!("❌ Failed to send to {}: {}", addr, e);
            }
        }
    }

    /// Get a cloned sender for a connected peer by its socket address
    pub async fn get_sender_by_addr(&self, addr: &SocketAddr) -> Option<Sender<String>> {
        self.peers.lock().await.get(addr).cloned()
    }

    /// Get a cloned sender for a connected peer by its node id
    pub async fn get_sender_by_node_id(&self, node_id: &str) -> Option<Sender<String>> {
        let addr_opt = { self.node_ids.lock().await.get(node_id).cloned() };
        if let Some(addr) = addr_opt {
            return self.peers.lock().await.get(&addr).cloned();
        }
        None
    }

    /// Send a serialized message line (without trailing newline) to a peer by address
    pub async fn send_to_addr(&self, addr: &SocketAddr, message: String) -> Result<(), String> {
        if let Some(sender) = self.get_sender_by_addr(addr).await {
            sender
                .try_send(message)
                .map_err(|e| format!("send_to_addr failed: {}", e))
        } else {
            Err("peer sender not found".to_string())
        }
    }

    /// Send a serialized message line (without trailing newline) to a peer by node id
    pub async fn send_to_node_id(&self, node_id: &str, message: String) -> Result<(), String> {
        if let Some(sender) = self.get_sender_by_node_id(node_id).await {
            sender
                .try_send(message)
                .map_err(|e| format!("send_to_node_id failed: {}", e))
        } else {
            Err("peer sender not found".to_string())
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
            let peer = Peer::new(format!("retry-{}", addr_str), addr_str.clone());
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
                    peer_store: None,
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

    // Relay counters
    pub fn inc_relay_forwarded(&self) {
        self.relay_forwarded.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_relay_dropped(&self) {
        self.relay_dropped.fetch_add(1, Ordering::Relaxed);
    }
    pub fn relay_stats(&self) -> (u64, u64) {
        (
            self.relay_forwarded.load(Ordering::Relaxed),
            self.relay_dropped.load(Ordering::Relaxed),
        )
    }

    // Reliable QoS helpers
    pub async fn add_inflight(&self, from: &str, to: &str, seq: u64) {
        self.reliable_inflight
            .lock()
            .await
            .insert((from.to_string(), to.to_string(), seq));
    }

    pub async fn remove_inflight(&self, from: &str, to: &str, seq: u64) {
        self.reliable_inflight
            .lock()
            .await
            .remove(&(from.to_string(), to.to_string(), seq));
    }

    pub async fn is_inflight(&self, from: &str, to: &str, seq: u64) -> bool {
        self.reliable_inflight
            .lock()
            .await
            .contains(&(from.to_string(), to.to_string(), seq))
    }

    // Relay binding management
    pub async fn set_binding(
        &self,
        from_node_id: &str,
        to_node_id: &str,
        store_forward: bool,
        expires_at: Option<u64>,
        qos: Option<String>,
    ) {
        self.relay_bindings.lock().await.insert(
            (from_node_id.to_string(), to_node_id.to_string()),
            BindingPrefs {
                store_forward,
                expires_at,
                qos,
            },
        );
    }

    pub async fn binding_store_forward(&self, from_node_id: &str, to_node_id: &str) -> bool {
        self.relay_bindings
            .lock()
            .await
            .get(&(from_node_id.to_string(), to_node_id.to_string()))
            .map(|b| b.store_forward)
            .unwrap_or(false)
    }

    pub async fn binding_expires_at(&self, from_node_id: &str, to_node_id: &str) -> Option<u64> {
        self.relay_bindings
            .lock()
            .await
            .get(&(from_node_id.to_string(), to_node_id.to_string()))
            .and_then(|b| b.expires_at)
    }

    pub async fn binding_qos(&self, from_node_id: &str, to_node_id: &str) -> Option<String> {
        self.relay_bindings
            .lock()
            .await
            .get(&(from_node_id.to_string(), to_node_id.to_string()))
            .and_then(|b| b.qos.clone())
    }

    pub async fn last_sequence(&self, from_node_id: &str, to_node_id: &str) -> Option<u64> {
        self.relay_last_sequence
            .lock()
            .await
            .get(&(from_node_id.to_string(), to_node_id.to_string()))
            .cloned()
    }

    pub async fn update_sequence(&self, from_node_id: &str, to_node_id: &str, seq: u64) {
        self.relay_last_sequence
            .lock()
            .await
            .insert((from_node_id.to_string(), to_node_id.to_string()), seq);
    }

    pub async fn is_bound(&self, from_node_id: &str, to_node_id: &str) -> bool {
        self.relay_bindings
            .lock()
            .await
            .contains_key(&(from_node_id.to_string(), to_node_id.to_string()))
    }

    pub async fn add_binding_id(&self, binding_id: &str, from_node_id: &str, to_node_id: &str) {
        self.relay_binding_ids.lock().await.insert(
            binding_id.to_string(),
            (from_node_id.to_string(), to_node_id.to_string()),
        );
    }

    pub async fn remove_binding_by_id(&self, binding_id: &str) -> Option<(String, String)> {
        let mut ids = self.relay_binding_ids.lock().await;
        let pair = ids.remove(binding_id);
        if let Some((from, to)) = &pair {
            self.relay_bindings
                .lock()
                .await
                .remove(&(from.clone(), to.clone()));
        }
        pair
    }

    /// List bindings for a given `from` node id, returning `(to, binding_id)` pairs.
    pub async fn list_bindings_for_from(
        &self,
        from_node_id: &str,
    ) -> Vec<(String, Option<String>)> {
        let bindings = self.relay_bindings.lock().await;
        let mut results: Vec<(String, Option<String>)> = Vec::new();
        // Build reverse index of (from,to) -> binding_id for quick lookup
        let ids = self.relay_binding_ids.lock().await;
        for ((from, to), _prefs) in bindings.iter() {
            if from == from_node_id {
                let bid = ids.iter().find_map(|(id, pair)| {
                    if pair.0 == *from && pair.1 == *to {
                        Some(id.clone())
                    } else {
                        None
                    }
                });
                results.push((to.clone(), bid));
            }
        }
        results
    }

    pub async fn enqueue_store_forward(
        &self,
        to_node_id: &str,
        message_json: String,
        expires_at: Option<u64>,
        priority_front: bool,
        soft_drop_bulk: bool,
        origin_from: Option<String>,
    ) -> bool {
        const MAX_QUEUE_PER_TARGET: usize = 1024;
        const MAX_QUEUE_GLOBAL: usize = 8192;
        // Accumulate notifications to send after releasing queue lock to avoid await while locked
        let mut to_notify: Vec<(String, crate::network::message::Reason)> = Vec::new();
        // If the incoming frame is already expired, notify origin immediately and drop.
        if let Some(exp) = expires_at {
            if exp <= current_unix_ts() {
                if let Some(o) = origin_from.as_ref() {
                    if self.has_node_id(o).await {
                        let notify = crate::network::message::Message::new(
                            o,
                            o,
                            crate::network::message::MessageType::RelayNotify {
                                notif_type: crate::network::message::Reason::Timeout,
                                binding_id: None,
                                detail: Some(format!("target={}", to_node_id)),
                            },
                            None,
                            None,
                        );
                        let _ = self.send_to_node_id(o, notify.as_json()).await;
                    }
                }
                return false;
            }
        }
        let mut q = self.relay_queue.lock().await;
        // Purge expired entries for this target first
        // Note: we may later surface purge events; for now we do not track a flag.
        if let Some(v) = q.get_mut(to_node_id) {
            // Drop expired entries and notify their origins of timeout
            let now = current_unix_ts();
            let mut kept: Vec<(String, Option<u64>, Option<String>)> = Vec::with_capacity(v.len());
            for (frame, exp, origin) in v.drain(..) {
                if exp.map(|e| e > now).unwrap_or(true) {
                    kept.push((frame, exp, origin));
                } else if let Some(o) = origin.as_ref() {
                    to_notify.push((o.clone(), crate::network::message::Reason::Timeout));
                }
            }
            *v = kept;
            // If any entries were purged, mark
            // (cheap check: compare lengths after retain by cloning len before)
            // Note: exact count not required; boolean is sufficient for notify decisions upstream.
            // We cannot easily read previous length without cloning; use can_enqueue check separately.
            // Enforce cap by dropping oldest if exceeding limit
            if v.len() >= MAX_QUEUE_PER_TARGET {
                let drop_count = v.len() + 1 - MAX_QUEUE_PER_TARGET;
                for _ in 0..drop_count {
                    let removed = v.remove(0);
                    if let Some(o) = removed.2.as_ref() {
                        to_notify.push((o.clone(), crate::network::message::Reason::Overload));
                    }
                }
            }
        }
        let entry = q.entry(to_node_id.to_string()).or_insert_with(Vec::new);
        if entry.len() >= MAX_QUEUE_PER_TARGET {
            // If soft_drop_bulk, drop the incoming frame silently
            if soft_drop_bulk {
                return false;
            }
            // Otherwise drop oldest to make room
            let removed = entry.remove(0);
            if let Some(o) = removed.2.as_ref() {
                to_notify.push((o.clone(), crate::network::message::Reason::Overload));
            }
        }
        if priority_front {
            entry.insert(0, (message_json, expires_at, origin_from));
        } else {
            entry.push((message_json, expires_at, origin_from));
        }

        // Enforce global cap by dropping oldest across targets (simple round-robin)
        let mut total_len: usize = q.values().map(|v| v.len()).sum();
        if total_len > MAX_QUEUE_GLOBAL {
            let mut keys: Vec<String> = q.keys().cloned().collect();
            keys.sort();
            let mut idx = 0usize;
            while total_len > MAX_QUEUE_GLOBAL && !keys.is_empty() {
                let k = &keys[idx % keys.len()];
                if let Some(vec) = q.get_mut(k) {
                    if !vec.is_empty() {
                        let removed = vec.remove(0);
                        if let Some(o) = removed.2.as_ref() {
                            to_notify.push((o.clone(), crate::network::message::Reason::Overload));
                        }
                        total_len -= 1;
                    } else {
                        // remove empty key from rotation to avoid tight loop
                        keys.remove(idx % keys.len());
                        continue;
                    }
                }
                idx += 1;
            }
        }
        drop(q);

        // Send accumulated notifications after releasing the queue lock
        for (o, reason) in to_notify {
            if self.has_node_id(&o).await {
                let notify = crate::network::message::Message::new(
                    &o,
                    &o,
                    crate::network::message::MessageType::RelayNotify {
                        notif_type: reason,
                        binding_id: None,
                        detail: Some(format!("target={}", to_node_id)),
                    },
                    None,
                    None,
                );
                let _ = self.send_to_node_id(&o, notify.as_json()).await;
            }
        }
        true
    }

    pub async fn can_enqueue_store_forward(&self, to_node_id: &str) -> bool {
        const MAX_QUEUE_PER_TARGET: usize = 1024;
        const MAX_QUEUE_GLOBAL: usize = 8192;
        let q = self.relay_queue.lock().await;
        let per_target_ok = q
            .get(to_node_id)
            .map(|v| v.len() < MAX_QUEUE_PER_TARGET)
            .unwrap_or(true);
        let total_len: usize = q.values().map(|v| v.len()).sum();
        let global_ok = total_len < MAX_QUEUE_GLOBAL;
        per_target_ok && global_ok
    }

    /// Helper to inspect queue contents for a target (primarily for tests).
    pub async fn test_get_queue_for(
        &self,
        to_node_id: &str,
    ) -> Vec<(String, Option<u64>, Option<String>)> {
        let q = self.relay_queue.lock().await;
        q.get(to_node_id).cloned().unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
struct BindingPrefs {
    store_forward: bool,
    // Unix epoch seconds; if None, no automatic expiry
    expires_at: Option<u64>,
    // Optional QoS hint
    qos: Option<String>,
}

fn current_unix_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
