// src/network/peer_manager.rs

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use crate::config::{Config, DeliveryConfig};
use crate::network::delivery::{DeliveryClass, DeliveryOutcome, MessageId};
use crate::network::message::Message;
use crate::network::{Peer, PeerStore};
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;

#[derive(Clone, Debug)]
struct DeliveryAttemptState {
    class: DeliveryClass,
    attempts: u32,
    outcome: Option<DeliveryOutcome>,
    expires_at: std::time::Instant,
}

#[derive(Clone, Debug)]
struct OrderedDeliveryBuffer {
    next_expected: u64,
    pending: BTreeMap<u64, Message>,
    /// Last time this scope received an in-sequence or buffered message.
    /// Used by `prune_ordered_inbound` to evict stale scopes.
    last_activity: std::time::Instant,
}

/// Which transport is currently preferred for reaching a given peer.
///
/// Set by the UDP listener on handshake completion (ADR-0004 §2.3) and by the TCP listener
/// on connect.  Defaults to `Tcp` when only a TCP connection is present.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tcp,
    Udp,
}

/// Record for a pending relay-coordinated hole-punch request (ADR-0005 Phase 3).
/// Keyed by `target_node_id` (the responder's node ID) in `PeerManager::pending_punches`.
#[derive(Clone, Debug)]
pub struct PendingPunch {
    pub attempt_id: String,
    /// Node ID of the peer that initiated the punch request.
    pub initiator_node_id: String,
    pub responder_node_id: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ObservedUdpAddrRecord {
    pub addr: String,
    pub observed_at: std::time::Instant,
    pub observer_node_id: Option<String>,
    pub request_nonce: Option<[u8; 8]>,
}

#[derive(Clone, Debug)]
pub struct PendingObservation {
    pub observer_node_id: String,
    pub expected_source: SocketAddr,
    pub nonce: [u8; 8],
    pub requested_at: std::time::Instant,
}

/// Handle to the live UDP socket, Noise session map, and static private key.
/// Stored in `PeerManager` once `spawn_udp_listener` has run.  Phase 3 punch execution
/// reads from this to send UDP probes and begin Noise handshakes.
#[cfg(feature = "noise")]
#[derive(Clone)]
pub(crate) struct UdpHandle {
    pub socket: Arc<tokio::net::UdpSocket>,
    pub sessions: crate::network::udp_listener::UdpSessions,
    pub static_private: Vec<u8>,
}

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
    // Store-and-forward queue caps (configurable via network.relay)
    relay_queue_max_per_target: Arc<AtomicUsize>,
    relay_queue_max_global: Arc<AtomicUsize>,
    // Track last seen sequence per (from,to) for ordering/dedup
    relay_last_sequence: Arc<Mutex<HashMap<(String, String), u64>>>,
    capabilities_by_node: Arc<Mutex<HashMap<String, Vec<String>>>>,
    // Map binding_id -> (from,to)
    relay_binding_ids: Arc<Mutex<HashMap<String, (String, String)>>>,
    // In-flight reliable forwards keyed by (from,to,sequence)
    reliable_inflight: Arc<Mutex<HashSet<(String, String, u64)>>>,
    // Framework delivery state (ADR-0006)
    delivery_attempts: Arc<Mutex<HashMap<String, DeliveryAttemptState>>>,
    delivery_dedup: Arc<Mutex<HashMap<(String, String), std::time::Instant>>>,
    delivery_next_ordering_sequence: Arc<Mutex<HashMap<(String, String, String), u64>>>,
    delivery_ordered_inbound: Arc<Mutex<HashMap<(String, String, String), OrderedDeliveryBuffer>>>,
    relay_next_sequence: Arc<Mutex<HashMap<(String, String), u64>>>,
    delivery_dedup_window_secs: Arc<AtomicU64>,
    delivery_ordered_buffer_limit: Arc<AtomicUsize>,
    // ── UDP transport (ADR-0004) ──────────────────────────────────────────────────
    /// Active transport kind per peer (node_id → TransportKind).
    transport_kind: Arc<Mutex<HashMap<String, TransportKind>>>,
    /// UDP listen addresses advertised by peers in their HELLO (node_id → "ip:port").
    udp_listen_addrs: Arc<Mutex<HashMap<String, String>>>,
    /// Active Noise session IDs keyed by node_id (set on handshake completion).
    udp_session_ids: Arc<Mutex<HashMap<String, [u8; 8]>>>,
    // ── NAT traversal / observed addresses (ADR-0005) ─────────────────────────────────────────
    /// Own node's most recently observed public UDP address (from TNCF OBSERVE_RESP).
    own_observed_addr: Arc<Mutex<Option<ObservedUdpAddrRecord>>>,
    /// Observed public UDP addresses reported for remote peers (from their HELLO or OBSERVE_RESP).
    /// The timestamp records when this node last received that observation data.
    udp_observed_addrs: Arc<Mutex<HashMap<String, ObservedUdpAddrRecord>>>,
    /// Pending punch requests keyed by correlation id.  (ADR-0005 Phase 3)
    pending_punches: Arc<Mutex<HashMap<String, PendingPunch>>>,
    pending_observations: Arc<Mutex<HashMap<[u8; 8], PendingObservation>>>,
    /// UDP socket handle — set by `set_udp_handle` after `spawn_udp_listener`.  (Phase 3)
    #[cfg(feature = "noise")]
    udp_handle: Arc<Mutex<Option<UdpHandle>>>,
    /// NatState for cookie and probe configuration.  Set by `set_nat_state` in main.  (Phase 3)
    #[cfg(feature = "noise")]
    nat_state:
        Arc<tokio::sync::RwLock<Option<std::sync::Arc<crate::network::nat_traversal::NatState>>>>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    const DEFAULT_QUEUE_MAX_PER_TARGET: usize = 1024;
    const DEFAULT_QUEUE_MAX_GLOBAL: usize = 8192;

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
            relay_queue_max_per_target: Arc::new(AtomicUsize::new(
                Self::DEFAULT_QUEUE_MAX_PER_TARGET,
            )),
            relay_queue_max_global: Arc::new(AtomicUsize::new(Self::DEFAULT_QUEUE_MAX_GLOBAL)),
            relay_binding_ids: Arc::new(Mutex::new(HashMap::new())),
            relay_last_sequence: Arc::new(Mutex::new(HashMap::new())),
            reliable_inflight: Arc::new(Mutex::new(HashSet::new())),
            delivery_attempts: Arc::new(Mutex::new(HashMap::new())),
            delivery_dedup: Arc::new(Mutex::new(HashMap::new())),
            delivery_next_ordering_sequence: Arc::new(Mutex::new(HashMap::new())),
            delivery_ordered_inbound: Arc::new(Mutex::new(HashMap::new())),
            relay_next_sequence: Arc::new(Mutex::new(HashMap::new())),
            delivery_dedup_window_secs: Arc::new(AtomicU64::new(3600)),
            delivery_ordered_buffer_limit: Arc::new(AtomicUsize::new(1024)),
            transport_kind: Arc::new(Mutex::new(HashMap::new())),
            udp_listen_addrs: Arc::new(Mutex::new(HashMap::new())),
            udp_session_ids: Arc::new(Mutex::new(HashMap::new())),
            own_observed_addr: Arc::new(Mutex::new(None)),
            udp_observed_addrs: Arc::new(Mutex::new(HashMap::new())),
            pending_punches: Arc::new(Mutex::new(HashMap::new())),
            pending_observations: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "noise")]
            udp_handle: Arc::new(Mutex::new(None)),
            #[cfg(feature = "noise")]
            nat_state: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub fn set_relay_queue_caps(
        &self,
        per_target: Option<usize>,
        global: Option<usize>,
    ) -> (usize, usize) {
        let per_target_cap = per_target
            .unwrap_or(Self::DEFAULT_QUEUE_MAX_PER_TARGET)
            .max(1);
        let global_cap = global.unwrap_or(Self::DEFAULT_QUEUE_MAX_GLOBAL).max(1);
        self.relay_queue_max_per_target
            .store(per_target_cap, Ordering::Relaxed);
        self.relay_queue_max_global
            .store(global_cap, Ordering::Relaxed);
        (per_target_cap, global_cap)
    }

    pub fn relay_queue_caps(&self) -> (usize, usize) {
        (
            self.relay_queue_max_per_target.load(Ordering::Relaxed),
            self.relay_queue_max_global.load(Ordering::Relaxed),
        )
    }

    pub fn set_delivery_config(&self, delivery: Option<DeliveryConfig>) {
        let delivery = delivery.unwrap_or_default();
        self.delivery_dedup_window_secs.store(
            delivery.dedup_window_secs.unwrap_or(3600),
            Ordering::Relaxed,
        );
        self.delivery_ordered_buffer_limit.store(
            delivery
                .ordered_max_buffered_messages
                .unwrap_or(1024)
                .max(1),
            Ordering::Relaxed,
        );
    }

    pub fn delivery_dedup_window_secs(&self) -> u64 {
        self.delivery_dedup_window_secs.load(Ordering::Relaxed)
    }

    pub fn delivery_ordered_buffer_limit(&self) -> usize {
        self.delivery_ordered_buffer_limit.load(Ordering::Relaxed)
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
                // Purge UDP maps for this node_id (ADR-0004).
                self.transport_kind.lock().await.remove(dup_node_id);
                self.udp_listen_addrs.lock().await.remove(dup_node_id);
                self.udp_session_ids.lock().await.remove(dup_node_id);
                // Purge NAT traversal maps (ADR-0005).
                self.udp_observed_addrs.lock().await.remove(dup_node_id);
                self.pending_punches.lock().await.retain(|_, pending| {
                    pending.initiator_node_id != *dup_node_id
                        && pending.responder_node_id != *dup_node_id
                });
                self.pending_observations
                    .lock()
                    .await
                    .retain(|_, pending| pending.observer_node_id != *dup_node_id);
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

    /// Return the TCP listen address advertised by a peer in its HELLO, if known.
    ///
    /// The `listen_addrs` map is indexed by address; this performs a reverse lookup
    /// by node_id.  Used by the connection policy to resolve TCP addresses for
    /// peers that are not currently connected.
    pub async fn tcp_listen_addr_for(&self, node_id: &str) -> Option<String> {
        let map = self.listen_addrs.lock().await;
        map.iter().find_map(|(addr, nid)| {
            if nid == node_id {
                Some(addr.clone())
            } else {
                None
            }
        })
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

    pub async fn record_delivery_attempt(
        &self,
        message_id: &MessageId,
        class: DeliveryClass,
        expires_at: std::time::Instant,
    ) {
        self.delivery_attempts.lock().await.insert(
            message_id.as_str().to_string(),
            DeliveryAttemptState {
                class,
                attempts: 0,
                outcome: None,
                expires_at,
            },
        );
    }

    pub async fn increment_delivery_attempts(&self, message_id: &MessageId) -> Option<u32> {
        let mut attempts = self.delivery_attempts.lock().await;
        let state = attempts.get_mut(message_id.as_str())?;
        state.attempts = state.attempts.saturating_add(1);
        Some(state.attempts)
    }

    pub async fn set_delivery_outcome(&self, message_id: &MessageId, outcome: DeliveryOutcome) {
        if let Some(state) = self
            .delivery_attempts
            .lock()
            .await
            .get_mut(message_id.as_str())
        {
            state.outcome = Some(outcome);
        }
    }

    pub async fn delivery_outcome(&self, message_id: &MessageId) -> Option<DeliveryOutcome> {
        self.delivery_attempts
            .lock()
            .await
            .get(message_id.as_str())
            .and_then(|state| state.outcome)
    }

    pub async fn clear_delivery_attempt(&self, message_id: &MessageId) {
        self.delivery_attempts
            .lock()
            .await
            .remove(message_id.as_str());
    }

    pub async fn delivery_expired(&self, message_id: &MessageId) -> bool {
        self.delivery_attempts
            .lock()
            .await
            .get(message_id.as_str())
            .map(|state| std::time::Instant::now() >= state.expires_at)
            .unwrap_or(false)
    }

    pub async fn delivery_class_for(&self, message_id: &MessageId) -> Option<DeliveryClass> {
        self.delivery_attempts
            .lock()
            .await
            .get(message_id.as_str())
            .map(|state| state.class)
    }

    pub async fn prune_delivery_dedup(&self, max_age: std::time::Duration) {
        let mut dedup = self.delivery_dedup.lock().await;
        let now = std::time::Instant::now();
        dedup.retain(|_, seen_at| now.duration_since(*seen_at) <= max_age);
    }

    pub async fn record_delivery_receipt(
        &self,
        origin_node_id: &str,
        message_id: &MessageId,
    ) -> bool {
        let key = (origin_node_id.to_string(), message_id.as_str().to_string());
        let mut dedup = self.delivery_dedup.lock().await;
        let is_new = !dedup.contains_key(&key);
        dedup.insert(key, std::time::Instant::now());
        is_new
    }

    pub async fn next_ordering_sequence(&self, from: &str, to: &str, ordering_key: &str) -> u64 {
        let key = (from.to_string(), to.to_string(), ordering_key.to_string());
        let mut sequences = self.delivery_next_ordering_sequence.lock().await;
        let next = sequences.get(&key).copied().unwrap_or(1);
        sequences.insert(key, next.saturating_add(1));
        next
    }

    pub async fn accept_ordered_incoming(
        &self,
        origin_node_id: &str,
        destination_node_id: &str,
        ordering_key: &str,
        ordering_sequence: u64,
        message: Message,
        max_buffered_messages: usize,
    ) -> Vec<Message> {
        let key = (
            origin_node_id.to_string(),
            destination_node_id.to_string(),
            ordering_key.to_string(),
        );

        let mut buffers = self.delivery_ordered_inbound.lock().await;
        let bucket = buffers.entry(key).or_insert_with(|| OrderedDeliveryBuffer {
            next_expected: 1,
            pending: BTreeMap::new(),
            last_activity: std::time::Instant::now(),
        });

        if ordering_sequence < bucket.next_expected {
            return Vec::new();
        }

        if ordering_sequence > bucket.next_expected {
            if bucket.pending.len() < max_buffered_messages {
                bucket.pending.insert(ordering_sequence, message);
                bucket.last_activity = std::time::Instant::now();
            }
            return Vec::new();
        }

        bucket.last_activity = std::time::Instant::now();
        let mut ready = vec![message];
        bucket.next_expected = bucket.next_expected.saturating_add(1);
        while let Some(next_message) = bucket.pending.remove(&bucket.next_expected) {
            ready.push(next_message);
            bucket.next_expected = bucket.next_expected.saturating_add(1);
        }

        ready
    }

    /// Evict ordered-delivery scopes that have not seen any activity within `max_age`.
    /// This prevents stale scopes (where the gap message never arrived) from accumulating
    /// in memory indefinitely.
    pub async fn prune_ordered_inbound(&self, max_age: std::time::Duration) {
        let mut buffers = self.delivery_ordered_inbound.lock().await;
        let now = std::time::Instant::now();
        buffers.retain(|_, bucket| now.duration_since(bucket.last_activity) <= max_age);
    }

    pub async fn next_relay_sequence(&self, from: &str, to: &str) -> u64 {
        let key = (from.to_string(), to.to_string());
        let mut sequences = self.relay_next_sequence.lock().await;
        let next = sequences.get(&key).copied().unwrap_or(1);
        sequences.insert(key, next.saturating_add(1));
        next
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
        let (max_queue_per_target, max_queue_global) = self.relay_queue_caps();
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
            if v.len() >= max_queue_per_target {
                let drop_count = v.len() + 1 - max_queue_per_target;
                for _ in 0..drop_count {
                    let removed = v.remove(0);
                    if let Some(o) = removed.2.as_ref() {
                        to_notify.push((o.clone(), crate::network::message::Reason::Overload));
                    }
                }
            }
        }
        let entry = q.entry(to_node_id.to_string()).or_insert_with(Vec::new);
        if entry.len() >= max_queue_per_target {
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
        if total_len > max_queue_global {
            let mut keys: Vec<String> = q.keys().cloned().collect();
            keys.sort();
            let mut idx = 0usize;
            while total_len > max_queue_global && !keys.is_empty() {
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
        let (max_queue_per_target, max_queue_global) = self.relay_queue_caps();
        let q = self.relay_queue.lock().await;
        let per_target_ok = q
            .get(to_node_id)
            .map(|v| v.len() < max_queue_per_target)
            .unwrap_or(true);
        let total_len: usize = q.values().map(|v| v.len()).sum();
        let global_ok = total_len < max_queue_global;
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

    // ── UDP transport accessors (ADR-0004) ──────────────────────────────────────

    /// Set the preferred transport kind for a peer identified by `node_id`.
    pub async fn set_transport_kind(&self, node_id: &str, kind: TransportKind) {
        self.transport_kind
            .lock()
            .await
            .insert(node_id.to_string(), kind);
    }

    /// Get the current transport kind for a peer, or `None` if not recorded.
    pub async fn get_transport_kind(&self, node_id: &str) -> Option<TransportKind> {
        self.transport_kind.lock().await.get(node_id).cloned()
    }

    /// Record a UDP listen address advertised in the peer's HELLO message.
    pub async fn add_udp_listen_addr(&self, node_id: &str, addr: &str) {
        self.udp_listen_addrs
            .lock()
            .await
            .insert(node_id.to_string(), addr.to_string());
    }

    /// Retrieve the UDP listen address for a peer, if known.
    pub async fn udp_listen_addr_for(&self, node_id: &str) -> Option<String> {
        self.udp_listen_addrs.lock().await.get(node_id).cloned()
    }

    /// Store the active Noise session ID for a peer (set on handshake completion).
    pub async fn set_udp_session_id(&self, node_id: &str, session_id: [u8; 8]) {
        self.udp_session_ids
            .lock()
            .await
            .insert(node_id.to_string(), session_id);
    }

    /// Retrieve the active Noise session ID for a peer.
    pub async fn udp_session_id_for(&self, node_id: &str) -> Option<[u8; 8]> {
        self.udp_session_ids.lock().await.get(node_id).copied()
    }

    #[cfg(feature = "noise")]
    pub async fn ensure_udp_session(
        &self,
        node_id: &str,
        local_node_id: &str,
        timeout: std::time::Duration,
    ) -> Result<[u8; 8], String> {
        if let Some(session_id) = self.udp_session_id_for(node_id).await {
            return Ok(session_id);
        }

        let target_addr = self
            .udp_listen_addr_for(node_id)
            .await
            .ok_or_else(|| format!("udp listen addr not found for {node_id}"))?
            .parse::<SocketAddr>()
            .map_err(|err| format!("invalid udp listen addr for {node_id}: {err}"))?;

        let handle = self
            .udp_handle
            .lock()
            .await
            .clone()
            .ok_or_else(|| "udp handle not initialized".to_string())?;

        crate::network::udp_listener::connect_udp(
            target_addr,
            &handle.socket,
            &handle.sessions,
            &handle.static_private,
            local_node_id,
        )
        .await
        .map_err(|err| err.to_string())?;

        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(session_id) = self.udp_session_id_for(node_id).await {
                return Ok(session_id);
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("timed out establishing udp session for {node_id}"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    #[cfg(not(feature = "noise"))]
    pub async fn ensure_udp_session(
        &self,
        node_id: &str,
        _local_node_id: &str,
        _timeout: std::time::Duration,
    ) -> Result<[u8; 8], String> {
        Err(format!(
            "udp transport is unavailable without the noise feature for {node_id}"
        ))
    }

    #[cfg(feature = "noise")]
    pub async fn send_udp_message_to_node(
        &self,
        node_id: &str,
        payload: &[u8],
    ) -> Result<(), String> {
        let session_id = self
            .udp_session_id_for(node_id)
            .await
            .ok_or_else(|| format!("udp session not found for {node_id}"))?;
        let handle = self
            .udp_handle
            .lock()
            .await
            .clone()
            .ok_or_else(|| "udp handle not initialized".to_string())?;

        crate::network::udp_listener::send_udp(
            &session_id,
            payload,
            &handle.socket,
            &handle.sessions,
        )
        .await
        .map_err(|err| err.to_string())
    }

    #[cfg(not(feature = "noise"))]
    pub async fn send_udp_message_to_node(
        &self,
        node_id: &str,
        _payload: &[u8],
    ) -> Result<(), String> {
        Err(format!(
            "udp transport is unavailable without the noise feature for {node_id}"
        ))
    }

    /// Dispatch a decrypted UDP payload from `node_id` to the event/plugin system.
    ///
    /// Phase 1: emits a structured log event.  Full plugin routing is Phase 2+.
    pub async fn dispatch_udp_payload(&self, node_id: &str, payload: &[u8]) {
        use crate::events::{
            dispatcher,
            model::{LogEvent, LogLevel, SystemEvent},
        };
        let mut meta = dispatcher::meta("udp", LogLevel::Debug);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "udp_payload_received".into(),
            detail: Some(format!("node_id={} bytes={}", node_id, payload.len())),
        }));
    }

    // ── NAT traversal accessors (ADR-0005) ──────────────────────────────────────

    /// Store the own node's most recently observed public UDP address.
    pub async fn set_own_observed_addr(
        &self,
        addr: &str,
        observer_node_id: Option<&str>,
        request_nonce: Option<[u8; 8]>,
    ) {
        *self.own_observed_addr.lock().await = Some(ObservedUdpAddrRecord {
            addr: addr.to_string(),
            observed_at: std::time::Instant::now(),
            observer_node_id: observer_node_id.map(str::to_string),
            request_nonce,
        });
    }

    /// Return own observed UDP address if it was seen less than `max_age_secs` ago.
    pub async fn own_udp_observed_addr_if_fresh(&self, max_age_secs: u64) -> Option<String> {
        self.own_observed_addr
            .lock()
            .await
            .as_ref()
            .filter(|record| record.observed_at.elapsed().as_secs() < max_age_secs)
            .map(|record| record.addr.clone())
    }

    /// Return the configured NAT-observation freshness window in seconds.
    pub async fn nat_observation_refresh_secs(&self) -> u64 {
        #[cfg(feature = "noise")]
        {
            if let Some(state) = self.nat_state.read().await.clone() {
                return state.refresh_secs;
            }
        }
        300
    }

    /// Store the observed public UDP address for a remote peer.
    pub async fn add_udp_observed_addr(
        &self,
        node_id: &str,
        addr: &str,
        observer_node_id: Option<&str>,
        request_nonce: Option<[u8; 8]>,
    ) {
        self.udp_observed_addrs.lock().await.insert(
            node_id.to_string(),
            ObservedUdpAddrRecord {
                addr: addr.to_string(),
                observed_at: std::time::Instant::now(),
                observer_node_id: observer_node_id.map(str::to_string),
                request_nonce,
            },
        );
    }

    /// Retrieve the observed public UDP address for a remote peer.
    pub async fn udp_observed_addr_for(&self, node_id: &str) -> Option<String> {
        self.udp_observed_addrs
            .lock()
            .await
            .get(node_id)
            .map(|record| record.addr.clone())
    }

    pub async fn udp_observed_record_for_if_fresh(
        &self,
        node_id: &str,
        max_age_secs: u64,
    ) -> Option<ObservedUdpAddrRecord> {
        self.udp_observed_addrs
            .lock()
            .await
            .get(node_id)
            .filter(|record| record.observed_at.elapsed().as_secs() < max_age_secs)
            .cloned()
    }

    /// Retrieve the observed public UDP address for a remote peer if it is still fresh.
    pub async fn udp_observed_addr_for_if_fresh(
        &self,
        node_id: &str,
        max_age_secs: u64,
    ) -> Option<String> {
        self.udp_observed_addrs
            .lock()
            .await
            .get(node_id)
            .and_then(|record| {
                if record.observed_at.elapsed().as_secs() < max_age_secs {
                    Some(record.addr.clone())
                } else {
                    None
                }
            })
    }

    /// Reverse-lookup: return the node_id for a connected peer's TCP socket address.
    pub async fn node_id_for_addr(&self, addr: &SocketAddr) -> Option<String> {
        self.node_ids
            .lock()
            .await
            .iter()
            .find_map(|(nid, a)| if a == addr { Some(nid.clone()) } else { None })
    }

    /// Record a pending relay-coordinated hole-punch request.
    pub async fn add_pending_punch(
        &self,
        attempt_id: &str,
        responder_node_id: &str,
        initiator_node_id: &str,
        timeout_ms: u64,
    ) {
        self.pending_punches.lock().await.insert(
            attempt_id.to_string(),
            PendingPunch {
                attempt_id: attempt_id.to_string(),
                initiator_node_id: initiator_node_id.to_string(),
                responder_node_id: responder_node_id.to_string(),
                timeout_ms,
            },
        );
    }

    /// Retrieve a pending punch record by attempt id.
    pub async fn get_pending_punch(&self, attempt_id: &str) -> Option<PendingPunch> {
        self.pending_punches.lock().await.get(attempt_id).cloned()
    }

    /// Remove a pending punch record by attempt id.
    pub async fn remove_pending_punch(&self, attempt_id: &str) {
        self.pending_punches.lock().await.remove(attempt_id);
    }

    pub async fn register_pending_observation(
        &self,
        observer_node_id: &str,
        expected_source: SocketAddr,
        nonce: [u8; 8],
    ) {
        self.pending_observations.lock().await.insert(
            nonce,
            PendingObservation {
                observer_node_id: observer_node_id.to_string(),
                expected_source,
                nonce,
                requested_at: std::time::Instant::now(),
            },
        );
    }

    pub async fn pending_observation(&self, nonce: &[u8; 8]) -> Option<PendingObservation> {
        self.pending_observations.lock().await.get(nonce).cloned()
    }

    pub async fn remove_pending_observation(&self, nonce: &[u8; 8]) -> Option<PendingObservation> {
        self.pending_observations.lock().await.remove(nonce)
    }

    /// Register the live UDP socket and Noise session map (called after `spawn_udp_listener`).
    #[cfg(feature = "noise")]
    pub async fn set_udp_handle(
        &self,
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        sessions: crate::network::udp_listener::UdpSessions,
        static_private: Vec<u8>,
    ) {
        *self.udp_handle.lock().await = Some(UdpHandle {
            socket,
            sessions,
            static_private,
        });
    }

    /// Register the `NatState` built from config (called in main.rs).
    #[cfg(feature = "noise")]
    pub async fn set_nat_state(
        &self,
        state: std::sync::Arc<crate::network::nat_traversal::NatState>,
    ) {
        *self.nat_state.write().await = Some(state);
    }

    /// Dispatch `PunchCoordinate` to the nat_traversal rendezvous handler.
    #[cfg(feature = "noise")]
    pub async fn handle_punch_coordinate_msg(
        &self,
        attempt_id: &str,
        from_node_id: &str,
        target_node_id: &str,
        timeout_ms: u64,
    ) {
        let nat = self.nat_state.read().await.clone();
        if let Some(state) = nat {
            crate::network::nat_traversal::handle_punch_coordinate(
                self,
                &state,
                attempt_id,
                from_node_id,
                target_node_id,
                timeout_ms,
            )
            .await;
        }
    }

    /// Dispatch `PunchReady` to the nat_traversal rendezvous handler.
    #[cfg(feature = "noise")]
    pub async fn handle_punch_ready_msg(
        &self,
        attempt_id: &str,
        responder_node_id: &str,
        target_node_id: &str,
        ok: bool,
    ) {
        let nat = self.nat_state.read().await.clone();
        if let Some(state) = nat {
            crate::network::nat_traversal::handle_punch_ready(
                self,
                &state,
                attempt_id,
                responder_node_id,
                target_node_id,
                ok,
            )
            .await;
        }
    }

    /// Execute a hole-punch window on receipt of `PunchGo`.  Spawns a background task.
    #[cfg(feature = "noise")]
    pub async fn handle_punch_go_msg(
        &self,
        local_node_id: &str,
        punch: crate::network::nat_traversal::PunchGoParams,
    ) {
        let nat = self.nat_state.read().await.clone();
        let handle = self.udp_handle.lock().await.clone();
        if let (Some(state), Some(h)) = (nat, handle) {
            let pm = self.clone();
            let local_node_id = local_node_id.to_string();
            tokio::spawn(async move {
                crate::network::nat_traversal::execute_punch_window(
                    &pm,
                    &h.socket,
                    &h.sessions,
                    &h.static_private,
                    &state,
                    &local_node_id,
                    punch,
                )
                .await;
            });
        }
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
