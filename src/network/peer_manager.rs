// src/network/peer_manager.rs

use parking_lot::RwLock as ParkingRwLock;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use crate::config::{Config, DeliveryConfig};
use crate::events::model::LogLevel;
use crate::network::connection::{ConnectionPolicy, RouteHealth, RouteKind};
use crate::network::delivery::{DeliveryClass, DeliveryOutcome, MessageId};
use crate::network::events::emit_network_event;
use crate::network::message::{Message, MessageOrigin, MessageType, Payload};
use crate::network::{Peer, PeerSource, PeerStore};
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;
use crate::security::node_identity::NodeIdentityRegistry;

#[derive(Clone, Debug)]
struct DeliveryAttemptState {
    class: DeliveryClass,
    /// The node the message is addressed to: the only node whose
    /// `DELIVERY_ACK` counts.
    destination: String,
    attempts: u32,
    outcome: Option<DeliveryOutcome>,
    expires_at: std::time::Instant,
}

#[derive(Clone, Debug)]
struct OrderedDeliveryBuffer {
    next_expected: u64,
    /// Out-of-order messages with their serialized size.
    pending: BTreeMap<u64, (Message, usize)>,
    pending_bytes: usize,
    /// Last time this scope received an in-sequence or buffered message.
    /// Used by `prune_ordered_inbound` to evict stale scopes.
    last_activity: std::time::Instant,
}

/// Ordered-reliable scopes and buffered bytes, counted per origin so one
/// origin cannot fill memory with ordering keys or out-of-order messages.
#[derive(Debug, Default)]
struct OrderedInbound {
    scopes: HashMap<(String, String, String), OrderedDeliveryBuffer>,
    usage: HashMap<String, OrderedUsage>,
    pending_bytes: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct OrderedUsage {
    scopes: usize,
    pending_bytes: usize,
}

impl OrderedInbound {
    const MAX_SCOPES_PER_ORIGIN: usize = 1024;
    const MAX_SCOPES: usize = 65_536;
    const MAX_PENDING_BYTES_PER_ORIGIN: usize = 4 * 1024 * 1024;
    const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
}

/// Reliable message IDs one origin sent within the dedup window, oldest first.
#[derive(Debug, Default)]
struct DedupWindow {
    order: VecDeque<(String, Instant)>,
    seen: HashSet<String>,
}

/// Reliable message IDs already delivered, bounded per origin and in total:
/// an origin flooding unique IDs only evicts its own oldest entries, which
/// matter least because retries come within seconds.
#[derive(Debug, Default)]
struct DeliveryDedup {
    windows: HashMap<String, DedupWindow>,
    total: usize,
}

impl DeliveryDedup {
    const MAX_PER_ORIGIN: usize = 16_384;
    const MAX_TOTAL: usize = 262_144;

    fn contains(&self, origin: &str, message_id: &str) -> bool {
        self.windows
            .get(origin)
            .is_some_and(|window| window.seen.contains(message_id))
    }

    /// Record `message_id` from `origin`; `false` if it was already recorded.
    fn record(&mut self, origin: &str, message_id: &str, now: Instant) -> bool {
        let window = self.windows.entry(origin.to_string()).or_default();
        if !window.seen.insert(message_id.to_string()) {
            return false;
        }
        window.order.push_back((message_id.to_string(), now));
        self.total += 1;
        if window.order.len() > Self::MAX_PER_ORIGIN {
            Self::evict_oldest(window, &mut self.total);
        }
        while self.total > Self::MAX_TOTAL {
            let Some(largest) = self.windows.values_mut().max_by_key(|w| w.order.len()) else {
                break;
            };
            Self::evict_oldest(largest, &mut self.total);
        }
        true
    }

    fn evict_oldest(window: &mut DedupWindow, total: &mut usize) {
        if let Some((message_id, _)) = window.order.pop_front() {
            window.seen.remove(&message_id);
            *total -= 1;
        }
    }

    fn prune(&mut self, max_age: std::time::Duration, now: Instant) {
        for window in self.windows.values_mut() {
            while window
                .order
                .front()
                .is_some_and(|(_, seen_at)| now.duration_since(*seen_at) > max_age)
            {
                Self::evict_oldest(window, &mut self.total);
            }
        }
        self.windows.retain(|_, window| !window.order.is_empty());
    }
}

#[derive(Clone, Debug)]
struct RouteHealthRecord {
    health: RouteHealth,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

impl Default for RouteHealthRecord {
    fn default() -> Self {
        Self {
            health: RouteHealth::Unknown,
            last_success: None,
            last_failure: None,
        }
    }
}

#[derive(Clone)]
struct ConnectionLifecycleRuntime {
    policy: ConnectionPolicy,
    config: Config,
    local_node_id: String,
    peer_store: PeerStore,
    plugin_manager: Weak<PluginManager>,
    allow_console: bool,
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

/// A punch this node coordinates as rendezvous (ADR-0005 Phase 3), keyed by
/// attempt ID in `PeerManager::pending_punches`.
#[derive(Clone, Debug)]
pub struct PendingPunch {
    pub attempt_id: String,
    /// Node ID of the peer that initiated the punch request.
    pub initiator_node_id: String,
    pub responder_node_id: String,
    pub timeout_ms: u64,
    /// When the attempt is forgotten: its time budget, at most
    /// [`MAX_PUNCH_TIMEOUT_MS`], after it was recorded.
    pub expires_at: Instant,
}

/// Longest a node waits for a punch it takes part in, whatever time budget a
/// peer asks for.  (ADR-0015)
pub const MAX_PUNCH_TIMEOUT_MS: u64 = 30_000;

/// Longest punch attempt ID a node accepts, in bytes. Every node involved
/// keeps the ID while the punch is in progress.
pub const MAX_ATTEMPT_ID_LEN: usize = 128;

fn attempt_id_acceptable(attempt_id: &str) -> bool {
    !attempt_id.is_empty() && attempt_id.len() <= MAX_ATTEMPT_ID_LEN
}

fn punch_deadline(now: Instant, timeout_ms: u64) -> Instant {
    now + std::time::Duration::from_millis(timeout_ms.min(MAX_PUNCH_TIMEOUT_MS))
}

/// A hole punch this node takes part in: one it asked a rendezvous for
/// (initiator), or an invitation it accepted (responder). `PUNCH_GO` is
/// followed only for one of these (ADR-0015).
#[derive(Clone, Debug)]
pub struct ExpectedPunch {
    /// The rendezvous that coordinates the attempt and must send `PUNCH_GO`.
    pub rendezvous_node_id: String,
    pub initiator_node_id: String,
    pub responder_node_id: String,
    /// The attempt is abandoned after this.
    pub expires_at: Instant,
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
    /// Stamped as `from` on every message sent over a UDP session.
    pub local_node_id: String,
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct PeerManager {
    peers: Arc<Mutex<HashMap<SocketAddr, Sender<Message>>>>,
    node_ids: Arc<Mutex<HashMap<String, SocketAddr>>>, // node_id -> addr
    // Address at which this node dialled each peer and reached it (node_id ->
    // addr). The only addresses used to suppress dials, to reconnect, and to
    // persist.
    verified_listen_addrs: Arc<Mutex<HashMap<String, String>>>,
    // Listen address a peer announced in its HELLO (node_id -> addr), used only
    // as a route to try when delivering to that peer.
    claimed_listen_addrs: Arc<Mutex<HashMap<String, String>>>,
    // Node identity binding (ADR-0012), created from the config on first use.
    node_identity: Arc<std::sync::OnceLock<Arc<NodeIdentityRegistry>>>,
    // Transport fingerprint bound to the node on each registered TCP connection.
    tcp_bound_fingerprints: Arc<Mutex<HashMap<SocketAddr, String>>>,
    // Noise fingerprint bound to a node on its active UDP session.
    udp_bound_fingerprints: Arc<Mutex<HashMap<String, String>>>,
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
    relay_queue_max_bytes: Arc<AtomicUsize>,
    // Track last seen sequence per (from,to) for ordering/dedup
    relay_last_sequence: Arc<Mutex<HashMap<(String, String), u64>>>,
    capabilities_by_node: Arc<Mutex<HashMap<String, Vec<String>>>>,
    // Map binding_id -> (from,to)
    relay_binding_ids: Arc<Mutex<HashMap<String, (String, String)>>>,
    // In-flight reliable forwards keyed by (from,to,sequence)
    reliable_inflight: Arc<Mutex<HashSet<(String, String, u64)>>>,
    // Framework delivery state (ADR-0006)
    delivery_attempts: Arc<Mutex<HashMap<String, DeliveryAttemptState>>>,
    delivery_dedup: Arc<Mutex<DeliveryDedup>>,
    delivery_next_ordering_sequence: Arc<Mutex<HashMap<(String, String, String), u64>>>,
    delivery_ordered_inbound: Arc<Mutex<OrderedInbound>>,
    relay_next_sequence: Arc<Mutex<HashMap<(String, String), u64>>>,
    delivery_dedup_window_secs: Arc<AtomicU64>,
    delivery_ordered_buffer_limit: Arc<AtomicUsize>,
    route_health: Arc<Mutex<HashMap<(String, RouteKind), RouteHealthRecord>>>,
    // On tokio's clock, which the liveness monitor ticks on.
    last_peer_activity: Arc<Mutex<HashMap<String, tokio::time::Instant>>>,
    lifecycle_generations: Arc<Mutex<HashMap<String, u64>>>,
    next_lifecycle_generation: Arc<AtomicU64>,
    reconnecting_peers: Arc<Mutex<HashSet<String>>>,
    lifecycle_runtime: Arc<Mutex<Option<ConnectionLifecycleRuntime>>>,
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
    /// Fresh observed public UDP address samples keyed by observer identity.
    own_observed_addr_samples: Arc<Mutex<HashMap<String, ObservedUdpAddrRecord>>>,
    /// Observed public UDP addresses reported for remote peers (from their HELLO or OBSERVE_RESP).
    /// The timestamp records when this node last received that observation data.
    udp_observed_addrs: Arc<Mutex<HashMap<String, ObservedUdpAddrRecord>>>,
    /// Gateway-reported external IP address discovered via UPnP-IGD.
    gateway_external_ip: Arc<ParkingRwLock<Option<String>>>,
    /// Public TCP address to advertise in HELLO once a direct inbound path is confirmed.
    public_tcp_hello_addr: Arc<ParkingRwLock<Option<String>>>,
    /// Lightweight capability hint for likely direct inbound TCP reachability.
    direct_tcp_hint: Arc<AtomicBool>,
    /// Last emitted NAT diagnostic summary; used to suppress duplicate events.
    nat_diagnostic_summary: Arc<ParkingRwLock<Option<String>>>,
    /// Pending punch requests keyed by correlation id.  (ADR-0005 Phase 3)
    pending_punches: Arc<Mutex<HashMap<String, PendingPunch>>>,
    /// Punches this node takes part in, keyed by attempt id.  (ADR-0015)
    expected_punches: Arc<Mutex<HashMap<String, ExpectedPunch>>>,
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
    const DEFAULT_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

    /// Verified listen addresses kept, one per node.
    const MAX_VERIFIED_LISTEN_ADDRS: usize = 4096;
    /// How long an `OBSERVE_REQ` waits for its answer.
    const PENDING_OBSERVATION_TTL: std::time::Duration = std::time::Duration::from_secs(30);
    /// Punches a node takes part in at once; invitations beyond this are declined.
    const MAX_EXPECTED_PUNCHES: usize = 256;
    /// Punches a node coordinates as rendezvous at once, in total and per
    /// initiator.
    const MAX_PENDING_PUNCHES: usize = 1024;
    const MAX_PENDING_PUNCHES_PER_INITIATOR: usize = 16;

    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            node_ids: Arc::new(Mutex::new(HashMap::new())),
            verified_listen_addrs: Arc::new(Mutex::new(HashMap::new())),
            claimed_listen_addrs: Arc::new(Mutex::new(HashMap::new())),
            node_identity: Arc::new(std::sync::OnceLock::new()),
            tcp_bound_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            udp_bound_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            capabilities_by_node: Arc::new(Mutex::new(HashMap::new())),
            relay_forwarded: Arc::new(AtomicU64::new(0)),
            relay_dropped: Arc::new(AtomicU64::new(0)),
            relay_bindings: Arc::new(Mutex::new(HashMap::new())),
            relay_queue: Arc::new(Mutex::new(HashMap::new())),
            relay_queue_max_per_target: Arc::new(AtomicUsize::new(
                Self::DEFAULT_QUEUE_MAX_PER_TARGET,
            )),
            relay_queue_max_global: Arc::new(AtomicUsize::new(Self::DEFAULT_QUEUE_MAX_GLOBAL)),
            relay_queue_max_bytes: Arc::new(AtomicUsize::new(Self::DEFAULT_QUEUE_MAX_BYTES)),
            relay_binding_ids: Arc::new(Mutex::new(HashMap::new())),
            relay_last_sequence: Arc::new(Mutex::new(HashMap::new())),
            reliable_inflight: Arc::new(Mutex::new(HashSet::new())),
            delivery_attempts: Arc::new(Mutex::new(HashMap::new())),
            delivery_dedup: Arc::new(Mutex::new(DeliveryDedup::default())),
            delivery_next_ordering_sequence: Arc::new(Mutex::new(HashMap::new())),
            delivery_ordered_inbound: Arc::new(Mutex::new(OrderedInbound::default())),
            relay_next_sequence: Arc::new(Mutex::new(HashMap::new())),
            delivery_dedup_window_secs: Arc::new(AtomicU64::new(3600)),
            delivery_ordered_buffer_limit: Arc::new(AtomicUsize::new(1024)),
            route_health: Arc::new(Mutex::new(HashMap::new())),
            last_peer_activity: Arc::new(Mutex::new(HashMap::new())),
            lifecycle_generations: Arc::new(Mutex::new(HashMap::new())),
            next_lifecycle_generation: Arc::new(AtomicU64::new(1)),
            reconnecting_peers: Arc::new(Mutex::new(HashSet::new())),
            lifecycle_runtime: Arc::new(Mutex::new(None)),
            transport_kind: Arc::new(Mutex::new(HashMap::new())),
            udp_listen_addrs: Arc::new(Mutex::new(HashMap::new())),
            udp_session_ids: Arc::new(Mutex::new(HashMap::new())),
            own_observed_addr: Arc::new(Mutex::new(None)),
            own_observed_addr_samples: Arc::new(Mutex::new(HashMap::new())),
            udp_observed_addrs: Arc::new(Mutex::new(HashMap::new())),
            gateway_external_ip: Arc::new(ParkingRwLock::new(None)),
            public_tcp_hello_addr: Arc::new(ParkingRwLock::new(None)),
            direct_tcp_hint: Arc::new(AtomicBool::new(false)),
            nat_diagnostic_summary: Arc::new(ParkingRwLock::new(None)),
            pending_punches: Arc::new(Mutex::new(HashMap::new())),
            expected_punches: Arc::new(Mutex::new(HashMap::new())),
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
        max_bytes: Option<usize>,
    ) -> (usize, usize, usize) {
        let per_target_cap = per_target
            .unwrap_or(Self::DEFAULT_QUEUE_MAX_PER_TARGET)
            .max(1);
        let global_cap = global.unwrap_or(Self::DEFAULT_QUEUE_MAX_GLOBAL).max(1);
        let bytes_cap = max_bytes.unwrap_or(Self::DEFAULT_QUEUE_MAX_BYTES).max(1);
        self.relay_queue_max_per_target
            .store(per_target_cap, Ordering::Relaxed);
        self.relay_queue_max_global
            .store(global_cap, Ordering::Relaxed);
        self.relay_queue_max_bytes
            .store(bytes_cap, Ordering::Relaxed);
        (per_target_cap, global_cap, bytes_cap)
    }

    pub fn relay_queue_caps(&self) -> (usize, usize) {
        (
            self.relay_queue_max_per_target.load(Ordering::Relaxed),
            self.relay_queue_max_global.load(Ordering::Relaxed),
        )
    }

    /// Global cap on buffered store-and-forward bytes across all targets.
    pub fn relay_queue_max_bytes(&self) -> usize {
        self.relay_queue_max_bytes.load(Ordering::Relaxed)
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

    pub async fn configure_connection_lifecycle(
        &self,
        config: Config,
        local_node_id: String,
        plugin_manager: &Arc<PluginManager>,
        peer_store: PeerStore,
        allow_console: bool,
    ) {
        let runtime = ConnectionLifecycleRuntime {
            policy: ConnectionPolicy::from_network_config(&config),
            config,
            local_node_id,
            peer_store,
            plugin_manager: Arc::downgrade(plugin_manager),
            allow_console,
        };
        *self.lifecycle_runtime.lock().await = Some(runtime);

        let peers: Vec<(String, SocketAddr)> = self
            .node_ids
            .lock()
            .await
            .iter()
            .map(|(node_id, addr)| (node_id.clone(), *addr))
            .collect();
        for (node_id, addr) in peers {
            self.start_liveness_monitor(node_id, Some(addr)).await;
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
        sender: Sender<Message>,
        node_id: String,
    ) -> Result<(), String> {
        // Prevent duplicate node IDs
        {
            let ids = self.node_ids.lock().await;
            if ids.contains_key(&node_id) {
                return Err(format!("duplicate node id {} already connected", node_id));
            }
        }
        self.peers.lock().await.insert(addr, sender.clone());
        self.node_ids.lock().await.insert(node_id.clone(), addr);
        self.mark_route_success(&node_id, RouteKind::Tcp).await;
        self.last_peer_activity
            .lock()
            .await
            .insert(node_id.clone(), tokio::time::Instant::now());
        if let Some(runtime) = self.lifecycle_runtime.lock().await.clone() {
            runtime.peer_store.reset_reconnect(&addr).await;
        }
        self.deliver_queued_frames(&node_id, addr, sender).await;
        self.start_liveness_monitor(node_id, Some(addr)).await;
        Ok(())
    }

    /// Hand the store-and-forward frames queued for `node_id` to its new
    /// connection at `addr`, oldest first. A frame leaves the queue only once
    /// the connection's channel has room for it: what fits now goes ahead of
    /// later messages, and a task sends the rest as the connection drains. The
    /// task stops when the connection is no longer the node's, leaving the
    /// remaining frames queued for its next connection. Expired frames are
    /// dropped.
    async fn deliver_queued_frames(
        &self,
        node_id: &str,
        addr: SocketAddr,
        sender: Sender<Message>,
    ) {
        while let Ok(permit) = sender.try_reserve() {
            match self.next_queued_frame(node_id).await {
                Some(message) => permit.send(message),
                None => return,
            }
        }
        if !self.has_queued_frames(node_id).await {
            return;
        }
        let peer_manager = self.clone();
        let node_id = node_id.to_string();
        tokio::spawn(async move {
            while let Ok(permit) = sender.reserve().await {
                let current = peer_manager
                    .peers
                    .lock()
                    .await
                    .get(&addr)
                    .is_some_and(|registered| registered.same_channel(&sender));
                if !current {
                    return;
                }
                match peer_manager.next_queued_frame(&node_id).await {
                    Some(message) => permit.send(message),
                    None => return,
                }
            }
        });
    }

    /// Remove and return the oldest unexpired frame queued for `node_id`.
    async fn next_queued_frame(&self, node_id: &str) -> Option<Message> {
        let mut queue = self.relay_queue.lock().await;
        let frames = queue.get_mut(node_id)?;
        let now = current_unix_ts();
        let mut next = None;
        while next.is_none() && !frames.is_empty() {
            // Frames are queued serialized, which is what the byte caps measure.
            let (frame, expires_at, _origin) = frames.remove(0);
            if expires_at.is_none_or(|expires_at| expires_at > now) {
                next = Message::from_json(&frame);
            }
        }
        if frames.is_empty() {
            queue.remove(node_id);
        }
        next
    }

    async fn has_queued_frames(&self, node_id: &str) -> bool {
        self.relay_queue
            .lock()
            .await
            .get(node_id)
            .is_some_and(|frames| !frames.is_empty())
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
        let removed = self.peers.lock().await.remove(addr).is_some();
        self.tcp_bound_fingerprints.lock().await.remove(addr);
        if removed {
            let mut ids = self.node_ids.lock().await;
            let remove_key: Option<String> =
                ids.iter()
                    .find_map(|(k, v)| if v == addr { Some(k.clone()) } else { None });
            if let Some(ref k) = remove_key {
                ids.remove(k);
            }
            drop(ids);
            if let Some(ref dup_node_id) = remove_key {
                self.forget_relay_client(dup_node_id).await;
                if self.udp_session_id_for(dup_node_id).await.is_some() {
                    self.transport_kind
                        .lock()
                        .await
                        .insert(dup_node_id.clone(), TransportKind::Udp);
                } else {
                    self.lifecycle_generations.lock().await.remove(dup_node_id);
                    self.transport_kind.lock().await.remove(dup_node_id);
                    self.last_peer_activity.lock().await.remove(dup_node_id);
                    self.forget_node_details(dup_node_id).await;
                }
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

    pub async fn handle_peer_disconnected(&self, addr: &SocketAddr) -> Option<String> {
        let node_id = self.remove_peer(addr).await?;
        self.mark_route_unresponsive(&node_id, RouteKind::Tcp).await;
        // Only a node this node dialled is redialled, at the address that
        // reached it; a peer that connected in reconnects itself.
        if let Some(reconnect_addr) = self.verified_listen_addr_for(&node_id).await {
            self.schedule_reconnect(node_id.clone(), reconnect_addr);
        }
        Some(node_id)
    }

    pub async fn route_health(&self, node_id: &str, kind: RouteKind) -> RouteHealth {
        let health = self.route_health.lock().await;
        let Some(record) = health.get(&(node_id.to_string(), kind)) else {
            return RouteHealth::Unknown;
        };
        if record.health == RouteHealth::Unresponsive {
            return RouteHealth::Unresponsive;
        }
        match (record.last_success, record.last_failure) {
            (None, None) => RouteHealth::Unknown,
            (Some(_), None) => RouteHealth::Healthy,
            (None, Some(_)) => RouteHealth::Suspect,
            (Some(success), Some(failure)) if success >= failure => RouteHealth::Healthy,
            (Some(_), Some(_)) => RouteHealth::Suspect,
        }
    }

    pub async fn mark_route_success(&self, node_id: &str, kind: RouteKind) {
        let mut health = self.route_health.lock().await;
        let record = health
            .entry((node_id.to_string(), kind))
            .or_insert_with(RouteHealthRecord::default);
        record.health = RouteHealth::Healthy;
        record.last_success = Some(Instant::now());
        Self::prune_stale_route_health(&mut health);
    }

    pub async fn mark_route_failure(&self, node_id: &str, kind: RouteKind) {
        let mut health = self.route_health.lock().await;
        let record = health
            .entry((node_id.to_string(), kind))
            .or_insert_with(RouteHealthRecord::default);
        // An ordinary delivery/heartbeat failure must not resurrect a route that the
        // liveness monitor already excluded; only `mark_route_success` may clear
        // `Unresponsive` (ADR-0007: "unresponsive candidates are excluded").
        if record.health != RouteHealth::Unresponsive {
            record.health = RouteHealth::Suspect;
        }
        record.last_failure = Some(Instant::now());
        Self::prune_stale_route_health(&mut health);
    }

    /// Bound `route_health` growth by evicting entries with no activity in over an hour.
    ///
    /// `node_id` is peer-supplied, so without this the map would grow without bound as
    /// short-lived or malicious peers churn through distinct ids (a resource-exhaustion
    /// risk). Kept separate from peer teardown so a route's last-known health (in
    /// particular `Unresponsive`) remains queryable for a while after a peer disconnects.
    fn prune_stale_route_health(health: &mut HashMap<(String, RouteKind), RouteHealthRecord>) {
        const RETENTION: std::time::Duration = std::time::Duration::from_secs(3600);
        health.retain(|_, record| {
            record
                .last_success
                .is_some_and(|t| t.elapsed() <= RETENTION)
                || record
                    .last_failure
                    .is_some_and(|t| t.elapsed() <= RETENTION)
        });
    }

    pub async fn mark_route_unresponsive(&self, node_id: &str, kind: RouteKind) {
        let mut health = self.route_health.lock().await;
        let record = health
            .entry((node_id.to_string(), kind))
            .or_insert_with(RouteHealthRecord::default);
        record.health = RouteHealth::Unresponsive;
        record.last_failure = Some(Instant::now());
    }

    pub async fn record_peer_activity(&self, node_id: &str, kind: RouteKind) {
        self.last_peer_activity
            .lock()
            .await
            .insert(node_id.to_string(), tokio::time::Instant::now());
        self.mark_route_success(node_id, kind).await;
    }

    pub async fn record_peer_activity_on_preferred_route(&self, node_id: &str) {
        let kind = match self.get_transport_kind(node_id).await {
            Some(TransportKind::Udp) => RouteKind::Udp,
            Some(TransportKind::Tcp) => RouteKind::Tcp,
            None if self.has_node_id(node_id).await => RouteKind::Tcp,
            None => return,
        };
        self.record_peer_activity(node_id, kind).await;
    }

    async fn start_liveness_monitor(&self, node_id: String, tcp_addr: Option<SocketAddr>) {
        let Some(runtime) = self.lifecycle_runtime.lock().await.clone() else {
            return;
        };
        let generation = self
            .next_lifecycle_generation
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut generations = self.lifecycle_generations.lock().await;
            if generations.contains_key(&node_id) {
                return;
            }
            generations.insert(node_id.clone(), generation);
        }

        let peer_manager = self.clone();
        tokio::spawn(async move {
            // A peer is unresponsive once it has been silent for the heartbeat
            // timeout *and* has left the probes sent in that time unanswered.
            // Silence alone is not enough: a node that was itself stalled (load,
            // suspend) has not read what its peers sent meanwhile, so it probes
            // before it gives up on anyone.
            let probes_before_timeout = u32::try_from(
                runtime
                    .policy
                    .heartbeat_timeout
                    .as_millis()
                    .div_ceil(runtime.policy.heartbeat_interval.as_millis().max(1))
                    .max(1),
            )
            .unwrap_or(u32::MAX);
            let mut last_probe: Option<tokio::time::Instant> = None;
            let mut unanswered_probes = 0u32;
            let mut ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + runtime.policy.heartbeat_interval,
                runtime.policy.heartbeat_interval,
            );
            // After a stall, tick once rather than in a burst that would count
            // probes the peer had no chance to answer.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let is_current = peer_manager
                    .lifecycle_generations
                    .lock()
                    .await
                    .get(&node_id)
                    .is_some_and(|current| *current == generation);
                if !is_current {
                    break;
                }

                let last_activity = peer_manager
                    .last_peer_activity
                    .lock()
                    .await
                    .get(&node_id)
                    .copied();
                if let Some(probe) = last_probe {
                    if last_activity.is_some_and(|seen| seen >= probe) {
                        unanswered_probes = 0;
                    } else {
                        unanswered_probes = unanswered_probes.saturating_add(1);
                    }
                }
                let silent = last_activity
                    .is_none_or(|seen| seen.elapsed() >= runtime.policy.heartbeat_timeout);
                if silent && unanswered_probes >= probes_before_timeout {
                    peer_manager
                        .mark_peer_unresponsive(&node_id, tcp_addr)
                        .await;
                    break;
                }

                let heartbeat = Message::outbound(
                    MessageType::Heartbeat,
                    Some(Payload::Text("liveness_probe_v1".to_string())),
                    runtime.config.realm.clone(),
                );
                let (kind, result) = if peer_manager.has_node_id(&node_id).await {
                    (
                        RouteKind::Tcp,
                        peer_manager.send_to_node_id(&node_id, heartbeat).await,
                    )
                } else if peer_manager.udp_session_id_for(&node_id).await.is_some() {
                    (
                        RouteKind::Udp,
                        peer_manager
                            .send_udp_message_to_node(&node_id, heartbeat)
                            .await,
                    )
                } else {
                    peer_manager
                        .mark_peer_unresponsive(&node_id, tcp_addr)
                        .await;
                    break;
                };
                last_probe = Some(tokio::time::Instant::now());
                if result.is_err() {
                    peer_manager.mark_route_failure(&node_id, kind).await;
                }
            }

            let mut generations = peer_manager.lifecycle_generations.lock().await;
            if generations
                .get(&node_id)
                .is_some_and(|current| *current == generation)
            {
                generations.remove(&node_id);
            }
        });
    }

    async fn mark_peer_unresponsive(&self, node_id: &str, tcp_addr: Option<SocketAddr>) {
        self.mark_route_unresponsive(node_id, RouteKind::Tcp).await;
        if self.udp_session_id_for(node_id).await.is_some() {
            self.mark_route_unresponsive(node_id, RouteKind::Udp).await;
        }
        self.udp_session_ids.lock().await.remove(node_id);
        self.udp_bound_fingerprints.lock().await.remove(node_id);
        self.transport_kind.lock().await.remove(node_id);
        let active_tcp_addr = self.node_ids.lock().await.get(node_id).copied();
        if let Some(addr) = active_tcp_addr {
            self.remove_peer(&addr).await;
        } else {
            self.lifecycle_generations.lock().await.remove(node_id);
            self.last_peer_activity.lock().await.remove(node_id);
            self.forget_node_details(node_id).await;
        }

        emit_network_event(
            "peer_manager",
            LogLevel::Warn,
            "peer_unresponsive",
            tcp_addr.map(|addr| addr.to_string()),
            Some(format!("node_id={node_id}")),
            self.lifecycle_runtime
                .lock()
                .await
                .as_ref()
                .is_some_and(|runtime| runtime.allow_console),
        );

        if let Some(addr) = self.verified_listen_addr_for(node_id).await {
            self.schedule_reconnect(node_id.to_string(), addr);
        }
    }

    fn schedule_reconnect(&self, node_id: String, addr: SocketAddr) {
        let peer_manager = self.clone();
        tokio::spawn(async move {
            let Some(runtime) = peer_manager.lifecycle_runtime.lock().await.clone() else {
                return;
            };
            {
                let mut reconnecting = peer_manager.reconnecting_peers.lock().await;
                if !reconnecting.insert(node_id.clone()) {
                    return;
                }
            }
            runtime.peer_store.insert(addr, PeerSource::Handshake).await;

            loop {
                if peer_manager.has_node_id(&node_id).await {
                    break;
                }
                let Some(attempt) = runtime
                    .peer_store
                    .next_reconnect_attempt(&addr, runtime.policy.reconnect_max_attempts)
                    .await
                else {
                    emit_network_event(
                        "peer_manager",
                        LogLevel::Warn,
                        "reconnect_exhausted",
                        Some(addr.to_string()),
                        Some(format!("node_id={node_id}")),
                        runtime.allow_console,
                    );
                    break;
                };

                tokio::time::sleep(runtime.policy.reconnect_delay_with_random_jitter(attempt))
                    .await;
                if peer_manager.has_node_id(&node_id).await {
                    break;
                }
                let Some(plugin_manager) = runtime.plugin_manager.upgrade() else {
                    break;
                };
                let peer = Peer::new(format!("reconnect-{node_id}"), addr.to_string());
                let result = crate::network::transport::connect_to_peer(
                    crate::network::transport::ConnectToPeerParams {
                        peer: &peer,
                        our_realm: runtime
                            .config
                            .realm
                            .clone()
                            .unwrap_or_else(RealmInfo::default),
                        our_port: runtime.config.port,
                        peer_manager: peer_manager.clone(),
                        plugin_manager,
                        allow_console: runtime.allow_console,
                        config: runtime.config.clone(),
                        local_node_id: runtime.local_node_id.clone(),
                        peer_store: Some(runtime.peer_store.clone()),
                    },
                )
                .await;

                if result.is_err() || !peer_manager.has_node_id(&node_id).await {
                    runtime.peer_store.mark_failure(&addr).await;
                    peer_manager
                        .mark_route_failure(&node_id, RouteKind::Tcp)
                        .await;
                    continue;
                }
                break;
            }
            peer_manager
                .reconnecting_peers
                .lock()
                .await
                .remove(&node_id);
        });
    }

    /// Queue `message` for every connected peer without waiting: a peer whose
    /// outbound queue is full misses this message instead of stalling the
    /// caller, and the `peers` lock is released before anything is sent.
    pub async fn broadcast(&self, message: &Message) {
        let senders: Vec<(SocketAddr, Sender<Message>)> = self
            .peers
            .lock()
            .await
            .iter()
            .map(|(addr, sender)| (*addr, sender.clone()))
            .collect();
        for (addr, sender) in senders {
            if let Err(e) = sender.try_send(message.clone()) {
                emit_network_event(
                    "peer_manager",
                    LogLevel::Warn,
                    "broadcast_send_failed",
                    Some(addr.to_string()),
                    Some(e.to_string()),
                    false,
                );
            }
        }
    }

    /// Get a cloned sender for a connected peer by its socket address
    pub async fn get_sender_by_addr(&self, addr: &SocketAddr) -> Option<Sender<Message>> {
        self.peers.lock().await.get(addr).cloned()
    }

    /// Get a cloned sender for a connected peer by its node id
    pub async fn get_sender_by_node_id(&self, node_id: &str) -> Option<Sender<Message>> {
        let addr_opt = { self.node_ids.lock().await.get(node_id).cloned() };
        if let Some(addr) = addr_opt {
            return self.peers.lock().await.get(&addr).cloned();
        }
        None
    }

    /// Queue `message` for the peer connected at `addr`. The connection sets
    /// `from` and `to` when it writes the frame.
    pub async fn send_to_addr(&self, addr: &SocketAddr, message: Message) -> Result<(), String> {
        if let Some(sender) = self.get_sender_by_addr(addr).await {
            sender
                .try_send(message)
                .map_err(|e| format!("send_to_addr failed: {}", e))
        } else {
            Err("peer sender not found".to_string())
        }
    }

    /// Queue `message` for the connected peer `node_id`. The connection sets
    /// `from` and `to` when it writes the frame.
    pub async fn send_to_node_id(&self, node_id: &str, message: Message) -> Result<(), String> {
        if let Some(sender) = self.get_sender_by_node_id(node_id).await {
            sender
                .try_send(message)
                .map_err(|e| format!("send_to_node_id failed: {}", e))
        } else {
            Err("peer sender not found".to_string())
        }
    }

    /// Record the listen address a peer announced in its HELLO. It is only a
    /// claim: [`tcp_listen_addr_for`](Self::tcp_listen_addr_for) may try it as
    /// a delivery route, but it never suppresses a dial, drives a reconnect,
    /// or reaches the peer store.
    pub async fn add_listen_addr(&self, listen_addr: &str, node_id: &str) {
        self.claimed_listen_addrs
            .lock()
            .await
            .insert(node_id.to_string(), listen_addr.to_string());
    }

    /// Record that dialling `addr` reached `node_id`.
    pub async fn set_verified_listen_addr(&self, node_id: &str, addr: SocketAddr) {
        let mut verified = self.verified_listen_addrs.lock().await;
        // Only dials this node made add entries, but keep the map bounded anyway.
        if verified.len() < Self::MAX_VERIFIED_LISTEN_ADDRS || verified.contains_key(node_id) {
            verified.insert(node_id.to_string(), addr.to_string());
        }
    }

    /// Whether a connected peer was reached by dialling `listen_addr`, so
    /// dialling it again would only duplicate that connection.
    pub async fn has_listen_addr(&self, listen_addr: &str) -> bool {
        let reached: Vec<String> = self
            .verified_listen_addrs
            .lock()
            .await
            .iter()
            .filter(|(_, addr)| *addr == listen_addr)
            .map(|(node_id, _)| node_id.clone())
            .collect();
        let connected = self.node_ids.lock().await;
        reached
            .iter()
            .any(|node_id| connected.contains_key(node_id))
    }

    /// The address this node reached `node_id` at by dialling it, if any.
    pub async fn verified_listen_addr_for(&self, node_id: &str) -> Option<SocketAddr> {
        self.verified_listen_addrs
            .lock()
            .await
            .get(node_id)
            .and_then(|addr| addr.parse().ok())
    }

    /// A TCP address to try when delivering to `node_id` while it is not
    /// connected: the verified address, or else the one it announced.
    pub async fn tcp_listen_addr_for(&self, node_id: &str) -> Option<String> {
        if let Some(addr) = self.verified_listen_addrs.lock().await.get(node_id) {
            return Some(addr.clone());
        }
        self.claimed_listen_addrs.lock().await.get(node_id).cloned()
    }

    /// Drop what a node announced about itself in HELLO once it has neither
    /// a TCP connection nor a UDP session.
    async fn forget_node_details(&self, node_id: &str) {
        self.claimed_listen_addrs.lock().await.remove(node_id);
        self.capabilities_by_node.lock().await.remove(node_id);
        self.udp_listen_addrs.lock().await.remove(node_id);
        self.udp_observed_addrs.lock().await.remove(node_id);
    }

    /// Tear down the relay state a client created over its TCP connection:
    /// its bindings, their IDs, sequences and in-flight forwards (ADR-0003).
    /// Frames already queued for store-and-forward stay queued.
    async fn forget_relay_client(&self, node_id: &str) {
        self.relay_bindings
            .lock()
            .await
            .retain(|(from, _), _| from != node_id);
        self.relay_binding_ids
            .lock()
            .await
            .retain(|_, (from, _)| from != node_id);
        self.relay_last_sequence
            .lock()
            .await
            .retain(|(from, _), _| from != node_id);
        self.reliable_inflight
            .lock()
            .await
            .retain(|(from, _, _)| from != node_id);
    }

    /// Number of relay bindings `node_id` has created on this node.
    pub async fn binding_count_from(&self, node_id: &str) -> usize {
        self.relay_bindings
            .lock()
            .await
            .keys()
            .filter(|(from, _)| from == node_id)
            .count()
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
        destination: &str,
        expires_at: std::time::Instant,
    ) {
        self.delivery_attempts.lock().await.insert(
            message_id.as_str().to_string(),
            DeliveryAttemptState {
                class,
                destination: destination.to_string(),
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

    /// Record a `DELIVERY_ACK` from `acked_by`. Only the message's destination
    /// can acknowledge it; an acknowledgement for a message this node is not
    /// delivering (already settled, or never sent) changes nothing.
    pub async fn acknowledge_delivery(
        &self,
        message_id: &MessageId,
        acked_by: &str,
    ) -> Result<(), &'static str> {
        let mut attempts = self.delivery_attempts.lock().await;
        let state = attempts
            .get_mut(message_id.as_str())
            .ok_or("unknown-message")?;
        if state.destination != acked_by {
            return Err("not-destination");
        }
        state.outcome = Some(DeliveryOutcome::AcknowledgedByPeer);
        Ok(())
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
        self.delivery_dedup
            .lock()
            .await
            .prune(max_age, Instant::now());
    }

    /// Whether `message_id` from `origin_node_id` was already delivered.
    pub async fn delivery_seen(&self, origin_node_id: &str, message_id: &MessageId) -> bool {
        self.delivery_dedup
            .lock()
            .await
            .contains(origin_node_id, message_id.as_str())
    }

    /// Record a delivered message; returns `false` if it was already recorded.
    pub async fn record_delivery_receipt(
        &self,
        origin_node_id: &str,
        message_id: &MessageId,
    ) -> bool {
        self.delivery_dedup
            .lock()
            .await
            .record(origin_node_id, message_id.as_str(), Instant::now())
    }

    pub async fn next_ordering_sequence(&self, from: &str, to: &str, ordering_key: &str) -> u64 {
        let key = (from.to_string(), to.to_string(), ordering_key.to_string());
        let mut sequences = self.delivery_next_ordering_sequence.lock().await;
        let next = sequences.get(&key).copied().unwrap_or(1);
        sequences.insert(key, next.saturating_add(1));
        next
    }

    /// Buffer or release an ordered-reliable message. Returns the messages now
    /// deliverable in order, or a reason when the message cannot be held: its
    /// origin has too many ordering scopes or buffered bytes. A refused message
    /// is not acknowledged, so its sender retries it.
    pub async fn accept_ordered_incoming(
        &self,
        origin_node_id: &str,
        destination_node_id: &str,
        ordering_key: &str,
        ordering_sequence: u64,
        message: Message,
        max_buffered_messages: usize,
    ) -> Result<Vec<Message>, &'static str> {
        let key = (
            origin_node_id.to_string(),
            destination_node_id.to_string(),
            ordering_key.to_string(),
        );

        let mut inbound = self.delivery_ordered_inbound.lock().await;
        let OrderedInbound {
            scopes,
            usage,
            pending_bytes,
        } = &mut *inbound;
        let origin_usage = usage.entry(origin_node_id.to_string()).or_default();
        if !scopes.contains_key(&key) {
            if origin_usage.scopes >= OrderedInbound::MAX_SCOPES_PER_ORIGIN
                || scopes.len() >= OrderedInbound::MAX_SCOPES
            {
                return Err("ordered-scopes-full");
            }
            origin_usage.scopes += 1;
        }
        let bucket = scopes.entry(key).or_insert_with(|| OrderedDeliveryBuffer {
            next_expected: 1,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            last_activity: std::time::Instant::now(),
        });

        if ordering_sequence < bucket.next_expected {
            return Ok(Vec::new());
        }

        if ordering_sequence > bucket.next_expected {
            if bucket.pending.contains_key(&ordering_sequence) {
                return Ok(Vec::new());
            }
            let size = message.as_json().len();
            if bucket.pending.len() >= max_buffered_messages
                || origin_usage.pending_bytes + size > OrderedInbound::MAX_PENDING_BYTES_PER_ORIGIN
                || *pending_bytes + size > OrderedInbound::MAX_PENDING_BYTES
            {
                return Err("ordered-buffer-full");
            }
            bucket.pending.insert(ordering_sequence, (message, size));
            bucket.pending_bytes += size;
            origin_usage.pending_bytes += size;
            *pending_bytes += size;
            bucket.last_activity = std::time::Instant::now();
            return Ok(Vec::new());
        }

        bucket.last_activity = std::time::Instant::now();
        let mut ready = vec![message];
        bucket.next_expected = bucket.next_expected.saturating_add(1);
        while let Some((next_message, size)) = bucket.pending.remove(&bucket.next_expected) {
            ready.push(next_message);
            bucket.pending_bytes -= size;
            origin_usage.pending_bytes -= size;
            *pending_bytes -= size;
            bucket.next_expected = bucket.next_expected.saturating_add(1);
        }

        Ok(ready)
    }

    /// Evict ordered-delivery scopes that have not seen any activity within `max_age`.
    /// This prevents stale scopes (where the gap message never arrived) from accumulating
    /// in memory indefinitely.
    pub async fn prune_ordered_inbound(&self, max_age: std::time::Duration) {
        let mut inbound = self.delivery_ordered_inbound.lock().await;
        let OrderedInbound {
            scopes,
            usage,
            pending_bytes,
        } = &mut *inbound;
        let now = std::time::Instant::now();
        scopes.retain(|(origin, _, _), bucket| {
            if now.duration_since(bucket.last_activity) <= max_age {
                return true;
            }
            if let Some(origin_usage) = usage.get_mut(origin) {
                origin_usage.scopes -= 1;
                origin_usage.pending_bytes -= bucket.pending_bytes;
            }
            *pending_bytes -= bucket.pending_bytes;
            false
        });
        usage.retain(|_, origin_usage| origin_usage.scopes > 0);
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

    /// Remove the binding `binding_id` if `owner` created it, returning its
    /// `(from, to)` pair.
    pub async fn remove_binding_by_id(
        &self,
        binding_id: &str,
        owner: &str,
    ) -> Option<(String, String)> {
        let mut ids = self.relay_binding_ids.lock().await;
        if ids.get(binding_id).is_none_or(|(from, _)| from != owner) {
            return None;
        }
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
        for (from, to) in bindings.keys() {
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
        let max_queue_bytes = self.relay_queue_max_bytes();
        // A frame larger than the whole byte budget can never be buffered.
        if message_json.len() > max_queue_bytes {
            return false;
        }
        // Accumulate notifications to send after releasing queue lock to avoid await while locked
        let mut to_notify: Vec<(String, crate::network::message::Reason)> = Vec::new();
        // If the incoming frame is already expired, notify origin immediately and drop.
        if let Some(exp) = expires_at {
            if exp <= current_unix_ts() {
                if let Some(o) = origin_from.as_ref() {
                    if self.has_node_id(o).await {
                        let notify = Message::outbound(
                            MessageType::RelayNotify {
                                notif_type: crate::network::message::Reason::Timeout,
                                binding_id: None,
                                detail: Some(format!("target={}", to_node_id)),
                            },
                            None,
                            None,
                        );
                        let _ = self.send_to_node_id(o, notify).await;
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

        // Enforce global caps (frame count and bytes) by dropping oldest across targets (simple round-robin)
        let mut total_len: usize = q.values().map(|v| v.len()).sum();
        let mut total_bytes: usize = q
            .values()
            .flat_map(|v| v.iter())
            .map(|(frame, _, _)| frame.len())
            .sum();
        if total_len > max_queue_global || total_bytes > max_queue_bytes {
            let mut keys: Vec<String> = q.keys().cloned().collect();
            keys.sort();
            let mut idx = 0usize;
            while (total_len > max_queue_global || total_bytes > max_queue_bytes)
                && !keys.is_empty()
            {
                let k = &keys[idx % keys.len()];
                if let Some(vec) = q.get_mut(k) {
                    if !vec.is_empty() {
                        let removed = vec.remove(0);
                        if let Some(o) = removed.2.as_ref() {
                            to_notify.push((o.clone(), crate::network::message::Reason::Overload));
                        }
                        total_len -= 1;
                        total_bytes = total_bytes.saturating_sub(removed.0.len());
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
                let notify = Message::outbound(
                    MessageType::RelayNotify {
                        notif_type: reason,
                        binding_id: None,
                        detail: Some(format!("target={}", to_node_id)),
                    },
                    None,
                    None,
                );
                let _ = self.send_to_node_id(&o, notify).await;
            }
        }
        true
    }

    pub async fn can_enqueue_store_forward(&self, to_node_id: &str) -> bool {
        let (max_queue_per_target, max_queue_global) = self.relay_queue_caps();
        let max_queue_bytes = self.relay_queue_max_bytes();
        let q = self.relay_queue.lock().await;
        let per_target_ok = q
            .get(to_node_id)
            .map(|v| v.len() < max_queue_per_target)
            .unwrap_or(true);
        let total_len: usize = q.values().map(|v| v.len()).sum();
        let total_bytes: usize = q
            .values()
            .flat_map(|v| v.iter())
            .map(|(frame, _, _)| frame.len())
            .sum();
        let global_ok = total_len < max_queue_global && total_bytes < max_queue_bytes;
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

    /// Record the UDP listen and observed addresses a peer announced in HELLO
    /// on a connection from `connection_addr`. The node sends observation
    /// requests, handshakes and punch probes to them, and they are claims, so
    /// each must be an address no more local than the connection, as gossip
    /// requires. Returns the addresses that were dropped.
    pub async fn record_hello_udp_addrs(
        &self,
        node_id: &str,
        connection_addr: SocketAddr,
        listen_addr: Option<&str>,
        observed_addr: Option<&str>,
    ) -> Vec<String> {
        let in_scope = |addr: &str| {
            addr.parse::<SocketAddr>().is_ok_and(|addr| {
                crate::network::peer_store::gossip_addr_allowed(addr, connection_addr)
            })
        };
        let mut dropped = Vec::new();
        if let Some(addr) = listen_addr {
            if in_scope(addr) {
                self.add_udp_listen_addr(node_id, addr).await;
            } else {
                dropped.push(addr.to_string());
            }
        }
        if let Some(addr) = observed_addr {
            if in_scope(addr) {
                self.add_udp_observed_addr(node_id, addr, None, None).await;
            } else {
                dropped.push(addr.to_string());
            }
        }
        dropped
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
        self.record_peer_activity(node_id, RouteKind::Udp).await;
        self.start_liveness_monitor(node_id.to_string(), None).await;
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

    /// Send `message` over the UDP session with `node_id`, stamped with this
    /// node as `from` and `node_id` as `to`.
    #[cfg(feature = "noise")]
    pub async fn send_udp_message_to_node(
        &self,
        node_id: &str,
        message: Message,
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
        let frame = message.into_frame(&handle.local_node_id, node_id);

        crate::network::udp_listener::send_udp(
            &session_id,
            frame.as_bytes(),
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
        _message: Message,
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
        let record = ObservedUdpAddrRecord {
            addr: addr.to_string(),
            observed_at: std::time::Instant::now(),
            observer_node_id: observer_node_id.map(str::to_string),
            request_nonce,
        };
        *self.own_observed_addr.lock().await = Some(record.clone());
        let sample_key = observer_node_id
            .map(str::to_string)
            .or_else(|| request_nonce.map(hex::encode))
            .unwrap_or_else(|| addr.to_string());
        // Samples older than the freshness window are never read again.
        let max_age = std::time::Duration::from_secs(self.nat_observation_refresh_secs().await);
        let mut samples = self.own_observed_addr_samples.lock().await;
        samples.retain(|_, sample| sample.observed_at.elapsed() < max_age);
        samples.insert(sample_key, record);
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

    /// Return all fresh local UDP observation samples.
    pub async fn own_udp_observed_records_if_fresh(
        &self,
        max_age_secs: u64,
    ) -> Vec<ObservedUdpAddrRecord> {
        self.own_observed_addr_samples
            .lock()
            .await
            .values()
            .filter(|record| record.observed_at.elapsed().as_secs() < max_age_secs)
            .cloned()
            .collect()
    }

    /// Return the configured NAT-observation freshness window in seconds.
    /// Whether this node may use `node_id` as a rendezvous for hole punching
    /// (`[network.nat_traversal] allowed_rendezvous`). Without NAT traversal
    /// state, set by `set_nat_state`, no rendezvous is used.
    pub async fn rendezvous_allowed(&self, node_id: &str) -> bool {
        #[cfg(feature = "noise")]
        {
            if let Some(state) = self.nat_state.read().await.as_ref() {
                return state.rendezvous_allowed(node_id);
            }
        }
        let _ = node_id;
        false
    }

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

    /// The node identity registry. The first caller's config creates it, so a
    /// host should call this once at startup with its final configuration.
    pub fn node_identity(&self, config: &Config) -> Arc<NodeIdentityRegistry> {
        self.node_identity
            .get_or_init(|| Arc::new(NodeIdentityRegistry::from_config(config)))
            .clone()
    }

    /// Record the transport fingerprint bound to the node registered on `addr`.
    pub async fn set_peer_bound_fingerprint(&self, addr: SocketAddr, fingerprint: Option<String>) {
        let mut bound = self.tcp_bound_fingerprints.lock().await;
        match fingerprint {
            Some(fingerprint) if self.peers.lock().await.contains_key(&addr) => {
                bound.insert(addr, fingerprint);
            }
            _ => {
                bound.remove(&addr);
            }
        }
    }

    /// Record the Noise fingerprint bound to `node_id` on its UDP session.
    pub async fn set_udp_bound_fingerprint(&self, node_id: &str, fingerprint: Option<String>) {
        let mut bound = self.udp_bound_fingerprints.lock().await;
        match fingerprint {
            Some(fingerprint) => bound.insert(node_id.to_string(), fingerprint),
            None => bound.remove(node_id),
        };
    }

    pub async fn udp_bound_fingerprint(&self, node_id: &str) -> Option<String> {
        self.udp_bound_fingerprints
            .lock()
            .await
            .get(node_id)
            .cloned()
    }

    /// The origin to attribute a frame received on `addr` to: the node
    /// registered on that connection and its bound fingerprint. `None` when no
    /// node is registered on `addr`.
    pub async fn origin_for_addr(&self, addr: &SocketAddr) -> Option<MessageOrigin> {
        let node_id = self.node_id_for_addr(addr).await?;
        let fingerprint = self.tcp_bound_fingerprints.lock().await.get(addr).cloned();
        Some(MessageOrigin::direct(node_id, fingerprint))
    }

    /// Record a punch this node coordinates as rendezvous. Returns `false`, and
    /// records nothing, when the attempt ID is empty, too long or already in
    /// use, or when the initiator or this node has too many punches in
    /// progress. A record lasts for the punch's time budget, at most
    /// [`MAX_PUNCH_TIMEOUT_MS`] (ADR-0015).
    pub async fn add_pending_punch(
        &self,
        attempt_id: &str,
        responder_node_id: &str,
        initiator_node_id: &str,
        timeout_ms: u64,
    ) -> bool {
        if !attempt_id_acceptable(attempt_id) {
            return false;
        }
        let mut pending = self.pending_punches.lock().await;
        let now = Instant::now();
        pending.retain(|_, punch| punch.expires_at > now);
        let by_initiator = pending
            .values()
            .filter(|punch| punch.initiator_node_id == initiator_node_id)
            .count();
        if pending.contains_key(attempt_id)
            || pending.len() >= Self::MAX_PENDING_PUNCHES
            || by_initiator >= Self::MAX_PENDING_PUNCHES_PER_INITIATOR
        {
            return false;
        }
        pending.insert(
            attempt_id.to_string(),
            PendingPunch {
                attempt_id: attempt_id.to_string(),
                initiator_node_id: initiator_node_id.to_string(),
                responder_node_id: responder_node_id.to_string(),
                timeout_ms,
                expires_at: punch_deadline(now, timeout_ms),
            },
        );
        true
    }

    /// Retrieve a pending punch record by attempt id, unless it expired.
    pub async fn get_pending_punch(&self, attempt_id: &str) -> Option<PendingPunch> {
        self.pending_punches
            .lock()
            .await
            .get(attempt_id)
            .filter(|punch| punch.expires_at > Instant::now())
            .cloned()
    }

    /// Remove and return the pending punch `attempt_id` if it is the one
    /// `initiator_node_id` asked to coordinate with `responder_node_id` and has
    /// not expired. A record for other nodes stays in place.
    pub async fn take_pending_punch(
        &self,
        attempt_id: &str,
        initiator_node_id: &str,
        responder_node_id: &str,
    ) -> Option<PendingPunch> {
        let mut pending = self.pending_punches.lock().await;
        let punch = pending.get(attempt_id)?;
        if punch.expires_at <= Instant::now() {
            pending.remove(attempt_id);
            return None;
        }
        if punch.initiator_node_id != initiator_node_id
            || punch.responder_node_id != responder_node_id
        {
            return None;
        }
        pending.remove(attempt_id)
    }

    /// Remove a pending punch record by attempt id.
    pub async fn remove_pending_punch(&self, attempt_id: &str) {
        self.pending_punches.lock().await.remove(attempt_id);
    }

    /// Agree to take part in punch `attempt_id`. Returns `false`, and agrees to
    /// nothing, when the attempt id is already in use or too many punches are
    /// in progress.
    pub async fn expect_punch(&self, attempt_id: &str, punch: ExpectedPunch) -> bool {
        if !attempt_id_acceptable(attempt_id) {
            return false;
        }
        let mut expected = self.expected_punches.lock().await;
        let now = Instant::now();
        expected.retain(|_, punch| punch.expires_at > now);
        if expected.len() >= Self::MAX_EXPECTED_PUNCHES || expected.contains_key(attempt_id) {
            return false;
        }
        expected.insert(attempt_id.to_string(), punch);
        true
    }

    /// Take the punch `attempt_id` if a `PUNCH_GO` from `rendezvous_node_id`
    /// for these two nodes matches what this node agreed to. A `PUNCH_GO` that
    /// does not match leaves the agreement in place.
    pub async fn take_expected_punch(
        &self,
        attempt_id: &str,
        rendezvous_node_id: &str,
        initiator_node_id: &str,
        responder_node_id: &str,
    ) -> Option<ExpectedPunch> {
        let mut expected = self.expected_punches.lock().await;
        let punch = expected.get(attempt_id)?;
        let matches = punch.rendezvous_node_id == rendezvous_node_id
            && punch.initiator_node_id == initiator_node_id
            && punch.responder_node_id == responder_node_id
            && punch.expires_at > Instant::now();
        if matches {
            expected.remove(attempt_id)
        } else {
            None
        }
    }

    /// Remember an `OBSERVE_REQ` sent to `observer_node_id`. Requests that
    /// got no answer within `PENDING_OBSERVATION_TTL` are dropped.
    pub async fn register_pending_observation(
        &self,
        observer_node_id: &str,
        expected_source: SocketAddr,
        nonce: [u8; 8],
    ) {
        let mut pending = self.pending_observations.lock().await;
        pending.retain(|_, observation| {
            observation.requested_at.elapsed() < Self::PENDING_OBSERVATION_TTL
        });
        pending.insert(
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
        self.pending_observations
            .lock()
            .await
            .get(nonce)
            .filter(|observation| {
                observation.requested_at.elapsed() < Self::PENDING_OBSERVATION_TTL
            })
            .cloned()
    }

    pub async fn remove_pending_observation(&self, nonce: &[u8; 8]) -> Option<PendingObservation> {
        self.pending_observations
            .lock()
            .await
            .remove(nonce)
            .filter(|observation| {
                observation.requested_at.elapsed() < Self::PENDING_OBSERVATION_TTL
            })
    }

    pub fn set_gateway_external_ip(&self, external_ip: Option<String>) {
        *self.gateway_external_ip.write() = external_ip;
    }

    pub fn gateway_external_ip(&self) -> Option<String> {
        self.gateway_external_ip.read().clone()
    }

    pub fn set_public_tcp_hello_addr(&self, addr: Option<String>) {
        *self.public_tcp_hello_addr.write() = addr;
    }

    pub fn public_tcp_hello_addr(&self) -> Option<String> {
        self.public_tcp_hello_addr.read().clone()
    }

    pub fn set_direct_tcp_hint(&self, enabled: bool) {
        self.direct_tcp_hint.store(enabled, Ordering::Relaxed);
    }

    pub fn direct_tcp_hint(&self) -> bool {
        self.direct_tcp_hint.load(Ordering::Relaxed)
    }

    pub fn replace_nat_diagnostic_summary(&self, summary: Option<String>) -> bool {
        let mut guard = self.nat_diagnostic_summary.write();
        if *guard == summary {
            false
        } else {
            *guard = summary;
            true
        }
    }

    /// Register the live UDP socket and Noise session map (called after `spawn_udp_listener`).
    #[cfg(feature = "noise")]
    pub async fn set_udp_handle(
        &self,
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        sessions: crate::network::udp_listener::UdpSessions,
        static_private: Vec<u8>,
        local_node_id: String,
    ) {
        *self.udp_handle.lock().await = Some(UdpHandle {
            socket,
            sessions,
            static_private,
            local_node_id,
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

    /// Execute a hole-punch window on receipt of `PunchGo` from the peer
    /// `rendezvous_node_id` at `rendezvous_addr`.  Spawns a background task.
    ///
    /// Only a `PunchGo` for a punch this node agreed to is followed, and only
    /// toward an address no more local than the rendezvous (ADR-0015).
    #[cfg(feature = "noise")]
    pub async fn handle_punch_go_msg(
        &self,
        local_node_id: &str,
        rendezvous_node_id: &str,
        rendezvous_addr: SocketAddr,
        punch: crate::network::nat_traversal::PunchGoParams,
    ) {
        let reject = |reason: &str| {
            crate::network::events::emit_network_event(
                "nat_traversal",
                LogLevel::Warn,
                "punch_go_rejected",
                Some(rendezvous_addr.to_string()),
                Some(format!(
                    "attempt_id={} rendezvous={} reason={}",
                    punch.attempt_id, rendezvous_node_id, reason
                )),
                false,
            );
        };
        let remote = if local_node_id == punch.initiator {
            &punch.responder_observed_addr
        } else if local_node_id == punch.responder {
            &punch.initiator_observed_addr
        } else {
            return reject("not-a-party");
        };
        let remote_allowed = remote.parse::<SocketAddr>().is_ok_and(|remote| {
            crate::network::peer_store::gossip_addr_allowed(remote, rendezvous_addr)
        });
        if !remote_allowed {
            return reject("address-out-of-scope");
        }
        let Some(expected) = self
            .take_expected_punch(
                &punch.attempt_id,
                rendezvous_node_id,
                &punch.initiator,
                &punch.responder,
            )
            .await
        else {
            return reject("not-expected");
        };
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
                    expected.expires_at,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn text(from: &str) -> Message {
        Message::new(from, "node-b", MessageType::Text("x".into()), None, None)
    }

    #[tokio::test]
    async fn dedup_evicts_only_the_flooding_origins_oldest_entries() {
        let pm = PeerManager::new();
        let id = |i: usize| MessageId::from(format!("id-{i}"));
        assert!(pm.record_delivery_receipt("other", &id(0)).await);
        for i in 0..=DeliveryDedup::MAX_PER_ORIGIN {
            assert!(pm.record_delivery_receipt("flooder", &id(i)).await);
        }
        assert!(!pm.delivery_seen("flooder", &id(0)).await);
        assert!(
            pm.delivery_seen("flooder", &id(DeliveryDedup::MAX_PER_ORIGIN))
                .await
        );
        assert!(pm.delivery_seen("other", &id(0)).await);
        assert!(!pm.record_delivery_receipt("other", &id(0)).await);
    }

    #[tokio::test]
    async fn ordered_buffers_are_bounded_per_origin() {
        let pm = PeerManager::new();
        let accept = |origin: &'static str, key: String, seq: u64, message: Message| {
            let pm = pm.clone();
            async move {
                pm.accept_ordered_incoming(origin, "node-b", &key, seq, message, 2)
                    .await
            }
        };
        // Out-of-order messages wait for the gap, up to the per-scope limit.
        for seq in [2, 3] {
            assert!(accept("node-a", "k".into(), seq, text("node-a"))
                .await
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            accept("node-a", "k".into(), 4, text("node-a"))
                .await
                .unwrap_err(),
            "ordered-buffer-full"
        );
        assert_eq!(
            accept("node-a", "k".into(), 1, text("node-a"))
                .await
                .unwrap()
                .len(),
            3
        );

        // Ordering scopes per origin are capped; other origins are unaffected.
        for i in 1..OrderedInbound::MAX_SCOPES_PER_ORIGIN {
            assert!(accept("node-a", format!("key-{i}"), 1, text("node-a"))
                .await
                .is_ok());
        }
        assert_eq!(
            accept("node-a", "one-too-many".into(), 1, text("node-a"))
                .await
                .unwrap_err(),
            "ordered-scopes-full"
        );
        assert!(accept("node-c", "k".into(), 1, text("node-c"))
            .await
            .is_ok());

        // Buffered bytes per origin are capped (4 MiB, so three 1 MiB messages).
        let big = || {
            Message::new(
                "node-d",
                "node-b",
                MessageType::Text("x".repeat(1024 * 1024)),
                None,
                None,
            )
        };
        let mut buffered = 0;
        let reason = loop {
            match accept("node-d", format!("big-{buffered}"), 2, big()).await {
                Ok(_) => buffered += 1,
                Err(reason) => break reason,
            }
        };
        assert_eq!(reason, "ordered-buffer-full");
        assert_eq!(buffered, 3);

        // Pruning idle scopes frees the origin's quota.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        pm.prune_ordered_inbound(std::time::Duration::ZERO).await;
        assert!(accept("node-a", "one-too-many".into(), 1, text("node-a"))
            .await
            .is_ok());
        assert!(accept("node-d", "after-prune".into(), 2, big())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn punch_go_is_followed_only_for_an_agreed_attempt() {
        let pm = PeerManager::new();
        let punch = |rendezvous: &str| ExpectedPunch {
            rendezvous_node_id: rendezvous.to_string(),
            initiator_node_id: "node-a".to_string(),
            responder_node_id: "node-c".to_string(),
            expires_at: Instant::now() + std::time::Duration::from_secs(5),
        };
        assert!(pm.expect_punch("p1", punch("node-b")).await);
        // A second invitation cannot take over the attempt id.
        assert!(!pm.expect_punch("p1", punch("node-x")).await);
        // A PUNCH_GO from another node, or for other nodes, is not followed
        // and does not cancel the agreement.
        assert!(pm
            .take_expected_punch("p1", "node-x", "node-a", "node-c")
            .await
            .is_none());
        assert!(pm
            .take_expected_punch("p1", "node-b", "node-a", "victim")
            .await
            .is_none());
        assert!(pm
            .take_expected_punch("p9", "node-b", "node-a", "node-c")
            .await
            .is_none());
        assert!(pm
            .take_expected_punch("p1", "node-b", "node-a", "node-c")
            .await
            .is_some());
        assert!(pm
            .take_expected_punch("p1", "node-b", "node-a", "node-c")
            .await
            .is_none());

        let mut expired = punch("node-b");
        expired.expires_at = Instant::now();
        assert!(pm.expect_punch("p2", expired).await);
        assert!(pm
            .take_expected_punch("p2", "node-b", "node-a", "node-c")
            .await
            .is_none());

        for i in 0..PeerManager::MAX_EXPECTED_PUNCHES {
            assert!(pm.expect_punch(&format!("n{i}"), punch("node-b")).await);
        }
        assert!(!pm.expect_punch("one-more", punch("node-b")).await);
        let long_id = "x".repeat(MAX_ATTEMPT_ID_LEN + 1);
        assert!(
            !PeerManager::new()
                .expect_punch(&long_id, punch("node-b"))
                .await
        );
    }

    /// Regression test: a peer could announce a loopback or LAN UDP
    /// address in HELLO and have the node send observation requests there.
    #[tokio::test]
    async fn hello_udp_addresses_must_be_no_more_local_than_the_connection() {
        let pm = PeerManager::new();
        let public: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let dropped = pm
            .record_hello_udp_addrs("node-a", public, Some("127.0.0.1:9"), Some("10.0.0.2:4000"))
            .await;
        assert_eq!(dropped, ["127.0.0.1:9", "10.0.0.2:4000"]);
        assert_eq!(pm.udp_listen_addr_for("node-a").await, None);
        assert_eq!(pm.udp_observed_addr_for("node-a").await, None);

        let dropped = pm
            .record_hello_udp_addrs("node-a", public, Some("not an address"), None)
            .await;
        assert_eq!(dropped, ["not an address"]);

        let dropped = pm
            .record_hello_udp_addrs(
                "node-a",
                public,
                Some("198.51.100.1:5001"),
                Some("203.0.113.7:4000"),
            )
            .await;
        assert!(dropped.is_empty());
        assert_eq!(
            pm.udp_listen_addr_for("node-a").await.as_deref(),
            Some("198.51.100.1:5001")
        );

        // Peers on one LAN, or one host, still share local addresses.
        let lan: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        assert!(pm
            .record_hello_udp_addrs("node-b", lan, Some("10.0.0.5:5001"), None)
            .await
            .is_empty());
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert!(pm
            .record_hello_udp_addrs("node-c", local, Some("127.0.0.1:5001"), None)
            .await
            .is_empty());
    }

    /// Regression test: a rendezvous kept every `PUNCH_COORDINATE`
    /// until it was answered, and a second one could take over an attempt ID.
    #[tokio::test]
    async fn a_rendezvous_keeps_few_punches_and_each_only_for_its_budget() {
        let pm = PeerManager::new();
        assert!(!pm.add_pending_punch("", "node-c", "node-a", 5000).await);
        let long_id = "x".repeat(MAX_ATTEMPT_ID_LEN + 1);
        assert!(
            !pm.add_pending_punch(&long_id, "node-c", "node-a", 5000)
                .await
        );

        assert!(pm.add_pending_punch("p1", "node-c", "node-a", 5000).await);
        assert!(!pm.add_pending_punch("p1", "node-d", "node-b", 5000).await);
        assert!(pm
            .take_pending_punch("p1", "node-b", "node-d")
            .await
            .is_none());
        assert!(pm
            .take_pending_punch("p1", "node-a", "node-c")
            .await
            .is_some());
        assert!(pm.get_pending_punch("p1").await.is_none());

        // A punch is forgotten when its budget runs out, at most 30 seconds.
        for i in 0..300 {
            assert!(
                pm.add_pending_punch(&format!("z{i}"), "node-c", "node-z", 0)
                    .await
            );
        }
        assert!(pm.pending_punches.lock().await.len() <= 1);
        assert!(
            pm.add_pending_punch("long", "node-c", "node-l", u64::MAX)
                .await
        );
        let expires_at = pm.get_pending_punch("long").await.unwrap().expires_at;
        assert!(
            expires_at <= Instant::now() + std::time::Duration::from_millis(MAX_PUNCH_TIMEOUT_MS)
        );

        // One initiator cannot occupy the rendezvous.
        for i in 0..PeerManager::MAX_PENDING_PUNCHES_PER_INITIATOR {
            assert!(
                pm.add_pending_punch(&format!("a{i}"), "node-c", "node-a", 5000)
                    .await
            );
        }
        assert!(
            !pm.add_pending_punch("a-more", "node-c", "node-a", 5000)
                .await
        );
        assert!(pm.add_pending_punch("b0", "node-c", "node-b", 5000).await);

        let initiators =
            PeerManager::MAX_PENDING_PUNCHES / PeerManager::MAX_PENDING_PUNCHES_PER_INITIATOR;
        for n in 0..initiators {
            for i in 0..PeerManager::MAX_PENDING_PUNCHES_PER_INITIATOR {
                pm.add_pending_punch(&format!("f{n}-{i}"), "node-c", &format!("flood-{n}"), 5000)
                    .await;
            }
        }
        assert_eq!(
            pm.pending_punches.lock().await.len(),
            PeerManager::MAX_PENDING_PUNCHES
        );
        assert!(
            !pm.add_pending_punch("full", "node-c", "node-new", 5000)
                .await
        );
    }

    /// A punch invitation is accepted only from a rendezvous this node may
    /// use (`[network.nat_traversal] allowed_rendezvous`), and from none
    /// without NAT traversal state.
    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn invitations_count_only_from_an_allowed_rendezvous() {
        use crate::network::nat_traversal::NatState;
        let pm = PeerManager::new();
        assert!(!pm.rendezvous_allowed("node-r").await);
        let mut nat = crate::config::NatTraversalConfig::default();
        pm.set_nat_state(Arc::new(NatState::from_config(&nat)))
            .await;
        assert!(pm.rendezvous_allowed("node-r").await);
        nat.allowed_rendezvous = Some(vec!["node-r".to_string()]);
        pm.set_nat_state(Arc::new(NatState::from_config(&nat)))
            .await;
        assert!(pm.rendezvous_allowed("node-r").await);
        assert!(!pm.rendezvous_allowed("node-x").await);
    }

    #[tokio::test]
    async fn unanswered_observation_requests_expire() {
        let pm = PeerManager::new();
        let observer: SocketAddr = "198.51.100.3:4000".parse().unwrap();
        pm.register_pending_observation("node-x", observer, [1; 8])
            .await;
        let stale = Instant::now()
            .checked_sub(PeerManager::PENDING_OBSERVATION_TTL)
            .unwrap();
        pm.pending_observations
            .lock()
            .await
            .get_mut(&[1; 8])
            .unwrap()
            .requested_at = stale;
        assert!(pm.pending_observation(&[1; 8]).await.is_none());
        pm.register_pending_observation("node-x", observer, [2; 8])
            .await;
        assert!(!pm.pending_observations.lock().await.contains_key(&[1; 8]));
        assert!(pm.pending_observation(&[2; 8]).await.is_some());
    }

    #[tokio::test]
    async fn only_dialled_addresses_suppress_dials_and_drive_reconnects() {
        let pm = PeerManager::new();
        let (tx, _inbound_rx) = tokio::sync::mpsc::channel(1);
        let inbound: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        pm.add_peer(inbound, tx, "node-b".into()).await.unwrap();
        // An inbound peer claims to listen on a bootstrap node's address.
        pm.add_listen_addr("198.51.100.7:50000", "node-b").await;
        pm.set_peer_capabilities("node-b", Some(vec!["relay".into()]))
            .await;
        assert!(!pm.has_listen_addr("198.51.100.7:50000").await);
        assert_eq!(pm.verified_listen_addr_for("node-b").await, None);
        assert_eq!(
            pm.tcp_listen_addr_for("node-b").await.as_deref(),
            Some("198.51.100.7:50000")
        );

        let (tx, _dialled_rx) = tokio::sync::mpsc::channel(1);
        let dialled: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        pm.add_peer(dialled, tx, "node-c".into()).await.unwrap();
        pm.set_verified_listen_addr("node-c", dialled).await;
        assert!(pm.has_listen_addr("127.0.0.1:40002").await);

        // Once a peer is gone its claims are forgotten. A dialled address stays
        // for reconnecting but no longer suppresses dials.
        pm.remove_peer(&inbound).await;
        pm.remove_peer(&dialled).await;
        assert_eq!(pm.tcp_listen_addr_for("node-b").await, None);
        assert!(!pm.peer_has_capability("node-b", "relay").await);
        assert_eq!(pm.verified_listen_addr_for("node-c").await, Some(dialled));
        assert!(!pm.has_listen_addr("127.0.0.1:40002").await);
    }

    async fn queue_texts(pm: &PeerManager, to: &str, count: usize) {
        for i in 0..count {
            let frame = Message::new(
                "node-a",
                to,
                MessageType::Text(format!("frame-{i}")),
                None,
                None,
            );
            assert!(
                pm.enqueue_store_forward(to, frame.as_json(), None, false, false, None)
                    .await
            );
        }
    }

    async fn next_text(rx: &mut tokio::sync::mpsc::Receiver<Message>) -> Option<String> {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("no frame arrived")?;
        match message.msg_type {
            MessageType::Text(text) => Some(text),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Regression test: frames queued for a node beyond the room in its
    /// connection's channel were dropped when it connected.
    #[tokio::test]
    async fn queued_frames_wait_for_room_in_the_connection() {
        let pm = PeerManager::new();
        queue_texts(&pm, "node-b", 40).await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        pm.add_peer("127.0.0.1:41002".parse().unwrap(), tx, "node-b".into())
            .await
            .unwrap();
        for i in 0..40 {
            assert_eq!(next_text(&mut rx).await, Some(format!("frame-{i}")));
        }
        assert!(pm.test_get_queue_for("node-b").await.is_empty());
    }

    /// Frames that did not fit stay queued, rather than going to a connection
    /// that is no longer the node's.
    #[tokio::test]
    async fn queued_frames_stay_queued_when_the_connection_closes() {
        let pm = PeerManager::new();
        queue_texts(&pm, "node-b", 10).await;
        let addr: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        pm.add_peer(addr, tx, "node-b".into()).await.unwrap();
        pm.remove_peer(&addr).await;
        assert_eq!(next_text(&mut rx).await.as_deref(), Some("frame-0"));
        assert_eq!(next_text(&mut rx).await.as_deref(), Some("frame-1"));
        // The channel closes once the delivering task has stopped.
        assert_eq!(next_text(&mut rx).await, None);
        let queued = pm.test_get_queue_for("node-b").await;
        assert_eq!(queued.len(), 8);
        assert!(queued[0].0.contains("frame-2"));
    }
}
