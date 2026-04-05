use crate::realms::RealmInfo;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DeliveryConfig {
    /// Default overall timeout for FireAndForget delivery attempts (ms).
    pub fire_and_forget_timeout_ms: Option<u64>,
    /// Default overall timeout for Reliable delivery attempts (ms).
    pub reliable_timeout_ms: Option<u64>,
    /// Default overall timeout for OrderedReliable delivery attempts (ms).
    pub ordered_reliable_timeout_ms: Option<u64>,
    /// Maximum number of retries for Reliable delivery attempts.
    pub reliable_retry_budget: Option<u32>,
    /// Maximum number of retries for OrderedReliable delivery attempts.
    pub ordered_reliable_retry_budget: Option<u32>,
    /// How long deduplication entries should be retained (seconds).
    pub dedup_window_secs: Option<u64>,
    /// Maximum number of pending ordered messages buffered per ordering scope.
    pub ordered_max_buffered_messages: Option<usize>,
    /// Delay between retry attempts for ACK-based delivery (ms).
    pub retry_interval_ms: Option<u64>,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            fire_and_forget_timeout_ms: Some(1000),
            reliable_timeout_ms: Some(5000),
            ordered_reliable_timeout_ms: Some(10000),
            reliable_retry_budget: Some(3),
            ordered_reliable_retry_budget: Some(3),
            dedup_window_secs: Some(3600),
            ordered_max_buffered_messages: Some(1024),
            retry_interval_ms: Some(500),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EncryptionPaths {
    pub own_certificate: Option<String>,
    pub own_private_key: Option<String>,
    pub trusted_cert_dir: Option<String>,
    pub trusted_crl_dir: Option<String>,
    pub rejected_dir: Option<String>,
    pub issuer_cert_dir: Option<String>,
    pub issuer_crl_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TrustPolicyPathsConfig {
    /// Directory where newly observed certificates (e.g. TOFU) are written
    pub observed_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EncryptionNoiseConfig {
    pub pattern: Option<String>,
    pub curve: Option<String>,
    pub cipher: Option<String>,
    pub hash: Option<String>,
    pub static_key_path: Option<String>,
}

// Default derived above

#[derive(Debug, Clone, Deserialize)]
pub struct TrustPolicyConfig {
    /// mode: open | allowlist | tofu | observe | hybrid (Phase 1)
    pub mode: Option<String>,
    /// migrated from EncryptionConfig.accept_self_signed (kept for non-CA modes)
    pub accept_self_signed: Option<bool>,
    /// store_new_certs: none | observed (trusted reserved for later phases)
    pub store_new_certs: Option<String>,
    /// Phase 2: reject certificates whose notAfter < now
    pub reject_expired: Option<bool>,
    /// Phase 2: reject certificates whose notBefore > now
    pub reject_before_valid: Option<bool>,
    /// Phase 2: require a valid issuer chain (ca / hybrid future)
    pub enforce_ca_chain: Option<bool>,
    /// Phase 3: list of allowed certificate subject strings (exact match on parsed full DN or substring if prefixed with '~')
    pub pin_subjects: Option<Vec<String>>,
    /// Phase 3: list of allowed SPKI fingerprints (hex lowercase)
    pub pin_fingerprints: Option<Vec<String>>,
    /// Phase 3: fingerprint hash algorithm (currently only sha256 supported)
    pub pin_fp_algo: Option<String>,
    /// Phase 3: require leaf subject to contain realm name (simple binding)
    pub realm_subject_binding: Option<bool>,
    pub paths: Option<TrustPolicyPathsConfig>,
}

impl Default for TrustPolicyConfig {
    fn default() -> Self {
        Self {
            mode: Some("open".to_string()),
            accept_self_signed: Some(false),
            store_new_certs: Some("none".to_string()),
            reject_expired: Some(false),
            reject_before_valid: Some(false),
            enforce_ca_chain: Some(false),
            pin_subjects: Some(vec![]),
            pin_fingerprints: Some(vec![]),
            pin_fp_algo: Some("sha256".to_string()),
            realm_subject_binding: Some(false),
            paths: Some(TrustPolicyPathsConfig::default()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    /// Optional secure channel backend selector: tls | noise | plaintext
    pub backend: Option<String>,
    /// Optional Noise backend settings (used when backend = "noise")
    pub noise: Option<EncryptionNoiseConfig>,
    /// Enable mutual TLS (client auth). Both sides must present certs.
    pub mtls: Option<bool>,
    /// DEPRECATED: use encryption.trust_policy.accept_self_signed
    pub accept_self_signed: Option<bool>,
    pub paths: Option<EncryptionPaths>,
    pub trust_policy: Option<TrustPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub port: u16,
    pub encryption: Option<EncryptionConfig>,
    pub bootstrap_nodes: Option<Vec<String>>,
    pub realm: Option<RealmInfo>,
    pub app_name: Option<String>,
    /// Logging / events configuration
    pub logging: Option<LoggingConfig>,
    /// Node identity / state directory configuration
    pub node: Option<NodeConfig>,
    /// Peer discovery configuration (optional)
    pub discovery: Option<DiscoveryConfig>,
    /// Optional realm access policy to constrain allowed remote node types
    pub realm_access: Option<RealmAccessConfig>,
    /// Network-scoped configuration (tables under [network.*])
    pub network: Option<NetworkConfig>,
}

/// Minimal set of default values that a plugin can supply for core runtime
/// parameters (only applied when the user has not explicitly set them).
#[derive(Debug, Clone, Default)]
pub struct ConfigDefaults {
    pub port: Option<u16>,
    pub realm: Option<RealmInfo>,
    pub app_name: Option<String>,
    pub encryption: Option<EncryptionConfig>,
    pub bootstrap_nodes: Option<Vec<String>>,
    /// Additional bootstrap nodes to append (deduped) if user already set some
    pub bootstrap_nodes_extend: Option<Vec<String>>,
    pub logging: Option<LoggingConfig>,
    pub node: Option<NodeConfig>,
    pub discovery: Option<DiscoveryConfig>,
}

impl ConfigDefaults {
    /// Apply values to a mutable config (used only when treating these as authoritative).
    pub fn apply(self, cfg: &mut Config) {
        if let Some(p) = self.port {
            cfg.port = p;
        }
        if let Some(r) = self.realm {
            cfg.realm = Some(r);
        }
        if let Some(a) = self.app_name {
            cfg.app_name = Some(a);
        }
        if let Some(e) = self.encryption {
            cfg.encryption = Some(e);
        }
        if let Some(b) = self.bootstrap_nodes {
            cfg.bootstrap_nodes = Some(b);
        }
        // bootstrap_nodes_extend intentionally not applied here; handled explicitly in main merge logic
        if let Some(l) = self.logging {
            cfg.logging = Some(l);
        }
        if let Some(n) = self.node {
            cfg.node = Some(n);
        }
        if let Some(d) = self.discovery {
            cfg.discovery = Some(d);
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Path to JSON line audit log (rotated). If unset, defaults to logs/trust_audit.jsonl
    pub json_path: Option<String>,
    /// Max size in bytes before rotation (default 5MB)
    pub json_max_bytes: Option<usize>,
    /// Number of rotated files to retain (default 3)
    pub json_rotate: Option<u32>,
    /// Disable console sink (default false)
    pub disable_console: Option<bool>,
}

// Default derived above

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: None,
            noise: None,
            mtls: Some(false),
            accept_self_signed: Some(false),
            paths: Some(EncryptionPaths::default()),
            trust_policy: Some(TrustPolicyConfig::default()),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 50000,
            encryption: Some(EncryptionConfig::default()),
            bootstrap_nodes: None,
            realm: Some(RealmInfo::default()),
            app_name: None,
            logging: None,
            node: Some(NodeConfig::default()),
            discovery: Some(DiscoveryConfig::default()),
            realm_access: None,
            network: Some(NetworkConfig {
                persistence: Some(NetworkPersistenceConfig::default()),
                relay: Some(RelayConfig::default()),
                udp: None,
                connection_policy: None,
                nat_traversal: None,
                delivery: Some(DeliveryConfig::default()),
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Explicit node ID (highest precedence if provided)
    pub id: Option<String>,
    /// Directory for persisted runtime state (node_id file etc.)
    pub state_dir: Option<String>,
    /// Filename inside state_dir that will store generated node id (default: node_id)
    pub id_file: Option<String>,
    /// Allow ephemeral (in-memory) UUID if no persistence possible
    pub allow_ephemeral: Option<bool>,
    /// Optional node type label advertised in HELLO (free-form, realm-defined, e.g., "daemon", "admin")
    pub node_type: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: None,
            state_dir: Some("data".to_string()),
            id_file: Some("node_id".to_string()),
            allow_ephemeral: Some(true),
            node_type: Some("daemon".to_string()),
        }
    }
}

impl NodeConfig {
    /// Resolve or generate a stable node id. Order:
    /// 1. Explicit id in config
    /// 2. Persisted file in state_dir/id_file
    /// 3. Generate UUID v4, persist (if possible)
    /// 4. Ephemeral UUID (if allowed)
    pub fn resolve_node_id(&self) -> String {
        // Helper to log warning without depending on events module (avoid cycle)
        fn warn(msg: &str) {
            eprintln!("⚠️ {}", msg);
        }

        // 1. Explicit
        if let Some(id) = &self.id {
            if Self::valid_id(id) {
                return id.clone();
            }
            warn("Invalid characters in configured node.id; falling back to persisted/generated");
        }

        // 2. File
        let state_dir = self.state_dir.clone().unwrap_or_else(|| "data".into());
        let id_file_name = self.id_file.clone().unwrap_or_else(|| "node_id".into());
        let path = std::path::Path::new(&state_dir).join(&id_file_name);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() && Self::valid_id(trimmed) {
                return trimmed.to_string();
            }
            warn("Persisted node_id file invalid or empty; regenerating");
        }

        // 3. Generate + persist
        let new_id = uuid::Uuid::new_v4().to_string();
        if std::fs::create_dir_all(&state_dir).is_ok() {
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, &new_id).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
                return new_id;
            }
        }

        // 4. Ephemeral
        if self.allow_ephemeral.unwrap_or(true) {
            warn("Using ephemeral node id (not persisted)");
            return new_id; // reuse generated UUID
        }
        // Last resort fallback string
        "unknown-node".to_string()
    }

    fn valid_id(id: &str) -> bool {
        id.len() <= 128
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable dynamic peer discovery (PeerRequest / PeerList gossip)
    pub enabled: bool,
    /// Interval seconds between automatic PeerRequest messages
    pub request_interval_secs: Option<u64>,
    /// How many peers to request each interval
    pub request_want: Option<u16>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            request_interval_secs: Some(90),
            request_want: Some(16),
        }
    }
}

/// Realm-scoped policy (optional) for peer type admission.
/// Developers may define their own node types for a given realm (e.g., "daemon", "admin", "worker").
/// If set, remote peers MUST advertise a node_type present in this allow-list; otherwise the connection is rejected.
#[derive(Debug, Clone, Deserialize)]
pub struct RealmAccessConfig {
    /// Allowed peer node types for the active realm. If None, all types are allowed.
    pub allowed_node_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPersistenceConfig {
    pub enabled: Option<bool>,
    pub path: Option<String>,
    pub max_entries: Option<usize>,
    pub ttl_secs: Option<u64>,
    pub save_interval_secs: Option<u64>,
}

impl Default for NetworkPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            // Use node.state_dir at runtime if path is None
            path: None,
            max_entries: Some(1024),
            ttl_secs: Some(7 * 24 * 3600),
            save_interval_secs: Some(60),
        }
    }
}

/// Connection preference policy (ADR-0005 Phase 1).
///
/// Controls which transport paths are tried and in what order when connecting
/// to a peer.  The default strategy is `"direct_then_relay"`.
///
/// ```toml
/// [network.connection_policy]
/// strategy = "direct_then_relay"
/// direct_tcp_timeout_ms = 3000
/// direct_udp_timeout_ms = 1000
/// punch_timeout_ms = 5000
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionPolicyConfig {
    /// Strategy string.
    ///
    /// | Value | Description |
    /// |---|---|
    /// | `direct_only` | TCP only; no UDP, no relay. |
    /// | `direct_then_relay` | TCP, fall back to relay. (**default**) |
    /// | `direct_then_udp_then_relay` | TCP → direct UDP → relay. |
    /// | `direct_then_punch_then_relay` | TCP → UDP → hole-punch → relay. (Phase 3) |
    /// | `relay_only` | Skip direct paths; use relay immediately. |
    pub strategy: Option<String>,
    /// Timeout for a direct TCP connect attempt (ms).
    pub direct_tcp_timeout_ms: Option<u64>,
    /// Timeout for a direct UDP session attempt (ms).
    pub direct_udp_timeout_ms: Option<u64>,
    /// Total time budget for relay-coordinated UDP hole punching (ms).  Phase 3.
    pub punch_timeout_ms: Option<u64>,
}

impl Default for ConnectionPolicyConfig {
    fn default() -> Self {
        Self {
            strategy: Some("direct_then_relay".to_string()),
            direct_tcp_timeout_ms: Some(3000),
            direct_udp_timeout_ms: Some(1000),
            punch_timeout_ms: Some(5000),
        }
    }
}

/// NAT traversal and hole-punching configuration (ADR-0005).
///
/// ```toml
/// [network.nat_traversal]
/// enabled = false
/// serve = false
/// refresh_secs = 300
/// cookie_ttl_secs = 30
/// probe_count = 6
/// probe_interval_ms = 100
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct NatTraversalConfig {
    /// Enable NAT traversal features (`"punch"` capability).
    pub enabled: Option<bool>,
    /// Allow this node to serve observation and punch-coordination to others.
    /// Requires `[network.relay].enabled = true` and `[network.udp].enabled = true`.
    pub serve: Option<bool>,
    /// How often to refresh the locally observed UDP address (seconds).
    pub refresh_secs: Option<u64>,
    /// Stateless cookie lifetime for the observation challenge/response (seconds).
    pub cookie_ttl_secs: Option<u64>,
    /// Number of KEEPALIVE probe datagrams sent during each punch attempt.
    pub probe_count: Option<u32>,
    /// Delay between successive probe datagrams (ms).
    pub probe_interval_ms: Option<u64>,
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            serve: Some(false),
            refresh_secs: Some(300),
            cookie_ttl_secs: Some(30),
            probe_count: Some(6),
            probe_interval_ms: Some(100),
        }
    }
}

/// UDP + Noise transport configuration (optional; opt-in, ADR-0004).
#[derive(Debug, Clone, Deserialize)]
pub struct UdpConfig {
    /// Enable the UDP Noise transport listener.  Default: false.
    pub enabled: Option<bool>,
    /// UDP port to bind.  Default: TCP port + 1.
    pub listen_port: Option<u16>,
    /// Maximum total datagram size enforced on send.  Must not exceed 1200.
    pub max_datagram_bytes: Option<usize>,
    /// Maximum application payload bytes.  Must not exceed 1176.
    pub max_app_payload_bytes: Option<usize>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            listen_port: None,
            max_datagram_bytes: Some(1200),
            max_app_payload_bytes: Some(1176),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    /// Persistent known peer store configuration (optional)
    pub persistence: Option<NetworkPersistenceConfig>,
    /// Relay configuration (optional; opt-in)
    pub relay: Option<RelayConfig>,
    /// UDP + Noise transport configuration (optional; opt-in, ADR-0004)
    pub udp: Option<UdpConfig>,
    /// Connection preference policy (ADR-0005 Phase 1)
    pub connection_policy: Option<ConnectionPolicyConfig>,
    /// NAT traversal and hole-punching configuration (ADR-0005)
    pub nat_traversal: Option<NatTraversalConfig>,
    /// Delivery semantics configuration (ADR-0006)
    pub delivery: Option<DeliveryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    /// Enable relay role on this node
    pub enabled: Option<bool>,
    /// Allow store-and-forward buffering when relaying
    pub store_forward: Option<bool>,
    /// Optional per-target queue cap (fallback to internal defaults if None)
    pub queue_max_per_target: Option<usize>,
    /// Optional global queue cap (fallback to internal defaults if None)
    pub queue_max_global: Option<usize>,
    /// Selection strategy to pick a relay when target is absent (none|rendezvous)
    pub selection: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            store_forward: Some(false),
            queue_max_per_target: Some(1024),
            queue_max_global: Some(8192),
            selection: Some("none".to_string()),
        }
    }
}

/// Policy for how to handle conflicts when a locked value differs from a
/// value provided via external configuration (e.g., file/env/cli).
#[derive(Copy, Clone, Debug)]
pub enum LockConflictPolicy {
    /// Fail fast with an error if the config attempts to override a locked value.
    Error,
    /// Log a warning (via eprintln! here; callers may emit events) and force the locked value.
    WarnAndOverride,
}

/// Hard overrides for configuration fields. These represent values the
/// application developer wants to bake into the binary. Use together with
/// `LockConflictPolicy` to control whether external config may differ.
///
/// For default-only behavior ("external config may override"), prefer
/// the existing `ConfigDefaults` mechanism which is applied before external
/// configuration.
#[derive(Clone, Debug, Default)]
pub struct ConfigLocks {
    pub port: Option<u16>,
    pub realm: Option<RealmInfo>,
    pub app_name: Option<String>,
    pub encryption_enabled: Option<bool>,
    pub node: Option<NodeLocks>,
}

#[derive(Clone, Debug, Default)]
pub struct NodeLocks {
    pub node_type: Option<String>,
}

impl ConfigLocks {
    /// Enforce locked values onto a mutable Config. If a value in cfg differs
    /// from the locked one, behavior is controlled by `policy`.
    pub fn enforce(&self, cfg: &mut Config, policy: LockConflictPolicy) -> anyhow::Result<()> {
        // Helper to handle conflict
        fn handle_conflict<T: std::fmt::Display + Clone + PartialEq>(
            field: &str,
            current: T,
            locked: T,
            policy: LockConflictPolicy,
            apply: impl FnOnce(T),
        ) -> anyhow::Result<()> {
            if current == locked {
                return Ok(());
            }
            match policy {
                LockConflictPolicy::Error => Err(anyhow::anyhow!(
                    "Config lock violation for '{}': config='{}' locked='{}'",
                    field,
                    current,
                    locked
                )),
                LockConflictPolicy::WarnAndOverride => {
                    eprintln!(
                        "⚠️  Config lock override for '{}': using locked='{}' (was '{}')",
                        field, locked, current
                    );
                    apply(locked);
                    Ok(())
                }
            }
        }

        if let Some(p) = self.port {
            let cur = cfg.port;
            handle_conflict("port", cur, p, policy, |v| cfg.port = v)?;
        }
        if let Some(ref r) = self.realm {
            let cur = cfg.realm.clone();
            match cur {
                Some(ref c) => handle_conflict(
                    "realm",
                    format!("{}:{}", c.name, c.version),
                    format!("{}:{}", r.name, r.version),
                    policy,
                    |_v| cfg.realm = Some(r.clone()),
                )?,
                None => {
                    cfg.realm = Some(r.clone());
                }
            }
        }
        if let Some(ref name) = self.app_name {
            let cur = cfg.app_name.clone();
            match cur {
                Some(ref c) => {
                    handle_conflict("app_name", c.clone(), name.clone(), policy, |_v| {
                        cfg.app_name = Some(name.clone())
                    })?
                }
                None => {
                    cfg.app_name = Some(name.clone());
                }
            }
        }
        if let Some(enabled) = self.encryption_enabled {
            // Ensure encryption config exists
            if cfg.encryption.is_none() {
                cfg.encryption = Some(EncryptionConfig::default());
            }
            if let Some(ref mut enc) = cfg.encryption {
                let cur = enc.enabled;
                handle_conflict("encryption.enabled", cur, enabled, policy, |v| {
                    enc.enabled = v
                })?;
            }
        }
        if let Some(ref nl) = self.node {
            if cfg.node.is_none() {
                cfg.node = Some(NodeConfig::default());
            }
            if let Some(ref mut node) = cfg.node {
                if let Some(ref t) = nl.node_type {
                    let cur = node.node_type.clone().unwrap_or_default();
                    handle_conflict("node.node_type", cur.clone(), t.clone(), policy, |_v| {
                        node.node_type = Some(t.clone())
                    })?;
                }
            }
        }
        Ok(())
    }
}

/// A simple facade for declaring hardcoded values with an `overridable` flag,
/// mirroring the user's mental model: "key => { value, overridable }".
///
/// Implementation detail: overridable=true maps to ConfigDefaults; overridable=false
/// maps to ConfigLocks with WarnAndOverride policy by default (no hard error).
#[derive(Clone, Debug, Default)]
pub struct SimpleHardcoded {
    pub port: Option<(u16, bool)>,
    pub realm: Option<(RealmInfo, bool)>,
    pub app_name: Option<(String, bool)>,
    pub encryption_enabled: Option<(bool, bool)>,
    pub node_node_type: Option<(String, bool)>,
}

impl SimpleHardcoded {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn port(mut self, port: u16, overridable: bool) -> Self {
        self.port = Some((port, overridable));
        self
    }
    pub fn realm(mut self, realm: RealmInfo, overridable: bool) -> Self {
        self.realm = Some((realm, overridable));
        self
    }
    pub fn app_name<T: Into<String>>(mut self, name: T, overridable: bool) -> Self {
        self.app_name = Some((name.into(), overridable));
        self
    }
    pub fn encryption_enabled(mut self, enabled: bool, overridable: bool) -> Self {
        self.encryption_enabled = Some((enabled, overridable));
        self
    }
    pub fn node_type<T: Into<String>>(mut self, t: T, overridable: bool) -> Self {
        self.node_node_type = Some((t.into(), overridable));
        self
    }

    /// Apply to a mutable Config. Overridable=true → defaults; otherwise → locks with warn-override.
    pub fn apply(&self, cfg: &mut Config) -> anyhow::Result<()> {
        // 1) Collect and apply defaults
        let mut defaults = ConfigDefaults::default();
        if let Some((p, true)) = self.port {
            defaults.port = Some(p);
        }
        if let Some((ref r, true)) = self.realm {
            defaults.realm = Some(r.clone());
        }
        if let Some((ref n, true)) = self.app_name {
            defaults.app_name = Some(n.clone());
        }
        if let Some((enabled, true)) = self.encryption_enabled {
            let mut enc = cfg.encryption.clone().unwrap_or_default();
            enc.enabled = enabled;
            defaults.encryption = Some(enc);
        }
        if let Some((ref t, true)) = self.node_node_type {
            let mut node = cfg.node.clone().unwrap_or_default();
            node.node_type = Some(t.clone());
            defaults.node = Some(node);
        }
        defaults.apply(cfg);

        // 2) Collect and enforce locks (WarnAndOverride policy by default)
        let mut locks = ConfigLocks::default();
        if let Some((p, false)) = self.port {
            locks.port = Some(p);
        }
        if let Some((ref r, false)) = self.realm {
            locks.realm = Some(r.clone());
        }
        if let Some((ref n, false)) = self.app_name {
            locks.app_name = Some(n.clone());
        }
        if let Some((enabled, false)) = self.encryption_enabled {
            locks.encryption_enabled = Some(enabled);
        }
        if let Some((ref t, false)) = self.node_node_type {
            locks.node = Some(NodeLocks {
                node_type: Some(t.clone()),
            });
        }
        locks.enforce(cfg, LockConflictPolicy::WarnAndOverride)
    }
}
