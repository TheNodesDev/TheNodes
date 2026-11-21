//! Binding of HELLO node IDs to transport identities (ADR-0012).
//!
//! A peer names itself in HELLO. The transport trust policy decides whether a
//! TLS certificate key or Noise static key may connect at all; this module
//! decides whether that key may use the node ID it claims. Without the
//! binding, any peer that passes the trust policy can claim another member's
//! node ID and receive its traffic.
//!
//! Evidence, strongest first:
//! - a pin: `[encryption.node_identity.pins]` lists the fingerprints a node ID
//!   may use;
//! - a certified name: the TLS leaf carries `URI:node://<realm>/<node_id>`
//!   for this node's realm and its chain validated against the configured
//!   trust anchors;
//! - a TOFU binding: the first fingerprint accepted for a node ID.
//!
//! A pin or certificate name that contradicts the claim rejects the
//! connection in every mode except `off`.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::config::{Config, NodeConfig};
use crate::events::{
    dispatcher,
    model::{LogEvent, LogLevel, SystemEvent},
};
use crate::security::secure_channel::{AuthSummary, SecurityBackend};

/// URI scheme of the SAN that names the node a TLS certificate was issued to:
/// `node://<realm>/<node_id>`, where `<realm>` is the realm's canonical code.
/// Each realm is its own namespace, so a name certifies a node ID only in the
/// realm it names.
pub const NODE_NAME_URI_SCHEME: &str = "node";

/// The URI naming `node_id` in the realm whose canonical code is `realm_code`.
pub fn node_name_uri(realm_code: &str, node_id: &str) -> String {
    format!("{NODE_NAME_URI_SCHEME}://{realm_code}/{node_id}")
}

/// The node ID a node-name URI names in the realm `realm_code`. Only the exact
/// form `node://<realm_code>/<node_id>` counts: no user, port, further path
/// segments, query or fragment, and a valid node ID. The scheme and realm are
/// compared ignoring ASCII case, as URI schemes and hosts are.
pub fn node_id_from_name_uri<'a>(uri: &'a str, realm_code: &str) -> Option<&'a str> {
    let (scheme, rest) = uri.split_once("://")?;
    if !scheme.eq_ignore_ascii_case(NODE_NAME_URI_SCHEME) {
        return None;
    }
    let (realm, node_id) = rest.split_once('/')?;
    if realm.is_empty() || !realm.eq_ignore_ascii_case(realm_code) {
        return None;
    }
    is_valid_node_id(node_id).then_some(node_id)
}

const DEFAULT_MAX_BINDINGS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeIdentityMode {
    /// HELLO node IDs are self-asserted labels.
    Off,
    /// Pins and certified names first, otherwise the first fingerprint seen
    /// for a node ID.
    Tofu,
    /// Every node ID needs a pin.
    Pinned,
    /// Every node ID needs a certified name or a pin.
    Certificate,
}

impl NodeIdentityMode {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "tofu" => Some(Self::Tofu),
            "pinned" => Some(Self::Pinned),
            "certificate" => Some(Self::Certificate),
            _ => None,
        }
    }
}

/// The kind of key a fingerprint was computed from. A node's TLS and Noise
/// keys differ, so TOFU binds each kind separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    Tls,
    Noise,
}

/// Parsed `[encryption.node_identity]`.
#[derive(Debug, Clone)]
pub struct NodeIdentityPolicy {
    pub mode: NodeIdentityMode,
    pub bindings_file: Option<PathBuf>,
    pub max_bindings: usize,
    pins: HashMap<String, Vec<String>>,
}

impl NodeIdentityPolicy {
    /// Parse and validate the configuration. Unknown modes, invalid node IDs
    /// and malformed fingerprints are errors, not silently ignored.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let section = config
            .encryption
            .as_ref()
            .and_then(|encryption| encryption.node_identity.as_ref());
        let mode = match section.and_then(|section| section.mode.as_deref()) {
            None => NodeIdentityMode::Tofu,
            Some(value) => NodeIdentityMode::parse(value)
                .ok_or_else(|| format!("unknown encryption.node_identity.mode {value:?}"))?,
        };
        let mut pins = HashMap::new();
        for (node_id, fingerprints) in section
            .and_then(|section| section.pins.as_ref())
            .into_iter()
            .flatten()
        {
            if !is_valid_node_id(node_id) {
                return Err(format!(
                    "invalid node ID {node_id:?} in encryption.node_identity.pins"
                ));
            }
            let mut normalized = Vec::with_capacity(fingerprints.len());
            for fingerprint in fingerprints {
                let fingerprint = fingerprint.trim().to_ascii_lowercase();
                if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!(
                        "pin for node {node_id:?} is not a SHA-256 hex fingerprint"
                    ));
                }
                normalized.push(fingerprint);
            }
            if normalized.is_empty() {
                return Err(format!("pin for node {node_id:?} lists no fingerprints"));
            }
            pins.insert(node_id.clone(), normalized);
        }
        Ok(Self {
            mode,
            bindings_file: section
                .and_then(|section| section.bindings_file.as_ref())
                .map(PathBuf::from),
            max_bindings: section
                .and_then(|section| section.max_bindings)
                .unwrap_or(DEFAULT_MAX_BINDINGS),
            pins,
        })
    }
}

/// A node ID as HELLO and Noise handshakes may carry it: 1-128 ASCII
/// alphanumerics, `-`, `_` or `.`.
pub fn is_valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty() && NodeConfig::valid_id(node_id)
}

/// What a secure channel proved about the remote party.
#[derive(Debug, Clone, Copy)]
pub struct PresentedIdentity<'a> {
    pub kind: IdentityKind,
    /// SHA-256 hex fingerprint of the key the remote proved it holds.
    pub fingerprint: &'a str,
    /// Node IDs the TLS leaf names in this node's realm (`node://` URI SANs);
    /// empty for Noise.
    pub node_names: &'a [String],
    /// Whether `node_names` are attested by a CA path validated against the
    /// configured trust anchors.
    pub node_names_certified: bool,
}

impl<'a> PresentedIdentity<'a> {
    /// The identity a channel authenticated: `None` for plaintext and for TLS
    /// peers that presented no certificate.
    pub fn from_auth(auth: &'a AuthSummary) -> Option<Self> {
        let kind = match auth.backend {
            SecurityBackend::Tls => IdentityKind::Tls,
            SecurityBackend::Noise => IdentityKind::Noise,
            SecurityBackend::Plaintext => return None,
        };
        Some(Self {
            kind,
            fingerprint: auth.fingerprint.as_deref()?,
            node_names: &auth.node_names,
            node_names_certified: auth.node_names_certified,
        })
    }

    pub fn noise(fingerprint: &'a str) -> Self {
        Self {
            kind: IdentityKind::Noise,
            fingerprint,
            node_names: &[],
            node_names_certified: false,
        }
    }
}

/// Node IDs a certificate was issued to in the realm `realm_code`: its
/// `node://<realm_code>/<node_id>` URI SANs. Names in other realms, other URIs
/// and unparseable certificates name no node.
pub fn node_names_from_certificate(der: &[u8], realm_code: &str) -> Vec<String> {
    use x509_parser::extensions::GeneralName;

    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => node_id_from_name_uri(uri, realm_code),
            _ => None,
        })
        .map(str::to_string)
        .collect()
}

/// Why a node ID was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingBasis {
    /// Binding is off; the node ID is a self-asserted label.
    Off,
    /// The connection carried no transport identity (plaintext, or TLS
    /// without a client certificate), so the node ID is unverified.
    Unauthenticated,
    Pin,
    Certificate,
    /// A TOFU binding; `first_use` when this connection creates it.
    Tofu {
        first_use: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentityVerdict {
    pub node_id: String,
    pub basis: BindingBasis,
    bound: Option<(IdentityKind, String)>,
}

impl NodeIdentityVerdict {
    /// The fingerprint bound to `node_id` on this connection, or `None` when
    /// the node ID is not bound to a transport identity.
    pub fn bound_fingerprint(&self) -> Option<&str> {
        self.bound
            .as_ref()
            .map(|(_, fingerprint)| fingerprint.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentityRejection {
    /// Stable reason code, e.g. `node-binding-mismatch`.
    pub reason: &'static str,
    pub node_id: String,
}

impl std::fmt::Display for NodeIdentityRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "node identity rejected for node_id={}: {}",
            self.node_id, self.reason
        )
    }
}

impl std::error::Error for NodeIdentityRejection {}

/// One persisted TOFU binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeBinding {
    pub kind: IdentityKind,
    pub node_id: String,
    pub fingerprint: String,
}

/// The node identity policy plus the TOFU bindings learned so far.
/// `PeerManager::node_identity` owns one per node.
pub struct NodeIdentityRegistry {
    policy: Result<NodeIdentityPolicy, String>,
    tofu: Mutex<HashMap<(IdentityKind, String), String>>,
}

impl NodeIdentityRegistry {
    /// Build the registry and load persisted bindings. An invalid
    /// configuration or unreadable bindings file yields a registry that
    /// rejects every node ID instead of one that binds nothing.
    pub fn from_config(config: &Config) -> Self {
        let loaded = NodeIdentityPolicy::from_config(config).and_then(|policy| {
            let tofu = match &policy.bindings_file {
                Some(path) => load_binding_map(path)?,
                None => HashMap::new(),
            };
            Ok((policy, tofu))
        });
        match loaded {
            Ok((policy, tofu)) => Self {
                policy: Ok(policy),
                tofu: Mutex::new(tofu),
            },
            Err(error) => {
                emit(
                    LogLevel::Error,
                    "node_identity_config_invalid",
                    error.clone(),
                );
                Self {
                    policy: Err(error),
                    tofu: Mutex::new(HashMap::new()),
                }
            }
        }
    }

    pub fn policy(&self) -> Result<&NodeIdentityPolicy, &str> {
        self.policy.as_ref().map_err(String::as_str)
    }

    /// Decide whether `identity` may use `node_id`. Has no side effects;
    /// call [`commit`](Self::commit) once the connection is registered.
    pub fn verify(
        &self,
        identity: Option<PresentedIdentity<'_>>,
        node_id: &str,
    ) -> Result<NodeIdentityVerdict, NodeIdentityRejection> {
        let reject = |reason| {
            Err(NodeIdentityRejection {
                reason,
                node_id: node_id.to_string(),
            })
        };
        let accept = |basis, bound| {
            Ok(NodeIdentityVerdict {
                node_id: node_id.to_string(),
                basis,
                bound,
            })
        };
        if !is_valid_node_id(node_id) {
            return reject("node-id-invalid");
        }
        let Ok(policy) = &self.policy else {
            return reject("node-identity-config-invalid");
        };
        if policy.mode == NodeIdentityMode::Off {
            return accept(BindingBasis::Off, None);
        }
        let pinned = policy.pins.get(node_id);
        let Some(identity) = identity else {
            if pinned.is_some() {
                return reject("node-pin-requires-identity");
            }
            // A node ID that a key already claimed is not handed to a
            // connection that proves no key.
            let tofu = self.tofu.lock();
            if [IdentityKind::Tls, IdentityKind::Noise]
                .into_iter()
                .any(|kind| tofu.contains_key(&(kind, node_id.to_string())))
            {
                return reject("node-binding-requires-identity");
            }
            drop(tofu);
            return match policy.mode {
                NodeIdentityMode::Pinned | NodeIdentityMode::Certificate => {
                    reject("node-identity-missing")
                }
                _ => accept(BindingBasis::Unauthenticated, None),
            };
        };

        let fingerprint = identity.fingerprint.to_ascii_lowercase();
        let bound = Some((identity.kind, fingerprint.clone()));
        match pinned {
            Some(fingerprints) if !fingerprints.contains(&fingerprint) => {
                return reject("node-pin-mismatch");
            }
            None if policy
                .pins
                .values()
                .any(|fingerprints| fingerprints.contains(&fingerprint)) =>
            {
                return reject("fingerprint-pinned-to-other-node");
            }
            _ => {}
        }
        let named = identity.node_names.iter().any(|name| name == node_id);
        if !identity.node_names.is_empty() && !named {
            return reject("node-name-mismatch");
        }

        if pinned.is_some() {
            return accept(BindingBasis::Pin, bound);
        }
        if named && identity.node_names_certified {
            return accept(BindingBasis::Certificate, bound);
        }
        match policy.mode {
            NodeIdentityMode::Pinned => reject("node-not-pinned"),
            NodeIdentityMode::Certificate => reject("node-name-not-certified"),
            NodeIdentityMode::Off | NodeIdentityMode::Tofu => {
                let tofu = self.tofu.lock();
                match tofu.get(&(identity.kind, node_id.to_string())) {
                    Some(existing) if *existing == fingerprint => {
                        accept(BindingBasis::Tofu { first_use: false }, bound)
                    }
                    Some(_) => reject("node-binding-mismatch"),
                    // A binding that cannot be recorded would leave the node
                    // ID free for the next key, so a full store refuses it.
                    None if tofu.len() >= policy.max_bindings => reject("node-binding-store-full"),
                    None => accept(BindingBasis::Tofu { first_use: true }, bound),
                }
            }
        }
    }

    /// Record what `verify` learned once the connection is registered: a
    /// first-use TOFU binding, or in `tofu` mode a certified name, which
    /// replaces an older binding so CA-managed key rotation keeps working.
    /// Returns `false` when a first-use binding could not be recorded because
    /// a conflicting binding was recorded in between or the store filled up.
    pub fn commit(&self, verdict: &NodeIdentityVerdict) -> bool {
        let Ok(policy) = &self.policy else {
            return false;
        };
        let Some((kind, fingerprint)) = &verdict.bound else {
            return true;
        };
        let replace = match verdict.basis {
            BindingBasis::Tofu { first_use: true } => false,
            BindingBasis::Certificate if policy.mode == NodeIdentityMode::Tofu => true,
            _ => return true,
        };
        let detail = format!(
            "node_id={} kind={:?} fingerprint={} basis={:?}",
            verdict.node_id, kind, fingerprint, verdict.basis
        );
        let key = (*kind, verdict.node_id.clone());
        let mut tofu = self.tofu.lock();
        match tofu.get(&key) {
            Some(existing) if existing == fingerprint => return true,
            Some(_) if !replace => {
                emit(LogLevel::Warn, "node_binding_conflict", detail);
                return false;
            }
            None if tofu.len() >= policy.max_bindings => {
                emit(LogLevel::Warn, "node_binding_store_full", detail);
                // A certified name stands without the record.
                return replace;
            }
            _ => {}
        }
        tofu.insert(key, fingerprint.clone());
        // Appended under the lock so the file records bindings in map order.
        if let Some(path) = &policy.bindings_file {
            let binding = NodeBinding {
                kind: *kind,
                node_id: verdict.node_id.clone(),
                fingerprint: fingerprint.clone(),
            };
            if let Err(error) = append_binding(path, &binding) {
                emit(
                    LogLevel::Warn,
                    "node_binding_persist_failed",
                    format!("{detail} path={} error={error}", path.display()),
                );
            }
        }
        drop(tofu);
        emit(LogLevel::Info, "node_binding_recorded", detail);
        true
    }

    /// Current TOFU bindings, sorted by node ID and kind.
    pub fn bindings(&self) -> Vec<NodeBinding> {
        let mut bindings: Vec<NodeBinding> = self
            .tofu
            .lock()
            .iter()
            .map(|((kind, node_id), fingerprint)| NodeBinding {
                kind: *kind,
                node_id: node_id.clone(),
                fingerprint: fingerprint.clone(),
            })
            .collect();
        bindings.sort_by(|a, b| (&a.node_id, a.kind as u8).cmp(&(&b.node_id, b.kind as u8)));
        bindings
    }
}

/// Read a bindings file: JSON lines, a later line replacing an earlier one
/// for the same node ID and kind. A missing file holds no bindings; lines
/// that do not parse (e.g. a write torn by a crash) are skipped.
pub fn load_bindings_file(path: &Path) -> std::io::Result<Vec<NodeBinding>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut latest: Vec<NodeBinding> = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<NodeBinding>(&line) {
            Ok(binding) => {
                latest.retain(|b| !(b.kind == binding.kind && b.node_id == binding.node_id));
                latest.push(binding);
            }
            Err(error) => emit(
                LogLevel::Warn,
                "node_binding_line_skipped",
                format!("path={} line={} error={error}", path.display(), index + 1),
            ),
        }
    }
    Ok(latest)
}

/// Remove every binding for `node_id` from a bindings file, rewriting it
/// atomically. Returns how many bindings were removed. A running node keeps
/// its in-memory bindings until it restarts.
pub fn forget_node_bindings(path: &Path, node_id: &str) -> std::io::Result<usize> {
    let bindings = load_bindings_file(path)?;
    let before = bindings.len();
    let kept: Vec<NodeBinding> = bindings
        .into_iter()
        .filter(|binding| binding.node_id != node_id)
        .collect();
    let removed = before - kept.len();
    if removed == 0 {
        return Ok(0);
    }
    let mut contents = String::new();
    for binding in &kept {
        contents.push_str(&serde_json::to_string(binding).map_err(std::io::Error::other)?);
        contents.push('\n');
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(removed)
}

fn load_binding_map(path: &Path) -> Result<HashMap<(IdentityKind, String), String>, String> {
    let bindings = load_bindings_file(path)
        .map_err(|error| format!("cannot read node bindings {}: {error}", path.display()))?;
    Ok(bindings
        .into_iter()
        .map(|binding| ((binding.kind, binding.node_id), binding.fingerprint))
        .collect())
}

fn append_binding(path: &Path, binding: &NodeBinding) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(binding).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())
}

fn emit(level: LogLevel, action: &str, detail: String) {
    let mut meta = dispatcher::meta("trust", level);
    meta.corr_id = Some(dispatcher::correlation_id());
    dispatcher::emit(LogEvent::System(SystemEvent {
        meta,
        action: action.into(),
        detail: Some(detail),
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionConfig, NodeIdentityConfig};

    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn config(section: NodeIdentityConfig) -> Config {
        Config {
            encryption: Some(EncryptionConfig {
                node_identity: Some(section),
                ..EncryptionConfig::default()
            }),
            ..Config::default()
        }
    }

    fn registry(mode: &str, pins: &[(&str, &str)]) -> NodeIdentityRegistry {
        let mut pin_map: HashMap<String, Vec<String>> = HashMap::new();
        for (node_id, fingerprint) in pins {
            pin_map
                .entry(node_id.to_string())
                .or_default()
                .push(fingerprint.to_string());
        }
        NodeIdentityRegistry::from_config(&config(NodeIdentityConfig {
            mode: Some(mode.to_string()),
            pins: Some(pin_map),
            ..NodeIdentityConfig::default()
        }))
    }

    fn tls<'a>(
        fingerprint: &'a str,
        names: &'a [String],
        certified: bool,
    ) -> PresentedIdentity<'a> {
        PresentedIdentity {
            kind: IdentityKind::Tls,
            fingerprint,
            node_names: names,
            node_names_certified: certified,
        }
    }

    fn reason(result: Result<NodeIdentityVerdict, NodeIdentityRejection>) -> &'static str {
        result.expect_err("expected rejection").reason
    }

    #[test]
    fn default_mode_is_tofu() {
        let policy = NodeIdentityPolicy::from_config(&Config::default()).unwrap();
        assert_eq!(policy.mode, NodeIdentityMode::Tofu);
        assert_eq!(policy.max_bindings, DEFAULT_MAX_BINDINGS);
    }

    #[test]
    fn invalid_configuration_rejects_every_node() {
        for section in [
            NodeIdentityConfig {
                mode: Some("pined".into()),
                ..NodeIdentityConfig::default()
            },
            NodeIdentityConfig {
                pins: Some(HashMap::from([("node a".into(), vec![FP_A.into()])])),
                ..NodeIdentityConfig::default()
            },
            NodeIdentityConfig {
                pins: Some(HashMap::from([("node-a".into(), vec!["abc".into()])])),
                ..NodeIdentityConfig::default()
            },
        ] {
            let config = config(section);
            assert!(NodeIdentityPolicy::from_config(&config).is_err());
            let registry = NodeIdentityRegistry::from_config(&config);
            assert_eq!(
                reason(registry.verify(None, "node-a")),
                "node-identity-config-invalid"
            );
        }
    }

    #[test]
    fn malformed_node_ids_are_rejected_in_every_mode() {
        for mode in ["off", "tofu", "pinned", "certificate"] {
            let registry = registry(mode, &[]);
            for node_id in ["", "has space", "slash/x", &"x".repeat(129)] {
                assert_eq!(reason(registry.verify(None, node_id)), "node-id-invalid");
            }
        }
    }

    #[test]
    fn off_accepts_any_claim_without_binding() {
        let registry = registry("off", &[("node-a", FP_A)]);
        let verdict = registry
            .verify(Some(tls(FP_B, &[], false)), "node-a")
            .unwrap();
        assert_eq!(verdict.basis, BindingBasis::Off);
        assert_eq!(verdict.bound_fingerprint(), None);
    }

    #[test]
    fn tofu_binds_first_fingerprint_and_rejects_another() {
        let registry = registry("tofu", &[]);
        let first = registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .unwrap();
        assert_eq!(first.basis, BindingBasis::Tofu { first_use: true });
        // Nothing is recorded before commit.
        assert!(registry
            .verify(Some(tls(FP_B, &[], false)), "node-a")
            .is_ok());
        assert!(registry.commit(&first));

        let again = registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .unwrap();
        assert_eq!(again.basis, BindingBasis::Tofu { first_use: false });
        assert_eq!(again.bound_fingerprint(), Some(FP_A));
        assert_eq!(
            reason(registry.verify(Some(tls(FP_B, &[], false)), "node-a")),
            "node-binding-mismatch"
        );
        // The same key may still claim other, unbound node IDs.
        assert!(registry
            .verify(Some(tls(FP_A, &[], false)), "node-b")
            .is_ok());
    }

    #[test]
    fn tofu_binds_tls_and_noise_keys_separately() {
        let registry = registry("tofu", &[]);
        let tls_verdict = registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .unwrap();
        assert!(registry.commit(&tls_verdict));
        let noise_verdict = registry
            .verify(Some(PresentedIdentity::noise(FP_B)), "node-a")
            .unwrap();
        assert_eq!(noise_verdict.basis, BindingBasis::Tofu { first_use: true });
    }

    #[test]
    fn commit_refuses_a_binding_recorded_in_between() {
        let registry = registry("tofu", &[]);
        let a = registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .unwrap();
        let b = registry
            .verify(Some(tls(FP_B, &[], false)), "node-a")
            .unwrap();
        assert!(registry.commit(&a));
        assert!(!registry.commit(&b));
        assert_eq!(registry.bindings()[0].fingerprint, FP_A);
    }

    #[test]
    fn unauthenticated_connections_stay_unbound_unless_pinned_or_strict() {
        let tofu = registry("tofu", &[("pinned-node", FP_A)]);
        let verdict = tofu.verify(None, "node-a").unwrap();
        assert_eq!(verdict.basis, BindingBasis::Unauthenticated);
        assert_eq!(verdict.bound_fingerprint(), None);
        assert_eq!(
            reason(tofu.verify(None, "pinned-node")),
            "node-pin-requires-identity"
        );
        for mode in ["pinned", "certificate"] {
            assert_eq!(
                reason(registry(mode, &[]).verify(None, "node-a")),
                "node-identity-missing"
            );
        }

        // Once a key is bound to a node ID, a connection without one cannot
        // use it.
        let bound = tofu
            .verify(Some(PresentedIdentity::noise(FP_B)), "node-b")
            .unwrap();
        assert!(tofu.commit(&bound));
        assert_eq!(
            reason(tofu.verify(None, "node-b")),
            "node-binding-requires-identity"
        );
    }

    #[test]
    fn pins_bind_in_every_mode_and_reserve_their_fingerprints() {
        for mode in ["tofu", "pinned", "certificate"] {
            let registry = registry(mode, &[("node-a", FP_A)]);
            let verdict = registry
                .verify(Some(tls(FP_A, &[], false)), "node-a")
                .unwrap();
            assert_eq!(verdict.basis, BindingBasis::Pin);
            assert_eq!(
                reason(registry.verify(Some(tls(FP_B, &[], false)), "node-a")),
                "node-pin-mismatch"
            );
            assert_eq!(
                reason(registry.verify(Some(tls(FP_A, &[], false)), "node-z")),
                "fingerprint-pinned-to-other-node"
            );
        }
        let uppercase = FP_A.to_ascii_uppercase();
        assert!(registry("pinned", &[("node-a", &uppercase)])
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .is_ok());
        assert_eq!(
            reason(registry("pinned", &[]).verify(Some(tls(FP_A, &[], false)), "node-a")),
            "node-not-pinned"
        );
    }

    #[test]
    fn certificate_names_constrain_and_certified_names_bind() {
        let named_a = vec!["node-a".to_string()];
        let registry = registry("certificate", &[]);
        // A name always constrains, certified or not.
        assert_eq!(
            reason(registry.verify(Some(tls(FP_A, &named_a, false)), "node-b")),
            "node-name-mismatch"
        );
        // Only a CA-certified name satisfies certificate mode.
        assert_eq!(
            reason(registry.verify(Some(tls(FP_A, &named_a, false)), "node-a")),
            "node-name-not-certified"
        );
        let verdict = registry
            .verify(Some(tls(FP_A, &named_a, true)), "node-a")
            .unwrap();
        assert_eq!(verdict.basis, BindingBasis::Certificate);
        // Noise has no certificates: certificate mode needs a pin there.
        assert_eq!(
            reason(registry.verify(Some(PresentedIdentity::noise(FP_A)), "node-a")),
            "node-name-not-certified"
        );
    }

    #[test]
    fn certified_name_replaces_tofu_binding_after_key_rotation() {
        let named_a = vec!["node-a".to_string()];
        let registry = registry("tofu", &[]);
        let old = registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .unwrap();
        assert!(registry.commit(&old));

        // An uncertified name does not override the existing binding.
        assert_eq!(
            reason(registry.verify(Some(tls(FP_B, &named_a, false)), "node-a")),
            "node-binding-mismatch"
        );
        let rotated = registry
            .verify(Some(tls(FP_B, &named_a, true)), "node-a")
            .unwrap();
        assert_eq!(rotated.basis, BindingBasis::Certificate);
        assert!(registry.commit(&rotated));
        assert!(registry
            .verify(Some(tls(FP_B, &[], false)), "node-a")
            .is_ok());
        assert_eq!(
            reason(registry.verify(Some(tls(FP_A, &[], false)), "node-a")),
            "node-binding-mismatch"
        );
    }

    #[test]
    fn full_store_refuses_new_first_use_bindings() {
        let registry = NodeIdentityRegistry::from_config(&config(NodeIdentityConfig {
            max_bindings: Some(1),
            ..NodeIdentityConfig::default()
        }));
        let a = registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .unwrap();
        // A second first-use verdict taken before the first is recorded.
        let late = registry
            .verify(Some(tls(FP_B, &[], false)), "node-c")
            .unwrap();
        assert!(registry.commit(&a));
        assert_eq!(
            reason(registry.verify(Some(tls(FP_B, &[], false)), "node-b")),
            "node-binding-store-full"
        );
        assert!(!registry.commit(&late));
        // Bound node IDs keep working.
        assert!(registry
            .verify(Some(tls(FP_A, &[], false)), "node-a")
            .is_ok());
        assert_eq!(registry.bindings().len(), 1);
    }

    #[test]
    fn bindings_persist_across_registries_and_can_be_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity/bindings.jsonl");
        let section = NodeIdentityConfig {
            bindings_file: Some(path.display().to_string()),
            ..NodeIdentityConfig::default()
        };

        let first = NodeIdentityRegistry::from_config(&config(section.clone()));
        let a = first.verify(Some(tls(FP_A, &[], false)), "node-a").unwrap();
        assert!(first.commit(&a));
        let b = first
            .verify(Some(PresentedIdentity::noise(FP_B)), "node-b")
            .unwrap();
        assert!(first.commit(&b));
        // A torn trailing line is skipped, not fatal.
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"kind\":\"tls\",\"node")
            .unwrap();

        let restarted = NodeIdentityRegistry::from_config(&config(section.clone()));
        assert_eq!(
            reason(restarted.verify(Some(tls(FP_B, &[], false)), "node-a")),
            "node-binding-mismatch"
        );
        assert_eq!(restarted.bindings().len(), 2);

        assert_eq!(forget_node_bindings(&path, "node-a").unwrap(), 1);
        assert_eq!(forget_node_bindings(&path, "node-a").unwrap(), 0);
        let forgotten = NodeIdentityRegistry::from_config(&config(section));
        assert!(forgotten
            .verify(Some(tls(FP_B, &[], false)), "node-a")
            .is_ok());
        assert_eq!(forgotten.bindings().len(), 1);
    }

    #[test]
    fn node_names_are_read_from_uri_sans_in_this_realm_only() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        for uri in [
            "node://railway-net/node-a",
            "https://example.test/",
            "NODE://Railway-Net/node-b",
            // Another realm's namespace certifies nothing here.
            "node://other-net/node-c",
            // Not the exact form.
            "node://railway-net/node-d/extra",
            "node://railway-net:80/node-e",
            "node://user@railway-net/node-f",
            "node://railway-net/node-g?x",
            "node:railway-net:node-h",
        ] {
            params
                .subject_alt_names
                .push(rcgen::SanType::URI(uri.try_into().unwrap()));
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        assert_eq!(
            node_names_from_certificate(certificate.der().as_ref(), "railway-net"),
            vec!["node-a".to_string(), "node-b".to_string()]
        );
        assert_eq!(
            node_names_from_certificate(certificate.der().as_ref(), "other-net"),
            vec!["node-c".to_string()]
        );
        assert!(node_names_from_certificate(b"not a certificate", "railway-net").is_empty());
        assert_eq!(node_name_uri("5g-net", "gw-01"), "node://5g-net/gw-01");
        assert_eq!(
            node_id_from_name_uri("node://5g-net/gw-01", "5g-net"),
            Some("gw-01")
        );
    }
}
