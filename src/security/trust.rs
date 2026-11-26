// src/security/trust.rs

use anyhow::{anyhow, Context, Result};
use base16ct::lower::encode_string;
use base64::Engine; // for base64 encode()
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::BufReader as StdBufReader;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use tokio_rustls::rustls::pki_types::CertificateDer;

pub use crate::security::encryption::CertificateUsage;

/// Runtime trust policy mode (Phase 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    Open,
    Allowlist,
    Tofu,
    Observe,
    HybridPlaceholder,
}

/// Parsing fails for a mode the node does not know. A config file cannot
/// contain one, since config loading rejects it.
impl FromStr for TrustMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "open" => Ok(TrustMode::Open),
            "allowlist" => Ok(TrustMode::Allowlist),
            "tofu" => Ok(TrustMode::Tofu),
            "observe" | "record" | "quarantine" => Ok(TrustMode::Observe),
            "hybrid" => Ok(TrustMode::HybridPlaceholder),
            _ => Err(()),
        }
    }
}

/// The configured trust mode: `open` when unset. A config file cannot hold an
/// unknown mode; one set in code trusts only the allowlist, never everyone.
fn configured_trust_mode(mode: Option<&str>) -> TrustMode {
    match mode {
        None => TrustMode::Open,
        Some(mode) => TrustMode::from_str(mode).unwrap_or(TrustMode::Allowlist),
    }
}

/// Parsed + normalized trust policy derived from configuration
#[derive(Debug, Clone)]
pub struct EffectiveTrustPolicy {
    pub mode: TrustMode,
    pub accept_self_signed: bool,
    pub reject_expired: bool,
    pub reject_before_valid: bool,
    pub enforce_ca_chain: bool,
    pub allowlist_fingerprints: Vec<String>,
    pub pin_subjects: Vec<String>,
    pub pin_fingerprints: Vec<String>,
    pub pin_fp_algo: String,
    /// The leaf must name a node in this realm (`URI:node://<realm>/<node_id>`).
    pub require_realm_node_name: bool,
    /// CRL directories checked when a chain is validated against a CA (ADR-0014).
    pub crl_dirs: Vec<String>,
    /// Trusted keys: their fingerprints are accepted, and `tofu` adds the
    /// keys it accepts for the first time (ADR-0016).
    pub trusted_dir: Option<String>,
    /// Where rejected keys are kept for review (ADR-0016).
    pub rejected_dir: Option<String>,
}

impl EffectiveTrustPolicy {
    pub(crate) fn pinned_fingerprint_match(&self, fingerprint: Option<&str>) -> Option<bool> {
        if self.pin_fingerprints.is_empty() {
            return None;
        }
        Some(fingerprint.is_some_and(|fingerprint| {
            self.pin_fingerprints
                .iter()
                .any(|pinned| fingerprints_equal(pinned, fingerprint))
        }))
    }

    /// The TLS policy from `[encryption.tls]`; `open` when it has no
    /// `trust_policy`.
    pub fn from_tls_config(cfg: Option<&crate::config::EncryptionTlsConfig>) -> Self {
        let paths = cfg.and_then(|tls| tls.paths.as_ref());
        let mut policy = Self::open_defaults();
        policy.trusted_dir = paths.and_then(|paths| paths.trusted_cert_dir.clone());
        policy.rejected_dir = paths.and_then(|paths| paths.rejected_dir.clone());
        policy.crl_dirs = paths
            .map(crate::config::TlsPaths::crl_dirs)
            .unwrap_or_default();
        let Some(tp) = cfg.and_then(|tls| tls.trust_policy.as_ref()) else {
            return policy;
        };
        policy.mode = configured_trust_mode(tp.mode.as_deref());
        policy.accept_self_signed = tp.accept_self_signed.unwrap_or(false);
        policy.reject_expired = tp.reject_expired.unwrap_or(false);
        policy.reject_before_valid = tp.reject_before_valid.unwrap_or(false);
        policy.enforce_ca_chain = tp.enforce_ca_chain.unwrap_or(false);
        policy.pin_subjects = tp.pin_subjects.clone().unwrap_or_default();
        policy.pin_fingerprints = normalize_fingerprint_list(tp.pin_fingerprints.clone());
        policy.pin_fp_algo = tp.pin_fp_algo.clone().unwrap_or_else(|| "sha256".into());
        policy.require_realm_node_name = tp.require_realm_node_name.unwrap_or(false);
        policy
    }

    /// The Noise policy from `[encryption.noise]`; `open` when it has no
    /// `trust_policy`.
    pub fn from_noise_config(cfg: Option<&crate::config::EncryptionNoiseConfig>) -> Self {
        let paths = cfg.and_then(|noise| noise.paths.as_ref());
        let mut policy = Self::open_defaults();
        policy.trusted_dir = paths.and_then(|paths| paths.trusted_dir.clone());
        policy.rejected_dir = paths.and_then(|paths| paths.rejected_dir.clone());
        let Some(tp) = cfg.and_then(|noise| noise.trust_policy.as_ref()) else {
            return policy;
        };
        policy.mode = configured_trust_mode(tp.mode.as_deref());
        policy.allowlist_fingerprints =
            normalize_fingerprint_list(tp.allowlist_fingerprints.clone());
        policy.pin_fingerprints = normalize_fingerprint_list(tp.pin_fingerprints.clone());
        policy
    }

    fn open_defaults() -> Self {
        Self {
            mode: TrustMode::Open,
            accept_self_signed: false,
            reject_expired: false,
            reject_before_valid: false,
            enforce_ca_chain: false,
            allowlist_fingerprints: vec![],
            pin_subjects: vec![],
            pin_fingerprints: vec![],
            pin_fp_algo: "sha256".into(),
            require_realm_node_name: false,
            crl_dirs: Vec::new(),
            trusted_dir: None,
            rejected_dir: None,
        }
    }
}

fn normalize_fingerprint_list(values: Option<Vec<String>>) -> Vec<String> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

/// Compare two fingerprint strings in constant time (with respect to their
/// contents; the length check below is not constant-time, but fingerprint
/// lengths are fixed-size hex digests and not secret).
///
/// Fingerprints are public SHA-256 digests derived from a peer's certificate or
/// Noise static key, not secrets, so a variable-time comparison would not leak
/// anything an attacker cannot already observe. This comparison is still
/// constant-time as defense in depth and to avoid setting a precedent of
/// short-circuiting comparisons in trust-decision code.
fn fingerprints_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Outcome of a trust evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecisionOutcome {
    Accept,
    Reject,
}

/// Detailed trust decision returned by evaluator
#[derive(Debug, Clone)]
pub struct TrustDecision {
    pub outcome: TrustDecisionOutcome,
    pub reason: &'static str,
    pub fingerprint: Option<String>,
    /// Whether a rejected key was kept in the rejected directory.
    pub stored: bool,
    pub chain_valid: Option<bool>,
    pub time_valid: Option<bool>,
    pub chain_reason: Option<String>,
    pub time_reason: Option<String>,
    /// A key `tofu` accepted for the first time, to be trusted once the
    /// connection is admitted ([`PendingTrust::persist`]).
    pub pending_trust: Option<PendingTrust>,
}

impl TrustDecision {
    pub fn accept(
        reason: &'static str,
        fp: Option<String>,
        stored: bool,
        chain_valid: Option<bool>,
        time_valid: Option<bool>,
        chain_reason: Option<String>,
        time_reason: Option<String>,
    ) -> Self {
        Self {
            outcome: TrustDecisionOutcome::Accept,
            reason,
            fingerprint: fp,
            stored,
            chain_valid,
            time_valid,
            chain_reason,
            time_reason,
            pending_trust: None,
        }
    }
    pub fn reject(
        reason: &'static str,
        fp: Option<String>,
        chain_valid: Option<bool>,
        time_valid: Option<bool>,
        chain_reason: Option<String>,
        time_reason: Option<String>,
    ) -> Self {
        Self {
            outcome: TrustDecisionOutcome::Reject,
            reason,
            fingerprint: fp,
            stored: false,
            chain_valid,
            time_valid,
            chain_reason,
            time_reason,
            pending_trust: None,
        }
    }
}

/// The file a key is kept as in a trusted or rejected directory: a leaf
/// certificate (`pem`) or a Noise static-key record (`noise`).
#[derive(Debug, Clone, Copy)]
pub struct KeyArtifact<'a> {
    pub extension: &'static str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Default)]
pub struct FingerprintTrustInput<'a> {
    pub fingerprint: Option<&'a str>,
    pub additional_allowlisted_fingerprints: Option<&'a HashSet<String>>,
    pub allowlist_error: Option<&'static str>,
    /// The key as a file, kept when it is rejected or first trusted by `tofu`.
    pub artifact: Option<KeyArtifact<'a>>,
    /// The key is a CA certificate. `tofu` never trusts one on first use,
    /// since a trusted CA could vouch for others (ADR-0016).
    pub is_ca_certificate: bool,
}

/// A key `tofu` accepted for the first time. It becomes trusted only once
/// the connection is admitted, after its node identity binding is recorded,
/// so a connection refused later leaves nothing in the trusted directory
/// (ADR-0016).
#[derive(Debug, Clone)]
pub struct PendingTrust {
    dir: PathBuf,
    file_name: String,
    bytes: Vec<u8>,
}

impl PendingTrust {
    /// The file the key will be written to.
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.file_name)
    }

    /// Write the key into the trusted directory. Fails with `StorageFull`
    /// when the directory holds [`MAX_STORED_KEYS`] entries.
    pub fn persist(&self) -> std::io::Result<()> {
        store_key_file(&self.dir, &self.file_name, &self.bytes)
    }
}

/// Decide whether a key may connect. A rejected key is kept in the policy's
/// rejected directory.
pub fn evaluate_fingerprint_trust(
    policy: &EffectiveTrustPolicy,
    input: FingerprintTrustInput<'_>,
) -> TrustDecision {
    let decision = decide_fingerprint_trust(policy, &input);
    record_rejected(policy, decision, input.artifact)
}

fn decide_fingerprint_trust(
    policy: &EffectiveTrustPolicy,
    input: &FingerprintTrustInput<'_>,
) -> TrustDecision {
    let fingerprint = input.fingerprint.map(str::to_owned);

    if policy.pinned_fingerprint_match(input.fingerprint).is_some() {
        let Some(fp) = input.fingerprint else {
            return TrustDecision::reject("fp-missing", None, None, None, None, None);
        };
        if policy.pinned_fingerprint_match(Some(fp)) == Some(false) {
            return TrustDecision::reject("fp-pin-mismatch", fingerprint, None, None, None, None);
        }
    }

    let allowlist_contains = input.fingerprint.is_some_and(|fp| {
        policy
            .allowlist_fingerprints
            .iter()
            .any(|allowed| fingerprints_equal(allowed, fp))
            || input
                .additional_allowlisted_fingerprints
                .is_some_and(|allowed| allowed.contains(fp))
    });
    let allowlist_available = !policy.allowlist_fingerprints.is_empty()
        || input.additional_allowlisted_fingerprints.is_some();

    match policy.mode {
        TrustMode::Open => {
            TrustDecision::accept("open-policy", fingerprint, false, None, None, None, None)
        }
        TrustMode::HybridPlaceholder => TrustDecision::accept(
            "hybrid-placeholder-open",
            fingerprint,
            false,
            None,
            None,
            None,
            None,
        ),
        TrustMode::Allowlist => {
            let Some(fp) = input.fingerprint else {
                return TrustDecision::reject("fingerprint-missing", None, None, None, None, None);
            };
            if allowlist_contains {
                return TrustDecision::accept(
                    "present-in-allowlist",
                    Some(fp.to_string()),
                    false,
                    None,
                    None,
                    None,
                    None,
                );
            }
            let reason = if allowlist_available {
                "not-in-allowlist"
            } else {
                input.allowlist_error.unwrap_or("no-allowlist")
            };
            TrustDecision::reject(reason, Some(fp.to_string()), None, None, None, None)
        }
        // A trusted key, including one `tofu` accepted before, connects; an
        // unknown one is accepted once and trusted when its connection is
        // admitted. Which node ID a key may use is the node identity
        // binding's decision (ADR-0012), not this one's.
        TrustMode::Tofu => {
            let Some(fp) = input.fingerprint else {
                return TrustDecision::reject("fingerprint-missing", None, None, None, None, None);
            };
            if allowlist_contains {
                return TrustDecision::accept(
                    "seen-before",
                    Some(fp.to_string()),
                    false,
                    None,
                    None,
                    None,
                    None,
                );
            }
            if let Some(reason) = input.allowlist_error {
                return TrustDecision::reject(reason, Some(fp.to_string()), None, None, None, None);
            }
            if input.is_ca_certificate {
                return TrustDecision::reject(
                    "tofu-ca-certificate",
                    Some(fp.to_string()),
                    None,
                    None,
                    None,
                    None,
                );
            }
            match first_use(policy, fp, input.artifact) {
                Ok(pending) => {
                    let mut decision = TrustDecision::accept(
                        "new-tofu",
                        Some(fp.to_string()),
                        false,
                        None,
                        None,
                        None,
                        None,
                    );
                    decision.pending_trust = Some(pending);
                    decision
                }
                Err(reason) => {
                    TrustDecision::reject(reason, Some(fp.to_string()), None, None, None, None)
                }
            }
        }
        TrustMode::Observe => {
            TrustDecision::reject("observe-only", fingerprint, None, None, None, None)
        }
    }
}

/// The trusted-directory entry for a key `tofu` sees for the first time, if
/// there is room for it.
fn first_use(
    policy: &EffectiveTrustPolicy,
    fingerprint: &str,
    artifact: Option<KeyArtifact<'_>>,
) -> Result<PendingTrust, &'static str> {
    let (Some(dir), Some(artifact)) = (policy.trusted_dir.as_deref(), artifact) else {
        return Err("tofu-storage-unavailable");
    };
    let dir = PathBuf::from(dir);
    let Ok(file_name) = key_file_name(fingerprint, artifact.extension) else {
        return Err("fingerprint-invalid");
    };
    if !dir.join(&file_name).exists() && ensure_room(&dir).is_err() {
        return Err("tofu-storage-full");
    }
    Ok(PendingTrust {
        dir,
        file_name,
        bytes: artifact.bytes.to_vec(),
    })
}

/// Keep a rejected key in the rejected directory, if one is configured.
fn record_rejected(
    policy: &EffectiveTrustPolicy,
    mut decision: TrustDecision,
    artifact: Option<KeyArtifact<'_>>,
) -> TrustDecision {
    if decision.outcome != TrustDecisionOutcome::Reject {
        return decision;
    }
    if let (Some(dir), Some(fp), Some(artifact)) = (
        policy.rejected_dir.as_deref(),
        decision.fingerprint.as_deref(),
        artifact,
    ) {
        decision.stored = key_file_name(fp, artifact.extension)
            .and_then(|name| store_key_file(Path::new(dir), &name, artifact.bytes))
            .is_ok();
    }
    decision
}

/// Evaluate a peer certificate chain for its concrete TLS role. Expects the
/// peer chain leaf first. Chains are validated against the CA certificates in
/// `trust_anchor_dir` (`[encryption.tls.paths] issuer_cert_dir`), never against
/// the trusted directory, which `tofu` writes to (ADR-0016). A rejected leaf is
/// kept in the policy's rejected directory.
pub fn evaluate_peer_cert_chain_for_usage(
    policy: &EffectiveTrustPolicy,
    trust_anchor_dir: Option<&str>,
    peer_chain: &[CertificateDer<'_>],
    realm: Option<&crate::realms::RealmInfo>,
    usage: CertificateUsage,
) -> TrustDecision {
    let leaf_pem = peer_chain.first().map(encode_certificate_pem);
    let artifact = leaf_pem.as_deref().map(|pem| KeyArtifact {
        extension: "pem",
        bytes: pem.as_bytes(),
    });
    let decision = decide_peer_cert_chain_at(
        policy,
        trust_anchor_dir,
        peer_chain,
        realm,
        usage,
        artifact,
        std::time::SystemTime::now(),
    );
    record_rejected(policy, decision, artifact)
}

fn decide_peer_cert_chain_at(
    policy: &EffectiveTrustPolicy,
    trust_anchor_dir: Option<&str>,
    peer_chain: &[CertificateDer<'_>],
    realm: Option<&crate::realms::RealmInfo>,
    usage: CertificateUsage,
    artifact: Option<KeyArtifact<'_>>,
    now: std::time::SystemTime,
) -> TrustDecision {
    use crate::security::encryption::{
        extract_validity_windows, validate_certificate_chain, validate_self_signed_certificate,
    };

    let mut chain_valid: Option<bool> = None;
    let mut chain_reason: Option<String> = None;
    let mut time_valid: Option<bool> = None;
    let mut time_reason: Option<String> = None;
    let leaf_fp = peer_chain.first().and_then(spki_fingerprint);
    if policy.enforce_ca_chain {
        let (cv, creason, self_signed) =
            validate_certificate_chain(peer_chain, trust_anchor_dir, &policy.crl_dirs, usage, now);
        chain_valid = Some(cv);
        chain_reason = Some(creason.clone());
        // A self-signed override is explicit and still requires a valid
        // self-signature, current validity, and matching TLS EKU. It never
        // overrides a key that webpki explicitly distrusts.
        if !cv
            && self_signed
            && policy.accept_self_signed
            && creason != "certificate-distrusted"
            && creason != "certificate-revoked"
        {
            match peer_chain
                .first()
                .ok_or_else(|| "empty-chain".to_string())
                .and_then(|certificate| validate_self_signed_certificate(certificate, usage, now))
            {
                Ok(()) => {
                    chain_valid = Some(true);
                    chain_reason = Some("self-signed-override".into());
                }
                Err(reason) => {
                    chain_reason = Some(reason);
                }
            }
        }
    } else if !peer_chain.is_empty() {
        chain_valid = Some(true);
        chain_reason = Some("not-enforced".into());
    }

    // The independent leaf-validity flags also work when CA-chain enforcement is off.
    if policy.reject_before_valid || policy.reject_expired {
        let now_unix = match now.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(_) => {
                return TrustDecision::reject(
                    "time-invalid",
                    leaf_fp,
                    chain_valid,
                    Some(false),
                    chain_reason,
                    Some("system-time-before-unix-epoch".into()),
                )
            }
        };
        let Some(leaf) = peer_chain.first() else {
            return TrustDecision::reject(
                "time-invalid",
                None,
                chain_valid,
                Some(false),
                chain_reason,
                Some("missing-leaf-certificate".into()),
            );
        };
        if let Some((nb, na)) = extract_validity_windows(leaf.as_ref()) {
            let mut ok = true;
            if policy.reject_before_valid && now_unix < nb {
                ok = false;
                time_reason = Some("not-yet-valid".into());
            }
            if policy.reject_expired && now_unix > na {
                ok = false;
                time_reason = Some("expired".into());
            }
            if ok {
                time_reason = Some("valid".into());
            }
            time_valid = Some(ok);
            if !ok {
                return TrustDecision::reject(
                    "time-invalid",
                    leaf_fp,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                );
            }
        } else {
            return TrustDecision::reject(
                "time-invalid",
                leaf_fp,
                chain_valid,
                Some(false),
                chain_reason,
                Some("validity-unparseable".into()),
            );
        }
    }
    if policy.enforce_ca_chain && chain_valid == Some(false) {
        return TrustDecision::reject(
            "chain-invalid",
            leaf_fp,
            chain_valid,
            time_valid,
            chain_reason,
            time_reason,
        );
    }

    // Extract leaf subject and CA flag (if parsable)
    let mut leaf_subject: Option<String> = None;
    let mut leaf_is_ca = false;
    if let Some(first) = peer_chain.first() {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(first.as_ref()) {
            leaf_subject = Some(parsed.tbs_certificate.subject.to_string());
            leaf_is_ca = parsed.tbs_certificate.is_ca();
        }
    }

    if !policy.pin_subjects.is_empty() {
        match &leaf_subject {
            Some(subj) => {
                let mut matched = false;
                for pin in &policy.pin_subjects {
                    if let Some(needle) = pin.strip_prefix('~') {
                        // substring pin
                        if subj.contains(needle) {
                            matched = true;
                            break;
                        }
                    } else if subj == pin {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return TrustDecision::reject(
                        "subject-pin-mismatch",
                        leaf_fp,
                        chain_valid,
                        time_valid,
                        chain_reason,
                        time_reason,
                    );
                }
            }
            None => {
                return TrustDecision::reject(
                    "subject-unparsed",
                    leaf_fp,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                );
            }
        }
    }
    if policy.require_realm_node_name {
        // Names in another realm, or no realm to compare with, count as none.
        let named = match (realm, peer_chain.first()) {
            (Some(realm), Some(leaf)) => {
                !crate::security::node_identity::node_names_from_certificate(
                    leaf.as_ref(),
                    &realm.canonical_code(),
                )
                .is_empty()
            }
            _ => false,
        };
        if !named {
            return TrustDecision::reject(
                "realm-node-name-missing",
                leaf_fp,
                chain_valid,
                time_valid,
                chain_reason,
                time_reason,
            );
        }
    }
    let trusted_dir = policy.trusted_dir.as_deref();
    let trusted_fingerprints = trusted_dir.map(load_trusted_fingerprints).transpose();
    let allowlist_error = match (policy.mode, trusted_dir, &trusted_fingerprints) {
        (TrustMode::Allowlist, None, _) => Some("no-trusted-dir"),
        (TrustMode::Allowlist | TrustMode::Tofu, Some(_), Err(_)) => Some("trusted-dir-unreadable"),
        _ => None,
    };
    let mut decision = decide_fingerprint_trust(
        policy,
        &FingerprintTrustInput {
            fingerprint: leaf_fp.as_deref(),
            additional_allowlisted_fingerprints: trusted_fingerprints
                .as_ref()
                .ok()
                .and_then(|set| set.as_ref()),
            allowlist_error,
            artifact,
            is_ca_certificate: leaf_is_ca,
        },
    );
    decision.chain_valid = chain_valid;
    decision.time_valid = time_valid;
    decision.chain_reason = chain_reason;
    decision.time_reason = time_reason;
    decision
}

pub fn sha256_fingerprint_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    encode_string(&h.finalize())
}

fn encode_certificate_pem(cert: &CertificateDer<'_>) -> String {
    let pem_body = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        pem_body
    )
}

/// Extract SHA-256 fingerprint of certificate SubjectPublicKeyInfo (SPKI)
pub fn spki_fingerprint(cert: &CertificateDer<'_>) -> Option<String> {
    let der = cert.as_ref();
    // First try proper parse using x509-parser for SPKI
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, parsed)) => Some(sha256_fingerprint_hex(
            parsed.tbs_certificate.subject_pki.raw,
        )),
        Err(_) => {
            // Fallback: hash full DER so we still have a stable identifier
            Some(sha256_fingerprint_hex(der))
        }
    }
}

/// Compute SPKI fingerprint from PEM-encoded certificate bytes.
pub fn spki_fingerprint_from_pem_bytes(pem_bytes: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(pem_bytes);
    let certificates = certs(&mut cursor).context("failed to parse certificate PEM")?;
    let first = certificates
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no certificate entries found"))?;
    let cert = CertificateDer::from(first);
    spki_fingerprint(&cert).ok_or_else(|| anyhow!("unable to compute SPKI fingerprint"))
}

/// Compute SPKI fingerprint from a PEM file on disk.
pub fn spki_fingerprint_from_pem_file<P: AsRef<Path>>(path: P) -> Result<String> {
    let data = fs::read(path.as_ref())
        .with_context(|| format!("failed to read certificate at {}", path.as_ref().display()))?;
    spki_fingerprint_from_pem_bytes(&data)
}

/// Load all PEM certs from directory and return set of fingerprints
pub fn load_trusted_fingerprints(dir: &str) -> std::io::Result<HashSet<String>> {
    let mut set = HashSet::new();
    let path = PathBuf::from(dir);
    if !path.exists() {
        return Ok(set);
    }
    for entry in std::fs::read_dir(path)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let p = entry.path();
        if p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("pem"))
            .unwrap_or(false)
        {
            if let Ok(f) = std::fs::File::open(&p) {
                let mut reader = StdBufReader::new(f);
                if let Ok(list) = certs(&mut reader) {
                    for c in list {
                        if let Some(fp) = spki_fingerprint(&CertificateDer::from(c)) {
                            set.insert(fp);
                        }
                    }
                }
            }
        }
    }
    Ok(set)
}

/// Load trusted Noise SHA-256 fingerprints from `.noise` key files, or from
/// files with a `fingerprint_sha256=` line. A missing directory holds none.
pub fn load_noise_fingerprints(dir: &str) -> std::io::Result<HashSet<String>> {
    let mut set = HashSet::new();
    let path = PathBuf::from(dir);
    if !path.exists() {
        return Ok(set);
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
            let normalized = stem.trim().to_ascii_lowercase();
            if is_sha256_hex(&normalized) {
                set.insert(normalized);
                continue;
            }
        }
        let contents = std::fs::read_to_string(&path)?;
        for line in contents.lines() {
            let candidate = line
                .strip_prefix("fingerprint_sha256=")
                .unwrap_or(line)
                .trim()
                .to_ascii_lowercase();
            if is_sha256_hex(&candidate) {
                set.insert(candidate);
                break;
            }
        }
    }
    Ok(set)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Most entries the node writes into a key directory: rejected keys into the
/// rejected directory, and keys `tofu` accepts into the trusted one. Keys
/// cost a peer nothing, so without a cap new ones could fill the disk.
/// Files an operator placed there count too.
pub const MAX_STORED_KEYS: usize = 4096;

/// Fails with `StorageFull` when `dir` already holds `MAX_STORED_KEYS` entries.
fn ensure_room(dir: &Path) -> std::io::Result<()> {
    let full = std::fs::read_dir(dir)
        .is_ok_and(|entries| entries.take(MAX_STORED_KEYS).count() >= MAX_STORED_KEYS);
    if full {
        return Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            format!("{} holds {MAX_STORED_KEYS} entries", dir.display()),
        ));
    }
    Ok(())
}

/// The file a key is kept as: its SHA-256 fingerprint and the extension.
/// Anything but a fingerprint is refused, so a value from an operator or a
/// library caller cannot name a path outside the key directory.
fn key_file_name(fingerprint: &str, extension: &str) -> std::io::Result<String> {
    if !is_sha256_hex(fingerprint) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{fingerprint:?} is not a SHA-256 hex fingerprint"),
        ));
    }
    Ok(format!(
        "{}.{}",
        fingerprint.to_ascii_lowercase(),
        extension.trim_start_matches('.')
    ))
}

/// Write a key file unless it exists, within the directory's cap.
fn store_key_file(dir: &Path, file_name: &str, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(file_name);
    if path.exists() {
        return Ok(());
    }
    ensure_room(dir)?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => file.write_all(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err),
    }
}

/// Keep a key file in `dir`, named after its fingerprint, within the cap.
pub fn store_key(
    dir: &str,
    fingerprint: &str,
    extension: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    store_key_file(
        Path::new(dir),
        &key_file_name(fingerprint, extension)?,
        bytes,
    )
}

/// The trusted and rejected directories of one secure-channel backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStore {
    /// `tls` or `noise`.
    pub backend: &'static str,
    /// Extension of the key files: `pem` or `noise`.
    pub extension: &'static str,
    pub trusted_dir: Option<String>,
    pub rejected_dir: Option<String>,
}

/// The key stores the configuration names: `[encryption.tls.paths]` and
/// `[encryption.noise.paths]`.
pub fn key_stores(config: &crate::config::Config) -> Vec<KeyStore> {
    let tls = config.tls().and_then(|tls| tls.paths.as_ref());
    let noise = config
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.noise.as_ref())
        .and_then(|noise| noise.paths.as_ref());
    vec![
        KeyStore {
            backend: "tls",
            extension: "pem",
            trusted_dir: tls.and_then(|paths| paths.trusted_cert_dir.clone()),
            rejected_dir: tls.and_then(|paths| paths.rejected_dir.clone()),
        },
        KeyStore {
            backend: "noise",
            extension: "noise",
            trusted_dir: noise.and_then(|paths| paths.trusted_dir.clone()),
            rejected_dir: noise.and_then(|paths| paths.rejected_dir.clone()),
        },
    ]
}

/// File names of the key files (`*.<extension>`) in `dir`, sorted. A missing
/// directory holds none.
pub fn list_key_files(dir: &str, extension: &str) -> std::io::Result<Vec<String>> {
    let path = Path::new(dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_key = Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case(extension));
        if is_key && entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Move a rejected key into the trusted directory. Returns `Ok(false)` when
/// the rejected directory does not hold the key; a key already trusted is
/// only removed from the rejected directory. Fails with `InvalidInput` for
/// anything but a SHA-256 hex fingerprint.
pub fn promote_rejected_to_trusted(store: &KeyStore, fingerprint: &str) -> std::io::Result<bool> {
    let file_name = key_file_name(fingerprint, store.extension)?;
    let (Some(rejected_dir), Some(trusted_dir)) =
        (store.rejected_dir.as_deref(), store.trusted_dir.as_deref())
    else {
        return Ok(false);
    };
    let src = PathBuf::from(rejected_dir).join(&file_name);
    if !src.is_file() {
        return Ok(false);
    }
    std::fs::create_dir_all(trusted_dir)?;
    let dst = PathBuf::from(trusted_dir).join(&file_name);
    if !dst.exists() {
        std::fs::copy(&src, &dst)?;
    }
    std::fs::remove_file(&src)?;
    if let Some(dispatcher) = crate::events::dispatcher::EventDispatcher::global() {
        use crate::events::model::{LogEvent, LogLevel, PromotionEvent};
        let meta = crate::events::dispatcher::meta("trust", LogLevel::Info);
        let evt = PromotionEvent {
            meta,
            fingerprint: fingerprint.to_string(),
            from_store: src.to_string_lossy().to_string(),
            to_store: dst.to_string_lossy().to_string(),
            operator: "runtime".into(),
            success: true,
        };
        let _ = dispatcher.tx.try_send(LogEvent::Promotion(evt));
    }
    Ok(true)
}

/// Check the trust settings before a node starts (ADR-0016): a policy whose
/// mode cannot work with the configured directories is an error, not a node
/// that trusts or records nothing.
pub fn check_trust_config(config: &crate::config::Config) -> Result<(), String> {
    let encryption = config.encryption.as_ref();
    let node_identity_off = encryption
        .and_then(|encryption| encryption.node_identity.as_ref())
        .and_then(|node_identity| node_identity.mode.as_deref())
        .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("off"));
    let tls = EffectiveTrustPolicy::from_tls_config(config.tls());
    let noise = EffectiveTrustPolicy::from_noise_config(
        encryption.and_then(|encryption| encryption.noise.as_ref()),
    );
    for (section, policy, trusted, rejected) in [
        (
            "[encryption.tls.trust_policy]",
            &tls,
            "[encryption.tls.paths] trusted_cert_dir",
            "[encryption.tls.paths] rejected_dir",
        ),
        (
            "[encryption.noise.trust_policy]",
            &noise,
            "[encryption.noise.paths] trusted_dir",
            "[encryption.noise.paths] rejected_dir",
        ),
    ] {
        match policy.mode {
            TrustMode::Tofu if policy.trusted_dir.is_none() => {
                return Err(format!(
                    "{section} mode = \"tofu\" needs {trusted}, where it keeps the keys it trusts"
                ));
            }
            // TOFU accepts any new key; only the node identity binding keeps
            // a key from using another node's ID.
            TrustMode::Tofu if node_identity_off => {
                return Err(format!(
                    "{section} mode = \"tofu\" needs node identity binding: set [encryption.node_identity] mode to tofu, pinned or certificate"
                ));
            }
            TrustMode::Observe if policy.rejected_dir.is_none() => {
                return Err(format!(
                    "{section} mode = \"observe\" needs {rejected}, where it keeps the keys it sees"
                ));
            }
            _ => {}
        }
    }
    let issuer_dir = config
        .tls()
        .and_then(|tls| tls.paths.as_ref())
        .and_then(|paths| paths.issuer_cert_dir.as_deref());
    if tls.enforce_ca_chain && issuer_dir.is_none() {
        return Err(
            "[encryption.tls.trust_policy] enforce_ca_chain = true needs [encryption.tls.paths] issuer_cert_dir: CA trust anchors are read only from there".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_fingerprint_trust, load_noise_fingerprints, promote_rejected_to_trusted,
        store_key, EffectiveTrustPolicy, FingerprintTrustInput, KeyArtifact, KeyStore,
        TrustDecision, TrustDecisionOutcome, TrustMode, MAX_STORED_KEYS,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn reports_fingerprint_pin_match_independently_of_policy_outcome() {
        let policy = EffectiveTrustPolicy {
            mode: TrustMode::Observe,
            pin_fingerprints: vec!["abc123".to_string()],
            ..EffectiveTrustPolicy::open_defaults()
        };

        assert_eq!(policy.pinned_fingerprint_match(Some("abc123")), Some(true));
        assert_eq!(policy.pinned_fingerprint_match(Some("def456")), Some(false));
        assert_eq!(policy.pinned_fingerprint_match(None), Some(false));
    }

    /// A Noise-style key fingerprint: 64 hex digits.
    fn key(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn store_policy(mode: TrustMode, dir: &Path) -> EffectiveTrustPolicy {
        EffectiveTrustPolicy {
            mode,
            trusted_dir: Some(dir.join("trusted").to_string_lossy().into_owned()),
            rejected_dir: Some(dir.join("rejected").to_string_lossy().into_owned()),
            ..EffectiveTrustPolicy::open_defaults()
        }
    }

    fn key_file(dir: &Path, store: &str, fingerprint: &str) -> PathBuf {
        dir.join(store).join(format!("{fingerprint}.noise"))
    }

    /// Evaluate a Noise key the way the secure channel does: the trusted
    /// directory is the allowlist.
    fn decide(policy: &EffectiveTrustPolicy, fingerprint: &str, is_ca: bool) -> TrustDecision {
        let trusted = policy
            .trusted_dir
            .as_deref()
            .map(|dir| load_noise_fingerprints(dir).unwrap());
        let record = format!("kind=noise-static-key\nfingerprint_sha256={fingerprint}\n");
        evaluate_fingerprint_trust(
            policy,
            FingerprintTrustInput {
                fingerprint: Some(fingerprint),
                additional_allowlisted_fingerprints: trusted.as_ref(),
                artifact: Some(KeyArtifact {
                    extension: "noise",
                    bytes: record.as_bytes(),
                }),
                is_ca_certificate: is_ca,
                ..Default::default()
            },
        )
    }

    /// A config file cannot hold an unknown mode; one set in code must not
    /// mean `open`.
    #[test]
    fn an_unknown_trust_mode_set_in_code_trusts_only_the_allowlist() {
        let tls = crate::config::EncryptionTlsConfig {
            trust_policy: Some(crate::config::TlsTrustPolicyConfig {
                mode: Some("allowlst".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            EffectiveTrustPolicy::from_tls_config(Some(&tls)).mode,
            TrustMode::Allowlist
        );
        let noise = crate::config::EncryptionNoiseConfig {
            trust_policy: Some(crate::config::NoiseTrustPolicyConfig {
                mode: Some("allowlst".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            EffectiveTrustPolicy::from_noise_config(Some(&noise)).mode,
            TrustMode::Allowlist
        );
        let unset = crate::config::NoiseTrustPolicyConfig::default();
        let noise = crate::config::EncryptionNoiseConfig {
            trust_policy: Some(unset),
            ..Default::default()
        };
        assert_eq!(
            EffectiveTrustPolicy::from_noise_config(Some(&noise)).mode,
            TrustMode::Open
        );
    }

    /// TOFU trusts a new key by adding it to the trusted directory, and only
    /// once its connection is admitted (ADR-0016).
    #[test]
    fn tofu_trusts_a_new_key_once_its_connection_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let tofu = store_policy(TrustMode::Tofu, dir.path());
        let first = decide(&tofu, &key(1), false);
        assert_eq!(first.reason, "new-tofu");
        assert_eq!(first.outcome, TrustDecisionOutcome::Accept);
        let pending = first.pending_trust.expect("a first use is pending");
        assert_eq!(pending.path(), key_file(dir.path(), "trusted", &key(1)));
        // A connection refused after the trust decision leaves nothing.
        assert!(!pending.path().exists());
        assert_eq!(decide(&tofu, &key(1), false).reason, "new-tofu");

        pending.persist().unwrap();
        let again = decide(&tofu, &key(1), false);
        assert_eq!(again.reason, "seen-before");
        assert!(again.pending_trust.is_none());
        // Which node ID a key may use is the node identity binding's
        // decision, so another new key is a first use too.
        assert_eq!(decide(&tofu, &key(2), false).reason, "new-tofu");
    }

    /// Modes other than TOFU never trust a key; the keys they reject are kept
    /// for review, and only an operator's promotion makes one trusted.
    #[test]
    fn other_modes_never_trust_and_keep_rejected_keys_for_review() {
        let dir = tempfile::tempdir().unwrap();
        let observe = decide(
            &store_policy(TrustMode::Observe, dir.path()),
            &key(1),
            false,
        );
        assert_eq!(observe.reason, "observe-only");
        assert!(observe.stored);
        let allowlist = decide(
            &store_policy(TrustMode::Allowlist, dir.path()),
            &key(2),
            false,
        );
        assert_eq!(allowlist.reason, "not-in-allowlist");
        assert!(allowlist.stored);
        let open = decide(&store_policy(TrustMode::Open, dir.path()), &key(3), false);
        assert_eq!(open.reason, "open-policy");
        assert!(!open.stored && open.pending_trust.is_none());

        assert!(key_file(dir.path(), "rejected", &key(1)).exists());
        assert!(key_file(dir.path(), "rejected", &key(2)).exists());
        assert!(!key_file(dir.path(), "rejected", &key(3)).exists());
        assert!(!dir.path().join("trusted").exists());

        // A rejected key is not known to TOFU.
        let tofu = store_policy(TrustMode::Tofu, dir.path());
        assert_eq!(decide(&tofu, &key(1), false).reason, "new-tofu");

        let store = KeyStore {
            backend: "noise",
            extension: "noise",
            trusted_dir: tofu.trusted_dir.clone(),
            rejected_dir: tofu.rejected_dir.clone(),
        };
        assert!(promote_rejected_to_trusted(&store, &key(1)).unwrap());
        assert!(!key_file(dir.path(), "rejected", &key(1)).exists());
        assert!(key_file(dir.path(), "trusted", &key(1)).exists());
        assert_eq!(decide(&tofu, &key(1), false).reason, "seen-before");
        assert!(!promote_rejected_to_trusted(&store, &key(3)).unwrap());
    }

    /// A trusted CA could vouch for other certificates, so TOFU never trusts
    /// one on first use.
    #[test]
    fn tofu_never_trusts_a_ca_certificate_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let tofu = store_policy(TrustMode::Tofu, dir.path());
        let decision = decide(&tofu, &key(1), true);
        assert_eq!(decision.reason, "tofu-ca-certificate");
        assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
        assert!(decision.pending_trust.is_none());
        assert!(key_file(dir.path(), "rejected", &key(1)).exists());
    }

    /// A fingerprint names a file, so an operator's input cannot reach outside
    /// the key directories.
    #[test]
    fn only_a_fingerprint_can_name_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let rejected = dir.path().join("rejected");
        std::fs::create_dir_all(&rejected).unwrap();
        let outside = dir.path().join("outside.noise");
        std::fs::write(&outside, b"not a key").unwrap();
        let store = KeyStore {
            backend: "noise",
            extension: "noise",
            trusted_dir: Some(dir.path().join("trusted").to_string_lossy().into_owned()),
            rejected_dir: Some(rejected.to_string_lossy().into_owned()),
        };
        for bad in [
            "../outside".to_string(),
            "..".to_string(),
            "abc123".to_string(),
            "z".repeat(64),
            format!("../{}", key(1)),
        ] {
            let err = promote_rejected_to_trusted(&store, &bad).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{bad}");
            let err = store_key(rejected.to_str().unwrap(), &bad, "noise", b"x").unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{bad}");
        }
        assert!(outside.exists());
        assert!(!dir.path().join("trusted").exists());
        assert_eq!(std::fs::read_dir(&rejected).unwrap().count(), 0);

        // An uppercase fingerprint names the same file.
        store_key(
            rejected.to_str().unwrap(),
            &key(0xab).to_ascii_uppercase(),
            "noise",
            b"kept",
        )
        .unwrap();
        assert!(promote_rejected_to_trusted(&store, &key(0xab)).unwrap());
    }

    #[test]
    fn full_key_directories_refuse_new_keys_and_keep_known_ones() {
        let dir = tempfile::tempdir().unwrap();
        let tofu = store_policy(TrustMode::Tofu, dir.path());
        decide(&tofu, &key(1), false)
            .pending_trust
            .unwrap()
            .persist()
            .unwrap();
        for i in 1..MAX_STORED_KEYS {
            std::fs::write(dir.path().join("trusted").join(format!("{i}.txt")), b"").unwrap();
        }
        assert_eq!(decide(&tofu, &key(1), false).reason, "seen-before");
        assert_eq!(decide(&tofu, &key(2), false).reason, "tofu-storage-full");

        let rejected = dir.path().join("rejected");
        std::fs::create_dir_all(&rejected).unwrap();
        store_key(rejected.to_str().unwrap(), &key(3), "noise", b"kept").unwrap();
        for i in 1..MAX_STORED_KEYS {
            std::fs::write(rejected.join(format!("{i}.txt")), b"").unwrap();
        }
        store_key(rejected.to_str().unwrap(), &key(3), "noise", b"kept").unwrap();
        let err = store_key(rejected.to_str().unwrap(), &key(4), "noise", b"new").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
    }
}

#[derive(Debug, Default)]
pub struct TrustStore {
    trusted_nodes: HashSet<String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            trusted_nodes: HashSet::new(),
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<()> {
        let content = fs::read_to_string(path)?;
        self.trusted_nodes = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();
        Ok(())
    }

    pub fn is_trusted(&self, node_id: &str) -> bool {
        self.trusted_nodes.contains(node_id)
    }

    pub fn add_trusted_node(&mut self, node_id: String) {
        self.trusted_nodes.insert(node_id);
    }
}
