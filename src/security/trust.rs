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

/// Storage policy for newly seen certs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreNew {
    None,
    Observed,
}

impl FromStr for TrustMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let m = match s.to_lowercase().as_str() {
            "allowlist" => TrustMode::Allowlist,
            "tofu" => TrustMode::Tofu,
            "observe" | "record" | "quarantine" => TrustMode::Observe,
            "hybrid" => TrustMode::HybridPlaceholder,
            _ => TrustMode::Open,
        };
        Ok(m)
    }
}

impl FromStr for StoreNew {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s.to_lowercase().as_str() {
            "observed" => StoreNew::Observed,
            _ => StoreNew::None,
        };
        Ok(v)
    }
}

/// Parsed + normalized trust policy derived from configuration
#[derive(Debug, Clone)]
pub struct EffectiveTrustPolicy {
    pub mode: TrustMode,
    pub accept_self_signed: bool,
    pub store_new: StoreNew,
    pub observed_dir: Option<String>,
    pub reject_expired: bool,
    pub reject_before_valid: bool,
    pub enforce_ca_chain: bool,
    pub allowlist_fingerprints: Vec<String>,
    pub pin_subjects: Vec<String>,
    pub pin_fingerprints: Vec<String>,
    pub pin_fp_algo: String,
    pub realm_subject_binding: bool,
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

    pub fn from_config(cfg: &crate::config::EncryptionConfig) -> Self {
        // Pull nested trust_policy, fall back to defaults if absent
        if let Some(tp) = &cfg.trust_policy {
            let mode = tp
                .mode
                .as_deref()
                .and_then(|s| TrustMode::from_str(s).ok())
                .unwrap_or(TrustMode::Open);
            let accept_self_signed = tp.accept_self_signed.unwrap_or(false);
            let store_new = tp
                .store_new_certs
                .as_deref()
                .and_then(|s| StoreNew::from_str(s).ok())
                .unwrap_or(StoreNew::None);
            let observed_dir = tp.paths.as_ref().and_then(|p| p.observed_dir.clone());
            let reject_expired = tp.reject_expired.unwrap_or(false);
            let reject_before_valid = tp.reject_before_valid.unwrap_or(false);
            let enforce_ca_chain = tp.enforce_ca_chain.unwrap_or(false);
            let pin_subjects = tp.pin_subjects.clone().unwrap_or_default();
            let pin_fingerprints = normalize_fingerprint_list(tp.pin_fingerprints.clone());
            let pin_fp_algo = tp.pin_fp_algo.clone().unwrap_or_else(|| "sha256".into());
            let realm_subject_binding = tp.realm_subject_binding.unwrap_or(false);
            Self {
                mode,
                accept_self_signed,
                store_new,
                observed_dir,
                reject_expired,
                reject_before_valid,
                enforce_ca_chain,
                allowlist_fingerprints: vec![],
                pin_subjects,
                pin_fingerprints,
                pin_fp_algo,
                realm_subject_binding,
            }
        } else {
            Self::open_defaults()
        }
    }

    pub fn from_noise_config(cfg: Option<&crate::config::EncryptionNoiseConfig>) -> Self {
        let Some(cfg) = cfg else {
            return Self::open_defaults();
        };
        let Some(tp) = &cfg.trust_policy else {
            return Self::open_defaults();
        };
        Self {
            mode: tp
                .mode
                .as_deref()
                .and_then(|mode| TrustMode::from_str(mode).ok())
                .unwrap_or(TrustMode::Open),
            accept_self_signed: false,
            store_new: tp
                .store_new
                .as_deref()
                .and_then(|mode| StoreNew::from_str(mode).ok())
                .unwrap_or(StoreNew::None),
            observed_dir: tp
                .paths
                .as_ref()
                .and_then(|paths| paths.observed_dir.clone()),
            reject_expired: false,
            reject_before_valid: false,
            enforce_ca_chain: false,
            allowlist_fingerprints: normalize_fingerprint_list(tp.allowlist_fingerprints.clone()),
            pin_subjects: vec![],
            pin_fingerprints: normalize_fingerprint_list(tp.pin_fingerprints.clone()),
            pin_fp_algo: "sha256".into(),
            realm_subject_binding: false,
        }
    }

    fn open_defaults() -> Self {
        Self {
            mode: TrustMode::Open,
            accept_self_signed: false,
            store_new: StoreNew::None,
            observed_dir: None,
            reject_expired: false,
            reject_before_valid: false,
            enforce_ca_chain: false,
            allowlist_fingerprints: vec![],
            pin_subjects: vec![],
            pin_fingerprints: vec![],
            pin_fp_algo: "sha256".into(),
            realm_subject_binding: false,
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
    pub stored: bool,
    pub chain_valid: Option<bool>,
    pub time_valid: Option<bool>,
    pub chain_reason: Option<String>,
    pub time_reason: Option<String>,
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
        }
    }

    fn with_stored(mut self, stored: bool) -> Self {
        self.stored = stored;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObservedArtifact<'a> {
    pub extension: &'static str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Default)]
pub struct FingerprintTrustInput<'a> {
    pub fingerprint: Option<&'a str>,
    pub additional_allowlisted_fingerprints: Option<&'a HashSet<String>>,
    pub allowlist_error: Option<&'static str>,
    pub identity: Option<&'a str>,
    pub observed_artifact: Option<ObservedArtifact<'a>>,
}

pub fn evaluate_fingerprint_trust(
    policy: &EffectiveTrustPolicy,
    input: FingerprintTrustInput<'_>,
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
            let stored_artifact = maybe_store_observed_artifact(policy, &input, false);
            let stored_identity = maybe_record_observed_identity_if_requested(
                policy,
                input.identity,
                input.fingerprint,
                true,
            );
            let stored = stored_artifact || stored_identity;
            TrustDecision::accept("open-policy", fingerprint, stored, None, None, None, None)
        }
        TrustMode::Allowlist => {
            let Some(fp) = input.fingerprint else {
                return TrustDecision::reject("fingerprint-missing", None, None, None, None, None);
            };
            if allowlist_contains {
                TrustDecision::accept(
                    "present-in-allowlist",
                    Some(fp.to_string()),
                    false,
                    None,
                    None,
                    None,
                    None,
                )
            } else {
                let stored_artifact = maybe_store_observed_artifact(policy, &input, false);
                let stored_identity = maybe_record_observed_identity_if_requested(
                    policy,
                    input.identity,
                    Some(fp),
                    true,
                );
                let stored = stored_artifact || stored_identity;
                let reason = if allowlist_available {
                    "not-in-allowlist"
                } else {
                    input.allowlist_error.unwrap_or("no-allowlist")
                };
                TrustDecision::reject(reason, Some(fp.to_string()), None, None, None, None)
                    .with_stored(stored)
            }
        }
        TrustMode::Tofu => {
            let Some(fp) = input.fingerprint else {
                return TrustDecision::reject("fingerprint-missing", None, None, None, None, None);
            };
            let (Some(dir), Some(identity)) = (policy.observed_dir.as_deref(), input.identity)
            else {
                return TrustDecision::reject(
                    "tofu-storage-unavailable",
                    Some(fp.to_string()),
                    None,
                    None,
                    None,
                    None,
                );
            };
            match load_observed_fingerprint_binding(dir, identity) {
                Ok(Some(remembered)) => {
                    if fingerprints_equal(&remembered, fp) {
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
                    return TrustDecision::reject(
                        "tofu-mismatch",
                        Some(fp.to_string()),
                        None,
                        None,
                        None,
                        None,
                    );
                }
                Ok(None) => {}
                Err(_) => {
                    return TrustDecision::reject(
                        "tofu-storage-unreadable",
                        Some(fp.to_string()),
                        None,
                        None,
                        None,
                        None,
                    );
                }
            }
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
            let stored_artifact = maybe_store_observed_artifact(policy, &input, false);
            match create_observed_fingerprint_binding(dir, identity, fp) {
                Ok(()) => TrustDecision::accept(
                    "new-tofu",
                    Some(fp.to_string()),
                    true,
                    None,
                    None,
                    None,
                    None,
                ),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    match load_observed_fingerprint_binding(dir, identity) {
                        Ok(Some(remembered)) if fingerprints_equal(&remembered, fp) => {
                            TrustDecision::accept(
                                "seen-before",
                                Some(fp.to_string()),
                                stored_artifact,
                                None,
                                None,
                                None,
                                None,
                            )
                        }
                        Ok(Some(_)) => TrustDecision::reject(
                            "tofu-mismatch",
                            Some(fp.to_string()),
                            None,
                            None,
                            None,
                            None,
                        ),
                        _ => TrustDecision::reject(
                            "tofu-storage-unreadable",
                            Some(fp.to_string()),
                            None,
                            None,
                            None,
                            None,
                        ),
                    }
                }
                Err(_) => TrustDecision::reject(
                    "tofu-storage-unwritable",
                    Some(fp.to_string()),
                    None,
                    None,
                    None,
                    None,
                ),
            }
        }
        TrustMode::Observe => {
            let stored_artifact = maybe_store_observed_artifact(policy, &input, true);
            let stored_identity =
                maybe_record_observed_identity(policy, input.identity, input.fingerprint, true);
            let stored = stored_artifact || stored_identity;
            TrustDecision::reject("observe-only", fingerprint, None, None, None, None)
                .with_stored(stored)
        }
        TrustMode::HybridPlaceholder => {
            let stored_artifact = maybe_store_observed_artifact(policy, &input, false);
            let stored_identity = maybe_record_observed_identity_if_requested(
                policy,
                input.identity,
                input.fingerprint,
                true,
            );
            let stored = stored_artifact || stored_identity;
            TrustDecision::accept(
                "hybrid-placeholder-open",
                fingerprint,
                stored,
                None,
                None,
                None,
                None,
            )
        }
    }
}

fn maybe_store_observed_artifact(
    policy: &EffectiveTrustPolicy,
    input: &FingerprintTrustInput<'_>,
    force: bool,
) -> bool {
    if !force && policy.store_new != StoreNew::Observed {
        return false;
    }
    let (Some(dir), Some(fp), Some(artifact)) = (
        policy.observed_dir.as_deref(),
        input.fingerprint,
        input.observed_artifact,
    ) else {
        return false;
    };
    store_observed_artifact(dir, fp, artifact.extension, artifact.bytes).is_ok()
}

fn maybe_record_observed_identity(
    policy: &EffectiveTrustPolicy,
    identity: Option<&str>,
    fingerprint: Option<&str>,
    overwrite: bool,
) -> bool {
    let (Some(dir), Some(identity), Some(fingerprint)) =
        (policy.observed_dir.as_deref(), identity, fingerprint)
    else {
        return false;
    };
    store_observed_fingerprint_binding(dir, identity, fingerprint, overwrite).is_ok()
}

fn maybe_record_observed_identity_if_requested(
    policy: &EffectiveTrustPolicy,
    identity: Option<&str>,
    fingerprint: Option<&str>,
    overwrite: bool,
) -> bool {
    if policy.store_new != StoreNew::Observed {
        return false;
    }
    maybe_record_observed_identity(policy, identity, fingerprint, overwrite)
}

/// Evaluate a peer certificate chain for its concrete TLS role.
/// Expects the peer chain leaf first.
pub fn evaluate_peer_cert_chain_for_usage(
    policy: &EffectiveTrustPolicy,
    trusted_cert_dir: Option<&str>,
    trust_anchor_dir: Option<&str>,
    observed_dir: Option<&str>,
    peer_chain: &[CertificateDer<'_>],
    realm: Option<&crate::realms::RealmInfo>,
    usage: CertificateUsage,
) -> TrustDecision {
    evaluate_peer_cert_chain_at(
        policy,
        trusted_cert_dir,
        trust_anchor_dir,
        observed_dir,
        peer_chain,
        realm,
        usage,
        std::time::SystemTime::now(),
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_peer_cert_chain_at(
    policy: &EffectiveTrustPolicy,
    trusted_cert_dir: Option<&str>,
    trust_anchor_dir: Option<&str>,
    observed_dir: Option<&str>,
    peer_chain: &[CertificateDer<'_>],
    realm: Option<&crate::realms::RealmInfo>,
    usage: CertificateUsage,
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
            validate_certificate_chain(peer_chain, trust_anchor_dir, usage, now);
        chain_valid = Some(cv);
        chain_reason = Some(creason.clone());
        // A self-signed override is explicit and still requires a valid
        // self-signature, current validity, and matching TLS EKU.
        if !cv && self_signed && policy.accept_self_signed {
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

    // Extract leaf fingerprint & subject (if parsable)
    let mut leaf_subject: Option<String> = None;
    if let Some(first) = peer_chain.first() {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(first.as_ref()) {
            leaf_subject = Some(parsed.tbs_certificate.subject.to_string());
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
    if policy.realm_subject_binding {
        if let (Some(r), Some(subj)) = (realm, &leaf_subject) {
            if !subj.contains(&r.name) {
                return TrustDecision::reject(
                    "realm-subject-mismatch",
                    leaf_fp,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                );
            }
        }
    }
    let trusted_fingerprints = trusted_cert_dir.map(load_trusted_fingerprints).transpose();
    let allowlist_error = match (policy.mode, trusted_cert_dir, &trusted_fingerprints) {
        (TrustMode::Allowlist, None, _) => Some("no-trusted-dir"),
        (TrustMode::Allowlist, Some(_), Err(_)) => Some("trusted-dir-unreadable"),
        _ => None,
    };
    let observed_pem = peer_chain.first().map(encode_certificate_pem);
    let observed_artifact = observed_pem.as_deref().map(|pem| ObservedArtifact {
        extension: "pem",
        bytes: pem.as_bytes(),
    });
    let mut decision = evaluate_fingerprint_trust(
        policy,
        FingerprintTrustInput {
            fingerprint: leaf_fp.as_deref(),
            additional_allowlisted_fingerprints: trusted_fingerprints
                .as_ref()
                .ok()
                .and_then(|set| set.as_ref()),
            allowlist_error,
            identity: observed_dir.and(leaf_subject.as_deref()),
            observed_artifact,
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

/// Load approved Noise SHA-256 fingerprints from observed-style artifacts.
pub fn load_noise_fingerprints(dir: &str) -> std::io::Result<HashSet<String>> {
    let mut set = HashSet::new();
    let path = PathBuf::from(dir);
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

/// Ensure observed directory exists
pub fn ensure_observed_dir(dir: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

fn observed_binding_path(dir: &str, identity: &str) -> PathBuf {
    PathBuf::from(dir).join("bindings").join(format!(
        "{}.txt",
        sha256_fingerprint_hex(identity.as_bytes())
    ))
}

pub fn load_observed_fingerprint_binding(
    dir: &str,
    identity: &str,
) -> std::io::Result<Option<String>> {
    let path = observed_binding_path(dir, identity);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("fingerprint=") {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(Some(value.to_ascii_lowercase()));
            }
        }
    }
    let value = content.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_ascii_lowercase()))
    }
}

pub fn store_observed_fingerprint_binding(
    dir: &str,
    identity: &str,
    fingerprint: &str,
    overwrite: bool,
) -> std::io::Result<()> {
    let path = observed_binding_path(dir, identity);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!(
        "fingerprint={}\nidentity={}\n",
        fingerprint.to_ascii_lowercase(),
        identity
    );
    if overwrite {
        return std::fs::write(path, content);
    }
    match create_observed_fingerprint_binding(dir, identity, fingerprint) {
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        result => result,
    }
}

fn create_observed_fingerprint_binding(
    dir: &str,
    identity: &str,
    fingerprint: &str,
) -> std::io::Result<()> {
    let path = observed_binding_path(dir, identity);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!(
        "fingerprint={}\nidentity={}\n",
        fingerprint.to_ascii_lowercase(),
        identity
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(content.as_bytes())
}

pub fn store_observed_artifact(
    dir: &str,
    fingerprint: &str,
    extension: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    ensure_observed_dir(dir)?;
    let path = PathBuf::from(dir).join(format!(
        "{}.{}",
        fingerprint,
        extension.trim_start_matches('.')
    ));
    if path.exists() {
        return Ok(());
    }
    std::fs::write(path, bytes)
}

/// Store a newly observed certificate in PEM form using its fingerprint as filename
pub fn store_observed_cert(dir: &str, fingerprint: &str, pem_bytes: &[u8]) -> std::io::Result<()> {
    store_observed_artifact(dir, fingerprint, "pem", pem_bytes)
}

/// Promote a certificate from observed_dir to trusted_cert_dir by copying the PEM file.
/// Returns Ok(true) if promoted, Ok(false) if source missing or already present in destination.
pub fn promote_observed_to_trusted(
    observed_dir: &str,
    trusted_dir: &str,
    fingerprint: &str,
) -> std::io::Result<bool> {
    let src = PathBuf::from(observed_dir).join(format!("{}.pem", fingerprint));
    if !src.exists() {
        return Ok(false);
    }
    std::fs::create_dir_all(trusted_dir)?;
    let dst = PathBuf::from(trusted_dir).join(format!("{}.pem", fingerprint));
    if dst.exists() {
        return Ok(false);
    }
    let data = std::fs::read(&src)?;
    std::fs::write(&dst, data)?;
    // Emit PromotionEvent via global events handle if available
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

#[cfg(test)]
mod tests {
    use super::{EffectiveTrustPolicy, StoreNew, TrustMode};

    #[test]
    fn reports_fingerprint_pin_match_independently_of_policy_outcome() {
        let policy = EffectiveTrustPolicy {
            mode: TrustMode::Observe,
            accept_self_signed: false,
            store_new: StoreNew::None,
            observed_dir: None,
            reject_expired: false,
            reject_before_valid: false,
            enforce_ca_chain: false,
            allowlist_fingerprints: Vec::new(),
            pin_subjects: Vec::new(),
            pin_fingerprints: vec!["abc123".to_string()],
            pin_fp_algo: "sha256".to_string(),
            realm_subject_binding: false,
        };

        assert_eq!(policy.pinned_fingerprint_match(Some("abc123")), Some(true));
        assert_eq!(policy.pinned_fingerprint_match(Some("def456")), Some(false));
        assert_eq!(policy.pinned_fingerprint_match(None), Some(false));
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
