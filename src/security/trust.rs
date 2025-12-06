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
use std::path::Path;
use std::path::PathBuf;
use tokio_rustls::rustls::pki_types::CertificateDer;
use std::str::FromStr;

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
    pub pin_subjects: Vec<String>,
    pub pin_fingerprints: Vec<String>,
    pub pin_fp_algo: String,
    pub realm_subject_binding: bool,
}

impl EffectiveTrustPolicy {
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
            let pin_fingerprints = tp.pin_fingerprints.clone().unwrap_or_default();
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
                pin_subjects,
                pin_fingerprints,
                pin_fp_algo,
                realm_subject_binding,
            }
        } else {
            // Default open / no store
            Self {
                mode: TrustMode::Open,
                accept_self_signed: false,
                store_new: StoreNew::None,
                observed_dir: None,
                reject_expired: false,
                reject_before_valid: false,
                enforce_ca_chain: false,
                pin_subjects: vec![],
                pin_fingerprints: vec![],
                pin_fp_algo: "sha256".into(),
                realm_subject_binding: false,
            }
        }
    }
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
}

/// Evaluate peer certificate chain according to effective policy.
/// Expects leaf first. Currently only leaf fingerprint matters (Phase 1).
pub fn evaluate_peer_cert_chain(
    policy: &EffectiveTrustPolicy,
    trusted_cert_dir: Option<&str>,
    observed_dir: Option<&str>,
    peer_chain: &[CertificateDer<'_>],
    realm: Option<&crate::realms::RealmInfo>,
) -> TrustDecision {
    // Placeholder chain/time validation (Phase 2 scaffolding)
    use crate::security::encryption::{extract_validity_windows, validate_chain_simple};
    let mut chain_valid: Option<bool> = None;
    let mut chain_reason: Option<String> = None;
    let mut time_valid: Option<bool> = None;
    let mut time_reason: Option<String> = None;
    let issuer_dir = trusted_cert_dir; // reuse trusted dir as issuer roots fallback (issuer_cert_dir not yet distinct in config usage here)
    let (cv, creason, self_signed) = validate_chain_simple(peer_chain, issuer_dir);
    if policy.enforce_ca_chain {
        chain_valid = Some(cv);
        chain_reason = Some(creason.clone());
    } else if !peer_chain.is_empty() {
        chain_valid = Some(true);
        chain_reason = Some("not-enforced".into());
    }
    // If chain invalid and self-signed allowed, override
    if policy.enforce_ca_chain
        && chain_valid == Some(false)
        && self_signed
        && policy.accept_self_signed
    {
        chain_valid = Some(true);
        chain_reason = Some("self-signed-override".into());
    }
    // Time validity
    if let Some(leaf) = peer_chain.first() {
        if let Some((nb, na)) = extract_validity_windows(leaf.as_ref()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let mut ok = true;
            if policy.reject_before_valid && now < nb {
                ok = false;
                time_reason = Some("not-yet-valid".into());
            }
            if policy.reject_expired && now > na {
                ok = false;
                time_reason = Some("expired".into());
            }
            if ok {
                time_reason = Some("valid".into());
            }
            time_valid = Some(ok);
            if policy.reject_before_valid && now < nb {
                return TrustDecision::reject(
                    "time-invalid",
                    None,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                );
            }
            if policy.reject_expired && now > na {
                return TrustDecision::reject(
                    "time-invalid",
                    None,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                );
            }
        } else if policy.reject_before_valid || policy.reject_expired {
            // Could not parse validity; be permissive (treat as valid) but note reason.
            time_valid = Some(true);
            time_reason = Some("unparsed".into());
        }
    }
    if policy.enforce_ca_chain && chain_valid == Some(false) {
        return TrustDecision::reject(
            "chain-invalid",
            None,
            chain_valid,
            time_valid,
            chain_reason,
            time_reason,
        );
    }

    // Extract leaf fingerprint & subject (if parsable)
    let leaf_fp = peer_chain.first().and_then(spki_fingerprint);
    let mut leaf_subject: Option<String> = None;
    if let Some(first) = peer_chain.first() {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(first.as_ref()) {
            leaf_subject = Some(parsed.tbs_certificate.subject.to_string());
        }
    }

    // Phase 3: pin enforcement (subject & fingerprint) before mode logic
    if !policy.pin_fingerprints.is_empty() {
        if let Some(ref fp) = leaf_fp {
            if !policy.pin_fingerprints.iter().any(|p| p == fp) {
                return TrustDecision::reject(
                    "fp-pin-mismatch",
                    leaf_fp,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                );
            }
        } else {
            return TrustDecision::reject(
                "fp-missing",
                None,
                chain_valid,
                time_valid,
                chain_reason,
                time_reason,
            );
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
    let fp_ref = leaf_fp.clone();
    match policy.mode {
        TrustMode::Open => {
            // Optionally store (Observed) only if we have a leaf and policy asks for it
            let mut stored = false;
            if policy.store_new == StoreNew::Observed {
                if let (Some(dir), Some(fp), Some(first)) =
                    (observed_dir, leaf_fp.as_ref(), peer_chain.first())
                {
                    // Write simple PEM if not already
                    let pem_body = base64::engine::general_purpose::STANDARD.encode(first.as_ref());
                    let pem = format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                        pem_body
                    );
                    if store_observed_cert(dir, fp, pem.as_bytes()).is_ok() {
                        stored = true;
                    }
                }
            }
            TrustDecision::accept(
                "open-policy",
                fp_ref,
                stored,
                chain_valid,
                time_valid,
                chain_reason,
                time_reason,
            )
        }
        TrustMode::Allowlist => {
            if let Some(dir) = trusted_cert_dir {
                if let Some(fp) = leaf_fp.as_ref() {
                    if let Ok(set) = load_trusted_fingerprints(dir) {
                        if set.contains(fp) {
                            TrustDecision::accept(
                                "present-in-trusted",
                                fp_ref,
                                false,
                                chain_valid,
                                time_valid,
                                chain_reason,
                                time_reason,
                            )
                        } else {
                            if policy.store_new == StoreNew::Observed {
                                if let (Some(obs_dir), Some(first)) =
                                    (observed_dir, peer_chain.first())
                                {
                                    let pem_body = base64::engine::general_purpose::STANDARD
                                        .encode(first.as_ref());
                                    let pem = format!(
                                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                                        pem_body
                                    );
                                    let _ = store_observed_cert(obs_dir, fp, pem.as_bytes());
                                }
                            }
                            TrustDecision::reject(
                                "not-in-trusted",
                                fp_ref,
                                chain_valid,
                                time_valid,
                                chain_reason,
                                time_reason,
                            )
                        }
                    } else {
                        if policy.store_new == StoreNew::Observed {
                            if let (Some(obs_dir), Some(first)) = (observed_dir, peer_chain.first())
                            {
                                if let Some(fp_inner) = fp_ref.as_ref() {
                                    let pem_body = base64::engine::general_purpose::STANDARD
                                        .encode(first.as_ref());
                                    let pem = format!(
                                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                                        pem_body
                                    );
                                    let _ = store_observed_cert(obs_dir, fp_inner, pem.as_bytes());
                                }
                            }
                        }
                        TrustDecision::reject(
                            "trusted-dir-unreadable",
                            fp_ref,
                            chain_valid,
                            time_valid,
                            chain_reason,
                            time_reason,
                        )
                    }
                } else {
                    TrustDecision::reject(
                        "no-leaf-cert",
                        None,
                        chain_valid,
                        time_valid,
                        chain_reason,
                        time_reason,
                    )
                }
            } else {
                TrustDecision::reject(
                    "no-trusted-dir",
                    fp_ref,
                    chain_valid,
                    time_valid,
                    chain_reason,
                    time_reason,
                )
            }
        }
        TrustMode::Tofu => {
            if let Some(fp) = leaf_fp.as_ref() {
                let mut seen = false;
                if let Some(dir) = trusted_cert_dir {
                    if let Ok(set) = load_trusted_fingerprints(dir) {
                        if set.contains(fp) {
                            seen = true;
                        }
                    }
                }
                if seen {
                    return TrustDecision::accept(
                        "seen-before",
                        fp_ref,
                        false,
                        chain_valid,
                        time_valid,
                        chain_reason,
                        time_reason,
                    );
                } else {
                    // New key; optionally store observed
                    let mut stored = false;
                    if policy.store_new == StoreNew::Observed {
                        if let (Some(dir), Some(first)) = (observed_dir, peer_chain.first()) {
                            let pem_body =
                                base64::engine::general_purpose::STANDARD.encode(first.as_ref());
                            let pem = format!(
                                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                                pem_body
                            );
                            if store_observed_cert(dir, fp, pem.as_bytes()).is_ok() {
                                stored = true;
                            }
                        }
                    }
                    return TrustDecision::accept(
                        "new-tofu",
                        fp_ref,
                        stored,
                        chain_valid,
                        time_valid,
                        chain_reason,
                        time_reason,
                    );
                }
            }
            TrustDecision::reject(
                "no-leaf-cert",
                None,
                chain_valid,
                time_valid,
                chain_reason,
                time_reason,
            )
        }
        TrustMode::HybridPlaceholder => {
            // For now treat as open but note placeholder status
            let mut stored = false;
            if policy.store_new == StoreNew::Observed {
                if let (Some(dir), Some(fp), Some(first)) = (
                    observed_dir,
                    peer_chain.first().and_then(spki_fingerprint).as_ref(),
                    peer_chain.first(),
                ) {
                    let pem_body = base64::engine::general_purpose::STANDARD.encode(first.as_ref());
                    let pem = format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                        pem_body
                    );
                    if store_observed_cert(dir, fp, pem.as_bytes()).is_ok() {
                        stored = true;
                    }
                }
            }
            TrustDecision::accept(
                "hybrid-placeholder-open",
                leaf_fp,
                stored,
                chain_valid,
                time_valid,
                chain_reason,
                time_reason,
            )
        }
        TrustMode::Observe => {
            let mut stored = false;
            if let (Some(dir), Some(fp), Some(first)) =
                (observed_dir, leaf_fp.as_ref(), peer_chain.first())
            {
                let pem_body = base64::engine::general_purpose::STANDARD.encode(first.as_ref());
                let pem = format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    pem_body
                );
                if store_observed_cert(dir, fp, pem.as_bytes()).is_ok() {
                    stored = true;
                }
            }
            TrustDecision {
                outcome: TrustDecisionOutcome::Reject,
                reason: "observe-only",
                fingerprint: leaf_fp,
                stored,
                chain_valid,
                time_valid,
                chain_reason,
                time_reason,
            }
        }
    }
}

/// Extract SHA-256 fingerprint of certificate SubjectPublicKeyInfo (SPKI)
pub fn spki_fingerprint(cert: &CertificateDer<'_>) -> Option<String> {
    let der = cert.as_ref();
    // First try proper parse using x509-parser for SPKI
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, parsed)) => {
            let spki = parsed.tbs_certificate.subject_pki.raw;
            let mut h = Sha256::new();
            h.update(spki);
            Some(encode_string(&h.finalize()))
        }
        Err(_) => {
            // Fallback: hash full DER so we still have a stable identifier
            let mut h = Sha256::new();
            h.update(der);
            Some(encode_string(&h.finalize()))
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

/// Ensure observed directory exists
pub fn ensure_observed_dir(dir: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Store a newly observed certificate in PEM form using its fingerprint as filename
pub fn store_observed_cert(dir: &str, fingerprint: &str, pem_bytes: &[u8]) -> std::io::Result<()> {
    ensure_observed_dir(dir)?;
    let path = PathBuf::from(dir).join(format!("{}.pem", fingerprint));
    if path.exists() {
        return Ok(());
    }
    std::fs::write(path, pem_bytes)
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
