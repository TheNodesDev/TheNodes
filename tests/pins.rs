use thenodes::security::trust::{
    evaluate_peer_cert_chain, spki_fingerprint, EffectiveTrustPolicy, TrustDecisionOutcome,
};
use tokio_rustls::rustls::pki_types::CertificateDer;

// Simple dummy cert (non-compliant) to exercise pin logic — fingerprint fallback path.
const DUMMY_CERT: &[u8] = b"\x30\x03\x02\x01\x01";

fn base_policy() -> thenodes::config::EncryptionConfig {
    let mut enc = thenodes::config::EncryptionConfig::default();
    let mut tp = thenodes::config::TrustPolicyConfig::default();
    tp.mode = Some("open".to_string());
    enc.trust_policy = Some(tp);
    enc
}

#[test]
fn fingerprint_pin_match_accepts() {
    let mut enc = base_policy();
    // Compute fp
    let fp = spki_fingerprint(&CertificateDer::from(DUMMY_CERT.to_vec())).unwrap();
    if let Some(tp) = &mut enc.trust_policy {
        tp.pin_fingerprints = Some(vec![fp.clone()]);
    }
    let policy = EffectiveTrustPolicy::from_config(&enc);
    let decision = evaluate_peer_cert_chain(
        &policy,
        None,
        None,
        &[CertificateDer::from(DUMMY_CERT.to_vec())],
        None,
    );
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Accept,
        "expected accept with matching pin"
    );
}

#[test]
fn fingerprint_pin_mismatch_rejects() {
    let mut enc = base_policy();
    if let Some(tp) = &mut enc.trust_policy {
        tp.pin_fingerprints = Some(vec!["deadbeef".into()]);
    }
    let policy = EffectiveTrustPolicy::from_config(&enc);
    let decision = evaluate_peer_cert_chain(
        &policy,
        None,
        None,
        &[CertificateDer::from(DUMMY_CERT.to_vec())],
        None,
    );
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Reject,
        "expected reject on pin mismatch"
    );
}

#[test]
fn subject_pin_mismatch_rejects() {
    let mut enc = base_policy();
    if let Some(tp) = &mut enc.trust_policy {
        tp.pin_subjects = Some(vec!['X'.to_string()]);
    }
    let policy = EffectiveTrustPolicy::from_config(&enc);
    let decision = evaluate_peer_cert_chain(
        &policy,
        None,
        None,
        &[CertificateDer::from(DUMMY_CERT.to_vec())],
        None,
    );
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Reject,
        "expected reject because subject not parsed or not matched"
    );
}
