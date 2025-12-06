use thenodes::security::trust::{
    evaluate_peer_cert_chain, spki_fingerprint, EffectiveTrustPolicy, TrustDecisionOutcome,
};
use tokio_rustls::rustls::pki_types::CertificateDer;

// Simple dummy cert (non-compliant) to exercise pin logic — fingerprint fallback path.
const DUMMY_CERT: &[u8] = b"\x30\x03\x02\x01\x01";

// removed: base_policy was unused after struct-literal refactors

#[test]
fn fingerprint_pin_match_accepts() {
    let fp = spki_fingerprint(&CertificateDer::from(DUMMY_CERT.to_vec())).unwrap();
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some("open".into()),
            pin_fingerprints: Some(vec![fp.clone()]),
            ..Default::default()
        }),
        ..Default::default()
    };
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
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some("open".into()),
            pin_fingerprints: Some(vec!["deadbeef".into()]),
            ..Default::default()
        }),
        ..Default::default()
    };
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
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some("open".into()),
            pin_subjects: Some(vec![String::from('X')]),
            ..Default::default()
        }),
        ..Default::default()
    };
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
