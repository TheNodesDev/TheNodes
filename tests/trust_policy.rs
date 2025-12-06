use thenodes::security::trust::{
    evaluate_peer_cert_chain, spki_fingerprint, EffectiveTrustPolicy, TrustDecisionOutcome,
};
use tokio_rustls::rustls::pki_types::CertificateDer;

// Minimal dummy DER cert (not a real certificate) just to test fallback hashing path.
const DUMMY_CERT: &[u8] = b"\x30\x03\x02\x01\x01"; // ASN.1 SEQUENCE of INTEGER 1

fn make_policy(open: bool) -> EffectiveTrustPolicy {
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some(if open {
                "open".into()
            } else {
                "allowlist".into()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    EffectiveTrustPolicy::from_config(&enc)
}

#[test]
fn spki_fingerprint_fallback_hashes() {
    let fp1 = spki_fingerprint(&CertificateDer::from(DUMMY_CERT.to_vec())).expect("fp");
    let fp2 = spki_fingerprint(&CertificateDer::from(DUMMY_CERT.to_vec())).expect("fp2");
    assert_eq!(
        fp1, fp2,
        "fingerprint must be deterministic for identical input"
    );
}

#[test]
fn open_mode_accepts_dummy_cert() {
    let policy = make_policy(true);
    let dummy = CertificateDer::from(DUMMY_CERT.to_vec());
    let decision = evaluate_peer_cert_chain(&policy, None, None, &[dummy], None);
    assert!(matches!(decision.outcome, TrustDecisionOutcome::Accept));
}

#[test]
fn fingerprint_pin_enforced() {
    let dummy = CertificateDer::from(DUMMY_CERT.to_vec());
    let fp = spki_fingerprint(&dummy).unwrap();
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some("open".into()),
            pin_fingerprints: Some(vec![fp.clone()]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let policy = EffectiveTrustPolicy::from_config(&enc);
    let decision =
        evaluate_peer_cert_chain(&policy, None, None, std::slice::from_ref(&dummy), None);
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Accept,
        "expected accept when fingerprint pinned"
    );

    // Now mismatch
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some("open".into()),
            pin_fingerprints: Some(vec!["deadbeef".into()]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let policy2 = EffectiveTrustPolicy::from_config(&enc);
    let decision2 = evaluate_peer_cert_chain(&policy2, None, None, &[dummy], None);
    assert_eq!(
        decision2.outcome,
        TrustDecisionOutcome::Reject,
        "expected reject on fingerprint mismatch"
    );
}

#[test]
fn subject_pin_unparsed_rejects() {
    // Our dummy cert cannot be parsed -> expect subject-unparsed when pins set
    let dummy = CertificateDer::from(DUMMY_CERT.to_vec());
    let enc = thenodes::config::EncryptionConfig {
        trust_policy: Some(thenodes::config::TrustPolicyConfig {
            mode: Some("open".into()),
            pin_subjects: Some(vec!["CN=Test".into()]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let policy = EffectiveTrustPolicy::from_config(&enc);
    let decision = evaluate_peer_cert_chain(&policy, None, None, &[dummy], None);
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Reject,
        "expected reject due to unparsed subject with pins set"
    );
}
