use thenodes::security::trust::{
    evaluate_peer_cert_chain_for_usage, spki_fingerprint, CertificateUsage, EffectiveTrustPolicy,
    TrustDecisionOutcome,
};
use tokio_rustls::rustls::pki_types::CertificateDer;

// Minimal dummy DER cert (not a real certificate) just to test fallback hashing path.
const DUMMY_CERT: &[u8] = b"\x30\x03\x02\x01\x01"; // ASN.1 SEQUENCE of INTEGER 1

fn make_policy(open: bool) -> EffectiveTrustPolicy {
    let enc = thenodes::config::EncryptionConfig {
        tls: Some(thenodes::config::EncryptionTlsConfig {
            trust_policy: Some(thenodes::config::TlsTrustPolicyConfig {
                mode: Some(if open {
                    "open".into()
                } else {
                    "allowlist".into()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    EffectiveTrustPolicy::from_tls_config(enc.tls.as_ref())
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
    let decision =
        evaluate_peer_cert_chain_for_usage(&policy, None, &[dummy], None, CertificateUsage::Either);
    assert!(matches!(decision.outcome, TrustDecisionOutcome::Accept));
}

#[test]
fn fingerprint_pin_enforced() {
    let dummy = CertificateDer::from(DUMMY_CERT.to_vec());
    let fp = spki_fingerprint(&dummy).unwrap();
    let enc = thenodes::config::EncryptionConfig {
        tls: Some(thenodes::config::EncryptionTlsConfig {
            trust_policy: Some(thenodes::config::TlsTrustPolicyConfig {
                mode: Some("open".into()),
                pin_fingerprints: Some(vec![fp.clone()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let policy = EffectiveTrustPolicy::from_tls_config(enc.tls.as_ref());
    let decision = evaluate_peer_cert_chain_for_usage(
        &policy,
        None,
        std::slice::from_ref(&dummy),
        None,
        CertificateUsage::Either,
    );
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Accept,
        "expected accept when fingerprint pinned"
    );

    // Now mismatch
    let enc = thenodes::config::EncryptionConfig {
        tls: Some(thenodes::config::EncryptionTlsConfig {
            trust_policy: Some(thenodes::config::TlsTrustPolicyConfig {
                mode: Some("open".into()),
                pin_fingerprints: Some(vec!["deadbeef".into()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let policy2 = EffectiveTrustPolicy::from_tls_config(enc.tls.as_ref());
    let decision2 = evaluate_peer_cert_chain_for_usage(
        &policy2,
        None,
        &[dummy],
        None,
        CertificateUsage::Either,
    );
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
        tls: Some(thenodes::config::EncryptionTlsConfig {
            trust_policy: Some(thenodes::config::TlsTrustPolicyConfig {
                mode: Some("open".into()),
                pin_subjects: Some(vec!["CN=Test".into()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let policy = EffectiveTrustPolicy::from_tls_config(enc.tls.as_ref());
    let decision =
        evaluate_peer_cert_chain_for_usage(&policy, None, &[dummy], None, CertificateUsage::Either);
    assert_eq!(
        decision.outcome,
        TrustDecisionOutcome::Reject,
        "expected reject due to unparsed subject with pins set"
    );
}

fn certificate_naming(uris: &[&str]) -> CertificateDer<'static> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    for uri in uris {
        params
            .subject_alt_names
            .push(rcgen::SanType::URI((*uri).try_into().unwrap()));
    }
    // The realm in the subject, which the setting this one replaced looked for.
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Railway Net");
    let key = rcgen::KeyPair::generate().unwrap();
    CertificateDer::from(params.self_signed(&key).unwrap().der().to_vec())
}

/// `require_realm_node_name` accepts a certificate only if it names a node in
/// this node's realm (ADR-0012). It replaced `realm_subject_binding`, which
/// only looked for the realm name in the subject.
#[test]
fn require_realm_node_name_accepts_only_names_in_this_realm() {
    let realm = thenodes::realms::RealmInfo::new("Railway Net", "1");
    let policy =
        EffectiveTrustPolicy::from_tls_config(Some(&thenodes::config::EncryptionTlsConfig {
            trust_policy: Some(thenodes::config::TlsTrustPolicyConfig {
                mode: Some("open".into()),
                require_realm_node_name: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }));
    let decide = |certificate: CertificateDer<'static>, realm| {
        evaluate_peer_cert_chain_for_usage(
            &policy,
            None,
            &[certificate],
            realm,
            CertificateUsage::Either,
        )
    };

    let named = decide(
        certificate_naming(&["node://railway-net/node-a"]),
        Some(&realm),
    );
    assert!(
        matches!(named.outcome, TrustDecisionOutcome::Accept),
        "{}",
        named.reason
    );

    for (uris, realm) in [
        (&["node://other-net/node-a"][..], Some(&realm)),
        (&[][..], Some(&realm)),
        (&["node://railway-net/node-a"][..], None),
    ] {
        let decision = decide(certificate_naming(uris), realm);
        assert!(
            matches!(decision.outcome, TrustDecisionOutcome::Reject),
            "{uris:?}"
        );
        assert_eq!(decision.reason, "realm-node-name-missing");
    }
}
