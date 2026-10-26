use std::fs;

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SignatureAlgorithm,
};
use tempfile::TempDir;
use thenodes::config::{Config, EncryptionConfig, EncryptionPaths, TrustPolicyConfig};
use thenodes::realms::RealmInfo;
use thenodes::security::encryption::{extract_validity_windows, validate_certificate_chain};
use thenodes::security::secure_channel::{SecureChannel, TlsSecureChannel};
use thenodes::security::trust::{
    evaluate_peer_cert_chain_for_usage, CertificateUsage, EffectiveTrustPolicy,
    TrustDecisionOutcome,
};
use tokio_rustls::rustls::pki_types::CertificateDer;

struct CertificateAuthority {
    certificate: Certificate,
    key: KeyPair,
}

fn certificate_authority(common_name: &str) -> CertificateAuthority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2040, 1, 1);
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    CertificateAuthority { certificate, key }
}

fn intermediate_authority(
    common_name: &str,
    issuer: &CertificateAuthority,
) -> CertificateAuthority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time_ymd(2021, 1, 1);
    params.not_after = date_time_ymd(2039, 1, 1);
    let key = KeyPair::generate().unwrap();
    let certificate = params
        .signed_by(&key, &issuer.certificate, &issuer.key)
        .unwrap();
    CertificateAuthority { certificate, key }
}

fn leaf_certificate(
    issuer: &CertificateAuthority,
    usage: ExtendedKeyUsagePurpose,
    not_before_year: i32,
    not_after_year: i32,
) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(vec!["node.thenodes.test".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "node.thenodes.test");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    params.not_before = date_time_ymd(not_before_year, 1, 1);
    params.not_after = date_time_ymd(not_after_year, 1, 1);
    let key = KeyPair::generate().unwrap();
    params
        .signed_by(&key, &issuer.certificate, &issuer.key)
        .unwrap()
        .der()
        .clone()
}

fn self_signed_leaf() -> CertificateDer<'static> {
    let mut params = CertificateParams::new(vec!["self.thenodes.test".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "self.thenodes.test");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2040, 1, 1);
    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().clone()
}

/// Uncompressed P-384 point of `EMOVTLSCAG3B`, one of the eMudhra intermediate
/// CA keys on rustls-webpki's distrusted SPKI list.
const DISTRUSTED_EMUDHRA_KEY: &str = concat!(
    "0473897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac",
    "280c5e05638ae7a2acd71c322a8e361cdeb9f69c4302b9dd8d73d1cc6caab2cc",
    "0aee4e216ce979dd518a4af4b626e5684cdd658037ed0c854e4cc12f4cf8646d",
    "0d",
);

struct DistrustedPublicKey(Vec<u8>);

impl PublicKeyData for DistrustedPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P384_SHA384
    }
}

/// Issues a leaf for the distrusted eMudhra key. The test has no private key
/// for it, so the leaf is signed by `issuer`.
fn distrusted_key_leaf(
    issuer: &CertificateAuthority,
    common_name: &str,
) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = date_time_ymd(2022, 1, 1);
    params.not_after = date_time_ymd(2038, 1, 1);
    let key = DistrustedPublicKey(hex::decode(DISTRUSTED_EMUDHRA_KEY).unwrap());
    params
        .signed_by(&key, &issuer.certificate, &issuer.key)
        .unwrap()
        .der()
        .clone()
}

fn trust_anchor_directory(ca: &CertificateAuthority) -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("root.pem"), ca.certificate.pem()).unwrap();
    directory
}

fn policy(
    enforce_ca_chain: bool,
    reject_expired: bool,
    reject_before_valid: bool,
    accept_self_signed: bool,
) -> EffectiveTrustPolicy {
    EffectiveTrustPolicy::from_config(&EncryptionConfig {
        trust_policy: Some(TrustPolicyConfig {
            mode: Some("open".to_string()),
            enforce_ca_chain: Some(enforce_ca_chain),
            reject_expired: Some(reject_expired),
            reject_before_valid: Some(reject_before_valid),
            accept_self_signed: Some(accept_self_signed),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn evaluate(
    policy: &EffectiveTrustPolicy,
    trust_anchor_dir: Option<&str>,
    chain: &[CertificateDer<'_>],
    usage: CertificateUsage,
) -> thenodes::security::trust::TrustDecision {
    evaluate_peer_cert_chain_for_usage(policy, None, trust_anchor_dir, None, chain, None, usage)
}

#[test]
fn accepts_a_cryptographically_valid_chain_with_an_intermediate() {
    let root = certificate_authority("TheNodes test root");
    let intermediate = intermediate_authority("TheNodes test intermediate", &root);
    let leaf = leaf_certificate(
        &intermediate,
        ExtendedKeyUsagePurpose::ServerAuth,
        2022,
        2038,
    );
    let roots = trust_anchor_directory(&root);
    let chain = [leaf, intermediate.certificate.der().clone()];

    let decision = evaluate(
        &policy(true, false, false, false),
        roots.path().to_str(),
        &chain,
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Accept);
    assert_eq!(decision.chain_valid, Some(true));
    assert_eq!(decision.chain_reason.as_deref(), Some("webpki-path-valid"));
}

#[test]
fn rejects_a_chain_signed_by_an_unknown_issuer() {
    let trusted_root = certificate_authority("Trusted root");
    let unknown_root = certificate_authority("Unknown root");
    let leaf = leaf_certificate(
        &unknown_root,
        ExtendedKeyUsagePurpose::ServerAuth,
        2022,
        2038,
    );
    let roots = trust_anchor_directory(&trusted_root);

    let decision = evaluate(
        &policy(true, false, false, false),
        roots.path().to_str(),
        &[leaf],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(decision.reason, "chain-invalid");
    assert_eq!(decision.chain_valid, Some(false));
    assert_eq!(decision.chain_reason.as_deref(), Some("unknown-issuer"));
}

#[test]
fn rejects_a_tampered_certificate_signature() {
    let root = certificate_authority("Trusted root");
    let leaf = leaf_certificate(&root, ExtendedKeyUsagePurpose::ServerAuth, 2022, 2038);
    let mut tampered = leaf.as_ref().to_vec();
    let last = tampered.last_mut().unwrap();
    *last ^= 0x01;
    let roots = trust_anchor_directory(&root);

    let decision = evaluate(
        &policy(true, false, false, false),
        roots.path().to_str(),
        &[CertificateDer::from(tampered)],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(decision.reason, "chain-invalid");
    assert_eq!(decision.chain_valid, Some(false));
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("invalid-certificate-signature")
    );
}

#[test]
fn reports_an_unsupported_signature_algorithm_as_a_stable_reason() {
    const ECDSA_WITH_SHA256: [u8; 10] =
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let root = certificate_authority("Trusted root");
    let leaf = leaf_certificate(&root, ExtendedKeyUsagePurpose::ServerAuth, 2022, 2038);
    // Relabel both signature algorithm fields as ecdsa-with-SHA224, which
    // webpki does not support.
    let mut relabeled = leaf.as_ref().to_vec();
    let positions: Vec<usize> = relabeled
        .windows(ECDSA_WITH_SHA256.len())
        .enumerate()
        .filter(|(_, window)| *window == ECDSA_WITH_SHA256)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 2);
    for position in positions {
        relabeled[position + ECDSA_WITH_SHA256.len() - 1] = 0x01;
    }
    let roots = trust_anchor_directory(&root);

    let decision = evaluate(
        &policy(true, false, false, false),
        roots.path().to_str(),
        &[CertificateDer::from(relabeled)],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("unsupported-signature-algorithm")
    );
}

#[test]
fn enforces_the_certificate_tls_role() {
    let root = certificate_authority("Trusted root");
    let server_leaf = leaf_certificate(&root, ExtendedKeyUsagePurpose::ServerAuth, 2022, 2038);
    let roots = trust_anchor_directory(&root);

    let decision = evaluate(
        &policy(true, false, false, false),
        roots.path().to_str(),
        &[server_leaf],
        CertificateUsage::ClientAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("required-eku-not-found")
    );
}

#[test]
fn accepts_a_validly_self_signed_leaf_only_with_explicit_override() {
    let leaf = self_signed_leaf();
    let decision = evaluate(
        &policy(true, false, false, true),
        None,
        &[leaf],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Accept);
    assert_eq!(decision.chain_valid, Some(true));
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("self-signed-override")
    );
}

#[test]
fn rejects_a_self_signed_override_with_a_tampered_signature() {
    let leaf = self_signed_leaf();
    let mut tampered = leaf.as_ref().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    let decision = evaluate(
        &policy(true, false, false, true),
        None,
        &[CertificateDer::from(tampered)],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(decision.reason, "chain-invalid");
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("self-signed-signature-invalid")
    );
}

#[test]
fn rejects_a_leaf_with_a_distrusted_public_key() {
    let root = certificate_authority("Trusted root");
    let leaf = distrusted_key_leaf(&root, "node.thenodes.test");
    let roots = trust_anchor_directory(&root);

    let decision = evaluate(
        &policy(true, false, false, false),
        roots.path().to_str(),
        &[leaf],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(decision.reason, "chain-invalid");
    assert_eq!(decision.chain_valid, Some(false));
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("certificate-distrusted")
    );
}

#[test]
fn does_not_apply_the_self_signed_override_to_a_distrusted_key() {
    let root = certificate_authority("Distrusted peer");
    // Subject equals issuer, so the override treats the leaf as self-signed.
    let leaf = distrusted_key_leaf(&root, "Distrusted peer");
    let roots = trust_anchor_directory(&root);

    let decision = evaluate(
        &policy(true, false, false, true),
        roots.path().to_str(),
        &[leaf],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(decision.reason, "chain-invalid");
    assert_eq!(
        decision.chain_reason.as_deref(),
        Some("certificate-distrusted")
    );
}

#[test]
fn validates_certificate_chain_time_at_a_fixed_instant() {
    let root = certificate_authority("Trusted root");
    let roots = trust_anchor_directory(&root);
    let now = std::time::UNIX_EPOCH
        + std::time::Duration::from_secs(
            date_time_ymd(2026, 1, 1)
                .unix_timestamp()
                .try_into()
                .unwrap(),
        );

    for (not_before_year, not_after_year, expected_valid, expected_reason) in [
        (2022, 2038, true, "webpki-path-valid"),
        (2022, 2023, false, "certificate-expired"),
        (2030, 2038, false, "certificate-not-yet-valid"),
    ] {
        let leaf = leaf_certificate(
            &root,
            ExtendedKeyUsagePurpose::ServerAuth,
            not_before_year,
            not_after_year,
        );
        let (valid, reason, self_signed) = validate_certificate_chain(
            &[leaf],
            roots.path().to_str(),
            CertificateUsage::ServerAuth,
            now,
        );

        assert_eq!(
            valid, expected_valid,
            "validity window: {not_before_year}..{not_after_year}"
        );
        assert_eq!(reason, expected_reason);
        assert!(!self_signed);
    }
}

#[test]
fn rejects_expired_and_not_yet_valid_leaf_certificates_when_configured() {
    let root = certificate_authority("Trusted root");
    let expired = leaf_certificate(&root, ExtendedKeyUsagePurpose::ServerAuth, 2000, 2001);
    let future = leaf_certificate(&root, ExtendedKeyUsagePurpose::ServerAuth, 2090, 2091);

    let expired_decision = evaluate(
        &policy(false, true, false, false),
        None,
        &[expired],
        CertificateUsage::ServerAuth,
    );
    assert_eq!(expired_decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(expired_decision.reason, "time-invalid");
    assert_eq!(expired_decision.time_reason.as_deref(), Some("expired"));

    let future_decision = evaluate(
        &policy(false, false, true, false),
        None,
        &[future],
        CertificateUsage::ServerAuth,
    );
    assert_eq!(future_decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(future_decision.reason, "time-invalid");
    assert_eq!(
        future_decision.time_reason.as_deref(),
        Some("not-yet-valid")
    );
}

#[test]
fn validity_enforcement_fails_closed_for_malformed_certificates() {
    let malformed = CertificateDer::from(b"not a certificate".to_vec());
    let decision = evaluate(
        &policy(false, true, true, false),
        None,
        &[malformed],
        CertificateUsage::ServerAuth,
    );

    assert_eq!(decision.outcome, TrustDecisionOutcome::Reject);
    assert_eq!(decision.reason, "time-invalid");
    assert_eq!(
        decision.time_reason.as_deref(),
        Some("validity-unparseable")
    );
}

#[test]
fn extracts_real_x509_validity_windows() {
    let root = certificate_authority("Trusted root");
    let leaf = leaf_certificate(&root, ExtendedKeyUsagePurpose::ServerAuth, 2022, 2038);

    let (not_before, not_after) = extract_validity_windows(leaf.as_ref()).unwrap();
    assert!(not_before < not_after);
    assert_eq!(not_before, 1_640_995_200);
    assert_eq!(not_after, 2_145_916_800);
}

#[tokio::test]
async fn tls_and_mtls_apply_the_role_aware_policy_after_handshake() {
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("node.pem");
    let key_path = directory.path().join("node.key.pem");

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "TheNodes handshake test");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2040, 1, 1);
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    fs::write(&cert_path, certificate.pem()).unwrap();
    fs::write(&key_path, key.serialize_pem()).unwrap();

    let config = Config {
        encryption: Some(EncryptionConfig {
            enabled: true,
            backend: Some("tls".to_string()),
            mtls: Some(true),
            paths: Some(EncryptionPaths {
                own_certificate: Some(cert_path.to_string_lossy().into_owned()),
                own_private_key: Some(key_path.to_string_lossy().into_owned()),
                ..Default::default()
            }),
            trust_policy: Some(TrustPolicyConfig {
                mode: Some("open".to_string()),
                accept_self_signed: Some(true),
                enforce_ca_chain: Some(true),
                reject_expired: Some(true),
                reject_before_valid: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let realm = RealmInfo::new("trust-test", "1.0");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_config = config.clone();
    let server_realm = realm.clone();
    let server = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        TlsSecureChannel::new()
            .accept(stream, peer_addr, &server_realm, &server_config, false)
            .await
    });

    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let client = TlsSecureChannel::new()
        .connect(stream, address, &realm, &config, false)
        .await;
    let server = server.await.unwrap();

    assert!(client.is_ok(), "client policy rejected: {:?}", client.err());
    assert!(server.is_ok(), "server policy rejected: {:?}", server.err());
}
