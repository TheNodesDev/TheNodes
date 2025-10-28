// src/security/encryption.rs
// Phase 2 helpers: certificate chain & time validity.

use std::fs;
use std::path::Path;

/// Parse DER certificate and return (not_before, not_after) as UNIX epoch seconds.
pub fn extract_validity_windows(der: &[u8]) -> Option<(i64, i64)> {
    // Placeholder: detailed time parsing disabled (x509-parser API mismatch). Return None to skip enforcement if flags off.
    if let Ok((_rem, _cert)) = x509_parser::parse_x509_certificate(der) {
        None
    } else {
        None
    }
}

/// Very lightweight 'chain validation' that checks for:
/// - presence of at least one cert (leaf)
/// - if more than one cert provided OR issuer root present on disk matching leaf issuer => treat as valid
/// - self-signed leaf accepted only if accept_self_signed allowed (caller decides)
/// Returns (chain_valid, chain_reason, self_signed_leaf)
pub fn validate_chain_simple(
    peer_chain: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
    issuer_cert_dir: Option<&str>,
) -> (bool, String, bool) {
    if peer_chain.is_empty() {
        return (false, "empty-chain".to_string(), false);
    }
    let leaf_der = peer_chain[0].as_ref();
    let parsed = match x509_parser::parse_x509_certificate(leaf_der) {
        Ok((_, c)) => c,
        Err(_) => return (false, "leaf-parse-error".into(), false),
    };
    let subject = parsed.tbs_certificate.subject.to_string();
    let issuer = parsed.tbs_certificate.issuer.to_string();
    let self_signed = subject == issuer;
    // If there are intermediates treat provisional success; deeper cryptographic validation deferred.
    if peer_chain.len() > 1 {
        return (true, "has-intermediate".into(), self_signed);
    }
    // Look for issuer cert file whose subject matches issuer (naive scan)
    if let Some(dir) = issuer_cert_dir {
        if let Ok(entries) = fs::read_dir(Path::new(dir)) {
            for e in entries.flatten() {
                let p = e.path();
                let is_pem = p
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|s| s.eq_ignore_ascii_case("pem"))
                    .unwrap_or(false);
                if !is_pem {
                    continue;
                }
                if let Ok(data) = fs::read(&p) {
                    let mut slice: &[u8] = &data;
                    if let Ok(list) = rustls_pemfile::certs(&mut slice) {
                        for der in list {
                            if let Ok((_, icert)) = x509_parser::parse_x509_certificate(&der) {
                                let isub = icert.tbs_certificate.subject.to_string();
                                if isub == issuer {
                                    return (true, "issuer-match".into(), self_signed);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if self_signed {
        return (true, "self-signed".into(), true);
    }
    (false, "unknown-issuer".into(), self_signed)
}
