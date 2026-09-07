// src/security/encryption.rs
// Certificate chain and time-validity helpers.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_rustls::rustls::pki_types::{CertificateDer, UnixTime};

/// TLS role in which a peer certificate is used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateUsage {
    ServerAuth,
    ClientAuth,
    Either,
}

/// Parse DER certificate and return (not_before, not_after) as UNIX epoch seconds.
pub fn extract_validity_windows(der: &[u8]) -> Option<(i64, i64)> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    if !remainder.is_empty() {
        return None;
    }
    let validity = certificate.validity();
    Some((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

/// Cryptographically validate a TLS certificate path against configured trust anchors.
///
/// The peer chain must be leaf-first. Trust anchors are loaded from PEM or DER
/// files in `trust_anchor_dir`. Validation includes certificate signatures,
/// CA/basic constraints, path length, EKU, critical extensions, name constraints,
/// and validity of the complete path at `now`. Hostname validation is deliberately
/// separate because TheNodes binds peers using node/realm policy rather than DNS.
///
/// Returns `(chain_valid, chain_reason, self_signed_leaf)`.
pub fn validate_certificate_chain(
    peer_chain: &[CertificateDer<'_>],
    trust_anchor_dir: Option<&str>,
    usage: CertificateUsage,
    now: SystemTime,
) -> (bool, String, bool) {
    if peer_chain.is_empty() {
        return (false, "empty-chain".to_string(), false);
    }

    let self_signed = is_self_signed_name(&peer_chain[0]);
    let trust_anchor_dir = match trust_anchor_dir {
        Some(path) if !path.trim().is_empty() => Path::new(path),
        _ => {
            return (
                false,
                "trust-anchor-dir-not-configured".to_string(),
                self_signed,
            )
        }
    };
    let anchor_certs = match load_trust_anchor_certificates(trust_anchor_dir) {
        Ok(certificates) => certificates,
        Err(reason) => return (false, reason, self_signed),
    };
    let trust_anchors = match anchor_certs
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(anchors) if !anchors.is_empty() => anchors,
        Ok(_) => return (false, "no-trust-anchors".to_string(), self_signed),
        Err(error) => return (false, format!("invalid-trust-anchor:{error}"), self_signed),
    };

    let leaf = match webpki::EndEntityCert::try_from(&peer_chain[0]) {
        Ok(leaf) => leaf,
        Err(error) => return (false, chain_error_reason(error), self_signed),
    };
    let now = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => UnixTime::since_unix_epoch(duration),
        Err(_) => {
            return (
                false,
                "system-time-before-unix-epoch".to_string(),
                self_signed,
            )
        }
    };

    let intermediates: Vec<CertificateDer<'_>> = peer_chain[1..]
        .iter()
        .filter(|certificate| {
            !anchor_certs
                .iter()
                .any(|anchor| anchor.as_ref() == certificate.as_ref())
        })
        .map(|certificate| CertificateDer::from(certificate.as_ref()))
        .collect();

    let verify = |key_usage| {
        leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediates,
            now,
            key_usage,
            None,
            None,
        )
        .map(|_| ())
    };
    let validation = match usage {
        CertificateUsage::ServerAuth => verify(webpki::KeyUsage::server_auth()),
        CertificateUsage::ClientAuth => verify(webpki::KeyUsage::client_auth()),
        CertificateUsage::Either => verify(webpki::KeyUsage::server_auth())
            .or_else(|_| verify(webpki::KeyUsage::client_auth())),
    };

    match validation {
        Ok(()) => (true, "webpki-path-valid".to_string(), self_signed),
        Err(error) => (false, chain_error_reason(error), self_signed),
    }
}

/// Verify that a certificate is genuinely self-signed rather than merely
/// carrying equal subject and issuer names.
pub fn validate_self_signed_certificate(
    certificate: &CertificateDer<'_>,
    usage: CertificateUsage,
    now: SystemTime,
) -> Result<(), String> {
    let (remainder, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|_| "self-signed-certificate-parse-error".to_string())?;
    if !remainder.is_empty() {
        return Err("self-signed-certificate-trailing-data".to_string());
    }
    if parsed.subject() != parsed.issuer() {
        return Err("certificate-is-not-self-signed".to_string());
    }
    parsed
        .verify_signature(None)
        .map_err(|_| "self-signed-signature-invalid".to_string())?;

    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system-time-before-unix-epoch".to_string())?;
    let now = x509_parser::time::ASN1Time::from_timestamp(now.as_secs() as i64)
        .map_err(|_| "system-time-invalid".to_string())?;
    if !parsed.validity().is_valid_at(now) {
        return Err("self-signed-certificate-time-invalid".to_string());
    }

    if let Some(extended_key_usage) = parsed
        .extended_key_usage()
        .map_err(|_| "self-signed-eku-invalid".to_string())?
    {
        let eku = extended_key_usage.value;
        let usage_matches = eku.any
            || match usage {
                CertificateUsage::ServerAuth => eku.server_auth,
                CertificateUsage::ClientAuth => eku.client_auth,
                CertificateUsage::Either => eku.server_auth || eku.client_auth,
            };
        if !usage_matches {
            return Err("required-eku-not-found".to_string());
        }
    }

    Ok(())
}

fn is_self_signed_name(certificate: &CertificateDer<'_>) -> bool {
    x509_parser::parse_x509_certificate(certificate.as_ref())
        .map(|(remainder, parsed)| remainder.is_empty() && parsed.subject() == parsed.issuer())
        .unwrap_or(false)
}

fn load_trust_anchor_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let entries = fs::read_dir(path).map_err(|_| "trust-anchor-dir-unreadable".to_string())?;
    let mut paths: Vec<PathBuf> = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "trust-anchor-dir-unreadable".to_string())?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            matches!(
                path.extension()
                    .and_then(|extension| extension.to_str())
                    .map(|extension| extension.to_ascii_lowercase())
                    .as_deref(),
                Some("pem" | "crt" | "cer" | "der")
            )
        })
        .collect();
    paths.sort();

    let mut certificates = Vec::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|_| "trust-anchor-file-unreadable".to_string())?;
        let is_der = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("der"));
        if is_der {
            certificates.push(CertificateDer::from(bytes));
            continue;
        }

        let mut reader = BufReader::new(bytes.as_slice());
        let parsed = rustls_pemfile::certs(&mut reader)
            .map_err(|_| "trust-anchor-pem-invalid".to_string())?;
        if parsed.is_empty() {
            let extension = path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default();
            if extension.eq_ignore_ascii_case("crt") || extension.eq_ignore_ascii_case("cer") {
                certificates.push(CertificateDer::from(bytes));
                continue;
            }
            return Err("trust-anchor-pem-empty".to_string());
        }
        certificates.extend(parsed.into_iter().map(CertificateDer::from));
    }

    if certificates.is_empty() {
        Err("no-trust-anchors".to_string())
    } else {
        Ok(certificates)
    }
}

fn chain_error_reason(error: webpki::Error) -> String {
    use webpki::Error;

    match error {
        Error::CertExpired => "certificate-expired".to_string(),
        Error::CertNotValidYet => "certificate-not-yet-valid".to_string(),
        Error::InvalidSignatureForPublicKey | Error::SignatureAlgorithmMismatch => {
            "invalid-certificate-signature".to_string()
        }
        Error::UnknownIssuer => "unknown-issuer".to_string(),
        Error::CaUsedAsEndEntity => "ca-used-as-end-entity".to_string(),
        Error::EndEntityUsedAsCa => "end-entity-used-as-ca".to_string(),
        Error::RequiredEkuNotFound => "required-eku-not-found".to_string(),
        Error::PathLenConstraintViolated => "path-length-constraint-violated".to_string(),
        Error::NameConstraintViolation => "name-constraint-violation".to_string(),
        Error::UnsupportedCriticalExtension => "unsupported-critical-extension".to_string(),
        Error::BadDer | Error::BadDerTime | Error::InvalidCertValidity => {
            "certificate-der-invalid".to_string()
        }
        other => format!("certificate-path-invalid:{other}"),
    }
}
