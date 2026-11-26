use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityBackend {
    Plaintext,
    Tls,
    Noise,
}

#[derive(Debug, Clone)]
pub struct AuthSummary {
    pub backend: SecurityBackend,
    pub fingerprint: Option<String>,
    pub subject: Option<String>,
    pub decision: String,
    pub reason: String,
    pub chain_valid: Option<bool>,
    pub time_valid: Option<bool>,
    /// Node IDs the peer's TLS leaf names in this node's realm
    /// (`node://<realm>/<node_id>` URI SANs).
    pub node_names: Vec<String>,
    /// Whether the leaf's chain validated against the configured trust
    /// anchors, so a CA attests `node_names`.
    pub node_names_certified: bool,
    /// A key `tofu` accepted for the first time. The connection writes it to
    /// the trusted directory once it is admitted (ADR-0016).
    pub pending_trust: Option<crate::security::trust::PendingTrust>,
}

/// Node IDs a TLS peer's leaf certificate names in this node's realm, and
/// whether a validated CA path attests them. A self-signed or allowlisted
/// certificate's names are only claims: the key holder can mint a certificate
/// with any name.
fn tls_node_names(
    chain: &[rustls::pki_types::CertificateDer<'_>],
    decision: &crate::security::trust::TrustDecision,
    realm: &crate::realms::RealmInfo,
) -> (Vec<String>, bool) {
    let realm_code = realm.canonical_code();
    let names = chain
        .first()
        .map(|leaf| {
            crate::security::node_identity::node_names_from_certificate(leaf.as_ref(), &realm_code)
        })
        .unwrap_or_default();
    let certified = decision.chain_valid == Some(true)
        && decision.chain_reason.as_deref() == Some("webpki-path-valid");
    (names, certified)
}

pub struct Channel {
    pub reader: Box<dyn AsyncBufRead + Send + Unpin>,
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub auth: AuthSummary,
}

pub fn validate_authenticated_node_id(auth: &AuthSummary, node_id: &str) -> Result<()> {
    if auth.backend == SecurityBackend::Noise {
        let Some(bound) = auth.subject.as_deref() else {
            anyhow::bail!("Noise handshake node identity is missing");
        };
        if bound != node_id {
            anyhow::bail!("Noise handshake node identity does not match HELLO node_id");
        }
    }
    Ok(())
}

#[async_trait]
pub trait SecureChannel: Send + Sync {
    async fn connect(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> Result<Channel>;

    async fn accept(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> Result<Channel>;
}

pub struct TlsSecureChannel;
impl Default for TlsSecureChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsSecureChannel {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SecureChannel for TlsSecureChannel {
    async fn connect(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> Result<Channel> {
        // Lift minimal TLS client setup from transport.rs for adapter scaffolding.
        use crate::events::{
            dispatcher,
            model::{BindingStatus, ConnectionRole, LogEvent, LogLevel, TrustDecisionEvent},
        };
        use crate::security::trust::{
            evaluate_peer_cert_chain_for_usage, CertificateUsage, EffectiveTrustPolicy,
        };
        use rustls::pki_types::CertificateDer;
        use rustls::ClientConfig;
        use rustls_pemfile::certs;
        use tokio_rustls::TlsConnector;

        let tls = config.tls().cloned().unwrap_or_default();
        let mtls = tls.mtls.unwrap_or(false);
        // TheNodes policy evaluates certificate acceptance immediately after
        // the handshake. The custom verifier still verifies CertificateVerify.
        let client_builder = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(DeferredServerCertVerifier));
        let client_cfg = if mtls {
            // Client auth chain
            let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
            let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
            if let Some(paths) = &tls.paths {
                if let (Some(cert_path), Some(key_path)) =
                    (&paths.own_certificate, &paths.own_private_key)
                {
                    if let Ok(f) = std::fs::File::open(cert_path) {
                        let mut reader = std::io::BufReader::new(f);
                        if let Ok(certs_loaded) = certs(&mut reader) {
                            cert_chain =
                                certs_loaded.into_iter().map(CertificateDer::from).collect();
                        }
                    }
                    if let Ok(kf) = std::fs::File::open(key_path) {
                        use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};
                        let mut reader = std::io::BufReader::new(kf);
                        if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
                            if let Some(key) = keys.pop() {
                                key_opt = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
                            }
                        }
                        if key_opt.is_none() {
                            if let Ok(kf2) = std::fs::File::open(key_path) {
                                let mut reader2 = std::io::BufReader::new(kf2);
                                if let Ok(mut keys) = rsa_private_keys(&mut reader2) {
                                    if let Some(key) = keys.pop() {
                                        key_opt = Some(rustls::pki_types::PrivateKeyDer::Pkcs1(
                                            key.into(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            match (cert_chain.is_empty(), key_opt) {
                (true, _) => client_builder.with_no_client_auth(),
                (false, None) => client_builder.with_no_client_auth(),
                (false, Some(key)) => client_builder
                    .with_client_auth_cert(cert_chain, key)
                    .expect("invalid client cert/key"),
            }
        } else {
            client_builder.with_no_client_auth()
        };
        let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));
        let domain_str = peer_addr.ip().to_string();
        let domain = rustls::pki_types::ServerName::try_from(domain_str.clone())?;
        let tls_stream = connector.connect(domain, stream).await?;

        // Trust evaluation
        let policy = EffectiveTrustPolicy::from_tls_config(Some(&tls));
        let chain: Vec<CertificateDer<'static>> = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .unwrap_or(&[])
            .iter()
            .map(|c| c.clone().into_owned())
            .collect();
        // CA trust anchors come only from issuer_cert_dir (ADR-0016).
        let trust_anchor_dir = tls
            .paths
            .as_ref()
            .and_then(|paths| paths.issuer_cert_dir.as_deref());
        let decision = evaluate_peer_cert_chain_for_usage(
            &policy,
            trust_anchor_dir,
            &chain,
            Some(realm),
            CertificateUsage::ServerAuth,
        );

        // Emit trust event (Info)
        let mut meta = dispatcher::meta("trust", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        if !allow_console {
            meta.suppress_console = true;
        }
        let trust_evt = TrustDecisionEvent {
            meta,
            role: ConnectionRole::Outbound,
            decision: format!("{:?}", decision.outcome),
            reason: decision.reason.to_string(),
            mode: format!("{:?}", policy.mode),
            fingerprint: decision.fingerprint.clone(),
            pinned_fingerprint_match: None,
            pinned_subject_match: None,
            realm_binding: BindingStatus::NotApplied,
            chain_valid: decision.chain_valid,
            chain_reason: decision.chain_reason.clone(),
            time_valid: decision.time_valid,
            time_reason: decision.time_reason.clone(),
            stored: Some(decision.stored.to_string()),
            peer_addr: Some(peer_addr.to_string()),
            realm: Some(realm.canonical_code()),
            dry_run: false,
            override_action: None,
        };
        dispatcher::emit(LogEvent::TrustDecision(trust_evt));
        if matches!(
            decision.outcome,
            crate::security::trust::TrustDecisionOutcome::Reject
        ) {
            anyhow::bail!("trust policy reject");
        }

        let (node_names, node_names_certified) = tls_node_names(&chain, &decision, realm);
        let (r, w) = tokio::io::split(tls_stream);
        Ok(Channel {
            reader: Box::new(tokio::io::BufReader::new(r)),
            writer: Box::new(w),
            auth: AuthSummary {
                backend: SecurityBackend::Tls,
                fingerprint: decision.fingerprint,
                subject: None,
                decision: "Accept".into(),
                reason: decision.reason.to_string(),
                chain_valid: decision.chain_valid,
                time_valid: decision.time_valid,
                node_names,
                node_names_certified,
                pending_trust: decision.pending_trust,
            },
        })
    }

    async fn accept(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> Result<Channel> {
        use crate::events::{
            dispatcher,
            model::{BindingStatus, ConnectionRole, LogEvent, LogLevel, TrustDecisionEvent},
        };
        use crate::security::trust::{
            evaluate_peer_cert_chain_for_usage, CertificateUsage, EffectiveTrustPolicy,
        };
        use rustls::pki_types::CertificateDer;
        use rustls::ServerConfig;
        use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
        use tokio_rustls::TlsAcceptor;

        let tls = config.tls().cloned().unwrap_or_default();
        // Load server cert/key
        let mut certs_vec = Vec::new();
        let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
        if let Some(paths) = &tls.paths {
            if let (Some(cert_path), Some(key_path)) =
                (&paths.own_certificate, &paths.own_private_key)
            {
                if let Ok(cert_file) = std::fs::File::open(cert_path) {
                    let mut reader = std::io::BufReader::new(cert_file);
                    if let Ok(c) = certs(&mut reader) {
                        certs_vec = c.into_iter().map(CertificateDer::from).collect();
                    }
                }
                if let Ok(key_file) = std::fs::File::open(key_path) {
                    let mut reader = std::io::BufReader::new(key_file);
                    if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
                        if let Some(key) = keys.pop() {
                            key_opt = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
                        }
                    }
                    if key_opt.is_none() {
                        if let Ok(kf) = std::fs::File::open(key_path) {
                            let mut reader = std::io::BufReader::new(kf);
                            if let Ok(mut keys) = rsa_private_keys(&mut reader) {
                                if let Some(key) = keys.pop() {
                                    key_opt =
                                        Some(rustls::pki_types::PrivateKeyDer::Pkcs1(key.into()));
                                }
                            }
                        }
                    }
                }
            }
        }
        if certs_vec.is_empty() || key_opt.is_none() {
            anyhow::bail!("tls inbound: missing cert/key");
        }
        // Safe to bind key after validation above
        let key = match key_opt {
            Some(k) => k,
            None => unreachable!("checked non-none above"),
        };
        let mtls = tls.mtls.unwrap_or(false);
        let acceptor = if mtls {
            let server_cfg = ServerConfig::builder()
                .with_client_cert_verifier(std::sync::Arc::new(DeferredClientCertVerifier))
                .with_single_cert(certs_vec, key)
                .expect("invalid cert/key");
            TlsAcceptor::from(std::sync::Arc::new(server_cfg))
        } else {
            let server_cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs_vec, key)
                .expect("invalid cert/key");
            TlsAcceptor::from(std::sync::Arc::new(server_cfg))
        };

        let tls_stream = acceptor.accept(stream).await?;
        // Peer chain for trust evaluation
        let peer_chain_owned: Vec<CertificateDer<'static>> = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.clone().into_owned()).collect())
            .unwrap_or_else(Vec::new);

        let policy = EffectiveTrustPolicy::from_tls_config(Some(&tls));
        // CA trust anchors come only from issuer_cert_dir (ADR-0016).
        let trust_anchor_dir = tls
            .paths
            .as_ref()
            .and_then(|paths| paths.issuer_cert_dir.as_deref());
        let decision = evaluate_peer_cert_chain_for_usage(
            &policy,
            trust_anchor_dir,
            &peer_chain_owned,
            Some(realm),
            CertificateUsage::ClientAuth,
        );

        let mut meta = dispatcher::meta("trust", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        if !allow_console {
            meta.suppress_console = true;
        }
        let trust_evt = TrustDecisionEvent {
            meta,
            role: ConnectionRole::Inbound,
            decision: format!("{:?}", decision.outcome),
            reason: decision.reason.to_string(),
            mode: format!("{:?}", policy.mode),
            fingerprint: decision.fingerprint.clone(),
            pinned_fingerprint_match: None,
            pinned_subject_match: None,
            realm_binding: BindingStatus::NotApplied,
            chain_valid: decision.chain_valid,
            chain_reason: decision.chain_reason.clone(),
            time_valid: decision.time_valid,
            time_reason: decision.time_reason.clone(),
            stored: Some(decision.stored.to_string()),
            peer_addr: Some(peer_addr.to_string()),
            realm: Some(realm.canonical_code()),
            dry_run: false,
            override_action: None,
        };
        dispatcher::emit(LogEvent::TrustDecision(trust_evt));
        if mtls
            && matches!(
                decision.outcome,
                crate::security::trust::TrustDecisionOutcome::Reject
            )
        {
            anyhow::bail!("trust policy reject");
        }

        let (node_names, node_names_certified) =
            tls_node_names(&peer_chain_owned, &decision, realm);
        let (r, w) = tokio::io::split(tls_stream);
        Ok(Channel {
            reader: Box::new(tokio::io::BufReader::new(r)),
            writer: Box::new(w),
            auth: AuthSummary {
                backend: SecurityBackend::Tls,
                fingerprint: decision.fingerprint,
                subject: None,
                decision: "Accept".into(),
                reason: decision.reason.to_string(),
                chain_valid: decision.chain_valid,
                time_valid: decision.time_valid,
                node_names,
                node_names_certified,
                pending_trust: decision.pending_trust,
            },
        })
    }
}

pub struct PlaintextChannel;
impl Default for PlaintextChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaintextChannel {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SecureChannel for PlaintextChannel {
    async fn connect(
        &self,
        stream: TcpStream,
        _peer_addr: std::net::SocketAddr,
        _realm: &crate::realms::RealmInfo,
        _config: &crate::config::Config,
        _allow_console: bool,
    ) -> Result<Channel> {
        let (r, w) = tokio::io::split(stream);
        Ok(Channel {
            reader: Box::new(tokio::io::BufReader::new(r)),
            writer: Box::new(w),
            auth: AuthSummary {
                backend: SecurityBackend::Plaintext,
                fingerprint: None,
                subject: None,
                decision: "Accept".into(),
                reason: "plaintext".into(),
                chain_valid: None,
                time_valid: None,
                node_names: Vec::new(),
                node_names_certified: false,
                pending_trust: None,
            },
        })
    }

    async fn accept(
        &self,
        stream: TcpStream,
        _peer_addr: std::net::SocketAddr,
        _realm: &crate::realms::RealmInfo,
        _config: &crate::config::Config,
        _allow_console: bool,
    ) -> Result<Channel> {
        let (r, w) = tokio::io::split(stream);
        Ok(Channel {
            reader: Box::new(tokio::io::BufReader::new(r)),
            writer: Box::new(w),
            auth: AuthSummary {
                backend: SecurityBackend::Plaintext,
                fingerprint: None,
                subject: None,
                decision: "Accept".into(),
                reason: "plaintext".into(),
                chain_valid: None,
                time_valid: None,
                node_names: Vec::new(),
                node_names_certified: false,
                pending_trust: None,
            },
        })
    }
}

/// Select a secure channel, rejecting Noise when its feature is unavailable.
pub fn make_secure_channel(cfg: &crate::config::Config) -> Result<Box<dyn SecureChannel>> {
    let enc = cfg.encryption.as_ref();
    let backend = enc.map(|encryption| {
        if !encryption.enabled {
            "plaintext".to_string()
        } else {
            encryption
                .backend
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .unwrap_or_else(|| "tls".to_string())
        }
    });
    let channel: Box<dyn SecureChannel> = match backend.as_deref() {
        Some("tls") => Box::new(TlsSecureChannel::new()),
        Some("none") | Some("plaintext") => Box::new(PlaintextChannel::new()),
        Some("noise") => {
            #[cfg(feature = "noise")]
            {
                Box::new(NoiseSecureChannel::new())
            }
            #[cfg(not(feature = "noise"))]
            {
                anyhow::bail!("encryption.backend = noise requires a build with --features noise");
            }
        }
        // A config file cannot name an unknown backend; one set in code
        // must not silently become another backend.
        Some(other) => anyhow::bail!("unknown encryption.backend \"{other}\""),
        None => Box::new(PlaintextChannel::new()),
    };
    Ok(channel)
}

#[cfg(feature = "noise")]
pub struct NoiseSecureChannel;
#[cfg(feature = "noise")]
impl Default for NoiseSecureChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "noise")]
impl NoiseSecureChannel {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "noise")]
const NOISE_XX_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[cfg(feature = "noise")]
fn load_noise_static_keypair(config: &crate::config::Config) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_path = config
        .encryption
        .as_ref()
        .and_then(|enc| enc.noise.as_ref())
        .map_or(crate::config::NoisePaths::DEFAULT_STATIC_KEY, |noise| {
            noise.static_key_path()
        });
    crate::network::udp_session::load_or_generate_static_keypair(std::path::Path::new(key_path))
        .map_err(|err| {
            anyhow::anyhow!("failed to load Noise static keypair from {key_path}: {err}")
        })
}

#[cfg(feature = "noise")]
fn local_noise_node_id(config: &crate::config::Config) -> String {
    config
        .node
        .as_ref()
        .map(crate::config::NodeConfig::resolve_node_id)
        .unwrap_or_else(|| "unknown-node".to_string())
}

#[cfg(feature = "noise")]
fn parse_noise_node_id(payload: &[u8]) -> Result<Option<String>> {
    if payload.is_empty() {
        anyhow::bail!("Noise handshake node identity is missing");
    }
    let node_id = std::str::from_utf8(payload)
        .map_err(|_| anyhow::anyhow!("Noise handshake node identity is not UTF-8"))?;
    if node_id.is_empty()
        || node_id.len() > 128
        || !node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("Noise handshake node identity is invalid");
    }
    Ok(Some(node_id.to_string()))
}

#[cfg(feature = "noise")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_noise_fingerprint(
    config: &crate::config::Config,
    role: crate::events::model::ConnectionRole,
    peer_addr: std::net::SocketAddr,
    realm: &crate::realms::RealmInfo,
    allow_console: bool,
    identity: &str,
    fingerprint: &str,
    remote_static: Option<&[u8]>,
) -> Result<crate::security::trust::TrustDecision> {
    use crate::events::{
        dispatcher,
        model::{BindingStatus, LogEvent, LogLevel, TrustDecisionEvent},
    };
    use crate::security::trust::{
        evaluate_fingerprint_trust, load_noise_fingerprints, EffectiveTrustPolicy,
        FingerprintTrustInput, KeyArtifact, TrustDecisionOutcome,
    };

    let noise_config = config
        .encryption
        .as_ref()
        .and_then(|enc| enc.noise.as_ref());
    let policy = EffectiveTrustPolicy::from_noise_config(noise_config);
    let trusted_dir = policy.trusted_dir.as_deref();
    let directory_fingerprints = trusted_dir.map(load_noise_fingerprints).transpose();
    let allowlist_error = match (policy.mode, trusted_dir, &directory_fingerprints) {
        (
            crate::security::trust::TrustMode::Allowlist | crate::security::trust::TrustMode::Tofu,
            Some(_),
            Err(_),
        ) => Some("trusted-dir-unreadable"),
        _ => None,
    };
    // The node ID the key claimed, for review: whether the key may use it is
    // the node identity binding's decision (ADR-0012), never this file's.
    let mut key_record = format!(
        "kind=noise-static-key\nfingerprint_sha256={fingerprint}\nclaimed_identity={identity}\n"
    );
    if let Some(remote_static) = remote_static {
        key_record.push_str(&format!("public_key_hex={}\n", hex::encode(remote_static)));
    }
    let key_record = key_record.into_bytes();
    let decision = evaluate_fingerprint_trust(
        &policy,
        FingerprintTrustInput {
            fingerprint: Some(fingerprint),
            additional_allowlisted_fingerprints: directory_fingerprints
                .as_ref()
                .ok()
                .and_then(|fingerprints| fingerprints.as_ref()),
            allowlist_error,
            artifact: Some(KeyArtifact {
                extension: "noise",
                bytes: &key_record,
            }),
            is_ca_certificate: false,
        },
    );

    let mut meta = dispatcher::meta("trust", LogLevel::Info);
    meta.corr_id = Some(dispatcher::correlation_id());
    if !allow_console {
        meta.suppress_console = true;
    }
    dispatcher::emit(LogEvent::TrustDecision(TrustDecisionEvent {
        meta,
        role,
        decision: format!("{:?}", decision.outcome),
        reason: decision.reason.to_string(),
        mode: format!("{:?}", policy.mode),
        fingerprint: decision.fingerprint.clone(),
        pinned_fingerprint_match: policy.pinned_fingerprint_match(Some(fingerprint)),
        pinned_subject_match: None,
        realm_binding: BindingStatus::NotApplied,
        chain_valid: None,
        chain_reason: None,
        time_valid: None,
        time_reason: None,
        stored: Some(decision.stored.to_string()),
        peer_addr: Some(peer_addr.to_string()),
        realm: Some(realm.canonical_code()),
        dry_run: false,
        override_action: None,
    }));
    if matches!(decision.outcome, TrustDecisionOutcome::Reject) {
        anyhow::bail!("trust policy reject");
    }
    Ok(decision)
}

#[cfg(feature = "noise")]
fn evaluate_noise_remote_static_key(
    config: &crate::config::Config,
    role: crate::events::model::ConnectionRole,
    peer_addr: std::net::SocketAddr,
    realm: &crate::realms::RealmInfo,
    allow_console: bool,
    remote_node_id: Option<&str>,
    remote_static: &[u8],
) -> Result<crate::security::trust::TrustDecision> {
    let fingerprint = crate::security::trust::sha256_fingerprint_hex(remote_static);
    let identity = remote_node_id
        .map(|node_id| format!("node:{node_id}"))
        .unwrap_or_else(|| match role {
            crate::events::model::ConnectionRole::Inbound => {
                format!("noise-inbound:{}", peer_addr.ip())
            }
            crate::events::model::ConnectionRole::Outbound => {
                format!("noise-outbound:{peer_addr}")
            }
        });
    evaluate_noise_fingerprint(
        config,
        role,
        peer_addr,
        realm,
        allow_console,
        &identity,
        &fingerprint,
        Some(remote_static),
    )
}

#[cfg(feature = "noise")]
#[async_trait]
impl SecureChannel for NoiseSecureChannel {
    async fn connect(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> Result<Channel> {
        use snow::Builder as NoiseBuilder;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (static_private, _) = load_noise_static_keypair(config)?;
        let params = NOISE_XX_PARAMS.parse().unwrap();
        let builder = NoiseBuilder::new(params);
        let mut pattern = builder
            .local_private_key(&static_private)
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; 65535];
        let mut handshake_payload = vec![0u8; 256];
        // Stage 1: send first message
        let len = pattern
            .write_message(&[], &mut buf)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let (mut rstream, mut wstream) = stream.into_split();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wstream.write_u16(len as u16),
        )
        .await??;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wstream.write_all(&buf[..len]),
        )
        .await??;
        // Receive responder message
        let rlen = tokio::time::timeout(std::time::Duration::from_secs(3), rstream.read_u16())
            .await?? as usize;
        let mut rbuf = vec![0u8; rlen];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            rstream.read_exact(&mut rbuf),
        )
        .await??;
        let remote_identity_len = pattern
            .read_message(&rbuf, &mut handshake_payload)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let remote_node_id = parse_noise_node_id(&handshake_payload[..remote_identity_len])?;
        // Final handshake message
        let local_node_id = local_noise_node_id(config);
        let len3 = pattern
            .write_message(local_node_id.as_bytes(), &mut buf)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wstream.write_u16(len3 as u16),
        )
        .await??;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wstream.write_all(&buf[..len3]),
        )
        .await??;
        let remote_static = pattern
            .get_remote_static()
            .ok_or_else(|| {
                anyhow::anyhow!("noise handshake completed without a remote static key")
            })?
            .to_vec();
        let decision = evaluate_noise_remote_static_key(
            config,
            crate::events::model::ConnectionRole::Outbound,
            peer_addr,
            realm,
            allow_console,
            remote_node_id.as_deref(),
            &remote_static,
        )?;
        let transport = pattern
            .into_transport_mode()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        // Share one transport state with a mutex between reader/writer
        let st = std::sync::Arc::new(parking_lot::Mutex::new(transport));
        let reader = Box::new(tokio::io::BufReader::new(NoiseReader::new(
            rstream,
            st.clone(),
        )));
        let writer = Box::new(NoiseWriter::new(wstream, st));
        Ok(Channel {
            reader,
            writer,
            auth: AuthSummary {
                backend: SecurityBackend::Noise,
                fingerprint: decision.fingerprint,
                subject: remote_node_id,
                decision: "Accept".into(),
                reason: decision.reason.to_string(),
                chain_valid: None,
                time_valid: None,
                node_names: Vec::new(),
                node_names_certified: false,
                pending_trust: decision.pending_trust,
            },
        })
    }

    async fn accept(
        &self,
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> Result<Channel> {
        use snow::Builder as NoiseBuilder;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (static_private, _) = load_noise_static_keypair(config)?;
        let params = NOISE_XX_PARAMS.parse().unwrap();
        let builder = NoiseBuilder::new(params);
        let mut pattern = builder
            .local_private_key(&static_private)
            .build_responder()
            .unwrap();
        let (mut rstream, mut wstream) = stream.into_split();
        let rlen1 = tokio::time::timeout(std::time::Duration::from_secs(3), rstream.read_u16())
            .await?? as usize;
        let mut rbuf1 = vec![0u8; rlen1];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            rstream.read_exact(&mut rbuf1),
        )
        .await??;
        let mut out = vec![0u8; 65535];
        pattern
            .read_message(&rbuf1, &mut out)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let local_node_id = local_noise_node_id(config);
        let len2 = pattern
            .write_message(local_node_id.as_bytes(), &mut out)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wstream.write_u16(len2 as u16),
        )
        .await??;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            wstream.write_all(&out[..len2]),
        )
        .await??;
        let rlen3 = tokio::time::timeout(std::time::Duration::from_secs(3), rstream.read_u16())
            .await?? as usize;
        let mut rbuf3 = vec![0u8; rlen3];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            rstream.read_exact(&mut rbuf3),
        )
        .await??;
        let mut final_out = vec![0u8; 256];
        let remote_identity_len = pattern
            .read_message(&rbuf3, &mut final_out)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let remote_node_id = parse_noise_node_id(&final_out[..remote_identity_len])?;
        let remote_static = pattern
            .get_remote_static()
            .ok_or_else(|| {
                anyhow::anyhow!("noise handshake completed without a remote static key")
            })?
            .to_vec();
        let decision = evaluate_noise_remote_static_key(
            config,
            crate::events::model::ConnectionRole::Inbound,
            peer_addr,
            realm,
            allow_console,
            remote_node_id.as_deref(),
            &remote_static,
        )?;
        let transport = pattern
            .into_transport_mode()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let st = std::sync::Arc::new(parking_lot::Mutex::new(transport));
        let reader = Box::new(tokio::io::BufReader::new(NoiseReader::new(
            rstream,
            st.clone(),
        )));
        let writer = Box::new(NoiseWriter::new(wstream, st));
        Ok(Channel {
            reader,
            writer,
            auth: AuthSummary {
                backend: SecurityBackend::Noise,
                fingerprint: decision.fingerprint,
                subject: remote_node_id,
                decision: "Accept".into(),
                reason: decision.reason.to_string(),
                chain_valid: None,
                time_valid: None,
                node_names: Vec::new(),
                node_names_certified: false,
                pending_trust: decision.pending_trust,
            },
        })
    }
}

#[cfg(feature = "noise")]
struct NoiseReader {
    inner: tokio::net::tcp::OwnedReadHalf,
    st: std::sync::Arc<parking_lot::Mutex<snow::TransportState>>,
    dec_buf: Vec<u8>,
    dec_pos: usize,
    read_len: Option<usize>,
    len_buf: [u8; 2],
    len_have: usize,
    enc_buf: Vec<u8>,
}

#[cfg(feature = "noise")]
impl NoiseReader {
    fn new(
        inner: tokio::net::tcp::OwnedReadHalf,
        st: std::sync::Arc<parking_lot::Mutex<snow::TransportState>>,
    ) -> Self {
        Self {
            inner,
            st,
            dec_buf: Vec::new(),
            dec_pos: 0,
            read_len: None,
            len_buf: [0; 2],
            len_have: 0,
            enc_buf: Vec::new(),
        }
    }
}

#[cfg(feature = "noise")]
impl tokio::io::AsyncRead for NoiseReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        // A frame with an empty payload yields no bytes; reading on keeps it
        // from looking like end of stream.
        loop {
            // serve from decrypted buffer first
            if this.dec_pos < this.dec_buf.len() {
                let avail = &this.dec_buf[this.dec_pos..];
                let n = std::cmp::min(avail.len(), buf.remaining());
                buf.put_slice(&avail[..n]);
                this.dec_pos += n;
                if this.dec_pos >= this.dec_buf.len() {
                    this.dec_buf.clear();
                    this.dec_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            // Read length prefix
            if this.read_len.is_none() {
                while this.len_have < 2 {
                    let mut lb = tokio::io::ReadBuf::new(&mut this.len_buf[this.len_have..]);
                    match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut lb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            let filled = lb.filled().len();
                            if filled == 0 {
                                // End of stream is clean only between frames.
                                if this.len_have == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(truncated_frame()));
                            }
                            this.len_have += filled;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                let len = u16::from_le_bytes(this.len_buf) as usize;
                if len == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "zero-length frame",
                    )));
                }
                this.read_len = Some(len);
                this.enc_buf.clear();
                this.enc_buf.reserve(len);
            }
            let target = this.read_len.unwrap();
            while this.enc_buf.len() < target {
                let needed = target - this.enc_buf.len();
                let mut tmp = vec![0u8; needed];
                let mut rb = tokio::io::ReadBuf::new(&mut tmp);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        let got = rb.filled().len();
                        if got == 0 {
                            return Poll::Ready(Err(truncated_frame()));
                        }
                        this.enc_buf.extend_from_slice(rb.filled());
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            // Decrypt
            let mut out = vec![0u8; target + 1024];
            let n = this
                .st
                .lock()
                .read_message(&this.enc_buf, &mut out)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            this.dec_buf = out[..n].to_vec();
            this.dec_pos = 0;
            this.read_len = None;
            this.len_have = 0;
            this.enc_buf.clear();
        }
    }
}

#[cfg(feature = "noise")]
fn truncated_frame() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "stream ended inside a frame",
    )
}

#[cfg(feature = "noise")]
struct NoiseWriter {
    inner: tokio::net::tcp::OwnedWriteHalf,
    st: std::sync::Arc<parking_lot::Mutex<snow::TransportState>>,
    out_buf: Vec<u8>,
    out_pos: usize,
}

#[cfg(feature = "noise")]
impl NoiseWriter {
    fn new(
        inner: tokio::net::tcp::OwnedWriteHalf,
        st: std::sync::Arc<parking_lot::Mutex<snow::TransportState>>,
    ) -> Self {
        Self {
            inner,
            st,
            out_buf: Vec::new(),
            out_pos: 0,
        }
    }

    /// Write out the buffered frame. A frame stays buffered until all of it
    /// has been written, so each chunk `poll_write` accepted is sent once.
    fn poll_drain(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        while self.out_pos < self.out_buf.len() {
            match std::pin::Pin::new(&mut self.inner).poll_write(cx, &self.out_buf[self.out_pos..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        self.out_buf.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "noise")]
impl tokio::io::AsyncWrite for NoiseWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();
        // The previous frame goes out before the next one is encrypted.
        std::task::ready!(this.poll_drain(cx))?;
        // Encrypt new frame (chunk to respect u16 framing)
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let max_chunk: usize = 60_000; // conservative to leave AEAD overhead
        let to_send = if buf.len() > max_chunk {
            &buf[..max_chunk]
        } else {
            buf
        };
        let mut enc = vec![0u8; to_send.len() + 1024];
        let n = this
            .st
            .lock()
            .write_message(to_send, &mut enc)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        if n > u16::MAX as usize {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted frame too large",
            )));
        }
        this.out_buf.reserve(2 + n);
        this.out_buf.extend_from_slice(&(n as u16).to_le_bytes());
        this.out_buf.extend_from_slice(&enc[..n]);
        // The chunk is accepted once it is encrypted: the frame is written now
        // if the socket takes it, otherwise by the next write, flush or
        // shutdown.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(to_send.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct DeferredServerCertVerifier;
impl rustls::client::danger::ServerCertVerifier for DeferredServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct DeferredClientCertVerifier;
impl rustls::server::danger::ClientCertVerifier for DeferredClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(all(test, not(feature = "noise")))]
mod tests {
    use super::make_secure_channel;
    use crate::config::Config;

    #[test]
    fn disabled_encryption_ignores_configured_backend() {
        let mut config = Config::default();
        let encryption = config
            .encryption
            .as_mut()
            .expect("default encryption config");
        encryption.enabled = false;
        encryption.backend = Some("noise".to_string());

        assert!(make_secure_channel(&config).is_ok());
    }
}

#[cfg(all(test, feature = "noise"))]
mod noise_stream_tests {
    use super::{NoiseReader, NoiseWriter};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpSocket, TcpStream};

    /// Transport states for the two ends of a Noise NN handshake.
    fn transport_pair() -> (snow::TransportState, snow::TransportState) {
        let params: snow::params::NoiseParams =
            "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let mut initiator = snow::Builder::new(params.clone())
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(params).build_responder().unwrap();
        let (mut msg, mut payload) = ([0u8; 128], [0u8; 128]);
        let n = initiator.write_message(&[], &mut msg).unwrap();
        responder.read_message(&msg[..n], &mut payload).unwrap();
        let n = responder.write_message(&[], &mut msg).unwrap();
        initiator.read_message(&msg[..n], &mut payload).unwrap();
        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    /// A loopback connection whose client side has a small send buffer, so
    /// writes block as soon as the server stops reading.
    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        let client = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn reader(stream: TcpStream, st: snow::TransportState) -> NoiseReader {
        NoiseReader::new(stream.into_split().0, Arc::new(parking_lot::Mutex::new(st)))
    }

    /// Regression test: a partial write used to return `Pending` without a
    /// waker, stalling the writer, and a write retried after `Pending` sent
    /// its frame twice.
    #[tokio::test]
    async fn writer_sends_each_byte_once_under_backpressure() {
        let (client, server) = connected_pair().await;
        let (initiator, responder) = transport_pair();
        let mut writer = NoiseWriter::new(
            client.into_split().1,
            Arc::new(parking_lot::Mutex::new(initiator)),
        );
        let mut reader = reader(server, responder);
        let data: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        let sender = tokio::spawn(async move {
            writer.write_all(&sent).await.unwrap();
            writer.shutdown().await.unwrap();
        });

        // Let the sender fill both socket buffers before anything is read.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), reader.read_to_end(&mut received))
            .await
            .expect("the writer stalled")
            .unwrap();
        assert_eq!(received.len(), data.len());
        assert!(received == data, "received bytes differ from those sent");
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn reader_skips_empty_frames_and_rejects_a_truncated_one() {
        let (mut client, server) = connected_pair().await;
        let (mut initiator, responder) = transport_pair();
        let mut frame = |plaintext: &[u8]| {
            let mut ciphertext = vec![0u8; plaintext.len() + 16];
            let n = initiator.write_message(plaintext, &mut ciphertext).unwrap();
            let mut frame = (n as u16).to_le_bytes().to_vec();
            frame.extend_from_slice(&ciphertext[..n]);
            frame
        };
        let mut wire = frame(b"");
        wire.extend(frame(b"after"));
        let cut = frame(b"lost");
        wire.extend_from_slice(&cut[..cut.len() - 1]);
        client.write_all(&wire).await.unwrap();
        client.shutdown().await.unwrap();

        let mut reader = reader(server, responder);
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after");
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
