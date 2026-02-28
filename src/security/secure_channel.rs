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
}

pub struct Channel {
    pub reader: Box<dyn AsyncBufRead + Send + Unpin>,
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub auth: AuthSummary,
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

fn redacted_trust_fields() -> (String, Option<String>, Option<String>, Option<String>) {
    ("redacted".to_string(), None, None, None)
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
        use crate::security::trust::{evaluate_peer_cert_chain, EffectiveTrustPolicy};
        use rustls::pki_types::CertificateDer;
        use rustls::{ClientConfig, RootCertStore};
        use rustls_pemfile::certs;
        use tokio_rustls::TlsConnector;

        // Use provided TCP stream for TLS client handshake.
        // Build roots
        let mut root_cert_store = RootCertStore::empty();
        if let Some(enc_paths) = config.encryption.as_ref().and_then(|e| e.paths.as_ref()) {
            if let Some(trusted_cert_dir) = &enc_paths.trusted_cert_dir {
                if let Ok(entries) = std::fs::read_dir(trusted_cert_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().map(|e| e == "pem").unwrap_or(false) {
                            if let Ok(file) = std::fs::File::open(&path) {
                                let mut reader = std::io::BufReader::new(file);
                                if let Ok(certs) = certs(&mut reader) {
                                    for cert in certs {
                                        let _ = root_cert_store.add(CertificateDer::from(cert));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let enc_owned = config.encryption.clone().unwrap_or_default();
        let enc_ref = &enc_owned;
        let mtls = enc_ref.mtls.unwrap_or(false);
        let accept_self_signed = enc_ref
            .trust_policy
            .as_ref()
            .and_then(|tp| tp.accept_self_signed)
            .or(enc_ref.accept_self_signed)
            .unwrap_or(false);
        let client_builder = ClientConfig::builder().with_root_certificates(root_cert_store);
        let mut client_cfg = if mtls {
            // Client auth chain
            let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
            let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
            if let Some(paths) = &enc_ref.paths {
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
        if accept_self_signed {
            client_cfg
                .dangerous()
                .set_certificate_verifier(std::sync::Arc::new(super_permissive_verifier()));
        }
        let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));
        let domain_str = peer_addr.ip().to_string();
        let domain = rustls::pki_types::ServerName::try_from(domain_str.clone())?;
        let tls_stream = connector.connect(domain, stream).await?;

        // Trust evaluation
        let policy = EffectiveTrustPolicy::from_config(enc_ref);
        let chain: Vec<CertificateDer<'static>> = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .unwrap_or(&[])
            .iter()
            .map(|c| c.clone().into_owned())
            .collect();
        let trusted_dir = enc_ref
            .paths
            .as_ref()
            .and_then(|p| p.trusted_cert_dir.as_deref());
        let observed_dir = policy.observed_dir.as_deref();
        let decision =
            evaluate_peer_cert_chain(&policy, trusted_dir, observed_dir, &chain, Some(realm));

        // Emit trust event (Info)
        let mut meta = dispatcher::meta("trust", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        if !allow_console {
            meta.suppress_console = true;
        }
        let (event_reason, event_fingerprint, event_chain_reason, event_time_reason) =
            redacted_trust_fields();
        let trust_evt = TrustDecisionEvent {
            meta,
            role: ConnectionRole::Outbound,
            decision: format!("{:?}", decision.outcome),
            reason: event_reason,
            mode: format!("{:?}", policy.mode),
            fingerprint: event_fingerprint,
            pinned_fingerprint_match: None,
            pinned_subject_match: None,
            realm_binding: BindingStatus::NotApplied,
            chain_valid: decision.chain_valid,
            chain_reason: event_chain_reason,
            time_valid: decision.time_valid,
            time_reason: event_time_reason,
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
        use crate::security::trust::{evaluate_peer_cert_chain, EffectiveTrustPolicy};
        use rustls::pki_types::CertificateDer;
        use rustls::ServerConfig;
        use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
        use tokio_rustls::TlsAcceptor;

        let enc_owned = config.encryption.clone().unwrap_or_default();
        let enc_ref = &enc_owned;
        // Load server cert/key
        let mut certs_vec = Vec::new();
        let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
        if let Some(paths) = &enc_ref.paths {
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
        let mtls = enc_ref.mtls.unwrap_or(false);
        let accept_self_signed = enc_ref
            .trust_policy
            .as_ref()
            .and_then(|tp| tp.accept_self_signed)
            .or(enc_ref.accept_self_signed)
            .unwrap_or(false);

        let acceptor = if mtls {
            if accept_self_signed {
                let server_cfg = ServerConfig::builder()
                    .with_client_cert_verifier(std::sync::Arc::new(PermissiveClientVerifier))
                    .with_single_cert(certs_vec, key)
                    .expect("invalid cert/key");
                TlsAcceptor::from(std::sync::Arc::new(server_cfg))
            } else {
                use rustls::server::WebPkiClientVerifier;
                use rustls::RootCertStore;
                let mut client_roots = RootCertStore::empty();
                if let Some(paths) = &enc_ref.paths {
                    if let Some(trusted_dir) = &paths.trusted_cert_dir {
                        if let Ok(entries) = std::fs::read_dir(trusted_dir) {
                            for entry in entries.flatten() {
                                let p = entry.path();
                                if p.extension().and_then(|e| e.to_str()) == Some("pem") {
                                    if let Ok(f) = std::fs::File::open(&p) {
                                        let mut reader = std::io::BufReader::new(f);
                                        if let Ok(certs) = rustls_pemfile::certs(&mut reader) {
                                            for c in certs {
                                                let _ = client_roots.add(
                                                    rustls::pki_types::CertificateDer::from(c),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                let client_roots = std::sync::Arc::new(client_roots);
                match WebPkiClientVerifier::builder(client_roots).build() {
                    Ok(verifier_arc) => {
                        let server_cfg = ServerConfig::builder()
                            .with_client_cert_verifier(verifier_arc)
                            .with_single_cert(certs_vec, key)
                            .expect("invalid cert/key");
                        TlsAcceptor::from(std::sync::Arc::new(server_cfg))
                    }
                    Err(_e) => {
                        let server_cfg = ServerConfig::builder()
                            .with_no_client_auth()
                            .with_single_cert(certs_vec, key)
                            .expect("invalid cert/key");
                        TlsAcceptor::from(std::sync::Arc::new(server_cfg))
                    }
                }
            }
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

        let policy = EffectiveTrustPolicy::from_config(enc_ref);
        let decision = evaluate_peer_cert_chain(
            &policy,
            enc_ref
                .paths
                .as_ref()
                .and_then(|p| p.trusted_cert_dir.as_deref()),
            policy.observed_dir.as_deref(),
            &peer_chain_owned,
            Some(realm),
        );

        let mut meta = dispatcher::meta("trust", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        if !allow_console {
            meta.suppress_console = true;
        }
        let (event_reason, event_fingerprint, event_chain_reason, event_time_reason) =
            redacted_trust_fields();
        let trust_evt = TrustDecisionEvent {
            meta,
            role: ConnectionRole::Inbound,
            decision: format!("{:?}", decision.outcome),
            reason: event_reason,
            mode: format!("{:?}", policy.mode),
            fingerprint: event_fingerprint,
            pinned_fingerprint_match: None,
            pinned_subject_match: None,
            realm_binding: BindingStatus::NotApplied,
            chain_valid: decision.chain_valid,
            chain_reason: event_chain_reason,
            time_valid: decision.time_valid,
            time_reason: event_time_reason,
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
            },
        })
    }
}

pub fn make_secure_channel(cfg: &crate::config::Config) -> Box<dyn SecureChannel> {
    let enc = cfg.encryption.as_ref();
    // Derive backend: default to tls if enabled, plaintext if disabled
    let backend = enc
        .and_then(|e| e.backend.as_deref())
        .map(|b| b.trim().to_ascii_lowercase())
        .or_else(|| {
            enc.map(|e| {
                if e.enabled {
                    "tls".to_string()
                } else {
                    "plaintext".to_string()
                }
            })
        });
    match backend.as_deref() {
        Some("tls") => Box::new(TlsSecureChannel::new()),
        Some("none") | Some("plaintext") => Box::new(PlaintextChannel::new()),
        Some("noise") => {
            #[cfg(feature = "noise")]
            {
                Box::new(NoiseSecureChannel::new())
            }
            #[cfg(not(feature = "noise"))]
            {
                // Feature not enabled; fall back to plaintext
                Box::new(PlaintextChannel::new())
            }
        }
        _ => {
            // Fallback to previous behavior
            if enc.map(|e| e.enabled).unwrap_or(false) {
                Box::new(TlsSecureChannel::new())
            } else {
                Box::new(PlaintextChannel::new())
            }
        }
    }
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
#[async_trait]
impl SecureChannel for NoiseSecureChannel {
    async fn connect(
        &self,
        stream: TcpStream,
        _peer_addr: std::net::SocketAddr,
        _realm: &crate::realms::RealmInfo,
        _config: &crate::config::Config,
        _allow_console: bool,
    ) -> Result<Channel> {
        use snow::Builder as NoiseBuilder;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let params = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let builder = NoiseBuilder::new(params);
        let kp = builder.generate_keypair().unwrap();
        let mut pattern = builder
            .local_private_key(&kp.private)
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; 65535];
        let mut write_msg = vec![0u8; 0];
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
        pattern
            .read_message(&rbuf, &mut write_msg)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        // Final handshake message
        let len3 = pattern
            .write_message(&[], &mut buf)
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
                fingerprint: None,
                subject: None,
                decision: "Accept".into(),
                reason: "noise(xx)".into(),
                chain_valid: None,
                time_valid: None,
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
        use snow::Builder as NoiseBuilder;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let params = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let builder = NoiseBuilder::new(params);
        let kp = builder.generate_keypair().unwrap();
        let mut pattern = builder
            .local_private_key(&kp.private)
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
        let len2 = pattern
            .write_message(&[], &mut out)
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
        let mut final_out = vec![0u8; 0];
        pattern
            .read_message(&rbuf3, &mut final_out)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
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
                fingerprint: None,
                subject: None,
                decision: "Accept".into(),
                reason: "noise(xx)".into(),
                chain_valid: None,
                time_valid: None,
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
                            return Poll::Ready(Ok(()));
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
                        return Poll::Ready(Ok(()));
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
        // Serve
        let n2 = std::cmp::min(this.dec_buf.len(), buf.remaining());
        buf.put_slice(&this.dec_buf[..n2]);
        this.dec_pos = n2;
        Poll::Ready(Ok(()))
    }
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
        // flush pending first
        if this.out_pos < this.out_buf.len() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.out_buf[this.out_pos..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(n)) => {
                    this.out_pos += n;
                    if this.out_pos < this.out_buf.len() {
                        return Poll::Pending;
                    } else {
                        this.out_buf.clear();
                        this.out_pos = 0;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
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
        this.out_buf.clear();
        this.out_buf.reserve(2 + n);
        this.out_buf.extend_from_slice(&(n as u16).to_le_bytes());
        this.out_buf.extend_from_slice(&enc[..n]);
        this.out_pos = 0;
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.out_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(w)) => {
                this.out_pos = w;
                if this.out_pos >= this.out_buf.len() {
                    this.out_buf.clear();
                    this.out_pos = 0;
                }
                Poll::Ready(Ok(to_send.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.out_pos < self.out_buf.len() {
            match std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(r) => std::task::Poll::Ready(r),
            }
        } else {
            std::task::Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// Helper: permissive verifier instance for self-signed acceptance
fn super_permissive_verifier() -> PermissiveVerifier {
    PermissiveVerifier
}

#[derive(Debug)]
struct PermissiveVerifier;
impl rustls::client::danger::ServerCertVerifier for PermissiveVerifier {
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
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[derive(Debug)]
struct PermissiveClientVerifier;
impl rustls::server::danger::ClientCertVerifier for PermissiveClientVerifier {
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
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
