// src/network/transport.rs

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Config;
use crate::constants::{DEFAULT_APP_NAME, PROTOCOL_NAME, PROTOCOL_VERSION};

#[derive(Debug)]
struct PermissiveVerifier;
impl ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
use crate::network::events::emit_network_event;
use crate::network::message::{Message, MessageType};
use crate::network::peer::Peer;
use crate::network::peer_manager::PeerManager;
use crate::realms::RealmInfo;
use rustls_pemfile::certs;
use std::error::Error;
use std::fs::File;
use std::io::BufReader as StdBufReader;
use std::net::SocketAddr;

use crate::events::{
    dispatcher,
    model::{BindingStatus, ConnectionRole, LogEvent, LogLevel, TrustDecisionEvent},
};
use crate::plugin_host::manager::PluginManager;
use crate::security::trust::{evaluate_peer_cert_chain, EffectiveTrustPolicy};
// ...existing code...

pub struct ConnectToPeerParams<'a> {
    pub peer: &'a Peer,
    pub our_realm: RealmInfo,
    pub our_port: u16,
    pub peer_manager: PeerManager,
    pub plugin_manager: Arc<PluginManager>,
    pub allow_console: bool,
    pub config: Config,
    pub local_node_id: String,
}

pub async fn connect_to_peer<'a>(params: ConnectToPeerParams<'a>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ConnectToPeerParams { peer, our_realm, our_port, peer_manager, plugin_manager, allow_console, config, local_node_id } = params;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "dial_start",
        Some(peer.address.clone()),
        Some(format!("peer_id={} local_port={}", peer.id, our_port)),
        allow_console,
    );

    let stream = TcpStream::connect(&peer.address).await?;
    let addr = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "tcp_connected",
        Some(addr.to_string()),
        Some(format!("local={} remote={}", local_addr, addr)),
        allow_console,
    );

    // TLS handshake if enabled
    let (mut reader, mut writer): (
        Box<dyn tokio::io::AsyncBufRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    );
    if let Some(enc) = &config.encryption {
        if enc.enabled {
            // Prefer new trust_policy.accept_self_signed, fall back to deprecated root field
            let accept_self_signed = enc
                .trust_policy
                .as_ref()
                .and_then(|tp| tp.accept_self_signed)
                .or(enc.accept_self_signed)
                .unwrap_or(false);
            let mut root_cert_store = RootCertStore::empty();
            if let Some(paths) = &enc.paths {
                if let Some(trusted_cert_dir) = &paths.trusted_cert_dir {
                    if let Ok(entries) = std::fs::read_dir(trusted_cert_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().map(|e| e == "pem").unwrap_or(false) {
                                if let Ok(file) = File::open(&path) {
                                    let mut reader = StdBufReader::new(file);
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
            let mtls = enc.mtls.unwrap_or(false);
            let client_builder = ClientConfig::builder().with_root_certificates(root_cert_store);
            let mut config = if mtls {
                // Load own cert/key for client auth
                let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
                let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
                if let Some(paths) = &enc.paths {
                    if let (Some(cert_path), Some(key_path)) =
                        (&paths.own_certificate, &paths.own_private_key)
                    {
                        if let Ok(f) = File::open(cert_path) {
                            let mut reader = StdBufReader::new(f);
                            if let Ok(certs_loaded) = certs(&mut reader) {
                                cert_chain =
                                    certs_loaded.into_iter().map(CertificateDer::from).collect();
                            }
                        }
                        if let Ok(kf) = File::open(key_path) {
                            use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};
                            let mut reader = StdBufReader::new(kf);
                            if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
                                if let Some(key) = keys.pop() {
                                    key_opt =
                                        Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
                                }
                            }
                            if key_opt.is_none() {
                                if let Ok(kf2) = File::open(key_path) {
                                    let mut reader2 = StdBufReader::new(kf2);
                                    if let Ok(mut keys) = rsa_private_keys(&mut reader2) {
                                        if let Some(key) = keys.pop() {
                                            key_opt = Some(
                                                rustls::pki_types::PrivateKeyDer::Pkcs1(key.into()),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if cert_chain.is_empty() || key_opt.is_none() {
                    emit_network_event(
                        "transport",
                        LogLevel::Warn,
                        "mtls_client_material_missing",
                        Some(addr.to_string()),
                        Some("falling_back=no_client_auth".to_string()),
                        allow_console,
                    );
                    client_builder.with_no_client_auth()
                } else {
                    emit_network_event(
                        "transport",
                        LogLevel::Info,
                        "mtls_client_cert_loaded",
                        Some(addr.to_string()),
                        Some(format!("chain_len={}", cert_chain.len())),
                        allow_console,
                    );
                    match key_opt {
                        Some(key) => client_builder
                            .with_client_auth_cert(cert_chain, key)
                            .expect("invalid client cert/key"),
                        None => {
                            emit_network_event(
                                "transport",
                                LogLevel::Warn,
                                "mtls_client_key_missing",
                                Some(addr.to_string()),
                                Some("falling_back=no_client_auth".to_string()),
                                allow_console,
                            );
                            client_builder.with_no_client_auth()
                        }
                    }
                }
            } else {
                client_builder.with_no_client_auth()
            };
            if accept_self_signed {
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(PermissiveVerifier));
            }
            let connector = TlsConnector::from(Arc::new(config));
            let domain_str = peer
                .address
                .split(':')
                .next()
                .unwrap_or("localhost")
                .to_string();
            emit_network_event(
                "transport",
                LogLevel::Info,
                "tls_outbound_start",
                Some(addr.to_string()),
                Some(format!(
                    "domain={} accept_self_signed={} mtls={} local={}",
                    domain_str, accept_self_signed, mtls, local_addr
                )),
                allow_console,
            );
            let domain = ServerName::try_from(domain_str.clone())?;
            let tls_stream = match connector.connect(domain, stream).await {
                Ok(ts) => {
                    emit_network_event(
                        "transport",
                        LogLevel::Info,
                        "tls_outbound_success",
                        Some(addr.to_string()),
                        Some(format!("local={} remote={}", local_addr, addr)),
                        allow_console,
                    );
                    ts
                }
                Err(e) => {
                    emit_network_event(
                        "transport",
                        LogLevel::Error,
                        "tls_outbound_failure",
                        Some(addr.to_string()),
                        Some(format!("local={} error={}", local_addr, e)),
                        allow_console,
                    );
                    return Err(e.into());
                }
            };

            let policy = EffectiveTrustPolicy::from_config(enc);
            let chain: Vec<CertificateDer<'static>> = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.clone().into_owned())
                .collect();
            let trusted_dir = enc
                .paths
                .as_ref()
                .and_then(|p| p.trusted_cert_dir.as_deref());
            let observed_dir = policy.observed_dir.as_deref();
            let decision = evaluate_peer_cert_chain(
                &policy,
                trusted_dir,
                observed_dir,
                &chain,
                Some(&our_realm),
            );
            // Emit structured trust event
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
                peer_addr: Some(addr.to_string()),
                realm: Some(our_realm.canonical_code()),
                dry_run: false,
                override_action: None,
            };
            dispatcher::emit(LogEvent::TrustDecision(trust_evt.clone()));
            emit_network_event(
                "transport",
                LogLevel::Info,
                "trust_decision_summary",
                Some(addr.to_string()),
                Some(format!(
                    "outcome={:?} mode={:?} stored={} chain_valid={:?} time_valid={:?}",
                    decision.outcome,
                    policy.mode,
                    decision.stored,
                    decision.chain_valid,
                    decision.time_valid
                )),
                allow_console,
            );
            if matches!(
                decision.outcome,
                crate::security::trust::TrustDecisionOutcome::Reject
            ) {
                return Err("trust policy reject".into());
            }
            let (r, w) = tokio::io::split(tls_stream);
            reader = Box::new(tokio::io::BufReader::new(r));
            writer = Box::new(w);
        } else {
            let (read_half, write_half) = stream.into_split();
            reader = Box::new(tokio::io::BufReader::new(read_half));
            writer = Box::new(write_half);
            emit_network_event(
                "transport",
                LogLevel::Info,
                "connection_mode_plaintext",
                Some(addr.to_string()),
                Some("reason=tls_disabled".to_string()),
                allow_console,
            );
        }
    } else {
        let (read_half, write_half) = stream.into_split();
        reader = Box::new(tokio::io::BufReader::new(read_half));
        writer = Box::new(write_half);
        emit_network_event(
            "transport",
            LogLevel::Info,
            "connection_mode_plaintext",
            Some(addr.to_string()),
            Some("reason=no_config".to_string()),
            allow_console,
        );
    }

    // Wait for peer's HELLO, then reply
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let hello = Message::from_json(&line).ok_or("Failed to parse HELLO")?;

    // Validate remote HELLO (duplicate/self check) before replying
    let (remote_node_id, remote_node_type) = match hello.msg_type {
        MessageType::Hello {
            ref node_id,
            ref node_type,
            ..
        } => (node_id.clone(), node_type.clone()),
        _ => return Err("Expected HELLO from server".into()),
    };
    // Optional realm access policy check on outbound for server's node_type
    if let Some(access) = &config.realm_access {
        if let Some(allowed) = &access.allowed_node_types {
            let pass = match &remote_node_type {
                Some(nt) => allowed.iter().any(|a| a == nt),
                None => false,
            };
            if !pass {
                emit_network_event(
                    "transport",
                    LogLevel::Warn,
                    "realm_access_reject",
                    Some(addr.to_string()),
                    Some(format!("remote_node_type={:?}", remote_node_type)),
                    allow_console,
                );
                return Err("server node_type not allowed".into());
            }
        }
    }
    if remote_node_id == local_node_id {
        // Emit system event for self-id rejection
        use crate::events::{
            dispatcher,
            model::{LogEvent, LogLevel, SystemEvent},
        };
        let mut meta = dispatcher::meta("network", LogLevel::Warn);
        meta.corr_id = Some(dispatcher::correlation_id());
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: "peer_reject_self_id".into(),
            detail: Some(format!("addr={} node_id={}", addr, remote_node_id)),
        }));
        return Err("remote node id matches our own".into());
    }
    if peer_manager.has_node_id(&remote_node_id).await {
        use crate::events::{
            dispatcher,
            model::{LogEvent, LogLevel, SystemEvent},
        };
        let mut meta = dispatcher::meta("network", LogLevel::Info);
        meta.corr_id = Some(dispatcher::correlation_id());
        // Determine flavor: same addr vs different addr
        let action = if peer_manager.has_addr(&addr).await {
            "peer_already_connected"
        } else {
            "peer_cross_connect_suppressed" // opposite side likely also dialing us
        };
        dispatcher::emit(LogEvent::System(SystemEvent {
            meta,
            action: action.into(),
            detail: Some(format!(
                "addr={} node_id={} direction=outbound",
                addr, remote_node_id
            )),
        }));
        return Ok(()); // Keep first connection only
    }

    // Reply HELLO with our realm; peers will compare canonical_code() + version.
    let reply = Message::new(
        DEFAULT_APP_NAME,
        &hello.from,
        MessageType::Hello {
            node_id: local_node_id.clone(),
            listen_addr: Some(format!("{}:{}", local_addr.ip(), our_port)),
            protocol: Some(PROTOCOL_NAME.to_string()),
            version: Some(PROTOCOL_VERSION.to_string()),
            node_type: config.node.as_ref().and_then(|n| n.node_type.clone()),
        },
        None,
        Some(our_realm.clone()),
    );
    writer.write_all(reply.as_json().as_bytes()).await?;
    writer.write_all(b"\n").await?;

    emit_network_event(
        "transport",
        LogLevel::Info,
        "app_handshake_success",
        Some(addr.to_string()),
        Some(format!("peer_id={}", hello.from)),
        allow_console,
    );

    // Create mpsc channel for outgoing messages
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);
    let mut write_half_for_task = writer;
    let addr_clone = addr;
    let allow_console_for_writer = allow_console;
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_half_for_task.write_all(msg.as_bytes()).await {
                emit_network_event(
                    "transport",
                    LogLevel::Error,
                    "write_failed",
                    Some(addr_clone.to_string()),
                    Some(e.to_string()),
                    allow_console_for_writer,
                );
                break;
            }
            if let Err(e) = write_half_for_task.write_all(b"\n").await {
                emit_network_event(
                    "transport",
                    LogLevel::Error,
                    "write_newline_failed",
                    Some(addr_clone.to_string()),
                    Some(e.to_string()),
                    allow_console_for_writer,
                );
                break;
            }
        }
    });
    if let Err(e) = peer_manager
        .add_peer(addr, tx, remote_node_id.clone())
        .await
    {
        emit_network_event(
            "transport",
            LogLevel::Error,
            "peer_register_failed",
            Some(addr.to_string()),
            Some(e.to_string()),
            allow_console,
        );
        return Err(e.into());
    }
    // If remote provided a listen_addr in its HELLO, record it for suppression logic
    if let MessageType::Hello { listen_addr: Some(listen), .. } = hello.msg_type {
        peer_manager.add_listen_addr(&listen, &remote_node_id).await;
    }

    // Spawn periodic PeerRequest gossip if discovery enabled
    if let Some(disc) = &config.discovery {
        if disc.enabled {
            let interval = disc.request_interval_secs.unwrap_or(90);
            let want = disc.request_want.unwrap_or(16);
            let target_addr = addr;
            let allow_console_for_gossip = allow_console;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    // TODO: send actual PeerRequest message to target_addr via its channel
                    // For now just log placeholder
                    emit_network_event(
                        "transport",
                        LogLevel::Debug,
                        "gossip_peer_request_placeholder",
                        Some(target_addr.to_string()),
                        Some(format!("want={}", want)),
                        allow_console_for_gossip,
                    );
                }
            });
        }
    }

    // Use shared receive-and-dispatch loop
    let discovery_enabled = config.discovery.as_ref().map(|d| d.enabled).unwrap_or(true);
    receive_and_dispatch(
        &mut reader,
        addr,
        plugin_manager,
        peer_manager.clone(),
        None,
        discovery_enabled,
        allow_console,
    )
    .await;
    Ok(())
}

/// Handshake-only variant used in tests: performs TCP+TLS (optional) + app HELLO exchange then returns.
/// Does NOT enter the long-running receive loop, preventing test hangs.
pub async fn connect_to_peer_handshake_only(
    peer: &Peer,
    our_realm: RealmInfo,
    our_port: u16,
    allow_console: bool,
    config: &Config,
    local_node_id: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    emit_network_event(
        "transport",
        LogLevel::Info,
        "dial_start_handshake_only",
        Some(peer.address.clone()),
        Some(format!("peer_id={} local_port={}", peer.id, our_port)),
        allow_console,
    );
    let stream = TcpStream::connect(&peer.address).await?;
    let addr = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "tcp_connected_handshake_only",
        Some(addr.to_string()),
        Some(format!("local={} remote={}", local_addr, addr)),
        allow_console,
    );

    let (mut reader, mut writer): (
        Box<dyn tokio::io::AsyncBufRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    );
    if let Some(enc) = &config.encryption {
        if enc.enabled {
            let accept_self_signed = enc
                .trust_policy
                .as_ref()
                .and_then(|tp| tp.accept_self_signed)
                .or(enc.accept_self_signed)
                .unwrap_or(false);
            let mut root_cert_store = RootCertStore::empty();
            if let Some(paths) = &enc.paths {
                if let Some(trusted_cert_dir) = &paths.trusted_cert_dir {
                    if let Ok(entries) = std::fs::read_dir(trusted_cert_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().map(|e| e == "pem").unwrap_or(false) {
                                if let Ok(file) = File::open(&path) {
                                    let mut reader = StdBufReader::new(file);
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
            let mtls = enc.mtls.unwrap_or(false);
            let client_builder = ClientConfig::builder().with_root_certificates(root_cert_store);
            let mut client_cfg = if mtls {
                // Load cert/key
                let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
                let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
                if let Some(paths) = &enc.paths {
                    if let (Some(cert_path), Some(key_path)) =
                        (&paths.own_certificate, &paths.own_private_key)
                    {
                        if let Ok(f) = File::open(cert_path) {
                            let mut reader = StdBufReader::new(f);
                            if let Ok(certs_loaded) = certs(&mut reader) {
                                cert_chain =
                                    certs_loaded.into_iter().map(CertificateDer::from).collect();
                            }
                        }
                        if let Ok(kf) = File::open(key_path) {
                            use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};
                            let mut reader = StdBufReader::new(kf);
                            if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
                                if let Some(key) = keys.pop() {
                                    key_opt =
                                        Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
                                }
                            }
                            if key_opt.is_none() {
                                if let Ok(kf2) = File::open(key_path) {
                                    let mut reader2 = StdBufReader::new(kf2);
                                    if let Ok(mut keys) = rsa_private_keys(&mut reader2) {
                                        if let Some(key) = keys.pop() {
                                            key_opt = Some(
                                                rustls::pki_types::PrivateKeyDer::Pkcs1(key.into()),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if cert_chain.is_empty() || key_opt.is_none() {
                    emit_network_event(
                        "transport",
                        LogLevel::Warn,
                        "mtls_client_material_missing_handshake_only",
                        Some(addr.to_string()),
                        Some("falling_back=no_client_auth".to_string()),
                        allow_console,
                    );
                    client_builder.with_no_client_auth()
                } else {
                    emit_network_event(
                        "transport",
                        LogLevel::Info,
                        "mtls_client_cert_loaded_handshake_only",
                        Some(addr.to_string()),
                        Some(format!("chain_len={}", cert_chain.len())),
                        allow_console,
                    );
                    match key_opt {
                        Some(key) => client_builder
                            .with_client_auth_cert(cert_chain, key)
                            .expect("invalid client cert/key"),
                        None => {
                            emit_network_event(
                                "transport",
                                LogLevel::Warn,
                                "mtls_client_key_missing_handshake_only",
                                Some(addr.to_string()),
                                Some("falling_back=no_client_auth".to_string()),
                                allow_console,
                            );
                            client_builder.with_no_client_auth()
                        }
                    }
                }
            } else {
                client_builder.with_no_client_auth()
            };
            if accept_self_signed {
                client_cfg
                    .dangerous()
                    .set_certificate_verifier(Arc::new(PermissiveVerifier));
            }
            let connector = TlsConnector::from(Arc::new(client_cfg));
            let domain_str = peer
                .address
                .split(':')
                .next()
                .unwrap_or("localhost")
                .to_string();
            let domain = ServerName::try_from(domain_str.clone())?;
            emit_network_event(
                "transport",
                LogLevel::Info,
                "tls_outbound_start_handshake_only",
                Some(addr.to_string()),
                Some(format!(
                    "domain={} accept_self_signed={} mtls={} local={}",
                    domain_str, accept_self_signed, mtls, local_addr
                )),
                allow_console,
            );
            let tls_stream = connector.connect(domain, stream).await?;
            emit_network_event(
                "transport",
                LogLevel::Info,
                "tls_outbound_success_handshake_only",
                Some(addr.to_string()),
                Some(format!("local={} remote={}", local_addr, addr)),
                allow_console,
            );
            // Trust evaluation
            let policy = EffectiveTrustPolicy::from_config(enc);
            let chain: Vec<CertificateDer<'static>> = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.clone().into_owned())
                .collect();
            let trusted_dir = enc
                .paths
                .as_ref()
                .and_then(|p| p.trusted_cert_dir.as_deref());
            let observed_dir = policy.observed_dir.as_deref();
            let decision = crate::security::trust::evaluate_peer_cert_chain(
                &policy,
                trusted_dir,
                observed_dir,
                &chain,
                Some(&our_realm),
            );
            emit_network_event(
                "transport",
                LogLevel::Info,
                "trust_decision_handshake_only",
                Some(addr.to_string()),
                Some(format!(
                    "outcome={:?} reason={} fp={:?}",
                    decision.outcome, decision.reason, decision.fingerprint
                )),
                allow_console,
            );
            if matches!(
                decision.outcome,
                crate::security::trust::TrustDecisionOutcome::Reject
            ) {
                return Err("trust policy reject".into());
            }
            let (r, w) = tokio::io::split(tls_stream);
            reader = Box::new(tokio::io::BufReader::new(r));
            writer = Box::new(w);
        } else {
            let (read_half, write_half) = stream.into_split();
            reader = Box::new(tokio::io::BufReader::new(read_half));
            writer = Box::new(write_half);
        }
    } else {
        let (read_half, write_half) = stream.into_split();
        reader = Box::new(tokio::io::BufReader::new(read_half));
        writer = Box::new(write_half);
    }
    // Server sends first HELLO; read it then respond.
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let hello = Message::from_json(&line).ok_or("Failed to parse HELLO (handshake-only)")?;
    let (remote_node_id, remote_node_type) = match hello.msg_type {
        MessageType::Hello {
            ref node_id,
            ref node_type,
            ..
        } => (node_id.clone(), node_type.clone()),
        _ => return Err("Expected HELLO from server".into()),
    };
    if let Some(access) = &config.realm_access {
        if let Some(allowed) = &access.allowed_node_types {
            let pass = match &remote_node_type {
                Some(nt) => allowed.iter().any(|a| a == nt),
                None => false,
            };
            if !pass {
                return Err("server node_type not allowed".into());
            }
        }
    }
    if remote_node_id == local_node_id {
        return Err("remote node id matches our own".into());
    }
    let reply = Message::new(
        DEFAULT_APP_NAME,
        &hello.from,
        MessageType::Hello {
            node_id: local_node_id,
            listen_addr: Some(format!("{}:{}", local_addr.ip(), our_port)),
            protocol: Some(PROTOCOL_NAME.to_string()),
            version: Some(PROTOCOL_VERSION.to_string()),
            node_type: config.node.as_ref().and_then(|n| n.node_type.clone()),
        },
        None,
        Some(our_realm.clone()),
    );
    writer.write_all(reply.as_json().as_bytes()).await?;
    writer.write_all(b"\n").await?;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "app_handshake_success_handshake_only",
        Some(addr.to_string()),
        Some(format!("peer_id={}", hello.from)),
        allow_console,
    );
    Ok(())
}

/// Shared receive-and-dispatch loop for peer connections
pub async fn receive_and_dispatch<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    addr: SocketAddr,
    plugin_manager: Arc<PluginManager>,
    peer_manager: PeerManager,
    // Optional: peer discovery store
    peer_store: Option<crate::network::peer_store::PeerStore>,
    discovery_enabled: bool,
    allow_console: bool,
) {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                emit_network_event(
                    "transport",
                    LogLevel::Info,
                    "peer_disconnected",
                    Some(addr.to_string()),
                    None,
                    allow_console,
                );
                peer_manager.remove_peer(&addr).await;
                use crate::events::{
                    dispatcher,
                    model::{LogEvent, LogLevel, SystemEvent},
                };
                let mut meta = dispatcher::meta("network", LogLevel::Info);
                meta.corr_id = Some(dispatcher::correlation_id());
                dispatcher::emit(LogEvent::System(SystemEvent {
                    meta,
                    action: "peer_disconnected".into(),
                    detail: Some(format!("addr={}", addr)),
                }));
                break;
            }
            Ok(_) => {
                if let Some(msg) = Message::from_json(&line) {
                    plugin_manager.dispatch_message(&msg);
                    match msg.msg_type {
                        MessageType::Hello { .. } => {
                            emit_network_event(
                                "transport",
                                LogLevel::Debug,
                                "duplicate_hello_ignored",
                                Some(addr.to_string()),
                                None,
                                allow_console,
                            );
                        }
                        MessageType::Text(text) => {
                            emit_network_event(
                                "transport",
                                LogLevel::Info,
                                "message_text",
                                Some(addr.to_string()),
                                Some(text),
                                allow_console,
                            );
                        }
                        MessageType::PeerRequest { want } => {
                            if discovery_enabled {
                                if let Some(store) = &peer_store {
                                    let connected: std::collections::HashSet<_> =
                                        peer_manager.list_peers().await.into_iter().collect();
                                    let sample = store.sample(want as usize, &connected).await;
                                    if !sample.is_empty() {
                                        let peers_str: Vec<String> =
                                            sample.iter().map(|s| s.to_string()).collect();
                                        let list_msg = Message::new(
                                            &addr.to_string(),
                                            &addr.to_string(),
                                            MessageType::PeerList {
                                                peers: peers_str.clone(),
                                            },
                                            None,
                                            msg.realm.clone(),
                                        );
                                        let _ = list_msg.as_json();
                                        emit_network_event(
                                            "transport",
                                            LogLevel::Debug,
                                            "peer_list_placeholder",
                                            Some(addr.to_string()),
                                            Some(format!("count={}", sample.len())),
                                            allow_console,
                                        );
                                        use crate::events::{
                                            dispatcher,
                                            model::{LogEvent, LogLevel, SystemEvent},
                                        };
                                        let mut meta =
                                            dispatcher::meta("discovery", LogLevel::Info);
                                        meta.corr_id = Some(dispatcher::correlation_id());
                                        dispatcher::emit(LogEvent::System(SystemEvent {
                                            meta,
                                            action: "peer_request_served".into(),
                                            detail: Some(format!(
                                                "addr={} returned={} want={}",
                                                addr,
                                                sample.len(),
                                                want
                                            )),
                                        }));
                                    }
                                }
                            }
                        }
                        MessageType::PeerList { peers } => {
                            if !discovery_enabled {
                                continue;
                            }
                            let mut added = 0usize;
                            if let Some(store) = &peer_store {
                                for p in peers {
                                    if let Ok(sock) = p.parse() {
                                        store
                                            .insert(
                                                sock,
                                                crate::network::peer_store::PeerSource::Gossip,
                                            )
                                            .await;
                                    }
                                    added += 1;
                                }
                            }
                            emit_network_event(
                                "transport",
                                LogLevel::Info,
                                "peer_list_received",
                                Some(addr.to_string()),
                                Some(format!("added={}", added)),
                                allow_console,
                            );
                            // Emit discovery event
                            use crate::events::{
                                dispatcher,
                                model::{LogEvent, LogLevel, SystemEvent},
                            };
                            let mut meta = dispatcher::meta("discovery", LogLevel::Info);
                            meta.corr_id = Some(dispatcher::correlation_id());
                            dispatcher::emit(LogEvent::System(SystemEvent {
                                meta,
                                action: "peer_list_received".into(),
                                detail: Some(format!("from={} added={}", addr, added)),
                            }));
                        }
                        _ => {
                            emit_network_event(
                                "transport",
                                LogLevel::Debug,
                                "message_other",
                                Some(addr.to_string()),
                                Some(format!("payload={:?}", msg.msg_type)),
                                allow_console,
                            );
                        }
                    }
                } else {
                    emit_network_event(
                        "transport",
                        LogLevel::Warn,
                        "message_invalid",
                        Some(addr.to_string()),
                        Some(line.trim().to_string()),
                        allow_console,
                    );
                }
            }
            Err(e) => {
                emit_network_event(
                    "transport",
                    LogLevel::Error,
                    "peer_read_error",
                    Some(addr.to_string()),
                    Some(e.to_string()),
                    allow_console,
                );
                break;
            }
        }
    }
}
