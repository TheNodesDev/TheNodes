// src/network/listener.rs

use crate::constants::*;
use crate::events::{
    dispatcher,
    model::{BindingStatus, ConnectionRole, LogEvent, LogLevel, TrustDecisionEvent},
};
use crate::network::events::emit_network_event;
use crate::network::message::{Message, MessageType};
use crate::network::peer_manager::PeerManager;
use crate::network::peer_store::PeerStore;
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;
use crate::security::trust::{evaluate_peer_cert_chain, EffectiveTrustPolicy};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn log_network_event(
    level: LogLevel,
    action: &str,
    addr: Option<String>,
    detail: Option<String>,
    allow_console: bool,
) {
    emit_network_event("listener", level, action, addr, detail, allow_console);
}

#[allow(clippy::too_many_arguments)]
pub async fn start_listener(
    port: u16,
    our_realm: RealmInfo,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    config: &crate::config::Config,
    node_id: String,
    peer_store: PeerStore,
    emit_console_errors: bool,
) -> Result<(), Box<dyn Error>> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    log_network_event(
        LogLevel::Info,
        "listener_bind",
        Some(addr.clone()),
        None,
        emit_console_errors,
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                log_network_event(
                    LogLevel::Info,
                    "incoming_connection",
                    Some(peer_addr.to_string()),
                    None,
                    emit_console_errors,
                );
                let realm = our_realm.clone();
                let peer_manager_clone = peer_manager.clone();
                let plugin_manager_clone = plugin_manager.clone();
                let port = listener.local_addr()?.port();
                let config_clone = config.clone();
                let node_id_clone = node_id.clone();
                let peer_store_clone = peer_store.clone();
                tokio::spawn(handle_connection(
                    stream,
                    peer_addr,
                    realm,
                    port,
                    peer_manager_clone,
                    plugin_manager_clone,
                    config_clone,
                    node_id_clone,
                    peer_store_clone,
                    emit_console_errors,
                ));
            }
            Err(e) => {
                log_network_event(
                    LogLevel::Error,
                    "accept_failed",
                    None,
                    Some(e.to_string()),
                    emit_console_errors,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::unnecessary_unwrap)]
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    our_realm: RealmInfo,
    our_port: u16,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    config: crate::config::Config,
    node_id: String,
    peer_store: PeerStore,
    emit_console_errors: bool,
) {
    log_network_event(
        LogLevel::Info,
        "handle_connection_start",
        Some(peer_addr.to_string()),
        None,
        emit_console_errors,
    );

    let local_addr = stream.local_addr().unwrap();
    let (mut reader, mut write_half): (
        Box<dyn tokio::io::AsyncBufRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    );
    // TLS acceptor logic
    if let Some(enc) = &config.encryption {
        if enc.enabled {
            use rustls::pki_types::CertificateDer;
            use rustls::ServerConfig;
            use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
            use std::fs::File;
            use std::io::BufReader as StdBufReader;
            use tokio_rustls::TlsAcceptor;
            let mut certs_vec = Vec::new();
            let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;
            if let Some(paths) = &enc.paths {
                if let (Some(cert_path), Some(key_path)) =
                    (&paths.own_certificate, &paths.own_private_key)
                {
                    // Load certs
                    if let Ok(cert_file) = File::open(cert_path) {
                        let mut reader = StdBufReader::new(cert_file);
                        if let Ok(certs) = certs(&mut reader) {
                            certs_vec = certs.into_iter().map(CertificateDer::from).collect();
                        }
                    }
                    // Load private key (try pkcs8, then pkcs1/rsa)
                    if let Ok(key_file) = File::open(key_path) {
                        let mut reader = StdBufReader::new(key_file);
                        if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
                            if let Some(key) = keys.pop() {
                                key_opt = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
                            }
                        }
                        if key_opt.is_none() {
                            let mut reader = StdBufReader::new(File::open(key_path).unwrap());
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
            if !certs_vec.is_empty() && key_opt.is_some() {
                let key_der = key_opt.unwrap();
                let mtls = enc.mtls.unwrap_or(false);
                let accept_self_signed = enc
                    .trust_policy
                    .as_ref()
                    .and_then(|tp| tp.accept_self_signed)
                    .or(enc.accept_self_signed)
                    .unwrap_or(false);
                // Build optional client verifier if mTLS enabled
                let acceptor = if mtls {
                    if accept_self_signed {
                        // Custom permissive verifier: require a client cert but skip issuer / chain validation.
                        use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
                        use rustls::DistinguishedName;
                        #[derive(Debug)]
                        struct PermissiveClientVerifier;
                        impl ClientCertVerifier for PermissiveClientVerifier {
                            fn offer_client_auth(&self) -> bool {
                                true
                            }
                            fn client_auth_mandatory(&self) -> bool {
                                true
                            }
                            fn root_hint_subjects(&self) -> &[DistinguishedName] {
                                &[]
                            }
                            fn verify_client_cert(
                                &self,
                                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                                _now: rustls::pki_types::UnixTime,
                            ) -> Result<ClientCertVerified, rustls::Error>
                            {
                                Ok(ClientCertVerified::assertion())
                            }
                            fn verify_tls12_signature(
                                &self,
                                _message: &[u8],
                                _cert: &rustls::pki_types::CertificateDer<'_>,
                                _dss: &rustls::DigitallySignedStruct,
                            ) -> Result<
                                rustls::client::danger::HandshakeSignatureValid,
                                rustls::Error,
                            > {
                                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
                            }
                            fn verify_tls13_signature(
                                &self,
                                _message: &[u8],
                                _cert: &rustls::pki_types::CertificateDer<'_>,
                                _dss: &rustls::DigitallySignedStruct,
                            ) -> Result<
                                rustls::client::danger::HandshakeSignatureValid,
                                rustls::Error,
                            > {
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
                        log_network_event(
                            LogLevel::Info,
                            "mtls_permissive",
                            Some(peer_addr.to_string()),
                            Some("accept_self_signed=true".to_string()),
                            emit_console_errors,
                        );
                        let server_cfg = ServerConfig::builder()
                            .with_client_cert_verifier(Arc::new(PermissiveClientVerifier))
                            .with_single_cert(certs_vec, key_der)
                            .expect("invalid cert/key");
                        TlsAcceptor::from(Arc::new(server_cfg))
                    } else {
                        use rustls::server::WebPkiClientVerifier;
                        use rustls::RootCertStore;
                        let mut client_roots = RootCertStore::empty();
                        let mut loaded_roots = 0usize;
                        if let Some(paths) = &enc.paths {
                            if let Some(trusted_dir) = &paths.trusted_cert_dir {
                                if let Ok(entries) = std::fs::read_dir(trusted_dir) {
                                    for entry in entries.flatten() {
                                        let p = entry.path();
                                        if p.extension().and_then(|e| e.to_str()) == Some("pem") {
                                            if let Ok(f) = std::fs::File::open(&p) {
                                                let mut reader = std::io::BufReader::new(f);
                                                if let Ok(certs) =
                                                    rustls_pemfile::certs(&mut reader)
                                                {
                                                    for c in certs {
                                                        if client_roots.add(rustls::pki_types::CertificateDer::from(c)).is_ok() { loaded_roots += 1; }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let client_roots = Arc::new(client_roots);
                        match WebPkiClientVerifier::builder(client_roots).build() {
                            Ok(verifier_arc) => {
                                log_network_event(
                                    LogLevel::Info,
                                    "mtls_required",
                                    Some(peer_addr.to_string()),
                                    Some(format!("trusted_roots_loaded={}", loaded_roots)),
                                    emit_console_errors,
                                );
                                let server_cfg = ServerConfig::builder()
                                    .with_client_cert_verifier(verifier_arc)
                                    .with_single_cert(certs_vec, key_der)
                                    .expect("invalid cert/key");
                                TlsAcceptor::from(Arc::new(server_cfg))
                            }
                            Err(e) => {
                                log_network_event(
                                    LogLevel::Error,
                                    "mtls_verifier_build_failed",
                                    Some(peer_addr.to_string()),
                                    Some(e.to_string()),
                                    emit_console_errors,
                                );
                                let server_cfg = ServerConfig::builder()
                                    .with_no_client_auth()
                                    .with_single_cert(certs_vec, key_der)
                                    .expect("invalid cert/key");
                                TlsAcceptor::from(Arc::new(server_cfg))
                            }
                        }
                    }
                } else {
                    let server_cfg = ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs_vec, key_der)
                        .expect("invalid cert/key");
                    TlsAcceptor::from(Arc::new(server_cfg))
                };
                log_network_event(
                    LogLevel::Info,
                    "tls_inbound_start",
                    Some(peer_addr.to_string()),
                    Some(format!("mtls={}", mtls)),
                    emit_console_errors,
                );
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        log_network_event(
                            LogLevel::Info,
                            "tls_inbound_success",
                            Some(peer_addr.to_string()),
                            None,
                            emit_console_errors,
                        );
                        // Extract peer certificates before splitting (avoid borrow of moved value)
                        let peer_chain_owned: Vec<CertificateDer<'static>> = tls_stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .map(|certs| {
                                certs
                                    .iter()
                                    .map(|c| c.clone().into_owned())
                                    .collect()
                            })
                            .unwrap_or_else(Vec::new);
                        let (r, w) = tokio::io::split(tls_stream);
                        reader = Box::new(tokio::io::BufReader::new(r));
                        write_half = Box::new(w);
                        let policy = EffectiveTrustPolicy::from_config(enc);
                        let decision = evaluate_peer_cert_chain(
                            &policy,
                            enc.paths
                                .as_ref()
                                .and_then(|p| p.trusted_cert_dir.as_deref()),
                            policy.observed_dir.as_deref(),
                            &peer_chain_owned,
                            Some(&our_realm),
                        );
                        // Emit structured trust event
                        let mut meta = dispatcher::meta("trust", LogLevel::Info);
                        meta.corr_id = Some(dispatcher::correlation_id());
                        if !emit_console_errors {
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
                            realm: Some(our_realm.canonical_code()),
                            dry_run: false,
                            override_action: None,
                        };
                        dispatcher::emit(LogEvent::TrustDecision(trust_evt.clone()));
                        log_network_event(
                            LogLevel::Info,
                            "trust_decision_summary",
                            Some(peer_addr.to_string()),
                            Some(format!(
                                "outcome={:?} mode={:?} stored={} mtls={} chain_valid={:?} time_valid={:?}",
                                decision.outcome,
                                policy.mode,
                                decision.stored,
                                mtls,
                                decision.chain_valid,
                                decision.time_valid
                            )),
                            emit_console_errors,
                        );
                        if mtls
                            && matches!(
                                decision.outcome,
                                crate::security::trust::TrustDecisionOutcome::Reject
                            )
                        {
                            log_network_event(
                                LogLevel::Warn,
                                "trust_policy_reject",
                                Some(peer_addr.to_string()),
                                None,
                                emit_console_errors,
                            );
                            return;
                        }
                    }
                    Err(e) => {
                        log_network_event(
                            LogLevel::Error,
                            "tls_inbound_failure",
                            Some(peer_addr.to_string()),
                            Some(e.to_string()),
                            emit_console_errors,
                        );
                        return;
                    }
                }
            } else {
                log_network_event(
                    LogLevel::Error,
                    "tls_missing_credentials",
                    Some(peer_addr.to_string()),
                    None,
                    emit_console_errors,
                );
                return;
            }
        } else {
            let (read_half, write_half_) = stream.into_split();
            reader = Box::new(tokio::io::BufReader::new(read_half));
            write_half = Box::new(write_half_);
        }
    } else {
        let (read_half, write_half_) = stream.into_split();
        reader = Box::new(tokio::io::BufReader::new(read_half));
        write_half = Box::new(write_half_);
    }
    let mut line = String::new();

    // Embed our realm; its canonical_code() will be used for matching and by consumers.
    let hello = Message::new(
        "TheNodes",
        &peer_addr.to_string(),
        MessageType::Hello {
            node_id: node_id.clone(),
            listen_addr: Some(format!("{}:{}", local_addr.ip(), our_port)),
            protocol: Some(PROTOCOL_NAME.to_string()),
            version: Some(PROTOCOL_VERSION.to_string()),
            node_type: config.node.as_ref().and_then(|n| n.node_type.clone()),
        },
        None,
        Some(our_realm.clone()),
    );

    if let Err(e) = write_half.write_all(hello.as_json().as_bytes()).await {
        log_network_event(
            LogLevel::Error,
            "hello_send_failed",
            Some(peer_addr.to_string()),
            Some(e.to_string()),
            emit_console_errors,
        );
        return;
    }
    if let Err(e) = write_half.write_all(b"\n").await {
        log_network_event(
            LogLevel::Error,
            "hello_newline_failed",
            Some(peer_addr.to_string()),
            Some(e.to_string()),
            emit_console_errors,
        );
        return;
    }

    // Create mpsc channel for outgoing messages
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);

    // Spawn a task to forward messages from rx to the socket
    let mut write_half_for_task = write_half;
    let peer_addr_clone = peer_addr;
    let emit_console_errors_clone = emit_console_errors;
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_half_for_task.write_all(msg.as_bytes()).await {
                log_network_event(
                    LogLevel::Error,
                    "stream_write_failed",
                    Some(peer_addr_clone.to_string()),
                    Some(e.to_string()),
                    emit_console_errors_clone,
                );
                break;
            }
            if let Err(e) = write_half_for_task.write_all(b"\n").await {
                log_network_event(
                    LogLevel::Error,
                    "stream_newline_failed",
                    Some(peer_addr_clone.to_string()),
                    Some(e.to_string()),
                    emit_console_errors_clone,
                );
                break;
            }
        }
    });

    // Wait for initial reply
    line.clear();
    match reader.read_line(&mut line).await {
        Ok(0) => {
            log_network_event(
                LogLevel::Warn,
                "peer_closed_connection",
                Some(peer_addr.to_string()),
                None,
                emit_console_errors,
            );
            return;
        }
        Ok(_) => {
            if let Some(reply) = Message::from_json(&line) {
                if let Some(peer_realm) = &reply.realm {
                    if !our_realm.matches(peer_realm) {
                        log_network_event(
                            LogLevel::Warn,
                            "realm_mismatch",
                            Some(peer_addr.to_string()),
                            Some(format!("remote_realm={:?}", peer_realm)),
                            emit_console_errors,
                        );
                        return;
                    }
                } else {
                    log_network_event(
                        LogLevel::Warn,
                        "realm_missing",
                        Some(peer_addr.to_string()),
                        None,
                        emit_console_errors,
                    );
                    return;
                }

                match reply.msg_type {
                    MessageType::Hello {
                        node_id: ref remote_node_id,
                        ref listen_addr,
                        ref protocol,
                        ref version,
                        ref node_type,
                    } => {
                        if remote_node_id == &node_id {
                            log_network_event(
                                LogLevel::Warn,
                                "remote_node_id_matches",
                                Some(peer_addr.to_string()),
                                Some(format!("node_id={}", remote_node_id)),
                                emit_console_errors,
                            );
                            use crate::events::{
                                dispatcher,
                                model::{LogEvent, LogLevel, SystemEvent},
                            };
                            let mut meta = dispatcher::meta("network", LogLevel::Warn);
                            meta.corr_id = Some(dispatcher::correlation_id());
                            dispatcher::emit(LogEvent::System(SystemEvent {
                                meta,
                                action: "peer_reject_self_id".into(),
                                detail: Some(format!(
                                    "addr={} node_id={}",
                                    peer_addr, remote_node_id
                                )),
                            }));
                            return;
                        }
                        // Enforce optional realm access policy for node types
                        if let Some(access) = &config.realm_access {
                            if let Some(allowed) = &access.allowed_node_types {
                                let pass = match node_type {
                                    Some(nt) => allowed.iter().any(|a| a == nt),
                                    None => false,
                                };
                                if !pass {
                                    log_network_event(
                                        LogLevel::Warn,
                                        "realm_access_denied",
                                        Some(peer_addr.to_string()),
                                        Some(format!("node_type={:?}", node_type)),
                                        emit_console_errors,
                                    );
                                    use crate::events::{
                                        dispatcher,
                                        model::{LogEvent, LogLevel, SystemEvent},
                                    };
                                    let mut meta = dispatcher::meta("network", LogLevel::Warn);
                                    meta.corr_id = Some(dispatcher::correlation_id());
                                    dispatcher::emit(LogEvent::System(SystemEvent {
                                        meta,
                                        action: "peer_reject_node_type".into(),
                                        detail: Some(format!(
                                            "addr={} node_type={:?}",
                                            peer_addr, node_type
                                        )),
                                    }));
                                    return;
                                }
                            }
                        }
                        if peer_manager.has_node_id(remote_node_id).await {
                            use crate::events::{
                                dispatcher,
                                model::{LogEvent, LogLevel, SystemEvent},
                            };
                            let mut meta = dispatcher::meta("network", LogLevel::Info);
                            meta.corr_id = Some(dispatcher::correlation_id());
                            let action = if peer_manager.has_addr(&peer_addr).await {
                                "peer_already_connected"
                            } else {
                                "peer_cross_connect_suppressed"
                            };
                            dispatcher::emit(LogEvent::System(SystemEvent {
                                meta,
                                action: action.into(),
                                detail: Some(format!(
                                    "addr={} node_id={} direction=inbound",
                                    peer_addr, remote_node_id
                                )),
                            }));
                            return; // Keep existing connection only
                        }
                        log_network_event(
                            LogLevel::Info,
                            "hello_received",
                            Some(peer_addr.to_string()),
                            Some(format!(
                                "node_id={} listen={:?} protocol={:?} version={:?}",
                                remote_node_id, listen_addr, protocol, version
                            )),
                            emit_console_errors,
                        );
                        if let Err(e) = peer_manager
                            .add_peer(peer_addr, tx.clone(), remote_node_id.clone())
                            .await
                        {
                            log_network_event(
                                LogLevel::Error,
                                "peer_register_failed",
                                Some(peer_addr.to_string()),
                                Some(e.to_string()),
                                emit_console_errors,
                            );
                            return;
                        }
                        if let Some(listen) = listen_addr {
                            // Track advertised listen address for suppression logic
                            peer_manager.add_listen_addr(listen, remote_node_id).await;
                        }
                    }
                    _ => {
                        log_network_event(
                            LogLevel::Debug,
                            "unexpected_message",
                            Some(peer_addr.to_string()),
                            Some(format!("payload={:?}", reply)),
                            emit_console_errors,
                        );
                    }
                }
            }
        }
        Err(e) => {
            log_network_event(
                LogLevel::Error,
                "peer_read_error",
                Some(peer_addr.to_string()),
                Some(e.to_string()),
                emit_console_errors,
            );
            return;
        }
    }

    // If we reach here without registering (e.g., unexpected code path), ensure channel closed.
    // Normal path registers inside HELLO match; nothing to do here.

    // Use shared receive-and-dispatch loop
    let discovery_enabled = config.discovery.as_ref().map(|d| d.enabled).unwrap_or(true);
    crate::network::transport::receive_and_dispatch(
        &mut reader,
        peer_addr,
        plugin_manager,
        peer_manager,
        Some(peer_store),
        discovery_enabled,
        emit_console_errors,
    )
    .await;
}
