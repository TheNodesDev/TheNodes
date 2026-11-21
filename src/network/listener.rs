// src/network/listener.rs

use crate::constants::*;
use crate::events::model::LogLevel;
use crate::network::events::emit_network_event;
use crate::network::limits::{
    InboundConnectionLimiter, InboundConnectionPermit, InboundLimitReason, NetworkLimits,
};
use crate::network::message::{Message, MessageType};
use crate::network::peer_manager::{PeerManager, TransportKind};
use crate::network::peer_store::PeerStore;
use crate::network::transport::read_bounded_line;
use crate::plugin_host::manager::PluginManager;
use crate::realms::RealmInfo;
use crate::security::node_identity::PresentedIdentity;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Delay after the first consecutive `accept()` error; doubles up to [`ACCEPT_BACKOFF_MAX`].
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

fn log_network_event(
    level: LogLevel,
    action: &str,
    addr: Option<String>,
    detail: Option<String>,
    allow_console: bool,
) {
    emit_network_event("listener", level, action, addr, detail, allow_console);
}

fn log_handshake_timeout(
    peer_addr: &SocketAddr,
    stage: &str,
    limits: &NetworkLimits,
    allow_console: bool,
) {
    log_network_event(
        LogLevel::Warn,
        "handshake_timeout",
        Some(peer_addr.to_string()),
        Some(format!(
            "stage={stage} handshake_timeout_ms={}",
            limits.handshake_timeout.as_millis()
        )),
        allow_console,
    );
}

/// Bind the TCP listener socket on every IPv4 interface. Hosts that must
/// observe bind failures before activating plugins call this first and then
/// [`run_listener`].
pub async fn bind_listener(port: u16, emit_console_errors: bool) -> std::io::Result<TcpListener> {
    bind_listener_on(
        SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port),
        emit_console_errors,
    )
    .await
}

/// Bind the TCP listener socket on `addr`, e.g. on [`Config::bind_ip`].
///
/// [`Config::bind_ip`]: crate::config::Config::bind_ip
pub async fn bind_listener_on(
    addr: SocketAddr,
    emit_console_errors: bool,
) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    log_network_event(
        LogLevel::Info,
        "listener_bind",
        Some(
            listener
                .local_addr()
                .map_or(addr.to_string(), |bound| bound.to_string()),
        ),
        None,
        emit_console_errors,
    );
    Ok(listener)
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
    let listener =
        bind_listener_on(SocketAddr::new(config.bind_ip(), port), emit_console_errors).await?;
    run_listener(
        listener,
        our_realm,
        peer_manager,
        plugin_manager,
        config,
        node_id,
        peer_store,
        emit_console_errors,
    )
    .await
}

/// Accept connections on an already bound listener.
#[allow(clippy::too_many_arguments)]
pub async fn run_listener(
    listener: TcpListener,
    our_realm: RealmInfo,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    config: &crate::config::Config,
    node_id: String,
    peer_store: PeerStore,
    emit_console_errors: bool,
) -> Result<(), Box<dyn Error>> {
    let limits = NetworkLimits::from_config(config);
    let limiter = InboundConnectionLimiter::from_limits(&limits);
    let mut accept_backoff: Option<Duration> = None;
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                accept_backoff = None;
                let permit = match limiter.try_acquire(peer_addr.ip()) {
                    Ok(permit) => permit,
                    Err(rejection) => {
                        let (level, action) = match rejection.reason {
                            InboundLimitReason::TotalCap if rejection.newly_saturated => {
                                (LogLevel::Warn, "inbound_connection_limit_reached")
                            }
                            InboundLimitReason::TotalCap => {
                                (LogLevel::Debug, "inbound_connection_rejected")
                            }
                            InboundLimitReason::PerIpCap => {
                                (LogLevel::Debug, "inbound_connection_rejected_per_ip")
                            }
                        };
                        log_network_event(
                            level,
                            action,
                            Some(peer_addr.to_string()),
                            Some(format!(
                                "active={} max={} max_per_ip={}",
                                limiter.active(),
                                limits.max_inbound_connections,
                                limits.max_inbound_connections_per_ip
                            )),
                            emit_console_errors,
                        );
                        drop(stream);
                        continue;
                    }
                };
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
                    limits,
                    permit,
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
                // Errors such as EMFILE repeat immediately; back off instead of spinning.
                let delay = accept_backoff
                    .map(|previous| (previous * 2).min(ACCEPT_BACKOFF_MAX))
                    .unwrap_or(ACCEPT_BACKOFF_MIN);
                accept_backoff = Some(delay);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::unnecessary_unwrap)]
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
    limits: NetworkLimits,
    permit: InboundConnectionPermit,
) {
    // Held until this task returns so the connection stays counted against the caps.
    let _permit = permit;
    log_network_event(
        LogLevel::Info,
        "handle_connection_start",
        Some(peer_addr.to_string()),
        None,
        emit_console_errors,
    );

    let local_addr = stream.local_addr().unwrap();
    let handshake_deadline = tokio::time::Instant::now() + limits.handshake_timeout;
    let secure_channel = match crate::security::secure_channel::make_secure_channel(&config) {
        Ok(channel) => channel,
        Err(error) => {
            log_network_event(
                LogLevel::Error,
                "secure_channel_config_failed",
                Some(peer_addr.to_string()),
                Some(error.to_string()),
                emit_console_errors,
            );
            return;
        }
    };
    let channel = match tokio::time::timeout_at(
        handshake_deadline,
        secure_channel.accept(stream, peer_addr, &our_realm, &config, emit_console_errors),
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        Ok(Err(e)) => {
            log_network_event(
                LogLevel::Error,
                "secure_channel_accept_failed",
                Some(peer_addr.to_string()),
                Some(e.to_string()),
                emit_console_errors,
            );
            return;
        }
        Err(_) => {
            log_handshake_timeout(&peer_addr, "secure channel", &limits, emit_console_errors);
            return;
        }
    };
    let channel_auth = channel.auth.clone();
    let mut reader = channel.reader;
    let mut write_half = channel.writer;
    log_network_event(
        LogLevel::Info,
        "secure_channel_established",
        Some(peer_addr.to_string()),
        Some(format!(
            "backend={:?} decision={} reason={} local={} remote={}",
            channel.auth.backend, channel.auth.decision, channel.auth.reason, local_addr, peer_addr
        )),
        emit_console_errors,
    );
    let mut line = String::new();

    // Embed our realm; its canonical_code() will be used for matching and by consumers.

    let own_observed_udp = peer_manager
        .own_udp_observed_addr_if_fresh(
            config
                .network
                .as_ref()
                .and_then(|n| n.nat_traversal.as_ref())
                .and_then(|nat| nat.refresh_secs)
                .unwrap_or(300),
        )
        .await;
    // The accepting side speaks first and does not know yet which node
    // connected, so its HELLO leaves `to` empty.
    let hello = Message::new(
        &node_id,
        "",
        MessageType::Hello {
            node_id: node_id.clone(),
            listen_addr: crate::network::hello_listen_addr(
                Some(&peer_manager),
                local_addr.ip(),
                our_port,
            ),
            protocol: Some(PROTOCOL_NAME.to_string()),
            version: Some(PROTOCOL_VERSION.to_string()),
            node_type: config.node.as_ref().and_then(|n| n.node_type.clone()),
            capabilities: crate::network::advertised_capabilities(&config, Some(&peer_manager)),
            udp_listen_addr: crate::network::udp_hello_addr(&config, local_addr.ip()),
            udp_observed_addr: own_observed_udp,
        },
        None,
        Some(our_realm.clone()),
    );

    let hello_line = format!("{}\n", hello.as_json());
    match tokio::time::timeout_at(handshake_deadline, async {
        write_half.write_all(hello_line.as_bytes()).await?;
        write_half.flush().await
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            log_network_event(
                LogLevel::Error,
                "hello_send_failed",
                Some(peer_addr.to_string()),
                Some(e.to_string()),
                emit_console_errors,
            );
            return;
        }
        Err(_) => {
            log_handshake_timeout(&peer_addr, "hello send", &limits, emit_console_errors);
            return;
        }
    }

    // Wait for initial reply
    line.clear();
    let hello_read = tokio::time::timeout_at(
        handshake_deadline,
        read_bounded_line(&mut reader, &mut line, NetworkLimits::MAX_HELLO_FRAME_BYTES),
    )
    .await;
    match hello_read {
        Err(_) => {
            log_handshake_timeout(&peer_addr, "hello", &limits, emit_console_errors);
            return;
        }
        Ok(Ok(0)) => {
            log_network_event(
                LogLevel::Warn,
                "peer_closed_connection",
                Some(peer_addr.to_string()),
                None,
                emit_console_errors,
            );
            return;
        }
        Ok(Ok(_)) => {
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
                        ref capabilities,
                        ref udp_listen_addr,
                        ref udp_observed_addr,
                    } => {
                        if let Err(err) = crate::network::transport::check_hello_addressing(
                            &reply,
                            remote_node_id,
                            &node_id,
                        ) {
                            log_network_event(
                                LogLevel::Warn,
                                "peer_reject_hello_addressing",
                                Some(peer_addr.to_string()),
                                Some(err),
                                emit_console_errors,
                            );
                            return;
                        }
                        if let Err(err) =
                            crate::security::secure_channel::validate_authenticated_node_id(
                                &channel_auth,
                                remote_node_id,
                            )
                        {
                            log_network_event(
                                LogLevel::Warn,
                                "noise_hello_identity_mismatch",
                                Some(peer_addr.to_string()),
                                Some(err.to_string()),
                                emit_console_errors,
                            );
                            return;
                        }
                        let node_identity = peer_manager.node_identity(&config);
                        let identity_verdict = match node_identity
                            .verify(PresentedIdentity::from_auth(&channel_auth), remote_node_id)
                        {
                            Ok(verdict) => verdict,
                            Err(rejection) => {
                                log_network_event(
                                    LogLevel::Warn,
                                    "peer_reject_node_identity",
                                    Some(peer_addr.to_string()),
                                    Some(rejection.to_string()),
                                    emit_console_errors,
                                );
                                return;
                            }
                        };
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
                                "node_id={} listen={:?} protocol={:?} version={:?} caps={:?}",
                                remote_node_id, listen_addr, protocol, version, capabilities
                            )),
                            emit_console_errors,
                        );
                        // Outgoing messages: the writer stamps every frame with the two ends of
                        // this connection (ADR-0012).
                        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(32);
                        let mut write_half_for_task = write_half;
                        let peer_addr_clone = peer_addr;
                        let emit_console_errors_clone = emit_console_errors;
                        let frame_from = node_id.clone();
                        let frame_to = remote_node_id.clone();
                        tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                let frame = msg.into_frame(&frame_from, &frame_to);
                                if let Err(e) =
                                    write_half_for_task.write_all(frame.as_bytes()).await
                                {
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
                                // TLS and Noise buffer what the socket did not take.
                                if let Err(e) = write_half_for_task.flush().await {
                                    log_network_event(
                                        LogLevel::Error,
                                        "stream_write_failed",
                                        Some(peer_addr_clone.to_string()),
                                        Some(e.to_string()),
                                        emit_console_errors_clone,
                                    );
                                    break;
                                }
                            }
                        });
                        // Record the binding before registering, which hands the
                        // peer its queued messages; a binding another connection
                        // took meanwhile, or a full store, refuses it.
                        if !node_identity.commit(&identity_verdict) {
                            log_network_event(
                                LogLevel::Warn,
                                "peer_reject_node_identity",
                                Some(peer_addr.to_string()),
                                Some(format!(
                                    "node_id={remote_node_id} binding could not be recorded"
                                )),
                                emit_console_errors,
                            );
                            return;
                        }
                        // A key `tofu` accepted for the first time becomes
                        // trusted only now that the connection is admitted
                        // (ADR-0016).
                        if let Some(pending) = &channel_auth.pending_trust {
                            if let Err(err) = pending.persist() {
                                log_network_event(
                                    LogLevel::Warn,
                                    "tofu_trust_unwritable",
                                    Some(peer_addr.to_string()),
                                    Some(format!(
                                        "node_id={remote_node_id} path={} error={err}",
                                        pending.path().display()
                                    )),
                                    emit_console_errors,
                                );
                                return;
                            }
                        }
                        if let Err(e) = peer_manager
                            .add_peer(peer_addr, tx, remote_node_id.clone())
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
                        peer_manager
                            .set_peer_bound_fingerprint(
                                peer_addr,
                                identity_verdict.bound_fingerprint().map(str::to_string),
                            )
                            .await;
                        peer_manager
                            .set_transport_kind(remote_node_id, TransportKind::Tcp)
                            .await;
                        peer_manager
                            .set_peer_capabilities(remote_node_id, capabilities.clone())
                            .await;
                        if let Some(listen) = listen_addr {
                            // Track advertised listen address for suppression logic
                            peer_manager.add_listen_addr(listen, remote_node_id).await;
                        }
                        // UDP listen (ADR-0004) and observed (ADR-0005 Phase 2)
                        // addresses from the peer's HELLO, within scope.
                        let dropped = peer_manager
                            .record_hello_udp_addrs(
                                remote_node_id,
                                peer_addr,
                                udp_listen_addr.as_deref(),
                                udp_observed_addr.as_deref(),
                            )
                            .await;
                        if !dropped.is_empty() {
                            log_network_event(
                                LogLevel::Warn,
                                "hello_udp_addr_rejected",
                                Some(peer_addr.to_string()),
                                Some(format!("node_id={remote_node_id} addrs={dropped:?}")),
                                emit_console_errors,
                            );
                        }
                        // Drain store-and-forward queue (handled inside add_peer), nothing else needed here
                    }
                    _ => {
                        log_network_event(
                            LogLevel::Warn,
                            "hello_expected",
                            Some(peer_addr.to_string()),
                            Some(format!("payload={:?}", reply.msg_type)),
                            emit_console_errors,
                        );
                        return;
                    }
                }
            } else {
                log_network_event(
                    LogLevel::Warn,
                    "hello_invalid",
                    Some(peer_addr.to_string()),
                    Some(format!("bytes={}", line.len())),
                    emit_console_errors,
                );
                return;
            }
        }
        Ok(Err(e)) => {
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

    // Only a registered peer reaches the dispatch loop; every other path above returned.

    // Use shared receive-and-dispatch loop
    let discovery_enabled = config.discovery.as_ref().map(|d| d.enabled).unwrap_or(true);
    let relay_enabled = config
        .network
        .as_ref()
        .and_then(|n| n.relay.as_ref())
        .and_then(|r| r.enabled)
        .unwrap_or(false);
    let relay_store_forward_enabled = config
        .network
        .as_ref()
        .and_then(|n| n.relay.as_ref())
        .and_then(|r| r.store_forward)
        .unwrap_or(false);
    let punch_rendezvous = config
        .network
        .as_ref()
        .and_then(|n| n.nat_traversal.as_ref())
        .and_then(|nt| nt.serve)
        .unwrap_or(false);
    crate::network::transport::receive_and_dispatch(
        &mut reader,
        peer_addr,
        plugin_manager,
        peer_manager,
        Some(peer_store),
        discovery_enabled,
        relay_enabled,
        relay_store_forward_enabled,
        emit_console_errors,
        node_id,
        punch_rendezvous,
        limits,
    )
    .await;
}
