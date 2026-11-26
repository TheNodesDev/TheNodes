// src/network/transport.rs

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::constants::{PROTOCOL_NAME, PROTOCOL_VERSION};
use crate::events::model::LogLevel;
use crate::network::connection::ConnectionPolicy;
use crate::network::events::emit_network_event;
use crate::network::limits::NetworkLimits;
use crate::network::message::{Message, MessageType};
use crate::network::peer::Peer;
use crate::network::peer_manager::{PeerManager, TransportKind};
use crate::realms::RealmInfo;
use crate::security::node_identity::{NodeIdentityRegistry, PresentedIdentity};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::plugin_host::manager::PluginManager;

/// Maximum number of characters of a rejected frame that are copied into log events.
const INVALID_FRAME_LOG_CHARS: usize = 256;

/// Read one newline-terminated frame into `line`, refusing frames larger than
/// `max_bytes` (newline included).
///
/// Returns the number of bytes appended, `0` at EOF. A frame that exceeds the
/// limit, or that is not valid UTF-8, yields `InvalidData`; callers are expected
/// to close the connection because the stream position is then undefined.
pub async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut String,
    max_bytes: usize,
) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break;
        }
        let (take, done) = match available.iter().position(|&b| b == b'\n') {
            Some(idx) => (idx + 1, true),
            None => (available.len(), false),
        };
        if bytes.len() + take > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame exceeds {max_bytes} bytes"),
            ));
        }
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if done {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "frame is not valid UTF-8")
    })?;
    line.push_str(text);
    Ok(bytes.len())
}

fn truncate_for_log(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    let mut out: String = trimmed.chars().take(max_chars).collect();
    if out.len() < trimmed.len() {
        out.push('\u{2026}');
    }
    out
}

async fn connect_with_timeout(
    address: &str,
    timeout: Duration,
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(stream) => Ok(stream?),
        Err(_) => Err(format!("tcp connect to {address} timed out after {timeout:?}").into()),
    }
}

/// Addresses taken from one `PEER_LIST`; the rest are ignored.
const MAX_GOSSIP_ADDRS: usize = 64;

fn handshake_timed_out(stage: &str) -> Box<dyn Error + Send + Sync> {
    format!("handshake timed out during {stage}").into()
}

/// A node dials only servers of its own realm: the server's HELLO must name
/// it, as the listener requires of clients. Otherwise gossip or a
/// reconnect could connect the node into another realm.
pub(crate) fn check_server_realm(hello: &Message, our_realm: &RealmInfo) -> Result<(), String> {
    match &hello.realm {
        Some(realm) if our_realm.matches(realm) => Ok(()),
        Some(realm) => Err(format!("server realm {realm:?} is not {our_realm:?}")),
        None => Err("server HELLO names no realm".to_string()),
    }
}

/// Check that a HELLO is addressed like every other frame (ADR-0012): `from`
/// is the node ID it announces and `to` is `expected_to`. The accepting side
/// sends the first HELLO before it knows which node connected, so that HELLO
/// has an empty `to`; the reply names the accepting node.
pub(crate) fn check_hello_addressing(
    hello: &Message,
    hello_node_id: &str,
    expected_to: &str,
) -> Result<(), String> {
    if hello.from != hello_node_id {
        return Err(format!(
            "from={:?} differs from node_id={:?}",
            hello.from, hello_node_id
        ));
    }
    if hello.to != expected_to {
        return Err(format!("to={:?} expected={:?}", hello.to, expected_to));
    }
    Ok(())
}

pub struct ConnectToPeerParams<'a> {
    pub peer: &'a Peer,
    pub our_realm: RealmInfo,
    pub our_port: u16,
    pub peer_manager: PeerManager,
    pub plugin_manager: Arc<PluginManager>,
    pub allow_console: bool,
    pub config: Config,
    pub local_node_id: String,
    pub peer_store: Option<crate::network::peer_store::PeerStore>,
}

pub async fn connect_to_peer(
    params: ConnectToPeerParams<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ConnectToPeerParams {
        peer,
        our_realm,
        our_port,
        peer_manager,
        plugin_manager,
        allow_console,
        config,
        local_node_id,
        peer_store,
    } = params;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "dial_start",
        Some(peer.address.clone()),
        Some(format!("peer_id={} local_port={}", peer.id, our_port)),
        allow_console,
    );

    let policy = ConnectionPolicy::from_network_config(&config);
    let limits = NetworkLimits::from_config(&config);
    let stream = connect_with_timeout(
        &peer.address,
        Duration::from_millis(policy.direct_tcp_timeout_ms.max(1)),
    )
    .await?;
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

    let handshake_deadline = tokio::time::Instant::now() + limits.handshake_timeout;
    let secure_channel = crate::security::secure_channel::make_secure_channel(&config)
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    let channel = tokio::time::timeout_at(
        handshake_deadline,
        secure_channel.connect(stream, addr, &our_realm, &config, allow_console),
    )
    .await
    .map_err(|_| handshake_timed_out("secure channel"))?
    .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    let channel_auth = channel.auth.clone();
    let mut reader = channel.reader;
    let mut writer = channel.writer;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "secure_channel_established",
        Some(addr.to_string()),
        Some(format!(
            "backend={:?} decision={} reason={} local={} remote={}",
            channel.auth.backend, channel.auth.decision, channel.auth.reason, local_addr, addr
        )),
        allow_console,
    );

    // Wait for peer's HELLO, then reply
    let mut line = String::new();
    tokio::time::timeout_at(
        handshake_deadline,
        read_bounded_line(&mut reader, &mut line, NetworkLimits::MAX_HELLO_FRAME_BYTES),
    )
    .await
    .map_err(|_| handshake_timed_out("hello"))??;
    let hello = Message::from_json(&line).ok_or("Failed to parse HELLO")?;

    // Validate remote HELLO (duplicate/self check) before replying
    let (remote_node_id, remote_node_type, remote_capabilities) = match hello.msg_type {
        MessageType::Hello {
            ref node_id,
            ref node_type,
            ref capabilities,
            ..
        } => (node_id.clone(), node_type.clone(), capabilities.clone()),
        _ => return Err("Expected HELLO from server".into()),
    };
    check_hello_addressing(&hello, &remote_node_id, "").inspect_err(|err| {
        emit_network_event(
            "transport",
            LogLevel::Warn,
            "peer_reject_hello_addressing",
            Some(addr.to_string()),
            Some(err.clone()),
            allow_console,
        );
    })?;
    check_server_realm(&hello, &our_realm).inspect_err(|err| {
        let action = if hello.realm.is_some() {
            "realm_mismatch"
        } else {
            "realm_missing"
        };
        emit_network_event(
            "transport",
            LogLevel::Warn,
            action,
            Some(addr.to_string()),
            Some(err.clone()),
            allow_console,
        );
    })?;
    crate::security::secure_channel::validate_authenticated_node_id(&channel_auth, &remote_node_id)
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    let node_identity = peer_manager.node_identity(&config);
    let identity_verdict = node_identity
        .verify(PresentedIdentity::from_auth(&channel_auth), &remote_node_id)
        .map_err(|rejection| {
            emit_network_event(
                "transport",
                LogLevel::Warn,
                "peer_reject_node_identity",
                Some(addr.to_string()),
                Some(rejection.to_string()),
                allow_console,
            );
            Box::new(rejection) as Box<dyn Error + Send + Sync>
        })?;
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
    let reply = Message::new(
        &local_node_id,
        &remote_node_id,
        MessageType::Hello {
            node_id: local_node_id.clone(),
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
    let reply_line = format!("{}\n", reply.as_json());
    tokio::time::timeout_at(handshake_deadline, async {
        writer.write_all(reply_line.as_bytes()).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| handshake_timed_out("hello reply"))??;

    emit_network_event(
        "transport",
        LogLevel::Info,
        "app_handshake_success",
        Some(addr.to_string()),
        Some(format!("peer_id={}", remote_node_id)),
        allow_console,
    );

    // Outgoing messages: the writer stamps every frame with the two ends of
    // this connection (ADR-0012).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(32);
    let mut write_half_for_task = writer;
    let addr_clone = addr;
    let allow_console_for_writer = allow_console;
    let frame_from = local_node_id.clone();
    let frame_to = remote_node_id.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let frame = msg.into_frame(&frame_from, &frame_to);
            if let Err(e) = write_half_for_task.write_all(frame.as_bytes()).await {
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
            // TLS and Noise buffer what the socket did not take.
            if let Err(e) = write_half_for_task.flush().await {
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
        }
    });
    // Record the binding before registering, which hands the peer its queued
    // messages; a binding another connection took meanwhile, or a full store,
    // refuses it.
    if !node_identity.commit(&identity_verdict) {
        let reason = format!("node_id={remote_node_id} binding could not be recorded");
        emit_network_event(
            "transport",
            LogLevel::Warn,
            "peer_reject_node_identity",
            Some(addr.to_string()),
            Some(reason.clone()),
            allow_console,
        );
        return Err(reason.into());
    }
    // A key `tofu` accepted for the first time becomes trusted only now that
    // the connection is admitted (ADR-0016).
    if let Some(pending) = &channel_auth.pending_trust {
        if let Err(err) = pending.persist() {
            let reason = format!(
                "node_id={remote_node_id} path={} error={err}",
                pending.path().display()
            );
            emit_network_event(
                "transport",
                LogLevel::Warn,
                "tofu_trust_unwritable",
                Some(addr.to_string()),
                Some(reason.clone()),
                allow_console,
            );
            return Err(reason.into());
        }
    }
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
    peer_manager
        .set_peer_bound_fingerprint(
            addr,
            identity_verdict.bound_fingerprint().map(str::to_string),
        )
        .await;
    peer_manager
        .set_transport_kind(&remote_node_id, TransportKind::Tcp)
        .await;
    peer_manager
        .set_peer_capabilities(&remote_node_id, remote_capabilities.clone())
        .await;
    // Update peer store with successful handshake metadata
    if let Some(store) = &peer_store {
        store
            .mark_success_with_meta(&addr, Some(remote_node_id.clone()), remote_capabilities)
            .await;
    }
    // Dialling `addr` reached this node, which is better evidence than the
    // listen address its HELLO announces.
    peer_manager
        .set_verified_listen_addr(&remote_node_id, addr)
        .await;
    if let MessageType::Hello {
        udp_listen_addr,
        udp_observed_addr,
        ..
    } = hello.msg_type
    {
        // Within scope of the connection.
        let dropped = peer_manager
            .record_hello_udp_addrs(
                &remote_node_id,
                addr,
                udp_listen_addr.as_deref(),
                udp_observed_addr.as_deref(),
            )
            .await;
        if !dropped.is_empty() {
            emit_network_event(
                "transport",
                LogLevel::Warn,
                "hello_udp_addr_rejected",
                Some(addr.to_string()),
                Some(format!("node_id={remote_node_id} addrs={dropped:?}")),
                allow_console,
            );
        }
    }

    // Spawn periodic PeerRequest gossip if discovery enabled
    if let Some(disc) = &config.discovery {
        if disc.enabled {
            let interval = disc.request_interval_secs.unwrap_or(90);
            let want = disc.request_want.unwrap_or(16);
            let target_addr = addr;
            let peer_manager_for_gossip = peer_manager.clone();
            let gossip_realm = our_realm.clone();
            let allow_console_for_gossip = allow_console;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    let req = Message::outbound(
                        MessageType::PeerRequest { want },
                        None,
                        Some(gossip_realm.clone()),
                    );
                    match peer_manager_for_gossip
                        .send_to_addr(&target_addr, req)
                        .await
                    {
                        Ok(()) => {
                            emit_network_event(
                                "transport",
                                LogLevel::Debug,
                                "gossip_peer_request_sent",
                                Some(target_addr.to_string()),
                                Some(format!("want={}", want)),
                                allow_console_for_gossip,
                            );
                        }
                        Err(err) => {
                            emit_network_event(
                                "transport",
                                LogLevel::Debug,
                                "gossip_peer_request_stopped",
                                Some(target_addr.to_string()),
                                Some(err),
                                allow_console_for_gossip,
                            );
                            break;
                        }
                    }
                }
            });
        }
    }

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
    receive_and_dispatch(
        &mut reader,
        addr,
        plugin_manager,
        peer_manager.clone(),
        None,
        discovery_enabled,
        relay_enabled,
        relay_store_forward_enabled,
        allow_console,
        local_node_id,
        punch_rendezvous,
        limits,
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
    let policy = ConnectionPolicy::from_network_config(config);
    let limits = NetworkLimits::from_config(config);
    let stream = connect_with_timeout(
        &peer.address,
        Duration::from_millis(policy.direct_tcp_timeout_ms.max(1)),
    )
    .await?;
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

    let handshake_deadline = tokio::time::Instant::now() + limits.handshake_timeout;
    let secure_channel = crate::security::secure_channel::make_secure_channel(config)
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    let channel = tokio::time::timeout_at(
        handshake_deadline,
        secure_channel.connect(stream, addr, &our_realm, config, allow_console),
    )
    .await
    .map_err(|_| handshake_timed_out("secure channel"))?
    .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    let channel_auth = channel.auth.clone();
    let mut reader = channel.reader;
    let mut writer = channel.writer;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "secure_channel_established_handshake_only",
        Some(addr.to_string()),
        Some(format!(
            "backend={:?} decision={} reason={} local={} remote={}",
            channel.auth.backend, channel.auth.decision, channel.auth.reason, local_addr, addr
        )),
        allow_console,
    );
    // Server sends first HELLO; read it then respond.
    let mut line = String::new();
    tokio::time::timeout_at(
        handshake_deadline,
        read_bounded_line(&mut reader, &mut line, NetworkLimits::MAX_HELLO_FRAME_BYTES),
    )
    .await
    .map_err(|_| handshake_timed_out("hello"))??;
    let hello = Message::from_json(&line).ok_or("Failed to parse HELLO (handshake-only)")?;
    let (remote_node_id, remote_node_type) = match hello.msg_type {
        MessageType::Hello {
            ref node_id,
            ref node_type,
            ..
        } => (node_id.clone(), node_type.clone()),
        _ => return Err("Expected HELLO from server".into()),
    };
    check_hello_addressing(&hello, &remote_node_id, "")?;
    check_server_realm(&hello, &our_realm)?;
    crate::security::secure_channel::validate_authenticated_node_id(&channel_auth, &remote_node_id)
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
    // No peer manager here: pins, certificate names and persisted bindings apply.
    NodeIdentityRegistry::from_config(config)
        .verify(PresentedIdentity::from_auth(&channel_auth), &remote_node_id)
        .map_err(|rejection| Box::new(rejection) as Box<dyn Error + Send + Sync>)?;
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
        &local_node_id,
        &remote_node_id,
        MessageType::Hello {
            node_id: local_node_id.clone(),
            listen_addr: crate::network::hello_listen_addr(None, local_addr.ip(), our_port),
            protocol: Some(PROTOCOL_NAME.to_string()),
            version: Some(PROTOCOL_VERSION.to_string()),
            node_type: config.node.as_ref().and_then(|n| n.node_type.clone()),
            capabilities: crate::network::advertised_capabilities(config, None),
            udp_listen_addr: crate::network::udp_hello_addr(config, local_addr.ip()),
            udp_observed_addr: None, // handshake-only — no peer_manager available
        },
        None,
        Some(our_realm.clone()),
    );
    let reply_line = format!("{}\n", reply.as_json());
    tokio::time::timeout_at(handshake_deadline, async {
        writer.write_all(reply_line.as_bytes()).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| handshake_timed_out("hello reply"))??;
    emit_network_event(
        "transport",
        LogLevel::Info,
        "app_handshake_success_handshake_only",
        Some(addr.to_string()),
        Some(format!("peer_id={}", remote_node_id)),
        allow_console,
    );
    Ok(())
}

enum FrameRead {
    Frame,
    Eof,
    Idle,
    Failed(std::io::Error),
}

async fn read_next_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut String,
    limits: &NetworkLimits,
) -> FrameRead {
    let read = read_bounded_line(reader, line, limits.max_frame_bytes);
    let result = match limits.idle_timeout {
        Some(idle) => match tokio::time::timeout(idle, read).await {
            Ok(result) => result,
            Err(_) => return FrameRead::Idle,
        },
        None => read.await,
    };
    match result {
        Ok(0) => FrameRead::Eof,
        Ok(_) => FrameRead::Frame,
        Err(err) => FrameRead::Failed(err),
    }
}

/// Deregister a peer whose connection ended. Its relay bindings go with it
/// (`PeerManager::remove_peer`).
async fn finish_connection(peer_manager: &PeerManager, addr: SocketAddr) {
    let removed_node_id = peer_manager.handle_peer_disconnected(&addr).await;
    use crate::events::{
        dispatcher,
        model::{LogEvent, LogLevel, SystemEvent},
    };
    let mut meta = dispatcher::meta("network", LogLevel::Info);
    meta.corr_id = Some(dispatcher::correlation_id());
    dispatcher::emit(LogEvent::System(SystemEvent {
        meta,
        action: "peer_disconnected".into(),
        detail: Some(format!("addr={} node_id={:?}", addr, removed_node_id)),
    }));
}

/// Shared receive-and-dispatch loop for peer connections
#[allow(clippy::too_many_arguments)]
pub async fn receive_and_dispatch<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    addr: SocketAddr,
    plugin_manager: Arc<PluginManager>,
    peer_manager: PeerManager,
    // Optional: peer discovery store
    peer_store: Option<crate::network::peer_store::PeerStore>,
    discovery_enabled: bool,
    relay_enabled: bool,
    relay_store_forward_enabled: bool,
    allow_console: bool,
    // ADR-0005: local node identity (for PunchGo initiator/responder determination).
    local_node_id: String,
    // ADR-0005: whether this node acts as a punch rendezvous (for PunchCoordinate/PunchReady).
    punch_rendezvous: bool,
    limits: NetworkLimits,
) {
    let mut line = String::new();
    loop {
        line.clear();
        match read_next_frame(reader, &mut line, &limits).await {
            FrameRead::Eof => {
                emit_network_event(
                    "transport",
                    LogLevel::Info,
                    "peer_disconnected",
                    Some(addr.to_string()),
                    None,
                    allow_console,
                );
                finish_connection(&peer_manager, addr).await;
                break;
            }
            FrameRead::Idle => {
                emit_network_event(
                    "transport",
                    LogLevel::Warn,
                    "peer_idle_timeout",
                    Some(addr.to_string()),
                    limits
                        .idle_timeout
                        .map(|idle| format!("idle_timeout_ms={}", idle.as_millis())),
                    allow_console,
                );
                finish_connection(&peer_manager, addr).await;
                break;
            }
            FrameRead::Failed(e) => {
                let action = if e.kind() == std::io::ErrorKind::InvalidData {
                    "peer_frame_rejected"
                } else {
                    "peer_read_error"
                };
                emit_network_event(
                    "transport",
                    LogLevel::Error,
                    action,
                    Some(addr.to_string()),
                    Some(e.to_string()),
                    allow_console,
                );
                finish_connection(&peer_manager, addr).await;
                break;
            }
            FrameRead::Frame => {
                if let Some(msg) = Message::from_json(&line) {
                    // Attribute the frame to the node registered on this connection,
                    // never to the `from` field the sender wrote. A connection whose
                    // peer was deregistered (e.g. by the liveness monitor) is closed.
                    let Some(delivered_by) = peer_manager.origin_for_addr(&addr).await else {
                        emit_network_event(
                            "transport",
                            LogLevel::Info,
                            "message_from_unregistered_connection",
                            Some(addr.to_string()),
                            Some("closing connection".to_string()),
                            allow_console,
                        );
                        finish_connection(&peer_manager, addr).await;
                        break;
                    };
                    let disposition = crate::network::delivery::process_incoming_message(
                        &peer_manager,
                        &local_node_id,
                        delivered_by,
                        msg,
                    )
                    .await;

                    let dispatch_messages = match disposition {
                        crate::network::delivery::IncomingMessageDisposition::Consumed => {
                            Vec::new()
                        }
                        crate::network::delivery::IncomingMessageDisposition::Dispatch(
                            messages,
                        ) => messages,
                    };

                    for msg in dispatch_messages {
                        // Admission only: plugins handle the message from their own
                        // bounded inbox, so a slow plugin cannot stall this connection.
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
                                            let list_msg = Message::outbound(
                                                MessageType::PeerList {
                                                    peers: peers_str.clone(),
                                                },
                                                None,
                                                msg.realm.clone(),
                                            );
                                            let send_result =
                                                peer_manager.send_to_addr(&addr, list_msg).await;
                                            emit_network_event(
                                                "transport",
                                                if send_result.is_ok() {
                                                    LogLevel::Debug
                                                } else {
                                                    LogLevel::Warn
                                                },
                                                "peer_list_sent",
                                                Some(addr.to_string()),
                                                Some(format!(
                                                    "count={} ok={} err={:?}",
                                                    sample.len(),
                                                    send_result.is_ok(),
                                                    send_result.err()
                                                )),
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
                                // Gossiped addresses are candidates, not nodes this node
                                // has reached, and may be no more local than the peer that
                                // named them.
                                let mut added = 0usize;
                                let mut refused = peers.len().saturating_sub(MAX_GOSSIP_ADDRS);
                                if let Some(store) = &peer_store {
                                    for p in peers.iter().take(MAX_GOSSIP_ADDRS) {
                                        match p.parse() {
                                            Ok(sock)
                                                if crate::network::peer_store::gossip_addr_allowed(
                                                    sock, addr,
                                                ) =>
                                            {
                                                store
                                                    .insert(
                                                        sock,
                                                        crate::network::peer_store::PeerSource::Gossip,
                                                    )
                                                    .await;
                                                added += 1;
                                            }
                                            _ => refused += 1,
                                        }
                                    }
                                }
                                emit_network_event(
                                    "transport",
                                    LogLevel::Info,
                                    "peer_list_received",
                                    Some(addr.to_string()),
                                    Some(format!("added={} refused={}", added, refused)),
                                    allow_console,
                                );
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
                            MessageType::RelayBind { .. } => {
                                crate::network::relay::handle_bind(
                                    &msg,
                                    &addr,
                                    &peer_manager,
                                    relay_enabled,
                                    relay_store_forward_enabled,
                                    allow_console,
                                )
                                .await;
                            }
                            MessageType::RelayBindAck {
                                ok,
                                reason,
                                binding_id,
                                peer_present,
                                nonce,
                            } => {
                                emit_network_event(
                                    "transport",
                                    LogLevel::Info,
                                    "relay_bind_ack",
                                    Some(addr.to_string()),
                                    Some(format!(
                                        "ok={} reason={:?} binding_id={:?} peer_present={:?} nonce={:?}",
                                        ok, reason, binding_id, peer_present, nonce
                                    )),
                                    allow_console,
                                );
                            }
                            MessageType::RelayForward { .. } => {
                                crate::network::relay::handle_forward(
                                    &msg,
                                    &addr,
                                    &peer_manager,
                                    relay_enabled,
                                    relay_store_forward_enabled,
                                    allow_console,
                                )
                                .await;
                            }
                            MessageType::RelayUnbind { .. } => {
                                crate::network::relay::handle_unbind(
                                    &msg,
                                    &addr,
                                    &peer_manager,
                                    allow_console,
                                )
                                .await;
                            }
                            MessageType::Ack { .. } => {
                                crate::network::relay::handle_ack(&msg, &addr, &peer_manager).await;
                            }
                            MessageType::DeliveryAck { .. } => {}
                            MessageType::PunchCoordinate {
                                attempt_id,
                                target,
                                timeout_ms,
                            } => {
                                #[cfg(feature = "noise")]
                                if punch_rendezvous {
                                    if let Some(from_id) =
                                        peer_manager.node_id_for_addr(&addr).await
                                    {
                                        let timeout_ms = timeout_ms.unwrap_or(5000);
                                        peer_manager
                                            .handle_punch_coordinate_msg(
                                                &attempt_id,
                                                &from_id,
                                                &target,
                                                timeout_ms,
                                            )
                                            .await;
                                    }
                                }
                                #[cfg(not(feature = "noise"))]
                                let _ = (attempt_id, target, timeout_ms, punch_rendezvous);
                            }
                            MessageType::PunchInvite {
                                attempt_id,
                                from_node_id,
                                timeout_ms,
                            } => {
                                let max_age_secs =
                                    peer_manager.nat_observation_refresh_secs().await;
                                let our_obs = peer_manager
                                    .own_udp_observed_addr_if_fresh(max_age_secs)
                                    .await;
                                // Agree to the punch before saying so: only a PUNCH_GO
                                // from this rendezvous for this attempt is followed.
                                // Only a rendezvous this node may use is followed
                                // (`[network.nat_traversal] allowed_rendezvous`).
                                let rendezvous = match peer_manager.node_id_for_addr(&addr).await {
                                    Some(rendezvous)
                                        if peer_manager.rendezvous_allowed(&rendezvous).await =>
                                    {
                                        Some(rendezvous)
                                    }
                                    _ => None,
                                };
                                let ok = match rendezvous {
                                    Some(rendezvous) if our_obs.is_some() => {
                                        let budget = Duration::from_millis(timeout_ms.min(
                                            crate::network::peer_manager::MAX_PUNCH_TIMEOUT_MS,
                                        ));
                                        peer_manager
                                            .expect_punch(
                                                &attempt_id,
                                                crate::network::peer_manager::ExpectedPunch {
                                                    rendezvous_node_id: rendezvous,
                                                    initiator_node_id: from_node_id.clone(),
                                                    responder_node_id: local_node_id.clone(),
                                                    expires_at: std::time::Instant::now() + budget,
                                                },
                                            )
                                            .await
                                    }
                                    _ => false,
                                };
                                let ready = Message::outbound(
                                    MessageType::PunchReady {
                                        attempt_id,
                                        target: from_node_id,
                                        ok,
                                    },
                                    None,
                                    None,
                                );
                                let _ = peer_manager.send_to_addr(&addr, ready).await;
                            }
                            MessageType::PunchReady {
                                attempt_id,
                                target,
                                ok,
                            } => {
                                #[cfg(feature = "noise")]
                                if punch_rendezvous {
                                    if let Some(responder_id) =
                                        peer_manager.node_id_for_addr(&addr).await
                                    {
                                        peer_manager
                                            .handle_punch_ready_msg(
                                                &attempt_id,
                                                &responder_id,
                                                &target,
                                                ok,
                                            )
                                            .await;
                                    }
                                }
                                #[cfg(not(feature = "noise"))]
                                let _ = (attempt_id, target, ok, punch_rendezvous);
                            }
                            MessageType::PunchGo {
                                attempt_id,
                                initiator,
                                responder,
                                initiator_observed_addr,
                                responder_observed_addr,
                                start_at_ms,
                                timeout_ms,
                            } => {
                                #[cfg(feature = "noise")]
                                if let Some(rendezvous) = peer_manager.node_id_for_addr(&addr).await
                                {
                                    peer_manager
                                        .handle_punch_go_msg(
                                            &local_node_id,
                                            &rendezvous,
                                            addr,
                                            crate::network::nat_traversal::PunchGoParams {
                                                attempt_id,
                                                initiator,
                                                responder,
                                                initiator_observed_addr,
                                                responder_observed_addr,
                                                start_at_ms,
                                                timeout_ms,
                                            },
                                        )
                                        .await;
                                }
                                #[cfg(not(feature = "noise"))]
                                let _ = (
                                    attempt_id,
                                    initiator,
                                    responder,
                                    initiator_observed_addr,
                                    responder_observed_addr,
                                    start_at_ms,
                                    timeout_ms,
                                );
                            }
                            MessageType::PunchAbort {
                                attempt_id,
                                target,
                                reason,
                            } => {
                                emit_network_event(
                                    "transport",
                                    LogLevel::Info,
                                    "punch_abort",
                                    Some(addr.to_string()),
                                    Some(format!(
                                        "attempt_id={} target={} reason={:?}",
                                        attempt_id, target, reason
                                    )),
                                    allow_console,
                                );
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
                    }
                } else {
                    emit_network_event(
                        "transport",
                        LogLevel::Warn,
                        "message_invalid",
                        Some(addr.to_string()),
                        Some(format!(
                            "bytes={} head={}",
                            line.len(),
                            truncate_for_log(&line, INVALID_FRAME_LOG_CHARS)
                        )),
                        allow_console,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{read_bounded_line, truncate_for_log};
    use tokio::io::BufReader;

    async fn read_all(input: &[u8], max_bytes: usize) -> Vec<std::io::Result<(usize, String)>> {
        let mut reader = BufReader::new(input);
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            match read_bounded_line(&mut reader, &mut line, max_bytes).await {
                Ok(0) => break,
                Ok(n) => out.push(Ok((n, line))),
                Err(err) => {
                    out.push(Err(err));
                    break;
                }
            }
        }
        out
    }

    #[tokio::test]
    async fn reads_lines_up_to_and_including_the_limit() {
        let frames = read_all(b"abc\nde\n", 4).await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].as_ref().unwrap(), &(4, "abc\n".to_string()));
        assert_eq!(frames[1].as_ref().unwrap(), &(3, "de\n".to_string()));
    }

    #[tokio::test]
    async fn rejects_frames_over_the_limit_without_buffering_them() {
        let frames = read_all(b"abcde\nok\n", 4).await;
        assert_eq!(frames.len(), 1);
        let err = frames[0].as_ref().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_unterminated_input_past_the_limit() {
        let payload = vec![b'x'; 10];
        let frames = read_all(&payload, 8).await;
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_err());
    }

    #[tokio::test]
    async fn returns_trailing_partial_line_at_eof() {
        let frames = read_all(b"tail", 8).await;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_ref().unwrap(), &(4, "tail".to_string()));
    }

    #[tokio::test]
    async fn rejects_invalid_utf8() {
        let frames = read_all(&[0xff, 0xfe, b'\n'], 8).await;
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].as_ref().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncates_long_log_text_on_char_boundaries() {
        assert_eq!(truncate_for_log("  short  ", 10), "short");
        let long = "å".repeat(300);
        let truncated = truncate_for_log(&long, 256);
        assert_eq!(truncated.chars().count(), 257);
        assert!(truncated.ends_with('\u{2026}'));
    }
}
