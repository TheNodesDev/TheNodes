// src/network/transport.rs

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::constants::{DEFAULT_APP_NAME, PROTOCOL_NAME, PROTOCOL_VERSION};
use crate::events::model::LogLevel;
use crate::network::events::emit_network_event;
use crate::network::message::{Message, MessageType};
use crate::network::peer::Peer;
use crate::network::peer_manager::PeerManager;
use crate::realms::RealmInfo;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::plugin_host::manager::PluginManager;
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
    pub peer_store: Option<crate::network::peer_store::PeerStore>,
}

pub async fn connect_to_peer<'a>(
    params: ConnectToPeerParams<'a>,
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

    let secure_channel = crate::security::secure_channel::make_secure_channel(&config);
    let channel = secure_channel
        .connect(stream, addr, &our_realm, &config, allow_console)
        .await
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
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
    reader.read_line(&mut line).await?;
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
            capabilities: crate::network::advertised_capabilities(&config),
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
    // Update peer store with successful handshake metadata
    if let Some(store) = &peer_store {
        store
            .mark_success_with_meta(&addr, Some(remote_node_id.clone()), remote_capabilities)
            .await;
    }
    // If remote provided a listen_addr in its HELLO, record it for suppression logic
    if let MessageType::Hello {
        listen_addr: Some(listen),
        ..
    } = hello.msg_type
    {
        peer_manager.add_listen_addr(&listen, &remote_node_id).await;
    }

    // Spawn periodic PeerRequest gossip if discovery enabled
    if let Some(disc) = &config.discovery {
        if disc.enabled {
            let interval = disc.request_interval_secs.unwrap_or(90);
            let want = disc.request_want.unwrap_or(16);
            let target_addr = addr;
            let peer_manager_for_gossip = peer_manager.clone();
            let local_node_id_for_gossip = local_node_id.clone();
            let gossip_realm = our_realm.clone();
            let allow_console_for_gossip = allow_console;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    let req = Message::new(
                        &local_node_id_for_gossip,
                        &target_addr.to_string(),
                        MessageType::PeerRequest { want },
                        None,
                        Some(gossip_realm.clone()),
                    );
                    match peer_manager_for_gossip
                        .send_to_addr(&target_addr, req.as_json())
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
    let relay_selection_enabled = config
        .network
        .as_ref()
        .and_then(|n| n.relay.as_ref())
        .and_then(|r| r.selection.clone())
        .map(|s| s == "rendezvous")
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
        relay_selection_enabled,
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

    let secure_channel = crate::security::secure_channel::make_secure_channel(config);
    let channel = secure_channel
        .connect(stream, addr, &our_realm, config, allow_console)
        .await
        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
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
            capabilities: crate::network::advertised_capabilities(config),
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
#[allow(clippy::too_many_arguments)]
pub async fn receive_and_dispatch<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    addr: SocketAddr,
    plugin_manager: Arc<PluginManager>,
    peer_manager: PeerManager,
    // Optional: peer discovery store
    peer_store: Option<crate::network::peer_store::PeerStore>,
    discovery_enabled: bool,
    relay_enabled: bool,
    relay_store_forward_enabled: bool,
    relay_selection_enabled: bool,
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
                // Remove peer and capture node_id for lifecycle notifications
                let removed_node_id = peer_manager.remove_peer(&addr).await;
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
                // Emit RelayNotify peer_left for all bindings originating from this peer
                if let Some(from_id) = removed_node_id {
                    let pairs = peer_manager.list_bindings_for_from(&from_id).await;
                    for (to_id, binding_id) in pairs {
                        let notify = Message::new(
                            &addr.to_string(),
                            &addr.to_string(),
                            MessageType::RelayNotify {
                                notif_type: crate::network::message::Reason::PeerLeft,
                                binding_id,
                                detail: Some(format!("from={} to={}", from_id, to_id)),
                            },
                            None,
                            None,
                        );
                        let _ = peer_manager.send_to_addr(&addr, notify.as_json()).await;
                    }
                }
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
                                        let send_result = peer_manager
                                            .send_to_addr(&addr, list_msg.as_json())
                                            .await;
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
                                        store.mark_success(&sock).await;
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
                                relay_selection_enabled,
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
