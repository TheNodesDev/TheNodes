// src/network/udp_listener.rs
//! UDP socket listener and session management for ADR-0004 Noise transport.
//!
//! ## Receive-path demux (ADR-0004 §2.1 + §4)
//! 1. First 4 bytes == `TNCF_MAGIC` → TNCF control frame; route by TYPE byte.
//! 2. Otherwise → session-ID-prefixed data frame (first 8 bytes = session_id).
//!
//! ## DoS hardening (ADR-0004 §4)
//! - At most 64 concurrent sessions in Handshaking state.
//! - At most 8 new-handshake (HANDSHAKE_MSG1) frames per second per source IP.
//! - Handshake expiry: 5 seconds; reaped by `spawn_session_reaper`.
//!
//! ## Session reaper
//! `spawn_session_reaper` runs periodically and removes:
//! - Established sessions inactive for > 2 × `SESSION_IDLE_TIMEOUT_SECS`.
//! - Handshaking sessions older than 5 seconds (`HANDSHAKE_EXPIRY_SECS`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::network::message::Message;
use crate::network::peer_manager::{PeerManager, TransportKind};
use crate::network::udp_session::{
    build_session_frame, build_tncf_frame, has_reserved_tncf_prefix, is_tncf_frame,
    load_or_generate_static_keypair, parse_tncf_frame, tncf_type, NoiseUdpSession,
    MAX_APP_PAYLOAD_BYTES, MAX_DATAGRAM_BYTES, SESSION_ID_LEN,
};
use crate::plugin_host::manager::PluginManager;

// ─── Types ─────────────────────────────────────────────────────────────────────

/// Shared map of all live UDP sessions keyed by their 8-byte session_id.
pub type UdpSessions = Arc<Mutex<HashMap<[u8; SESSION_ID_LEN], NoiseUdpSession>>>;

// ─── Constants ─────────────────────────────────────────────────────────────────

const MAX_CONCURRENT_HANDSHAKES: usize = 64;
const HANDSHAKE_RATE_LIMIT_PER_IP: u32 = 8; // per second
const HANDSHAKE_EXPIRY_SECS: u64 = 5;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 120;
const REAPER_INTERVAL_SECS: u64 = 30;

// ─── Rate-limit state (per-IP) ─────────────────────────────────────────────────

/// Tracks new-handshake attempts per IP address within a 1-second window.
struct IpRateEntry {
    count: u32,
    window_start: Instant,
}

impl IpRateEntry {
    fn check_and_increment(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 1;
            self.window_start = now;
            true
        } else if self.count < HANDSHAKE_RATE_LIMIT_PER_IP {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

// ─── spawn_udp_listener ────────────────────────────────────────────────────────

/// Bind a UDP socket, spawn the receive loop, and return the socket + sessions map.
///
/// # Parameters
/// - `bind_addr`: the local socket address to bind (e.g., `"0.0.0.0:51820"`).
/// - `peer_manager`: shared peer manager (for recording `TransportKind` on handshake completion).
/// - `local_node_id`: this node's stable identity string.
/// - `static_private`: the 32-byte Noise static private key.
/// - `nat_state`: optional NAT traversal state for Phase 2+3 (ADR-0005).
///
/// # Returns
/// `(Arc<UdpSocket>, UdpSessions)`.  The caller can also use the socket for outbound
/// `connect_udp` calls.
///
/// # Errors
/// Returns `std::io::Error` if the socket cannot be bound.
pub async fn spawn_udp_listener(
    bind_addr: SocketAddr,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    local_node_id: String,
    config: crate::config::Config,
    static_private: Vec<u8>,
    nat_state: Option<Arc<crate::network::nat_traversal::NatState>>,
) -> std::io::Result<(Arc<UdpSocket>, UdpSessions)> {
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));

    // Register the socket handle in PeerManager for Phase 3 punch execution.
    peer_manager
        .set_udp_handle(socket.clone(), sessions.clone(), static_private.clone())
        .await;

    let sock_recv = socket.clone();
    let sessions_recv = sessions.clone();
    let pm_recv = peer_manager.clone();
    let plugin_manager_recv = plugin_manager.clone();
    let node_id_recv = local_node_id.clone();
    let config_recv = config;
    let key_recv = static_private.clone();
    let nat_recv = nat_state;

    tokio::spawn(async move {
        run_recv_loop(
            sock_recv,
            sessions_recv,
            pm_recv,
            plugin_manager_recv,
            node_id_recv,
            config_recv,
            key_recv,
            nat_recv,
        )
        .await;
    });

    Ok((socket, sessions))
}

// ─── receive loop ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_recv_loop(
    socket: Arc<UdpSocket>,
    sessions: UdpSessions,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    local_node_id: String,
    config: crate::config::Config,
    static_private: Vec<u8>,
    nat_state: Option<Arc<crate::network::nat_traversal::NatState>>,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM_BYTES + 64];
    let mut rate_limits: HashMap<IpAddr, IpRateEntry> = HashMap::new();

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                crate::network::events::emit_network_event(
                    "udp_listener",
                    crate::events::model::LogLevel::Error,
                    "recv_error",
                    None,
                    Some(e.to_string()),
                    false,
                );
                continue;
            }
        };

        let datagram = &buf[..len];

        if len > MAX_DATAGRAM_BYTES {
            crate::network::events::emit_network_event(
                "udp_listener",
                crate::events::model::LogLevel::Warn,
                "udp_datagram_too_large",
                Some(src.to_string()),
                Some(format!("len={} max={}", len, MAX_DATAGRAM_BYTES)),
                false,
            );
            continue;
        }

        if is_tncf_frame(datagram) {
            handle_tncf(
                datagram,
                src,
                &socket,
                &sessions,
                &peer_manager,
                &local_node_id,
                &config,
                &static_private,
                &mut rate_limits,
                nat_state.as_deref(),
            )
            .await;
        } else {
            handle_session_frame(
                datagram,
                src,
                &sessions,
                &peer_manager,
                &plugin_manager,
                &local_node_id,
            )
            .await;
        }
    }
}

// ─── TNCF frame dispatch ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_tncf(
    datagram: &[u8],
    src: SocketAddr,
    socket: &Arc<UdpSocket>,
    sessions: &UdpSessions,
    peer_manager: &PeerManager,
    local_node_id: &str,
    config: &crate::config::Config,
    static_private: &[u8],
    rate_limits: &mut HashMap<IpAddr, IpRateEntry>,
    nat_state: Option<&crate::network::nat_traversal::NatState>,
) {
    let (frame_type, body) = match parse_tncf_frame(datagram) {
        Some(v) => v,
        None => return, // too short — drop silently
    };

    match frame_type {
        tncf_type::KEEPALIVE => {
            // Keepalive: update last_seen for any session matching the source addr.
            // We must search by peer_addr because no session_id in a keepalive.
            let mut map = sessions.lock().await;
            for session in map.values_mut() {
                if session.peer_addr == src {
                    session.last_seen = Instant::now();
                }
            }
        }

        tncf_type::HANDSHAKE_MSG1 => {
            // ADR-0004 §2.5: DoS rate-limit check.
            let entry = rate_limits.entry(src.ip()).or_insert(IpRateEntry {
                count: 0,
                window_start: Instant::now(),
            });
            if !entry.check_and_increment() {
                crate::network::events::emit_network_event(
                    "udp_listener",
                    crate::events::model::LogLevel::Warn,
                    "udp_hs_rate_limited",
                    Some(src.to_string()),
                    None,
                    false,
                );
                return;
            }

            // ADR-0004 §2.5: Concurrent handshake cap.
            {
                let map = sessions.lock().await;
                let handshaking_count = map.values().filter(|s| !s.is_established()).count();
                if handshaking_count >= MAX_CONCURRENT_HANDSHAKES {
                    crate::network::events::emit_network_event(
                        "udp_listener",
                        crate::events::model::LogLevel::Warn,
                        "udp_hs_cap_reached",
                        Some(src.to_string()),
                        None,
                        false,
                    );
                    return;
                }
            }

            // Body layout for HANDSHAKE_MSG1: [SESSION_ID: 8][NOISE_MSG1: variable].
            // Anti-amplification: we MUST NOT respond with a message larger than this datagram.
            if body.len() < SESSION_ID_LEN {
                return;
            }
            let session_id: [u8; SESSION_ID_LEN] = body[..SESSION_ID_LEN].try_into().unwrap();
            if has_reserved_tncf_prefix(&session_id) {
                crate::network::events::emit_network_event(
                    "udp_listener",
                    crate::events::model::LogLevel::Warn,
                    "udp_hs_reserved_session_id",
                    Some(src.to_string()),
                    Some(hex::encode(session_id)),
                    false,
                );
                return;
            }
            let noise_msg1 = &body[SESSION_ID_LEN..];

            // ADR-0004 §2.1: Responder MUST reuse the initiator's session_id.
            let result = NoiseUdpSession::new_responder(
                session_id,
                src,
                noise_msg1,
                static_private,
                local_node_id,
            );

            match result {
                Ok((session, msg2_bytes)) => {
                    // Anti-amplification: only send msg2 if <= 3× the incoming datagram.
                    // In practice Noise_XX msg2 is ~96 bytes; msg1 is ~48 bytes — ratio is ~2×,
                    // well within the 3× limit.
                    if msg2_bytes.len() <= datagram.len() * 3 {
                        // Build TNCF HANDSHAKE_MSG2 frame body: [SESSION_ID][NOISE_MSG2]
                        let mut tncf_body = Vec::with_capacity(SESSION_ID_LEN + msg2_bytes.len());
                        tncf_body.extend_from_slice(&session_id);
                        tncf_body.extend_from_slice(&msg2_bytes);
                        let frame = build_tncf_frame(tncf_type::HANDSHAKE_MSG2, &tncf_body);
                        let _ = socket.send_to(&frame, src).await;
                    }
                    sessions.lock().await.insert(session_id, session);
                }
                Err(e) => {
                    crate::network::events::emit_network_event(
                        "udp_listener",
                        crate::events::model::LogLevel::Warn,
                        "udp_hs_responder_failed",
                        Some(src.to_string()),
                        Some(e.to_string()),
                        false,
                    );
                }
            }
        }

        tncf_type::HANDSHAKE_MSG2 => {
            // Initiator receives msg2; body = [SESSION_ID][NOISE_MSG2].
            if body.len() < SESSION_ID_LEN {
                return;
            }
            let session_id: [u8; SESSION_ID_LEN] = body[..SESSION_ID_LEN].try_into().unwrap();
            if has_reserved_tncf_prefix(&session_id) {
                return;
            }
            let noise_msg2 = &body[SESSION_ID_LEN..];

            // Advance the handshake while holding the sessions lock (required to
            // mutate the session), but capture only small owned facts about a
            // newly-established session and release the lock immediately
            // afterwards. `finalize_session` may perform blocking file I/O
            // (ADR-0008 Noise trust modes) and must never run while this lock is
            // held — see the comment on `finalize_session` for why.
            enum Advance {
                SendMsg3 {
                    msg3_bytes: Vec<u8>,
                    established: Option<EstablishedSessionInfo>,
                },
                NoResponse,
                Failed(String),
            }

            let advance = {
                let mut map = sessions.lock().await;
                let Some(session) = map.get_mut(&session_id) else {
                    return;
                };
                match session.advance_handshake(noise_msg2, Some(local_node_id)) {
                    Ok(Some(msg3_bytes)) => {
                        let established = session
                            .is_established()
                            .then(|| EstablishedSessionInfo::capture(session));
                        Advance::SendMsg3 {
                            msg3_bytes,
                            established,
                        }
                    }
                    Ok(None) => Advance::NoResponse,
                    Err(e) => {
                        map.remove(&session_id);
                        Advance::Failed(e.to_string())
                    }
                }
            };

            match advance {
                Advance::SendMsg3 {
                    msg3_bytes,
                    established,
                } => {
                    // Build TNCF HANDSHAKE_MSG3: [SESSION_ID][NOISE_MSG3]
                    let mut tncf_body = Vec::with_capacity(SESSION_ID_LEN + msg3_bytes.len());
                    tncf_body.extend_from_slice(&session_id);
                    tncf_body.extend_from_slice(&msg3_bytes);
                    let frame = build_tncf_frame(tncf_type::HANDSHAKE_MSG3, &tncf_body);
                    let _ = socket.send_to(&frame, src).await;

                    if let Some(info) = established {
                        let accepted = finalize_session(
                            session_id,
                            info,
                            peer_manager,
                            config,
                            crate::events::model::ConnectionRole::Outbound,
                        )
                        .await;
                        if !accepted {
                            sessions.lock().await.remove(&session_id);
                        }
                    }
                }
                Advance::NoResponse => {
                    // Should not happen for an initiator receiving msg2.
                }
                Advance::Failed(e) => {
                    crate::network::events::emit_network_event(
                        "udp_listener",
                        crate::events::model::LogLevel::Warn,
                        "udp_hs_advance_failed",
                        Some(src.to_string()),
                        Some(e),
                        false,
                    );
                }
            }
        }

        tncf_type::HANDSHAKE_MSG3 => {
            // Responder receives msg3; body = [SESSION_ID][NOISE_MSG3].
            if body.len() < SESSION_ID_LEN {
                return;
            }
            let session_id: [u8; SESSION_ID_LEN] = body[..SESSION_ID_LEN].try_into().unwrap();
            if has_reserved_tncf_prefix(&session_id) {
                return;
            }
            let noise_msg3 = &body[SESSION_ID_LEN..];

            // See the matching comment in the HANDSHAKE_MSG2 arm: capture owned
            // facts and release the sessions lock before calling
            // `finalize_session`, which may perform blocking file I/O.
            enum Advance {
                Established(EstablishedSessionInfo),
                NotYetEstablished,
                Unexpected,
                Failed(String),
            }

            let advance = {
                let mut map = sessions.lock().await;
                let Some(session) = map.get_mut(&session_id) else {
                    return;
                };
                match session.advance_handshake(noise_msg3, None) {
                    Ok(None) => {
                        if session.is_established() {
                            Advance::Established(EstablishedSessionInfo::capture(session))
                        } else {
                            Advance::NotYetEstablished
                        }
                    }
                    Ok(Some(_)) => Advance::Unexpected,
                    Err(e) => {
                        map.remove(&session_id);
                        Advance::Failed(e.to_string())
                    }
                }
            };

            match advance {
                Advance::Established(info) => {
                    let accepted = finalize_session(
                        session_id,
                        info,
                        peer_manager,
                        config,
                        crate::events::model::ConnectionRole::Inbound,
                    )
                    .await;
                    if !accepted {
                        sessions.lock().await.remove(&session_id);
                    }
                }
                Advance::NotYetEstablished => {}
                Advance::Unexpected => {
                    // Unexpected response in msg3 path.
                }
                Advance::Failed(e) => {
                    crate::network::events::emit_network_event(
                        "udp_listener",
                        crate::events::model::LogLevel::Warn,
                        "udp_hs_msg3_failed",
                        Some(src.to_string()),
                        Some(e),
                        false,
                    );
                }
            }
        }

        tncf_type::OBSERVE_REQ => {
            if let Some(nat) = nat_state {
                crate::network::nat_traversal::handle_observe_req(nat, socket, src, body).await;
            }
        }

        tncf_type::COOKIE_CHALLENGE => {
            crate::network::nat_traversal::handle_cookie_challenge(peer_manager, socket, src, body)
                .await;
        }

        tncf_type::OBSERVE_RESP => {
            crate::network::nat_traversal::handle_observe_resp(peer_manager, src, body).await;
        }

        _ => {
            // Unknown TNCF TYPE — drop silently.
        }
    }
}

// ─── Session-ID-prefixed data frame ───────────────────────────────────────────

async fn handle_session_frame(
    datagram: &[u8],
    src: SocketAddr,
    sessions: &UdpSessions,
    peer_manager: &PeerManager,
    plugin_manager: &Arc<PluginManager>,
    local_node_id: &str,
) {
    if datagram.len() < SESSION_ID_LEN {
        return;
    }
    let session_id: [u8; SESSION_ID_LEN] = datagram[..SESSION_ID_LEN].try_into().unwrap();
    let ciphertext = &datagram[SESSION_ID_LEN..];

    // Decrypt (and capture everything needed afterwards) while the sessions lock is
    // held, then drop the guard before awaiting any further work. `process_incoming_message`
    // and `dispatch_message` may deliver a reply through `PluginContext`/`PeerManager`,
    // which can route back into `send_udp` and try to re-lock this same, non-reentrant
    // `tokio::sync::Mutex` — holding the guard across those awaits would deadlock the
    // entire UDP receive loop for every peer on the node.
    enum Decrypted {
        Ok {
            node_id: Option<String>,
            payload: Vec<u8>,
        },
        Err(String),
    }

    let mut map = sessions.lock().await;
    let outcome = map.get_mut(&session_id).and_then(|session| {
        if !session.is_established() {
            // Frames arriving for a still-Handshaking session by session-ID prefix are dropped.
            return None;
        }
        let mut plaintext = vec![0u8; ciphertext.len()];
        Some(match session.decrypt(ciphertext, &mut plaintext, src) {
            Ok(n) => {
                plaintext.truncate(n);
                crate::network::events::emit_network_event(
                    "udp_listener",
                    crate::events::model::LogLevel::Debug,
                    "udp_data_received",
                    Some(src.to_string()),
                    Some(format!(
                        "session={} node_id={:?} bytes={}",
                        hex::encode(session_id),
                        session.node_id,
                        plaintext.len()
                    )),
                    false,
                );
                Decrypted::Ok {
                    node_id: session.node_id.clone(),
                    payload: plaintext,
                }
            }
            Err(e) => Decrypted::Err(e.to_string()),
        })
    });
    drop(map);

    match outcome {
        Some(Decrypted::Ok {
            node_id: Some(node_id),
            payload,
        }) => {
            // Dispatch to the PeerManager so callers can receive UDP messages.
            // (The peer_manager UDP receive API is defined in peer_manager.rs.)
            if let Ok(payload_text) = std::str::from_utf8(&payload) {
                if let Some(message) = Message::from_json(payload_text) {
                    let disposition = crate::network::delivery::process_incoming_message(
                        peer_manager,
                        local_node_id,
                        Some(node_id.as_str()),
                        message,
                    )
                    .await;

                    match disposition {
                        crate::network::delivery::IncomingMessageDisposition::Consumed => {}
                        crate::network::delivery::IncomingMessageDisposition::Dispatch(
                            messages,
                        ) => {
                            for message in messages {
                                plugin_manager.dispatch_message(&message).await;
                            }
                        }
                    }
                    return;
                }
            }

            peer_manager.dispatch_udp_payload(&node_id, &payload).await;
        }
        Some(Decrypted::Ok { node_id: None, .. }) => {}
        Some(Decrypted::Err(e)) => {
            crate::network::events::emit_network_event(
                "udp_listener",
                crate::events::model::LogLevel::Warn,
                "udp_decrypt_failed",
                Some(src.to_string()),
                Some(format!("session={} err={}", hex::encode(session_id), e)),
                false,
            );
        }
        None => {}
    }
}

// ─── Handshake completion callback ────────────────────────────────────────────

/// Owned facts about a just-established session, captured while the session-map
/// lock is briefly held so the lock can be dropped before any further work runs.
struct EstablishedSessionInfo {
    node_id: Option<String>,
    fingerprint: Option<[u8; 32]>,
    peer_addr: SocketAddr,
}

impl EstablishedSessionInfo {
    fn capture(session: &NoiseUdpSession) -> Self {
        Self {
            node_id: session.node_id.clone(),
            fingerprint: session.remote_static_fingerprint(),
            peer_addr: session.peer_addr,
        }
    }
}

/// Evaluate Noise trust for a newly established session and, if accepted,
/// register it with the peer manager.
///
/// Callers MUST NOT hold the `UdpSessions` lock while calling this function.
/// Trust evaluation (`evaluate_noise_fingerprint`) may perform blocking file I/O
/// for TOFU, directory-based allowlists, or observed-artifact storage (ADR-0008).
/// Running that I/O — even via `spawn_blocking` — while the sessions mutex is held
/// would stall every other UDP session, `send_udp`, and the session reaper on this
/// node until the disk operation completes. This function accepts owned data
/// instead of a session reference specifically so it cannot be called while
/// borrowing the session map.
async fn finalize_session(
    session_id: [u8; SESSION_ID_LEN],
    info: EstablishedSessionInfo,
    peer_manager: &PeerManager,
    config: &crate::config::Config,
    role: crate::events::model::ConnectionRole,
) -> bool {
    let EstablishedSessionInfo {
        node_id,
        fingerprint,
        peer_addr,
    } = info;
    let (Some(node_id), Some(fingerprint)) = (node_id, fingerprint) else {
        return false;
    };
    let fingerprint = hex::encode(fingerprint);
    let identity = format!("node:{node_id}");
    let realm = config.realm.clone().unwrap_or_default();
    let config_for_eval = config.clone();
    let node_id_for_eval = node_id.clone();
    let eval_result = tokio::task::spawn_blocking(move || {
        crate::security::secure_channel::evaluate_noise_fingerprint(
            &config_for_eval,
            role,
            peer_addr,
            &realm,
            false,
            &identity,
            &fingerprint,
            None,
        )
    })
    .await;

    match eval_result {
        Ok(Ok(_decision)) => {}
        Ok(Err(err)) => {
            crate::network::events::emit_network_event(
                "udp_listener",
                crate::events::model::LogLevel::Warn,
                "udp_session_trust_rejected",
                Some(peer_addr.to_string()),
                Some(format!("node_id={node_id_for_eval} error={err}")),
                false,
            );
            return false;
        }
        Err(join_err) => {
            crate::network::events::emit_network_event(
                "udp_listener",
                crate::events::model::LogLevel::Warn,
                "udp_session_trust_eval_panicked",
                Some(peer_addr.to_string()),
                Some(format!("node_id={node_id_for_eval} error={join_err}")),
                false,
            );
            return false;
        }
    }

    peer_manager
        .set_transport_kind(&node_id_for_eval, TransportKind::Udp)
        .await;
    peer_manager
        .set_udp_session_id(&node_id_for_eval, session_id)
        .await;
    crate::network::events::emit_network_event(
        "udp_listener",
        crate::events::model::LogLevel::Info,
        "udp_session_established",
        Some(peer_addr.to_string()),
        Some(format!(
            "node_id={} session={}",
            node_id_for_eval,
            hex::encode(session_id)
        )),
        false,
    );
    true
}

// ─── Outbound: initiate a UDP Noise session ────────────────────────────────────

/// Begin a Noise handshake with `target_addr` as the initiator.
///
/// Sends TNCF HANDSHAKE_MSG1 and inserts the pending session into `sessions`.
/// Returns the new `session_id` on success.
///
/// The handshake completion is driven by the receive loop in `spawn_udp_listener`.
pub async fn connect_udp(
    target_addr: SocketAddr,
    socket: &Arc<UdpSocket>,
    sessions: &UdpSessions,
    static_private: &[u8],
    _local_node_id: &str,
) -> Result<[u8; SESSION_ID_LEN], Box<dyn std::error::Error + Send + Sync>> {
    let (session, msg1_bytes) = NoiseUdpSession::new_initiator(target_addr, static_private)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(std::io::Error::other(e.to_string()))
        })?;

    let session_id = session.session_id;

    // TNCF HANDSHAKE_MSG1 body: [SESSION_ID][NOISE_MSG1]
    let mut tncf_body = Vec::with_capacity(SESSION_ID_LEN + msg1_bytes.len());
    tncf_body.extend_from_slice(&session_id);
    tncf_body.extend_from_slice(&msg1_bytes);
    let frame = build_tncf_frame(tncf_type::HANDSHAKE_MSG1, &tncf_body);

    socket.send_to(&frame, target_addr).await?;

    sessions.lock().await.insert(session_id, session);

    Ok(session_id)
}

/// Send an encrypted UDP datagram to a peer identified by `session_id`.
///
/// The session MUST be in Established state.
pub async fn send_udp(
    session_id: &[u8; SESSION_ID_LEN],
    plaintext: &[u8],
    socket: &Arc<UdpSocket>,
    sessions: &UdpSessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if plaintext.len() > MAX_APP_PAYLOAD_BYTES {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "UDP plaintext payload too large: {} > {}",
                plaintext.len(),
                MAX_APP_PAYLOAD_BYTES
            ),
        )));
    }

    let mut map = sessions.lock().await;
    let session = map.get_mut(session_id).ok_or("session not found")?;

    let mut ciphertext = vec![0u8; plaintext.len() + 64];
    let n = session.encrypt(plaintext, &mut ciphertext).map_err(|e| {
        Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error + Send + Sync>
    })?;
    ciphertext.truncate(n);

    let dest = session.peer_addr;
    let frame = build_session_frame(session_id, &ciphertext);
    if frame.len() > MAX_DATAGRAM_BYTES {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "UDP datagram too large: {} > {}",
                frame.len(),
                MAX_DATAGRAM_BYTES
            ),
        )));
    }
    drop(map); // release lock before I/O
    socket.send_to(&frame, dest).await?;
    Ok(())
}

// ─── Session reaper ────────────────────────────────────────────────────────────

/// Spawn a background task that periodically evicts:
/// - Handshaking sessions older than `HANDSHAKE_EXPIRY_SECS` (5 s).
/// - Established sessions idle for more than `2 × SESSION_IDLE_TIMEOUT_SECS`.
pub fn spawn_session_reaper(sessions: UdpSessions) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(REAPER_INTERVAL_SECS));
        loop {
            interval.tick().await;
            reap_sessions(&sessions).await;
        }
    });
}

async fn reap_sessions(sessions: &UdpSessions) {
    let now = Instant::now();
    let mut map = sessions.lock().await;
    let before = map.len();
    map.retain(|_, session| {
        if session.is_established() {
            // Established sessions that never obtained a node_id after handshake are
            // stale and must be evicted (ADR-0004 §3).
            if session.node_id.is_none() {
                return false;
            }
            now.duration_since(session.last_seen)
                < Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS * 2)
        } else {
            // Handshaking — enforce expiry.
            now.duration_since(session.created_at) < Duration::from_secs(HANDSHAKE_EXPIRY_SECS)
        }
    });
    let after = map.len();
    if before != after {
        crate::network::events::emit_network_event(
            "udp_listener",
            crate::events::model::LogLevel::Debug,
            "udp_sessions_reaped",
            None,
            Some(format!("removed={}", before - after)),
            false,
        );
    }
}

// ─── Helper: build static key path from config ────────────────────────────────

/// Resolve the Noise static keypair from the filesystem, generating it if absent.
///
/// Uses `encryption.noise.static_key_path`, defaulting to `pki/noise/static.key`.
pub fn load_static_key(config: &crate::config::Config) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let key_path = config
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.noise.as_ref())
        .and_then(|noise| noise.static_key_path.as_deref())
        .unwrap_or("pki/noise/static.key");
    let key_path = std::path::Path::new(key_path);
    load_or_generate_static_keypair(key_path)
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "noise"))]
mod tests {
    use super::*;
    use crate::network::message::MessageType;
    use crate::network::peer_manager::PeerManager;
    use crate::network::peer_store::PeerStore;
    use crate::plugin_host::{Plugin, PluginContext, PluginManager, PluginRegistrar};
    use async_trait::async_trait;
    use std::path::Path;

    fn generate_noise_private_key() -> Vec<u8> {
        let params: snow::params::NoiseParams =
            "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        snow::Builder::new(params)
            .generate_keypair()
            .unwrap()
            .private
    }

    /// Run a full in-memory Noise XX handshake between two sessions sharing the same
    /// `session_id`, returning (local_view, remote_view) both `Established`.
    fn establish_pair(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        remote_node_id: &str,
        local_node_id: &str,
    ) -> (NoiseUdpSession, NoiseUdpSession) {
        let local_key = generate_noise_private_key();
        let remote_key = generate_noise_private_key();

        let (mut local, msg1) =
            NoiseUdpSession::new_initiator(remote_addr, &local_key).expect("initiator");
        let (mut remote, msg2) = NoiseUdpSession::new_responder(
            local.session_id,
            local_addr,
            &msg1,
            &remote_key,
            remote_node_id,
        )
        .expect("responder");
        let msg3 = local
            .advance_handshake(&msg2, Some(local_node_id))
            .expect("advance initiator")
            .expect("initiator must produce msg3");
        assert!(remote
            .advance_handshake(&msg3, None)
            .expect("advance responder")
            .is_none());

        assert!(local.is_established());
        assert!(remote.is_established());
        (local, remote)
    }

    fn noise_allowlist_config(fingerprint: &str) -> crate::config::Config {
        crate::config::Config {
            encryption: Some(crate::config::EncryptionConfig {
                noise: Some(crate::config::EncryptionNoiseConfig {
                    trust_policy: Some(crate::config::NoiseTrustPolicyConfig {
                        mode: Some("allowlist".to_string()),
                        allowlist_fingerprints: Some(vec![fingerprint.to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn udp_session_applies_noise_allowlist_before_registration() {
        let local_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let remote_node_id = "remote-peer";
        let (session, _) = establish_pair(local_addr, remote_addr, remote_node_id, "local-node");
        let fingerprint = hex::encode(
            session
                .remote_static_fingerprint()
                .expect("established session fingerprint"),
        );
        let peer_manager = PeerManager::new();

        assert!(
            finalize_session(
                session.session_id,
                EstablishedSessionInfo::capture(&session),
                &peer_manager,
                &noise_allowlist_config(&fingerprint),
                crate::events::model::ConnectionRole::Outbound,
            )
            .await
        );
        assert_eq!(
            peer_manager.udp_session_id_for(remote_node_id).await,
            Some(session.session_id)
        );

        let rejected_manager = PeerManager::new();
        assert!(
            !finalize_session(
                session.session_id,
                EstablishedSessionInfo::capture(&session),
                &rejected_manager,
                &noise_allowlist_config(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ),
                crate::events::model::ConnectionRole::Outbound,
            )
            .await
        );
        assert_eq!(
            rejected_manager.udp_session_id_for(remote_node_id).await,
            None
        );
    }

    fn noise_tofu_config(observed_dir: &Path) -> crate::config::Config {
        crate::config::Config {
            encryption: Some(crate::config::EncryptionConfig {
                noise: Some(crate::config::EncryptionNoiseConfig {
                    trust_policy: Some(crate::config::NoiseTrustPolicyConfig {
                        mode: Some("tofu".to_string()),
                        store_new: Some("observed".to_string()),
                        paths: Some(crate::config::TrustPolicyPathsConfig {
                            observed_dir: Some(observed_dir.to_string_lossy().into_owned()),
                            allowlist_dir: None,
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Regression test for the disk-I/O-under-lock hazard: TOFU trust evaluation
    /// reads/writes an on-disk observed-binding file (`evaluate_noise_fingerprint`
    /// → `load_observed_fingerprint_binding`/`store_observed_fingerprint_binding`),
    /// which is exactly the blocking path that must never run while the
    /// `UdpSessions` lock is held. `finalize_session` takes owned data instead of a
    /// session reference precisely so it cannot be called under that lock.
    #[tokio::test]
    async fn udp_session_finalize_applies_noise_tofu_with_directory_backed_binding() {
        let temp = tempfile::tempdir().unwrap();
        let config = noise_tofu_config(temp.path());

        let local_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let remote_node_id = "remote-peer";

        // First handshake: TOFU has no prior binding, so it must be accepted and
        // the binding persisted to disk.
        let (session_a, _) = establish_pair(local_addr, remote_addr, remote_node_id, "local-node");
        let peer_manager = PeerManager::new();
        assert!(
            finalize_session(
                session_a.session_id,
                EstablishedSessionInfo::capture(&session_a),
                &peer_manager,
                &config,
                crate::events::model::ConnectionRole::Outbound,
            )
            .await
        );
        assert_eq!(
            peer_manager.udp_session_id_for(remote_node_id).await,
            Some(session_a.session_id)
        );

        // Second handshake from a different remote static key (impersonation
        // attempt) under the same identity must be rejected because it no longer
        // matches the persisted binding.
        let (session_b, _) = establish_pair(local_addr, remote_addr, remote_node_id, "local-node");
        let rejected_manager = PeerManager::new();
        assert!(
            !finalize_session(
                session_b.session_id,
                EstablishedSessionInfo::capture(&session_b),
                &rejected_manager,
                &config,
                crate::events::model::ConnectionRole::Outbound,
            )
            .await
        );
        assert_eq!(
            rejected_manager.udp_session_id_for(remote_node_id).await,
            None
        );
    }

    /// Regression test for directory-backed Noise allowlists, another
    /// `finalize_session` path that performs blocking directory/file reads.
    #[tokio::test]
    async fn udp_session_finalize_applies_directory_backed_noise_allowlist() {
        let temp = tempfile::tempdir().unwrap();
        let local_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let remote_node_id = "remote-peer";
        let (session, _) = establish_pair(local_addr, remote_addr, remote_node_id, "local-node");
        let fingerprint = hex::encode(
            session
                .remote_static_fingerprint()
                .expect("established session fingerprint"),
        );
        std::fs::write(temp.path().join(format!("{fingerprint}.noise")), b"").unwrap();

        let config = crate::config::Config {
            encryption: Some(crate::config::EncryptionConfig {
                noise: Some(crate::config::EncryptionNoiseConfig {
                    trust_policy: Some(crate::config::NoiseTrustPolicyConfig {
                        mode: Some("allowlist".to_string()),
                        paths: Some(crate::config::TrustPolicyPathsConfig {
                            observed_dir: None,
                            allowlist_dir: Some(temp.path().to_string_lossy().into_owned()),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let peer_manager = PeerManager::new();
        assert!(
            finalize_session(
                session.session_id,
                EstablishedSessionInfo::capture(&session),
                &peer_manager,
                &config,
                crate::events::model::ConnectionRole::Outbound,
            )
            .await
        );
        assert_eq!(
            peer_manager.udp_session_id_for(remote_node_id).await,
            Some(session.session_id)
        );
    }

    #[test]
    fn udp_static_key_uses_configured_noise_path() {
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("identity").join("noise.key");
        let config = crate::config::Config {
            encryption: Some(crate::config::EncryptionConfig {
                noise: Some(crate::config::EncryptionNoiseConfig {
                    static_key_path: Some(key_path.to_string_lossy().into_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let first = load_static_key(&config).expect("configured key should be generated");
        let second = load_static_key(&config).expect("configured key should be reloaded");
        assert_eq!(first, second);
        assert!(key_path.exists());
    }

    /// Plugin that answers every message by replying to `target_node_id` over UDP,
    /// re-entering `send_udp` on the same `sessions` map used by `handle_session_frame`.
    struct ReplyingPlugin {
        target_node_id: String,
    }

    #[async_trait]
    impl Plugin for ReplyingPlugin {
        fn plugin_id(&self) -> &'static str {
            "replying-plugin"
        }

        async fn on_message(&self, _message: &Message, ctx: &PluginContext) {
            let _ = ctx
                .peer_manager
                .send_udp_message_to_node(&self.target_node_id, b"pong")
                .await;
        }
    }

    /// Regression test for the sessions-lock reentrancy deadlock: a plugin replying
    /// over UDP from inside `on_message` must not hang `handle_session_frame`, which
    /// would otherwise freeze UDP receive processing for every peer on the node.
    #[tokio::test]
    async fn handle_session_frame_does_not_deadlock_when_plugin_replies_over_udp() {
        let local_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let remote_node_id = "remote-peer";
        let local_node_id = "local-node";

        let (local_session, mut remote_session) =
            establish_pair(local_addr, remote_addr, remote_node_id, local_node_id);
        let session_id = local_session.session_id;

        let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
        sessions.lock().await.insert(session_id, local_session);

        // Encrypt an inbound message as the remote peer would, addressed to us.
        let inbound = Message::new(
            remote_node_id,
            local_node_id,
            MessageType::Heartbeat,
            None,
            None,
        );
        let plaintext = inbound.as_json();
        let mut ciphertext = vec![0u8; plaintext.len() + 64];
        let n = remote_session
            .encrypt(plaintext.as_bytes(), &mut ciphertext)
            .expect("encrypt");
        ciphertext.truncate(n);
        let datagram = build_session_frame(&session_id, &ciphertext);

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_manager = PeerManager::new();
        peer_manager
            .set_udp_handle(socket, sessions.clone(), generate_noise_private_key())
            .await;
        peer_manager
            .set_udp_session_id(remote_node_id, session_id)
            .await;

        let ctx = PluginContext::new(
            Arc::new(peer_manager.clone()),
            PeerStore::new(),
            crate::events::dispatcher::handle(),
            local_node_id.to_string(),
            crate::config::Config::default(),
            false,
        );
        let mut plugin_manager = PluginManager::with_context(ctx);
        plugin_manager.register_handler(Box::new(ReplyingPlugin {
            target_node_id: remote_node_id.to_string(),
        }));
        let plugin_manager = Arc::new(plugin_manager);

        // Bound the regression test so a sessions-lock reentrancy bug fails promptly
        // instead of hanging the test suite.
        tokio::time::timeout(
            Duration::from_secs(1),
            handle_session_frame(
                &datagram,
                remote_addr,
                &sessions,
                &peer_manager,
                &plugin_manager,
                local_node_id,
            ),
        )
        .await
        .expect(
            "handle_session_frame must not deadlock when a plugin replies over UDP \
             from on_message",
        );
    }
}
