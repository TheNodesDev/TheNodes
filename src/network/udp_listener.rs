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
    let key_recv = static_private.clone();
    let nat_recv = nat_state;

    tokio::spawn(async move {
        run_recv_loop(
            sock_recv,
            sessions_recv,
            pm_recv,
            plugin_manager_recv,
            node_id_recv,
            key_recv,
            nat_recv,
        )
        .await;
    });

    Ok((socket, sessions))
}

// ─── receive loop ─────────────────────────────────────────────────────────────

async fn run_recv_loop(
    socket: Arc<UdpSocket>,
    sessions: UdpSessions,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    local_node_id: String,
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

            let mut map = sessions.lock().await;
            if let Some(session) = map.get_mut(&session_id) {
                match session.advance_handshake(noise_msg2, Some(local_node_id)) {
                    Ok(Some(msg3_bytes)) => {
                        // Build TNCF HANDSHAKE_MSG3: [SESSION_ID][NOISE_MSG3]
                        let mut tncf_body = Vec::with_capacity(SESSION_ID_LEN + msg3_bytes.len());
                        tncf_body.extend_from_slice(&session_id);
                        tncf_body.extend_from_slice(&msg3_bytes);
                        let frame = build_tncf_frame(tncf_type::HANDSHAKE_MSG3, &tncf_body);
                        let _ = socket.send_to(&frame, src).await;

                        if session.is_established() {
                            finalize_session(session, peer_manager).await;
                        }
                    }
                    Ok(None) => {
                        // Should not happen for an initiator receiving msg2.
                    }
                    Err(e) => {
                        crate::network::events::emit_network_event(
                            "udp_listener",
                            crate::events::model::LogLevel::Warn,
                            "udp_hs_advance_failed",
                            Some(src.to_string()),
                            Some(e.to_string()),
                            false,
                        );
                        map.remove(&session_id);
                    }
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

            let mut map = sessions.lock().await;
            if let Some(session) = map.get_mut(&session_id) {
                match session.advance_handshake(noise_msg3, None) {
                    Ok(None) => {
                        if session.is_established() {
                            finalize_session(session, peer_manager).await;
                        }
                    }
                    Ok(Some(_)) => {
                        // Unexpected response in msg3 path.
                    }
                    Err(e) => {
                        crate::network::events::emit_network_event(
                            "udp_listener",
                            crate::events::model::LogLevel::Warn,
                            "udp_hs_msg3_failed",
                            Some(src.to_string()),
                            Some(e.to_string()),
                            false,
                        );
                        map.remove(&session_id);
                    }
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

async fn finalize_session(session: &NoiseUdpSession, peer_manager: &PeerManager) {
    if let Some(node_id) = &session.node_id {
        peer_manager
            .set_transport_kind(node_id, TransportKind::Udp)
            .await;
        peer_manager
            .set_udp_session_id(node_id, session.session_id)
            .await;
        crate::network::events::emit_network_event(
            "udp_listener",
            crate::events::model::LogLevel::Info,
            "udp_session_established",
            Some(session.peer_addr.to_string()),
            Some(format!(
                "node_id={} session={}",
                node_id,
                hex::encode(session.session_id)
            )),
            false,
        );
    }
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
/// Looks for `pki/noise/static.key` relative to the process working directory.
pub fn load_static_key() -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let key_path = std::path::Path::new("pki/noise/static.key");
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

    /// Plugin that answers every message by replying to `target_node_id` over UDP,
    /// re-entering `send_udp` on the same `sessions` map used by `handle_session_frame`.
    struct ReplyingPlugin {
        target_node_id: String,
    }

    #[async_trait]
    impl Plugin for ReplyingPlugin {
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
