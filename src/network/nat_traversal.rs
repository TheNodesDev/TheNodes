// src/network/nat_traversal.rs
//! NAT traversal helpers for ADR-0005.
//!
//! ## Phase 2 — Observed-address discovery (TNCF)
//!
//! Three TNCF control types carry the observe handshake over UDP:
//!
//! | Type             | Sender | Wire body                                                     |
//! |------------------|--------|---------------------------------------------------------------|
//! | OBSERVE_REQ      | client | `[nonce:8][cookie_len:1][cookie:variable]`                    |
//! | COOKIE_CHALLENGE | server | `[nonce:8][cookie_len:1][cookie:variable]`                    |
//! | OBSERVE_RESP     | server | `[nonce:8][addr_len:1][addr:utf8][observed_at_ms:8_LE]`      |
//!
//! Flow:
//! 1. Client sends OBSERVE_REQ (cookie_len = 0).
//! 2. Server replies COOKIE_CHALLENGE (cookie = SHA-256(secret ‖ bucket ‖ addr)[..16]).
//! 3. Client echoes OBSERVE_REQ with the received cookie.
//! 4. Server validates and replies OBSERVE_RESP with client's observed UDP address.
//! 5. Client calls `peer_manager.set_own_observed_addr`.
//!
//! ## Phase 3 — Relay-coordinated UDP hole punch
//!
//! All punch coordination flows over TCP (existing connections to rendezvous node B):
//!
//! ```text
//! A  →  B : PunchCoordinate { target: C }
//! B  →  C : PunchInvite     { from_node_id: A }
//! C  →  B : PunchReady      { target: A, ok: true }
//! B  →  A : PunchGo         { …, start_at_ms }
//! B  →  C : PunchGo         { …, start_at_ms }
//! A,C     : send probe_count KEEPALIVE probes (opens NAT)
//! A       : connect_udp → C (Noise handshake initiator)
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;

use crate::network::peer_manager::PeerManager;
use crate::network::udp_listener::UdpSessions;
use crate::network::udp_session::{build_tncf_frame, tncf_type};

// ─── Constants ─────────────────────────────────────────────────────────────────

const OBSERVE_NONCE_LEN: usize = 8;
const OBSERVE_RESP_OBSERVED_AT_LEN: usize = 8;
/// Milliseconds of lead time before both peers start their punch window.
const PUNCH_COORDINATE_DELAY_MS: u64 = 500;

// ─── NatState ──────────────────────────────────────────────────────────────────

/// Configuration and keying material for NAT traversal (ADR-0005 §2).
///
/// A single `Arc<NatState>` is shared between the UDP receive loop
/// (`udp_listener`) and the TCP dispatch loop (`transport::receive_and_dispatch`).
#[derive(Debug)]
pub struct NatState {
    /// 32-byte secret for HMAC-style cookie construction.  Generated at startup.
    pub cookie_secret: [u8; 32],
    /// Cookie validity window in seconds.  Two consecutive windows are accepted.
    pub cookie_ttl_secs: u64,
    /// Number of KEEPALIVE probes per punch attempt.
    pub probe_count: u32,
    /// Delay between successive probes (ms).
    pub probe_interval_ms: u64,
    /// Whether this node serves as a punch rendezvous.
    pub serve: bool,
    /// How often to re-probe peers for an updated observed address (seconds).
    pub refresh_secs: u64,
}

impl NatState {
    /// Build a `NatState` from config, generating a fresh random cookie secret.
    pub fn from_config(cfg: &crate::config::NatTraversalConfig) -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            cookie_secret: secret,
            cookie_ttl_secs: cfg.cookie_ttl_secs.unwrap_or(30),
            probe_count: cfg.probe_count.unwrap_or(6),
            probe_interval_ms: cfg.probe_interval_ms.unwrap_or(100),
            serve: cfg.serve.unwrap_or(false),
            refresh_secs: cfg.refresh_secs.unwrap_or(300),
        }
    }
}

/// Parameters delivered in a `PunchGo` coordination message.
#[derive(Clone, Debug)]
pub struct PunchGoParams {
    pub attempt_id: String,
    pub initiator: String,
    pub responder: String,
    pub initiator_observed_addr: String,
    pub responder_observed_addr: String,
    pub start_at_ms: u64,
    pub timeout_ms: u64,
}

// ─── Cookie helpers ────────────────────────────────────────────────────────────

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Derive a 16-byte cookie: `SHA-256(secret ‖ bucket_le ‖ addr_utf8)[..16]`.
fn make_cookie(secret: &[u8; 32], ttl_secs: u64, addr: SocketAddr) -> [u8; 16] {
    let bucket = now_unix_ms() / (ttl_secs * 1000);
    let mut h = Sha256::new();
    h.update(secret);
    h.update(bucket.to_le_bytes());
    h.update(addr.to_string().as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

/// Validate a cookie against the current and previous time bucket (boundary tolerance).
fn validate_cookie(secret: &[u8; 32], ttl_secs: u64, addr: SocketAddr, cookie: &[u8]) -> bool {
    if cookie.len() != 16 {
        return false;
    }
    let now_ms = now_unix_ms();
    let ttl_ms = ttl_secs * 1000;
    let current_bucket = now_ms / ttl_ms;
    for bucket in [current_bucket, current_bucket.saturating_sub(1)] {
        let mut h = Sha256::new();
        h.update(secret);
        h.update(bucket.to_le_bytes());
        h.update(addr.to_string().as_bytes());
        if &h.finalize()[..16] == cookie {
            return true;
        }
    }
    false
}

// ─── Phase 2: UDP observed-address handlers ───────────────────────────────────

/// Handle an incoming TNCF `OBSERVE_REQ` frame.
///
/// Called by `handle_tncf` in `udp_listener.rs`.
///
/// - If `cookie_len == 0`: reply with `COOKIE_CHALLENGE`.
/// - If cookie valid: reply with `OBSERVE_RESP` containing `src`'s address.
pub async fn handle_observe_req(
    nat: &NatState,
    socket: &Arc<UdpSocket>,
    src: SocketAddr,
    body: &[u8],
) {
    if !nat.serve {
        return;
    }

    if body.len() < OBSERVE_NONCE_LEN + 1 {
        return;
    }
    let nonce = &body[..OBSERVE_NONCE_LEN];
    let cookie_len = body[OBSERVE_NONCE_LEN] as usize;

    if cookie_len == 0 {
        // Initial probe — issue a stateless cookie challenge.
        let cookie = make_cookie(&nat.cookie_secret, nat.cookie_ttl_secs, src);
        let mut challenge_body = Vec::with_capacity(OBSERVE_NONCE_LEN + 1 + 16);
        challenge_body.extend_from_slice(nonce);
        challenge_body.push(16u8);
        challenge_body.extend_from_slice(&cookie);
        let frame = build_tncf_frame(tncf_type::COOKIE_CHALLENGE, &challenge_body);
        let _ = socket.send_to(&frame, src).await;
        return;
    }

    // Cookie-bearing probe — validate then respond.
    let cookie_start = OBSERVE_NONCE_LEN + 1;
    if body.len() < cookie_start + cookie_len {
        return;
    }
    let cookie = &body[cookie_start..cookie_start + cookie_len];
    if !validate_cookie(&nat.cookie_secret, nat.cookie_ttl_secs, src, cookie) {
        return; // invalid cookie — drop silently
    }

    let addr_str = src.to_string();
    let addr_bytes = addr_str.as_bytes();
    if addr_bytes.len() > 255 {
        return;
    }
    let observed_at_ms = now_unix_ms();
    let mut resp_body =
        Vec::with_capacity(OBSERVE_NONCE_LEN + 1 + addr_bytes.len() + OBSERVE_RESP_OBSERVED_AT_LEN);
    resp_body.extend_from_slice(nonce);
    resp_body.push(addr_bytes.len() as u8);
    resp_body.extend_from_slice(addr_bytes);
    resp_body.extend_from_slice(&observed_at_ms.to_le_bytes());
    let frame = build_tncf_frame(tncf_type::OBSERVE_RESP, &resp_body);
    let _ = socket.send_to(&frame, src).await;
}

/// Handle an incoming TNCF `COOKIE_CHALLENGE` frame.
///
/// Called by `handle_tncf` in `udp_listener.rs`.
/// Re-sends `OBSERVE_REQ` with the echoed cookie.
pub async fn handle_cookie_challenge(
    peer_manager: &PeerManager,
    socket: &Arc<UdpSocket>,
    src: SocketAddr,
    body: &[u8],
) {
    if body.len() < OBSERVE_NONCE_LEN + 1 {
        return;
    }
    let nonce = &body[..OBSERVE_NONCE_LEN];
    let cookie_len = body[OBSERVE_NONCE_LEN] as usize;
    let cookie_start = OBSERVE_NONCE_LEN + 1;
    if body.len() < cookie_start + cookie_len {
        return;
    }
    let cookie = &body[cookie_start..cookie_start + cookie_len];
    let nonce_array: [u8; OBSERVE_NONCE_LEN] = match nonce.try_into() {
        Ok(value) => value,
        Err(_) => return,
    };
    let Some(pending) = peer_manager.pending_observation(&nonce_array).await else {
        return;
    };
    if pending.expected_source != src {
        return;
    }
    let mut req_body = Vec::with_capacity(OBSERVE_NONCE_LEN + 1 + cookie_len);
    req_body.extend_from_slice(nonce);
    req_body.push(cookie_len as u8);
    req_body.extend_from_slice(cookie);
    let frame = build_tncf_frame(tncf_type::OBSERVE_REQ, &req_body);
    let _ = socket.send_to(&frame, src).await;
}

/// Handle an incoming TNCF `OBSERVE_RESP` frame.
///
/// Called by `handle_tncf` in `udp_listener.rs`.
/// Parses the observed address and updates `peer_manager.own_observed_addr`.
pub async fn handle_observe_resp(peer_manager: &PeerManager, src: SocketAddr, body: &[u8]) {
    if body.len() < OBSERVE_NONCE_LEN + 1 {
        return;
    }
    let addr_len = body[OBSERVE_NONCE_LEN] as usize;
    let addr_start = OBSERVE_NONCE_LEN + 1;
    if body.len() < addr_start + addr_len {
        return;
    }
    let addr_bytes = &body[addr_start..addr_start + addr_len];
    let addr_str = match std::str::from_utf8(addr_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    let observed_at_start = addr_start + addr_len;
    if body.len() < observed_at_start + OBSERVE_RESP_OBSERVED_AT_LEN {
        return;
    }
    // Validate the address before storing.
    if addr_str.parse::<SocketAddr>().is_err() {
        return;
    }
    let nonce: [u8; OBSERVE_NONCE_LEN] = match body[..OBSERVE_NONCE_LEN].try_into() {
        Ok(value) => value,
        Err(_) => return,
    };
    let Some(pending) = peer_manager.remove_pending_observation(&nonce).await else {
        return;
    };
    if pending.expected_source != src {
        return;
    }
    peer_manager
        .set_own_observed_addr(addr_str, Some(&pending.observer_node_id), Some(nonce))
        .await;
    crate::network::events::emit_network_event(
        "nat_traversal",
        crate::events::model::LogLevel::Info,
        "observed_addr_updated",
        None,
        Some(format!("addr={}", addr_str)),
        false,
    );
}

/// Send a TNCF `OBSERVE_REQ` (initial probe, cookie_len = 0) to `target_addr`.
pub async fn send_observe_req(
    peer_manager: &PeerManager,
    observer_node_id: &str,
    socket: &Arc<UdpSocket>,
    target_addr: SocketAddr,
) {
    use rand::RngCore;
    let mut nonce = [0u8; OBSERVE_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    peer_manager
        .register_pending_observation(observer_node_id, target_addr, nonce)
        .await;
    let mut body = Vec::with_capacity(OBSERVE_NONCE_LEN + 1);
    body.extend_from_slice(&nonce);
    body.push(0u8); // cookie_len = 0
    let frame = build_tncf_frame(tncf_type::OBSERVE_REQ, &body);
    let _ = socket.send_to(&frame, target_addr).await;
}

/// Spawn a background loop that periodically probes known peers to refresh our observed address.
pub fn spawn_observation_refresh_loop(
    nat: Arc<NatState>,
    peer_manager: PeerManager,
    socket: Arc<UdpSocket>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(nat.refresh_secs.max(5)));
        loop {
            interval.tick().await;
            let node_ids = peer_manager.list_node_ids().await;
            for nid in node_ids {
                if !peer_manager
                    .peer_has_capability(&nid, "punch_rendezvous")
                    .await
                {
                    continue;
                }

                let target_str = match peer_manager.udp_listen_addr_for(&nid).await {
                    Some(addr) => Some(addr),
                    None => {
                        peer_manager
                            .udp_observed_addr_for_if_fresh(&nid, nat.refresh_secs)
                            .await
                    }
                };
                if let Some(udp_addr_str) = target_str {
                    if let Ok(target_addr) = udp_addr_str.parse::<SocketAddr>() {
                        send_observe_req(&peer_manager, &nid, &socket, target_addr).await;
                    }
                }
            }
        }
    });
}

// ─── Phase 3: Relay-coordinated punch ─────────────────────────────────────────

/// Rendezvous: handle `PunchCoordinate { target, timeout_ms }` from `from_node_id`.
///
/// Validates that both peers have fresh observed UDP addresses and the target
/// advertises the `"punch"` capability, then sends `PunchInvite` to the target.
pub async fn handle_punch_coordinate(
    peer_manager: &PeerManager,
    nat: &NatState,
    attempt_id: &str,
    from_node_id: &str,
    target_node_id: &str,
    timeout_ms: u64,
) {
    if !nat.serve {
        return;
    }
    let initiator_obs = peer_manager
        .udp_observed_addr_for_if_fresh(from_node_id, nat.refresh_secs)
        .await;
    let responder_obs = peer_manager
        .udp_observed_addr_for_if_fresh(target_node_id, nat.refresh_secs)
        .await;

    if initiator_obs.is_none() || responder_obs.is_none() {
        let abort = crate::network::message::Message::new(
            "thenodes",
            from_node_id,
            crate::network::message::MessageType::PunchAbort {
                attempt_id: attempt_id.to_string(),
                target: target_node_id.to_string(),
                reason: Some(crate::network::message::Reason::NoObservedAddr),
            },
            None,
            None,
        );
        let _ = peer_manager
            .send_to_node_id(from_node_id, abort.as_json())
            .await;
        return;
    }

    if !peer_manager
        .peer_has_capability(target_node_id, "punch")
        .await
    {
        let abort = crate::network::message::Message::new(
            "thenodes",
            from_node_id,
            crate::network::message::MessageType::PunchAbort {
                attempt_id: attempt_id.to_string(),
                target: target_node_id.to_string(),
                reason: Some(crate::network::message::Reason::CapabilityMissing),
            },
            None,
            None,
        );
        let _ = peer_manager
            .send_to_node_id(from_node_id, abort.as_json())
            .await;
        return;
    }

    peer_manager
        .add_pending_punch(attempt_id, target_node_id, from_node_id, timeout_ms)
        .await;

    let invite = crate::network::message::Message::new(
        "thenodes",
        target_node_id,
        crate::network::message::MessageType::PunchInvite {
            attempt_id: attempt_id.to_string(),
            from_node_id: from_node_id.to_string(),
            timeout_ms,
        },
        None,
        None,
    );
    let _ = peer_manager
        .send_to_node_id(target_node_id, invite.as_json())
        .await;
}

/// Rendezvous: handle `PunchReady { target, ok }` from `responder_node_id`.
///
/// If `ok`, looks up the cached observed addresses and sends `PunchGo` to both.
pub async fn handle_punch_ready(
    peer_manager: &PeerManager,
    nat: &NatState,
    attempt_id: &str,
    responder_node_id: &str,
    target_node_id: &str, // "target" in PunchReady = the initiator
    ok: bool,
) {
    if !ok {
        // Clean up; notify initiator.
        let pending = peer_manager.get_pending_punch(attempt_id).await;
        peer_manager.remove_pending_punch(attempt_id).await;
        if let Some(p) = pending {
            let abort = crate::network::message::Message::new(
                "thenodes",
                &p.initiator_node_id,
                crate::network::message::MessageType::PunchAbort {
                    attempt_id: attempt_id.to_string(),
                    target: responder_node_id.to_string(),
                    reason: Some(crate::network::message::Reason::Declined),
                },
                None,
                None,
            );
            let _ = peer_manager
                .send_to_node_id(&p.initiator_node_id, abort.as_json())
                .await;
        }
        return;
    }

    // `target_node_id` in PunchReady is the initiator who requested the punch.
    // `responder_node_id` is whoever sent us this PunchReady.
    let pending = match peer_manager.get_pending_punch(attempt_id).await {
        Some(p) => p,
        None => return,
    };
    if pending.responder_node_id != responder_node_id || pending.initiator_node_id != target_node_id
    {
        return;
    }
    let initiator_node_id = &pending.initiator_node_id;
    let timeout_ms = pending.timeout_ms;

    let init_obs = match peer_manager
        .udp_observed_addr_for_if_fresh(initiator_node_id, nat.refresh_secs)
        .await
    {
        Some(a) => a,
        None => return,
    };
    let resp_obs = match peer_manager
        .udp_observed_addr_for_if_fresh(responder_node_id, nat.refresh_secs)
        .await
    {
        Some(a) => a,
        None => return,
    };

    let start_at_ms = now_unix_ms() + PUNCH_COORDINATE_DELAY_MS;

    for (dest, dest_obs) in [
        (initiator_node_id.as_str(), resp_obs.as_str()),
        (responder_node_id, init_obs.as_str()),
    ] {
        let _ = dest_obs; // suppress unused
        let go = crate::network::message::Message::new(
            "thenodes",
            dest,
            crate::network::message::MessageType::PunchGo {
                attempt_id: attempt_id.to_string(),
                initiator: initiator_node_id.clone(),
                responder: responder_node_id.to_string(),
                initiator_observed_addr: init_obs.clone(),
                responder_observed_addr: resp_obs.clone(),
                start_at_ms,
                timeout_ms,
            },
            None,
            None,
        );
        let _ = peer_manager.send_to_node_id(dest, go.as_json()).await;
    }

    peer_manager.remove_pending_punch(attempt_id).await;
}

/// Both peers: execute the synchronized hole-punch window on receipt of `PunchGo`.
///
/// 1. Waits until `start_at_ms`.
/// 2. Sends `probe_count` KEEPALIVE packets to the remote's observed address.
/// 3. If this node is the **initiator**, begins a Noise handshake with `connect_udp`.
pub async fn execute_punch_window(
    _peer_manager: &PeerManager,
    socket: &Arc<UdpSocket>,
    sessions: &UdpSessions,
    static_private: &[u8],
    nat: &NatState,
    local_node_id: &str,
    punch: PunchGoParams,
) {
    let now_ms = now_unix_ms();
    if punch.start_at_ms > now_ms {
        tokio::time::sleep(Duration::from_millis(punch.start_at_ms - now_ms)).await;
    }

    let am_initiator = local_node_id == punch.initiator;
    let remote_observed_str = if am_initiator {
        punch.responder_observed_addr.as_str()
    } else {
        punch.initiator_observed_addr.as_str()
    };
    let remote_addr: SocketAddr = match remote_observed_str.parse() {
        Ok(a) => a,
        Err(_) => return,
    };

    // Open peer's NAT entry by sending KEEPALIVE probes from our side.
    for _ in 0..nat.probe_count {
        let frame = build_tncf_frame(tncf_type::KEEPALIVE, &[]);
        let _ = socket.send_to(&frame, remote_addr).await;
        tokio::time::sleep(Duration::from_millis(nat.probe_interval_ms)).await;
    }

    if am_initiator {
        match crate::network::udp_listener::connect_udp(
            remote_addr,
            socket,
            sessions,
            static_private,
            local_node_id,
        )
        .await
        {
            Ok(_session_id) => {
                // session_id is in Handshaking state here; `finalize_session` in
                // udp_listener.rs calls `set_udp_session_id` once the Noise handshake
                // completes (MSG3 exchange done).  Do NOT call it here — an early call
                // would cause `dispatch_via_hole_punch`'s poll loop to find the ID,
                // attempt to encrypt on a not-yet-established session, and fail.
                crate::network::events::emit_network_event(
                    "nat_traversal",
                    crate::events::model::LogLevel::Info,
                    "punch_handshake_initiated",
                    Some(remote_addr.to_string()),
                    Some(format!("responder={}", punch.responder)),
                    false,
                );
            }
            Err(e) => {
                crate::network::events::emit_network_event(
                    "nat_traversal",
                    crate::events::model::LogLevel::Warn,
                    "punch_handshake_failed",
                    Some(remote_addr.to_string()),
                    Some(e.to_string()),
                    false,
                );
            }
        }
    }
}
