// src/network/udp_session.rs
//! Noise_XX_25519_ChaChaPoly_BLAKE2s session management for UDP transport.
//!
//! ADR-0004: UDP + Noise Transport (Phase 1)
//!
//! ## Session lifecycle
//! 1. Initiator calls `NoiseUdpSession::new_initiator` → sends msg1.
//! 2. Responder calls `NoiseUdpSession::new_responder(session_id, peer_addr, msg1)` → sends msg2.
//! 3. Initiator calls `session.advance_handshake(msg2)` → sends msg3; session transitions to
//!    Established (for the initiator).
//! 4. Responder calls `session.advance_handshake(msg3)` → returns None; session transitions to
//!    Established (for the responder).
//! 5. Both sides use `encrypt` / `decrypt` for application data.
//!
//! ## Wire frame layout
//! Data/handshake frame:  `[SESSION_ID: 8][NOISE_MSG: variable]`
//! TNCF control frame:    `[MAGIC: 4][VERSION: 1][TYPE: 1][RESERVED: 2][BODY: variable]`
//!
//! ## Key storage
//! Static keypair is persisted at the path supplied to `load_or_generate_static_keypair`.
//! File contains 64 bytes: `[private(32)] ++ [public(32)]`.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;

// ─── ADR-0004 §2.4 wire constants ─────────────────────────────────────────────

/// Maximum total datagram size (including session_id header and AEAD tag).
pub const MAX_DATAGRAM_BYTES: usize = 1200;

/// Maximum application payload bytes after subtracting session_id (8) and AEAD tag (16).
pub const MAX_APP_PAYLOAD_BYTES: usize = 1176;

pub const SESSION_ID_LEN: usize = 8;

/// Session IDs beginning with the TNCF magic are reserved and MUST NOT be used
/// for Noise sessions, because the UDP demux checks TNCF first.
#[inline]
pub fn has_reserved_tncf_prefix(session_id: &[u8; SESSION_ID_LEN]) -> bool {
    session_id[..4] == TNCF_MAGIC
}

// ─── TNCF control-frame constants (ADR-0004 §7) ───────────────────────────────

/// TheNodes Control Frame magic: ASCII "TNCF".
pub const TNCF_MAGIC: [u8; 4] = [0x54, 0x4E, 0x43, 0x46];

pub const TNCF_VERSION_1: u8 = 1;

/// Fixed header length: MAGIC(4) + VERSION(1) + TYPE(1) + RESERVED(2) = 8 bytes.
pub const TNCF_HEADER_LEN: usize = 8;

/// TNCF TYPE byte constants.
pub mod tncf_type {
    /// Keepalive / NAT hole-punch probe. BODY is empty or ignored.
    pub const KEEPALIVE: u8 = 0x01;
    /// Noise handshake message 1 (initiator → responder). BODY = raw Noise msg.
    pub const HANDSHAKE_MSG1: u8 = 0x10;
    /// Noise handshake message 2 (responder → initiator). BODY = raw Noise msg.
    pub const HANDSHAKE_MSG2: u8 = 0x11;
    /// Noise handshake message 3 (initiator → responder). BODY = raw Noise msg.
    pub const HANDSHAKE_MSG3: u8 = 0x12;
    /// Observed-address probe: requester asks server to echo its UDP source addr.  (ADR-0005 §2)
    /// BODY: `[nonce:8][cookie_len:1][cookie:variable]`.
    pub const OBSERVE_REQ: u8 = 0x20;
    /// Stateless cookie challenge issued by server to a first-time OBSERVE_REQ.  (ADR-0005 §2)
    /// BODY: `[nonce:8][cookie_len:1][cookie:variable]`.
    pub const COOKIE_CHALLENGE: u8 = 0x21;
    /// Server's reply containing the requester's observed public UDP address.  (ADR-0005 §2)
    /// BODY: `[nonce:8][addr_len:1][addr:utf8][observed_at_ms:8_LE]`.
    pub const OBSERVE_RESP: u8 = 0x22;
}

// ─── Session state ─────────────────────────────────────────────────────────────

/// Internal state of a `NoiseUdpSession`.
#[cfg(feature = "noise")]
pub enum UdpSessionState {
    /// Noise XX handshake in progress.
    Handshaking {
        handshake: Box<snow::HandshakeState>,
        /// Number of Noise messages sent so far (1 after initiator writes msg1, 2 after
        /// responder writes msg2, 3 after initiator writes msg3).
        step: u8,
    },
    /// Handshake complete; ready for encrypted transport.
    Established {
        transport: Box<snow::TransportState>,
        /// BLAKE2s fingerprint (first 32 bytes) of the remote static public key.
        remote_static_fingerprint: [u8; 32],
    },
}

/// Stub for non-noise builds.
#[cfg(not(feature = "noise"))]
pub enum UdpSessionState {
    Handshaking { step: u8 },
    Established { remote_static_fingerprint: [u8; 32] },
}

// ─── Session struct ────────────────────────────────────────────────────────────

/// A Noise/UDP peer session.
pub struct NoiseUdpSession {
    /// Initiator-generated session identifier.  The responder MUST reuse this value; it MUST
    /// NOT generate a new session_id.  (ADR-0004 §2.1)
    pub session_id: [u8; SESSION_ID_LEN],

    /// Set to the remote's `node_id` upon handshake completion.  MUST be `Some` before the
    /// session may be used for application data.
    pub node_id: Option<String>,

    /// Most recently confirmed SocketAddr for this peer.  Updated on every successful
    /// `decrypt()` call to support path migration.  (ADR-0004 §2.7)
    pub peer_addr: SocketAddr,

    /// Session state — held in `Option` so we can take ownership during transitions.
    state: Option<UdpSessionState>,

    /// Timestamp of last received datagram (used by the session reaper).
    pub last_seen: Instant,

    /// Creation timestamp (used to enforce the 5-second handshake-expiry limit).
    pub created_at: Instant,
}

impl NoiseUdpSession {
    /// Returns `true` if the session has completed the Noise handshake.
    pub fn is_established(&self) -> bool {
        matches!(self.state, Some(UdpSessionState::Established { .. }))
    }

    /// Returns the remote static public-key fingerprint, or `None` if not yet established.
    pub fn remote_static_fingerprint(&self) -> Option<[u8; 32]> {
        match &self.state {
            Some(UdpSessionState::Established {
                remote_static_fingerprint,
                ..
            }) => Some(*remote_static_fingerprint),
            _ => None,
        }
    }

    /// Borrow the inner state (useful for pattern matching in the listener).
    pub fn state(&self) -> Option<&UdpSessionState> {
        self.state.as_ref()
    }
}

// ─── Noise-enabled constructors and methods ────────────────────────────────────

#[cfg(feature = "noise")]
impl NoiseUdpSession {
    const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

    /// Create an **initiator** session.  Generates a random `session_id` and the first Noise
    /// handshake message.
    ///
    /// Returns `(session, msg1_bytes)`.  The caller MUST send `msg1_bytes` to the peer wrapped in
    /// a TNCF frame with TYPE = `tncf_type::HANDSHAKE_MSG1`.
    pub fn new_initiator(
        peer_addr: SocketAddr,
        static_private: &[u8],
    ) -> Result<(Self, Vec<u8>), snow::Error> {
        use rand::RngCore;

        let mut session_id = [0u8; SESSION_ID_LEN];
        let mut rng = rand::thread_rng();
        loop {
            rng.fill_bytes(&mut session_id);
            if !has_reserved_tncf_prefix(&session_id) {
                break;
            }
        }

        let builder = snow::Builder::new(Self::NOISE_PARAMS.parse()?);
        let mut handshake = builder
            .local_private_key(static_private)
            .build_initiator()?;

        let mut msg = vec![0u8; MAX_DATAGRAM_BYTES];
        let written = handshake.write_message(&[], &mut msg)?;
        msg.truncate(written);

        let session = Self {
            session_id,
            node_id: None,
            peer_addr,
            state: Some(UdpSessionState::Handshaking {
                handshake: Box::new(handshake),
                step: 1,
            }),
            last_seen: Instant::now(),
            created_at: Instant::now(),
        };
        Ok((session, msg))
    }

    /// Create a **responder** session from the first initiator handshake message.
    ///
    /// `session_id` MUST be the value copied from the incoming TNCF frame body prefix.
    /// `local_node_id` is embedded in the msg2 payload so the initiator learns our identity.
    /// Returns `(session, msg2_bytes)`.  The caller MUST send `msg2_bytes` wrapped in a TNCF
    /// frame with TYPE = `tncf_type::HANDSHAKE_MSG2`.
    pub fn new_responder(
        session_id: [u8; SESSION_ID_LEN],
        peer_addr: SocketAddr,
        msg1: &[u8],
        static_private: &[u8],
        local_node_id: &str,
    ) -> Result<(Self, Vec<u8>), snow::Error> {
        let builder = snow::Builder::new(Self::NOISE_PARAMS.parse()?);
        let mut handshake = builder
            .local_private_key(static_private)
            .build_responder()?;

        let mut scratch = vec![0u8; MAX_DATAGRAM_BYTES];
        handshake.read_message(msg1, &mut scratch)?;

        // Embed our node_id in the msg2 payload (encrypted to the initiator's ephemeral key).
        let payload = local_node_id.as_bytes();
        let mut msg2 = vec![0u8; MAX_DATAGRAM_BYTES];
        let written = handshake.write_message(payload, &mut msg2)?;
        msg2.truncate(written);

        let session = Self {
            session_id,
            node_id: None,
            peer_addr,
            state: Some(UdpSessionState::Handshaking {
                handshake: Box::new(handshake),
                step: 2,
            }),
            last_seen: Instant::now(),
            created_at: Instant::now(),
        };
        Ok((session, msg2))
    }

    /// Advance the handshake by consuming an inbound Noise message.
    ///
    /// `local_node_id` is only used when the **initiator** writes msg3 (it is embedded in the
    /// msg3 payload so the responder learns our identity).  Pass `None` when calling on the
    /// responder side.
    ///
    /// Node-id extraction:
    /// - Initiator reading msg2: extracts `responder_node_id` from the msg2 payload, stores in
    ///   `self.node_id`.
    /// - Responder reading msg3: extracts `initiator_node_id` from the msg3 payload, stores in
    ///   `self.node_id`.
    ///
    /// Returns:
    /// - `Ok(Some(bytes))` – a response message to send (initiator sending msg3).
    /// - `Ok(None)` – handshake is now complete, no response needed.
    ///
    /// # Errors
    /// Returns `snow::Error` on authentication failure or an out-of-order message.
    pub fn advance_handshake(
        &mut self,
        payload: &[u8],
        local_node_id: Option<&str>,
    ) -> Result<Option<Vec<u8>>, snow::Error> {
        let state = self.state.take().expect("NoiseUdpSession: state is None");
        match state {
            UdpSessionState::Handshaking {
                mut handshake,
                step,
            } => {
                let mut scratch = vec![0u8; MAX_DATAGRAM_BYTES];
                let n = handshake.read_message(payload, &mut scratch)?;
                self.last_seen = Instant::now();
                // Extract remote node_id from the handshake payload if present.
                if n > 0 {
                    if let Ok(id) = std::str::from_utf8(&scratch[..n]) {
                        if !id.is_empty() {
                            self.node_id = Some(id.to_owned());
                        }
                    }
                }

                if handshake.is_handshake_finished() {
                    // Responder finished after reading msg3.
                    let remote_static = Self::extract_remote_static(&handshake);
                    let transport = handshake.into_transport_mode()?;
                    self.state = Some(UdpSessionState::Established {
                        transport: Box::new(transport),
                        remote_static_fingerprint: remote_static,
                    });
                    Ok(None)
                } else {
                    // Initiator needs to write msg3 after reading msg2.
                    let id_payload = local_node_id.unwrap_or("").as_bytes();
                    let mut msg = vec![0u8; MAX_DATAGRAM_BYTES];
                    let written = handshake.write_message(id_payload, &mut msg)?;
                    msg.truncate(written);

                    if handshake.is_handshake_finished() {
                        // Initiator finished after writing msg3.
                        let remote_static = Self::extract_remote_static(&handshake);
                        let transport = handshake.into_transport_mode()?;
                        self.state = Some(UdpSessionState::Established {
                            transport: Box::new(transport),
                            remote_static_fingerprint: remote_static,
                        });
                    } else {
                        self.state = Some(UdpSessionState::Handshaking {
                            handshake,
                            step: step + 1,
                        });
                    }
                    Ok(Some(msg))
                }
            }
            other => {
                self.state = Some(other);
                Err(snow::Error::State(
                    snow::error::StateProblem::HandshakeAlreadyFinished,
                ))
            }
        }
    }

    /// Encrypt `plaintext` into `ciphertext`.  Returns the number of ciphertext bytes written.
    ///
    /// Caller MUST ensure `ciphertext` is at least `plaintext.len() + 16` bytes.
    /// Both `plaintext` and the total datagram MUST respect `MAX_APP_PAYLOAD_BYTES` /
    /// `MAX_DATAGRAM_BYTES` limits.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, snow::Error> {
        match &mut self.state {
            Some(UdpSessionState::Established { transport, .. }) => {
                transport.write_message(plaintext, ciphertext)
            }
            _ => Err(snow::Error::State(
                snow::error::StateProblem::HandshakeNotFinished,
            )),
        }
    }

    /// Decrypt `ciphertext` into `plaintext`.  Returns the number of plaintext bytes written.
    ///
    /// Also updates `peer_addr` to `src` for path migration (ADR-0004 §2.7).
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
        src: SocketAddr,
    ) -> Result<usize, snow::Error> {
        match &mut self.state {
            Some(UdpSessionState::Established { transport, .. }) => {
                let n = transport.read_message(ciphertext, plaintext)?;
                // ADR-0004 §2.7: update mutable path on every successful decrypt.
                self.peer_addr = src;
                self.last_seen = Instant::now();
                Ok(n)
            }
            _ => Err(snow::Error::State(
                snow::error::StateProblem::HandshakeNotFinished,
            )),
        }
    }

    // Helper: extract remote static public key fingerprint from a finished HandshakeState.
    fn extract_remote_static(handshake: &snow::HandshakeState) -> [u8; 32] {
        handshake
            .get_remote_static()
            .map(|s| {
                let mut fp = [0u8; 32];
                let len = s.len().min(32);
                fp[..len].copy_from_slice(&s[..len]);
                fp
            })
            .unwrap_or([0u8; 32])
    }
}

// ─── Persistent static keypair ────────────────────────────────────────────────

/// Load a persistent Noise static keypair from `key_path`, or generate and persist one.
///
/// File format: 64 bytes — `[private(32)] ++ [public(32)]`.
///
/// Returns `(private_bytes, public_bytes)`.
///
/// # Errors
/// Returns `io::Error` on filesystem failure or if the `snow` builder fails.
#[cfg(feature = "noise")]
pub fn load_or_generate_static_keypair(key_path: &Path) -> io::Result<(Vec<u8>, Vec<u8>)> {
    if key_path.exists() {
        let data = std::fs::read(key_path)?;
        if data.len() == 64 {
            return Ok((data[..32].to_vec(), data[32..].to_vec()));
        }
        // File corrupt or legacy format — regenerate.
    }

    let builder = snow::Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?,
    );
    let keypair = builder
        .generate_keypair()
        .map_err(|e| io::Error::other(format!("{e}")))?;

    let mut file_bytes = Vec::with_capacity(64);
    file_bytes.extend_from_slice(&keypair.private);
    file_bytes.extend_from_slice(&keypair.public);

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(key_path, &file_bytes)?;
    Ok((keypair.private, keypair.public))
}

/// No-op stub when the `noise` feature is disabled.
#[cfg(not(feature = "noise"))]
pub fn load_or_generate_static_keypair(_key_path: &Path) -> io::Result<(Vec<u8>, Vec<u8>)> {
    Ok((vec![], vec![]))
}

// ─── TNCF frame helpers ────────────────────────────────────────────────────────

/// Checks whether `buf` starts with the TNCF magic bytes.
#[inline]
pub fn is_tncf_frame(buf: &[u8]) -> bool {
    buf.len() >= TNCF_HEADER_LEN && buf[..4] == TNCF_MAGIC
}

/// Build a TNCF frame: `MAGIC | VERSION | TYPE | RESERVED(2) | body`.
pub fn build_tncf_frame(frame_type: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(TNCF_HEADER_LEN + body.len());
    frame.extend_from_slice(&TNCF_MAGIC);
    frame.push(TNCF_VERSION_1);
    frame.push(frame_type);
    frame.push(0x00); // RESERVED[0]
    frame.push(0x00); // RESERVED[1]
    frame.extend_from_slice(body);
    frame
}

/// Extract TNCF TYPE byte and BODY slice from a raw datagram assumed to be a TNCF frame.
///
/// Returns `None` if the datagram is too short.
pub fn parse_tncf_frame(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.len() < TNCF_HEADER_LEN {
        return None;
    }
    let frame_type = buf[5];
    let body = &buf[TNCF_HEADER_LEN..];
    Some((frame_type, body))
}

/// Build a data/handshake wire frame: `[SESSION_ID: 8] ++ noise_msg`.
pub fn build_session_frame(session_id: &[u8; SESSION_ID_LEN], noise_msg: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SESSION_ID_LEN + noise_msg.len());
    frame.extend_from_slice(session_id);
    frame.extend_from_slice(noise_msg);
    frame
}
