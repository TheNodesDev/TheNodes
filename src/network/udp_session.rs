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
//! Data frame:            `[SESSION_ID: 8][NONCE: 8 LE][CIPHERTEXT: variable]` (ADR-0013)
//! TNCF control frame:    `[MAGIC: 4][VERSION: 1][TYPE: 1][RESERVED: 2][BODY: variable]`
//!
//! Each data frame carries the Noise transport nonce explicitly, so frames may be
//! lost or reordered; a replay window rejects nonces already accepted.
//!
//! ## Key storage
//! Static keypair is persisted at the path supplied to `load_or_generate_static_keypair`.
//! File contains 64 bytes: `[private(32)] ++ [public(32)]`.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;

#[cfg(feature = "noise")]
use sha2::Digest;

// ─── ADR-0004 §2.4 wire constants ─────────────────────────────────────────────

/// Maximum total datagram size (including session_id header and AEAD tag).
pub const MAX_DATAGRAM_BYTES: usize = 1200;

/// Maximum application payload bytes after subtracting session_id (8), nonce (8) and
/// AEAD tag (16).
pub const MAX_APP_PAYLOAD_BYTES: usize = 1168;

pub const SESSION_ID_LEN: usize = 8;

/// Explicit transport nonce at the start of each data frame's body (ADR-0013).
pub const NONCE_LEN: usize = 8;

/// How far below the highest accepted nonce a frame may arrive and still be
/// accepted once. Older frames are dropped as replays.
pub const REPLAY_WINDOW: u64 = 1024;

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
    /// Noise handshake message 1 (initiator → responder).
    /// BODY: `[session_id:8][cookie_len:1][cookie:cookie_len][noise_msg1]` (ADR-0013).
    pub const HANDSHAKE_MSG1: u8 = 0x10;
    /// Noise handshake message 2 (responder → initiator). BODY = raw Noise msg.
    pub const HANDSHAKE_MSG2: u8 = 0x11;
    /// Noise handshake message 3 (initiator → responder). BODY = raw Noise msg.
    pub const HANDSHAKE_MSG3: u8 = 0x12;
    /// A responder under load asks the initiator to prove its source address before
    /// it spends a Diffie-Hellman on msg1; the initiator resends msg1 with the cookie.
    /// BODY: `[session_id:8][cookie_len:1][cookie:cookie_len]` (ADR-0013).
    pub const HANDSHAKE_COOKIE: u8 = 0x13;
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
        transport: Box<snow::StatelessTransportState>,
        /// Nonce for the next frame this side sends.
        send_nonce: u64,
        replay: ReplayWindow,
        /// SHA-256 fingerprint of the remote static public key.
        remote_static_fingerprint: [u8; 32],
    },
}

/// Nonces accepted on one session: any nonce above the highest seen, or one
/// within `REPLAY_WINDOW` below it that has not been accepted yet.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl ReplayWindow {
    fn slot(nonce: u64) -> (usize, u64) {
        let index = (nonce % REPLAY_WINDOW) as usize;
        (index / 64, 1 << (index % 64))
    }

    fn is_marked(&self, nonce: u64) -> bool {
        let (word, bit) = Self::slot(nonce);
        self.seen[word] & bit != 0
    }

    fn set_mark(&mut self, nonce: u64, marked: bool) {
        let (word, bit) = Self::slot(nonce);
        if marked {
            self.seen[word] |= bit;
        } else {
            self.seen[word] &= !bit;
        }
    }

    /// Whether a frame with `nonce` may be accepted. Check before decrypting,
    /// and [`accept`](Self::accept) only once the frame authenticated.
    pub fn check(&self, nonce: u64) -> bool {
        match self.highest {
            None => true,
            Some(highest) if nonce > highest => true,
            Some(highest) => highest - nonce < REPLAY_WINDOW && !self.is_marked(nonce),
        }
    }

    pub fn accept(&mut self, nonce: u64) {
        match self.highest {
            Some(highest) if nonce <= highest => self.set_mark(nonce, true),
            highest => {
                // Slots between the old and new highest held nonces now below
                // the window; clear them for reuse.
                let first_new = highest.map_or(0, |h| h + 1);
                if nonce - first_new >= REPLAY_WINDOW {
                    self.seen = Default::default();
                } else {
                    for stale in first_new..nonce {
                        self.set_mark(stale, false);
                    }
                }
                self.set_mark(nonce, true);
                self.highest = Some(nonce);
            }
        }
    }
}

/// Why a data frame was not accepted.
#[derive(Debug)]
pub enum SessionFrameError {
    /// The nonce was already accepted or is below the replay window.
    Replay,
    /// The frame is too short to hold a nonce.
    Truncated,
    #[cfg(feature = "noise")]
    Noise(snow::Error),
    /// The session is still handshaking.
    NotEstablished,
}

impl std::fmt::Display for SessionFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replay => f.write_str("replayed or too old nonce"),
            Self::Truncated => f.write_str("frame shorter than its nonce"),
            #[cfg(feature = "noise")]
            Self::Noise(error) => write!(f, "{error}"),
            Self::NotEstablished => f.write_str("session not established"),
        }
    }
}

impl std::error::Error for SessionFrameError {}

#[cfg(feature = "noise")]
impl From<snow::Error> for SessionFrameError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
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

    /// The initiator's msg1, kept until msg2 arrives so it can be resent with
    /// a cookie the responder asks for.
    initiator_msg1: Option<Vec<u8>>,

    /// Cookie challenges the initiator answered for this handshake.
    pub cookie_retries: u8,
}

impl NoiseUdpSession {
    /// Returns `true` if the session has completed the Noise handshake.
    pub fn is_established(&self) -> bool {
        matches!(self.state, Some(UdpSessionState::Established { .. }))
    }

    /// `false` once a handshake step failed in a way the session cannot
    /// recover from. A message that merely did not verify leaves the session
    /// usable; see [`advance_handshake`](Self::advance_handshake).
    pub fn is_usable(&self) -> bool {
        self.state.is_some()
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

    /// The msg1 an initiator sent, while it still waits for msg2.
    pub fn initiator_msg1(&self) -> Option<&[u8]> {
        self.initiator_msg1.as_deref()
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
            initiator_msg1: Some(msg.clone()),
            cookie_retries: 0,
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
            initiator_msg1: None,
            cookie_retries: 0,
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
    /// A message that does not verify, and any handshake message for an
    /// established session, leaves the session unchanged; after any other error
    /// [`is_usable`](Self::is_usable) is `false`.
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
                let n = match handshake.read_message(payload, &mut scratch) {
                    Ok(n) => n,
                    Err(err) => {
                        // snow restores its state when a message does not
                        // verify, so a forged datagram leaves the handshake
                        // able to continue with the genuine one.
                        self.state = Some(UdpSessionState::Handshaking { handshake, step });
                        return Err(err);
                    }
                };
                self.last_seen = Instant::now();
                self.initiator_msg1 = None;
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
                    let transport = handshake.into_stateless_transport_mode()?;
                    self.state = Some(UdpSessionState::Established {
                        transport: Box::new(transport),
                        send_nonce: 0,
                        replay: ReplayWindow::default(),
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
                        let transport = handshake.into_stateless_transport_mode()?;
                        self.state = Some(UdpSessionState::Established {
                            transport: Box::new(transport),
                            send_nonce: 0,
                            replay: ReplayWindow::default(),
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

    /// Encrypt `plaintext` into `frame_body` as `[nonce: 8 LE][ciphertext]`.
    /// Returns the number of bytes written.
    ///
    /// Caller MUST ensure `frame_body` is at least `NONCE_LEN + plaintext.len() + 16`
    /// bytes. Both `plaintext` and the total datagram MUST respect
    /// `MAX_APP_PAYLOAD_BYTES` / `MAX_DATAGRAM_BYTES` limits.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        frame_body: &mut [u8],
    ) -> Result<usize, snow::Error> {
        match &mut self.state {
            Some(UdpSessionState::Established {
                transport,
                send_nonce,
                ..
            }) => {
                // Noise reserves the highest nonce; a session that used every
                // other one has to be replaced.
                if *send_nonce == u64::MAX {
                    return Err(snow::error::StateProblem::Exhausted.into());
                }
                if frame_body.len() < NONCE_LEN {
                    return Err(snow::Error::Input);
                }
                let nonce = *send_nonce;
                let n = transport.write_message(nonce, plaintext, &mut frame_body[NONCE_LEN..])?;
                frame_body[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
                *send_nonce += 1;
                Ok(NONCE_LEN + n)
            }
            _ => Err(snow::Error::State(
                snow::error::StateProblem::HandshakeNotFinished,
            )),
        }
    }

    /// Decrypt a data frame body (`[nonce][ciphertext]`) into `plaintext`.
    /// Returns the number of plaintext bytes written.
    ///
    /// Only a frame that authenticates and passes the replay window updates the
    /// window, `last_seen`, and `peer_addr` (path migration, ADR-0004 §2.7).
    pub fn decrypt(
        &mut self,
        frame_body: &[u8],
        plaintext: &mut [u8],
        src: SocketAddr,
    ) -> Result<usize, SessionFrameError> {
        match &mut self.state {
            Some(UdpSessionState::Established {
                transport, replay, ..
            }) => {
                if frame_body.len() < NONCE_LEN {
                    return Err(SessionFrameError::Truncated);
                }
                let (nonce, ciphertext) = frame_body.split_at(NONCE_LEN);
                let nonce = u64::from_le_bytes(nonce.try_into().expect("NONCE_LEN bytes"));
                if !replay.check(nonce) {
                    return Err(SessionFrameError::Replay);
                }
                let n = transport.read_message(nonce, ciphertext, plaintext)?;
                replay.accept(nonce);
                self.peer_addr = src;
                self.last_seen = Instant::now();
                Ok(n)
            }
            _ => Err(SessionFrameError::NotEstablished),
        }
    }

    // Helper: extract remote static public key fingerprint from a finished HandshakeState.
    fn extract_remote_static(handshake: &snow::HandshakeState) -> [u8; 32] {
        handshake
            .get_remote_static()
            .map(|s| {
                let mut fp = [0u8; 32];
                fp.copy_from_slice(sha2::Sha256::digest(s).as_slice());
                fp
            })
            .unwrap_or([0u8; 32])
    }
}

// ─── Persistent static keypair ────────────────────────────────────────────────

/// Load a persistent Noise static keypair from `key_path`, or generate and persist one.
///
/// File format: 64 bytes — `[private(32)] ++ [public(32)]`. A new file is
/// created readable by its owner only, and an existing one readable by others
/// is restricted to its owner (Unix).
///
/// Returns `(private_bytes, public_bytes)`.
///
/// # Errors
/// Returns `io::Error` on filesystem failure, if the `snow` builder fails, or
/// if the file is not a 64-byte key. A damaged key file is never replaced: the
/// key is the node's identity, and a new one would be bound to nobody.
#[cfg(feature = "noise")]
pub fn load_or_generate_static_keypair(key_path: &Path) -> io::Result<(Vec<u8>, Vec<u8>)> {
    if key_path.exists() {
        let data = std::fs::read(key_path)?;
        if data.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} holds {} bytes, not a 64-byte Noise static key; restore it, or remove it to generate a new identity",
                    key_path.display(),
                    data.len()
                ),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(key_path)?.permissions().mode();
            if mode & 0o077 != 0 {
                std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        return Ok((data[..32].to_vec(), data[32..].to_vec()));
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
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    std::io::Write::write_all(&mut options.open(key_path)?, &file_bytes)?;
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

/// Build a data frame: `[SESSION_ID: 8] ++ body`, where `body` is the
/// `[nonce][ciphertext]` written by [`NoiseUdpSession::encrypt`].
pub fn build_session_frame(session_id: &[u8; SESSION_ID_LEN], body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SESSION_ID_LEN + body.len());
    frame.extend_from_slice(session_id);
    frame.extend_from_slice(body);
    frame
}

/// Body of a `HANDSHAKE_MSG1` or `HANDSHAKE_COOKIE` frame:
/// `[session_id][cookie_len:1][cookie]`, followed by msg1 for `HANDSHAKE_MSG1`.
pub fn build_handshake_body(
    session_id: &[u8; SESSION_ID_LEN],
    cookie: &[u8],
    noise_msg: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(SESSION_ID_LEN + 1 + cookie.len() + noise_msg.len());
    body.extend_from_slice(session_id);
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(noise_msg);
    body
}

/// Split a `HANDSHAKE_MSG1` or `HANDSHAKE_COOKIE` body into
/// `(session_id, cookie, rest)`; `None` if it is truncated.
pub fn parse_handshake_body(body: &[u8]) -> Option<([u8; SESSION_ID_LEN], &[u8], &[u8])> {
    let session_id: [u8; SESSION_ID_LEN] = body.get(..SESSION_ID_LEN)?.try_into().ok()?;
    let cookie_len = *body.get(SESSION_ID_LEN)? as usize;
    let cookie_start = SESSION_ID_LEN + 1;
    let cookie = body.get(cookie_start..cookie_start + cookie_len)?;
    Some((session_id, cookie, &body[cookie_start + cookie_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_each_nonce_once_within_the_window() {
        let mut window = ReplayWindow::default();
        for nonce in [5, 3, 7, 4] {
            assert!(window.check(nonce), "{nonce}");
            window.accept(nonce);
        }
        for nonce in [5, 3, 7, 4] {
            assert!(!window.check(nonce), "replayed {nonce}");
        }
        // Lost frames leave gaps that can still be filled.
        assert!(window.check(6));
        assert!(window.check(0));

        // A jump moves the window: nonces that fell below it are refused, and
        // reused slots start empty.
        window.accept(7 + REPLAY_WINDOW);
        assert!(!window.check(7));
        assert!(window.check(8));
        assert!(window.check(6 + REPLAY_WINDOW));
        assert!(!window.check(7 + REPLAY_WINDOW));
        window.accept(10 * REPLAY_WINDOW);
        assert!(!window.check(9 * REPLAY_WINDOW));
        assert!(window.check(10 * REPLAY_WINDOW - 1));
    }

    #[test]
    fn handshake_bodies_round_trip() {
        let id = [1u8; SESSION_ID_LEN];
        let body = build_handshake_body(&id, &[9; 16], b"msg1");
        let (parsed_id, cookie, rest) = parse_handshake_body(&body).unwrap();
        assert_eq!(
            (parsed_id, cookie, rest),
            (id, &[9u8; 16][..], &b"msg1"[..])
        );
        assert!(parse_handshake_body(&body[..SESSION_ID_LEN + 4]).is_none());
        assert!(parse_handshake_body(&id).is_none());
    }

    #[cfg(all(feature = "noise", unix))]
    #[test]
    fn static_key_file_is_private_and_never_silently_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noise/static.key");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let keypair = load_or_generate_static_keypair(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        // A key left readable by others is restricted and keeps the identity.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_or_generate_static_keypair(&path).unwrap(), keypair);
        assert_eq!(mode(&path), 0o600);
        // A damaged key is an error, not a new identity.
        std::fs::write(&path, [7u8; 10]).unwrap();
        let err = load_or_generate_static_keypair(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), [7u8; 10]);
    }

    #[cfg(feature = "noise")]
    fn established_pair() -> (NoiseUdpSession, NoiseUdpSession) {
        let key = || {
            snow::Builder::new(NoiseUdpSession::NOISE_PARAMS.parse().unwrap())
                .generate_keypair()
                .unwrap()
                .private
        };
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (mut initiator, msg1) = NoiseUdpSession::new_initiator(addr, &key()).unwrap();
        let (mut responder, msg2) =
            NoiseUdpSession::new_responder(initiator.session_id, addr, &msg1, &key(), "b").unwrap();
        let msg3 = initiator
            .advance_handshake(&msg2, Some("a"))
            .unwrap()
            .unwrap();
        assert!(responder.advance_handshake(&msg3, None).unwrap().is_none());
        (initiator, responder)
    }

    #[cfg(feature = "noise")]
    #[test]
    fn a_forged_handshake_message_leaves_the_handshake_able_to_finish() {
        let key = || {
            snow::Builder::new(NoiseUdpSession::NOISE_PARAMS.parse().unwrap())
                .generate_keypair()
                .unwrap()
                .private
        };
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (mut initiator, msg1) = NoiseUdpSession::new_initiator(addr, &key()).unwrap();
        let (mut responder, msg2) =
            NoiseUdpSession::new_responder(initiator.session_id, addr, &msg1, &key(), "b").unwrap();

        // A forged msg2: a valid-looking ephemeral key, then garbage.
        let mut forged = msg2.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(initiator.advance_handshake(&forged, Some("a")).is_err());
        assert!(initiator.advance_handshake(&[0u8; 16], Some("a")).is_err());
        assert!(initiator.is_usable() && !initiator.is_established());

        let msg3 = initiator
            .advance_handshake(&msg2, Some("a"))
            .unwrap()
            .unwrap();
        assert!(responder.advance_handshake(&[0u8; 16], None).is_err());
        assert!(responder.is_usable());
        assert!(responder.advance_handshake(&msg3, None).unwrap().is_none());
        assert!(initiator.is_established() && responder.is_established());

        // Handshake messages for an established session change nothing.
        assert!(responder.advance_handshake(&msg3, None).is_err());
        assert!(responder.is_established());
    }

    #[cfg(feature = "noise")]
    #[test]
    fn lost_and_reordered_frames_decrypt_and_replays_do_not() {
        let (mut sender, mut receiver) = established_pair();
        let frames: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let mut body = vec![0u8; NONCE_LEN + 64];
                let n = sender
                    .encrypt(format!("frame-{i}").as_bytes(), &mut body)
                    .unwrap();
                body.truncate(n);
                body
            })
            .collect();
        let src: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let mut plaintext = vec![0u8; 64];
        // Frame 1 is lost and 3 arrives before 2.
        for i in [0, 3, 2] {
            let n = receiver.decrypt(&frames[i], &mut plaintext, src).unwrap();
            assert_eq!(&plaintext[..n], format!("frame-{i}").as_bytes());
        }
        assert!(matches!(
            receiver.decrypt(&frames[3], &mut plaintext, src),
            Err(SessionFrameError::Replay)
        ));
        // A forged frame does not move the window or the peer's path.
        let mut forged = frames[1].clone();
        *forged.last_mut().unwrap() ^= 1;
        let elsewhere: SocketAddr = "198.51.100.9:9".parse().unwrap();
        assert!(matches!(
            receiver.decrypt(&forged, &mut plaintext, elsewhere),
            Err(SessionFrameError::Noise(_))
        ));
        assert_eq!(receiver.peer_addr, src);
        let n = receiver.decrypt(&frames[1], &mut plaintext, src).unwrap();
        assert_eq!(&plaintext[..n], b"frame-1");
    }
}
