# ADR 0004: UDP Transport with Noise Secure Sessions

- Status: Accepted
- Date: 2026-03-08
- Target: 0.3.x
- Depends on: ADR-0001 (Noise XX already implemented over TCP)
- Enables: ADR-0005 (NAT traversal and hole punching)

## Context

TheNodes currently operates exclusively over TCP. The transport layer consists
of `TcpListener::bind` / `TcpListener::accept` in `listener.rs` and
`TcpStream::connect` in `transport.rs`. The `SecureChannel` trait (ADR-0001)
takes `TcpStream` explicitly in both `connect` and `accept`.

This is not a flaw; TCP was the correct starting point. However, exclusive use
of TCP closes off two important capabilities:

1. **NAT traversal.** TCP simultaneous-open (the basis of TCP hole punching) is
   unreliable on the symmetric NAT prevalent on mobile, CG-NAT, and most home
   routers. UDP-based hole punching (ADR-0005) succeeds in a significantly wider
   class of NAT configurations. ADR-0005 requires raw UDP datagrams with
   predictable timing and explicit keepalive control — these constraints cannot
   be satisfied through a TCP-only stack.

2. **Datagram-oriented direct messaging.** A UDP path avoids TCP
  connection-establishment overhead and supports NAT traversal and
  datagram-based communication patterns that are not a natural fit for a
  TCP-only stack.

The question is: **which approach to take for UDP — raw UDP with an explicit
security layer, or QUIC as an all-in-one transport?**

### Why not QUIC

QUIC (RFC 9000 / RFC 9001, implemented in Rust via `quinn`) was considered and
explicitly rejected for this ADR. The reasoning:

1. **Scope discipline.** QUIC packages congestion control, stream multiplexing,
   delivery reliability, and TLS 1.3-bound session establishment into a single
   layer. This exceeds the scope of "add UDP transport support". Raw UDP + Noise
   keeps this ADR tightly aligned with its purpose.

2. **Architectural control.** QUIC cedes session lifecycle, flow control, and
   connection establishment to the QUIC library. Adding UDP as a raw transport
   with an explicit Noise handshake preserves full control: session framing,
   reliability strategy, keepalive intervals, and demultiplexing are all
   TheNodes-owned decisions.

3. **NAT traversal compatibility.** ADR-0005 needs raw datagram access,
   predictable hole-punch timing, and explicit keepalive datagrams. Raw UDP
   aligns directly with standard STUN/ICE hole-punch techniques. QUIC's
   internal connection management makes datagram timing less predictable and
   complicates the integration with hole-punch rendezvous.

4. **Complexity and dependency surface.** `quinn` is a large, rapidly evolving
   library. `snow` (the Noise implementation already in `Cargo.toml`) is
   lightweight, well-understood, has explicit cryptographic semantics, and is
   already used for the TCP Noise backend. No new dependencies are required.

5. **Future flexibility.** Adopting raw UDP + Noise now does not prevent adding
   QUIC as an optional transport in a future ADR. The reverse is not true:
   committing to QUIC first makes it harder to reason about the lower layer.

6. **Layering model.** The recommended architecture is:  
   Transport → UDP  
   Security → Noise XX handshake + AEAD  
   Reliability → explicit optional layer (future)  
   Traversal → ADR-0005  

   This matches well-understood P2P design patterns and keeps each layer
   replaceable independently.

### Existing Noise foundation

The `noise` Cargo feature already exists and gates `snow = { version = "0.9",
optional = true }` (`snow` is MIT OR Apache-2.0). `NoiseSecureChannel` in
`src/security/secure_channel.rs` fully implements the Noise XX pattern
(`Noise_XX_25519_ChaChaPoly_BLAKE2s`) over TCP streams. The UDP path reuses
the same pattern and the same `snow` dependency, adding only a datagram framing
and session-demultiplexing layer. No new crate dependencies are required.

---

## Decision

Add **UDP as a first-class optional transport**, secured with a Noise XX
handshake and per-session AEAD encryption, feature-gated under the existing
`noise` Cargo feature.

The transport is additive in two message-layer places:

- `MessageType::Hello` gains an optional `udp_listen_addr` field.
- capability advertisement may include `"udp"` when UDP support is both
  compiled in and enabled in runtime config.

UDP remains a transport-layer addition beneath the existing message model. The
existing `SecureChannel` trait (ADR-0001) is **not modified**. UDP uses a
parallel `NoiseUdpSession` type plus helper functions in
`src/network/udp_listener.rs` and `src/network/udp_session.rs`.

However, bypassing the TCP-oriented `SecureChannel` trait does **not** mean UDP
may bypass TheNodes' authentication, trust, and observability seam. UDP/Noise
must still surface backend-consistent authentication metadata and trust
decisions through an adapter or event model that is semantically equivalent to
`AuthSummary`, so operators retain one coherent audit story across TLS, TCP
Noise, and UDP Noise.

The implemented UDP wire model has two frame classes:

- **TNCF control frames** for keepalive and Noise handshake control.
- **Session-ID-prefixed encrypted frames** for established UDP payload traffic.

---

## Design

### 1 — Transport kind tracking (`src/network/peer_manager.rs`)

```rust
/// Which transport protocol underlies a peer connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tcp,
    Udp,
}
```

`PeerManager` tracks transport metadata keyed by `node_id`:

- `transport_kind`
- `udp_listen_addrs`
- `udp_session_ids`

with async accessors such as:

```rust
pub async fn set_transport_kind(&self, node_id: &str, kind: TransportKind);
pub async fn get_transport_kind(&self, node_id: &str) -> Option<TransportKind>;
pub async fn add_udp_listen_addr(&self, node_id: &str, addr: &str);
pub async fn udp_listen_addr_for(&self, node_id: &str) -> Option<String>;
pub async fn set_udp_session_id(&self, node_id: &str, session_id: [u8; 8]);
pub async fn udp_session_id_for(&self, node_id: &str) -> Option<[u8; 8]>;
```

`SocketAddr` MUST NOT be used as the key. `TransportKind` represents the most
recently successful or preferred transport path to a peer. Peers may be
reachable through multiple transports and may switch between transports over
time; `TransportKind` is therefore mutable session metadata, not a permanent
property of the peer. `remove_peer` cleans this map alongside all existing maps.

The TCP path now records `TransportKind::Tcp` explicitly after HELLO
registration in both the inbound and outbound handshake paths. The UDP path
records `TransportKind::Udp` and the active `session_id` when a Noise session
finishes handshaking.

### 2 — Wire format and demultiplexing

The implementation does **not** use one universal UDP frame layout for all
datagrams. Instead, it distinguishes two frame classes before session lookup.

#### 2.1 — TNCF control frames

Control frames begin with the TheNodes control magic:

```
[ MAGIC:    4 bytes  — 0x54 0x4E 0x43 0x46 ("TNCF") ]
[ VERSION:  1 byte   — currently 0x01                  ]
[ TYPE:     1 byte   — frame type                      ]
[ RESERVED: 2 bytes  — zero on send, ignored on recv   ]
[ BODY:     variable                                   ]
```

Phase 1 currently implements these TNCF `TYPE` values:

```rust
pub mod tncf_type {
    pub const KEEPALIVE: u8 = 0x01;
    pub const HANDSHAKE_MSG1: u8 = 0x10;
    pub const HANDSHAKE_MSG2: u8 = 0x11;
    pub const HANDSHAKE_MSG3: u8 = 0x12;
}
```

For the three handshake control types, the TNCF body layout is:

```
[ SESSION_ID: 8 bytes ][ NOISE_MSG: variable ]
```

So in the implemented code, Noise handshake datagrams are carried as **TNCF
control frames**, not as bare session-ID-prefixed datagrams.

#### 2.2 — Session frames

Established encrypted UDP payload traffic uses:

```
[ session_id: 8 bytes ][ ciphertext: N bytes ]
```

- `session_id` — a random 8-byte identifier assigned **by the initiator** at
  session creation. The initiator MUST generate this value; the responder MUST
  reuse it unchanged for all frames in that session. No bidirectional
  negotiation of `session_id` occurs. This invariant prevents session
  desynchronisation.
- `ciphertext` — the output of transport-mode `write_message` after the Noise
  session has been established.

**Session identity vs. network path.** Sessions are demultiplexed by
`session_id`, not by `SocketAddr`. `SocketAddr` is mutable observed metadata
(path) and MUST NOT be treated as session identity. The source address of a
datagram MAY change between packets (NAT rebinding, path migration); this MUST
not cause the session to be considered a new or invalid session.

`peer_addr` is updated on every successful decrypt to support path migration.

#### 2.3 — `session_id` MUST NOT begin with `TNCF`

Because the receive path checks for `TNCF` control frames **before** session
lookup, session identifiers MUST NOT begin with the TNCF magic value. If bytes
0–3 equal `TNCF`, the datagram is parsed as a control frame rather than as a
session frame.

The implementation enforces this in two places:

- initiator-side generation rerolls until the prefix is not `TNCF`, and
- inbound handshake processing rejects values that begin with `TNCF`.

This means sentinel or special `session_id` values are not used for control
traffic. Pre-session signalling belongs on the TNCF control plane.

**Datagram size limits.** Two distinct limits apply and MUST NOT be conflated:

- `max_datagram_bytes` defines the **hard transport cap** on the total UDP
  datagram size on the wire (default **1200**). Safe for IPv6 minimum path MTU
  of 1280 minus IPv6/UDP headers.
- `max_app_payload_bytes` defines a **conservative upper bound** for plaintext
  message content. It is chosen to avoid fragmentation after accounting for the
  session header, Noise encryption overhead, and message serialization. The
  default of **1176** (= 1200 − 8 session header − 16 AEAD tag) is a
  reasonable starting point but MUST be treated as a conservative estimate, not
  a mathematically exact ceiling; Noise framing and envelope serialization may
  consume additional bytes. Payloads exceeding `max_app_payload_bytes` SHOULD
  fall back to TCP or relay. Implementations MUST enforce `max_datagram_bytes`
  based on the final serialized and encrypted UDP datagram size.

The current implementation enforces the Phase 1 defaults of **1200** and
**1176** via `MAX_DATAGRAM_BYTES` and `MAX_APP_PAYLOAD_BYTES` in
`src/network/udp_session.rs` / `src/network/udp_listener.rs`. `UdpConfig`
already exposes matching config fields, but the runtime currently enforces the
ADR defaults rather than per-node overrides.

No fragmentation is implemented in Phase 1.

### 3 — Session state machine (`src/network/udp_session.rs`)

```rust
pub enum UdpSessionState {
    /// Noise XX handshake in progress.
    Handshaking {
        handshake: Box<snow::HandshakeState>,
        step: u8,
    },
    /// Handshake complete; ready for encrypted transport.
    Established {
        transport: Box<snow::TransportState>,
        remote_static_fingerprint: [u8; 32],
    },
}

pub struct NoiseUdpSession {
    pub session_id: [u8; 8],
    pub node_id: Option<String>,
    pub peer_addr: SocketAddr,
    state: Option<UdpSessionState>,
    pub last_seen: Instant,
    pub created_at: Instant,
}
```

Initiator and responder roles mirror the TCP Noise backend exactly:

- **Initiator** builds with `builder.build_initiator()`, sends handshake
  message 1, waits for message 2, sends message 3, enters transport mode.
- **Responder** builds with `builder.build_responder()`, reads message 1,
  sends message 2, reads message 3, enters transport mode.

The Noise parameter string is identical to the TCP backend:
`"Noise_XX_25519_ChaChaPoly_BLAKE2s"`.

Peer identity is exchanged inside the Noise handshake payloads:

- the responder embeds `local_node_id` in `msg2`, and
- the initiator embeds `local_node_id` in `msg3`.

`NoiseUdpSession::advance_handshake()` extracts that payload and stores the
remote `node_id`. Established sessions without a confirmed `node_id` are not
used for application payload dispatch.

**Keypair handling.** UDP Noise sessions MUST use a **persistent node-static
keypair**, not a per-session ephemeral keypair. That key material must be
treated as long-lived node identity, not as a throwaway transport secret.
The key path SHOULD be configurable and may default to `pki/noise/static.key`
(consistent with the `pki/` convention for other local identity material).
On startup, the node loads this keypair via
`builder.local_private_key(&private_key_bytes)`.

For TheNodes' security posture, the steady-state expectation is that the party
that owns the node identity also owns this key material. In an operator-managed
deployment that may literally be an operator; in a consumer or chat-style app
it may instead be the application runtime or the end user on a device. The key
requirement is not "operator involvement" but that the identity is durable,
recoverable when the deployment model requires it, and not silently regenerated
as if it were disposable transport state. Automatic first-run generation may
exist as a bootstrap convenience, but it is not by itself a complete lifecycle
model for every deployment shape.

This requirement exists for three reasons: (1) the remote static fingerprint
retained in `NoiseUdpSession` is only meaningful for trust policy (TOFU,
allowlisting) if it is stable across reconnects; (2) NAT
rebinding identity continuity requires a stable static key so that a session
resumed from a new address can be re-authenticated; (3) ADR-0005 hole punching
depends on consistent identity across sessions.

At minimum, the lifecycle story must cover:

- configurable key location,
- how long-lived key material is provisioned or created for the relevant
  deployment model,
- rotation semantics (rotation creates a new transport identity and requires
  trust re-evaluation),
- backup/restore expectations for nodes that rely on long-lived UDP identity,
  and
- filesystem protection expectations for the private key.

Note: the current TCP Noise backend uses `builder.generate_keypair()` (ephemeral
per-handshake). That behaviour predates this requirement and is a separate
concern. UDP MUST use persistent keys from Phase 1 onwards.

**Node ↔ session routing.** After the Noise handshake completes and peer
identity is known, the implementation records a mapping from `node_id` to the
active UDP `session_id` in `PeerManager`. This allows higher-level components
to route to a peer without scanning the session table.

**Tracking note: TCP/UDP identity alignment.** A follow-up ADR should evaluate
aligning TCP Noise identity semantics with UDP so that peer identity and trust
policy behave consistently across transports. The current asymmetry (ephemeral
keys on TCP, persistent node-static keys on UDP) creates a divergent trust
model that should be resolved before trust policy is enforced in Phase 2.

### 4 — UDP listener (`src/network/udp_listener.rs`)

A single `tokio::net::UdpSocket` is bound at startup when UDP is enabled and
the binary is built with the `noise` feature.

The startup path is:

1. `main.rs` calls `load_static_key()`.
2. It resolves the UDP bind port from `[network.udp].listen_port` or `port + 1`.
3. It calls `spawn_udp_listener(...)`.
4. On success it starts `spawn_session_reaper(sessions)`.

```rust
// Note: plugin_manager and nat_state were added during ADR-0005 integration.
pub async fn spawn_udp_listener(
    bind_addr: SocketAddr,
    peer_manager: PeerManager,
    plugin_manager: Arc<PluginManager>,
    local_node_id: String,
    static_private: Vec<u8>,
    nat_state: Option<Arc<NatState>>,
) -> std::io::Result<(Arc<UdpSocket>, UdpSessions)>;
```

`spawn_udp_listener()` binds the socket, spawns the receive loop internally,
and returns both the shared socket and the `UdpSessions` map.

The receive path behaves as follows:

1. Reads a datagram via `socket.recv_from`.
2. Drops inbound datagrams larger than `MAX_DATAGRAM_BYTES`.
3. **Control-frame check first:** if `is_tncf_frame(datagram)` is true,
   dispatch by TNCF `TYPE` and skip session-frame parsing.
4. Otherwise treat the datagram as a session-ID-prefixed frame.

Currently implemented TNCF handling:

- `KEEPALIVE`
  - updates `last_seen` for any session whose current `peer_addr` matches the
    source address.
- `HANDSHAKE_MSG1`
  - enforces per-IP rate limits and handshake concurrency caps,
  - rejects `session_id` values that begin with `TNCF`,
  - creates a responder session,
  - sends `HANDSHAKE_MSG2` only if the response would not exceed a 3×
    anti-amplification bound,
  - inserts the pending session into `sessions`.
- `HANDSHAKE_MSG2`
  - advances the initiator handshake,
  - sends `HANDSHAKE_MSG3`,
  - finalizes the session if the handshake completes.
- `HANDSHAKE_MSG3`
  - advances the responder handshake,
  - finalizes the session if the handshake completes.

Session-frame handling only processes **established** sessions. On successful
decrypt it:

- updates `peer_addr`,
- updates `last_seen`, and
- dispatches the plaintext payload to `PeerManager::dispatch_udp_payload()`.

Frames addressed to a still-handshaking session via the session-frame path are
dropped.

Handshake completion is finalized by:

```rust
peer_manager.set_transport_kind(node_id, TransportKind::Udp).await;
peer_manager.set_udp_session_id(node_id, session.session_id).await;
```

Outbound handshakes are initiated by:

```rust
pub async fn connect_udp(
    target_addr: SocketAddr,
    socket: &Arc<UdpSocket>,
    sessions: &UdpSessions,
    static_private: &[u8],
    _local_node_id: &str,
) -> Result<[u8; SESSION_ID_LEN], Box<dyn std::error::Error + Send + Sync>>;
```

This creates the initiator session, sends `HANDSHAKE_MSG1` as a TNCF control
frame, and inserts the pending session into the shared session map.

Encrypted outbound payload delivery uses:

```rust
pub async fn send_udp(
    session_id: &[u8; SESSION_ID_LEN],
    plaintext: &[u8],
    socket: &Arc<UdpSocket>,
    sessions: &UdpSessions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
```

`send_udp()` enforces both the plaintext and final datagram size limits.

#### DoS and resource-exhaustion limits

An unknown `session_id` MUST NOT cause unlimited state allocation. The
following guards MUST be enforced:

- **Handshake concurrency cap:** at most N concurrent `Handshaking` sessions
  (default: 64). Excess inbound initiations are dropped silently.
- **Handshake rate limit:** at most M new handshakes per second per source IP
  (default: 8/s). Violations are dropped silently.
- **Handshake expiry:** `Handshaking` sessions that do not complete within a
  deadline (default: 5 seconds) are evicted regardless of `last_seen`.
- **Established session expiry:** established sessions idle for more than
  `2 × SESSION_IDLE_TIMEOUT_SECS` are reaped.
- **No reflection / amplification:** the listener MUST NOT send any response
  to a datagram that fails to match a session or a valid control frame. Silent
  drop is the only correct action.

Expiry is implemented by a dedicated `spawn_session_reaper()` task running at a
30-second interval. It is **not** integrated into the TCP keepalive machinery.

### 5 — HELLO extension (`src/network/message.rs`)

```rust
MessageType::Hello {
    node_id: String,
    listen_addr: Option<String>,
    protocol: Option<String>,
    version: Option<String>,
    node_type: Option<String>,
    capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_listen_addr: Option<String>,
}
```

This is a purely additive field. Nodes that do not support UDP omit it; older
nodes that predate this ADR will ignore it via serde's unknown-field handling.
When both sides advertise a `udp_listen_addr`, either side may initiate a UDP
session.

There is no separate `HelloPayload` struct in the current implementation; the
field lives directly on the `MessageType::Hello` variant.

### 6 — Capability flag

`advertised_capabilities` in `src/network/mod.rs` adds `"udp"` when
the binary is built with `noise` **and** `[network.udp].enabled = true`:

```rust
if cfg!(feature = "noise") {
    if let Some(udp) = config.network.as_ref().and_then(|n| n.udp.as_ref()) {
        if udp.enabled.unwrap_or(false) {
            caps.push("udp".to_string());
        }
    }
}
```

A peer that sees `"udp"` in both its own and the remote's capability set, and
both HELLOs carry `udp_listen_addr`, may initiate a UDP session. If either side
lacks the `"udp"` capability, only TCP is used.

`udp_hello_addr()` uses the same gating and advertises either the configured UDP
port or `tcp_port + 1`.

Both inbound and outbound TCP HELLO handling record the remote peer's
`udp_listen_addr` in `PeerManager` if present, and both paths now explicitly set
`TransportKind::Tcp` after successful HELLO registration.

### 7 — Configuration (`src/config.rs`)

```toml
[network.udp]
# Enable UDP transport with Noise secure sessions.
# Requires the 'noise' Cargo feature.
enabled = false

# UDP listen port. Default: main TCP port + 1.
listen_port = 4434

# Maximum UDP datagram size on the wire (bytes).
# Safe for IPv6 minimum path MTU (1280) minus IPv6/UDP headers.
max_datagram_bytes = 1200

# Conservative upper bound for plaintext message content (bytes).
# Accounts for session header, Noise AEAD overhead, and serialization.
# 1176 = 1200 - 8 (session_id) - 16 (AEAD tag); treat as a conservative
# estimate, not an exact ceiling. Payloads exceeding this MUST fall back
# to TCP or relay.
max_app_payload_bytes = 1176
```

`UdpConfig` is defined in `src/config.rs` and currently defaults to:

- `enabled = false`
- `listen_port = None`
- `max_datagram_bytes = 1200`
- `max_app_payload_bytes = 1176`

At startup, when UDP is enabled, the current implementation binds
`0.0.0.0:<listen_port>` or `0.0.0.0:<tcp_port + 1>`.

### 8 — Security and current scope

UDP uses the same Noise parameter string as the TCP backend:

```text
Noise_XX_25519_ChaChaPoly_BLAKE2s
```

Plaintext UDP is not part of this ADR. UDP transport exists only behind the
existing `noise` feature.

The current Phase 1 implementation stores the remote static public-key
fingerprint inside `NoiseUdpSession` state. It does **not** yet thread UDP
handshakes through the TCP-oriented `AuthSummary` / `SecureChannel` reporting
path.

Today, successful UDP establishment is surfaced through transport metadata and
network events such as `udp_session_established`, while decrypted payloads are
forwarded through `PeerManager::dispatch_udp_payload()`.

This alone is not sufficient to satisfy the architectural intent of ADR-0001.
ADR-0004 therefore requires UDP Noise authentication and trust outcomes to be
surfaced through backend-consistent audit and trust metadata rather than only
through transport-local success events.

The X.509 certificate-chain validation logic used by the TLS path does not
apply here. Trust policy for Noise static keys remains future work.

ADR-0005 may extend TNCF with additional control types for NAT traversal and
rendezvous, but ADR-0004 itself currently implements only `KEEPALIVE` and the
three handshake control types.

---

## Phasing

ADR-0004 defines a Phase 1 transport foundation plus explicitly deferred
follow-up work that builds on that foundation.

### Phase 1 (implemented scope)

- `TransportKind { Tcp, Udp }` plus `PeerManager` transport metadata.
- `NoiseUdpSession` state machine with Noise XX handshake.
- Shared `UdpSocket` listener started by `spawn_udp_listener()`.
- TNCF-first UDP demultiplexing.
- TNCF `KEEPALIVE`, `HANDSHAKE_MSG1`, `HANDSHAKE_MSG2`, `HANDSHAKE_MSG3`.
- `session_id` parser-safety rule: it MUST NOT begin with `TNCF`.
- Persistent static keypair handling with configurable location; a deployment
  may use `pki/noise/static.key` as the default path.
- Outbound `connect_udp()` initiation and `send_udp()` encrypted payload send.
- `udp_listen_addr` HELLO extension.
- `"udp"` capability advertisement gated by feature and runtime config.
- `[network.udp]` config schema.
- Dedicated session reaper.

### Deferred follow-ups (separate future work)

- Trust policy for Noise static keys (TOFU / allowlist / pinning), likely via a
  dedicated follow-up ADR.
- Optional reliability layer for UDP payload delivery, if later deemed
  necessary.
- Possible alignment of TCP Noise identity semantics with UDP static-key
  semantics as part of later identity/trust-policy work.
- Possible surfacing of UDP authentication data through shared security/audit
  summary structures.

### Separate follow-on work (ADR-0005)

- NAT traversal and hole punching built on the TNCF control plane.
- Additional rendezvous / observation frame types.
- Relay-assisted coordination for punch attempts.

---

## Consequences

### Positive

- Raw UDP is available for future NAT traversal and hole punching.
- The existing TCP `SecureChannel` path remains untouched.
- HELLO and capability changes are additive and backward-compatible.
- The receive path cleanly separates TNCF control traffic from session traffic.
- Session-ID collisions with the `TNCF` magic are prevented in code.
- Datagram size limits are enforced on both receive and send paths.
- UDP transport metadata is recorded explicitly in `PeerManager`.

### Negative / Trade-offs

- No built-in reliability: payloads are still subject to loss and reordering.
- Larger payloads still require TCP or relay fallback.
- Persistent static keys introduce key lifecycle and rotation concerns.
- The runtime now maintains a session table plus a background reaper.
- UDP authentication/trust reporting is not yet unified with the TCP security
  reporting path.

---

## Alternatives Considered

- **QUIC via `quinn`:** Explicitly evaluated and rejected. See the "Why not
  QUIC" section above. QUIC remains a possible future transport ADR but is out
  of scope for this lower-level UDP transport foundation.

- **TCP + relay only (no UDP):** Simpler short-term, but it blocks the UDP
  transport substrate needed for NAT traversal and direct datagram exchange.

- **WebRTC data channels:** Rejected as out of scope and unnecessarily complex
  for a native Rust node runtime.

- **Per-session ephemeral-only UDP identity:** Rejected for Phase 1. The
  implemented UDP transport intentionally persists a static keypair so peer
  identity can remain stable across reconnects and future trust policy.

---

## Open Questions

1. Should TCP Noise be aligned with the UDP path's persistent static-key model?
2. Should the runtime start honoring per-node `max_datagram_bytes` /
   `max_app_payload_bytes` overrides instead of enforcing fixed ADR defaults?
3. Should Phase 2 add a lightweight reliability layer for ordered UDP delivery?
4. Should UDP authentication data be surfaced through the shared security/audit
   summary path used by TCP/TLS today?
5. Should one peer eventually be allowed to maintain multiple simultaneous UDP
   sessions, or should `PeerManager` continue to treat one active `session_id`
   as the preferred path?

---

## References

- ADR-0001: Secure Channel Abstraction — Noise XX already implemented over TCP
  in `src/security/secure_channel.rs`.
- ADR-0003: Relay Nodes — relay remains the fallback when UDP is unavailable or
  payload size exceeds the configured transport envelope.
- ADR-0005: NAT Traversal and Hole Punching — extends the TNCF control plane
  introduced here.
- [Noise Protocol Framework specification](https://noiseprotocol.org/noise.html)
- [snow crate (MIT OR Apache-2.0)](https://docs.rs/snow/)
- RFC 4821 — Packetization Layer Path MTU Discovery
- RFC 8445 — ICE (architectural reference for future ADR-0005 work)
