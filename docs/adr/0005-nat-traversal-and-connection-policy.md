# ADR 0005: NAT Traversal, Hole Punching, and Connection Preference Policy

- Status: Accepted
- Date: 2026-03-08
- Target: 0.3.x
- Depends on: ADR-0003 (Relay Nodes), ADR-0004 (UDP Transport with Noise Secure Sessions)
- Requires: `noise` feature for UDP traversal paths

## Context

TheNodes currently has three transport building blocks:

1. direct TCP using the existing secure channel path,
2. relay fallback from ADR-0003, and
3. direct UDP + Noise from ADR-0004 when a peer's UDP endpoint is known.

What is still missing is a framework-level strategy for deciding:

- when to try direct TCP,
- when to try direct UDP,
- when to attempt UDP hole punching, and
- when to fall back to relay.

Without that strategy, transport policy leaks into callers and plugins.

### ADR-0005 design basis

This ADR builds directly on the UDP transport model defined in ADR-0004.

ADR-0004 establishes the following transport-layer rules:

- A single shared UDP socket bound according to `[network.udp]`.
- **TNCF control frames** for all pre-session control-plane traffic.
- **Session frames** identified by an 8-byte `session_id` prefix, used only for
  Noise handshake and encrypted session traffic.
- Control frames are identified by the `TNCF` magic (`0x54 0x4E 0x43 0x46`) in
  bytes 0–3 and are explicitly demultiplexed **before session lookup**.
- No sentinel or control-signalling `session_id` values exist. Session identifiers 
  are random and used only for Noise session demultiplexing, except that values 
  beginning with the `TNCF` magic are invalid and must not be generated.

ADR-0005 therefore reuses the TNCF-based UDP control plane introduced in
ADR-0004. All NAT traversal and rendezvous signalling (for example address
discovery, cookie challenge, and punch coordination) are implemented as
TNCF control-frame types rather than introducing a separate pre-session
datagram format.

## Constraints and honest NAT caveats

Before defining a design, these constraints must be explicit:

- **UDP hole punching is best-effort, not guaranteed.** It works well on full-cone and many restricted-cone NATs, but it often fails on symmetric NAT and many CG-NAT/mobile environments.
- **Relay remains necessary.** Even with a good punch design, some peers will remain relay-only.
- **TCP simultaneous-open is out of scope.** ADR-0004 already provides a live UDP socket. UDP punching is simpler and materially more reliable than TCP hole punching across platforms.
- **UPnP / NAT-PMP / PCP are out of scope.** They may be useful later, but they are separate concerns with different security and deployment trade-offs.
- **Observed external UDP addresses are advisory and time-sensitive.** NAT rebinding can make them stale.
- **Address observation discloses the node's public UDP source address to the observing node.** This is comparable to relay disclosure and must remain opt-in and policy-controlled.

## Foundation from ADR-0004

ADR-0004 already provides the critical substrate for traversal:

- a single bound `UdpSocket` per node,
- TNCF-based pre-session UDP control framing,
- `NoiseUdpSession` for UDP secure sessions,
- HELLO advertisement of `udp_listen_addr`,
- `"udp"` capability advertisement, and
- runtime transport metadata in peer tracking.

The most important implication is this:

> Address observation, punch probes, and the UDP Noise handshake must all use the same UDP socket from ADR-0004.

Using a different UDP socket would discover or punch a different NAT mapping and make the result unreliable.

## Decision

Introduce a **framework-level connection policy** and a **TheNodes-native NAT traversal flow** that reuses ADR-0004's existing UDP socket and TNCF control frames.

### High-level decisions

1. **Connection policy becomes explicit runtime behavior.**
   Transport fallback is owned by the framework, not by plugins.

2. **No STUN datagram demultiplexing in `udp_listener.rs`.**
   This ADR does not add RFC 5389 cookie parsing to the UDP hot path.

3. **No sentinel `session_id` values.**
   Pre-session traversal messages use TNCF control frames only.

4. **Observed-address discovery uses the existing UDP socket and TNCF control frames.**
   The design stays consistent with ADR-0004 instead of introducing a parallel wire format.

  Observed-address discovery is still only a reachability hint until it is
  bound to authenticated peer state. A UDP observation reply must not become a
  standalone trust fact.

5. **UDP hole punching is coordinated over authenticated node-to-node messages.**
   Relay or rendezvous coordination happens over the existing secure channel / relay plane, not over unauthenticated public UDP messages.

6. **Relay remains the required fallback.**
   Punching is an optimization, not a replacement for ADR-0003.

## Decision details

## 1. Connection preference policy

Add a policy-driven state machine for outbound connectivity.

The policy is configured via a new section:

```toml
[network.connection_policy]
# direct_only | direct_then_relay | direct_then_udp_then_relay |
# direct_then_punch_then_relay | relay_only
strategy = "direct_then_relay"

# Timeout for direct TCP connect before moving to the next stage.
direct_tcp_timeout_ms = 3000

# Timeout for direct UDP attempt when a usable UDP address is known.
direct_udp_timeout_ms = 1000

# Total time budget for relay-coordinated UDP hole punching.
punch_timeout_ms = 5000
```

A new internal entry point is introduced:

```rust
pub async fn connect_with_policy(
    target_node_id: &str,
    policy: &ConnectionPolicy,
    peer_manager: &PeerManager,
    config: &Config,
) -> ConnectionOutcome
```

```rust
pub enum ConnectionOutcome {
    AlreadyConnected,
    DirectTcp { addr: SocketAddr },
    DirectUdp { addr: SocketAddr },
    HolePunchUdp { addr: SocketAddr },
    ViaRelay { relay_node_id: String },
    NoRoute { reason: String },
}
```

`deliver_to_node` and any higher-level delivery helper route through this policy entry point rather than hard-coding fallback order.

### Strategy semantics

- `direct_only`
  - Try direct TCP only.
  - No UDP direct attempt.
  - No punching.
  - No relay.

- `direct_then_relay`
  - Try direct TCP.
  - Fall back to relay.
  - This is the backward-compatible default when relay is enabled.

- `direct_then_udp_then_relay`
  - Try direct TCP.
  - If the peer advertises `"udp"` and a usable UDP address is known, try direct UDP Noise.
  - Fall back to relay.

- `direct_then_punch_then_relay`
  - Try direct TCP.
  - Try direct UDP when a usable UDP address is already known.
  - If direct UDP fails and traversal prerequisites are met, attempt relay-coordinated UDP hole punching.
  - Fall back to relay if punching fails.

- `relay_only`
  - Skip all direct paths.
  - Use relay immediately.

## 2. External address observation over TNCF

External address observation is defined as a TheNodes-native flow built on TNCF control frames.

### Why TNCF observation instead of STUN parsing

ADR-0004 already established that pre-session UDP control traffic belongs on the TNCF control plane. Reusing TNCF:

- matches the existing listener demultiplexing model,
- avoids dual wire-format logic in `udp_listener.rs`,
- avoids STUN-specific parsing in the hot path, and
- keeps anti-amplification rules under the same transport design.

### New TNCF control types

`src/network/udp_session.rs` is extended with additional TNCF type codes:

```rust
pub mod tncf_type {
    pub const KEEPALIVE: u8 = 0x01;
    pub const HANDSHAKE_MSG1: u8 = 0x10;
    pub const HANDSHAKE_MSG2: u8 = 0x11;
    pub const HANDSHAKE_MSG3: u8 = 0x12;

    pub const OBSERVE_REQ: u8 = 0x20;
    pub const COOKIE_CHALLENGE: u8 = 0x21;
    pub const OBSERVE_RESP: u8 = 0x22;
}
```

### Observation flow

1. Node A selects a rendezvous-capable peer that it already trusts and can already reach through the existing secure channel / relay topology.
2. Node A allocates a pending observation record bound to that rendezvous peer identity and request nonce.
3. Node A sends a TNCF `OBSERVE_REQ` from the ADR-0004 UDP socket.
4. Any UDP reply from an unexpected source address or without a matching pending observation record is ignored.
5. The observing node responds with `COOKIE_CHALLENGE` unless the request already contains a valid cookie.
6. Node A retries `OBSERVE_REQ` with the cookie.
7. The observing node responds with `OBSERVE_RESP`, containing the observed `ip:port` and freshness metadata.
8. Node A stores the result together with the observing peer identity and request metadata; only then may it be considered eligible for reuse by connection policy or HELLO advertisement.

### Why a cookie is required

Observation must not become a reflection or amplification primitive. A stateless cookie challenge proves reachability of the source address before the observer returns any address information.

The cookie does **not** by itself authenticate the observing peer. That
authentication comes from binding the UDP exchange to an already-authenticated
rendezvous relationship and discarding replies that do not match the expected
peer and nonce.

### TNCF body layouts

```text
OBSERVE_REQ
[ nonce: 8 bytes ][ cookie_len: 1 byte ][ cookie: variable ]

COOKIE_CHALLENGE
[ nonce: 8 bytes ][ cookie_len: 1 byte ][ cookie: variable ]

OBSERVE_RESP
[ nonce: 8 bytes ][ observed_addr_len: 1 byte ][ observed_addr: utf8 "ip:port" ][ observed_at_ms: 8 bytes ]
```

The exact cookie construction is implementation-defined, but it must be stateless or cheap to validate and bound to the sender address and short TTL.

## 3. HELLO metadata extension

ADR-0004 already added `udp_listen_addr` to `MessageType::Hello`.

ADR-0005 adds a second optional field:

```rust
MessageType::Hello {
    // ... existing fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_listen_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_observed_addr: Option<String>,
}
```

### Semantics

- `udp_listen_addr`
  - The node's own configured or locally bound UDP address.
  - Useful on LANs, port-forwarded deployments, and directly reachable hosts.

- `udp_observed_addr`
  - The node's most recently observed public UDP address, as reported by a rendezvous-capable peer.
  - Useful for NAT traversal.
  - Advisory only while it remains fresh enough according to policy.
  - Must be associated internally with the authenticated observer identity that supplied it; it is not a standalone trust fact.

`udp_observed_addr` MUST be treated as stale after the policy-defined
observation freshness window. Stale observed addresses MUST NOT be used for
direct UDP attempts or punch coordination, and SHOULD be omitted from HELLO
advertisement until refreshed.

ADR-0005 does not require `udp_observed_addr` to be persisted across restarts.
It does require that any reusable observation record carry enough metadata to
answer: who observed this, when, and for which pending request.

## 4. Capability flags

ADR-0004 already advertises `"udp"` when built with `noise` and `[network.udp].enabled = true`.

ADR-0005 adds:

- `"punch"` — this node can participate in NAT traversal as a peer.
- `"punch_rendezvous"` — this node can serve observation and punch coordination.

A node advertises `"punch"` only when:

- built with `noise`,
- `[network.udp].enabled = true`, and
- `[network.nat_traversal].enabled = true`.

A node advertises `"punch_rendezvous"` only when:

- all `"punch"` requirements hold,
- relay mode is enabled, and
- `[network.nat_traversal].serve = true`.

`"punch_rendezvous"` is intentionally stronger than `"punch"` because the rendezvous role carries extra policy and abuse-control responsibility.

## 5. Relay-coordinated UDP hole punching

When strategy `direct_then_punch_then_relay` is configured and direct paths fail, TheNodes uses an authenticated rendezvous flow to coordinate UDP hole punching.

### Coordination messages

Additive `MessageType` variants are introduced in `src/network/message.rs`:

```rust
MessageType::PunchCoordinate {
    attempt_id: String,
    target: String,
    timeout_ms: Option<u64>,
}

MessageType::PunchInvite {
    attempt_id: String,
    from_node_id: String,
    timeout_ms: u64,
}

MessageType::PunchReady {
    attempt_id: String,
    target: String,
    ok: bool,
}

MessageType::PunchGo {
    attempt_id: String,
    initiator: String,
    responder: String,
    initiator_observed_addr: String,
    responder_observed_addr: String,
    start_at_ms: u64,
    timeout_ms: u64,
}

MessageType::PunchAbort {
    attempt_id: String,
    target: String,
    reason: Option<Reason>,
}
```

These messages travel over the existing authenticated message layer, not over raw public UDP.
`attempt_id` provides correlation across retries, duplicate control messages,
and overlapping punch attempts involving the same peer pair.

### Coordination flow

1. **Initiator → rendezvous**
  - Send `PUNCH_COORDINATE { attempt_id, target, timeout_ms }`.

2. **Rendezvous validation**
   - Verify both peers:
     - are in the same realm,
     - advertise `"udp"` and `"punch"`,
     - have `udp_observed_addr` values that are still fresh under the active
       observation freshness policy, and
     - satisfy local trust/policy rules.

3. **Rendezvous → responder**
  - Send `PUNCH_INVITE` carrying the same `attempt_id`.

4. **Responder → rendezvous**
  - Reply `PUNCH_READY { attempt_id, ok }`.

5. **Rendezvous → both peers**
   - Send `PUNCH_GO` with:
    - the same `attempt_id`,
     - both observed UDP addresses,
     - deterministic initiator/responder roles,
     - a synchronized start time marking the beginning of the coordinated
       probe window,
     - the punch timeout budget.

6. **Punch window opens**
   - At `start_at_ms`, both peers begin sending short bursts of TNCF
     `KEEPALIVE` datagrams to the other peer's observed address.
   - Probe bursts continue for the configured punch window
     (`probe_count × probe_interval_ms`) so the overlap can tolerate modest
     clock skew, scheduling latency, and NAT mapping delay.
   - These are only NAT-opening probes; they do not create session state.

7. **Noise handshake starts**
   - The designated initiator calls the existing ADR-0004 UDP connect path and
     sends `HANDSHAKE_MSG1`.
   - The initiator MAY retransmit `HANDSHAKE_MSG1` within the punch window if
     needed, while staying within the configured timeout budget.
   - The responder does not start an independent initiator handshake; it only
     listens and responds.

8. **Success**
   - If ADR-0004 UDP Noise session establishment succeeds, the transport for that peer is promoted to `TransportKind::Udp`.

9. **Failure**
  - On timeout or explicit abort, the caller falls back according to the configured connection strategy.

### Deterministic initiator rule

To avoid conflicting simultaneous Noise handshakes:

- the node that requested `PUNCH_COORDINATE` is always the UDP Noise initiator,
- the invited peer is the responder.

Both peers still send probe datagrams, but only one side sends `HANDSHAKE_MSG1`.

`start_at_ms` defines the beginning of a coordinated probe window, not a
single exact packet moment. The designated initiator MAY retransmit
`HANDSHAKE_MSG1` within that window while the responder remains strictly in
listening/responding mode.

### Relay requirement

A rendezvous node must only coordinate punches for authenticated peers that it is already willing to serve under the relay/trust policy. This ADR assumes the rendezvous function is paired with relay-capable infrastructure from ADR-0003.

## 6. Runtime state additions

`PeerManager` already tracks transport kind, UDP listen addresses, and UDP session IDs.

ADR-0005 extends peer metadata with observed UDP address state:

```rust
pub async fn add_udp_observed_addr(&self, node_id: &str, addr: &str);
pub async fn udp_observed_addr_for(&self, node_id: &str) -> Option<String>;
```

The local node also tracks its own most recent observed UDP address and timestamp for HELLO advertisement and connection-policy decisions.
Architecturally, the stored record should include at least the observed address,
observation time, and the authenticated observer peer identity; a bare address
string is not sufficient if the result will influence later policy decisions.

The runtime should also track pending observation requests and pending punch
attempts by explicit correlation ID rather than by peer pair alone.

A future reachability cache may also record recent punch success/failure to avoid repeated expensive attempts against obviously relay-only peers.

## 7. New NAT traversal configuration

```toml
[network.nat_traversal]
enabled = false

# Allow this node to act as an observation and punch-coordination server.
# Requires [network.relay].enabled = true and [network.udp].enabled = true.
serve = false

# How often to refresh the locally observed UDP address.
refresh_secs = 300

# Stateless cookie lifetime for observation challenge/response.
cookie_ttl_secs = 30

# Number of probe datagrams to send during a punch attempt.
# Together with probe_interval_ms, this defines a short coordinated probe window.
probe_count = 6

# Delay between successive probe datagrams.
# Chosen to tolerate modest clock skew and scheduling jitter while keeping
# both NAT mappings open long enough to overlap.
probe_interval_ms = 100
```

## 8. Security and abuse controls

ADR-0005 must preserve ADR-0004's existing security posture.

### Required safeguards

- Observation replies require a valid cookie.
- Observation replies from unexpected sources or without matching pending request state are silently dropped.
- Unknown or malformed TNCF traversal control frames are silently dropped.
- Punch coordination is only offered to authenticated peers.
- Rendezvous nodes only coordinate peers inside the same realm and policy envelope.
- Punch probes do not allocate long-lived session state by themselves.
- Only ADR-0004 Noise handshake completion creates a trusted UDP session.

`udp_observed_addr` is therefore a policy-scoped routing hint, not an identity
assertion and not a substitute for authenticated peer state.

### Important limitation

Hole punching improves reachability, not identity. Peer authentication still comes from the Noise XX session and the existing trust policy.

## 9. Code changes

| Area | Change |
|---|---|
| `src/network/message.rs` | Add `udp_observed_addr` to `MessageType::Hello`; add `PunchCoordinate`, `PunchInvite`, `PunchReady`, `PunchGo`, `PunchAbort` |
| `src/config.rs` | Add `ConnectionPolicyConfig` and `NatTraversalConfig` to `NetworkConfig` |
| `src/network/mod.rs` | Extend capability advertisement for `punch` / `punch_rendezvous` |
| `src/network/connection.rs` | New module for `connect_with_policy`, strategy ordering, and `ConnectionOutcome` |
| `src/network/nat_traversal.rs` | New module for observed-address refresh, cookie validation, and punch orchestration helpers |
| `src/network/udp_session.rs` | Add `OBSERVE_REQ`, `COOKIE_CHALLENGE`, `OBSERVE_RESP` TNCF types |
| `src/network/udp_listener.rs` | Extend TNCF dispatch to handle observation control frames while preserving TNCF-first demux |
| `src/network/relay.rs` and/or relay handlers | Handle `PUNCH_*` control messages and rendezvous policy checks |
| `src/network/peer_manager.rs` | Store observed UDP addresses and optional traversal outcomes |
| `src/main.rs` | Start background observation refresh task when enabled |

## 10. Wire compatibility

All proposed wire changes are additive:

- new `MessageType` variants are ignored by older nodes that do not understand them,
- `udp_observed_addr` is optional and omitted when absent,
- new TNCF frame types extend the control namespace without changing existing ADR-0004 frame semantics.

No existing message variant or established UDP frame format is modified.

## Consequences

### Positive

- Transport fallback becomes explicit, centralized, and consistent.
- ADR-0004's UDP transport becomes useful beyond LAN-only direct use.
- The design stays aligned with the implemented TNCF model.
- Relay remains a reliable fallback for hard NAT cases.
- No sentinel `session_id` hacks are needed.

### Negative / trade-offs

- More protocol surface: new capabilities, new HELLO field, new message types, new TNCF control types.
- Rendezvous-capable nodes take on more operational responsibility.
- Some NATs will still require relay, so punching adds complexity without universal success.
- Address freshness and timeout tuning materially affect success rate.

## Phasing

### Phase 1 — Connection policy + direct UDP preference

- Add `ConnectionPolicyConfig`.
- Add `connect_with_policy`.
- Support `direct_only`, `direct_then_relay`, `direct_then_udp_then_relay`, and `relay_only`.
- Reuse existing ADR-0004 `udp_listen_addr` for opportunistic direct UDP.

This phase requires no new TNCF types.

### Phase 2 — Observed-address discovery

- Add `udp_observed_addr`.
- Add `OBSERVE_REQ`, `COOKIE_CHALLENGE`, `OBSERVE_RESP`.
- Add observed-address refresh loop.
- Add `punch` / `punch_rendezvous` capability gating.

This phase requires `[network.udp].enabled = true` and the `noise` feature.

### Phase 3 — Relay-coordinated UDP hole punching

- Add `PUNCH_*` message types.
- Add punch orchestration.
- Add `direct_then_punch_then_relay` strategy.
- Use TNCF `KEEPALIVE` bursts plus the existing ADR-0004 UDP Noise handshake.

Relay fallback remains mandatory after punch timeout.

## Alternatives considered

### 1. RFC 5389 STUN parsing in the UDP listener

Rejected for this ADR.

Reasons:

- does not match ADR-0004's TNCF-first design,
- adds a second control wire format to the UDP receive path,
- complicates anti-amplification and parser hardening,
- is unnecessary for TheNodes-native rendezvous.

### 2. Sentinel `session_id` values for punch probes

Rejected.

Reasons:

- conflicts with ADR-0004’s parser-safety rule that `session_id` values must not begin with `TNCF`,
- overloads session identity with pre-session signaling,
- makes the listener path less explicit and harder to reason about.

### 3. TCP simultaneous-open

Rejected.

Reasons:

- less reliable in practice than UDP punching,
- platform quirks on macOS and Windows,
- no advantage over the existing ADR-0004 UDP socket.

### 4. TURN-style relay allocation

Rejected for now.

Reasons:

- substantially more complex than current relay forwarding,
- would introduce a much larger protocol and state surface,
- relay forwarding from ADR-0003 already covers the mandatory fallback path.

### 5. Application-level transport policy

Rejected.

Reasons:

- transport routing is framework responsibility,
- would leak network complexity into plugins and applications,
- would make behavior inconsistent across embeddings.

## Open questions

1. Should `punch_rendezvous` be limited to relay nodes only, or may any authenticated UDP-capable peer serve observation + coordination?
2. Should punch failure history be persisted, or remain an in-memory reachability hint only?
3. Should Phase 3 add a second punch attempt with reversed initiator/responder roles for difficult NATs?
4. Should public delivery/result enums become `#[non_exhaustive]` before adding new transport outcomes?

## References

- ADR-0003: Relay Nodes
- ADR-0004: UDP Transport with Noise Secure Sessions
- `src/network/udp_listener.rs`
- `src/network/udp_session.rs`
- `src/network/message.rs`
- `src/network/mod.rs`
- `src/network/relay.rs`
- `src/network/peer_manager.rs`
- `src/config.rs`
