# ADR 0003: Relay Nodes in TheNodes

- Status: Accepted
- Date: 2025-12-06
- Target: 0.2.x (incremental, non-breaking)

## Context
Many peers cannot establish direct P2P links due to NAT/firewalls, temporary unreachability, mobile/sleeping devices, or asymmetric networks. TheNodes needs a transport-level relay role to restore reachability without exposing payloads.

## Decision
- Introduce a relay capability advertised during HELLO: `capabilities: ["relay"]`, with optional extensions (`relay_store_forward`, `relay_high_bandwidth`, `relay_low_latency`, `relay_unmetered`).
- Deterministic relay selection to avoid herd effects: filter by realm/capabilities and load, sort by stability/RTT, then hash-distribute: `index = hash(node_id + realm) mod candidate_count`.
- Connection model:
  - Bind phase: client opens a SecureChannel to relay, sends `RELAY_BIND { target: <node_id> }`.
  - Forwarding phase: on successful binds for A and B, relay routes encrypted frames: `A <-> relay <-> B` using a minimal frame `{ to, from, sequence, payload }`.
  - Optional store-and-forward: bounded buffering with TTL and limits, configurable per realm.
- Security: Relay authenticates peers per realm policy (TLS or Noise via SecureChannel). Payloads remain opaque end-to-end; relay cannot decrypt or alter contents. Identity verification is not short-circuited by relay.
- Failure handling: Overload rejection, graceful closes, heartbeats/liveness, fast failover, and rebinding on relay restart.
- Privacy: Minimal metadata retention; obey realm policies; drop expired buffers promptly.

## Implications
- Protocol additions: `RELAY_BIND` request/ack; opaque forwarding frame type; capability flags in HELLO.
- Configuration: Realm-level toggles for allowed relay types, store-and-forward TTL/limits, load thresholds.
- Discovery: PeerRequest/PeerList flows include relay capabilities; bootstrap sources advertise relays.
- Metrics: Relay load, liveness, failure/failover events; optional stability/RTT sampling.
- Testing: NAT fallback scenarios, high-latency, rapid reconnects, overload/recovery, store-and-forward reliability, routing correctness under stress.

## Wire-Level Schema

### RELAY_BIND Request (from client to relay)
- Fields:
  - `target`: node id string (realm-unique)
  - `want_store_forward`: bool (optional; default false)
  - `qos`: optional relay hint (`low_latency` | `high_bandwidth` | `unmetered`)
  - `nonce`: u64 for request correlation
  - `expires_at`: optional epoch seconds for bind TTL (client hint)

Example (JSON-like envelope carried over SecureChannel):
```
{
  "type": "RELAY_BIND",
  "target": "node-b",
  "want_store_forward": false,
  "qos": "low_latency",
  "nonce": 42,
  "expires_at": 1733433600
}
```

### RELAY_BIND Ack (from relay to client)
- Fields:
  - `ok`: bool
  - `reason`: optional string on failure (`overload`, `unknown_target`, `policy_denied`, `already_bound`, `timeout`)
  - `binding_id`: opaque relay binding identifier (for subsequent control/teardown)
  - `peer_present`: bool (true if target is currently bound)
  - `nonce`: echoes request nonce

Example:
```
{
  "type": "RELAY_BIND_ACK",
  "ok": true,
  "binding_id": "bind-7f7c...",
  "peer_present": true,
  "nonce": 42
}
```

### Forwarding Frame (opaque payload)
- Fields:
  - `to`: node id
  - `from`: node id
  - `sequence`: u64 (per-flow sequence for simple ordering/duplicate detection)
  - `payload`: bytes (opaque to relay)

```
{
  "type": "RELAY_FWD",
  "to": "node-b",
  "from": "node-a",
  "sequence": 128,
  "payload": "<opaque bytes>"
}
```

## Bind Lifecycle State Machine (Relay Perspective)
- `Idle` → `BindingRequested` on `RELAY_BIND` receipt
- Validate realm policy, capacity, and target availability
  - On deny: send `RELAY_BIND_ACK{ok:false,reason}` → `Idle`
  - On accept: create `Binding(binding_id)` → `AwaitPeer`
- `AwaitPeer`: if both A and B bound → `Forwarding`
  - Heartbeats; monitor liveness and load
  - Optional store-and-forward when peer temporarily absent (bounded TTL/limits)
- `Forwarding`: route frames `A <-> B`; apply fairness/backpressure
- Teardown on:
  - client close, heartbeat miss, overload policy, or explicit unbind → `Idle`

## Failure & Teardown Signals
- `RELAY_BIND_ACK{ok:false,reason}` for immediate denial
- `RELAY_NOTIFY{type:overload|peer_left|timeout}` control messages during lifecycle
- Explicit `RELAY_UNBIND{binding_id}` to close gracefully

## Alternatives Considered
- TURN-like centralized relays: rejected to preserve modular, peer-driven discovery and reduce central dependencies.
- Only hole punching: insufficient in constrained environments; relay provides consistent fallback.
- App-level relaying: rejected to keep transport responsibilities in transport layer and preserve payload opacity.

## Migration
No changes required for existing non-relay nodes. Relay functionality is opt-in per realm and activated via capabilities and config.

## Open Questions
- QUIC-based forwarding support and priority flows for control vs data.
- Pluggable buffering backends and fine-grained fairness policies.
- Error taxonomy for bind denials, path teardown, and overload signals.

## References
- Related: `docs/adr/0001-secure-channel-abstraction.md`
- Complements: Persistent peer store in `docs/adr/0002-persistent-peer-store.md`
