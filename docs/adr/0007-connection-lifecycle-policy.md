# ADR 0007: Framework-Owned Connection Lifecycle Policy

- Status: Accepted
- Date: 2026-09-01
- Target: 0.3.x
- Depends on: ADR-0005 (NAT Traversal, Hole Punching, and Connection Preference Policy)

## Context

ADR-0005 defines how the framework chooses direct, UDP, punch, and relay paths,
but route selection alone does not keep long-lived peer connections reliable on
intermittent networks. A heartbeat message type and manual reconnect command
already exist, but there is no scheduled liveness enforcement, retry pacing, or
runtime route-health feedback.

Leaving these concerns to plugins would duplicate transport logic and prevent
the framework from consistently re-evaluating routes.

## Decision

Extend the existing connection policy with framework-owned lifecycle behavior.
This is additive to `ConnectionStrategy`; it does not introduce a new strategy.

### Heartbeat and liveness

Each active peer has one asynchronous liveness monitor. The monitor sends a
tagged `HEARTBEAT` probe at `heartbeat_interval_ms`. Tagged probes and responses
are framework control traffic; existing untagged heartbeat messages retain
their existing dispatch behavior.

Any inbound peer activity refreshes the liveness deadline. If no activity is
seen within `heartbeat_timeout_ms`, active routes are marked unresponsive and
the connection is removed from active routing.

### Reconnection

Disconnected or unresponsive peers with a known TCP listening address are
retried asynchronously. Consecutive failures use exponential backoff capped by
`reconnect_max_delay_ms`, with symmetric jitter to avoid synchronized retry
bursts. A successful handshake resets the attempt sequence.

Reconnect attempt state belongs to `PeerStore`; live task ownership and route
state belong to `PeerManager`.

### Route health

The runtime tracks `Unknown`, `Healthy`, `Suspect`, or `Unresponsive` for each
peer and transport route. Inbound activity and successful delivery refresh a
route to healthy. Delivery or reconnect failures make it suspect, while a
liveness timeout makes it unresponsive.

`connect_with_policy` preserves the candidate order defined by the configured
strategy when candidates have equal health. A healthy or unknown candidate is
preferred over a suspect candidate, and unresponsive candidates are excluded.
This allows route re-evaluation without replacing the strategy state machine.

## Configuration

All fields are optional under `[network.connection_policy]`:

```toml
heartbeat_interval_ms = 30000
heartbeat_timeout_ms = 90000
reconnect_base_delay_ms = 1000
reconnect_multiplier = 2.0
reconnect_max_delay_ms = 60000
reconnect_max_attempts = 8
reconnect_jitter_ratio = 0.2
```

Existing configuration files remain valid. Invalidly small intervals are
clamped to safe positive values, the multiplier is at least `1.0`, and the
jitter ratio is constrained to `0.0..=1.0`.

## Consequences

- Long-lived connections recover without plugin-owned retry loops.
- Retry jitter reduces coordinated reconnect spikes after network disruption.
- Existing transport strategies and heartbeat consumers remain compatible.
- Health is intentionally in-memory and coarse-grained; persistence, detailed
  scoring, and transport-specific diagnostics remain separate concerns.
