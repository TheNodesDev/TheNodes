# ADR 0001: Secure Channel Abstraction (TLS today, Noise opt-in)

- Status: Accepted
- Date: 2025-12-06
- Target: 0.2.x (incremental, non-breaking)

## Context
Currently, `src/network/transport.rs` and `src/network/listener.rs` embed `rustls` directly for TLS/mTLS handshakes. Introducing another backend (e.g., Noise using `snow`) would duplicate handshake and stream wiring logic, and complicate trust/event reporting. We want a clean seam so we can:
- Support multiple security backends (TLS now; Noise later) behind one interface.
- Keep eventing (trust decisions) consistent regardless of backend.
- Compile and test incrementally, with cargo features gating optional backends.

## Decision
Introduce a trait-based secure channel abstraction that returns split async I/O plus an authentication summary; select implementation via a small factory informed by config and compile-time features.

### Key Types
```rust
pub enum SecurityBackend { Plaintext, Tls, Noise }

pub struct AuthSummary {
    pub backend: SecurityBackend,          // tls | noise | plaintext
    pub fingerprint: Option<String>,       // TLS: SPKI; Noise: static key fp (future)
    pub subject: Option<String>,           // TLS DN if parsable
    pub decision: String,                  // Accept/Reject (for events)
    pub reason: String,                    // Details for audit
    pub chain_valid: Option<bool>,         // TLS-only
    pub time_valid: Option<bool>,          // TLS-only
}

pub struct Channel {
    pub reader: Box<dyn tokio::io::AsyncBufRead + Send + Unpin>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    pub auth: AuthSummary,
}

#[async_trait::async_trait]
pub trait SecureChannel: Send + Sync {
    async fn connect(
        &self,
        stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> anyhow::Result<Channel>;

    async fn accept(
        &self,
        stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
        realm: &crate::realms::RealmInfo,
        config: &crate::config::Config,
        allow_console: bool,
    ) -> anyhow::Result<Channel>;
}
```

Implementations:
- `TlsSecureChannel`: wraps `rustls` TLS/mTLS logic, deriving `AuthSummary` via `evaluate_peer_cert_chain` and emitting trust decision events.
- `NoiseSecureChannel` (feature `noise`): uses `snow` (XX) with u16 length-prefixed encrypted frames and handshake timeouts; `chain_valid/time_valid=None`. Fingerprint emission for noise static keys is deferred.
- `PlaintextChannel`: used when `encryption.enabled = false` for development.

Factory:
```rust
pub fn make_secure_channel(cfg: &crate::config::Config) -> Box<dyn SecureChannel> { /* select by cfg + features */ }
```

Config addition (non-breaking default):
```toml
[encryption]
enabled = true
backend = "tls"  # tls | noise | plaintext (plaintext implied if enabled=false)
```
If `backend = "noise"` but the `noise` feature is not compiled, we fall back to `plaintext` (documented behavior) and may log a warning.

Events/Trust:
- TLS: unchanged trust decision events (SPKI, pins, realm binding, chain/time flags).
- Noise: emit acceptance metadata in `AuthSummary`; full trust/pinning is future work.

## Alternatives Considered
- Long-lived feature branch with invasive refactor later: high merge risk and delayed feedback.
- Duplicating TLS logic for Noise: code drift and inconsistent events.
- Single enum in transport without a trait: harder to test/multibackend injection; tighter coupling to transport.

## Consequences
- Positive: Clear seam for TLS/Noise/Plaintext; simpler testing (mockable); consistent observability.
- Neutral: Small increase in indirection; minor config surface (`backend`).
- Negative/Risks: Event duplication or drift if split across layers; mitigated by centralizing event emission in backend adapters.

## Implementation Summary
Delivered across incremental changes:
1) Added `SecureChannel` trait, `Channel`, `AuthSummary`, and `make_secure_channel` under `src/security/secure_channel.rs`.
2) Implemented `TlsSecureChannel` by lifting existing handshake code; trust evaluation and events intact.
3) Wired `transport` and `listener` to use the factory and returned `Channel` (no behavior change initially).
4) Added optional `backend` config key; default remains TLS when `encryption.enabled=true`, plaintext when disabled.
5) Implemented `NoiseSecureChannel` under `--features noise` with real XX handshake, encrypted framing, and timeouts; reader/writer wrappers.
6) Hardened framing (reject zero-length), added handshake timeouts, and broadened tests.

## Testing
- Unit: factory selection; `PlaintextChannel` smoke.
- Integration: TLS handshake via trait; Noise roundtrip; large/fragmented/oversized payloads; ordered multi-frame; deterministic negative handshake; fuzz-lite randomized.
- CI: clippy/fmt/tests; optional matrix for Noise feature toggling.

## Decision Drivers
- Backward-compatible, observable, incremental delivery.
- Minimize touching message/realm logic; contain change to handshake + stream setup.

## Open Questions
- Noise key fingerprint emission and pinning semantics.
- Consolidation of transport vs encryption config; defer to future ADR.

## References
- Tracking issue template: `.github/ISSUE_TEMPLATE/secure-channel-abstraction.md`
- Prior discussion (superseded by this ADR): RFC-0001 in repo history.
