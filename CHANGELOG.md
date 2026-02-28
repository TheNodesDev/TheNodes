# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/) once the first public release is cut.

## [Unreleased]


## [0.2.0] - 2026-02-28

### Breaking
- **Wire protocol**: All message type tokens now use SCREAMING_SNAKE_CASE (e.g., `PEER_REQUEST`, `RELAY_BIND`). Nodes running pre-0.2 wire format cannot interoperate with 0.2+.
- **Wire protocol**: `Reason` enum values serialize as snake_case (`policy_denied`, `timeout`, etc.).
- **Wire protocol**: `HELLO` message now includes optional `capabilities` field for peer metadata exchange.
- **API**: `start_listener()` now requires an additional `emit_console_errors: bool` argument.
- **API**: `run_prompt_mode()` signature changed to `(plugin_manager, config)` (two arguments).
- **API**: `connect_to_peer()` now takes a `ConnectToPeerParams` struct instead of positional arguments.
- **Behavior**: `send_to_addr` and `send_to_node_id` switched from blocking `.send().await` to non-blocking `try_send()` to prevent channel backpressure hangs.

### Added
- **ADR-0003 Relay Nodes: Core implementation complete**
  - `RELAY_BIND` request with target, want_store_forward, qos, nonce, expires_at fields.
  - `RELAY_BIND_ACK` response with ok, reason, binding_id, peer_present, nonce fields.
  - `RELAY_FWD` opaque forwarding frame with to, from, sequence fields.
  - `RELAY_UNBIND` explicit teardown with binding_id.
  - `RELAY_NOTIFY` lifecycle notifications (overload, timeout, peer_left).
- Relay QoS behaviors:
  - `low_latency`: bypass store-and-forward enqueue entirely.
  - `high_throughput`: priority enqueue at front for faster draining.
  - `bulk`: enqueue at back with soft-drop when per-target cap is reached.
  - `reliable`: ACK-based delivery with delayed retry (~500ms) cancelled by ACK.
- Reliable QoS scaffolding:
  - New wire token `ACK` with `to/from/sequence/status` for hop-level delivery acknowledgements.
  - In-flight tracking keyed by `(from, to, sequence)` with single delayed retry.
- Deterministic relay selection via Rendezvous (HRW) hashing with capability gating.
- Store-and-forward with per-target (1024) and global (8192) queue caps; TTL-based expiry.
- Origin-aware notifications: overload purges and TTL expiry notify the originating peer.
- Relay helper APIs and builders (`RelayBindBuilder`, `RelayForwardBuilder`).
- **ADR-0002 Persistent Peer Store: Core implementation complete**
  - `PeerStore` with in-memory store plus optional file persistence (`peers.json`).
  - `PeerRecord` entries with `addr`, `source` (Bootstrap/Handshake/Gossip/Manual), `failures`, `last_success_epoch`, `node_id`, `capabilities`.
  - Persistence APIs: `load_from_file` with TTL expiry and max-entry cap; `save_to_file` with LRU-sorted JSON output.
  - Periodic background flush via `spawn_periodic_save(path, interval_secs)`.
  - Config-driven initialization: `from_config(cfg)` reads `[network.persistence]` section and auto-starts periodic saves.
  - Metadata capture on handshake: transport wiring calls `mark_success_with_meta(addr, node_id, capabilities)` after successful HELLO exchange.
- Config keys for `[network.persistence]`: `enabled`, `path`, `max_entries`, `ttl_secs`, `save_interval_secs`.
- **ADR-0001 Secure Channel Abstraction: Core implementation complete**
  - Trait-based `SecureChannel` abstraction with `connect()` and `accept()` methods returning split async I/O plus `AuthSummary`.
  - `AuthSummary` struct capturing backend type, fingerprint, subject, decision, reason, and optional chain/time validity.
  - `Channel` struct with boxed async reader/writer and auth metadata.
  - Factory function `make_secure_channel(cfg)` selects implementation based on config and compile-time features.
  - Three backend implementations:
    - `TlsSecureChannel`: wraps existing rustls TLS/mTLS logic with full trust evaluation and event emission.
    - `NoiseSecureChannel` (feature-gated under `noise`): XX handshake via `snow` crate with 25519/ChaChaPoly/BLAKE2s, u16 length-prefixed framing, and handshake timeouts.
    - `PlaintextChannel`: used when `encryption.enabled = false` for development.
  - Config key `encryption.backend` to select backend: `tls` (default), `noise`, or `none`.
  - Optional `[encryption.noise]` section for pattern, curve, cipher, hash, and static key path.
  - Fallback behavior: if `backend = "noise"` but feature not compiled, falls back to plaintext with warning.
- Security module now explicitly exports secure-channel APIs via `src/security/mod.rs`.

### Changed
- Unified wire tokens to screaming snake case for all message types:
  - `HELLO`, `TEXT`, `PEER_REQUEST`, `PEER_LIST`, `DATA_REQUEST`, `DATA_RESPONSE`, `HEARTBEAT`, `DISCONNECT`, `EXTENSION`.
  - Relay tokens: `RELAY_BIND`, `RELAY_BIND_ACK`, `RELAY_FWD`, `RELAY_UNBIND`, `RELAY_NOTIFY`, `ACK`.
- Standardized denial/notification reasons via `Reason` enum (snake_case on wire):
  - `policy_denied`, `timeout`, `already_bound`, `unknown_target`, `overload`, `peer_left`.
  - Both `RelayBindAck.reason` and `RelayNotify.notif_type` now use `Reason` enum.
- Switched `send_to_addr` and `send_to_node_id` from blocking `.send().await` to non-blocking `try_send()` to prevent channel backpressure hangs.
- Runtime networking now uses the SecureChannel factory path in both outbound transport and inbound listener handshakes, removing duplicated inline handshake setup paths.
- Startup now initializes `PeerStore` from final merged config (`PeerStore::from_config`) and updates plugin context to use that runtime-configured store.
- Relay store-and-forward queue caps are now runtime-configurable via `network.relay.queue_max_per_target` and `network.relay.queue_max_global` (with safe defaults preserved).
- HELLO capability advertisement is now centralized and consistently config-driven across listener, outbound transport, and handshake-only transport paths.

### Fixed
- Resolved async hang in `enqueue_store_forward`: removed `.await` calls while holding `relay_queue` mutex; notifications now sent after releasing lock.
- Discovery periodic task now sends real `PEER_REQUEST` messages (replacing placeholder behavior).
- `PEER_REQUEST` handling now sends actual `PEER_LIST` responses instead of constructing placeholders only.
- Templates (production/hybrid-app): align to current public APIs so newly scaffolded apps build cleanly.
	- listener: add the new `emit_console_errors: bool` argument to `start_listener(…)`.
	- bootstrap: pass `allow_console` based on prompt mode (`!args.prompt`).
	- prompt: update to `run_prompt_mode(plugin_manager, config)` two-argument signature.
- Generator: ensure template files are fully materialized in new apps.
	- Always rename `Cargo.toml.template` → `Cargo.toml` and `*.rs.tmpl` → `*.rs` (removed fragile glob checks).

### Tests
- New integration tests for relay functionality: `relay_notify.rs` (overload notification), `relay_store_forward.rs` (delivery, expiry, per-target/global caps).

## [0.1.0] - 2025-10-28

### Added
- Core async-first P2P framework with plugin host, supporting both NEP (Node-Embedded Plugins) and CAL (Core-as-a-Library) modes.
- Networking components: peer manager, listener, protocol, with dynamic peer discovery (PeerRequest/PeerList) gated by config.
- Realm abstraction for logical network segmentation and compatibility.
- Optional TLS (rustls) with trust policy modes: open, allowlist, observe, and TOFU; mTLS flag.
- Pin-based trust controls: subject/fingerprint pinning and realm-subject binding.
- Trust promotion helper and prompt commands (e.g., `trust observed list`, `trust promote <fingerprint>`).
- Background reconnect after promotion to apply trust changes without manual intervention.
- Event system with structured System/Trust events and JSONL audit sink.
- Plugin-supplied configuration defaults (including `bootstrap_nodes_extend` append semantics).
- Example plugins and apps: `examples/kvstore_plugin` and `examples/simple_node.rs`.
- Template scaffolding hardened to avoid IDE/indexing noise: manifests use `Cargo.toml.template` and Rust sources `*.rs.tmpl`, restored by the generator when scaffolding projects.
- Strict ASCII kebab-case transliteration utility: Latin-only transliteration with `ü/Ü → ue`, non‑Latin treated as separators, and collapsed/truncated separators.

### Docs
- Plugin authoring guide updated to current APIs (MSRV 1.74, crate-type under `[lib]`, prompt usage, async-trait note).
- Security/trust plan updated to reflect current status: Phase 1 complete; Phase 2 scaffolding (chain/time); Phase 3 pinning & promotion delivered; audit logging available.

### Build
- Tooling: added `rust-toolchain.toml` (MSRV 1.74).
- CI: relaxed Clippy policy (deny correctness/perf; warn style/complexity), formatting check, and full workspace build/test.

### Security
- Trust policy enhancements and auditability: pinning, realm binding, promotion UX, and structured JSONL trust audit sink.

---
Guidelines for future entries:
- Group entries under Added / Changed / Fixed / Security / Deprecated / Removed / Performance / Docs as applicable.
- Link issues or PR numbers once the repository is public.
