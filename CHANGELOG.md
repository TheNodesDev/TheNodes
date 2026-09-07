# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-09-07

### Breaking
- **Plugin API/ABI**: `PLUGIN_ABI_VERSION` is now 3. Plugins must provide a valid, stable `Plugin::plugin_id()`, receive a plugin-bound context during dispatch, and rebuild against the matching host release.
- **Wire protocol**: `RELAY_FWD` now carries opaque bytes in the required base64 `opaque_payload_b64` field. The generic outer `Message.payload` must be `null`; mixed 0.3.x/0.4.x relay deployments are unsupported.

### Added
- Transport-agnostic fingerprint trust evaluation shared by TLS SPKI and Noise static keys, with structured decisions, allowlist, TOFU, observe, and exact SHA-256 pins.
- Noise trust configuration under `[encryption.noise.trust_policy]`, including inline fingerprints, allowlist and observed directories, and `AuthSummary` fingerprint reporting.
- Per-plugin durable data directories through `PluginContext::plugin_data_dir()`. The framework supplies isolation and location; plugins continue to own their storage engine and format.
- Optional `upnp` Cargo feature using UPnP-IGD to map the TCP listen port, publish the mapped address in HELLO metadata, and classify observed NAT behavior for diagnostics.
- ADR-0008 for shared fingerprint trust, ADR-0009 for UPnP/NAT diagnostics, and ADR-0010 for explicit relay framing.

### Changed
- TCP Noise now uses the configured persistent static key, allowing stable trust decisions across reconnects.
- Relay forwarding, retries, reliable delivery, and store-and-forward queues preserve the explicit opaque payload field verbatim.
- Noise remains intentionally opt-in; the default Cargo feature set remains empty.

### Fixed
- `encryption.enabled = false` now always selects plaintext, even when a stale explicit backend remains in configuration.
- Replaced heuristic certificate-chain checks with cryptographic WebPKI path validation against configured CA trust anchors. Validation now enforces signatures, CA/path constraints, EKU, critical extensions, name constraints, and current-time validity for the complete path when `enforce_ca_chain = true`.
- Implemented real X.509 `notBefore`/`notAfter` extraction. `reject_before_valid` and `reject_expired` now reject matching leaf certificates and fail closed when validity cannot be parsed.
- TLS policy evaluation now uses `issuer_cert_dir` for CA trust anchors (falling back to `trusted_cert_dir` for compatibility), distinguishes server- and client-auth EKU, and verifies TLS handshake signatures even when certificate acceptance is deferred to TheNodes trust policy.
- Self-signed chain overrides now require a cryptographically valid self-signature.

### Security
- CRL/OCSP processing remains unsupported. Configured CRL directories are not read and revocation status is not enforced.

## [0.3.0] - 2026-09-05

### Breaking
- **Security/API**: `make_secure_channel` now returns a `Result`. Selecting Noise without the compiled `noise` feature returns an error instead of falling back to plaintext; inbound and outbound connection paths propagate or log the failure.
- **MSRV**: Raised the minimum supported Rust version from 1.74 to 1.83 to support the existing version 4 lockfile and locked dependencies. The minimum is now declared in `Cargo.toml` and checked in CI with default and all features.
- **Plugin API/ABI**: `Plugin::on_message` and `PluginManager::dispatch_message` are now async, and `PLUGIN_ABI_VERSION` is now 2. Plugins must update `on_message` to `async fn` and rebuild before loading.
- **API**: `PluginContext` is now constructed via `PluginContext::new(...)` and carries local node identity, runtime config, console-permission state, and an async plugin-manager handle for framework-owned delivery.
- **Wire protocol**: `HELLO` now includes optional `udp_listen_addr` and `udp_observed_addr` fields for UDP transport and NAT-traversal metadata exchange.
- **Config/API**: `NetworkConfig` now includes optional `udp`, `connection_policy`, `nat_traversal`, and `delivery` sections. Manual struct initialization must populate these fields.

### Added
- Plugins can declare exact `MessageType::Extension` kind subscriptions through `Plugin::subscribed_extension_kinds`; the default continues to receive all extension kinds.
- **ADR-0004 UDP + Noise transport**
  - New UDP transport modules: `src/network/udp_session.rs` and `src/network/udp_listener.rs`.
  - TNCF control-frame handling, Noise XX UDP session management, persistent Noise static key loading, session reaping, and UDP session/path tracking in `PeerManager`.
  - Optional UDP capability advertisement plus `udp_hello_addr()` support for HELLO metadata.
  - `handle_session_frame` processes each frame without holding the UDP sessions lock across `process_incoming_message`/plugin dispatch, so a plugin replying over UDP from `on_message` (or a framework-level delivery ACK) cannot re-enter the non-reentrant sessions mutex via `send_udp` and deadlock UDP receive processing.
- **ADR-0005 connection policy and NAT traversal**
  - New `src/network/connection.rs` with `connect_with_policy`, `ConnectionPolicy`, `ConnectionStrategy`, and `ConnectionOutcome`.
  - New `src/network/nat_traversal.rs` with observed-address refresh, cookie-based observation flow, pending-observation matching, relay-coordinated punch helpers, and NAT traversal runtime state.
  - New config sections for `[network.connection_policy]` and `[network.nat_traversal]`.
  - New message types for `PUNCH_COORDINATE`, `PUNCH_INVITE`, `PUNCH_READY`, `PUNCH_GO`, and `PUNCH_ABORT`, including `attempt_id` correlation across coordinated punch flows.
- **ADR-0006 delivery semantics**
  - New `src/network/delivery.rs` with `DeliveryClass`, `DeliveryOptions`, `DeliveryOutcome`, `DeliveryFailureReason`, `DeliveryPathConstraints`, `DeliveryRuntime`, and stable UUID v7 `MessageId` generation.
  - New `DELIVERY_ACK` wire message type for framework-level hop acknowledgements.
  - `Message` now carries optional validated `DeliveryMetadata` (`message_id`, `class`, `ordering_key`, `ordering_sequence`); malformed delivery metadata is rejected at deserialization.
  - `PeerManager` now tracks delivery attempts, deduplication windows, ordered inbound buffers, relay sequencing, and stale ordered-scope eviction state.
  - Plugin host now exposes framework-owned async delivery APIs via `PluginContext::deliver_message(...)` and `PluginContext::send_message(...)`.
  - New `[network.delivery]` config section with keys: `fire_and_forget_timeout_ms`, `reliable_timeout_ms`, `ordered_reliable_timeout_ms`, `reliable_retry_budget`, `ordered_reliable_retry_budget`, `dedup_window_secs`, `ordered_max_buffered_messages`, `retry_interval_ms`.
- **ADR-0007 framework-owned connection lifecycle policy**
  - `PeerManager` now runs one asynchronous liveness monitor per active peer, sending tagged `HEARTBEAT` probes (`liveness_probe_v1`/`liveness_response_v1`) and tracking per-route `RouteHealth` (`Unknown`, `Healthy`, `Suspect`, `Unresponsive`).
  - Liveness credit and heartbeat replies require a verified sender: `process_incoming_message` only trusts `Message.from` when it matches the node_id actually bound to the connection/session the message arrived on, so a connected peer cannot forge another peer's identity to keep its liveness deadline refreshed.
  - `RouteHealth::Unresponsive` is sticky; only a subsequent successful delivery or handshake clears it, so an unrelated in-flight failure cannot resurrect an excluded route to `Suspect`.
  - Route-health and last-activity bookkeeping is bounded via age-based pruning, since `node_id` is peer-supplied and would otherwise grow unbounded as peers churn through distinct identities.
  - Disconnected or unresponsive peers with a known TCP listen address are retried automatically with exponential backoff, symmetric jitter, and a configurable attempt budget tracked in `PeerStore`.
  - `connect_with_policy` now re-evaluates candidate routes by health, preferring healthy/unknown routes over suspect ones and excluding unresponsive routes, while preserving the configured strategy's candidate order for ties.
  - New `[network.connection_policy]` keys: `heartbeat_interval_ms`, `heartbeat_timeout_ms`, `reconnect_base_delay_ms`, `reconnect_multiplier`, `reconnect_max_delay_ms`, `reconnect_max_attempts`, `reconnect_jitter_ratio`.

### Changed
- Inbound plugin dispatch now awaits each handler before continuing and skips extension messages that do not match a plugin's declared kinds.
- Runtime startup now injects delivery config into `PeerManager`, refreshes `PluginContext` with final runtime state, and starts the UDP Noise listener and NAT traversal helpers when enabled.
- Inbound and outbound transport handling now records TCP/UDP transport metadata, captures peer UDP listen and observed addresses from `HELLO`, and routes TCP, UDP, and relay-carried reliable/ordered messages through the delivery layer before plugin dispatch.
- Observed-address state now tracks observer/request metadata for pending observation flows and uses explicit correlation for relay-coordinated punch state.
- Capability advertisement is now config-driven for `udp`, `punch`, and `punch_rendezvous` in addition to existing relay capabilities.
- `uuid` dependency now enables UUID v7 generation for delivery message IDs.
- Default config wiring now includes defaults for delivery semantics and explicit support for the new UDP, connection policy, and NAT traversal config sections.
- Delivery routing now delegates normal path selection to connection policy and can initiate relay-coordinated UDP hole punching when policy selects that path.

### Fixed
- `PluginManager::dispatch_message` now bounds each plugin's `on_message` call with a timeout so a single slow or hung plugin cannot indefinitely stall dispatch to other plugins or the connection's read loop; a `plugin_dispatch_timeout` system event is emitted when the bound is hit.
- The template generator now gives NEP plugins build and deployment instructions instead of suggesting that a library crate be run directly.
- The custom-host template now uses standard-library Unix timestamps, keeping all generated dependencies within the release-seeded Rust 1.83-compatible graph.

### Docs
- Documented async plugin message handling, extension-kind subscriptions, and the decision to keep plugin storage owned by plugins rather than adding a generic core storage API.
- Added decision records:
  - `docs/adr/0004-udp-noise-transport.md`
  - `docs/adr/0005-nat-traversal-and-connection-policy.md`
  - `docs/adr/0006-delivery-semantics-and-reliability-model.md`
  - `docs/adr/0007-connection-lifecycle-policy.md`

### Tests
- Added plugin dispatch coverage proving async handlers are awaited and non-subscribed extension kinds are filtered.
- Added a regression test proving `handle_session_frame` does not deadlock when a plugin replies over UDP from `on_message`.
- Added unit and integration coverage for UDP transport, NAT traversal, connection policy, and delivery semantics via:
  - `tests/udp_transport.rs`
  - `tests/nat_traversal.rs`
  - `tests/connection_policy.rs`
  - `tests/delivery_semantics.rs`
- Added delivery-layer regression coverage for relay ACK flow, plugin-context reliable delivery, ordered buffer limits, and UDP preferred-path bidirectionality.
- Added inline unit tests in `delivery.rs` for delivery-option validation, duplicate suppression, ordered gap-fill release, and UUID v7 message ID generation.
- Added inline unit tests in `message.rs` validating delivery-metadata round-tripping and rejecting malformed ordering/sequence combinations.
- Added inline unit tests for UDP capability advertisement and `udp_hello_addr()` gating by feature flag and config.
- Added `tests/connection_lifecycle.rs` covering heartbeat liveness monitoring, automatic reconnect with backoff, route-health tracking, spoofed-sender heartbeat rejection, and sticky `Unresponsive` route health.
- Updated peer store tests to account for the expanded `NetworkConfig` shape.
- CI now tests the standalone plugin example and verifies that every generated template is formatted and builds on Rust 1.83, including a repeat build with the reconciled lockfile.


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
