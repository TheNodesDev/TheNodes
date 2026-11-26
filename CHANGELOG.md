# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Breaking
- **Plugin API/ABI**: `PLUGIN_ABI_VERSION` is now 4. Native libraries must export `thenodes_plugin_abi_version` and an ABI 4 `register_plugin`, normally generated with `thenodes::export_plugin!`; ABI 3 libraries are rejected before any of their plugin code runs. `PluginRegistrarApi::register_plugin`, `PluginHandle`, and `load_plugins_from_dir` were removed. See `docs/PLUGIN_ABI_4_MIGRATION.md`.
- **Plugin host API**: `PluginManager::dispatch_message` is synchronous admission and returns a `DispatchReport` instead of awaiting plugin handlers. `PluginRegistrar::register_handler` returns `Result<(), PluginRegistrationError>`. `PluginLoader::load_plugins` takes `&mut PluginManager` and returns typed `PluginLoadError`s. `get_prompt_plugin` was replaced by `resolve_prompt` and `dispatch_prompt`.
- **Plugin context**: the public `peer_manager` and `peer_store` fields were replaced by `peer_manager()` and `peer_store()` accessors that return `None` in native plugin contexts. `PluginContext::set_plugin_manager` was removed; the manager installs a weak reference when startup begins. Context sends from a context without host services return `DeliveryFailureReason::Unavailable` instead of `PolicyDenied`.
- **Events**: `EventHandle::register_sink` returns `Result<(), SinkRegistrationError>` and refuses sinks from native plugin contexts.
- **Registration**: two plugins supplying different early configuration defaults for the same single-valued field, or the same prompt prefix, now fail registration instead of the last plugin winning.
- **Node identity binding** (ADR-0012): a HELLO `node_id` must now match the TLS certificate key or Noise static key that authenticated the connection. The default `[encryption.node_identity]` mode is `tofu`, so a node that changes its key without a CA-certified node name is rejected until its binding is forgotten; set `mode = "off"` for the previous behaviour. HELLO and Noise handshake node IDs must be 1-128 ASCII letters, digits, `-`, `_` or `.`. In `tofu` mode a connection without a transport identity cannot use a node ID that is already bound to a key (`node-binding-requires-identity`); with TLS but without mTLS, a node this node has dialled cannot connect back inbound until `mtls` is enabled. A full binding store (`max_bindings`) rejects node IDs seen for the first time (`node-binding-store-full`). CA-managed deployments whose certificates lack a `URI:node://<realm>/<node_id>` SAN are bound by TOFU, so a rotated key is rejected until the certificate is reissued with `thenodes-cert --realm-code <code> --node-id <id>` or the binding is forgotten. A connection's binding is recorded before the peer is registered, and a binding that can no longer be recorded at that point (another connection bound the node ID meanwhile, or the store filled up) refuses the connection (`peer_reject_node_identity`, `udp_session_identity_rejected`).
- **Frame addressing** (ADR-0012): `from` and `to` on the wire are always node IDs: the node that sent the frame and the peer it was sent to. The connection's writer (and the UDP send path) stamps both on every frame, replacing the socket addresses, `"TheNodes"` and `"thenodes"` labels earlier versions wrote. A received frame whose `from` is not the node bound to the connection or session, or whose `to` is not the local node, is dropped with a `message_rejected` event. HELLO follows the same rule: `from` is its `node_id`, and the accepting side's HELLO, sent before it knows who connected, has an empty `to`; a mismatch closes the connection with `peer_reject_hello_addressing`. Nodes from earlier versions cannot connect.
- **Relay tunnels**: a `RELAY_FWD` addressed to the local node is unwrapped only for `TEXT`, `DATA_REQUEST`, `DATA_RESPONSE`, `EXTENSION` and `DELIVERY_ACK` messages whose `from`/`to` match the tunnel; other tunnels, including nested ones, are dropped with a `message_rejected` event.
- **Relay forwarding** (ADR-0012): a relay forwards a `RELAY_FWD` only for a live binding its sending peer created, and only when the frame's `from` field names that peer; other frames are refused with `RELAY_NOTIFY` (`policy_denied`, or `timeout` for an expired binding) and a `relay_forward_rejected` event. An expired binding can be re-bound. Relays no longer forward to other relays: `[network.relay].selection` was removed, and a config that still sets it is rejected. Binding IDs are random (`bind:<hex>`), `RELAY_UNBIND` removes only the sender's own binding, and a hop `ACK` counts only from the forwarded frame's target (`relay_ack_rejected`).
- **Delivery acknowledgements**: a `DELIVERY_ACK` counts only from the node the message was sent to (`delivery_ack_rejected` otherwise). A reliable message that arrived through a relay is acknowledged through that relay instead of the first relay the node knows, and a sender the node cannot reach directly or through the delivering relay gets no acknowledgement. `DeliveryRuntime::deliver_message` sends with `from` set to the local node.
- **Peer addresses** (ADR-0012): the listen address in HELLO is a claim. Only addresses this node dialled and reached the node at suppress bootstrap dials, drive reconnects, and are persisted, so a node no longer redials a peer that connected to it. HELLO details (listen address, capabilities, UDP addresses) and a relay client's bindings, sequences and in-flight forwards are dropped when the peer disconnects; the `RELAY_NOTIFY peer_left` previously sent to the closed connection is gone. The UDP listen and observed addresses in HELLO are kept only if they are no more local than the connection, the rule gossip follows (`hello_udp_addr_rejected`), so a peer can no longer make a node send observation requests, handshakes or probes to its loopback or private network.
- **Realms**: a node dialling another node refuses a server whose HELLO names another realm or none (`realm_mismatch`, `realm_missing`), as it already refused such clients.
- **Gossip and peer store**: a `PEER_LIST` adds at most 64 addresses, each no more local than the peer that sent it, as unverified candidates (they are no longer marked successful); `PEER_REQUEST` answers contain only addresses this node has connected to. `[network.persistence].max_entries` applies at runtime, dropping never-reached candidates first.
- **Delivery limits**: duplicate suppression is capped per origin and in total, and out-of-order `OrderedReliable` messages per origin and in total by ordering keys and bytes. An ordered message that cannot be buffered is no longer acknowledged and then dropped; it is left unacknowledged for the sender to retry (`ordered_delivery_deferred`). A relay client may hold 64 bindings (`MAX_BINDINGS_PER_CLIENT`), and a reliable relay forward's in-flight entry is released after its single retry. A `message_id` is at most 128 bytes and an `ordering_key` at most 256 (`delivery::MAX_MESSAGE_ID_LEN`, `MAX_ORDERING_KEY_LEN`); a received message that exceeds them is dropped, and building or sending one fails validation.
- **UDP sessions** (ADR-0013): session frames carry an explicit 8-byte nonce (`[session_id][nonce][ciphertext]`) and `HANDSHAKE_MSG1` carries a cookie field (`[session_id][cookie_len][cookie][msg1]`), so UDP sessions cannot be established with earlier versions. `MAX_APP_PAYLOAD_BYTES` and the `[network.udp].max_app_payload_bytes` default drop from 1176 to 1168. `NoiseUdpSession::encrypt` writes `[nonce][ciphertext]`, and `decrypt` reads it and returns `SessionFrameError`.
- **Configuration is fail-closed**: a config key TheNodes does not define is an error, so a misspelt section or setting (for example `[encryption] enable = true`) stops startup instead of being ignored; this also applies to removed settings such as `[network.relay].selection`. The standalone host refuses to start when its config file cannot be read, unless `--allow-default-config` is given. Security settings accept only the values TheNodes knows, ignoring ASCII case: `[encryption] backend`, the TLS and Noise trust `mode`, `pin_fp_algo` (`sha256`), `[encryption.node_identity] mode`, and the fixed Noise suite settings `pattern` (`XX`), `curve` (`25519`), `cipher` (`ChaChaPoly`) and `hash` (`BLAKE2s`). An unknown trust mode used to mean `open`. In a config built in code, an unknown backend is now an error instead of TLS or plaintext, and an unknown trust mode trusts only the allowlist.
- **TLS configuration** (ADR-0016): TLS settings moved to their own section, as Noise's already were: `[encryption] mtls` is `[encryption.tls] mtls`, `[encryption.paths]` is `[encryption.tls.paths]`, and `[encryption.trust_policy]` is `[encryption.tls.trust_policy]`. `[encryption] accept_self_signed`, deprecated and never read, is removed (use `[encryption.tls.trust_policy] accept_self_signed`). There are no aliases: a 0.4 configuration fails to load, and the error names where each setting went. Library: `EncryptionConfig` has `tls: Option<EncryptionTlsConfig>` instead of `mtls`, `accept_self_signed`, `paths` and `trust_policy`; `EncryptionPaths` and `TrustPolicyConfig` are now `TlsPaths` and `TlsTrustPolicyConfig`; `EffectiveTrustPolicy::from_config` is `from_tls_config`. New: `Config::from_toml_str`, `Config::tls`.
- **Plugin libraries** (Unix): `PluginLoader` refuses a library that another user could have written or replaced (`PluginLoadError::UnsafePath`). The library and every directory above it, after resolving symlinks, must be owned by the node's user or root and not writable by other users; group write is accepted for the owner's private group unless the entry has a POSIX ACL (on Linux), and directories with the sticky bit may be writable by others. The library is loaded from its resolved path.
- **Certificate revocation** (ADR-0014): with `enforce_ca_chain = true`, peer chains are checked against the CRLs in `trusted_crl_dir` and `issuer_crl_dir`, which were previously never read; a revoked certificate is rejected with `certificate-revoked`, and an unreadable or invalid CRL rejects the chain. The host refuses to start when CRL directories are set without `enforce_ca_chain` and the TLS backend, or when a CRL cannot be read. The shipped example configs no longer set them.
- **Certificate store and TOFU** (ADR-0016): the TLS and Noise key stores have the same layout: `own`, `trusted`, `issuers` and `rejected`.
  - In every mode, a key the trust policy rejects is kept in `rejected_dir` (`[encryption.tls.paths]`, `[encryption.noise.paths]`) when it is set, and `trust promote <fingerprint>` (prompt) or `thenodes-ctl trust promote` moves it to the trusted directory; `trust observed list` / `thenodes-ctl trust observed-list` became `trust rejected list` / `trust rejected-list`, and both list TLS and Noise keys. `observe` requires `rejected_dir`.
  - `tofu` no longer keeps identity bindings. It accepts a trusted key, and a new key once, adding it to `trusted_cert_dir` (TLS) or `trusted_dir` (Noise) after the connection's node identity binding is recorded and before the peer is registered; a key that cannot be written refuses the connection (`tofu_trust_unwritable`). Which node ID a key may use is the node identity binding's decision (ADR-0012), so `tofu` requires a trusted directory and refuses to start with `[encryption.node_identity] mode = "off"`. A `CA:true` certificate is never trusted on first use (`tofu-ca-certificate`). Nothing a node observes, rejects or accepts in another mode becomes trusted when it switches to `tofu`.
  - TOFU bindings from 0.4 (`observed_dir/bindings/`) are not read; keys are trusted again on their first connection after the upgrade.
  - `enforce_ca_chain` validates chains only against `issuer_cert_dir`, which it now requires; `trusted_cert_dir` is no longer a fallback trust-anchor store. Move CA certificates used as anchors to `issuer_cert_dir`.
  - Removed: `observed_dir`, `store_new` (`store_new_certs` for TLS), and the trust policies' `paths` sections (`[encryption.trust_policy.paths]` and `[encryption.noise.trust_policy.paths]`); Noise's `allowlist_dir` is `[encryption.noise.paths] trusted_dir`, and `[encryption.noise] static_key_path` is `[encryption.noise.paths] static_key`. The PKI subfolder `observed` in STABILITY.md is replaced by `rejected`.
  - Library: `EffectiveTrustPolicy` has `trusted_dir` and `rejected_dir` instead of `store_new` and `observed_dir`; `StoreNew` is removed; `TrustDecision` gained `pending_trust` (`PendingTrust`) and `AuthSummary` gained `pending_trust`; `FingerprintTrustInput` has `artifact` (`KeyArtifact`, formerly `ObservedArtifact`) and `is_ca_certificate` instead of `identity` and `observed_artifact`; `evaluate_peer_cert_chain_for_usage` takes the trust-anchor directory only (trusted and rejected directories come from the policy); `promote_observed_to_trusted`, `store_observed_artifact`, `store_observed_cert`, `ensure_observed_dir`, and the `*_observed_fingerprint_binding` functions are replaced by `promote_rejected_to_trusted`, `store_key`, `KeyStore`, `key_stores`, `list_key_files`, `check_trust_config` and `MAX_STORED_KEYS`; `EncryptionNoiseConfig` has `paths: Option<NoisePaths>` and `static_key_path()` instead of the `static_key_path` field.
- **Noise static key**: a key file that is not a 64-byte key now stops the node instead of being replaced by a new key, which was a new and unbound identity.
- **Hole punching** (ADR-0015): a node follows a `PUNCH_GO` only for a punch it requested or an invitation it accepted, from that punch's rendezvous, and before the punch's deadline (at most 30 seconds); a rendezvous hands out a peer's UDP address only if that address answered one of its cookie-verified observation requests. Peers must therefore observe through the rendezvous they punch through. Attempt IDs are at most 128 bytes (`MAX_ATTEMPT_ID_LEN`). A rendezvous coordinates at most 1024 punches at once, 16 per initiator, each only for its time budget (at most 30 seconds); it refuses an attempt ID already in use (`PUNCH_ABORT` with reason `overload`, `punch_coordinate_refused`), and only the invited responder's `PUNCH_READY` settles an attempt.
- **Realm binding**: `realm_subject_binding` (`[encryption.trust_policy]` in 0.4), which only checked that the certificate subject contained the realm name, is replaced by `[encryption.tls.trust_policy] require_realm_node_name`, which requires the leaf certificate to name a node in this node's realm with a `URI:node://<realm>/<node_id>` SAN (`realm-node-name-missing`). A config that still sets `realm_subject_binding` fails to load, and the error names the replacement. Library: the field is `require_realm_node_name` in `TlsTrustPolicyConfig` and `EffectiveTrustPolicy`.
- **thenodes-cert**: `--realm`, which took the realm name, and the realm DNS SAN it added are removed. `--node-id` requires `--realm-code`, the realm's canonical code.
- **Library API**: `process_incoming_message` takes a `MessageOrigin` instead of `Option<&str>`, and `unwrap_tunneled_message` was replaced by `attribute_incoming_message`. `PeerManager::send_to_node_id`, `send_to_addr`, `broadcast` and `send_udp_message_to_node` take a `Message` instead of serialized JSON, `add_peer` and the `get_sender_by_*` accessors use `Sender<Message>`, and `set_udp_handle` takes the local node ID. `Message::outbound` builds a message whose `from` and `to` the transport sets. `relay::handle_forward` and `transport::receive_and_dispatch` no longer take `relay_selection_enabled`, `PeerManager::remove_binding_by_id` takes the requesting owner, and `PeerManager::record_delivery_attempt` takes the destination node. `PeerManager::accept_ordered_incoming` returns `Result`, `PeerManager::delivery_seen`, `set_verified_listen_addr`, `verified_listen_addr_for` and `binding_count_from` were added, `add_listen_addr` records only a claimed address, and `PeerStore::with_max_entries` and `peer_store::gossip_addr_allowed` were added. `Message` has a private field, so it can no longer be built with a struct literal outside the crate; use `Message::new`. `AuthSummary` gained `node_names` and `node_names_certified`, and `EncryptionConfig` gained `node_identity`. `validate_certificate_chain` takes the CRL directories, and `EffectiveTrustPolicy` gained `crl_dirs`; `security::encryption::load_revocation_lists` and `check_revocation_config`, `TlsPaths::crl_dirs`, `Config::bind_ip` and `NetworkConfig::bind_ip` were added. `NatState` gained `observed_sources` (`ObservedSources`), `nat_traversal::execute_punch_window` takes the punch's deadline, `PeerManager::handle_punch_go_msg` takes the rendezvous node and address, and `PeerManager::expect_punch`, `take_expected_punch` and `ExpectedPunch` were added. `network::bind_listener_on` binds a given address; `start_listener` binds `Config::bind_ip`. `PluginLoadError` gained `UnsafePath`. `PeerManager::add_pending_punch` returns whether the punch was recorded, `PendingPunch` gained `expires_at`, and `PeerManager::take_pending_punch`, `record_hello_udp_addrs`, `peer_manager::MAX_ATTEMPT_ID_LEN`, `NoiseUdpSession::is_usable`, `delivery::MAX_MESSAGE_ID_LEN` and `MAX_ORDERING_KEY_LEN` were added. `TrustMode::from_str` fails for unknown values instead of returning `Open`. `RelayConfig` gained `allowed_relays`, and `NatTraversalConfig` and `NatState` gained `allowed_rendezvous`.
- **Broadcast**: `PeerManager::broadcast` (and plugin broadcasts) queue with `try_send`; a peer whose outbound queue is full misses the message and a `broadcast_send_failed` event is emitted instead of the call waiting.

### Added
- `[encryption.node_identity]` with `off`, `tofu`, `pinned` and `certificate` modes, explicit `pins`, a persistent `bindings_file`, and `max_bindings`; `security::node_identity` (`NodeIdentityRegistry`, `NodeIdentityPolicy`, `PresentedIdentity`); `PeerManager::node_identity`. An invalid section stops the standalone host at startup.
- `Message::origin()` and `MessageOrigin` (`peer`, `peer_fingerprint`, `relayed_from`, `authenticated_sender()`), so plugins can authorise on the node bound to the delivering connection.
- `thenodes-cert --realm-code <code> --node-id <id>` adds a `URI:node://<code>/<id>` SAN naming the node in its realm, and `thenodes-ctl node-binding list|forget <node_id>` manages persisted bindings.
- Plugin lifecycle: `Plugin::on_start`, `Plugin::on_stop`, and `Plugin::max_managed_tasks`; `PluginManager::start_all`, `acknowledge_failure`, `activate`, `begin_shutdown`/`shutdown` with drain or discard, `escalate`, and `subscribe_failures`; typed `StartReport`, `ShutdownReport`, `PluginFailure`, and per-plugin states. Repeated or concurrent lifecycle calls join the same transition, and a dropped waiter does not abandon it. ADR-0011 documents the contract.
- Native plugin runtime: each loaded library runs its handlers' callbacks and managed tasks on its own Tokio runtime, created at startup and released without blocking at shutdown. Handlers cross the boundary as a synchronous endpoint; no future crosses it, and plugin panics are caught in the plugin's code copy and reported as plugin failures.
- Host services for plugin contexts: `deliver_message`, `send_message`, `broadcast`, `connected_peer_ids`, and event submission run in host code on the host runtime with lifecycle checks. Native plugin events now reach the host's event dispatcher.
- Managed background tasks via `PluginContext::spawn_task`, with a per-plugin limit, `TaskContext::activated`/`cancelled`, and `TaskHandle::join`.
- Per-plugin bounded FIFO inboxes and bounded prompt admission, configured through `PluginHostOptions`, with explicit `Rejection` outcomes (`NotReady`, `Overloaded`, `Stopping`, `Unavailable`) and aggregated `plugin_admission_rejected` events.
- `DeliveryFailureReason::NotReady`, `Stopping`, and `Unavailable` for lifecycle refusals of plugin sends.
- Structured lifecycle events: `plugin_starting`, `plugin_started`, `plugin_start_failed`, `plugin_waiting`, `plugin_stopping`, `plugin_stopped`, `plugin_stop_failed`, `plugin_failed`, `plugin_task_failed`, `plugin_failed_to_quiesce`, and `plugin_send_failed`. They carry categories and timings, not error text or payloads.
- `network::bind_listener` and `network::run_listener`, so hosts observe TCP bind failures before activating plugins.
- `[network] bind_ip` selects the address the TCP and UDP listeners bind to (every IPv4 interface by default).
- `[network.relay] allowed_relays` and `[network.nat_traversal] allowed_rendezvous` list the node IDs this node may use as relays and as rendezvous. Unset, any peer that announces the `relay` or `punch_rendezvous` capability may be chosen, as before; an empty list allows none. `Config::relay_allowed`, `Config::rendezvous_allowed`, `NatTraversalConfig::rendezvous_allowed`, `NatState::rendezvous_allowed` and `PeerManager::rendezvous_allowed` were added.
- `--allow-default-config` runs the standalone host with the built-in defaults when its config file is missing.
- CRL checking for CA-validated TLS chains (ADR-0014), with chain reasons `certificate-revoked`, `crl-dir-unreadable`, `crl-invalid:<error>` and `crl-signature-invalid`, and a `crl_outdated` warning at startup for a CRL past its nextUpdate.
- `NativeRegistrar::set_runtime_workers`, `PluginLoader::discover` (sorted library paths), `PluginLoader::load_library`, and `pinned_library_count`.
- Lifecycle integration tests that build and load real native fixtures with the host's toolchain, lockfile, and features, run native scenarios in child processes, and exercise the standalone host including signal escalation.

### Changed
- The standalone `thenodes` host loads libraries in sorted order, starts plugins, binds its listener, and only then activates plugins and connects to bootstrap peers. Every plugin is required: a load or start failure stops startup (including a failure of an already started plugin while later plugins are still starting), any later plugin failure shuts the node down, and both exit with status 1. Ctrl+C, prompt exit, and failures share one cleanup path; a second SIGINT or SIGTERM escalates. A configured UDP transport that fails to start now fails startup.
- Loaded native libraries are pinned for the life of the process on every success and error path, replacing `mem::forget` at the end of `main`.
- The interactive prompt dispatches through the plugin manager on every call; a retained prompt selection cannot reach a stopping or failed plugin.
- `examples/kvstore_plugin` and the native test fixtures are workspace members so they share the host's `Cargo.lock`; the example's separate lockfile was removed. The example and the NEP plugin template forward the `noise` and `upnp` features.
- `examples/simple_node.rs` and the CAL, hybrid, custom-host, and NEP plugin templates use the explicit lifecycle and managed tasks.
- Unsupported signature algorithms now report the chain reasons `unsupported-signature-algorithm` and `unsupported-signature-algorithm-for-public-key` instead of `certificate-path-invalid:<webpki error>`. An empty extended key usage extension reports `certificate-der-invalid`.

### Removed
- The five-second plugin dispatch timeout and its `plugin_dispatch_timeout` event. TheNodes imposes no time limit on plugin dispatch, prompts, startup, or shutdown; hosts apply their own through shutdown and escalation.

### Fixed
- Noise over TCP no longer stalls or duplicates data under backpressure. A partially written frame made the writer return `Pending` without a wakeup, so the connection's writer could hang for good, and a write retried after `Pending` sent its frame twice; flushing did not write the buffered frame. The reader no longer reports end of stream for a frame with an empty payload, and a stream that ends inside a frame is an `UnexpectedEof` error.
- Connection writers flush after every frame and after HELLO, so a frame that TLS or Noise buffered no longer waits for the next frame to go out.
- The liveness monitor no longer drops a peer on its first tick after this node itself stalled for longer than the heartbeat timeout: a peer is declared unresponsive only after it has been silent for the timeout and left the probes sent meanwhile unanswered, and missed ticks no longer fire in a burst.
- The peer store file is replaced instead of rewritten in place: a save writes a temporary file in the same directory, syncs it and renames it over the old one. An interrupted save no longer leaves an empty or truncated file, which the next start loaded as an empty peer store.
- Store-and-forward frames queued for a node are no longer dropped when it connects and they do not fit in its connection's channel (32 frames). A frame leaves the queue only when the channel has room for it, and frames still queued when the connection closes wait for the next one.
- `thenodes-cert --cn` sets the certificate's subject CN; it was parsed and ignored, so every certificate had the generator's default subject. The CN defaults to the node ID given with `--node-id`, otherwise `thenodes-<unix_ts>`.

### Security
- Node IDs are bound to transport identities: a peer that passes the trust policy can no longer take over a pinned, CA-certified or previously bound node ID over TCP, and a UDP Noise session with another key no longer replaces a node's UDP route. Rejections emit `peer_reject_node_identity` and `udp_session_identity_rejected`; recorded bindings emit `node_binding_recorded`.
- A peer can no longer claim another node's ID in `from`: frames whose `from` does not match the node bound to the connection are dropped, so plugins, delivery acknowledgements, ordering and relay bindings all see the delivering node. Relay tunnels can no longer inject control messages such as `PEER_LIST`, `PUNCH_GO` or relay signalling into a node.
- `PeerManager::broadcast` no longer holds the peer table lock while waiting on a peer, so one peer that stops reading cannot freeze the node.
- Relays are no longer an open proxy: forwarding requires the sender's own binding and names the sender as origin, so a tunnel's origin is checked by the relay, a peer cannot fill another node's store-and-forward queue or trigger notifications to it, and frames cannot loop between relays. Delivery receipts, hop acknowledgements and relay unbinds can no longer be forged by nodes other than the expected peer.
- A connection whose peer was deregistered (for example by the liveness monitor) is closed on its next frame; its frames were previously still processed, without a verified sender.
- UDP sessions survive lost and reordered datagrams instead of failing permanently after the first loss, and a 1024-nonce replay window drops replayed frames, which can no longer move a session's path. A `HANDSHAKE_MSG1` can no longer replace an existing session by reusing its ID (`udp_hs_session_id_in_use`). Under load, or past a source's handshake rate, the responder answers msg1 with a stateless `HANDSHAKE_COOKIE` (new TNCF type `0x13`) and does no Diffie-Hellman until the initiator returns it, so spoofed sources cannot fill handshake slots. Expired handshakes are reaped every 5 seconds and before the handshake cap is checked, per-IP rate entries are pruned, `KEEPALIVE` no longer refreshes sessions, and pending observation requests and stale observation samples expire.
- Peers can no longer grow a node's state without bound or steer its dials: delivery dedup, ordered buffers, relay bindings and the peer store are capped; HELLO and relay state is dropped on disconnect; gossip cannot point a node at more local addresses than the peer's own, or keep its candidates alive with fake successes; and an inbound peer's claimed listen address can no longer suppress a bootstrap dial or redirect reconnects.
- `node_type` and HELLO capabilities are documented as self-declared, not an access-control boundary.
- Relayed payloads are documented as readable and modifiable by the relay; ADR-0003's opaque end-to-end forwarding is not implemented.
- A node started in a directory other users can write to no longer runs a `plugins/` library they placed there: libraries another user could have written or replaced are refused.
- One datagram can no longer end a UDP session: a handshake message for an established session is ignored, handshake messages count only from the session's peer address, and one that does not verify leaves the handshake waiting for the genuine message. Previously a `HANDSHAKE_MSG2` or `HANDSHAKE_MSG3` from anywhere with a known session ID removed the session, even an established one.
- A peer can no longer aim a node's UDP traffic through hole punching: `PUNCH_GO` frames from arbitrary peers, with arbitrary addresses or start times, are dropped (`punch_go_rejected`); a rendezvous no longer passes on addresses that peers merely claimed in HELLO (`punch_address_unverified`); at most 256 punches are in progress; and outgoing UDP handshakes count toward the concurrent-handshake cap.
- `trust promote` and the key store functions accept only a SHA-256 hex fingerprint, so a fingerprint can no longer name a path outside the key directories.
- A node can limit the peers it uses as relays and rendezvous to the node IDs it lists (`allowed_relays`, `allowed_rendezvous`). Any peer can announce the `relay` capability, and the first one that did was chosen, so any peer that passed the trust policy could read and alter relayed messages. With `allowed_rendezvous` set, punch invitations are accepted only from a listed rendezvous.
- A plugin config default for `[encryption]`, which can turn encryption off, is printed and emitted as `plugin_default_encryption_applied`; SECURITY.md documents what plugin defaults can change.
- The node writes at most 4096 entries into a trusted or rejected key directory (`trust::MAX_STORED_KEYS`); beyond that nothing new is stored and `tofu` rejects new keys (`tofu-storage-full`). A peer can no longer prepare, while a node only observes, rejects or accepts it, trust that a later switch to `tofu` would honour.
- The Noise static key file is created with mode 0600, and an existing key file readable by group or others is restricted to 0600 when loaded. `thenodes-cert` restricts a private key file before writing the key instead of after.
- Transport limits (`[network.limits]`): wire frames are read through a bounded line reader and a frame larger than `max_frame_bytes` (default 1 MiB) closes the connection instead of growing an unbounded buffer; HELLO frames are capped at 64 KiB before any trust decision. The secure-channel handshake plus HELLO exchange must complete within `handshake_timeout_ms` (default 10 s), a connection that delivers no frame for `idle_timeout_ms` (default 5 min, `0` disables) is closed and deregistered, and inbound connections are capped globally (`max_inbound_connections`, default 1024) and per remote IP (`max_inbound_connections_per_ip`, default 32). Rejected and timed-out connections emit `inbound_connection_limit_reached`, `inbound_connection_rejected`, `inbound_connection_rejected_per_ip`, `handshake_timeout`, `peer_idle_timeout`, and `peer_frame_rejected` network events.
- Inbound connections whose first frame is not a valid HELLO are now closed; previously an unregistered connection could keep sending frames into the dispatch loop.
- Outbound TCP connects (bootstrap, reconnect, delivery, handshake-only) honour `connection_policy.direct_tcp_timeout_ms`, which was previously parsed but never applied, and the listener backs off (50 ms doubling to 1 s) on repeated `accept()` errors such as file-descriptor exhaustion instead of spinning.
- Relay store-and-forward adds a global byte cap (`[network.relay].queue_max_bytes`, default 64 MiB) next to the existing frame-count caps; the oldest frames are evicted across targets when it is exceeded. `PeerManager::set_relay_queue_caps` takes and returns the byte cap as a third value.
- A read error on an established connection now deregisters the peer like a clean disconnect does, and `message_invalid` events log at most 256 characters of the rejected frame.
- Upgraded the direct `rustls-webpki` dependency to 0.103.16 with an explicit `ring` backend. CA-chain validation now rejects any path containing one of the known compromised eMudhra public keys, with chain reason `certificate-distrusted`, and the self-signed override does not apply to such keys. Trust-policy defaults are unchanged, but a configured trust anchor carrying one of these keys now causes every path through it to be rejected.
- Removed the unused `webpki-roots` dependency. TheNodes uses application-configured CA trust anchors rather than the bundled root store.
- `rustls` 0.22 still depends on `rustls-webpki` 0.102 for TLS handshake signature verification; TheNodes certificate path validation uses the upgraded direct dependency.

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
