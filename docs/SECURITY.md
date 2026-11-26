
# Security Policy and Secure Defaults

TheNodes follows a security-by-design, secure-by-default policy:

- Security is a first-class design concern across networking, trust, and plugin boundaries.
- Production-facing templates and examples default to encrypted transport (TLS) and a restrictive trust posture.
- Insecure modes (plaintext, open trust) are available for development only and must be explicitly opted-in.

This document outlines the encryption and certificate trust model and how secure defaults are applied.

---

## 1. Security Defaults and Configurability

- Encryption is strongly recommended and enabled by default in production templates. Core remains configurable for development.
- To explicitly enable (or confirm) TLS in any app:

```toml
[encryption]
enabled = true
```
- When enabled, peer connections use the selected `tls` or `noise` backend.
    Noise requires the `noise` Cargo feature.

- Development fast-start (explicit opt-out):

```toml
[encryption]
enabled = false # Development-only; plaintext traffic
```

---

## 2. Encryption Modes

- **TLS** via [`rustls`](https://github.com/rustls/rustls), the default backend when encryption is enabled.
- **Noise XX** via `snow`, available with the optional `noise` Cargo feature.
- **Plaintext**, for explicitly configured development or controlled environments only.
- Future plans include QUIC and additional pluggable crypto backends.

---

## 3. Why `rustls`?

| Feature           | rustls            | OpenSSL         |
|------------------|-------------------|-----------------|
| Language         | Rust (memory-safe) | C (unsafe)      |
| Native deps      | None              | Yes             |
| FIPS 140-2       | ❌ Not certified  | Some builds  |
| Security         | Modern & safe | ⚠️ Requires caution |

---

## 4. Certificate Structure and Trust Model

TheNodes uses a flexible PKI-style structure for certificate storage and validation.

### Recommended directory layout:

```
pki/
├── own/                # The application's own certificate and private key
├── trusted/            # Trusted CA and peer certificates
│   ├── certs/          # Trusted certs
│   └── crl/            # Certificate revocation lists (optional)
├── rejected/           # Certificates the trust policy rejected, for review
├── issuers/            # CA trust anchors and their CRLs
│   ├── certs/          # Root CA trust anchors
│   └── crl/            # CRLs from those CAs (optional)
└── noise/              # The same store for Noise static keys
    ├── static.key      # This node's static key
    ├── trusted/        # Trusted static keys (<fingerprint>.noise)
    └── rejected/       # Static keys the trust policy rejected
```

In this layout (ADR-0016), a peer is trusted when its key is in `trusted`, a CA vouches for chains when it is in
`issuers`, and a key the trust policy rejects is kept in `rejected`, from
where an operator promotes it to `trusted` (`trust promote <fingerprint>` in
the prompt or `thenodes-ctl trust promote`).

Each of these paths is **fully configurable** in the config file. Relative
paths, and the built-in defaults such as `pki/`, `plugins/`, `data/` and
`logs/`, are relative to the directory the node is started in. Start a
service in a directory only its own user can write to, for example with
`WorkingDirectory=` in a systemd unit.

```toml
[encryption]
enabled = true

[encryption.tls.paths]
own_certificate  = "pki/own/cert.pem"
own_private_key  = "pki/own/key.pem"
trusted_cert_dir = "pki/trusted/certs"
issuer_cert_dir  = "pki/issuers/certs"
# With enforce_ca_chain = true (see below):
# trusted_crl_dir = "pki/trusted/crl"
# issuer_crl_dir  = "pki/issuers/crl"
```

Each backend has its own section ([ADR-0016](adr/0016-secure-channel-configuration-and-certificate-store.md)):
`[encryption.tls]` holds `mtls`, `paths` and `trust_policy`, and
`[encryption.noise]` the static key and `trust_policy` for Noise. A node uses
both when it runs TLS over TCP, since UDP sessions are always Noise.
`[encryption.node_identity]` applies to both. A config written for 0.4 fails
to load, and the error names where each moved setting went.

This structure supports both direct peer validation and CA-based validation chains.

The configuration is fail-closed. The node refuses to start when the config
file is missing (unless started with `--allow-default-config`, which runs
plaintext with open trust) and when the file contains a key it does not know,
so a misspelt setting such as `[encryption] enable = true` is an error rather
than an unprotected node. The same holds for values: the backend, the trust
modes, `pin_fp_algo`, the node identity mode
and the Noise suite settings accept only the values listed for them, so
`mode = "allowlst"` stops startup instead of meaning `open`.

---

## 5. Trust Policy Modes

When TLS is enabled, each incoming peer certificate is evaluated according to the configured
`[encryption.tls.trust_policy]` `mode`. The modes currently implemented in code are summarised below:

| Mode            | Behaviour                                                                 | Typical Use                                |
|-----------------|----------------------------------------------------------------------------|--------------------------------------------|
| `open`          | Accept any presented certificate. Still honours pinning / time / chain flags when enabled. | Quick local development or fully trusted lab networks. |
| `allowlist`     | Accept only certificates whose SPKI fingerprint is in a certificate under `trusted_cert_dir`. Any other certificate is rejected. | Locked-down production where operators curate the trusted store. |
| `observe`       | Reject every connection; the certificates are kept in `rejected_dir`, which this mode requires. | Staged rollouts where operators want visibility without permitting traffic. |
| `tofu` (Trust On First Use) | Accept a certificate in the trusted store, and a new one once: it is added to `trusted_cert_dir` when its connection is admitted. Requires `trusted_cert_dir` and node identity binding. | Controlled onboarding; switch to `allowlist` afterwards to freeze the store. |
| `hybrid` (placeholder) | Currently behaves like `open` but emits metadata allowing future staged enforcement. | Migration experiments before full hybrid enforcement ships. |

In every mode, a certificate the trust policy rejects is kept in `rejected_dir`
when it is set, for review and promotion.

When `enforce_ca_chain = true`, TheNodes performs cryptographic WebPKI path validation for the peer's TLS role. Trust anchors are loaded only from `issuer_cert_dir`, which this setting requires: the node refuses to start without it. The trusted store is never a source of trust anchors, since `tofu` writes to it. The peer supplies intermediate certificates during the TLS handshake. Complete-path validation includes certificate signatures, CA/path constraints, EKU, critical extensions, name constraints, and current-time validity.

`reject_expired` and `reject_before_valid` independently enforce the leaf certificate's parsed `notAfter` and `notBefore` values even when CA-chain enforcement is disabled. If either applicable check is enabled and the validity window cannot be parsed, the connection is rejected.

Certificate revocation lists (ADR-0014) apply when `enforce_ca_chain = true`.
The leaf and intermediates of every chain validated against a CA are checked
against the CRLs in `trusted_crl_dir` and `issuer_crl_dir` (DER or PEM files),
read again for every connection. A revoked certificate is rejected with
`certificate-revoked`, and the self-signed override never applies to it. A
certificate whose CA has no CRL there is not revoked, and a CRL past its
nextUpdate still applies; the node warns about it at startup. A CRL directory
or file that cannot be used rejects the chain instead of revoking nothing. The
node refuses to start when CRL directories are set without `enforce_ca_chain`
and the TLS backend, since no CRL would ever be consulted, or when a CRL cannot
be read. OCSP is not supported.

A directly trusted TLS certificate or Noise static key is revoked by removing
it from the trusted directory (or its fingerprint from the inline allowlist or
pin set) and restarting the affected nodes.

> Selecting `backend = "noise"` without the compiled `noise` feature fails secure-channel creation and rejects the connection; it never falls back to plaintext.

Noise remains intentionally opt-in. When compiled, the remote XX static key is
identified by a SHA-256 hexadecimal fingerprint and evaluated using `open`,
`allowlist`, `tofu`, or `observe`:

```toml
[encryption.noise.paths]
static_key   = "pki/noise/static.key"
trusted_dir  = "pki/noise/trusted"
rejected_dir = "pki/noise/rejected"

[encryption.noise.trust_policy]
mode = "allowlist"
allowlist_fingerprints = ["<sha256-hex>"]
pin_fingerprints = ["<sha256-hex>"]
```

A Noise key is trusted when its fingerprint is in `allowlist_fingerprints` or
a `<fingerprint>.noise` file in `trusted_dir`. A rejected key is kept in
`rejected_dir` as such a file, with the node ID it claimed
(`claimed_identity=`), which is unverified and for review only. A rejected
Noise decision terminates the connection, and accepted channels expose the
static-key fingerprint in their authentication summary.

### Trust on first use

`tofu` trusts a new key by adding it to the trusted directory
(`trusted_cert_dir` for TLS, `trusted_dir` for Noise). The key is written
only once its connection is admitted:
after the node identity binding is recorded (ADR-0012), so a connection
refused later, for example by a node ID pin, leaves nothing in the trusted
directory. Which node ID a key may use is decided by the node identity
binding alone, so `tofu` requires it: the node refuses to start with
`tofu` and `[encryption.node_identity] mode = "off"`. A certificate with
`CA:true` is never trusted on first use (`tofu-ca-certificate`).

The trusted and rejected directories hold at most 4096 entries each, files an
operator placed there included; keys cost a peer nothing, so beyond that
nothing new is stored, and `tofu` rejects new keys with `tofu-storage-full`
while trusted ones keep connecting. Review the trusted directory before
switching from `tofu` to `allowlist`: every key accepted during onboarding is
in it.

Modes other than `tofu` never add to the trusted directory, so a key that a
node observed, rejected or accepted in another mode is new after a switch to
`tofu`. Versions before 0.5.0 kept TOFU bindings in `observed_dir/bindings/`;
they are no longer read, and keys are trusted again on their first connection
after the upgrade.

The Noise static key file is created readable by its owner only, and an
existing key file readable by others is restricted to its owner when loaded.
A key file that is not a valid key stops the node instead of being replaced,
since a new key would be a new, unbound identity. `thenodes-cert` restricts a
private key file before writing the key into it.

### Node identity binding

The trust policy decides whether a key may connect. Node identity binding
(ADR-0012) decides whether that key may use the node ID it claims in HELLO, so a
trusted peer cannot take over another member's node ID and receive its traffic.
It applies to TLS and Noise over TCP and to UDP Noise sessions:

| Mode | A node ID is accepted when |
|------|----------------------------|
| `tofu` (default) | it has a matching pin or a CA-certified name, or its first accepted fingerprint matches |
| `pinned` | its fingerprint is pinned for it |
| `certificate` | the TLS leaf names it in a `URI:node://<realm>/<node_id>` SAN for this node's realm and the chain validated against the configured CA, or it is pinned |
| `off` | always; node IDs are self-asserted labels |

```toml
[encryption.node_identity]
mode = "tofu"
bindings_file = "pki/node-identity/bindings.jsonl"

[encryption.node_identity.pins]
"<peer-node-id>" = ["<sha256-hex>"]   # another node's ID -> the fingerprints it may use
```

- A pin, or a certificate name that does not match the claimed node ID, rejects
  the connection in every mode except `off`. A pinned fingerprint cannot claim
  another node ID.
- A certificate name binds the node ID by itself only when `enforce_ca_chain`
  validated the chain against `issuer_cert_dir`. A self-signed or allowlisted
  certificate can name any node, because whoever holds the key can mint one.
- TOFU binds TLS and Noise keys separately. Without `bindings_file`, bindings
  last for the process lifetime. A node that changes its key without a CA-certified
  name is rejected until `thenodes-ctl node-binding forget <node_id>` removes
  its binding and the node restarts.
- A connection without a transport identity (plaintext, or TLS without mTLS on
  the accepting side) carries an unverified node ID: `tofu` accepts it unless
  the node ID is pinned or already bound to a key, while `pinned` and
  `certificate` reject it. With TLS but without mTLS, a node that this node has
  dialled (and so bound) cannot connect back inbound; enable `mtls` so the
  accepting side sees the client's key.
- When the binding store holds `max_bindings` entries, a node ID seen for the
  first time is rejected (`node-binding-store-full`) rather than accepted
  unbound.
- Upgrading a CA-managed deployment: certificates without a
  `URI:node://<realm>/<node_id>` SAN are bound by TOFU in `tofu` mode, so a
  rotated key is rejected (`node-binding-mismatch`) until its binding is
  forgotten. Reissue certificates with `thenodes-cert --realm-code --node-id` before
  rotating keys, or run `thenodes-ctl node-binding forget <node_id>` after.
- An invalid `[encryption.node_identity]` section stops the node at startup.

Every frame names both ends of the hop that carried it: the transport stamps
`from` with the sending node and `to` with the peer on every frame it writes,
and a received frame whose `from` is not the node bound to the connection or
UDP session, or whose `to` is not the local node, is dropped
(`message_rejected`). HELLO's `from` must equal its `node_id`.

Plugins read `Message::origin()`. For a direct message, `Message::from` is
therefore always the node bound to the delivering connection, and
`origin().authenticated_sender()` returns it when that node ID is bound to a
transport identity. A message unwrapped from a relay tunnel keeps its origin in
`from` and `origin().relayed_from`. A relay forwards a tunnel only for its own
sending peer's live binding and only when the tunnel names that peer as its
origin, so the origin is as trustworthy as the relay. There is no end-to-end
proof of origin, so relayed messages have no authenticated sender. Nor are
tunnelled payloads end-to-end encrypted: a relay can read and alter them, and
ADR-0003's description of relayed payloads as opaque end to end is not
implemented. Applications that need confidentiality or integrity across a
relay protect the payload themselves.

A `DELIVERY_ACK` counts only from the node the message was sent to, and a hop
`ACK` only from the target a relay forwarded to. Only the node that created a
relay binding can remove it, and binding IDs are random. A tunnel
only carries `TEXT`, `DATA_REQUEST`, `DATA_RESPONSE`, `EXTENSION` and
`DELIVERY_ACK`. Other message types, including nested tunnels, are rejected.

HELLO `node_type` and capabilities are self-declared. `realm_access.allowed_node_types`
filters well-behaved peers but is not an access-control boundary.

A node chooses its relays and rendezvous among the peers that announce the
`relay` and `punch_rendezvous` capabilities, so by default any peer that
passes the trust policy can offer itself as a relay and read or alter what is
relayed through it. `[network.relay] allowed_relays` and
`[network.nat_traversal] allowed_rendezvous` restrict the choice to the node
IDs they list, and node identity binding ties those node IDs to keys. With
`allowed_rendezvous` set, a node also accepts punch invitations only from a
listed rendezvous. An empty list allows none. The acknowledgement of a
relayed message still returns through the relay that delivered it.

### Peer-supplied data

State that peers can make a node keep is bounded, and peers cannot direct a
node's dials:

- The listen address in HELLO is a claim. Only addresses this node dialled and
  reached the right node at suppress bootstrap dials, drive reconnects, or are
  persisted; a peer that connected in is not redialled. HELLO details are
  forgotten when a peer has neither a TCP connection nor a UDP session.
- The UDP listen and observed addresses in HELLO are claims the node sends
  observation requests, handshakes and probes to, so they are kept only if
  they are no more local than the connection, by the same rule as gossip.
- A node connects only within its realm, in both directions: the listener
  refuses a client whose HELLO names another realm, and a dialling node
  refuses such a server.
- A `PEER_LIST` adds at most 64 addresses, each no more local than the peer
  that sent it: a peer on a public address cannot point the node at LAN or
  loopback services, while peers on the same LAN can share LAN addresses.
  Unspecified, multicast and broadcast addresses and port 0 are refused.
  Gossiped addresses are candidates, not successes, and are never passed on
  in answers to `PEER_REQUEST` until the node has connected to them.
- The peer store keeps `[network.persistence].max_entries` records at
  runtime; a full store drops never-reached candidates first.
- Duplicate suppression keeps 16 384 message IDs per origin and 262 144 in
  total. Out-of-order ordered-reliable messages are buffered up to 1 024
  ordering keys and 4 MiB per origin (65 536 keys and 64 MiB in total); a
  message that does not fit is not acknowledged, so its sender retries. A
  message ID is at most 128 bytes and an ordering key at most 256, so the
  kept IDs and keys are bounded in bytes as well; a message with longer ones
  is dropped.
- A relay client may hold 64 bindings, and they end with its connection.

UDP sessions (ADR-0013) carry an explicit nonce per frame and drop replays
with a 1024-nonce window; only authenticated frames refresh a session or move
its path. A handshake cannot take over an existing session ID, and under load
the responder requires a stateless cookie proving the initiator's source
address before it performs a Diffie-Hellman. Handshake messages count only
from the session's peer address and never for an established session, and
one that does not verify leaves the handshake waiting for the genuine
message, so a datagram with a known session ID cannot end a session.

Hole punching (ADR-0015) cannot be used to aim a node's UDP traffic. A node
follows a `PUNCH_GO` only for a punch it requested or an invitation it
accepted, only from that punch's rendezvous, once, and before the punch's
deadline (at most 30 seconds); at most 256 punches are in progress, and
outgoing handshakes count toward the handshake cap. The address it probes
must be no more local than the rendezvous. A rendezvous hands out an address
only if it answered a cookie-verified observation request from it, never the
address a peer announced in HELLO alone. A rendezvous coordinates at most
1 024 punches at once, 16 per initiator, each only for its time budget; it
does not let a second request take over an attempt ID, and only the invited
responder settles an attempt. Attempt IDs are at most 128 bytes.

## 6. Certificate Management Options

TheNodes ships with the optional `thenodes-cert` helper, which can generate self-signed certificates, copy them into the correct PKI directories, and print an SPKI fingerprint you can pin in `config.toml`:

```sh
cargo run --bin thenodes-cert -- \
    --realm-code my-realm \
    --node-id my-node \
    --out-cert pki/own/cert.pem \
    --out-key pki/own/key.pem \
    --copy-to-trusted
```

`--node-id <id>` adds a `URI:node://<realm-code>/<id>` SAN, which names the node
in its realm; it requires `--realm-code`, the realm's canonical code: `[realm]
code` when set, otherwise `[realm] name` in lowercase ASCII with every other
character as `-` (a node logs its own as `realm` in its trust events). Each
realm is its own namespace, and peers count only names in their own
realm. They enforce the name in every node identity mode, but it binds the
node ID by itself only in a certificate signed by a CA that peers trust (see
*Node identity binding*). With OpenSSL, add
`subjectAltName = URI:node://<realm-code>/<id>` to the certificate extensions.
`[encryption.tls.trust_policy] require_realm_node_name = true` refuses a peer
certificate that names no node in this node's realm
(`realm-node-name-missing`). `--cn` sets the subject's CN, which defaults to
the node ID; TheNodes does not authorize on the subject except through
`pin_subjects`. A node presents its certificate before any trust check, to
anyone who connects to its TLS port and, with mTLS, to any server it dials,
so the node name and the default CN show them its realm code and node ID.

You can continue to use standard tools like:

```sh
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

- Store outputs from either workflow in the appropriate subdirectory of `pki/` as shown above, or integrate them with your existing PKI automation.

---

## 7. Plaintext (Development Only)

- Plaintext mode exists for development or constrained internal environments and must be explicitly set to `enabled = false`.
- Production templates ship with TLS enabled by default; remove TLS only with clear risk acceptance.

---

## 8. Plugin Security (NEP Mode)

### Security Model Overview

**NEP Mode** introduces additional security considerations compared to CAL mode due to dynamic plugin loading:

| Mode | Trust Boundary | Attack Surface |
|------|---------------|----------------|
| **CAL** | Single binary compilation | Compile-time dependencies only |
| **NEP** | Host binary + runtime plugins | Dynamic loading, FFI interface, plugin directory |

### Key Security Risks

#### 1. Plugin Directory Compromise
```
plugins/
├── libmydomain.so      # Legitimate plugin
└── libmalware.so       # Malicious plugin (attacker-placed)
```

**Mitigation:**
- On Unix the loader refuses a library that another user could have written
  or replaced. The library and every directory above it, after resolving
  symlinks, must be owned by the node's user or root and not writable by other
  users. Group write is accepted for the owner's private group (the default
  under `umask 002`), unless the entry has a POSIX ACL: the group bits are
  then the ACL's mask, which may grant write to other users. A directory with
  the sticky bit, such as `/tmp`, may be writable by others, who cannot rename
  or remove entries they do not own. The library is loaded from the path that
  was checked. Windows has no such check, and ACLs on systems other than Linux
  (macOS, NFSv4) are not examined.
- Restrict `plugins/` directory permissions (owner-only write)
- Distribute plugins over authenticated channels and verify artifacts externally
- Pin plugins to the exact TheNodes host release and rebuild them with the host toolchain

#### 2. FFI Interface Vulnerabilities
Plugin ABI 4 checks an exported `thenodes_plugin_abi_version` before any plugin
code is invoked, and registration outcomes are typed and authoritative. The
registrar table uses a C layout, but the transferred endpoint is still a Rust
trait object. It is not a stable cross-language or arbitrary-toolchain ABI, and
the version check is compatibility checking, not authentication: loading a
library can run its native constructors before the check.

The native boundary carries owned data and completion sinks only. No future,
Tokio handle, or runtime-bound host object crosses it, and plugin panics are
caught inside the plugin's own code copy and reported as data. These measures
prevent accidental cross-copy unwinding and runtime misuse; they do not contain
a plugin built with `panic = "abort"`, undefined behavior, memory corruption,
`process::exit`, or code that never yields. Host and plugins must use the same
TheNodes release, toolchain, lockfile, features, and global allocator.

Loaded libraries stay mapped until the process exits, including after failed
registration, so code referenced by surviving objects, tasks, or destructors is
never unloaded.

**Remaining Considerations:**
- Evaluate optional sandboxing (e.g., WASM or separate processes) for untrusted plugins.
- Continue recommending locked-down `plugins/` directory permissions.

#### 3. Plugin Privilege Escalation
- Plugins run with full process privileges
- No sandboxing between plugins. Per-library runtimes, per-plugin inboxes,
  admission limits, managed task scopes, and per-plugin data directories
  organize trusted code; they do not restrict what a native plugin can access.
- Library initializers run when the library is loaded, before plugin startup
- A plugin can supply config defaults, applied to settings the config file does
  not set. They include `[encryption]`, which a plugin can turn off, and
  `bootstrap_nodes`; `bootstrap_nodes_extend` adds to the operator's list even
  when it is set. A plugin default for `[encryption]` is printed and emitted as
  `plugin_default_encryption_applied`. Set `[encryption]` in the config file to
  decide it yourself.

#### 4. Availability
TheNodes imposes no time limits on plugin code. A plugin that blocks or never
yields can stall the other handlers on its runtime and keep shutdown waiting.
The standalone host reports the phase it is waiting on and escalates on a
second SIGINT or SIGTERM, then exits unsuccessfully; an external supervisor
remains the final authority. A failed plugin is isolated, and the standalone
host shuts down on any plugin failure.

### Security Best Practices

#### For Plugin Authors
- Build plugins from the host's exact TheNodes source, Rust toolchain, `Cargo.lock`,
  and TheNodes feature set, with unwinding panics and the system allocator.
- Emit events through `PluginContext::events`; lifecycle events never contain
  payloads, configuration, hook error text, or panic messages, and plugin events
  should follow the same rule.

#### For Node Operators

TheNodes does not provide plugin signature verification or a plugin
allowlist in its configuration schema. Restrict write access to the configured
plugin directory and verify release artifacts before deployment.

#### File System Security
```bash
# Set secure permissions
chmod 755 /path/to/plugins/         # Directory readable, not writable by others
chmod 644 /path/to/plugins/*.so     # Plugins readable, not writable
chown node:node /path/to/plugins/   # Owned by node process user
```

### Future Security Enhancements

#### Phase 1 (Pre-1.0)
- [x] Versioned registration table and ABI compatibility checking
- [x] Version query checked before registration; authoritative registration outcomes
- [x] Plugin panics contained in the plugin's code copy; loaded code pinned
- [ ] Plugin signature verification
- [ ] Stable cross-toolchain and cross-language plugin ABI
- [ ] Plugin allowlisting configuration

#### Phase 2 (Post-1.0)
- [ ] WASM-based plugin runtime (full sandboxing)
- [ ] Capability-based security model
- [ ] Plugin marketplace with verified signatures
- [ ] Runtime plugin isolation (separate processes)

### CAL Mode Security Advantages

For security-critical deployments, consider **CAL mode**:
- No dynamic loading attack surface
- Compile-time dependency verification
- Full binary control and signing
- Rust type system protection throughout

---

## Summary

| Feature                    | Approach                         |
|---------------------------|----------------------------------|
| Encryption Default         | On in production templates; configurable in core |
| Encryption Type            | TLS via `rustls`                 |
| Trust Mechanism            | Fully structured PKI directory   |
| Plugin Security (NEP)      | Directory permissions + exact-version ABI checks; no built-in signatures or allowlist |
| Plugin Security (CAL)      | Compile-time only (safer)        |
| Future Expansion           | QUIC, plugin crypto, WASM plugins |
| Interop with C/OpenSSL     | No (by design)                   |
| Cert Validation            | Configurable path-based trust    |
| Rejected Certs             | Kept in `rejected_dir` for review and promotion |

---
