# ADR 0008: Transport-Agnostic Fingerprint Trust

- Status: Accepted
- Date: 2026-09-07
- Target: 0.4.0

## Context

TLS peers were evaluated through certificate policy while Noise XX accepted any
remote static key. Duplicating the complete TLS evaluator for Noise would mix
X.509-only checks with a transport that has no certificates, subjects, EKUs, or
certificate chains.

## Decision

TheNodes uses one fingerprint decision core for TLS and Noise:

- `open`, `allowlist`, `tofu`, and `observe` have the same acceptance semantics;
- exact SHA-256 hexadecimal fingerprints are used for allowlists and pins;
- TOFU binds a peer identity hint to the first accepted fingerprint;
- observed artifacts and identity bindings are stored in the configured observed
  directory;
- every evaluation produces the existing structured `TrustDecision`.

TLS remains a layered evaluator. X.509 parsing, certificate usage, validity, realm
and subject binding, and WebPKI chain validation run before the leaf SPKI
fingerprint enters the shared core.

Noise hashes the remote static public key with SHA-256 after the XX handshake and
evaluates it through the shared core. A rejected decision terminates the
connection. TCP and UDP handshake payloads carry a validated node ID used as the
TOFU identity, and the TCP path verifies that identity against the subsequent
HELLO. Accepted channels expose the fingerprint through `AuthSummary`.

Noise policy is configured independently:

```toml
[encryption.noise.trust_policy]
mode = "allowlist" # open | allowlist | tofu | observe
store_new = "none" # none | observed
allowlist_fingerprints = ["<sha256-hex>"]
pin_fingerprints = ["<sha256-hex>"]

[encryption.noise.trust_policy.paths]
allowlist_dir = "pki/noise/trusted"
observed_dir = "pki/noise/observed"
```

An allowlist directory accepts observed-style files named
`<sha256-fingerprint>.noise` or text artifacts containing a
`fingerprint_sha256=<sha256-hex>` line.

Noise remains opt-in through the `noise` Cargo feature. Selecting it without the
feature fails closed; there is no plaintext fallback.

## Consequences

- TLS and Noise share policy semantics and decision reporting without pretending
  Noise has X.509 properties.
- Persistent Noise static keys are required for stable identity, TOFU, and pins.
- Operators can promote a reviewed `.noise` artifact from observed storage into
  the allowlist directory.
- Noise trust is enforced before TCP or UDP sessions are registered for
  application traffic.

## Rejected Alternatives

- Treat every successful Noise handshake as trusted: encryption would not
  authenticate the expected node.
- Reuse certificate files for Noise keys: this would incorrectly impose X.509
  semantics on Noise.
- Compile Noise by default: the optional feature keeps the default dependency and
  cryptographic surface smaller.
