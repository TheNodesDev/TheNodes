
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
├── rejected/           # Automatically stores rejected certs (if enabled)
└── issuers/            # CA trust anchors and future CRLs
    ├── certs/          # Root CA trust anchors
    └── crl/            # Intermediate CRLs
```

Each of these paths is **fully configurable** in the config file.

```toml
[encryption]
enabled = true

[encryption.paths]
own_certificate  = "pki/own/cert.pem"
own_private_key  = "pki/own/key.pem"
trusted_cert_dir = "pki/trusted/certs"
trusted_crl_dir  = "pki/trusted/crl"
rejected_dir     = "pki/rejected"
issuer_cert_dir  = "pki/issuers/certs"
issuer_crl_dir   = "pki/issuers/crl"
```

This structure supports both direct peer validation and CA-based validation chains.

---

## 5. Trust Policy Modes

When TLS is enabled, each incoming peer certificate is evaluated according to the configured
`[encryption.trust_policy]` `mode`. The modes currently implemented in code are summarised below:

| Mode            | Behaviour                                                                 | Typical Use                                | `store_new_certs = "observed"` |
|-----------------|----------------------------------------------------------------------------|--------------------------------------------|---------------------------------|
| `open`          | Accept any presented certificate. Still honours pinning / time / chain flags when enabled. | Quick local development or fully trusted lab networks. | Writes a PEM copy of newly seen certs to the observed directory (if configured). |
| `allowlist`     | Accept only certificates whose SPKI fingerprint already exists under `pki/trusted/certs`. Any unrecognised cert is rejected. | Locked-down production where operators curate a fixed allowlist. | Records rejected certificates when explicitly enabled. |
| `observe`       | Reject every connection after recording the presented certificate for review. | Staged rollouts where operators want visibility without permitting traffic. | Always attempts to write a PEM copy. |
| `tofu` (Trust On First Use) | Atomically bind the first fingerprint to a peer identity and require the same fingerprint thereafter. Missing identity or unavailable storage rejects the connection. | Controlled onboarding with durable, writable observed storage. | Stores the first-seen certificate and identity binding. |
| `hybrid` (placeholder) | Currently behaves like `open` but emits metadata allowing future staged enforcement. | Migration experiments before full hybrid enforcement ships. | Stores newly seen certs, same as `open`. |

When `enforce_ca_chain = true`, TheNodes performs cryptographic WebPKI path validation for the peer's TLS role. Trust anchors are loaded from `issuer_cert_dir`; `trusted_cert_dir` is used as a compatibility fallback when no issuer directory is configured. The peer supplies intermediate certificates during the TLS handshake. Complete-path validation includes certificate signatures, CA/path constraints, EKU, critical extensions, name constraints, and current-time validity.

`reject_expired` and `reject_before_valid` independently enforce the leaf certificate's parsed `notAfter` and `notBefore` values even when CA-chain enforcement is disabled. If either applicable check is enabled and the validity window cannot be parsed, the connection is rejected.

CRL and OCSP processing are deliberate non-goals for version 0.4.0. The configured
CRL directories are reserved for future use and are not read, and revocation status
is not enforced. Operators that need to revoke a directly trusted TLS certificate or
Noise static key must remove its fingerprint from the allowlist or pin set and
restart the affected nodes. General CA revocation infrastructure may be reconsidered
after 1.0.

> Selecting `backend = "noise"` without the compiled `noise` feature fails secure-channel creation and rejects the connection; it never falls back to plaintext.

Noise remains intentionally opt-in. When compiled, the remote XX static key is
identified by a SHA-256 hexadecimal fingerprint and evaluated using `open`,
`allowlist`, `tofu`, or `observe`:

```toml
[encryption.noise.trust_policy]
mode = "allowlist"
allowlist_fingerprints = ["<sha256-hex>"]
pin_fingerprints = ["<sha256-hex>"]

[encryption.noise.trust_policy.paths]
allowlist_dir = "pki/noise/trusted"
observed_dir = "pki/noise/observed"
```

Observed `.noise` artifacts can be reviewed and copied into the allowlist
directory. A rejected Noise decision terminates the connection, and accepted
channels expose the static-key fingerprint in their authentication summary.

If you enable `store_new_certs = "observed"`, ensure the `observed_dir` path is configured in
`[encryption.trust_policy.paths]`. In `allowlist` mode, unlisted peers remain rejected but their
certificates can still be persisted for review. Use `observe` when every connection must be rejected
while presented certificates are collected.

## 6. Certificate Management Options

TheNodes ships with the optional `thenodes-cert` helper, which can generate self-signed certificates, copy them into the correct PKI directories, and print an SPKI fingerprint you can pin in `config.toml`:

```sh
cargo run --bin thenodes-cert -- \
    --realm my-realm \
    --out-cert pki/own/cert.pem \
    --out-key pki/own/key.pem \
    --copy-to-trusted
```

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
- Restrict `plugins/` directory permissions (owner-only write)
- Distribute plugins over authenticated channels and verify artifacts externally
- Pin plugins to the exact TheNodes host release and rebuild them with the host toolchain

#### 2. FFI Interface Vulnerabilities
The registration symbol and registrar function table use a C layout, but ABI 3
still transfers a Rust trait object in `PluginHandle`. It is not a stable
cross-language or arbitrary-toolchain ABI.

**Remaining Considerations:**
- Document ABI expectations for third-party authors (done in README plugin guide).
- Evaluate optional sandboxing (e.g., WASM) for untrusted plugins.
- Continue recommending locked-down `plugins/` directory permissions.

#### 3. Plugin Privilege Escalation
- Plugins run with full process privileges
- No sandboxing between plugins
- Early initialization (before main application logic)

### Security Best Practices

#### For Plugin Authors
```toml
# Cargo.toml - Pin compatible TheNodes version
[dependencies]
thenodes = "=0.4.0"  # Exact version for ABI compatibility
```

#### For Node Operators

TheNodes 0.4.0 does not provide plugin signature verification or a plugin
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
| Rejected Certs             | Optionally auto-stored           |

---
