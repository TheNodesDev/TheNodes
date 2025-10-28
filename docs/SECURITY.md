
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
- When enabled, all peer connections use TLS.

- Development fast-start (explicit opt-out):

```toml
[encryption]
enabled = false # Development-only; plaintext traffic
```

---

## 2. Encryption Modes

- Default: **TLS** via [`rustls`](https://github.com/rustls/rustls)
- Future plans: **QUIC** (built-in encryption) and pluggable crypto backends.

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
└── issuers/            # Intermediate CA certs and CRLs
    ├── certs/          # Intermediate certs
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
| `allowlist`     | Accept only certificates whose SPKI fingerprint already exists under `pki/trusted/certs`. Any unrecognised cert is rejected. | Locked-down production where operators curate a fixed allowlist. | **Never** writes to `observed/`; rejected peers are stopped before storage occurs. |
| `observe`       | Reject certificates that are not already pinned/trusted while still copying them into `pki/observed/certs` for review. | Staged rollouts where operators want visibility without permitting the connection. | Writes a PEM copy even though the session is rejected. |
| `tofu` (Trust On First Use) | Accept the first time a fingerprint is seen, record it, and require the same fingerprint on subsequent connections. | Gradual rollout where you harvest fingerprints during an onboarding phase. | Stores the first-seen cert so future rotations can be reviewed. |
| `hybrid` (placeholder) | Currently behaves like `open` but emits metadata allowing future staged enforcement. | Migration experiments before full hybrid enforcement ships. | Stores newly seen certs, same as `open`. |

> Note: a future `ca` mode is reserved for full chain-of-trust enforcement and is not yet active.

If you enable `store_new_certs = "observed"`, ensure the `observed_dir` path is configured in
`[encryption.trust_policy.paths]`. Keep in mind that the setting has no effect in `allowlist`
mode because unlisted peers are rejected before their certificates can be persisted (consider `observe` when you want to capture but still block).

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
- Implement plugin signature verification
- Use allowlists for permitted plugins

#### 2. FFI Interface Vulnerabilities
Current plugin interface now ships with a C-compatible registrar API that exposes
versioned function tables instead of raw Rust trait objects.

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
thenodes = "=0.1.0"  # Exact version for ABI compatibility
```

#### For Node Operators
```toml
# config.toml - Restrict plugin loading
[plugins]
directory = "/secure/path/plugins"
verify_signatures = true
allowed_plugins = ["libmydomain.so", "libmetrics.so"]
```

#### File System Security
```bash
# Set secure permissions
chmod 755 /path/to/plugins/         # Directory readable, not writable by others
chmod 644 /path/to/plugins/*.so     # Plugins readable, not writable
chown node:node /path/to/plugins/   # Owned by node process user
```

### Future Security Enhancements

#### Phase 1 (Pre-1.0)
- [ ] Plugin signature verification
- [ ] Stable FFI-safe plugin API design
- [ ] ABI compatibility checking
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
| Plugin Security (NEP)      | Directory permissions + signatures |
| Plugin Security (CAL)      | Compile-time only (safer)        |
| Future Expansion           | QUIC, plugin crypto, WASM plugins |
| Interop with C/OpenSSL     | No (by design)                   |
| Cert Validation            | Configurable path-based trust    |
| Rejected Certs             | Optionally auto-stored           |

---
