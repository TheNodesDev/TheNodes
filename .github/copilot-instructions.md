# Copilot Instructions for TheNodes

## Project Overview
- **TheNodes** is a modular, plugin-driven P2P node framework written in Rust.
- The system supports two main operation modes:
  - **Node-Embedded Plugins (NEP):** Main binary hosts plugins for app logic.
  - **Core-as-a-Library (CAL):** Node logic as a reusable library.
- Major components are organized in `src/` by domain (network, security, realms etc). Plugins are loaded dynamically from the `plugins/` directory.

## Key Architecture
- **Networking:**
  - `src/network/` handles P2P, peer management, message types, and custom protocol logic.
  - `src/network/transport.rs` manages encrypted/unencrypted comms.
- **Security:**
  - `src/security/` covers encryption, key management, and trust validation.
  - **Encryption/PKI Policy:**
    - TLS encryption (via `rustls`) is **optional** and can be enabled/disabled in the config file:
      ```toml
      [encryption]
      enabled = true  # or false
      ```
    - When enabled, all network communication uses TLS with certificates.
    - PKI directory structure is required for certificate and trust management:
      ```
      pki/
        own/            # Node's own cert/key
        trusted/        # Trusted peer certs and CRLs
        rejected/       # Optionally store rejected certs
        issuers/        # CA/issuer certs and CRLs
      ```
      Example config paths:
      ```toml
      [encryption.paths]
      own_certificate  = "pki/own/cert.pem"
      own_private_key  = "pki/own/key.pem"
      trusted_cert_dir = "pki/trusted/certs"
      trusted_crl_dir  = "pki/trusted/crl"
      rejected_dir     = "pki/rejected"
      issuer_cert_dir  = "pki/issuers/certs"
      issuer_crl_dir   = "pki/issuers/crl"
      ```
    - TheNodes **does not generate or manage certificates**. Use external tools (e.g., `openssl`) to create and manage certs, and place them in the correct subdirectories.
    - Both direct peer validation and CA-based validation chains are supported by the PKI layout.
    - If encryption is **disabled** (`enabled = false`), all network traffic is plaintext. This is allowed for development, internal, or constrained environments.
    - **Default:** Encryption is off (opt-in).
    - **Interop:** No support for C/OpenSSL interop (by design).
    - **Future:** QUIC and plugin-based crypto may be added.
    - **Enforcement:** All contributors must follow this security/encryption model. See `SECURITY.md` for details and rationale.
- **Realms:**
  - `src/realms/` defines logical network boundaries ("realms") to ensure compatible communication.
- **Persistence:**
  - `src/persistence/` (if present) manages state/database logic.
- **Plugins:**
  - Plugins are `.so`/`.dll` files in `plugins/`. See `examples/` for plugin templates.

## Async-First API Policy

**Async-First Design:**

- All new APIs, features, and plugin interfaces should be designed as `async` by default, unless there is a clear and documented reason not to.
- Use `async fn` and `.await` for all I/O, networking, and plugin interactions to ensure non-blocking, scalable concurrency.
- Prefer async traits and async-aware data structures throughout the codebase.
- This applies to both core framework code and plugin implementations.

**Rationale:**
- Async Rust enables efficient handling of many concurrent tasks, which is essential for a modular, networked, plugin-driven system like TheNodes.
- Following this policy ensures consistency, performance, and future-proofing as the project grows.

**See also:**
- [Tokio async programming guide](https://tokio.rs/tokio/tutorial)
- [async-trait crate documentation](https://docs.rs/async-trait/)


## Developer Workflows
- **Build (library):**
  - `cargo build --release --lib`
- **Build (standalone NEP host):**
  - `cargo build --release`
- **Run with config:**
  - `cargo run -- --config config.toml`
- **Integration tests:**
  - Place in `tests/` or use `cargo test`

## Project Conventions
- **Module Structure:**
  - Each domain (network, security, realms, etc) has its own subdirectory with a `mod.rs` entry point.
  - Utilities are in `src/utils/`.
- **Configuration:**
  - Config files are TOML, typically in `config/`.
- **Logging:**
  - Custom logger in `src/utils/logger.rs` (if present).
- **Naming:**
  - Use clear, domain-driven names for modules and files.
- **Realms:**
  - Realms are used to separate logical networks; see `src/realms/realm.rs` for validation logic.

## Versioning & Backward Compatibility

- Initial development (pre-0.1.0) policy: Do not keep backward-compatibility shims. Prefer clean APIs and remove transitional wrappers.
- When an API needs to change, update templates and examples accordingly instead of preserving old entry points.
- Add concise migration notes in PRs/CHANGELOG when behavior changes.

## Integration Points & Patterns
- **Plugins:**
  - Loaded at runtime; follow the example in `examples/` for interface and structure.
- **Cross-component communication:**
  - Use message types and protocols defined in `src/network/`.
- **Security:**
  - All network comms should use encryption utilities from `src/security/`.

## References
- See `README.md` for architecture, terminology, and build/run details.
- Key files: `src/main.rs`, `src/lib.rs`, `src/network/`, `src/security/`, `src/realms/`, `plugins/`, `examples/`.

---

**If you are unsure about a pattern or workflow, check `README.md` or ask for clarification.**
