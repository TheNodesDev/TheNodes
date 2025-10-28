# Trust Policy Plan for TheNodes

This document captures the design and phased implementation approach for flexible certificate trust policies. It relocates `accept_self_signed` under a new `[encryption.trust_policy]` section and introduces richer policy controls.

> Security-by-default alignment: Production templates in TheNodes enable TLS (`encryption.enabled = true`) and recommend `mtls = true` with a restrictive trust policy (e.g., `mode = "allowlist"`, optional pinning) out of the box. Development usage may explicitly disable encryption for local testing. The schema and phases below remain the same; the difference is the default posture in distributed templates.

Operational helpers:
- Use `thenodes-cert` to bootstrap test credentials and obtain SPKI fingerprints:
  ```bash
  cargo run --bin thenodes-cert -- --realm <realm> --copy-to-trusted
  ```
  Place outputs under `pki/` and optionally pin the printed fingerprint in `[encryption.trust_policy]`.
- When running with the interactive prompt, operators can manage trust state at runtime:
  - `trust observed list` — list observed certificate fingerprints
  - `trust trusted list` — list trusted certificate filenames
  - `trust promote <fingerprint>` — promote an observed fingerprint into trusted

## Current status (2025‑10‑28)

- Phase 1: COMPLETE (config moved under `[encryption.trust_policy]`, modes open/allowlist/observe/tofu end‑to‑end, observed persistence, fingerprinting, prompt commands).
- mTLS flag: AVAILABLE (`[encryption].mtls = true|false`).
- Phase 2: PARTIAL (chain/time scaffolding present; optional chain enforcement and self‑signed override wired; time windows parsed permissively when flags are set; full path validation deferred).
- Phase 3: PARTIAL/CORE DELIVERED (fingerprint/subject pinning and realm binding; promotion helper; prompt‑level trust manage commands; background reconnect after promotion).
- Audit logging: DELIVERED (structured JSON lines sink with rotation; see `logging` config). Metrics counters still TBD.

What remains: full WebPKI chain building, strict time validity enforcement, hybrid/CA modes, soft‑fail toggles, live reload of pins, optional metrics.

## 1. Objectives
- Support multiple network trust postures: open, allowlist, observe, TOFU, CA, hybrid.
- Allow incremental hardening without rewrites.
- Provide optional persistence of newly seen certificates.
- Keep configuration declarative and auditable.
- Preserve backward compatibility (existing configs continue to parse with deprecation warnings later).

## 2. Config Schema (Phase 1 + forward looking)
```toml
[encryption]
enabled = true

  [encryption.paths]
  own_certificate  = "pki/own/cert.pem"
  own_private_key  = "pki/own/key.pem"
  trusted_cert_dir = "pki/trusted/certs"
  rejected_dir     = "pki/rejected"
  issuer_cert_dir  = "pki/issuers/certs"

  [encryption.trust_policy]
  mode = "open"              # open | allowlist | observe | tofu (Phase 1 implements these modes)
  accept_self_signed = true   # moved from encryption root; only relevant when mode != ca
  allow_unlisted = true       # (allowlist/hybrid) accept even if not pre-trusted (Phase 2)
  store_new_certs = "none"   # none | trusted | observed (Phase 1 supports none/observed)
  reject_expired = true       # Phase 2
  reject_before_valid = true  # Phase 2
  enforce_ca_chain = false    # Phase 2 (ca / hybrid)
  pin_subjects = []           # Phase 3
  pin_fp_algo = "sha256"     # Phase 3
  pin_fingerprints = []       # Phase 3 (DELIVERED)
  realm_subject_binding = false # Phase 3 (DELIVERED)

  [encryption.trust_policy.paths]
  observed_dir = "pki/observed/certs"   # created if needed
  # rejected_dir already in encryption.paths
```

## 3. Phase Breakdown
### mTLS Flag (Added post Phase 1 implementation)
An `mtls` boolean flag has been added under `[encryption]` to optionally require and present node certificates on BOTH sides of a TLS connection. This integrates with the trust policy evaluation pipeline described in this document without changing existing modes.

```toml
[encryption]
enabled = true
mtls = true   # when true, outbound connections present our cert; inbound requires client cert
```

Behavioral notes:
- When `mtls = false` (default):
  - Outbound: Client performs server cert trust evaluation only.
  - Inbound: Server does not request a client certificate; peer identity is unauthenticated at TLS layer.
- When `mtls = true`:
  - Outbound: Client loads `own_certificate` + `own_private_key` and sends its certificate chain.
  - Inbound: Server constructs a `WebPkiClientVerifier` root store from `trusted_cert_dir` and requires a client certificate during handshake.
  - After handshake, the presented peer certificate chain (if any) is passed to `evaluate_peer_cert_chain` just like on outbound side.

Interaction with trust modes:
- open: Still accepts any presented certificate; with mTLS enabled, the client must present a syntactically valid cert but policy will not reject based on trust content.
- allowlist: With mTLS enabled, inbound connections whose client cert is not found (fingerprint/SPKI match) in the trusted set are rejected; without mTLS they are accepted because no client cert is provided to evaluate.
- observe: Always rejects peer certificates that are not pre-trusted, but still persists them to the observed directory for later promotion.
- tofu: With mTLS enabled, first-seen client certs may be stored (if `store_new_certs = observed`) and subsequent changes will be detectable in future enhancements. Without mTLS, TOFU only applies to server certificates.

Operational guidance:
- Enable `mtls` only after populating `trusted_cert_dir` with the certificates (or issuer roots for future CA modes) of peers you expect, otherwise allowlist mode will reject all clients.
- For early deployments using `tofu`, it is safe to enable `mtls` to begin accumulating an observed catalog of peer certs for potential later promotion.
- If `mtls` is enabled but the local node lacks its own cert/key pair, the outbound side logs a warning and downgrades to one-way TLS; the inbound side will fail to start TLS without a valid pair.

Future phases (CA / hybrid) will extend the verifier construction to use issuer/CRL directories; no additional config flag is expected—`mtls` remains the on/off switch for mutual presentation while trust policy governs acceptance semantics.

### Phase 1 (Implemented)
- New config structs: `TrustPolicyConfig`, limited fields: `mode`, `accept_self_signed`, `store_new_certs`, `observed_dir`.
- Modes implemented: `open`, `allowlist`, `observe`, `tofu`.
- Behavior:
  - open: accept any cert (no validation beyond parse). Optionally store if `store_new_certs == observed`.
  - allowlist: only accept if cert matches something in trusted directory.
  - observe: reject untrusted certs but copy them into the observed directory so operators can promote later.
  - tofu: if unseen fingerprint -> store (if configured) and accept; if seen -> accept; if changed for same peer identity (future improvement - Phase 2).
- Certificate fingerprint algorithm: SHA-256 of SPKI (with helper function).
- Storage: write PEM as-is into `observed_dir` (filename = `<sha256>.pem`).
- Logging: decision reason and fingerprint.
- Deprecate (not yet remove) `encryption.accept_self_signed` (still parsed; if set and trust_policy.accept_self_signed is None, carry value over).

### Phase 2 (Current implementation status)
Implemented:
- Real SPKI fingerprint (x509-parser) with fallback hashing
- Chain validation scaffold (basic issuer/self-signed heuristics) via `validate_chain_simple`
- Enforcement flags integrated: `enforce_ca_chain`, `reject_expired`, `reject_before_valid` (time parsing currently placeholder: validity windows not enforced yet unless parsing is later upgraded)
- Extended logging: includes `chain_valid`, `chain_reason`, `time_valid`, `time_reason`
- Self-signed override when `accept_self_signed=true` even if `enforce_ca_chain=true`

Deferred / Not yet fully implemented:
- True cryptographic chain building + signature/path validation (future webpki integration)
- Actual notBefore/notAfter parsing & rejection (placeholder returns `unparsed`) 
- New modes `ca` and `hybrid` (reserved; selecting them should currently fall back or be rejected)
- `allow_unlisted` behavior for hybrid
- Warn vs hard-reject toggles (currently only hard reject where applicable)

Rationale for partial implementation: Provide immediate introspection (reasons + flags) and stable SPKI identity while keeping strict PKI roadmap incremental.

### Phase 3 (Pinning & Promotion)
Status: PARTIALLY IMPLEMENTED (core delivered)

Delivered in code:
1. Configuration additions (under `[encryption.trust_policy]`):
  - `pin_subjects = []` (list of exact subjects or substring matches when prefixed with `~`).
  - `pin_fingerprints = []` (list of SPKI SHA-256 hex strings; comparison is case-sensitive exact).
  - `pin_fp_algo = "sha256"` (currently only `sha256` accepted; future algorithms may include `sha512`).
  - `realm_subject_binding = false` (when true, the active realm name must appear as a substring inside the certificate subject; enforced before mode logic).
2. Enforcement ordering (hard reject at first unmet constraint):
  1. Fingerprint pin set (if non-empty) – peer fingerprint MUST be present.
  2. Subject pin set – peer subject MUST match an entry (exact or substring rule).
  3. Realm binding (if enabled) – realm name substring check against subject.
  4. Chain / time heuristic flags (`enforce_ca_chain`, `reject_expired`, `reject_before_valid`).
  5. Mode-specific evaluation (`open | allowlist | observe | tofu`).
3. Promotion helper: `promote_observed_to_trusted(observed_dir, trusted_dir, fingerprint)` copies `<observed_dir>/<fp>.pem` to trusted store (idempotent; returns `Ok(true)` if newly promoted, `Ok(false)` otherwise).
4. Tests: `tests/pins.rs` covers positive and negative paths for fingerprint and subject pin matching.
5. Logging: Trust decision lines now include rejection reasons like `fp-pin-mismatch`, `subject-pin-mismatch`, `realm-subject-mismatch` prior to mode logic reasons.
6. UX: After `trust promote <fingerprint>` in the prompt, the node now triggers background reconnect attempts to known peers (non‑blocking) so promotions take effect without a manual `/connect`.

Operational guidance:
- Use pinning to freeze expected identities after an initial TOFU observation period. Populate `pin_fingerprints` from logged fingerprints or observed directory filenames.
- Subject pins are useful when operating a private CA issuing predictable CN/OU patterns. Use `~substring` form for coarse pattern binding without regex overhead (e.g., `~MyOrg-Nodes`).
- Enable `realm_subject_binding` to ensure cross-realm certificates (misconfiguration or malicious) are rejected early.
- Always keep at least one path (pins or allowlist) consistent across rolling certificate rotations; update pins before deploying new certs to avoid outages.

Limitations / Deferred items:
- No regex/glob; only exact or leading `~` substring semantics.
- If subject cannot be parsed and any subject-based constraint exists, connection is rejected (future: make configurable soft-fail).
- Only SHA-256 fingerprints supported regardless of `pin_fp_algo` value (parser enforces `sha256`).
- No hot reload of pins; requires process restart to pick up config changes.
- Promotion is exposed via the interactive prompt (`trust observed list`, `trust trusted list`, `trust promote <fp>`). A non‑interactive CLI flag set is still TBD.
- Metrics counters for pin violations and trust outcomes are not emitted yet.

Planned near-term enhancements (still part of Phase 3 completion definition):
- Validity (notBefore/notAfter) real parsing & enforcement (brings `reject_expired` / `reject_before_valid` to life).
- WebPKI-based full chain path construction under `enforce_ca_chain`.
- Optional soft-fail toggle for unparsable subjects.
- Live reload (SIGHUP or file watch) for pin sets.
- CLI/Prompt: list observed, promote by fingerprint, generate pin template (prompt commands already available; CLI packaging TBD).
- Realm binding might expand to allow multiple accepted realm substrings.

### Phase 4 (Planned)
- Plugin trust decision hooks.
- CLI utilities / maintenance commands (non‑interactive trust ops, pin template generation).
- Metrics and observability (counters for decisions, promotions, violations).

## 4. Data Structures (Phase 1)
```rust
#[derive(Debug, Clone, Deserialize)]
pub struct TrustPolicyPathsConfig {
    pub observed_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustPolicyConfig {
  pub mode: Option<String>,                // "open" | "allowlist" | "observe" | "tofu"
    pub accept_self_signed: Option<bool>,    // migrated from encryption
    pub store_new_certs: Option<String>,     // none | observed | trusted (trusted reserved for Phase 2)
    pub paths: Option<TrustPolicyPathsConfig>,
}
```

Runtime translation after parsing:
```rust
pub enum TrustMode { Open, Allowlist, Observe, Tofu }
pub enum StoreNew { None, Observed }
```

## 5. Fingerprinting
- Use SPKI DER -> SHA-256 hex (lowercase). Filename pattern `<fp>.pem`.
- Recompute each connection; use in logs and storage.

## 6. Functions (Phase 1)
- `load_trusted_certs(dir) -> HashSet<Vec<u8>>` (store SPKI bytes or fingerprint).
- `extract_spki_fingerprint(cert_der: &[u8]) -> String`.
- `ensure_observed_dir(path)` create if missing.
- `store_observed_cert(path, fingerprint, pem_bytes)`.
- Entry point adaptation inside current TLS client + server sides before final acceptance.

## 7. Migration Logic
1. Parse config.
2. If `encryption.trust_policy.accept_self_signed` is None and legacy `encryption.accept_self_signed` present, copy value.
3. Warn (log) if legacy root field used directly.
4. Preserve backward compatibility for existing configs without trust_policy: inject default `TrustMode::Open`.

## 8. Logging & Audit

Runtime console examples:
```
TRUST decision=ACCEPT mode=open fp=ab12... reason=open-policy
TRUST decision=ACCEPT mode=tofu fp=cd34... reason=new-tofu stored=observed
TRUST decision=ACCEPT mode=allowlist fp=ef56... reason=present-in-trusted
TRUST decision=REJECT mode=observe fp=aa77... reason=observe-only
```

Structured audit log:
- JSON lines sink is available; configure via `logging` in `config.toml`.
- Defaults write to `logs/trust_audit.jsonl` with simple rotation parameters when enabled.

## 9. Failure Handling
- On reject: close connection gracefully; log reason.
- Avoid partial writes before policy decision final.

## 10. Out of Scope (Phase 1)
- Chain validation
- CRL / OCSP
- Pinning
- Promotion workflow

---

Status summary: Phase 1 complete; mTLS flag available; Phase 2 scaffolding active with optional enforcement; Phase 3 core pinning/promotion delivered with prompt UX and background reconnects; audit logging available. Remaining work is focused on full PKI validation, live reloads, and richer CLI/metrics.
