# Stability & Public API (Pre-1.0)

TheNodes is currently in a pre-1.0 state. **APIs may still change**; we are converging on stability but will prioritize progress and correctness over strict compatibility. This document declares *intent* so early adopters know what they can reasonably build against.

Semantic Versioning expectation before 1.0.0: minor versions (`0.x`) MAY introduce breaking changes. After 1.0.0, only major versions will.

## Stability Classes
| Class | Meaning | Compatibility Promise (pre-1.0) | Post-1.0 Goal |
|-------|---------|---------------------------------|---------------|
| Stable-intent (best‑effort) | We expect to keep shape; only additive changes likely | Best‑effort stability. Breaking changes are possible; when feasible we will deprecate first and provide migration notes. | Backward compatible (SemVer) |
| Evolving | Likely to change based on feedback | May break without deprecation | Graduates to Stable-intent or Internal |
| Internal | Not for external use | May change anytime | Hidden / minimized |
| Experimental | Feature gated / clearly marked | May be removed | Becomes Stable or removed |

## Declared Stable-Intent Surface (Pre-1.0)
These items are re-exported (or will be) through the `prelude` or documented directly. Pre‑1.0 these come with a best‑effort promise, not a hard guarantee:
- `config::Config` (top-level struct) and its de/serialization contract (field names & basic meanings). Note: field additions are expected; field renames/removals are possible with a short deprecation/migration note when feasible.
- `config::ConfigDefaults` (shape may grow additively)
- Event record envelope fields: `meta.level`, `meta.timestamp`, `action`, `detail` (we strive to keep these stable so tooling doesn't break)
- PKI directory structure naming (subfolders: `own`, `trusted`, `issuers`, `observed`) — additive subfolders may be introduced

The following are intentionally softened pre‑1.0 (treat as Evolving unless otherwise noted):
- `network::message::{Message, MessageType, Payload}` schema: Envelope remains stable‑intent; individual variants and payload shapes may change. Prefer non‑exhaustive matching and tolerant parsing.
- `realms::RealmInfo`: may evolve as realm semantics are refined.

## Evolving (Subject to Change)
- Peer discovery strategy internals (interval semantics, sampling algorithm)
- `ConfigDefaults` merging heuristics (port detection heuristic may change)
- Trust policy depth features (pinning, realm binding, CA enforcement flags) beyond simple modes
- Future `node_type` / role policy engine
- Heartbeat presence / cadence (currently optional / deferred)

## Experimental / Planned
- Data diode (unidirectional) communication policies
- Reliability tiers (WAL, replay, durability guarantees)
- QUIC transport & pluggable crypto layer
- Capability negotiation during handshake

## Internal (Not Public API)
- `peer_store` structure and its method set
- Connection backoff timings, retry scheduling
- Exact names of `SystemEvent.action` strings (except those explicitly documented later)
- Temporary debug / println! output formatting

## Prelude Policy
A curated `prelude` module is provided for ergonomic imports. Inclusion signals stable-intent. Exclusion does **not** automatically mean internal, but indicates *use deliberately*.

### Notably Excluded: `plugin_host::Plugin`
The plugin trait is intentionally **not** in the prelude initially for two reasons:
1. CAL Mode Neutrality: When embedding TheNodes as a library (Core-as-a-Library) an application may choose not to host runtime plugins at all; forcing the plugin trait into the default import surface blurs that model boundary.
2. Surface Hardening: The method set may expand (e.g. asynchronous lifecycle hooks) before 1.0; keeping it out of the prelude reduces accidental lock-in.

It may be added later once lifecycle guarantees are finalized.

## Versioning & Additive Changes
We may add:
- New `MessageType` variants (recommend using non-exhaustive pattern matching)
- New optional config keys
- New event `action` strings
without bumping a *breaking* (major) version after 1.0. Before 1.0 we still attempt to maintain forward motion without churn.

Pre‑1.0, when we do break behavior or rename fields, we'll aim to:
- Call it out clearly in CHANGELOG under a "Breaking changes" section
- Provide a brief MIGRATION note or example when the change is user‑facing
- When feasible, offer a one‑release deprecation period (soft warning/log) before removal

## Recommendations for Integrators
- Match on `MessageType` with a `_ => {}` fallback to tolerate new variants.
- Avoid relying on println!/console output. Use structured events where possible.
- Treat unspecified config keys as unstable; check for existence.
- Keep a local wrapper facade if you need absolute API insulation.
- Place application/business logic in plugins: Consider the core crate a networking + security substrate. This minimizes churn exposure and allows you to adopt future core versions with fewer merge conflicts.

### Optional hardening strategies
- Pin to a minor version range within 0.x that you have validated.
- Use Cargo features to opt into experimental pieces explicitly (see below).
- Validate your plugins against protocol and plugin‑API versions in CI.

## Pre‑1.0 Deprecation Practice
These are practices, not hard guarantees before 1.0:
- Deprecate first when feasible (warning logs and/or `#[deprecated]` attributes)
- Keep deprecated items for at least one subsequent minor (or a minimum of ~30 days between releases)
- Security fixes or correctness bugs may bypass deprecation and break immediately

## Stability Annotations & Feature Flags
- Mark extendable enums with `#[non_exhaustive]` where appropriate.
- Use `#[deprecated(note = "...", since = "0.x")]` for deprecations when applicable.
- Gate experimental functionality behind `experimental-*` Cargo features and/or config flags; default builds should not enable experimental features.
- Document stability level in module or item docs (e.g., "Status: Stable‑intent (best‑effort)", "Evolving", "Experimental").

## Future Formalization
Before tagging 0.1.0:
- Re‑evaluate the declared stable‑intent list and promote items that proved stable in practice.
- Add a `prelude` test ensuring only stable‑intent items are exported.
- Provide event action registry documentation.

Feedback welcome. Open an issue or discussion thread with proposed changes to this document.
