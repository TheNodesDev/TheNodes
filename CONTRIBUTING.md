# Contributing to TheNodes

Thanks for your interest in contributing! This guide explains how to propose changes, report issues, add plugins, and understand stability expectations before 1.0.

## Table of Contents
- [Contributing to TheNodes](#contributing-to-thenodes)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [Project Goals Snapshot](#project-goals-snapshot)
  - [Stability \& Public API](#stability--public-api)
  - [Issue Reporting](#issue-reporting)
  - [Development Setup](#development-setup)
    - [Async-first APIs](#async-first-apis)
    - [Templates](#templates)
  - [Branching \& Workflow](#branching--workflow)
  - [Commit Message Conventions](#commit-message-conventions)
  - [Pull Request Checklist](#pull-request-checklist)
  - [Testing Guidelines](#testing-guidelines)
  - [Plugin Development](#plugin-development)
    - [Put Your Application Logic in Plugins](#put-your-application-logic-in-plugins)
    - [Naming Conventions](#naming-conventions)
  - [Configuration Defaults](#configuration-defaults)
  - [Security \& Trust Policy Changes](#security--trust-policy-changes)
  - [Documentation Guidelines](#documentation-guidelines)
  - [Licensing](#licensing)
  - [FAQ](#faq)

## Code of Conduct
We are committed to providing a welcoming, harassment‑free environment for everyone.

Core expectations:
- Be respectful: disagree with ideas, not people.
- Use inclusive, professional language — avoid slurs, stereotypes, or personal attacks.
- Assume good intent first; ask for clarification before escalating.
- No harassment, doxxing, or unsolicited private contact.
- Keep discussions focused on the project's scope (technical merit, design trade‑offs, security, reliability, UX for operators, etc.).

Unacceptable behavior includes: harassment (sexualized language or imagery, intimidation, stalking), insults or belittling comments, publishing others' private information, or repeated disruptive conduct after being asked to stop.

Reporting:
- For urgent or sensitive issues (harassment, safety, security disclosure overlap), contact the maintainers privately (open a confidential issue or email the repository owner if available).
- For ordinary moderation concerns, start with a public issue and clearly label the concern (e.g. "conduct").

Enforcement actions may include warnings, PR/issue locking, or (in severe/repeated cases) blocking. Decisions are made by maintainers with an aim toward fairness, transparency, and project health.

By participating you agree to uphold this standard. Thank you for helping keep the community constructive and respectful.

## Project Goals Snapshot
TheNodes is a modular, async-first P2P framework supporting:
- NEP (Node-Embedded Plugin) mode: runtime dynamic plugins
- CAL (Core-as-a-Library) embedding
- Optional encryption (TLS) & trust policy layers
- Realms for logical network segmentation
- Event-driven instrumentation & audit logging
- Extensible protocol (discovery, future roles/policies)

## Stability & Public API
See `STABILITY.md` for current stable-intent vs evolving areas. Before 1.0 breaking changes *can* occur, but we aim to minimize churn on the prelude exports and message schemas.


## Issue Reporting
Please include:
- Environment (OS, Rust version: `rustc -V`)
- Reproduction steps (config snippets, logs, message samples)
- Expected vs actual behavior
- If security-sensitive, DO NOT open a public issue—contact maintainers privately first.

See `SECURITY.md` for responsible disclosure guidance.

## Development Setup
1. Install Rust (stable) via `rustup`.
2. Clone repo and run:
   ```sh
   cargo build
   cargo test
   ```
3. (Optional) Run two local nodes with different configs for manual peer interaction.
4. Toolchain: This repo pins Rust via `rust-toolchain.toml`. MSRV is 1.74; avoid nightly-only features.

### Async-first APIs
Design new APIs as async by default. Prefer `async fn` and async traits (use `async-trait` when needed), and avoid blocking calls in async contexts.

### Templates
In `templates/`, keep manifests as `Cargo.toml.template` and Rust sources as `*.rs.tmpl`. Use `templates/generate_app.sh` to scaffold a project, which restores proper filenames. Do not commit real `Cargo.toml` or `.rs` files under `templates/`.

## Branching & Workflow
- `main` is the integration branch (fast-forward preferred if clean, otherwise squash or merge commit with context).
- Feature branches: `feat/<short-description>`.
- Bug fix branches: `fix/<issue-id-or-keyword>`.
- Draft PRs encouraged for early feedback.

## Commit Message Conventions
Follow a lightweight Conventional Commits style for clarity and changelog automation later:
```
feat(discovery): add peer list gossip handling
fix(peer): avoid duplicate cross-connect rejection log
refactor(events): streamline dispatcher path
docs: add stability matrix
chore: update dependencies
```
Breaking changes (post-1.0) would include `!` (e.g., `feat!: change handshake field`). Pre-1.0 you may still mark them for reviewer clarity.

## Pull Request Checklist
- [ ] Linked to an issue (or explains why not).
- [ ] Includes tests (unit or integration) for behavior changes.
- [ ] No new deny-level Clippy findings. Run the same check as CI:
   ```sh
   cargo clippy --workspace --all-targets --all-features -- -D clippy::correctness -D clippy::perf -W clippy::style -W clippy::complexity
   ```
- [ ] Formatting passes:
   ```sh
   cargo fmt --all -- --check
   ```
- [ ] Added/updated docs where behavior is user-visible (README, SECURITY, STABILITY, or inline `//!`).
- [ ] Updated `CHANGELOG.md` (under `[Unreleased]` with correct category) if user-facing. Suggested categories: Added, Changed, Fixed, Removed, Security, Docs, Build.
- [ ] Ensures license headers not needed (we rely on root licenses).

## Testing Guidelines
- Fast unit tests should live near code or in `tests/`.
- Multi-node interaction tests: use temporary directories for `state_dir` and distinct ports.
- Determinism: avoid real-time sleeps where possible; prefer timeouts with generous margins.
- For discovery logic, sample peer store carefully (avoid flaky random tests by seeding `SmallRng` if necessary).
 
Run all tests (CI-equivalent):
```sh
cargo test --workspace --all-features -- --nocapture
```

## Plugin Development
1. Use the example at `examples/kvstore_plugin`.
2. Implement `Plugin` trait methods you need (`on_message`, optionally `on_prompt`).
3. Provide lightweight extension messages via `MessageType::Extension { kind }` plus JSON payload.
4. Use `early_config_defaults()` if you want to supply realm / port / config defaults (they only apply if operator did not set them).
5. Avoid blocking calls—remain async-aware and offload heavy work to tasks.

See `docs/PLUGIN_AUTHORING.md` for a full walkthrough. At runtime, you can enter a plugin’s prompt by typing its prefix; type `exit` to leave.

### Put Your Application Logic in Plugins
Treat the core crate as infrastructure (networking, discovery, realms, security). All domain/business workflows, state machines, and higher-level protocols should live inside one or more plugins:
- Keeps upstream upgrade path clean (less chance of merge conflicts on core updates).
- Lets you ship/enable features selectively just by deploying or removing a shared library.
- Enables parallel development (different teams own different plugins).
- Facilitates test isolation: you can mock or stub only the stable-intent surfaces.

Only propose core changes when they provide generic value (e.g., new transport, event type, or security primitive). Otherwise: extend via a plugin.

### Naming Conventions
- Extension message kinds: reverse-domain-ish or namespaced (`kvstore.put`, `metrics.report`).
- Avoid collisions by prefixing with plugin name.

## Configuration Defaults
Plugins can supply defaults for most top-level config fields via `ConfigDefaults` (append semantics for `bootstrap_nodes_extend`). Operator config always wins.

## Security & Trust Policy Changes
When modifying trust policy logic:
- Emit appropriate `TrustDecisionEvent` or `SystemEvent` entries.
- Update `SECURITY.md` and `CHANGELOG.md`.
- Maintain backward compatibility for existing config keys unless raising a documented breaking change (pre-1.0 still minimize churn).
- Also update `docs/SECURITY_TRUST_POLICY_PLAN.md` when advancing phases or changing behavior.

## Documentation Guidelines
- Module-level docs: add `//!` at top explaining purpose, invariants, and extension points.
- Public functions: explain rationale, not just *what*.
- Complex async flows: include brief state diagrams or bullet lifecycle steps.

## Licensing
The project is dual-licensed under **Apache-2.0 OR MIT**.
By submitting a contribution you agree it is provided under these terms.

Include only original work or correctly licensed third-party code (ensure compatibility with both licenses). Attributions (if required) should go into a new or existing `NOTICE` file—open a PR first.
Do not add per-file license headers; the root dual-license applies project-wide.

## FAQ
**Q: Should I add the Plugin trait to the prelude?**  
A: Not yet; we're keeping CAL-mode lean. It may be added once lifecycle hooks stabilize.

**Q: How do I add a new message type?**  
Add variant to `MessageType`, mark enum `#[non_exhaustive]` if growth expected, update serializer tests, and add doc comment describing semantics.
Review realm compatibility rules in `src/realms/realm.rs` and update them if the new message changes cross-realm behavior.

**Q: Do I need to regenerate anything after adding a plugin?**  
No codegen step; just rebuild and ensure the `.so` is copied into `plugins/`.

---
Thank you for helping build TheNodes!
