# ADR 0014: Certificate Revocation Lists

- Status: Proposed
- Date: 2026-11-07
- Target: 0.5.0

## Context

The TLS paths have had `trusted_crl_dir` and `issuer_crl_dir` since 0.1.0, and
the shipped example configurations set both. Neither directory was ever read.
A certificate listed in a CRL there was accepted like any other, and nothing
told the operator so. Version 0.4.0 documented CRL processing as a non-goal
but kept the settings.

Version 0.4.0 also added cryptographic path validation against configured
certificate authorities (`enforce_ca_chain`). The validator, rustls-webpki,
checks CRLs as part of the same path validation.

These settings were in `[encryption.paths]` and `[encryption.trust_policy]`
in 0.4 and are in `[encryption.tls.paths]` and `[encryption.tls.trust_policy]`
from 0.5.0 (ADR-0016).

Revocation matters only for certificates that a CA vouches for. A directly
trusted certificate (allowlisted, pinned or self-signed) is revoked by removing
it, and a CRL cannot speak for it.

## Decision

### What is checked

When a peer's TLS chain is validated against a CA, the leaf and every
intermediate are checked against all CRLs in `trusted_crl_dir` and
`issuer_crl_dir`. A directory holds DER files (`.crl`, `.der`) and PEM files
(`.pem`, or a `.crl` with `X509 CRL` blocks).

- A revoked certificate fails validation with chain reason
  `certificate-revoked`. The self-signed override (`accept_self_signed`)
  never applies to it.
- A certificate whose issuer has no CRL in the directories is not revoked.
- A CRL past its nextUpdate still applies. What it revokes stays revoked; only
  revocations made since it was issued are missing.
- A CRL directory that cannot be read, a file that does not parse, and a CRL
  whose signature does not verify fail validation (`crl-dir-unreadable`,
  `crl-invalid:<error>`, `crl-signature-invalid`). An unusable CRL never means
  that nothing is revoked.

CRLs are read for every validation, as trust anchors are, so a replaced CRL
applies to the next connection without a restart. Established connections are
not checked again.

OCSP is not supported.

### Startup checks

The standalone host refuses to start when:

- a CRL directory is set, but CRLs can never be consulted: encryption is off,
  the backend is not TLS, or `enforce_ca_chain` is not `true`;
- a configured CRL directory cannot be read, or a CRL in it does not parse.

A CRL past its nextUpdate is reported at startup (console and a `crl_outdated`
event at warn level).

## Consequences

- Revoking a CA-issued certificate takes a CRL from its CA in one of the
  directories; connections made after that reject it.
- Configurations that set CRL directories without `enforce_ca_chain`,
  including the examples shipped before 0.5.0, stop at startup until the
  settings are removed or CA validation is enabled. The shipped examples now
  have them commented out.
- Validation reads the CRL directories from disk for every connection, like
  the trust anchors. Caching both is a separate change.
- Directly trusted certificates and Noise keys are still revoked by removing
  them from the allowlist or pin set.

## Rejected Alternatives

- **Keep CRLs unsupported and refuse to start when they are configured.**
  Honest, but leaves CA deployments without revocation while the validator
  already supports it.
- **Treat a certificate without a CRL as revoked.** Every CA would need a CRL
  in place before any of its certificates could connect.
- **Reject everything from a CA whose CRL is past its nextUpdate.** A CRL
  that was not renewed in time would take the whole network down, while the
  revocations it lists hold regardless.
