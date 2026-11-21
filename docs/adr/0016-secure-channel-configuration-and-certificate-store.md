# ADR 0016: Secure-Channel Configuration and Certificate Store

- Status: Proposed
- Date: 2026-11-08
- Target: 0.5.0
- Amends: ADR-0008 (TOFU identity bindings and the observed directory)
- Relates to: ADR-0001 (secure channel abstraction), ADR-0004 (UDP sessions
  are Noise), ADR-0012 (node identity binding), ADR-0014 (CRLs)

## Context

In 0.4, the TLS settings sit directly in `[encryption]`: `mtls`,
`[encryption.paths]` and `[encryption.trust_policy]`. Noise has its own
section, `[encryption.noise]`, with `[encryption.noise.trust_policy]`
(ADR-0008). A node uses both backends at once when it runs TLS over TCP, since
UDP sessions are always Noise (ADR-0004), yet nothing in the layout says which
settings belong to which. The asymmetry has concrete costs:

- The two policies share structs where their settings differ. The TLS
  `[encryption.trust_policy.paths]` accepted `allowlist_dir`, which only Noise
  reads, so `deny_unknown_fields` could not reject it.
- The same setting has two names: `store_new_certs` for TLS, `store_new` for
  Noise.
- `[encryption] accept_self_signed`, marked deprecated in favour of
  `[encryption.trust_policy] accept_self_signed`, was accepted but never read.

The certificate store has `own`, `trusted` and `issuers`, each with `certs`
and `crl`, and `rejected`. The certificates of refused peers belong in
`rejected`, from where an operator moves the ones to trust into `trusted`.
0.4 had a `rejected_dir` setting, documented as storing rejected certificates,
but never wrote to it. Instead, ADR-0008 added an observed directory
(`observed_dir`, written with `store_new_certs`/`store_new = "observed"`) that
held three different things:

- copies of rejected keys (`observe`, and `allowlist`),
- copies of accepted keys (`open`, `hybrid`, `tofu`),
- TOFU's state: a binding from a peer identity (the TLS subject DN, or
  `node:<node_id>` for Noise) to the first fingerprint accepted for it, in
  `observed_dir/bindings/`.

The binding existed because a set of trusted fingerprints cannot express "this
identity has this key". Node identity binding (ADR-0012) now does exactly
that, for TLS and Noise, with pins, CA-certified names, persistence, a cap,
and a binding recorded before the peer is registered. The transport binding
duplicated it: for Noise it bound the same `node:<node_id>`, for TLS a subject
DN that the key holder chooses and nothing else in TheNodes authorizes on.
Keeping both had concrete costs:

- Modes that only observe or reject wrote bindings that `tofu` later trusted,
  so a peer could claim an identity while a node only observed it and be
  trusted after the switch to `tofu`, locking out the genuine key.
- `tofu` accepted an allowlisted key without binding its identity, which a
  different key could then claim.
- The transport binding was written during the handshake, before the node
  identity check, so a connection that a node ID pin refused still left a
  binding that locked the genuine key out.

Finally, `enforce_ca_chain` used `trusted_cert_dir` as its trust anchors when
`issuer_cert_dir` was unset, mixing the certificates trusted as peers with the
CAs trusted to vouch for others.

The two trust policies cannot simply be merged into one section either. They
evaluate different keys with different checks: TLS has chains, validity, CRLs,
subject pins and realm binding, Noise has none of these, and their trusted
directories hold different files. One section would either force the same mode
on both or hold settings that apply to only one of them.

## Decision

### One section per backend

Each backend has its own section in `[encryption]`, with the same shape: its
key store under `paths`, and its `trust_policy`.

```toml
[encryption]
enabled = true
backend = "tls"                  # TCP backend: tls | noise | none

[encryption.tls]
mtls = true

[encryption.tls.paths]
own_certificate  = "pki/own/cert.pem"
own_private_key  = "pki/own/key.pem"
trusted_cert_dir = "pki/trusted/certs"
rejected_dir     = "pki/rejected"
issuer_cert_dir  = "pki/issuers/certs"
# trusted_crl_dir / issuer_crl_dir (ADR-0014)

[encryption.tls.trust_policy]
mode = "allowlist"               # open | allowlist | tofu | observe | hybrid

[encryption.noise.paths]
static_key   = "pki/noise/static.key"
trusted_dir  = "pki/noise/trusted"
rejected_dir = "pki/noise/rejected"

[encryption.noise.trust_policy]
mode = "allowlist"               # open | allowlist | tofu | observe

[encryption.node_identity]       # applies to both backends (ADR-0012)
mode = "tofu"
```

`[encryption]` keeps what is common to both backends: `enabled`, `backend` and
`[encryption.node_identity]`. Each policy accepts only its own settings. In the
library, the types follow the sections: `EncryptionTlsConfig`, `TlsPaths` and
`TlsTrustPolicyConfig` mirror `EncryptionNoiseConfig`, `NoisePaths` and
`NoiseTrustPolicyConfig`, and `EffectiveTrustPolicy::from_tls_config` mirrors
`from_noise_config`.

### The key store

1. **Trusted.** A key is trusted when it is in the trusted directory (any PEM
   certificate in `trusted_cert_dir` for TLS, a `<fingerprint>.noise` file in
   `trusted_dir` for Noise) or in the inline allowlist.
2. **Rejected.** In every mode, a key the trust policy rejects is kept in the
   rejected directory, when one is set, for review. `thenodes-ctl trust
   promote <fingerprint>` and the prompt's `trust promote` move it to the
   trusted directory. `observe` requires a rejected directory.
3. **Trust anchors.** `enforce_ca_chain` validates chains only against
   `issuer_cert_dir`, which it requires. `trusted_cert_dir` is never a source
   of trust anchors.
4. **Caps.** The node writes at most 4096 entries into a trusted or rejected
   directory, files placed there by an operator included.

### Trust on first use

`tofu` accepts a trusted key, and a new key once: the key is added to the
trusted directory. `tofu` keeps no identity bindings of its own; which node ID
a key may use is decided by node identity binding alone (ADR-0012).

- The key is written only after the connection's node identity binding is
  recorded, and before the peer is registered, so a connection refused later
  leaves nothing in the trusted directory. A key that cannot be written
  refuses the connection (`tofu_trust_unwritable`), and a full trusted
  directory rejects new keys (`tofu-storage-full`).
- `tofu` requires the trusted directory and node identity binding: the node
  refuses to start with `tofu` and `[encryption.node_identity] mode = "off"`.
- A certificate with `CA:true` is never trusted on first use
  (`tofu-ca-certificate`): a trusted CA could vouch for other certificates.

### Migration from 0.4

There are no aliases. A 0.4 configuration fails to load as having unknown
keys, and the error names the replacement of each setting
(`Config::from_toml_str`):

| 0.4 | 0.5 |
|-----|-----|
| `[encryption] mtls` | `[encryption.tls] mtls` |
| `[encryption.paths]` | `[encryption.tls.paths]` |
| `[encryption.trust_policy]` | `[encryption.tls.trust_policy]` |
| `[encryption] accept_self_signed` (never read) | `[encryption.tls.trust_policy] accept_self_signed` |
| `store_new_certs`, `store_new` | removed: rejected keys go to `rejected_dir`, `tofu` adds accepted ones to the trusted directory |
| `[encryption.trust_policy.paths] observed_dir` | removed: `[encryption.tls.paths] rejected_dir` |
| `[encryption.noise] static_key_path` | `[encryption.noise.paths] static_key` |
| `[encryption.noise.trust_policy.paths] allowlist_dir` | `[encryption.noise.paths] trusted_dir` |
| `[encryption.noise.trust_policy.paths] observed_dir` | removed: `[encryption.noise.paths] rejected_dir` |

TOFU bindings in `observed_dir/bindings/` are not read. They hold only
fingerprints, not certificates, so they cannot be converted: keys are trusted
again on their first connection after the upgrade. Node identity binding is
new in 0.5.0 too, so node IDs are bound on first use after the upgrade either
way. Deployments that validated chains against `trusted_cert_dir` move their
CA certificates to `issuer_cert_dir`.

## Consequences

- Which settings apply to TCP and which to UDP follows from the section names,
  and a setting placed under the wrong backend is an error instead of being
  ignored. Adding a backend means adding a section.
- Nothing a node observes, rejects or accepts in another mode becomes trusted
  when it switches to `tofu`; only `tofu` and an operator's promotion add to
  the trusted directory.
- The onboarding workflow: run `tofu`, review the trusted directory, switch to
  `allowlist`. Every key accepted during onboarding stays trusted until
  removed.
- `tofu` accepts every new key once, whatever identity it claims;
  impersonating a known node ID is prevented by node identity binding, which
  `tofu` depends on.
- Every 0.4 configuration that sets TLS or Noise trust options must be edited.

## Rejected Alternatives

- **One shared `[encryption.trust_policy]` for both backends:** see Context.
- **Keeping the old names as aliases:** two ways to write the same setting is
  the inconsistency this decision removes, and 0.5.0 already breaks
  configuration compatibility (unknown keys and values are errors).
- **Keeping the transport binding next to node identity binding:** two TOFU
  stores for the same claim, the second weaker and the source of the problems
  described above.
- **Writing first-use keys during the handshake:** a connection refused by node
  identity binding would still become trusted.
- **Trusting `CA:true` first-use certificates as leaves only:** trusting them
  at all invites operators to rely on them as anchors; refusing them keeps CAs
  an explicit operator decision in `issuer_cert_dir`.
