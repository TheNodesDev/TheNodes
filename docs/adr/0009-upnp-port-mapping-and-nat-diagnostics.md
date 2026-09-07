# ADR 0009: Optional UPnP Port Mapping and NAT Diagnostics

- Status: Accepted
- Date: 2026-09-07
- Target: 0.4.0
- Supersedes: ADR-0005 only where it places UPnP outside the NAT traversal scope

## Context

Observed-address discovery and UDP hole punching improve reachability but do not
request a stable inbound mapping from common consumer routers. Operators also
need a lightweight indication of whether observed endpoints appear stable across
probes.

UPnP changes router state and adds a network-facing dependency. It must therefore
remain optional at both compile time and runtime, while connection policy and
relay fallback continue to work without it.

## Decision Drivers

- Improve inbound TCP reachability on common consumer routers without requiring
  manual port forwarding.
- Keep router mutation out of default builds and default runtime behavior.
- Reuse authenticated observations already collected by ADR-0005 instead of
  introducing a separate NAT-probing protocol.
- Preserve relay as the reliable fallback when mapping or direct connectivity
  fails.

## Decision

Add optional UPnP-IGD support through the `upnp` Cargo feature and `igd-next`.
Runtime activation is separate:

```toml
[network.nat]
enabled = false
lease_duration_secs = 3600
```

When enabled, startup discovers an IGD gateway, obtains its external IPv4
address, and requests a TCP mapping for the node listen port when the node is
behind NAT. A successful public mapping is advertised through HELLO listen
metadata and adds a `direct_tcp` capability hint.

TheNodes compares fresh observed UDP endpoints and the gateway address to emit a
diagnostic classification:

- `unknown`;
- `upnp_mapped`;
- `cone_like` when at least two relevant observations report the same endpoint;
- `symmetric_like` when observers report different ports;
- `double_nat_likely` when public addresses disagree.

These values are diagnostics and routing hints, not protocol guarantees.

## Scope

Version 0.4.0 supports UPnP-IGD only. Mappings with a finite lease are renewed
after 75 percent of the lease duration, with a 60-second retry after failures.
PCP, NAT-PMP, gateway event subscriptions, and exhaustive NAT behavior detection
are future work.

## Consequences

- Default builds and default runtime configuration remain unchanged.
- A successful mapping improves direct TCP reachability without removing relay
  fallback.
- Routers may reject discovery or mapping; failures are surfaced as network
  events and startup continues.
- Enabling UPnP permits the node to modify compatible gateway state. Operators
  must opt in and remain responsible for whether that is acceptable on their
  network.
- Integration tests skip cleanly when no IGD device is available.

## Rejected Alternatives

- Enable UPnP by default: rejected because automatic router mutation must require
  explicit operator consent.
- Implement mapping in plugins: rejected because advertised listen addresses and
  connection hints are framework-owned transport state.
- Add PCP and NAT-PMP in the same change: deferred to keep the initial protocol
  and dependency surface narrow.
- Treat endpoint classification as authoritative NAT detection: rejected because
  a small set of observations cannot prove router behavior.

