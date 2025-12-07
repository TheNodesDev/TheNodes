# ADR 0002: Persistent Known Peer Store

- Status: Accepted
- Date: 2025-12-06
- Target: 0.2.x (incremental, non-breaking)

## Context
Peers discovered at runtime (via successful connections and gossip) are lost on restart, reducing reconnect efficiency, discovery resilience, and boot time. We need a bounded, TTL-governed persistence of known peers across runs.

## Decision
- Add an on-disk peer store with minimal metadata per entry:
  - `addr: SocketAddr`, `source: {Bootstrap|Gossip|Connected}`, `last_seen: UnixTime`
  - Optional: `node_id`, `capabilities`
- Persist policies:
  - Bounded by `max_entries`; drop oldest or LRU beyond cap
  - TTL expiry via `ttl_secs` filter on load
  - Periodic flush governed by `save_interval_secs`
- Realm isolation: store is realm-bound (per file or per-entry realm code) to avoid cross-realm pollution.
- Update triggers:
  - On successful connect/register (`source=Connected`, update `last_seen`)
  - On receiving `PeerList`/discovery (`source=Gossip`)
  - On bootstrap seeding (`source=Bootstrap`)
- Startup load: read, expire by TTL, cap to `max_entries`, hydrate in-memory `PeerStore`, optionally enqueue early dial attempts with backoff.

## Configuration
Under `network.persistence`:
- `enabled: bool`
- `path: string` (e.g., `data/peers.json`)
- `max_entries: u32` (default 1024)
- `ttl_secs: u64` (default 7 days)
- `save_interval_secs: u64` (default 60)

## Format
Compact JSON or TOML. Example JSON entry:
```
{
  "addr": "203.0.113.10:7447",
  "source": "Gossip",
  "last_seen": 1733430000,
  "node_id": "node-abc",
  "capabilities": ["relay"]
}
```

## Privacy & Security
- Store minimal metadata; no payloads or logs.
- Respect realm policies; separate per realm.
- Future option: encrypt file if realms require it (not default).

## Alternatives Considered
- Ephemeral only: slower recovery, less resilient.
- DB-backed store: heavier footprint; not necessary initially.
- Plugin-managed persistence: possible later; core implementation ensures baseline behavior.

## Implications
- Code: extend `src/network/peer_store.rs` with `load_from_file`/`save_to_file` and periodic flushing.
- Bootstrap/Transport: update on events (connect, gossip) and load at startup.
- Config parsing: add keys in `src/config.rs`.
- Tests: TTL expiry, cap enforcement, roundtrip, realm isolation.

## Migration
Disabled by default; enabling adds a file to `path`. No breaking changes.

## References
- Related: `docs/adr/0001-secure-channel-abstraction.md`
- Complements: Relay selection/discovery in `docs/adr/0003-relay-nodes.md`
