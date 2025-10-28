# Events Reliability & Consensus Preparation Plan

Date: 2025-10-05
Status: Draft (Foundational design; implementation to be phased)
Owners: Core Runtime / Observability / (Future) Consensus Plugin Authors

---
## 0. Goals
1. Provide configurable reliability tiers for the event system, ranging from lightweight (in-memory) to strong durability with per-sink exactly-once semantics.
2. Eliminate silent event loss unless explicitly configured (and observable via counters/events when configured).
3. Prepare architecture for future BFT / consensus plugins without overloading the event system with deterministic protocol traffic.
4. Preserve backward compatibility for existing deployments (default remains lightweight).

---
## 1. Event Reliability Tiers

| Tier (Mode)   | Config `events.mode` | Persistence | Replay to Sinks | Duplicate Risk | Use Case |
|---------------|---------------------|-------------|-----------------|----------------|----------|
| 1. Memory     | `memory`            | No          | No              | N/A            | Dev, low criticality, minimal overhead |
| 2. Durable    | `durable`           | WAL         | No              | N/A            | Forensic audit (post-mortem), compliance storage |
| 3. Replay     | `replay`            | WAL         | Yes (At least once) | Yes (idempotent sinks needed) | Crash recovery with guaranteed delivery |
| 4. Exact Once | `exact_once`        | WAL + per-sink acks | Yes (only unacked) | No (per-sink) | Safety/security critical sinks, side-effect sensitive |

Notes:
- Tiers are strictly additive in guarantees and complexity.
- Tier 4 does not improve "loss" guarantees beyond Tier 3; it eliminates duplicates.

---
## 2. Configuration Additions

`[events]` section (new) — initial proposed keys:
```toml
[events]
mode = "memory"              # memory | durable | replay | exact_once
buffer_capacity = 4096        # bounded channel capacity
backpressure = "block"       # block | drop_new | drop_oldest
wal_dir = "logs/event_wal"
segment_max_bytes = 8388608   # 8MB rotation
sync_mode = "interval"       # always | interval | os
sync_interval_ms = 200        # only for interval mode
batch_flush = 32              # 0 = flush each append
max_replay_events = 0         # 0 = no limit (replay all)
acks_commit_interval_ms = 500 # only used for exact_once
```

Future/optional:
- `encryption = true` (encrypt WAL segments at rest)
- `checksum = true` (CRC32 / BLAKE3 per line or segment)
- `priority_separation = true` (multi-queue dispatch)

---
## 3. Event Envelope Evolution

Introduce `EventEnvelope` to wrap current `LogEvent`:
```rust
struct EventEnvelope {
    seq: u64,
    ingested_ts: SystemTime,
    meta: EventMeta,      // meta.ts = logical event time; meta extended (see below)
    event: LogEvent,
}
```
New fields in `EventMeta` (backward compatible):
- `priority: EventPriority` (Critical | High | Normal | Low) (default Normal)
- `schema_version: u16` (default 1)
- `parent_corr_id: Option<String>` (causal chain support)

### Rationale
- Allows deterministic hashing/log anchoring independent of JSON internal structure changes.
- Facilitates future Merkle commitments & selective replay filters.

---
## 4. WAL (Write-Ahead Log) Design

Format: Line-delimited JSON (Phase 1), each line is a serialized `EventEnvelope`.

Segment naming:
```
wal_dir/
  events.00000001.wal
  events.00000002.wal
  index.json            # last_seq, active segment, optional hash roots
  acks.json             # (Tier 4 only) per-sink ack map
```

Rotation Trigger: `segment_max_bytes` exceeded after write.

Index file example:
```json
{ "last_seq": 123456, "active_segment": "events.00000009.wal" }
```

Sync Policies:
- `always`: fsync after every append (highest durability cost)
- `interval`: buffered writes, fsync at interval or on rotation (default)
- `os`: rely on OS flush (fastest, weakest crash window)

Batching: accumulate up to `batch_flush` envelopes before write/flush to reduce syscalls.

Future-proofing: Each segment may later include a header line (e.g., `{"segment":1,"encoding":"jsonl","schema":1}`) enabling binary encoding upgrade without breaking earlier segments.

---
## 5. Ingestion & Backpressure

### Current (Baseline)
- `try_send()` → drops silently when full.

### New Policy
1. Determine mode:
   - If `backpressure = block`: use `send().await` (producer stalls when full).
   - If `drop_new`: attempt `try_send`; if full, increment `DROPPED_EVENTS`.
   - If `drop_oldest`: maintain an auxiliary deque; pop_front then try again.
2. If `mode != memory`:
   - Assign seq (atomic increment).
   - Append to WAL (respect batch + sync mode).
   - On success, enqueue.
3. Emit periodic `SystemEvent` summarizing drops and queue utilization.

Atomic counters:
- `events_emitted_total`
- `events_durable_total`
- `events_dropped_total`
- `wal_flush_total`

---
## 6. Replay (Tier 3)
On startup if mode is `replay` or `exact_once`:
1. Scan `index.json` → start from first segment.
2. Stream envelopes in order (bounded by `max_replay_events` if > 0).
3. Dispatch to sinks using same channels (mark each as replay phase until done).
4. After replay completion, switch to live ingestion.

Duplicates: Allowed; sinks must be idempotent.

---
## 7. Exact Once (Tier 4)
Per-sink persistence & selective redelivery.

Per-sink state:
```json
{
  "sinks": { "console": 1200, "json_file": 1200, "webhook_v1": 1194 },
  "last_persisted": 1200
}
```

Mechanics:
- Each sink gets a unique stable `id`.
- Dispatcher loads `acks.json` → computes min ack.
- Replay only events with `seq > last_acked[sink]` per sink.
- Delivery path adds envelope to sink-specific bounded channel; sink processes.
- On completion, sink calls `ack(seq)` (auto or explicit based on sink property).
- Acks batched & persisted every `acks_commit_interval_ms` or N events.
- Segment GC: segment deletable when all sinks have acked >= segment max seq.

Fallback/Degradation:
- If `acks.json` write fails repeatedly → log `SystemEvent` and degrade to `replay` mode (flag set) until recovery.

---
## 8. Sink Trait Evolution

Initial extension (non-breaking):
```rust
#[async_trait]
pub trait LogSink {
    fn id(&self) -> &str { "anon" }                 // default for legacy
    fn exact_once_capable(&self) -> bool { false }   // must override to participate in Tier 4
    async fn handle(&self, env: &EventEnvelope);
}
```

For explicit ack sinks (optional future): provide `AckHandle` injected at creation; if not used, auto-ack after `handle` returns.

Registration rules in Tier 4:
- If sink not `exact_once_capable` → disallow or warn and treat it in a shadow (at-least-once) path.

---
## 9. Consensus Plugin Preparation

Consensus (BFT) will NOT use the event bus for deterministic protocol progression.

Early accommodations:
1. Add `priority` (so consensus audit events won’t be blocked by low-priority floods).
2. Reserve naming: `component="consensus"` or `namespace="consensus"` (future field).
3. Document: event system = observability/audit, not state input.
4. Provide stub module (future): `consensus_substrate` with trait placeholders:
   - `ConsensusEngine`
   - `ReplicatedState`
   - Log abstraction for deterministic feed (separate from event WAL).

Out of scope now: message scheduler, quorum certificates, Merkle segment hashing.

---
## 10. Security & Integrity Enhancements (Future)
| Item | Purpose |
|------|---------|
| Line checksums | Corruption detection per event (CRC32 / BLAKE3) |
| Segment Merkle root | Tamper-evident anchoring / inclusion proofs |
| WAL encryption | Confidential events at rest |
| Classification labels | Selective sink routing (Public/Internal/Confidential) |
| Rolling policy checksum | Associate trust decisions with policy version fingerprint |

---
## 11. Observability & Health
Periodic (every 10s) `SystemEvent` sample:
```
{ "type":"system", "action":"events_health", "detail":"queued=128 dropped=0 wal_lag=0 mode=replay" }
```
Expose programmatic snapshot (future):
```rust
struct EventHealth { queue_len: usize, dropped: u64, mode: EventsMode, wal_pending_flush: usize }
```

---
## 12. Migration & Backward Compatibility
- Default mode: `memory`. Existing configs unaffected.
- `init_default_events()` becomes wrapper reading `[events]` if present.
- Legacy sinks without `id()` unsupported only in Tier 4 (warn & ignore or treat as transient). Document requirement.

---
## 13. Phased Implementation Plan

| Phase | Scope | PR Milestones |
|-------|-------|---------------|
| 1 | Backpressure + counters + EventEnvelope (seq, priority, schema_version) (memory mode only) | Add config parsing, update dispatcher, tests for drop/block behavior |
| 2 | WAL append + rotation (durable mode) | WAL writer module, unit tests (append, rotate), crash simulation test |
| 3 | Replay (replay mode) | Startup scan, limited replay test, idempotency guidelines doc |
| 4 | Exact-once skeleton | Sink ID trait extension, acks.json persistence, selective delivery, GC basic |
| 5 | Hardening | Failure injection, metrics events, segment deletion, stress tests |
| 6 | Optional | Checksums, Merkle, encryption, classification |
| 7 | Consensus prep | Stub consensus traits module + docs, priority usage demonstration |

Parallel docs updates each phase.

---
## 14. Testing Strategy Overview
- Unit: WAL writer (append, rotate, recover index), ack store persistence.
- Property: Replay invariants (monotonic sequence, no gaps, duplicates only in replay mode).
- Stress: High-throughput emission under block vs drop policies.
- Fault injection: Simulate fsync failure, partial segment truncation, ack file corruption.
- Integration: End-to-end: emit → restart → replay → verify counts.

---
## 15. Open Questions (To Resolve Before Phase 3)
1. Accept JSON only or plan early for binary envelope encoding negotiation? (Recommend: add segment header now.)
2. Minimum viable set of sinks required to be exact-once? (Likely only critical external export sinks.)
3. Policy for non-capable sinks in exact_once mode (fail vs degrade)? (Recommend: warn + treat as at-least-once.)
4. Need for a `flush()` API for latency-sensitive sinks? (Maybe Phase 2.)

---
## 16. Immediate Next Steps
1. Implement Phase 1 skeleton (envelope + block/drop config) – small patch.
2. Draft WAL writer module API & integration point.
3. Add `[events]` parsing and fallback to existing default if absent.
4. Update README / developer docs with new modes and constraints.

---
## 17. Appendix: Minimal WAL Writer Interface (Draft)
```rust
pub struct WalWriter { /* hidden */ }
impl WalWriter {
    pub async fn open(cfg: &WalConfig) -> io::Result<Self>;
    pub async fn append(&mut self, env: &EventEnvelope) -> io::Result<()>; // internal buffering
    pub async fn flush(&mut self) -> io::Result<()>;  // force write
    pub async fn rotate_if_needed(&mut self) -> io::Result<()>;
    pub fn last_seq(&self) -> u64;
}
```

`WalConfig` includes: dir, segment_max_bytes, sync_mode, sync_interval, batch_flush.

---
## 18. Non-Goals (For Now)
- Using event WAL as the deterministic consensus log.
- Cross-node replication of event stream (future optional replication plugin).
- Built-in cryptographic notarization (future enhancement).

---
## 19. Risk & Mitigation Snapshot
| Risk | Mitigation |
|------|------------|
| Complexity creep (Tier 4) | Implement only after measuring real need; keep behind feature flag |
| Performance regression | Bench with synthetic event flood pre/post each phase |
| Plugin breakage | Maintain backward trait defaults; version docs clearly |
| Disk growth | Segment GC by ack + retention policy config |
| Silent drops persist | Add mandatory counter + periodic health events |

---
End of Plan.
