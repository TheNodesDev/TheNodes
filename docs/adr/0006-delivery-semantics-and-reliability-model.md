# ADR 0006: Delivery Semantics and Reliability Model

- Status: Accepted
- Date: 2026-03-15
- Target: 0.3.x
- Depends on: ADR-0001 (Secure Channel Abstraction), ADR-0002 (Persistent Known Peer Store), ADR-0003 (Relay Nodes), ADR-0004 (UDP Transport with Noise Secure Sessions), ADR-0005 (NAT Traversal, Hole Punching, and Connection Preference Policy)

## Context

TheNodes now has multiple transport building blocks and path-selection rules:

- secure direct TCP via ADR-0001,
- persistent peer knowledge via ADR-0002,
- relay fallback via ADR-0003,
- direct UDP + Noise via ADR-0004, and
- multi-path connection policy via ADR-0005.

What is still missing is a framework-level answer to a simpler but more
important question:

> When a caller asks TheNodes to deliver a message, what does "delivery" mean?

Today, some delivery-related behavior already exists in transport-specific form.
For example, the relay path already has `sequence`, `ACK`, bounded retry, and
store-and-forward behavior. Those pieces are useful groundwork, but they do not
yet define a transport-independent delivery contract for the framework as a
whole.

Without such a contract:

- applications and plugins cannot reason consistently about success or failure,
- retry and duplicate behavior risk becoming transport-specific accidents,
- path switching across direct, relay, and UDP routes becomes harder to reason
  about, and
- unidirectional or no-return paths are easy to mishandle because ACK is often
  assumed implicitly.

ADR-0006 therefore sits above transport selection and below application logic.
Its role in the stack is:

```text
Application / plugin logic
    ↓
Delivery semantics (ADR-0006)
    ↓
Connection policy (ADR-0005)
    ↓
Transport options
    ├─ TCP / secure channel (ADR-0001)
    ├─ UDP + Noise (ADR-0004)
    └─ Relay fallback (ADR-0003)
    ↓
Persistent peer knowledge (ADR-0002) informs selection/hints
```

The separation is explicit:

- ADR-0005 decides how a path is selected.
- ADR-0006 decides what message behavior is promised over that path.
- The delivery layer defined by ADR-0006 delegates path choice to ADR-0005 and
  must not duplicate or bypass connection-policy routing logic.
- ADR-0002 may inform path choice and retry heuristics, but it does not define
  delivery guarantees by itself.

## Scope and boundaries

### In scope

- delivery classes / delivery modes,
- acknowledgement semantics,
- retry behavior,
- timeout behavior,
- duplicate detection and replay-window behavior,
- ordering guarantees and their scope,
- path-switching rules during delivery,
- interaction with realm policy,
- support for unidirectional or no-return paths, and
- use of persistent peer knowledge from ADR-0002 where relevant.

### Out of scope

- defining new transport protocols,
- changing the Noise handshake,
- modifying relay wire protocol details,
- defining new encryption protocols,
- designing a full congestion-control system, and
- designing or physically enforcing a data-diode transport.

### Non-goals

ADR-0006 does not:

- replace ADR-0005 connection policy,
- redesign relay framing from ADR-0003,
- redesign Noise usage from ADR-0001 / ADR-0004,
- assume that all paths are bidirectional, or
- define fan-out or broadcast delivery semantics.

ADR-0006 treats delivery as point-to-point by default. Fan-out — delivering one
logical message to multiple peers simultaneously — introduces ordering,
deduplication, and partial-failure questions that are out of scope here and are
left for a future ADR.

It defines delivery semantics over existing and future transports; it does not
redefine those transports.

### Runtime-lifetime boundary (0.3.x scope)

Unless and until a later ADR introduces durable delivery state, the guarantees
in ADR-0006 are scoped to a **live node runtime**, not across arbitrary process
crash/restart boundaries. In-flight retries, replay-window contents, ordered
buffers, and per-scope sequencing state may be lost when a node restarts.

This means ADR-0006 defines framework-level delivery behavior for a running
TheNodes instance, not durable queue semantics. Higher layers must not infer
cross-restart exactly-once or cross-restart order continuity from this ADR.

## Decision

Introduce a transport-independent, framework-owned delivery model for TheNodes.

The model defines explicit delivery classes, acknowledgement semantics,
duplicate suppression, retry and timeout behavior, ordering scope, and
path-switching rules independently of whether a message ultimately travels over
direct TCP, direct UDP, punched UDP, relay, or a future transport.

### High-level decisions

1. Delivery semantics are a framework concern, not an application/plugin concern.
2. A framework-level delivery API is the primary outbound interface for higher
  layers. Plugins and applications express delivery intent through this layer
  rather than selecting transports directly.
3. Transport selection remains owned by ADR-0005; delivery guarantees sit above
   path selection.
4. Message identity remains stable across retries and path changes.
5. Reliable delivery classes require end-to-end acknowledgement from the remote
   TheNodes node and therefore require an ACK-capable path.
6. Ordering is supported only inside an explicitly named scope; global ordering
   is not provided.
7. Unidirectional or no-return paths are first-class and are supported via a
   non-ACK-based delivery class.
8. Duplicate suppression belongs to the framework delivery layer, not only to
   applications.
9. Realm policy constrains which delivery classes and path behaviors are
   permitted in a given context.

## Decision details

## 1. Delivery API boundary

ADR-0006 is not only a statement about semantic behavior in the abstract. It
also defines the intended framework boundary where that behavior becomes
concrete.

TheNodes should expose a framework-owned delivery layer as the normal outbound
interface for plugins and higher-level components. Callers submit delivery
intent to this layer rather than selecting TCP, UDP, or relay paths directly.
The delivery layer then applies ADR-0006 semantics, delegates route selection
to ADR-0005, and uses the appropriate transport mechanisms from ADR-0001,
ADR-0003, and ADR-0004.

Higher-level components should normally send through the delivery layer, not
through transport-specific TCP, UDP, or relay send paths directly. Lower-level
transport entry points may still exist internally, but they are not the
preferred framework boundary for message sending because they bypass or weaken
the semantic contract defined by this ADR.

A conceptual delivery API boundary typically needs to accept:

- destination identity such as `node_id`,
- message payload or envelope,
- requested delivery class,
- timeout and retry budget,
- optional ordering key, and
- optional path constraints.

That boundary should also give the caller back a framework-managed handle or
result object that can expose the assigned `message_id`, allow waiting for a
terminal outcome, and optionally surface delivery lifecycle information such as
retries or path switching.

## 2. Delivery classes

ADR-0006 defines three framework delivery classes:

```rust
enum DeliveryClass {
    FireAndForget,
    Reliable,
    OrderedReliable,
}
```

These names are conceptual; final Rust type names may vary, but the semantic
separation must remain.

### FireAndForget

Characteristics:

- sender emits the message once from the perspective of delivery semantics,
- no acknowledgement is required,
- no acknowledgement-driven retry is performed,
- the class may be used on unidirectional or no-return paths,
- duplicate reception is still possible if local implementation detail,
  transport behavior, or relay behavior causes replay or re-forwarding, and
- success means the local node accepted the message for transmission under the
  selected path/policy.

FireAndForget exists because some paths may not have a reverse channel and some
message categories do not justify reliability overhead.

FireAndForget is the most basic and transport-independent delivery class and can
operate over both bidirectional and unidirectional paths. Reliable and
OrderedReliable build on additional assumptions such as the availability of a
reverse path and acknowledgement capability.

FireAndForget defines the external delivery contract: the framework does not
guarantee remote acknowledgement or reliable delivery. The implementation may
perform limited local retransmission or retry as a transport-level
optimization, but such behavior is internal and must not change the observable
delivery semantics. In particular, FireAndForget must not be interpreted as
Reliable, and duplicate delivery remains possible.

FireAndForget does not guarantee delivery, but it is not guaranteed to succeed
locally either. A FireAndForget request may still result in `NoRoute`,
`PolicyDenied`, or `UnsupportedOnPath` if the framework cannot legally or
technically dispatch the message. `LocalAccepted` means the message has been
accepted for transmission by the local node, not that transmission was possible
in all cases.

Relay store-and-forward from ADR-0003 is transport-internal behavior from the
perspective of the delivery class. A FireAndForget message that is buffered and
later delivered by a relay node still has `LocalAccepted` as its terminal success
outcome from the sender's point of view. The sender does not observe the buffering
delay.

### Reliable

Characteristics:

- sender retries until acknowledgement is received or the delivery attempt
  times out,
- bidirectional connectivity is required,
- duplicate detection is mandatory, and
- ordering is not implied.

Reliable means: either the remote TheNodes node acknowledges acceptance into the
appropriate delivery layer, or the sender receives a terminal failure or expiry
outcome.

### OrderedReliable

Characteristics:

- same acknowledgement and retry model as Reliable, and
- in-order delivery is guaranteed only inside an explicitly named ordering
  scope.

ADR-0006 does not allow global ordering. OrderedReliable requires an ordering
key such as a stream ID, conversation key, message lane, or equivalent
higher-level scope identifier. A request for OrderedReliable without an
ordering scope is invalid.

OrderedReliable delivery requires an explicit ordering scope identifier. The
ordering key MUST be stable across retries and transport/path changes. The
ordering key MUST NOT be implicitly derived from the transport. Ordering
guarantees apply only within the same ordering scope and are not global.

Reliable and OrderedReliable are intentionally separated because many messages
need reliability without the cost and statefulness of ordered release.

## 3. Delivery outcomes

The delivery layer recognizes the following conceptual outcomes:

```rust
enum DeliveryOutcome {
    LocalAccepted,
    ForwardedToTransport,
    AcknowledgedByPeer,
    DeliveryFailed { reason: DeliveryFailureReason },
    Expired,
    UnsupportedOnPath,
}
```

```rust
enum DeliveryFailureReason {
    NoRoute,
    PolicyDenied,
    RetryBudgetExhausted,
    /// Path was available at dispatch time but lost a required capability
    /// (e.g. reverse channel) before delivery completed.
    PathLostDuringDelivery,
}
```

These are canonical framework concepts. Not all delivery classes expose or use
all of them.

Examples:

- Terminal success conditions are:

```text
DeliveryClass     Terminal success condition
--------------------------------------------
FireAndForget     LocalAccepted
Reliable          AcknowledgedByPeer
OrderedReliable   AcknowledgedByPeer
```

- `ForwardedToTransport` is an internal progression state and may or may not be
  surfaced publicly.
- `ForwardedToTransport` means the delivery layer handed the message to a
  selected transport or forwarding mechanism. It does not imply that the remote
  peer received the message, nor that the message is durably stored, unless the
  specific transport explicitly provides such guarantees.
- `ForwardedToTransport` is a progression state, not a success state. A message
  that has been forwarded to a transport may still ultimately fail, expire, or
  be retried on another path.
- `UnsupportedOnPath` means the requested delivery class cannot be satisfied by
  any currently available path capability.
- `Expired` means the delivery attempt exceeded its overall delivery deadline
  before successful completion, including the case where acknowledgement never
  arrived before that deadline.

The model intentionally uses `Expired` for deadline exhaustion and reserves
`DeliveryFailed { reason: ... }` for non-deadline terminal failures such as
policy denial, route absence, capability loss, or retry-budget exhaustion.

`UnsupportedOnPath` means that the requested delivery class cannot function
over the currently available path due to technical or semantic limitations. For
example, Reliable delivery over a path with no reverse communication is
`UnsupportedOnPath`.

`PolicyDenied` means that the requested delivery class would be technically
possible over the available path, but is disallowed by realm policy,
configuration, or administrative rules.

At minimum, terminal outcomes must be available to the framework and to higher
layers that request explicit delivery completion. Intermediate states may
remain internal implementation details or be emitted only through observability
hooks.

## 4. Message identity and deduplication

Reliable delivery requires an explicit message identity.

The delivery layer therefore defines a stable `message_id` concept with the
following rules:

- Reliable and OrderedReliable messages MUST carry a stable message ID assigned
  by the originating TheNodes node.
- FireAndForget messages SHOULD carry a framework message ID when practical for
  tracing and diagnostics, but FireAndForget does not depend on acknowledgement
  semantics.
- Retransmissions MUST reuse the same `message_id`.
- Path switching MUST NOT generate a new `message_id`.

A logical message retains the same message identity across retries,
retransmissions, and transport/path switching. Changing transport, for example
from direct TCP to relay or from relay to UDP, MUST NOT create a new logical
message. Deduplication and acknowledgement operate on the logical message
identity, not on the specific transport instance.

Message IDs MUST be unique within their origin scope and collision-resistant in
practice. The recommended default is UUID v7 (time-ordered, random suffix).
An implementation may instead use a composite origin-local identifier only if it
remains safe across restart boundaries, for example by using a persisted
monotonic counter or by combining a boot/session epoch with the counter. A plain
`(node_id || monotonic_counter)` scheme is not sufficient unless restart safety
is guaranteed. Whichever format is adopted, the framework must document its
collision properties: an undetected `message_id` collision would allow a
distinct message to be silently suppressed by the deduplication layer.

Message identity may survive restart in the identifier format, but that does not
mean deduplication state survives restart. In 0.3.x, a node restart may cause a
previously seen logical message to fall outside the receiver's retained runtime
state and therefore be re-accepted.

Message identity is unique within an origin scope rather than globally. The
conceptual deduplication key is:

```text
(origin_node_id, message_id)
```

The delivery layer retains duplicate-suppression state in a replay window for a
bounded, implementation-defined retention period. Deduplication state MUST be
retained for at least as long as the maximum configured delivery timeout for that
message class. Retaining state for a shorter period than the retry window would
allow a late retransmission to escape deduplication and be delivered again.
Deduplication storage must also be bounded in time and/or size according to
implementation constraints or realm policy to prevent unbounded resource growth.

For 0.3.x, this retention requirement is defined for the lifetime of a running
node process. Persistence of replay-window state across restart is out of scope
for this ADR and would require a later durability-oriented design.

Deduplication belongs conceptually to the delivery layer, not only to the
application layer. This is required because:

- retransmissions can cross transport boundaries,
- relay and direct paths can overlap in time,
- path switching can cause the same logical message to arrive more than once,
  and
- applications should not be forced to rediscover framework-level duplicates.

For Reliable and OrderedReliable, a duplicate message that falls inside the
replay window MUST NOT be delivered again to the upper layer. The receiver
SHOULD still emit an acknowledgement indicating that the message has already
been accepted, so the sender can complete its retry loop safely.

## 5. Acknowledgement semantics

ACK semantics are defined at the TheNodes delivery layer, not at an individual
transport hop. In the context of Reliable and OrderedReliable delivery, ACK is a
framework-level acknowledgement.

ACK means:

- the remote TheNodes node received the message,
- validated it for the requested delivery class,
- accepted it into its own delivery/deduplication state, and
- for ordered scopes, recorded it into the appropriate ordering state.

ACK does not mean:

- that the application has processed the message,
- that application business logic succeeded, or
- that an intermediate relay accepted or buffered the message.

In other words, framework-level ACK means the remote TheNodes node has received
the message, validated it, and accepted it into its delivery and deduplication
layer. It does not imply that the application or plugin has processed the
message, only that the framework has accepted responsibility for it.

Therefore:

- ACK is end-to-end between TheNodes nodes, not hop-by-hop.
- Relay forwarding or relay store-and-forward does not by itself satisfy the
  `AcknowledgedByPeer` outcome.
- Reliable and OrderedReliable are unavailable on paths where return traffic is
  impossible or forbidden.

An acknowledgement emitted by a relay node indicating that the relay has
accepted or buffered a message is not equivalent to `AcknowledgedByPeer`. Only
an end-to-end acknowledgement from the destination TheNodes node satisfies the
Reliable or OrderedReliable delivery contract.

The current relay-level `ACK` message type from ADR-0003 is compatible with
this direction and may be one transport-specific carrier for the semantic ACK,
but ADR-0006 defines the meaning above the wire token.

## 6. Retry and timeout behavior

Reliable and OrderedReliable use the same high-level retry model.

The model includes:

- an initial transmission attempt,
- a retry interval,
- a retry budget, and
- an overall delivery timeout / expiry budget.

The expiry budget defines the terminal delivery deadline. If acknowledgement has
not arrived before that deadline, the outcome is `Expired` rather than a
separate timeout-specific failure reason.

Retry budget and expiry are independent limits. A delivery attempt stops when
either the retry budget is exhausted or the overall expiry deadline is reached,
whichever happens first.

The retry budget is the number of additional retransmission attempts allowed
after the initial send.

Concrete default values are implementation and configuration concerns rather
than ADR-level constants.

Retry rules:

- retries stop when an ACK is received,
- retries stop when the retry budget is exhausted,
- retries stop when the delivery attempt expires,
- retries MUST reuse the same `message_id`, and
- OrderedReliable retries MUST also reuse the same ordering scope and sequence
  identity.

Retries may switch path in cooperation with ADR-0005 connection policy and any
applicable realm policy. This means a delivery attempt may begin on one path
and continue on another if the framework decides that doing so is both allowed
and potentially useful.

If a delivery attempt requires capabilities that disappear during delivery, for
example loss of the reverse path required for ACK, the framework may attempt to
migrate the delivery attempt to another path if permitted by policy and retry
budget. If no suitable path remains, the outcome becomes
`DeliveryFailed { PathLostDuringDelivery }` or `Expired`, depending on whether
the overall delivery deadline has been reached.

Retry logic must not create infinite loops. Relay buffering, local queueing, or
path migration do not reset the retry budget automatically.

## 7. Ordering semantics

ADR-0006 explicitly rejects global ordering.

Ordering exists only within a named ordering scope, for example:

- a stream,
- a conversation,
- a message channel, or
- another caller-defined ordering lane.

OrderedReliable therefore requires a per-scope sequencing model.

If different ordering scopes are used, ordering between those scopes is not
guaranteed and may legitimately diverge.

OrderedReliable delivery may block later messages in the same ordering scope
while waiting for missing earlier messages. Implementations must therefore
define bounded buffering and a policy for what happens when earlier messages
never arrive, for example due to expiry. In such cases, the blocked ordered
delivery must fail or expire rather than being released out of order.

Conceptually, ordering state is keyed by:

```text
(origin_node_id, destination_node_id, ordering_key)
```

Inside that scope:

- messages are assigned monotonically increasing sequence numbers,
- duplicates are suppressed,
- out-of-order arrivals may be buffered within bounded implementation-defined
  limits, and
- messages are released to the upper layer in sequence order only.

If missing earlier messages do not arrive before the bounded retry/expiry model
forces completion, the blocked ordered delivery fails or expires rather than
being released out of order.

For 0.3.x, ordered sequencing is runtime-local. A sender restart may begin a
new logical sequencing epoch for a given ordering key unless and until TheNodes
adds durable sequence state. Receivers and applications must not assume that an
ordering scope survives restart with continuity guarantees.

Reliable does not imply ordering. Different ordering keys have no ordering
relationship to one another.

## 8. Path switching behavior

ADR-0005 allows the framework to use different path types:

- direct TCP,
- direct UDP,
- punched UDP, and
- relay.

ADR-0006 defines what happens when delivery crosses those path boundaries.

Rules:

- retries may switch transport/path if the chosen delivery class and policy
  permit it,
- `message_id` remains constant across retries and path changes,
- duplicate suppression treats a retransmission over a different path as the
  same logical message,
- path switching is normally transparent to the caller except through timing,
  observability, and final outcome, and
- OrderedReliable preserves order through stable ordering scope and sequence
  state, not by assuming one fixed transport path.

Path capabilities relevant to delivery semantics include at minimum:

- `HasReverseChannel`: the path supports return traffic (required for ACK),
- `CanSatisfyAck`: the remote node can send a delivery-layer ACK on this path, and
- `PolicyPermitsDeliveryClass`: realm policy accepts the requested delivery class
  on this path.

These are conceptual attributes; their concrete representation is partly owned by
ADR-0005 (path selection) and partly by realm policy. ADR-0006 requires that the
delivery layer can distinguish `UnsupportedOnPath` (the path structurally lacks a
needed capability) from `PolicyDenied` (the path has the capability but policy
forbids it) and from `PathLostDuringDelivery` (the capability was present at
dispatch but was lost before completion).

Path switching can create duplicates at the receiver if two attempts overlap.
That is expected; the delivery layer deduplication rules handle it.

If a delivery class requires ACK but all remaining feasible paths lose reverse
path capability, the framework either:

- returns `UnsupportedOnPath` immediately if no valid ACK-capable path exists at
  dispatch time, or
- transitions to `Expired` / `DeliveryFailed` if an in-flight attempt loses its
  usable paths before completion.

## 9. Unidirectional and no-return paths

ADR-0006 explicitly treats lack of reverse traffic as a path capability issue,
not as a whole-realm identity.

This matters because a deployment may contain:

- bidirectional paths,
- unidirectional paths,
- paths where ACK is technically possible but policy-forbidden, and
- future constrained links that are neither pure TCP-style sessions nor pure
  relay paths.

The framework rules are:

- FireAndForget is valid on such paths.
- Reliable and OrderedReliable require a reverse path and are therefore
  unsupported when no reverse path exists.
- The absence of a reverse path must not be hidden behind false reliability
  claims.

ADR-0006 does not define a physical data-diode transport. It only requires that
the delivery semantics model can represent paths where reverse traffic is not
available.

## 10. Realm policy interaction

ADR-0006 defines the framework's delivery vocabulary. Realm policy decides
which delivery classes are permitted in a particular context.

Examples:

- some realms may allow only FireAndForget,
- some may forbid relay for specific message categories,
- some may require reliable delivery for selected message classes, and
- some may prohibit ACK-generating traffic on particular paths.

Therefore:

- delivery-class selection is always subject to realm policy,
- policy is checked before dispatch and during path selection, and
- a path that is technically capable may still be policy-forbidden.

Policy denial is a delivery failure, not transport success.

## 11. Relationship to ADR-0002 persistent peer store

ADR-0002 may inform delivery behavior, but it does not define it.

Persistent peer knowledge may provide hints such as:

- whether a peer has recently been reachable,
- whether relay capability or store-and-forward capability was previously seen,
- whether recent delivery attempts succeeded over a direct or relay path, and
- whether a reverse path is likely based on recent observed behavior.

Those hints may influence retry-path choice or feasibility checks, but stale
peer knowledge must not override actual runtime path reality.

Delivery guarantees come from the active delivery/path state, not from the
existence of remembered peer metadata.

ADR-0002 may later become one building block for durable delivery metadata, but
that durability is explicitly not provided by ADR-0006 as currently scoped.

## 12. Recommended conceptual API types

The following conceptual model is recommended even if the final Rust names vary:

```rust
struct DeliveryRequest {
    destination: String,
    payload: Vec<u8>,
    options: DeliveryOptions,
}

enum DeliveryClass {
    FireAndForget,
    Reliable,
    OrderedReliable,
}

enum DeliveryOutcome {
    LocalAccepted,
    ForwardedToTransport,
    AcknowledgedByPeer,
    DeliveryFailed { reason: DeliveryFailureReason },
    Expired,
    UnsupportedOnPath,
}

// See section 3 for the full definition and rationale.
enum DeliveryFailureReason {
    NoRoute,
    PolicyDenied,
    RetryBudgetExhausted,
    PathLostDuringDelivery,
}

struct DeliveryOptions {
    class: DeliveryClass,
    timeout: Option<Duration>,
    retry_budget: Option<u32>,
    ordering_key: Option<String>,
    /// Constraints or hints on which transport paths are acceptable.
    /// The concrete type is defined in cooperation with ADR-0005.
    path_constraints: Option<PathConstraints>,
}

struct DeliveryHandle {
    message_id: MessageId,
    // implementation-defined status / wait mechanism
}
```

`DeliveryRequest` represents outbound delivery intent as seen by higher layers.
It is submitted to the framework delivery layer rather than to a transport-
specific send path. `DeliveryHandle` represents the framework-owned lifecycle
of that logical delivery attempt.

For `OrderedReliable`, `ordering_key` MUST be present. For FireAndForget and
Reliable, `ordering_key` is either ignored or rejected by validation, but it
must not be treated as an implicit source of ordering semantics.

The framework should also conceptually maintain per-message identity and, for
ordered delivery, per-scope sequence state.

## 13. Failure semantics

The framework must distinguish at least these failure cases:

- no route is available,
- the requested delivery class is unsupported on the currently available path,
- policy forbids the requested class or path,
- retry budget was exhausted before acknowledgement, and
- path capability needed for completion was lost after dispatch.

The framework must also distinguish deadline expiry as its own terminal outcome:

- the overall delivery lifetime expired before successful completion.

These must not be collapsed into one opaque "delivery failed" state internally,
even if a future public API chooses to expose a more compact error surface.

Duplicate re-arrival is not automatically a failure. For Reliable and
OrderedReliable, duplicate receipt within the deduplication window is treated as
evidence that the remote framework has already accepted the logical message.

## Consequences

### Positive

- TheNodes gets an explicit, framework-owned delivery contract.
- Plugins and applications can reason about success, failure, and retry without
  transport-specific guesswork.
- Relay, TCP, UDP, and future transports can coexist under one semantic model.
- Unidirectional and no-ACK paths are supported explicitly rather than as
  broken edge cases.
- Message identity and path switching become safer because duplicates are
  defined rather than accidental.

### Negative / trade-offs

- The framework becomes more stateful.
- Duplicate-suppression / replay-window state is required.
- Retry and ACK logic increase complexity.
- Ordered delivery requires per-scope sequencing and buffering state.
- Public API surfaces may need to become more explicit about delivery options
  and outcomes than they are today.
- Delivery guarantees are honest but limited: in 0.3.x they do not survive
  arbitrary node restart without additional durable state.

## Alternatives considered

### 1. Let applications define delivery semantics

Rejected.

Reasons:

- transport behavior would become inconsistent,
- plugins would reimplement reliability badly and differently, and
- message semantics would leak out of the framework.

### 2. Make everything best-effort

Rejected.

Reasons:

- path switching across relay/direct transports would be harder to reason about,
- duplicate handling would remain ambiguous, and
- many applications need explicit reliability.

### 3. Make everything reliable and ACK-based

Rejected.

Reasons:

- it fails on unidirectional or no-return paths,
- it imposes unnecessary overhead on low-value message classes, and
- it incorrectly assumes that every environment can support ACK.

### 4. Provide global ordering

Rejected.

Reasons:

- it is too expensive,
- it is unrealistic across multiple changing paths, and
- most use cases do not need it.

## Open questions

1. Should ACK mean "accepted by remote framework" only, or should some future
   classes allow stronger acknowledgement semantics?
2. Should OrderedReliable be scoped primarily by stream, plugin, conversation
   key, or a generic ordering-lane identifier?
3. Should retry budgets be global defaults, per realm, or per message?
4. How long should deduplication windows be retained in practice?
5. Should reachability history from ADR-0002 or later caches influence retry
   strategy more strongly?
6. The ADR-0003 relay path can emit a relay-level `ACK` when a relay node accepts
   a forwarded message for buffering. That relay ACK represents relay acceptance,
   not end-to-end peer acceptance. Should this intermediate state surface as a new
   `ForwardedToRelay` outcome visible to callers, be suppressed entirely as a
   transport-internal detail, or be accessible only through observability hooks?

## References

- ADR-0001: Secure Channel Abstraction
- ADR-0002: Persistent Known Peer Store
- ADR-0003: Relay Nodes
- ADR-0004: UDP Transport with Noise Secure Sessions
- ADR-0005: NAT Traversal, Hole Punching, and Connection Preference Policy
- `src/network/message.rs`
- `src/network/relay.rs`
- `src/network/peer_manager.rs`