# ADR 0015: Hole-Punch Authorization

- Status: Proposed
- Date: 2026-11-07
- Target: 0.5.0
- Amends: ADR-0005 (§5, relay-coordinated UDP hole punching)

## Context

In ADR-0005's hole punch, initiator A asks rendezvous B to coordinate a punch
to responder C (`PUNCH_COORDINATE`), B invites C (`PUNCH_INVITE`), C answers
(`PUNCH_READY`), and B sends both `PUNCH_GO` with each side's observed UDP
address and a start time. Both then send KEEPALIVE probes to the other's
address, and A starts a Noise handshake there.

As implemented:

- a node followed a `PUNCH_GO` from any connected peer, for any attempt, and
  probed whatever address it named;
- it slept until any start time the frame gave, one task per frame;
- the initiator's handshake (`connect_udp`) did not count toward the cap of
  64 concurrent handshakes;
- B handed out the `udp_observed_addr` that A and C announced in their HELLO.
  That address is a claim, so a peer could name a victim and have two honest
  nodes probe it;
- B kept every `PUNCH_COORDINATE` without a limit or an expiry, a new one
  with an attempt ID in use replaced that attempt, and a
  `PUNCH_READY { ok: false }` from any peer ended an attempt;
- a node used any peer that announced `punch_rendezvous` as its rendezvous.

## Decision

### A node follows only punches it agreed to

- The initiator records the attempt before sending `PUNCH_COORDINATE`: the
  rendezvous it asks, itself and the target, and a deadline at the end of its
  time budget.
- The responder records the attempt when it accepts a `PUNCH_INVITE`: the
  sending peer as rendezvous, the invite's initiator, itself, and a deadline
  from the invite's time budget, at most 30 seconds. It answers
  `PUNCH_READY { ok: true }` only once the attempt is recorded.
- A node takes part in at most 256 punches at once and declines further
  invitations. An attempt ID that is already recorded is not taken over.
- A `PUNCH_GO` is followed only if it comes from the recorded rendezvous,
  names the recorded initiator and responder, and arrives before the
  deadline, and only once. Any other `PUNCH_GO` is dropped
  (`punch_go_rejected`) and leaves the recorded attempt in place.
- The address to probe must be no more local than the rendezvous's own
  address, the rule gossip uses (ADR-0012, *Peer addresses*).
- The punch window starts at `start_at_ms` but never after the deadline; a
  start time beyond it abandons the punch.
- The handshake a punch starts counts toward the concurrent-handshake cap,
  like every outgoing handshake (ADR-0013).

### The rendezvous hands out only addresses it observed

A rendezvous records the source of every `OBSERVE_REQ` whose cookie it
validated (ADR-0005 §2); the cookie shows that the sender receives at that
address. It keeps up to 4096 sources, each for twice the observation refresh
interval. It sends `PUNCH_GO` only if both peers' announced addresses are
among them, and otherwise drops the attempt (`punch_address_unverified`).
Peers already observe their address through their rendezvous-capable peers,
so a working punch is unaffected.

### The rendezvous bounds what it coordinates

- A rendezvous coordinates at most 1024 punches at once, and at most 16 for
  one initiator. Each attempt lasts only for its time budget, at most 30
  seconds.
- Attempt IDs are at most 128 bytes, on the rendezvous and in the attempts a
  node records.
- A `PUNCH_COORDINATE` beyond these limits, or with an attempt ID already in
  use, is refused with `PUNCH_ABORT` (reason `overload`) and a
  `punch_coordinate_refused` event. It never replaces another attempt.
- Only the invited responder's `PUNCH_READY` settles an attempt.

### Choosing a rendezvous

`[network.nat_traversal] allowed_rendezvous` lists the node IDs this node may
use as rendezvous. When it is set, the node asks only listed peers to observe
its address or coordinate a punch, and accepts a `PUNCH_INVITE` only from a
listed rendezvous; an empty list allows none. When it is unset, any peer that
announces `punch_rendezvous` may be used. The list names node IDs, so it is
as strong as their binding (ADR-0012).

No message format changes.

## Consequences

- A peer can no longer make a node probe an address of its choosing. It
  needs an attempt the node agreed to, and the rendezvous must have seen the
  address answer a cookie challenge, which a host that does not run TheNodes
  never does.
- A malicious rendezvous can still steer a punch it coordinates, but only for
  attempts the nodes agreed to, one window each, within the scope rule.
- A punch fails when the rendezvous did not observe both peers itself, for
  example when they observed their addresses through another node.
- Pending punches are bounded in number and time on every node.
- Without `allowed_rendezvous`, any peer that passes the trust policy can
  offer itself as rendezvous and steer the punches it coordinates.

## Rejected Alternatives

- **Bind the observation to the node through its nonce.** `PUNCH_COORDINATE`
  and `PUNCH_READY` would carry the nonce of the sender's last observation,
  and the rendezvous would use exactly the source it saw for it. That ties
  the address to the node rather than to any TheNodes host, but changes the
  wire format; the cookie check already rules out arbitrary victims.
- **Require UDP sessions between the rendezvous and both peers.** The
  session's authenticated path would be the address, but punching is meant
  for peers that cannot yet hold sessions.
