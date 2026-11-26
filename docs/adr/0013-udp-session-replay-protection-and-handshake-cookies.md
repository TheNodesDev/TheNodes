# ADR 0013: UDP Session Replay Protection and Handshake Cookies

- Status: Proposed
- Date: 2026-10-31
- Target: 0.5.0
- Amends: ADR-0004 (session frames, `HANDSHAKE_MSG1`, DoS limits)

## Context

ADR-0004 carries established UDP traffic as `[session_id][ciphertext]`, where
the ciphertext comes from a stateful Noise transport. Its nonce is implicit and
must advance by one with every frame, so:

- one lost or reordered datagram made every later frame fail to decrypt. The
  session stayed registered as the node's UDP route while delivering nothing,
  and the peer's keepalives kept it from being reaped;
- `HANDSHAKE_MSG1` with the `session_id` of an existing session replaced it.
  Session IDs travel in clear in every data frame, so anyone on the path could
  tear down a session with one datagram;
- a `HANDSHAKE_MSG2` or `HANDSHAKE_MSG3` with a known `session_id` that did
  not advance the handshake removed the session, even an established one,
  whatever address it came from;
- the responder performed a Diffie-Hellman for every msg1 before learning
  anything about the sender. The per-IP rate limit and the cap of 64
  concurrent handshakes counted spoofed source addresses, so a stream of
  spoofed msg1 datagrams could hold every handshake slot. The reaper ran every
  30 seconds although handshakes expire after 5;
- a `KEEPALIVE` from a session's address refreshed that session, without any
  authentication, and was matched by scanning every session.

## Decision

### Explicit nonces and a replay window

Session frames carry the Noise transport nonce:

```
[ session_id: 8 ][ nonce: 8, little-endian ][ ciphertext: N ]
```

Each side counts its own nonces from zero and uses Noise in stateless
transport mode, so a frame decrypts on its own. The receiver keeps a replay
window of 1024 nonces: it accepts a nonce above the highest it has seen, or
one up to 1023 below it that it has not accepted yet. The window is checked
before decrypting and updated only after the frame authenticated; only then
are `last_seen` and the session's path (`peer_addr`) updated. A replayed or
too old frame is dropped (`udp_frame_replayed`, at debug level). A session
whose send nonce reaches 2^64 - 1, which Noise reserves, refuses to send.

The largest application payload shrinks from 1176 to 1168 bytes.

### Handshakes cannot take over or end a session

A `HANDSHAKE_MSG1` whose `session_id` names an existing session, established
or still handshaking, is dropped (`udp_hs_session_id_in_use`).

`HANDSHAKE_MSG2` and `HANDSHAKE_MSG3` count only when they come from the
session's peer address, and never for an established session. A message that
does not verify leaves the handshake as it was, so the genuine message can
still complete it. A session is removed only when its handshake can no longer
continue.

### Handshake cookies under load

`HANDSHAKE_MSG1` gains a cookie field:

```
HANDSHAKE_MSG1   [ session_id: 8 ][ cookie_len: 1 ][ cookie ][ noise msg1 ]
HANDSHAKE_COOKIE [ session_id: 8 ][ cookie_len: 1 ][ cookie ]      (0x13)
```

Normally an initiator sends an empty cookie and the responder proceeds. When
half of the concurrent-handshake slots are taken, or the sender's IP has used
its handshake rate, the responder replies with `HANDSHAKE_COOKIE` instead of
performing a Diffie-Hellman. The reply is smaller than the msg1 it answers.
The cookie is `SHA-256(secret ‖ time bucket ‖ source address ‖ session_id)`
truncated to 16 bytes, from a per-process secret, and is valid for the current
and previous 30-second bucket, so the responder keeps no state for it. The
initiator resends its original msg1 with the cookie, at most twice per
handshake, and only for a cookie from the address it sent msg1 to.

A msg1 with a valid cookie comes from a sender that receives at its source
address. The per-IP rate limit and the concurrent-handshake cap then apply to
real addresses.

### Housekeeping

- The cap of 64 concurrent handshakes counts the handshakes a node starts
  (`connect_udp`, including those a hole punch starts, ADR-0015) as well as
  those it answers.
- The reaper runs every 5 seconds, the handshake expiry, and expired
  handshakes are also dropped before the concurrent-handshake cap is checked.
- Per-IP rate entries are dropped once their one-second window has passed.
- `KEEPALIVE` changes no state. It only opens NAT mappings during hole
  punching; sessions stay alive through authenticated frames.
- Pending `OBSERVE_REQ` correlations expire after 30 seconds, and stored
  observations of this node's address are dropped once they are older than
  the observation refresh window.

## Consequences

- UDP sessions survive loss and reordering, and replayed frames cannot move a
  session's path or keep it alive.
- An on-path observer can no longer reset a session by reusing its ID or by
  forging handshake messages.
- Spoofed handshakes cost the responder a hash and a 33-byte reply instead of
  a Diffie-Hellman and a handshake slot. Under load, a legitimate handshake
  takes one more round trip.
- The session frame and `HANDSHAKE_MSG1` formats change; nodes from earlier
  versions cannot establish UDP sessions with this version.
- Sessions are not rekeyed. At one frame per microsecond the nonce space lasts
  over half a million years.

## Rejected Alternatives

- **Always require a cookie.** Simpler, but every UDP session, including hole
  punches, would pay an extra round trip.
- **Reset the session on a decrypt failure.** Recovers from loss, but any
  forged datagram would then tear the session down.
- **A 64-nonce window.** Smaller, but reordering on busy paths can exceed it;
  1024 nonces cost 128 bytes per session.
