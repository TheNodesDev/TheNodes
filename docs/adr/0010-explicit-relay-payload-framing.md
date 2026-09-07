# ADR 0010: Explicit Relay Payload Framing

- Status: Accepted
- Date: 2026-09-07
- Target: 0.4.0
- Supersedes: the `RELAY_FWD` wire shape described by ADR-0003

## Context

`RELAY_FWD` previously carried forwarded bytes in the generic outer
`Message.payload`. That made the forwarding envelope implicit and allowed relay
control metadata and end-to-end application data to be confused.

## Decision

`MessageType::RelayForward` owns an explicit `opaque_payload_b64` string:

```json
{
  "from": "outer-from",
  "to": "relay-1",
  "msg_type": {
    "RELAY_FWD": {
      "to": "node-b",
      "from": "node-a",
      "sequence": 128,
      "opaque_payload_b64": "<base64>"
    }
  },
  "payload": null,
  "realm": null
}
```

The outer `Message.payload` must be `null` for relay-forward frames. Deserialization
rejects malformed base64 and rejects frames that use both payload locations.
Forwarding, retry, reliable delivery, and store-and-forward paths preserve the
encoded value verbatim. Relays do not decode or interpret the application bytes.

This is an intentional breaking wire change. Mixed 0.3.x and 0.4.x relay paths
are unsupported and deployments must upgrade relay participants together.

## Consequences

- The relay wire contract clearly separates routing metadata from opaque data.
- Binary payloads remain compatible with line-delimited JSON.
- Existing callers must use relay payload builders or base64-encode bytes into
  `opaque_payload_b64`.

