# ADR 0012: Node Identity Binding and Sender Attribution

- Status: Proposed
- Date: 2026-10-30
- Target: 0.5.0
- Amends: ADR-0002 (which peer addresses are kept and persisted), ADR-0003
  (what a relay forwards, which relays a node uses), ADR-0006 (which delivery
  acknowledgements count), ADR-0007 (which peers are reconnected)
- Relates to: ADR-0004 (UDP sessions), ADR-0008 (transport trust policy),
  ADR-0010 (relay payload framing), ADR-0016 (trusted key store)

## Context

Peers name themselves with the `node_id` in HELLO. Routing, relay bindings,
delivery acknowledgements and liveness all key on that name. The transport
trust policy (ADR-0008) decides whether a TLS certificate key or Noise static
key may connect, but before this decision nothing tied the key to the name:

- any peer that passed the trust policy could claim another member's node ID.
  Its traffic was then routed to the squatter, and the real node was refused
  as a duplicate;
- a UDP Noise session for an existing node ID replaced that node's UDP route;
- `Message::from` reached plugins exactly as the sender wrote it, so a plugin
  that authorised by `from` could be fooled by any connected peer. Delivery
  acknowledgements, ordering and relay bindings also keyed on `from`;
- senders filled `from` and `to` inconsistently: node IDs, socket addresses,
  `"TheNodes"`, `"thenodes"` and plugin labels. A receiver could not tell a
  label from a claim to be another node;
- a `RELAY_FWD` addressed to the local node was unwrapped into whatever message
  it carried, including control messages such as `PEER_LIST` or `PUNCH_GO`,
  from peers that were not connected to the local node at all;
- a relay forwarded every `RELAY_FWD` from any connected peer under whatever
  origin the frame named, without checking for a binding, and could hand a
  frame for an absent target on to another relay with no hop limit. Delivery
  receipts, hop acknowledgements and relay unbinds were accepted from any peer,
  and binding IDs were derived from the endpoints and the client's clock;
- any peer could announce the `relay` capability, and a node sent through the
  first peer that did;
- a `PEER_LIST` added every address it named to the peer store and marked it
  as reached, including loopback and private addresses from a peer on a
  public address, and HELLO's UDP addresses were used as given.

## Decision

This ADR decides what follows from knowing which node sent a frame:

- which node ID a key may use (*Binding a node ID to a key*);
- how frames name their ends and how received messages are attributed to a
  node (*Addressing frames*, *Attributing received messages*);
- what a relay forwards, and for whom (*Relay forwarding*);
- which relays a node uses (*Choosing relays*);
- which peer addresses are trusted for dialling, reconnecting and persisting
  (*Peer addresses*).

Which keys may connect at all remains the transport trust policy's decision
(ADR-0008, ADR-0016), and the delivery classes and their guarantees remain
ADR-0006's.

### Binding a node ID to a key

After the secure channel and HELLO, the node ID is checked against the key that
authenticated the connection. The check is the same for TLS and Noise, over TCP
and UDP, and is configured once:

```toml
[encryption.node_identity]
mode = "tofu"                     # off | tofu | pinned | certificate
bindings_file = "pki/node-identity/bindings.jsonl"
max_bindings = 4096

[encryption.node_identity.pins]
"<peer-node-id>" = ["<sha256-hex>"]   # another node's ID -> the fingerprints it may use
```

The evidence, strongest first:

1. **Pin.** The node ID's pinned fingerprints. A pinned node ID with another
   key, and a pinned key claiming another node ID, are rejected in every mode
   except `off`.
2. **Certificate name.** A `URI:node://<realm>/<node_id>` SAN in the TLS
   leaf, where `<realm>` is the realm's canonical code. Each realm is its own
   namespace: only names in this node's realm count, so a certificate naming
   a node in another realm certifies nothing here, even from the same CA. A
   name that does not match the claim is rejected in every mode except
   `off`. The name binds the node ID by itself only when the chain validated
   against the configured trust anchors (`enforce_ca_chain`). A self-signed or
   allowlisted certificate's name is a claim, because whoever holds the key
   can mint a certificate with any name.
3. **TOFU.** The first fingerprint accepted for a node ID, kept per key kind
   (TLS or Noise) in memory and, when `bindings_file` is set, appended to a
   JSON-lines file. A CA-certified name replaces an older TOFU binding, so key
   rotation under a CA needs no operator action.

`tofu` (the default) accepts any of the three; `pinned` requires a pin;
`certificate` requires a certified name or a pin; `off` restores self-asserted
node IDs. A connection without a transport identity (plaintext, or TLS without
mTLS on the accepting side) carries an unverified node ID. `tofu` accepts it
unless the node ID is pinned or already bound to a key; the strict modes reject
it. When the binding store holds `max_bindings` entries, a node ID seen for the
first time is rejected, since a binding that cannot be recorded would leave the
node ID free for the next key.

Checking and recording are separate. The connection is checked, then its
TOFU binding is recorded, and only then is the peer registered, since
registration hands it queued messages. A binding that can no longer be
recorded (another connection bound the node ID in between, or the store
filled up) refuses the connection, and a recorded binding is never
overwritten by a later claimant. A key the transport trust policy accepts on
first use is added to the trusted store after the binding is recorded
(ADR-0016). Node IDs must be 1-128 ASCII letters, digits, `-`, `_` or `.`.
An invalid configuration stops the standalone host at startup and rejects
every node ID in library use.

### Addressing frames

`from` and `to` on the wire always name the two ends of the hop that carries
the frame: the node that sent it and the peer it was sent to. The transport
sets them. Each TCP connection's writer knows both node IDs once the HELLO
exchange has succeeded and stamps them on every frame it writes; the UDP send
path does the same with the session's node. Code that sends a message does not
address it, and `Message::outbound` builds one without `from` and `to`.

HELLO is written before the connection is registered and follows the same rule
directly: `from` is the HELLO's `node_id`. The accepting side sends the first
HELLO before it knows which node connected, so that HELLO leaves `to` empty;
the reply names the accepting node. A HELLO that breaks this closes the
connection.

The endpoints of a relay tunnel are carried by the `RELAY_FWD` frame's own
`from` and `to` fields and by the inner message, never by the outer frame's
`from` and `to`.

### Attributing received messages

Every received message is attributed to the node bound to the connection or
UDP session that delivered it. `Message::origin()` returns a `MessageOrigin`
that the host sets and the wire never carries:

- a frame whose `from` is not the delivering node, or whose `to` is not the
  local node, is dropped with a `message_rejected` event. A direct message's
  `from` is therefore the delivering node, and
  `origin().authenticated_sender()` returns that node when its node ID is bound
  to a transport identity;
- a `RELAY_FWD` addressed to the local node is unwrapped only when its payload
  is a `TEXT`, `DATA_REQUEST`, `DATA_RESPONSE`, `EXTENSION` or `DELIVERY_ACK`
  message whose `from` and `to` match the tunnel. The unwrapped message keeps
  its `from`, and `origin().relayed_from` marks it as relayed. The relay only
  forwards tunnels whose origin is its own sending peer (see *Relay
  forwarding*), so the origin is as trustworthy as the relay, but it has no
  authenticated sender.
  Tunnels with an opaque payload are delivered as the `RELAY_FWD` frame
  itself;
- a `DELIVERY_ACK` counts only when it comes from the node the acknowledged
  message was sent to, directly or as the origin of a tunnel. A reliable
  message is acknowledged along the path it arrived on: directly, or through
  the relay that delivered it. This narrows ADR-0006's end-to-end
  acknowledgement, which any peer could previously give.

A connection whose peer has been deregistered, for example by the liveness
monitor, is closed on its next frame.

### Relay forwarding

This amends ADR-0003's forwarding phase, in which a relay forwarded frames
between bound clients without checking which node sent them. A relay knows
which node sent each frame and forwards only what that node is entitled to
send:

- A `RELAY_FWD` is forwarded only for a binding the sending peer created with
  `RELAY_BIND`, while the binding is live, and only when the frame's `from`
  field names the sending peer. Other frames are refused with
  `RELAY_NOTIFY{type:policy_denied}`, or `timeout` for an expired binding, and
  a `relay_forward_rejected` event. An expired binding can be replaced by a new
  `RELAY_BIND`.
- A relay forwards only to targets connected to it, or queues for
  store-and-forward. It never hands a frame to another relay, so frames cannot
  loop between relays. The `network.relay.selection` setting that enabled
  relay-to-relay forwarding is removed.
- Binding IDs are random. `RELAY_UNBIND` removes a binding only when sent by the
  node that created it.
- A hop-level `ACK` counts only when sent by the target the frame was forwarded
  to.
- A client may hold 64 bindings. Its bindings, their sequences and in-flight
  forwards end with its connection.

### Choosing relays

`[network.relay] allowed_relays` lists the node IDs this node may use as
relays. When it is set, only a listed peer is chosen; an empty list allows
none. When it is unset, any peer that announces `relay` may be chosen. The
list names node IDs, so it is as strong as their binding: with `pinned` or
`certificate`, only the holder of the pinned key or certified name can be
chosen.

The list decides which relay this node sends through, not which relay may
deliver to it. A relayed message from any relay is accepted, and acknowledged
through the relay that delivered it.

### Peer addresses

The listen address in a HELLO is a claim, like the node ID before binding. An
address is verified only when this node dials it and reaches the node over a
connection that passed node identity binding. Only verified addresses suppress
a dial to the same address, drive a reconnect, or are written to the peer
store; a claimed address is only tried as a delivery route. A node therefore
reconnects to peers it dialled, and a peer that connected in reconnects
itself. What a peer announced in HELLO is forgotten once it has neither a TCP
connection nor a UDP session.

An address a peer reports is used only if it is no more local than the peer
that reported it: a peer on a public address can name only public addresses,
a peer on the same LAN also LAN addresses, and a peer on loopback any address.
Unspecified, multicast and broadcast addresses and port 0 are never used. The
rule applies to the addresses in a `PEER_LIST`, at most 64 per list, which are
kept as unverified candidates, and to the UDP listen and observed addresses
in HELLO, to which the node sends observation requests, handshakes and probes.
A node answers `PEER_REQUEST` only with addresses it has connected to.

This amends ADR-0002, which persisted the address of every connected peer and
every gossiped one, and ADR-0007, which reconnected every peer with a known
listening address: both now use verified addresses only.

## Consequences

- A trusted peer can no longer take over a node ID that is pinned, certified,
  or already bound. In `tofu` mode a node ID that this node has never seen can
  still be claimed first; deployments that need more use `pinned` or
  `certificate`.
- Keys rotated outside a CA are rejected in `tofu` mode until the operator
  runs `thenodes-ctl node-binding forget <node_id>` and restarts the node.
- Plugins have a sender they can authorise on. Relayed messages remain
  unauthenticated end to end. ADR-0003's description of relayed payloads as
  opaque end to end is not implemented yet.
- `node_type` and HELLO capabilities remain self-declared and are not an
  access-control boundary. Without `allowed_relays`, any peer that passes the
  trust policy can offer itself as a relay and read or alter what is relayed
  through it.
- Frame addressing is a wire change: nodes from earlier versions, which write
  labels into `from`, cannot connect.
- With TLS but without mTLS, the accepting side never sees the client's key.
  A node this node has dialled, and so bound, cannot connect back inbound in
  `tofu` mode; such deployments need `[encryption.tls] mtls`.
- A target that is not connected to the relay a client chose is reachable
  only through store-and-forward on that relay.
- A node does not redial a peer that connected to it. Deployments in which
  only one side can dial keep working; where both sides dial, the side that
  dialled reconnects.

## Rejected Alternatives

- **Derive the node ID from the key.** Binding would be implicit, but node IDs
  would become hex digests and every configuration, bootstrap list and plugin
  that addresses nodes by name would break.
- **Certificate names only.** Strong with a CA but unavailable for Noise and
  for self-signed deployments, which are the common case today.
- **Rewrite `from` on receipt.** Replacing `from` with the delivering node
  makes it trustworthy without changing senders, but leaves `from` meaning
  different things on the wire and silently corrects frames that should be
  refused.
- **A separate field for the sending node or its socket address.** Once
  senders stop writing labels into `from`, it is the sending node. The socket
  address is known from the connection and does not belong in the frame.
- **Keep relay-to-relay forwarding with a hop limit.** A hop limit stops loops,
  but the second relay sees the first relay as the sender and would have to
  accept the origin it names. Any peer can claim the `relay` capability, so
  that would reopen origin spoofing.
