# Authenticated TOS Messenger channel

The `tos_messenger` channel drains events from `tos-messengerd`'s production
runtime socket. It is deliberately separate from `tos_messenger_lab`: the lab
carrier is plaintext acceptance tooling, while this adapter only sees an event
after the daemon has authenticated, decrypted, admitted, and durably staged it.

```json
{
  "channels": {
    "tos_messenger": {
      "enabled": true,
      "socket_path": "/run/user/1000/tos-messengerd/runtime.sock",
      "poll_interval_ms": 250,
      "lease_seconds": 30,
      "routes": [{
        "chat_id": "room_<64 lowercase hex>",
        "conversation_id": "conv_<64 lowercase hex>",
        "room_id": "room_<same 64 lowercase hex>",
        "membership_epoch": 7,
        "session_id": "ses_<64 lowercase hex>",
        "recipient_endpoint_id": "mep_<64 lowercase hex>",
        "lifetime_seconds": 86400
      }]
    }
  }
}
```

The adapter lists pending events, takes a bounded application lease, and accepts
the strict `text`, `room.message`, and `room.moderation` payload profiles. It independently
reparses the event, checks daemon metadata against the document, recomputes the
content-addressed Event ID, and decodes the domain-separated canonical body.
For `room.message` it additionally binds the body Room ID to the Event Room ID
and requires a non-zero membership epoch, then publishes it as an OpenFox
`group`/`room` input. Unknown, substituted, cross-room, or malformed events are
rejected before the OpenFox bus.

`room.moderation` is never published as user text. The adapter independently
decodes its canonical Room ID, authority revisions, target Event ID, action and
reason, then publishes a typed runtime control. OpenFox completes the daemon
lease only after a gap-free per-target decision is durable in the session
store. An exact replay is idempotent; a revision gap, an untrusted control, or
damaged overlay state fails closed and leaves the lease available for retry.

On `hide`, already-applied history is projected as
`[message hidden by room moderation]`; the stored immutable original is not
placed in the provider-facing `Message`, and the target contributes no action
provenance. A running turn for that room is conservatively aborted so it cannot
schedule further model/tool work from withdrawn input. `restore` recovers the
stored original. If the target has not reached this OpenFox instance, a durable
tombstone prevents a later/out-of-order copy from becoming model-visible.

For accepted input it sets `AuthenticatedMessagingOrigin` from the verified
Agent, Endpoint, Device, Event, conversation, kind, and daemon receive time.
That typed metadata is persisted by the Agent runtime but omitted from model
provider payloads; tool and custody authorization use it as non-model-controlled
provenance.

`Send` accepts only a response whose context carries the exact authenticated
Messenger Event it is answering and whose chat has an operator-configured
route. OpenFox sends only message semantics to `outbox.compose`; the daemon
owns sender identity, network, clock, kind, payload schema and Event ID. The
configured conversation/room/session/recipient binding is never taken from
model output. A stable idempotency key derived from the authenticated input,
exact response and route makes process retries return the same Event ID;
content or recipient substitution is refused by the daemon's durable claim.
The daemon may honestly remain queue-only when no production transport is
configured, and this channel never falls back to the lab carrier.

For a direct route, `chat_id` must equal `conversation_id`, `room_id` is empty,
and `membership_epoch` is zero. For a room route, `chat_id` must equal
`room_id`, and the epoch is required. One route represents one current delivery
recipient; multi-recipient fan-out remains a daemon/MLS transport concern, not
an OpenFox authority decision.

Application delivery is at-least-once across a process
crash because publishing to the in-process bus and completing the daemon lease
cannot be one transaction. The stable Messenger Event ID is always used as the
OpenFox message ID so downstream session handling can deduplicate a replay.
