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
      "enable_attachments": true,
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

With `enable_attachments`, the adapter also drains the daemon's reserved
`attachments.pending`/`attachments.claim` boundary. The general runtime inbox
cannot list or claim an `artifact.encrypted` Event and OpenFox never receives
its Reference, fetch grant, capability private key, ciphertext, or scanner
stderr. The daemon first fetches the manifest-bound chunks, authenticates and
opens them, and runs every SHA-256-pinned scanner in its fail-closed Linux
sandbox. It releases only bounded non-empty UTF-8 `text/plain` plus the exact
plaintext digest and scanner identities.

OpenFox independently checks all returned identifiers, filename, media type,
size, UTF-8 shape, scanner ordering and canonical digests, and recomputes the
SHA-256 of the returned body. It publishes the body with an authenticated
`artifact.encrypted` origin and completes the lease only after the Agent
session has durably persisted that exact Event/content/provenance tuple. A
fetch, AEAD, scan, validation, or persistence failure releases no content and
leaves the durable lease retryable.

The same option also enables outbound `SendMedia`. OpenFox resolves only a
registered `media://` reference, opens the exact regular file without following
a symlink, hashes at most 512 MiB, and sends filename, canonical media type,
size, digest and sequential 1 MiB plaintext chunks over local API v5. The
daemon immediately AEAD-encrypts each chunk and persists only ciphertext. It
owns fresh encryption/upload/fetch keys, the fixed operator storage origin and
key, retention, external Endpoint signatures, locator, sender/network/clock,
and Event ID. A complete signed StoredAck must verify before the Event enters
the delivery journal. Interrupted plaintext ingestion, storage upload, daemon
restart and exact OpenFox retry resume the same durable transaction; a changed
digest or route conflicts. One shared media caption is first emitted as a
canonical text Event and attachments reply to it; divergent per-part captions
are refused rather than discarded. Neither the model nor OpenFox receives the
Endpoint or upload-capability private key.

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
route. The AgentLoop preserves that runtime-owned origin and sets the reply
target to the current inbound Event when it publishes its final response; it
does not reconstruct an empty generic outbound context after model execution.
OpenFox sends only message semantics to `outbox.compose`; the daemon
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

Ordinary message leases now use an explicit durable-application handshake. The
adapter does not complete the daemon lease merely because an in-process bus
publish succeeded. The Agent session store atomically binds the stable Event ID
to the exact user content and authenticated provenance, fsyncs it, and only then
answers the channel. Exact replay after a crash is idempotent and does not run a
second model turn; Event-ID substitution fails closed. A production message for
a currently busy session is not placed in the volatile steering queue: its
lease remains retryable until that session can durably accept it. A hard turn
abort may roll back assistant/tool work but retains an input whose lease was
already completed.

The JSONL session directory is mode `0700`; message, metadata and moderation
files are mode `0600`. Opening the store also tightens recognized legacy session
files, preventing decrypted Messenger history from remaining group/world
readable on the OpenFox host.

## Typed Agent Packet provider handoff

The native `tos-service-provider` may expose its existing Agent Packet verifier
and shared A2A/MCP/Agent Packet Execution Gate on an owner-private local socket:

```text
-messenger-agent-packet-socket /run/user/1000/openfox-provider/agent-packet.sock
```

The parent directory must already exist with no group/world permissions. The
provider refuses a relative path, symlink, ordinary-file replacement or public
directory, creates the socket as mode `0600`, and removes it on shutdown. Unix
socket possession is only a delivery boundary: the received canonical Packet
still passes the protocol's finalized sender/controller verification and replay
guard before the purchase-bound adapter reaches the one shared Execution Gate.
Packet bytes never become AgentLoop/model text. `tos-messenger` supplies the
matching bounded Unix receiver; production daemon assembly remains separate
from this channel until an admitted `agent.packet` route exists.
