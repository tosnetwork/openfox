# Authenticated TOS Messenger inbox

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
      "lease_seconds": 30
    }
  }
}
```

The adapter lists pending events, takes a bounded application lease, and accepts
only the strict `text` payload profile. It independently reparses the event,
checks daemon metadata against the document, recomputes the content-addressed
Event ID, and decodes the domain-separated canonical text body. A Messenger-
generated fixture cross-checks this small independent decoder. Unknown,
substituted, or malformed events are rejected before the OpenFox bus.

For accepted input it sets `AuthenticatedMessagingOrigin` from the verified
Agent, Endpoint, Device, Event, conversation, kind, and daemon receive time.
That typed metadata is persisted by the Agent runtime but omitted from model
provider payloads; tool and custody authorization use it as non-model-controlled
provenance.

This first production adapter is intentionally receive-only. `Send` fails
closed until the Messenger route-strategy gate and production group driver are
accepted; it never constructs an event in OpenFox and never falls back to the
plaintext lab carrier. Application delivery is at-least-once across a process
crash because publishing to the in-process bus and completing the daemon lease
cannot be one transaction. The stable Messenger Event ID is always used as the
OpenFox message ID so downstream session handling can deduplicate a replay.
