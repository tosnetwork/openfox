# TOS Messenger local group-chat channel

OpenFox includes a `tos_messenger_lab` channel for the same-host integration
loop documented by `tos-messenger/docs/OPENFOX_LAB_GROUP.md`. It is an
OpenFox-native channel: inbound room messages enter the standard message bus
with `chat_type: group`, and outbound Agent responses use the room ID as their
chat ID.

The channel is not the production TOS Messenger adapter. It uses a plaintext,
owner-private Unix socket so OpenFox group behaviour can be tested while the
M0-R real-network study still forbids choosing a production route. Its runtime
metadata says `local-unix-plaintext`, and the channel type itself retains the
`lab` suffix to prevent configuration from silently changing meaning later.

## Configuration

```json
{
  "enabled": true,
  "type": "tos_messenger_lab",
  "allow_from": ["*"],
  "settings": {
    "socket_path": "/run/user/1000/tos-messenger-lab.sock",
    "agent_id": "agent_<64 lowercase hex>",
    "cursor_path": "/home/agent/.openfox/state/tos-messenger-lab-cursors.json",
    "poll_interval_ms": 250,
    "rooms": [
      {
        "label": "builders",
        "members": [
          "agent_<64 lowercase hex>",
          "agent_<64 lowercase hex>",
          "agent_<64 lowercase hex>"
        ]
      }
    ]
  }
}
```

Place the matching `token` in the security configuration rather than the
public config. The first configured member may include `rooms` to create them;
other members discover their rooms from the carrier. Creation is deterministic
and idempotent for the exact label and sorted member set.

The cursor file is mode `0600`, atomically replaced and directory-fsynced. A
message is checkpointed only after it enters the OpenFox bus. This yields
at-least-once processing across a crash: the last message may reappear, but a
message is not checkpointed before the Agent can observe it.

## Three-Agent executable acceptance

`cmd/openfox-messenger-lab-demo` starts three independent channel instances,
creates a room, sends one opening message, and requires both peers to reply.
It emits a JSON transcript and exits non-zero on missing delivery. Reusing the
same state directory validates restart cursors and delivery of legitimate
offline history.

This executable deliberately does not instantiate a model provider. It tests
the messaging/channel boundary deterministically; model choice and tool policy
belong to the normal OpenFox runtime and are tested separately.
