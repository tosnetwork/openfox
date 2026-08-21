# TOS Messenger local group-chat channel

OpenFox includes a `tos_messenger_lab` channel for the same-host integration
loop documented by `tos-messenger/docs/OPENFOX_LAB_GROUP.md`. It is an
OpenFox-native channel: inbound room messages enter the standard message bus
with `chat_type: group`, and outbound Agent responses use the room ID as their
chat ID.

The channel is not the production TOS Messenger route. Its preferred
`openmls-proxy` mode connects each OpenFox process to a different owner-private
Unix socket. Each proxy alone owns that Agent's OpenMLS snapshot, encrypts
before publishing, and decrypts only after authentication; the shared lab Hub
acts as an opaque ciphertext Relay. Runtime metadata says
`local-unix-openmls-ciphertext-relay`. The legacy direct-Hub fixture remains
available with `local-unix-plaintext` metadata. The proxy/bootstrap boundary is
`tos-messenger` `9219ddb`.

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
    "encryption": "openmls-proxy",
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
public config. In encrypted mode `socket_path` names this Agent's proxy, not
the shared Relay. Bootstrap uses genuine OpenMLS KeyPackages and sequential
Welcome/Commit transitions, then stores one mode-`0600` snapshot per Agent.
The first configured member may include `rooms` to create the matching opaque
Relay room; other members discover it. Creation is deterministic and
idempotent for the exact label and sorted member set.

The cursor file is mode `0600`, atomically replaced and directory-fsynced. A
message is checkpointed only after it enters the OpenFox bus. This yields
at-least-once processing across a crash: the last message may reappear, but a
message is not checkpointed before the Agent can observe it. The long-running
Agent command strengthens this boundary as described below.

## Three-Agent executable acceptance

`cmd/openfox-messenger-lab-demo -encrypted` starts three independent channel
instances against three `tos-messenger-openfox-mls` proxies, creates a room,
sends one opening message, and requires both peers to reply.
It emits a JSON transcript and exits non-zero on missing delivery. Reusing the
same state directory validates restart cursors and delivery of legitimate
offline history.

The acceptance test also checks that the Relay state contains neither the
plaintext nor a private MLS snapshot, that ciphertext tampering fails without
advancing durable state, and that conversation continues after every proxy is
restarted. This executable deliberately does not instantiate a model provider. It tests
the messaging/channel boundary deterministically; model choice and tool policy
belong to the normal OpenFox runtime and are tested separately.

## Independent long-running Agent processes

`cmd/openfox-messenger-lab-agent` runs exactly one channel in one OS process.
Give each process its own Agent ID, token, OpenMLS proxy socket, cursor,
transcript state and private control socket. The founder alone uses
`-create-room`; every process names the same label and exact member
set. A typical peer also uses:

```text
-trigger-prefix process-probe: -reply-prefix ack-from-
```

The trigger is important when a new process first catches up old room history:
the peer records that history but replies only to explicitly marked acceptance
probes, so startup cannot create an ACK storm for earlier conversations.
Replies include the opening Event ID and use a client ID derived from Agent,
target Event and exact reply. Thus a replay after process restart is stable.

The control socket is mode `0600` and exposes:

- `GET /v1/health` for the exact Agent/Room binding;
- `POST /v1/send` with `{"request_id":"stable-id","content":"..."}`;
- `GET /v1/transcript` for the bounded durable local transcript.

After an operating-system service restart, wait until `/v1/health` succeeds;
an `active` supervisor state can briefly precede control-socket readiness.

`request_id` is passed through to the proxy/Relay client-ID claim. Reusing it
with identical content returns the same message; content substitution is
refused. The transcript is mode `0600`, atomically replaced, bounded to 4096
records and rejects Event-ID substitution. These processes remain deterministic
acceptance Agents without a model provider in the default `static` reply mode;
they exercise process separation, encrypted channel ownership, durable restart,
and operator-visible control.

For a stronger runtime acceptance, add both:

```text
-reply-mode agent-loop \
-agent-workspace /absolute/private/path/for/this-agent
```

This starts the real OpenFox `AgentLoop.Run` and gives it a local deterministic
provider, so no external model credential or network call is involved. Inbound
events are durably transcribed before entering the Agent bus; trigger filtering
still prevents catch-up loops. The AgentLoop performs its normal room/session
routing, durable history application and response publication. A separate
outbound worker requires the response to target the exact room and current
inbound Event, derives a stable send claim from Agent, target and content, and
records `runtime: openfox-agent-loop` plus `reply_to_event_id` in the private
transcript. The channel passes that reply Event ID into the strict MLS
plaintext frame, validates it again on receipt, and restores it into every
recipient's inbound context; the opaque Relay never receives the field. The
channel does not advance its cursor until this complete path is durable. A
crash before completion retries the input; a crash after completion
but before cursor fsync recognizes the durable reply and skips a second Agent
turn. Each process must use a different mode-`0700` Agent workspace, whose
session history survives process restart. This proves local OpenFox runtime
composition only; it is not evidence for a production model, public route or
independent operator.
