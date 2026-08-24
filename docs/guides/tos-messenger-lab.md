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

Fresh Messenger MLS proxy v2 rooms also have a terminal removed-member state.
When a poll receives an authenticated removal, OpenFox durably deletes that
room and cursor from its active poll set. A later `410 Gone` is not retried as a
Relay outage, sends to the retired room fail locally, and restart ignores the
same configured room when its proxy confirms that this Agent is no longer a
member. The long-running Agent process remains up after that restart: its
control health response preserves the durable room ID and reports
`active_member: false`, while `/v1/send` returns `410 Gone` without entering the
channel. The proxy remains healthy for operator inspection; this lifecycle does
not grant OpenFox authority to create a membership change.

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
The process itself waits up to the bounded `-startup-timeout` (30 seconds by
default, at most five minutes) for its configured Messenger proxy Unix listener.
This prevents a systemd `After=` process-ordering edge from becoming a failed
Agent start, while the subsequent authenticated room request remains the real
readiness and identity check. A non-socket path and an expired or cancelled
wait fail closed.

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

## Reproducible systemd-user deployment

`cmd/openfox-messenger-lab-deploy` renders the seven-process acceptance loop as
four Messenger services (one opaque Relay and three owner-private OpenMLS
proxies) plus three independently supervised OpenFox AgentLoop services. It
requires clean absolute executable, state, credential and unit paths. Existing
different unit files are refused unless `-replace-units` is explicit; symlink
targets/components, non-executable binaries, public credential permissions,
duplicate credentials and partial three-member MLS bootstrap state fail
closed.

The Relay receives one mode-`0600` environment file containing all three
random credentials because it authenticates all members. Each proxy and its
matching OpenFox process receive a separate derived mode-`0600` file containing
only that Agent's token. Units therefore do not give Alice Bob's or Carol's
Relay authority. They retain `UMask=0077`, read-only home/system protection,
private tmp, SUID/personality/realtime restrictions and an `AF_UNIX`-only
address-family boundary. State and Agent workspaces are real mode-`0700`
directories. Capability-bounding directives are deliberately omitted because
some unprivileged/containerized user managers cannot execute the required
`capset`; deployment acceptance requires the generated units to start under the
actual target supervisor rather than treating syntax verification as runtime
evidence.

Build and inspect a deployment plan first:

```sh
GOWORK=off go build -tags goolm,stdjson -o /tmp/openfox-messenger-lab-deploy \
  ./cmd/openfox-messenger-lab-deploy

/tmp/openfox-messenger-lab-deploy -check -replace-units \
  -unit-dir "$HOME/.config/systemd/user" \
  -env-file "$HOME/.config/tos-messenger-openfox-lab.env" \
  -state-dir "$HOME/.local/state/tos-messenger-openfox-mls" \
  -relay-bin "$HOME/.local/bin/tos-messenger-lab-group" \
  -proxy-bin "$HOME/.local/bin/tos-messenger-openfox-mls" \
  -driver-bin "$HOME/.local/libexec/tos-openmls-driver" \
  -openfox-agent-bin "$HOME/.local/bin/openfox-messenger-lab-agent"
```

Remove `-check` to install atomically. The single JSON result contains no
secret: it lists changed/unchanged units, whether all three MLS snapshots still
need bootstrap, the exact argument array for the existing Messenger bootstrap
command, and the two argument arrays for `systemctl --user daemon-reload` and
`enable --now`. Operators execute bootstrap first when requested, then the
activation arrays. Exact rerun preserves credentials and reports every unit
unchanged. The command never invokes a shell or systemd itself, so installing
files cannot silently activate a partial deployment.

## Machine-checkable running acceptance

`cmd/openfox-messenger-lab-verify` independently checks an already running
seven-process deployment. It does not read Relay credentials and cannot create
a new acceptance round: all three transcripts must already contain the exact
opening and two reply Event IDs, and Alice's durable opening record must bind
the supplied request ID, before it issues the identical Alice request. That
request must return the original Event ID without changing any complete
transcript or the opaque Relay state.

The verifier requires the expected SHA-256 digest and absolute path of every
deployed artifact. It also requires three distinct mode-`0600` control sockets,
the exact room and request identities, and the exact transcript length. It
fails closed on an inactive or substituted Agent, non-AgentLoop reply, missing
or duplicate Event, wrong reply causality, cross-transcript plaintext mismatch,
socket replacement, artifact replacement, Relay-state replacement, unexpected
JSON field or duplicate JSON key, redirect, non-`0600` Relay state, or any of
the three acceptance plaintexts appearing in that state.

Example, after obtaining the exact IDs and hashes from the acceptance round:

```sh
GOWORK=off go run ./cmd/openfox-messenger-lab-verify \
  -alice-control "$XDG_RUNTIME_DIR/openfox-messenger-agent-alice.sock" \
  -bob-control "$XDG_RUNTIME_DIR/openfox-messenger-agent-bob.sock" \
  -carol-control "$XDG_RUNTIME_DIR/openfox-messenger-agent-carol.sock" \
  -relay-state "$HOME/.local/state/tos-messenger-openfox-mls/relay.json" \
  -room-id "room_<64-lowercase-hex>" \
  -request-id "acceptance-stable-id" \
  -content "process-probe: exact acceptance text" \
  -opening-event-id "msg_<64-lowercase-hex>" \
  -bob-reply-event-id "msg_<64-lowercase-hex>" \
  -carol-reply-event-id "msg_<64-lowercase-hex>" \
  -expected-transcript-records 120 \
  -artifact "openfox-messenger-lab-agent=<sha256>:$HOME/.local/bin/openfox-messenger-lab-agent"
```

Repeat `-artifact` for the Relay, proxy, OpenMLS driver, Agent and deployer.
Success emits one `openfox.messenger-lab-acceptance.v1` JSON report containing
the exact identities, artifact hashes, Relay hash/size/mode and per-Agent
record counts. Its `scope` is always `same-host-local-route-only`; it is not
M0-R, public-network, independent-operator, or independent-implementation
evidence. The artifact paths are operator-supplied pinned inputs; the report
does not by itself prove which executable image a supervisor loaded. Check the
seven unit states and their process identities separately through the target
systemd user manager.
