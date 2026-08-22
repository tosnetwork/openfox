# Two independently operated OpenFox Messenger agents

This runbook exercises two real OpenFox `AgentLoop` processes over two
independent `tos-messengerd` state owners and public TLS. It is the deployment
procedure for the Phase E Messenger acceptance; it is not by itself proof that
two operators actually ran it.

The acceptance runner uses the production `tos_messenger` channel and ordinary
AgentLoop. Its deterministic local response provider makes transport evidence
repeatable and credential-free. It accepts no EndpointID, DeviceID, SessionID,
conversation ID, Relay or route input.

## Prerequisites on both hosts

- a canonical local AgentID and finalized Endpoint delegation;
- an owner-private `tos-messengerd` state directory and runtime socket;
- finalized Contact Descriptor and signed device/prekey publication;
- public DNS and a valid TLS certificate for the Descriptor's exact
  `https://HOST/v1/tos-messenger/messages` URL;
- `transport: "https-bootstrap"`, `discovery.mode: "tos-dht-https"`, and
  `publication.mode: "prekeys"` in daemon configuration; and
- reciprocal discovery configuration. `.tos` input additionally requires the
  finalized Native DNS client configuration.

The daemon setup and reverse-proxy boundary are documented in
`tos-messenger/docs/HTTPS_BOOTSTRAP_TRANSPORT.md`. Public port 443 may forward
the exact path to the daemon's private TLS listener; redirects and plaintext
ingress are rejected.

Build the two commands on each host from the recorded OpenFox commit:

```sh
GOWORK=off go build -tags goolm -o /usr/local/bin/openfox-messenger-agent ./cmd/openfox-messenger-agent
GOWORK=off go build -tags goolm -o /usr/local/bin/openfox-messenger-evidence ./cmd/openfox-messenger-evidence
```

Create the local private directories explicitly:

```sh
install -d -m 0700 /var/lib/openfox-messenger-agent /run/openfox-messenger-agent
install -d -m 0700 /var/lib/openfox-messenger-agent/workspace
```

## Start Bob

Bob replies only to acceptance messages beginning with `ping:`. Substitute the
canonical AgentID and actual daemon socket:

```sh
openfox-messenger-agent \
  -agent-id agent_BOB64 \
  -daemon-socket /run/tos-messengerd/runtime.sock \
  -workspace /var/lib/openfox-messenger-agent/workspace \
  -state /var/lib/openfox-messenger-agent/transcript.json \
  -control-socket /run/openfox-messenger-agent/control.sock \
  -trigger-prefix ping: \
  -reply-prefix ack:
```

Alice uses the same command with her own identity and paths, and a trigger such
as `never-reply:` so Bob's `ack:` does not create a reply loop.

## Send without an OpenFox route

On Alice's host, send either Bob's `.tos` alias or canonical AgentID. The
control boundary represents only operator recipient intent; unknown JSON fields
are rejected.

```sh
curl --fail --unix-socket /run/openfox-messenger-agent/control.sock \
  -H 'content-type: application/json' \
  --data '{"request_id":"phase-e-001","recipient":"bob.tos","content":"ping:hello from Alice"}' \
  http://localhost/v1/send
```

`request_id` is operator-stable for exact retry. OpenFox derives the delivery
intent; the daemon canonicalizes the alias once and owns all subsequent Agent,
Endpoint, Device, session, Event and carrier authority.

Wait for the reply, then restart Bob's OpenFox process (and, in a separate
round, Bob's daemon), retaining both durable state directories. Send a second
request with a new request ID and confirm another reply. Exact redelivery of an
already-applied inbound Event is acknowledged from the durable transcript and
does not invoke AgentLoop or send a duplicate reply.

## Export and verify

On each host, export the transcript through its owner-private socket:

```sh
curl --fail --unix-socket /run/openfox-messenger-agent/control.sock \
  http://localhost/v1/transcript > transcript.json
```

Copy both files to the evidence reviewer and run:

```sh
openfox-messenger-evidence \
  -left alice-transcript.json \
  -right bob-transcript.json \
  -require-restart-agent agent_BOB64
```

The verifier requires distinct canonical AgentIDs, canonical Event IDs, exact
cross-transcript content, authenticated sender continuity, reply causality and
activity under two process run IDs for the restarted Agent. It deliberately
does not infer operator or network independence from files. The published
evidence record must also bind host/operator identities, public endpoints,
finalized checkpoints, redacted configuration digests, binary digests and exact
commits from OpenFox, `tos-messenger`, `tos-service-protocol` and
`tos-service-spec`.
