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
does not infer operator or network independence from files.

## Sign the operator evidence

Unsigned transcript matching is smoke evidence only. Each operator creates a
strict `tos.openfox.messenger-operator-attestation.v1` JSON document with these
fields (lowercase hexadecimal, Unix seconds, and the exact public Descriptor
endpoint):

```json
{
  "schema": "tos.openfox.messenger-operator-attestation.v1",
  "operator_id": "independent-operator-alice",
  "site_id": "alice-public-site",
  "agent_id": "agent_A64",
  "transcript_sha256": "TRANSCRIPT_SHA256",
  "public_messenger_endpoint": "https://alice.example/v1/tos-messenger/messages",
  "network_id": "tos-testnet",
  "genesis_root_hash": "GENESIS_ROOT_SHA256",
  "genesis_file_hash": "GENESIS_FILE_SHA256",
  "openfox_commit": "OPENFOX_GIT_SHA1",
  "messenger_commit": "MESSENGER_GIT_SHA1",
  "openfox_binary_sha256": "OPENFOX_BINARY_SHA256",
  "messenger_binary_sha256": "MESSENGER_BINARY_SHA256",
  "openfox_config_sha256": "REDACTED_OPENFOX_CONFIG_SHA256",
  "messenger_config_sha256": "REDACTED_MESSENGER_CONFIG_SHA256",
  "interval_start_unix": 1787410000,
  "interval_end_unix": 1787413600,
  "attestation_public_key_ed25519_hex": "OPERATOR_ED25519_PUBLIC_KEY"
}
```

The interval must cover every transcript entry and may span at most seven
days. Generate the exact domain-separated signing bytes without exposing a
private key to OpenFox:

```sh
openfox-messenger-evidence \
  -attestation-message alice-attestation-unsigned.json \
  > alice-signing-message.json
```

The operator's independently controlled Ed25519 signer signs the bytes obtained
by hex-decoding `message_hex`—not the printable hexadecimal and not
`message_sha256`. Add the lowercase 64-byte signature as
`attestation_signature_ed25519_hex`. Repeat independently for Bob.

The acceptance verification command is then:

```sh
openfox-messenger-evidence \
  -left alice-transcript.json \
  -right bob-transcript.json \
  -left-attestation alice-attestation.json \
  -right-attestation bob-attestation.json \
  -require-restart-agent agent_BOB64
```

The verifier checks both Ed25519 signatures; exact transcript hashes; AgentID;
public HTTPS endpoints; network/genesis tuple; commits; binary/config digests;
observation intervals; and distinct asserted operator, site, endpoint and key
values. Those signed assertions prevent artifact substitution but do not prove
that the named parties are independent. The external reviewer must verify the
real operators/sites and sign the completed evidence record. The published
record also binds finalized checkpoints and the exact `tos-service-protocol`
and `tos-service-spec` commits.
