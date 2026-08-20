# TOS Messenger action authorization

OpenFox can route classified tools and custody operations through the local
`tos-messengerd` runtime socket. Messenger remains the authority for effect
ceilings, owner decisions, mandates, durable budgets, and one-shot claims;
OpenFox supplies the facts only the runtime can know: the exact provider tool
call and the authenticated messages present in its context.

## Why this is a socket boundary

The integration deliberately uses the daemon's narrow local API instead of
importing `tos-messenger` as an OpenFox library. The repositories pin different
Go toolchains, and a direct import would merge dependency and release
boundaries while duplicating policy authority inside the Agent process. The
socket keeps one policy implementation and matches the eventual production
channel shape. Its small versioned envelope is covered by strict codec and
failure tests.

## Configuration

```json
{
  "tools": {
    "action_authorization": {
      "enabled": true,
      "socket_path": "/run/user/1000/tos-messengerd/runtime.sock",
      "timeout_seconds": 30
    }
  }
}
```

The socket path must be clean and absolute. The timeout is at most 60 seconds
and also bounds how long a tool waits while an owner decides. A missing daemon,
bad response, invalid configuration, unknown effect, or unclassified injected
tool fails closed before the tool's `Execute` method runs. Disabling the option
preserves legacy deployments.

## Provenance and replay behavior

Tool-call IDs, arguments, Agent/session identity, and the inbound message ID
produce a domain-separated SHA-256 idempotency key. The model cannot supply
that key. Exact concurrent retries reach one durable Messenger grant, and only
one caller can claim it.

Authenticated TOS Messaging Events carry typed Agent, Endpoint, Device, Event,
conversation, kind, and receive-time provenance. OpenFox stores that metadata
with session history but provider adapters omit it from model API requests.
Every authenticated remote message still represented by the durable session is
cited. Legacy history, unattributed remote input, lossy summaries, conflicting
event metadata, or more than 32 origins makes lineage incomplete and refuses
tool execution. Starting a new session is the explicit recovery from an
unreviewably large lineage.

The local plaintext `tos_messenger_lab` channel intentionally supplies no
authenticated origin and therefore cannot exercise privileged tools when this
boundary is enabled. A production daemon channel must populate
`AuthenticatedMessagingOrigin` only after the daemon has authenticated and
admitted the event.

## Custody boundary

`servicebridge.AuthorizedCustodySigner` wraps the existing custody signer.
Before escrow funding it sends the exact canonical quote surface—provider,
capability/version/class, manifest, transport binding, network and asset code
identity, decimal atomic amount, escrow/dispute digests, expiry, and mandate—to
Messenger as a `spend`. Settlement signing separately requests `key-use`.
Refusal or incomplete lineage leaves the wrapped signer unreachable.
`nativeimpl.NewNativeBuyer` requires both the Messenger authorizer and a
mandate ID and installs this wrapper itself; production callers cannot inject a
bare custody session into the assembled buyer. Lower-level `servicebridge.Buyer`
remains available for isolated tests and alternate compositions, which must
apply an equivalent authority boundary explicitly.
