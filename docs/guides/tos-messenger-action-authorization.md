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
After the single funding lease, the buyer first resolves exact finalized
funding and then calls the same Messenger client through `quotes.verify` with
the commitment, deterministic escrow address, and those complete terms. The
address is only a candidate locator: Messenger independently checks the exact
finalized account's contract, canonical StateInit and held commitment, and does
not persist a locator supplied by OpenFox. Task construction/dispatch remains
blocked until Messenger independently matches the finalized Accepted Quote and
its full network identity. This check runs again on crash recovery while the
funding lease prevents a second payment.

`nativeimpl.NewNativeBuyer` requires the Messenger authorizer, finalized-Quote
verifier, and mandate ID and installs both boundaries itself; production
callers cannot inject a bare custody session or omit post-funding verification
from the assembled buyer. Lower-level `servicebridge.Buyer` remains available
for isolated tests and alternate compositions, but its required verifier still
fails a purchase closed before dispatch.

`nativeimpl.NewChainBuyerStack` is the production chain assembly boundary. It
requires exactly three RPC authorities and fixes a strict 2-of-3 quorum, then
shares one Native Registry locator and finalized Native, stablecoin, and escrow
resolvers between the Buyer SDK, capability validation, and settlement reads.
Each resolver has its own durable checkpoint, and the budget journal must
already exist in an owner-private state directory. `NewChainNativeBuyer` wraps
that stack with the mandatory Messenger authorization and Quote-verification
boundaries for one negotiation. Construction is deliberately read-only: it
does not claim endpoints are live, deploy an escrow, fund it, or dispatch a
task. Those remain separate, reviewable command stages.

The handoff between those stages uses
`nativeimpl.MarshalPreparedPurchase`/`UnmarshalPreparedPurchase`. Its strict
`tos.openfox.prepared-purchase.v1` artifact binds the protobuf Proposal,
canonical manifest, Accepted Quote, escrow Data and StateInit, stablecoin route,
buyer wallet, and exact atomic amount. Unknown fields, trailing JSON,
non-canonical Base64/BOCs, an invalid integrity digest, and re-digested linked
field substitutions are rejected. Loading the artifact does not authorize a
deployment or payment; the Buyer SDK reconstructs and revalidates it against
fresh finalized state before funding.
