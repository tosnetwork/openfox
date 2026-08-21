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

## Staged production purchase command

`tos-service-purchase` exposes one effect per invocation:

```text
tos-service-purchase prepare          --config BUYER.json --input INPUT.json --output PURCHASE.json
tos-service-purchase inspect          --purchase PURCHASE.json
tos-service-purchase deploy-prepare   --config BUYER.json --purchase PURCHASE.json --output DEPLOYMENT.json
tos-service-purchase deploy-broadcast --config BUYER.json --deployment DEPLOYMENT.json
tos-service-purchase fund             --config BUYER.json --purchase PURCHASE.json --request-key KEY --evidence FUNDING.json \
  --messenger-socket RUNTIME.sock --mandate-id MANDATE --capability-class CLASS
tos-service-purchase dispatch         --config BUYER.json --policy POLICY.json --purchase PURCHASE.json \
  --funding-evidence FUNDING.json --task TASK.json --evidence SETTLEMENT.json \
  --messenger-socket RUNTIME.sock --mandate-id MANDATE --capability-class CLASS \
  --transport agent_packet --endpoint ENDPOINT --ca CA.pem --bearer-token-file TOKEN \
  --sender-agent-id BUYER --recipient-agent-id PROVIDER --capability-id CAPABILITY \
  --agent-signing-seed SEED
```

`prepare` performs finalized Capability and stablecoin resolution and writes a
review artifact. `inspect` is read-only. `deploy-prepare` asks `tosctl` custody
to sign the exact StateInit-bearing message with `--build-only`, while
`deploy-broadcast` submits only that reviewed message. `fund` first takes a
durable production funding lease, maps the exact Proposal through the same
`PurchaseTermsForProposal` function as `AuthorizedCustodySigner`, and consumes
a Messenger `spend` authorization under the named mandate. Only then may it
require the exact escrow to be quorum-finalized in `awaiting_funding` and reach
custody. It returns only after exact funding is finalized. A deployment or
funding broadcast with an uncertain result fails as ambiguous and is never
rebuilt or automatically rebroadcast; restart recovery reads finalized state
under the persisted lease and cannot ask custody to pay again.

`dispatch` accepts A2A, MCP, or Agent Packet and requires the endpoint to equal
the Quote's decoded transport binding. Remote plaintext is refused; HTTPS uses
TLS 1.3, an explicitly reviewed CA and no environment proxy, while loopback
HTTP remains available only for the frozen local profile. The command verifies
the signed policy, prepared purchase, exact finalized-funding handoff, task
binding and source-archive digest, re-runs finalized Capability/escrow checks,
and calls Messenger `quotes.verify` before transport dispatch. A non-terminal
settlement returns `ErrSettlementPending`; the durable `execution` phase makes
the next invocation read settlement without dispatching the task again.

The chain config has schema `tos.openfox.chain-buyer-config.v1` and is a strict
owner-only JSON file. It names the private state directory, complete network
domain, exactly three endpoints, reviewed Registry/escrow/asset-wallet code BOC
files and hashes, buyer identities, bounded budget/finality policy, and pinned
`tosctl` executable/config/wallet settings. The purchase input has schema
`tos.openfox.purchase-input.v1` and contains the strict protobuf Proposal, an
absolute reviewed canonical-manifest path, exact escrow terms, the public
execution signer, and transport binding. Workflow output directories must
already be mode `0700`; artifacts are newly linked at mode `0600` and an
existing path is never overwritten.
One OpenFox process is the sole writer for each configured state directory;
separate agents and concurrent operators use separate directories. The Buyer
SDK's funding journal additionally takes an OS file lock around budget and
broadcast-lease transitions, while the shared provider Gate remains the final
cross-transport at-most-once execution authority.

The `dispatch` stage itself goes through `NewChainNativeBuyer`, the Messenger
authority client and `quotes.verify`. The older lower-level
`tos-service-buyer` funded-task transport command remains local acceptance
tooling and is not a substitute for those gates.

`NewChainNativeBuyer` also verifies the owner Ed25519 signature over the
domain-separated canonical spending policy before accepting production
composition. The canonical form binds full network and stablecoin identities,
purchase/window ceilings, expiry, sorted Capability allow-list, and confirmation
mode; false allow-list entries and sub-second/oversized windows have no alternate
encoding. Lower-level policy vectors retain their isolated presence checks, but
the production chain constructor cannot accept a non-empty placeholder as an
owner signature.
