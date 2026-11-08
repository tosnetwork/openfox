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
      "timeout_seconds": 30,
      "physical_capabilities": {
        "i2c": {
          "capability_id": "cap_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "operations": ["detect", "scan", "read"]
        }
      }
    }
  }
}
```

The socket path must be clean and absolute. The timeout is at most 60 seconds
and also bounds how long a tool waits while an owner decides. A missing daemon,
bad response, invalid configuration, unknown effect, or unclassified injected
tool fails closed before the tool's `Execute` method runs. Disabling the option
preserves legacy deployments.

Physical I/O is the deliberate exception to legacy behavior. The built-in
`i2c`, `spi`, and `serial` tools are unavailable unless action authorization is
enabled and their exact tool name has a local `physical_capabilities` entry.
Capability IDs use `cap_` plus 64 lowercase hexadecimal characters. Operations
are an explicit allow-list (`detect`/`scan`/`read`/`write` for I2C,
`list`/`read`/`transfer` for SPI, and `list`/`read`/`write` for serial).
Each invocation is classified as `physical-io`, commits the Capability, tool,
operation, at most 8 KiB of owner-reviewable canonical JSON arguments, their
digest, provenance, and retry key, and always
waits for a one-shot Messenger owner decision—even when the configured effect
ceiling would otherwise allow it. Enabling a hardware tool alone grants no
sensor or actuator authority.

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

## Paid work on the Service Actor rail

Paid software work no longer funds an escrow, so there is no custody wrapper
and no Messenger `quotes.verify` step. The buyer's payment is the Service
Actor `call` it signs in tosctl custody, and both sides re-derive everything
from finalized state; see [Service Actor rail](service-actor-rail.md).

## Retired escrow version 1 purchase stack

The native purchase and provider stack that settled through the stablecoin
escrow version 1 contract (`nativeimpl.NewNativeBuyer`,
`NewChainBuyerStack`, `NewChainNativeBuyer`, the `tos.openfox.prepared-purchase.v1`
and `tos.openfox.chain-buyer-config.v1` artifacts, and the
`tos-service-purchase` and `tos-service-provider` commands) was removed on
2026-10-05 together with escrow version 1 support. The opportunity
coordinator no longer accepts a `purchase` section. The escrow-backed Paid
Demand product has also been retired; paid software work settles on the
Service Actor rail.
