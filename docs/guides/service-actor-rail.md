# Paid software work on the Service Actor rail

OpenFox sells and buys bounded software work (a deterministic Go test run of
an inline source archive) on the TOS Service Actor rail. There is no
negotiation and no demand matching: a purchase starts from a Capability the
provider published in the Native Registry, takes a Quote and calls the
provider's Service Actor. The work and its result travel as signed Agent
Packets through the Messenger; nothing a packet or a gateway says is trusted.
Finalized TOS state is the only authority.

## Roles and custody

Every key stays in tosctl custody. An OpenFox rail node holds no key material;
its configuration names the pinned tosctl binary, the tosctl configuration and
the environment variable that carries the vault URL.

| Key | Holder | Signs |
|---|---|---|
| owner wallet (provider) | tosctl wallet | the messages that carry the Agent and Capability registrations, the actor deployment, policy updates, `respond`, `withdraw_revenue` |
| attestor controller (`service-attestor`) | tosctl vault | the request-bound SRP2 response domain, inside `respond` |
| packet controller | tosctl vault, a controller of the node's Native Registry Agent | the Agent registration, the Capability registration, every Agent Packet |
| buyer wallet | tosctl wallet | the message that carries the Agent registration, `call`, `expire`, `claim_refund` |

`openfox earning service` is the one entry point: `init`, `offer`, `preflight`,
`serve`, `status` and `withdraw` for a provider; `init`, `buy` and `purchases`
for a buyer. The commands that sign or send (`init`, `offer`, `withdraw`) run
the pinned tosctl from a sealed in-memory copy with only the vault URL in its
environment, print a preview first and do nothing without `--yes`. They print a
JSON report on stdout and the preview and progress on stderr; neither holds a
secret or the vault URL. Standard output that is a pipe or a file carries
exactly that JSON document: the start-up banner is printed only to a terminal.

Three things still need other tools:

- **Funding the owner wallet.** Create it with `tosctl wallet create`, send it
  TOS and activate it with `tosctl wallet activate`. `init` and `offer` stop
  with the wallet address and the amount needed when it is missing, inactive
  or short.
- **A carrier for Agent Packets.** Across hosts that is an Agent Packet Relay
  (end-to-end encrypted, below) or a `tos-messengerd` daemon per Agent; on one
  host two nodes of one user can use the direct transport instead.
- **The provider's executor.** The jobs run in a private container runtime
  that only root can reach. The operator installs that runtime and the
  **executor service** (tos-ai `software-work-executord`) as root, once; see
  [Executor](#executor) below. **The provider node itself runs as an ordinary
  user**: it sends each job to the service over a Unix socket and never opens
  the runtime socket or a root-owned file. `offer` asks the service to
  describe itself and records the socket.

`scripts/service-front-door-e2e.sh` runs the whole sequence below, two nodes
and one paid job, on a local network and checks every chain fact itself. With
`E2E_EXECUTOR_SOCKET` both nodes run as the invoking user; without it the
script runs the legacy single-user mode as root.

## Setting up a node: `init`

Both roles start with `init`, which establishes the node's Agent and writes the
rail configuration:

```
export VAULT_URL=…   # read by tosctl only; never printed or stored
openfox earning service init \
  --rail-config /…/rail.json --state-dir /…/rail \
  --rpc https://… --rpc https://… --rpc https://… \
  --global-config /…/global.config.json --network-label tos:global-id:<n> \
  --tosctl /…/tosctl --tosctl-config /…/tosctl-config.json \
  --wallet provider \
  --registry-code-boc /…/tos-service-native-registry-v1.boc.base64 \
  --actor-code-hash tvm-cell-sha256:… \
  --relay-url https://relay.example          # or --messenger-socket, --direct-peer, below
```

The transport may be left out of the first run. Two nodes that reach each
other directly each need the other's Agent id, which only that node's `init`
produces; so `init` without a transport establishes the node, reports
`transport: missing`, and `serve`, `buy` and `preflight` refuse until `init`
is run again with `--direct-peer`, `--relay-url` or `--messenger-socket`. That
second run sends nothing.

Only choices the owner must make are inputs. Everything else is derived and
checked:

- **tosctl pin.** `init` hashes the binary and pins it. With `--tosctl-sha256`
  the binary must have that digest. Without it the pin is **trust on first
  use**: the digest printed is the digest of whatever binary was found, so
  compare it with the release you meant to install. A binary that later
  differs from the pin is refused until its new digest is given explicitly.
- **Network domain and registry code hash.** tosctl derives them from the chain
  global configuration and the network label. `init` requires the registry code
  file to hash to the code that tosctl release signs for, and a quorum of the
  RPC endpoints (and no endpoint of another network) to serve that genesis.
- **Wallet.** The address comes from `tosctl wallet ls`. A wallet that is
  missing, not active or holds less than the registration needs stops `init`
  with the address and the amount. Only a V3R2, V4R2 or V5R1 wallet sends:
  tosctl signs their messages with an expiry, and every "the earlier message
  can no longer be included" decision below rests on it. `init`, `offer` and
  `withdraw` refuse any other wallet type (a V1R3 message never expires), and
  a wallet whose type tosctl could not read, before signing or sending.
- **Packet controller.** `--packet-controller` (default `openfox-packet`) is
  created in the vault if it is absent. tosctl never replaces an existing one.
- **Agent.** `init` builds a one-controller policy, has tosctl sign the
  registration, checks that it targets the address the Agent id derives under
  the configured network and registry code, sends it from the owner wallet with
  2 TOS attached and waits for the Agent in finalized state.
- **Paths.** The receiver socket defaults to `<state-dir>/rail-receiver.sock`.

The configuration is written owner-only (`0600`) and must read back through the
strict loader. Without `--yes`, `init` creates, signs and sends nothing and
prints what it would do.

A buyer adds its spending policy, which is an allow-list of providers:
`--allow-provider agent_…` (repeatable), with `--max-per-purchase`,
`--max-in-window`, `--window-seconds`, `--max-open-purchases`,
`--refund-reserve` and `--confirm-above` in TOS, and optionally `--gateway-url`,
`--gateway-token-file`, `--gateway-ca-file` and `--caller-id`. Re-running
`init` with these flags adds or replaces the buyer section; a re-run keeps the
provider section, and keeps the buyer section and the transport it does not
restate.

### Re-running and interruption

`init` and `offer` keep one journal, `state_dir/setup/journal.json`. It holds
the inputs that determine on-chain identities, the nonces drawn for them
(written before tosctl builds anything, so a re-run builds the same Agent and
the same Capability) and, for every chain message, whether it was handed to
tosctl. Each step:

1. reads finalized state first, and is done if its effect is there;
2. if an earlier run may have sent the message, waits for finalized state and
   **never sends again** while that message could still be included; it
   reports `the outcome of a sent message is not yet established` and exits,
   and a later run resumes. Only when finalized chain time is past the
   message's inclusion window (five minutes after the send began) and the
   effect is still absent is the message sent again;
3. otherwise marks the step as sending in the journal, then runs tosctl.

The five minutes are tosctl's own two-minute bound on a send, the two-minute
lifetime of the wallet message it signs, and one minute for a host clock that
runs behind the chain and for the hop from the wallet to the registry or the
actor. They are counted from the moment the wallet message is handed to
tosctl; a step that first builds and signs a registration starts its window
after that.

A tosctl failure that is one of its checks before broadcasting (insufficient
balance, wallet not active, entry not found) clears the mark; any other failure
is an unknown outcome. Only the final `command failed:` line of tosctl's
diagnostics classifies a failure, and diagnostics cut at their bound classify
as nothing. Changing an input that determines an identity after its
step was sent is refused: another packet controller or network would be a
second Agent, other terms a second Service Actor and Capability. To change the
terms of a published actor use `tosctl agent service send --operation
update-policy`; to start over use another state directory and configuration.

Only one of `init`, `offer`, `withdraw` and `withdraw --acknowledge` runs at a
time in a state directory. Each takes the lock `state_dir/setup/run.lock`
before it reads the configuration or the journal and holds it until it
returns; a second run fails at once with `another init, offer or withdraw run
is in progress`, having read, signed and sent nothing. The operating system
drops the lock when the process ends, so a killed run never leaves it behind.
`serve`, `status`, `preflight`, `pause` and `resume` do not take it: none of
them reads or writes the journal or sends a withdrawal, and withdrawing
beside a serving node is the intended use.

The journal is the only place the Agent's nonce lives until `init` writes the
rail configuration. **If the state directory is lost after the registration
was sent and before the configuration was written, a new `init` draws a new
nonce and registers a second Agent**; the first one stays registered and
unused. Keep the state directory until `init` reports `config.write`; after
that a re-run adopts the Agent the configuration names.

## Provider

1. `openfox earning service init …` (above).
2. Publish the offer:

   ```
   openfox earning service offer --rail-config /…/rail.json \
     --price 0.3 --storage-fee 0.25 --cleanup-bounty 0.1 \
     --response-sla 3600 --refund-claim-window 3600
   ```

   The executor is the executor service at
   `/run/tos-service-executor/executor.sock` unless another one is named:
   `--executor-socket <path>` for a service on another socket, or `--executor
   <binary> --containerd-socket <socket>` for the legacy single-user mode
   (below). The two cannot be combined. The default never selects something
   that does not work: before `offer` creates a key or sends a message it asks
   the service to describe itself and stops unless a root process answers on
   that socket, its container backend is ready, and it runs the image and the
   limits the manifest commits to.

   Amounts are decimal TOS and are handled as checked nanoTOS integers. The
   contract's bounds are applied before anything is sent: the price is
   positive; the cleanup bounty is 0.1 to 1 TOS; the storage fee is at least
   0.1 TOS plus the cleanup bounty; the response SLA and the refund-claim
   window are 3600 to 2592000 seconds. Optional: `--version` (default
   `1.0.0`), `--attestor-controller` (default `service-attestor`, created if
   absent), `--deploy-funding` (default and minimum 1.2 TOS),
   `--retention-seconds`, `--respond-budget-seconds`, `--offer-out`, and for
   the legacy mode `--executor-sha256` (otherwise the executor is pinned on
   first use, as tosctl is) and `--fifo-dir`.

   `offer` prints a preview of everything that is signed or sent: the owner
   wallet, the actor address (computed by tosctl without signing), the pinned
   actor code hash, the attestor key id, the terms, the manifest digest, the
   Capability id and address, the metadata hash and the value attached to each
   message. While the attestor controller does not exist yet, the run without
   `--yes` still shows every term, every attached value, the totals and a
   `to_be_created` list; only what derives from the new key (the actor
   address, the manifest digest, the Capability id and address, the metadata
   hash) is left open, since the run with `--yes` creates the key and sends in
   one go. With `--yes` it then:

   - deploys the Service Actor with the attestor and zero metadata, and
     verifies from finalized state that the account runs the pinned code, is
     owned by the owner wallet and snapshots that attestor;
   - builds the manifest (key 12 limits the output to 1 MiB, key 17 commits to
     the Agent Packet transport binding, key 18 names the attestor and key 21
     the actor with the pinned code hash);
   - has tosctl sign the Capability registration, checks that it targets the
     address the Capability id derives, sends it with 2 TOS attached and waits
     for it in finalized state;
   - sends `update-policy` with every policy field, the NSM1 metadata hash of
     the Capability version and the software-work proof scheme;
   - runs the preflight's own `manifest.local`, `chain.capability`,
     `chain.actor`, `chain.attestor` and `chain.admission` checks, and only
     then writes the provider section of the configuration and the **offer
     file** (default `state_dir/setup/offer.json`).

   The offer file (`tos.openfox.rail-offer.v2`) holds the Capability id, the
   version, the provider Agent id, the manifest digest and the manifest bytes,
   and, when `relay_urls` is configured, the provider's current encryption key
   card ([Relay](#relay-any-hosts-end-to-end-encrypted)). It holds nothing
   secret and carries no authority; give it to buyers.
3. `openfox earning service preflight --rail-config <file>` (below).
4. Run `openfox earning service serve --rail-config <file>`. For each task it
   verifies the packets and the Quote, refuses input over the quoted bound,
   admits the request once through the finalized rail gate (pending, call
   proven, lifecycle replayed, getters cross-checked, time left to execute and
   respond), re-checks immediately before execution, sends the job to the
   executor, verifies the outcome and its objects, builds
   the `SoftwareWorkReceiptV1`, checks it against the attestor policy (exact
   request bindings, charge equal to the price, the runner's own outcome), re-
   checks the request is still pending, and sends `respond`. After the respond
   is final it delivers the result and redelivers it in fresh packets until the
   buyer acknowledges it or the manifest retention ends. A failed or ambiguous
   execution is never attested; the buyer's refund path applies. What each
   answer of the executor service leads to is listed under
   [Executor](#executor).
5. `openfox earning service status` lists the requests, the actor's credited
   revenue and the last withdrawals (below).
6. Withdraw credited revenue:

   ```
   openfox earning service withdraw --rail-config <file> --amount 1.5   # or --all
   ```

   It reads the credited revenue at a finalized checkpoint and previews the
   amount, the destination (the owner wallet: the contract pays a withdrawal
   to the actor's owner) and the 0.2 TOS attached for fees. Zero and more than
   the credit are refused. With `--yes` it records the withdrawal in
   `state_dir/withdrawals/` before sending, tags the message with a query id
   and resolves it from the finalized transaction that carries that id and
   pays exactly the amount to the owner, so revenue credited in the meantime
   does not confuse it. A record is `submitted`, then `finalized`, `failed`
   (the transaction failed; nothing was debited), `not_included` (the
   inclusion window passed without it) or `unknown`. An unresolved withdrawal
   blocks the next one. `finalized` means the actor paid out; the wallet's own
   credit is not followed, so every record says `wallet_credit: not_verified`.

   A withdrawal can stay `unknown` for good: the actor's history no longer
   reaches the record's anchor, or a finalized transaction carries its query
   id without a payout of exactly the amount. Nothing closes such a record
   automatically. To resolve it by hand, compare `credited_before_nanotos` in
   the record with the actor's credited revenue in `status` and look at the
   owner wallet's transactions since `started_unix`; then close the record
   with

   ```
   openfox earning service withdraw --rail-config <file> \
     --acknowledge <query id> --note "what you checked" [--yes]
   ```

   It first tries once more to resolve the record from finalized state, and
   does nothing else if that succeeds. Otherwise it is accepted only after the
   withdrawal's inclusion window has passed on finalized chain time, shows
   what the node knows, and with `--yes` stores the record as
   `owner_acknowledged` together with the note, the earlier state and detail,
   the checkpoint and the credited revenue at that checkpoint. It moves no
   funds and sends nothing, and it does not say whether the actor paid out:
   the next withdrawal reads the credited revenue from finalized state.

The manual steps remain available: `openfox earning service manifest` and
`openfox earning service metadata` build the manifest and print the metadata
hash for an offer published with tosctl by hand.

## Operating a provider

### Preflight

`openfox earning service preflight --rail-config <file>` (`--config` is an
alias) checks that the node is ready to admit paid work and prints a JSON
report:

```json
{"schema": "tos.openfox.provider-preflight", "version": 1, "generated_unix": 1900000000,
 "ok": false, "admission_paused": false,
 "checks": [{"id": "chain.attestor", "status": "fail", "message": "the actor has no attestor …"}]}
```

Each check is `pass`, `fail`, `warn` or `unknown`; the command exits non-zero
when any check is `fail`. `version` changes only when a field changes meaning
or is removed; new checks may appear within a version. A check whose
prerequisite did not pass is `unknown` with the prerequisite named.

| Check | Fails (or warns) when |
|---|---|
| `config.parse` | the file is not owner-only (`0600`) strict JSON |
| `config.provider` | the provider section is missing or names an invalid Capability, controller, wallet or path |
| `state_dir.private` | `state_dir` is missing, a symbolic link, not `0700` or owned by another user |
| `state_dir.disk_free` | less than 1 GiB is free under `state_dir` |
| `admission.pause` | warns while admission is paused; fails if the pause marker is unreadable |
| `process.user` | passes for an ordinary user. With `executor_socket` a root node **fails**: nothing in it needs root, and a root node runs tosctl, the vault access and the listeners with the privilege the executor service exists to confine. In the legacy mode, where a root-only runtime forces root, it warns |
| `tosctl.pin` | the binary is missing or does not hash to its pin |
| `executor.service` | (`executor_socket`) nothing answers on the socket, the process serving it is not root (the kernel's peer credential of the connection), the service refuses this user's uid (it admits one: `TOS_EXECUTOR_ALLOWED_UID`), or it is not ready. When the socket's directory is closed to this process, the message says whether the user is missing from the group or only needs a new login session |
| `executor.image` | (`executor_socket`) the image the service says it runs jobs in is not the manifest's toolchain digest, or the service is not ready, which is also what a pinned image that is not imported and unpacked in the runtime looks like |
| `executor.limits` | (`executor_socket`) a manifest limit is zero or looser than the limit the service enforces, or the service takes less source than a task may carry |
| `executor.pin` | (legacy mode) the executor binary is missing or does not hash to its pin |
| `tosctl.config` | the tosctl configuration is missing or world-accessible |
| `tosctl.vault_env` | the variable `vault_url_env` names is unset (its value is never printed) |
| `transport.peers` | reports which transport each configured peer uses; fails when neither `messenger_socket` nor `direct_peers` is set, a direct peer is malformed, or its socket is a symbolic link, not a socket, owned by another user or in a directory group or others can write; warns when a direct peer's socket is absent (that node is not serving) |
| `containerd.socket` | (legacy mode) the runtime socket is missing, cannot be inspected by this user (a socket in a root-only directory reads as missing to any other user), not a socket, or world-accessible; it is never connected to |
| `manifest.local` | the manifest is not canonical, or its actor code hash, version or transport differ from the configuration |
| `rpc.endpoints` | fewer than 3 or more than 8 endpoints, duplicate authorities, plain HTTP off loopback, or a quorum that is not a strict majority |
| `rpc.independence` | always `unknown`: distinct authorities are enforced, distinct operators are not verified |
| `rpc.genesis` | an endpoint serves another genesis, or fewer than a quorum match (warns when some are unreachable but a quorum matches); the network id is a label bound only by the genesis hashes |
| `chain.finalized` | no finalized checkpoint is read by a strict majority |
| `clock.skew` | warns when the local clock is more than 30 s from the checkpoint's chain time (which includes the block's age) |
| `chain.registry` | the Native Registry account does not read under `registry_code_hash` |
| `chain.capability` | the Capability is missing, tombstoned, owned by another Agent, lacks the version, the version is revoked, or names another manifest digest |
| `chain.actor` | the actor is not active or does not run `actor_code_hash` |
| `chain.attestor` | the actor has no attestor (attestor-less actors are refused), or its attestor is not the manifest's |
| `chain.admission` | the protocol's own admission verification (binding, metadata hash, proof scheme, policy bounds) refuses the offer |
| `signer.attestor`, `signer.packet` | the controller does not resolve in the tosctl vault, or resolves to another key than the manifest attestor or `packet_key_id` |
| `signer.wallet` | always `unknown`: tosctl cannot resolve a wallet without signing |

The executor checks are those of the configured mode only; a section that
names both executors, or neither, fails `config.provider`. The service checks
read no path of the service: `executor.image` and `executor.limits` are what
the service, proven to be served by root, says about itself, and they are
`unknown` when it did not answer.

Preflight sends nothing to the chain and signs nothing. The signer checks run
`tosctl agent native-registry controller`, which prints a controller's public
key and key ID only. Its finalized reads keep their checkpoint fences in a
private scratch directory, so it writes nothing into `state_dir`. Endpoint
URLs in messages are replaced by their positions (`rpc_endpoints[0]`), since a
path may carry an access token.

### Status

`openfox earning service status --rail-config <file>` prints:

- `admission`: whether new admissions are paused, since when and why;
- `actor`: the actor's finalized accounting at one checkpoint:
  `credited_revenue_nanotos` (the contract's `withdrawable_revenue`),
  `pending_liability_nanotos`, `refundable_liability_nanotos`,
  `locked_storage_fees_nanotos` and the actor balance. Credited revenue is not
  money received: it reaches a wallet only after `withdraw_revenue` finalizes
  and the wallet credit is verified, and `wallet_receipt` is `not_tracked`;
- `withdrawals`: the ten newest withdrawals made with `withdraw`, newest
  first, each with its amount, state and `wallet_credit: not_verified`. An
  unresolved record is shown as finalized state decides it at this checkpoint;
  `status` does not rewrite the record;
- `requests`: every request with the fields the earlier listing printed, plus
  `source` (`record`, or `slot` for a request the rail gate admitted that has
  no provider record yet; a slot entry has an empty `schema`), `slot_state`
  (the rail gate's record), `chain_fact` and one `operator_state` with a
  `state_reason`.

`chain_fact` is what the finalized read said: `not_read`, `pending`,
`refundable`, `responded`, `responded_with_another_hash`,
`responded_without_local_result` (a respond exists but the node holds no
attested result to compare it with), `refund_claimed`, `swept`, `not_found`
(neither pending nor refundable and no terminal transaction in the complete
history), `history_incomplete` (the history read failed or stopped at its
bound) or `actor_not_active`.

| `operator_state` | Meaning |
|---|---|
| `admitted` | the rail gate admitted the request; execution has not started |
| `executing` | the execution was handed to the executor. With the executor service the record's `state` is `executing` while the node has no verified outcome yet and keeps asking for it |
| `result_available` | executed and attested locally; respond not sent, or sent and the request still pending |
| `responded` | a finalized `respond` carries this request's attested response hash (price and storage fee credited to the actor) |
| `refunded` | a finalized `expire` made the price refundable, or `claim_refund` paid it to the caller |
| `swept` | a finalized `sweep_expired_request` returned the price to the caller |
| `outcome_unknown` | anything not established: a failed or ambiguous execution awaiting expiry, an execution the executor service cannot account for (record `state` `unknown`), a respond whose finality was not read, a chain read that failed, an incomplete history, or local and chain facts that disagree |

These are projections of local records and finalized facts, not contract
states. `status` reads one finalized checkpoint through the node's own
checkpoint fences; `--offline` skips the chain. A reader that cannot be opened
or a read that fails is reported in `actor.error` (endpoint URLs replaced by
their positions) and the rest of the report is still printed. When the chain
does not settle a request (not read, history incomplete, actor not active),
the states it would decide stay `outcome_unknown`; only a respond the node
itself saw finalized before delivering is reported as `responded`.
`--records` prints only the request list, in the earlier array shape with the
added fields.

### Pause and resume

`openfox earning service pause --rail-config <file> [--reason <text>]` writes
an owner-only marker `state_dir/admission-paused`; a running `serve` checks it
before every admission, so no restart is needed. Work already admitted still
executes, responds and delivers. A task that arrives while paused is held in
the inbox, not refused and not counted against its retry cap; after
`openfox earning service resume` it is admitted if its request is still
admissible. Held tasks leave the inbox's open-message bounds and have bounds
of their own (the same per-sender and total limits), so they never keep out
results and acknowledgements of admitted work; a task over the hold bound is
retired. A held task is pruned with other incomplete inbox entries an hour
after it was held, and a request that is never answered falls to the buyer's
refund path. `serve` logs one `admission paused` line per round while tasks
are held, with the count held and retired. Pausing never touches funds. It
does not stop buyers from calling the actor; to stop new calls on chain,
change the actor's policy with the owner wallet. An unreadable marker is
treated as paused and its error is logged.

## Buyer

1. `openfox earning service init …` with `--allow-provider agent_…` for the
   provider named in the offer file (above).
2. Buy from the offer file:

   ```
   openfox earning service buy --rail-config <file> --offer /…/offer.json --source <archive>
   ```

   Exactly one Quote source is used: `--offer`, `--quote-package` (a package
   obtained out of band) or, with neither, the configured gateway.

   With `--offer` the Quote Proposal package is built locally; it needs no
   provider secret and no signature. The provider Agent is the Capability's
   **finalized owner**, not the file's word; the file's manifest bytes must
   hash to the **finalized digest** of the version; the transport is the
   rail's deterministic Agent Packet binding to that owner; price, storage fee
   and terms hash are read from the actor's finalized policy. An offer file
   that finalized state contradicts is refused. `--capability-id` and
   `--version` may be given only if they agree with the file.

   The package then goes through the same path as any other:

   1. the offer is verified at a finalized checkpoint and the Quote validated;
   2. input over the quoted inline bound (at most 1 MiB) is refused before
      anything is reserved or paid;
   3. the costs are shown and the owner policy applied: the price (refunded
      only if no attested response arrives and the refund is claimed), the
      non-refundable storage fee, the 0.2 TOS admission allowance, the
      attached value `price + storage fee + 0.2 TOS`, and that a refund takes
      two transactions from the buyer wallet inside the refund window
      (`expire`, then `claim_refund`, which attaches 0.2 TOS), each paying
      fees;
   4. the call is prepared and sent with the quoted terms hash.
3. `openfox earning service serve` delivers the task once the call is admitted,
   accepts a result only when its Receipt hashes to the finalized attested
   response and binds the buyer's own request, price and provider, and the
   artifact matches every digest the Receipt states, and acknowledges it. If
   the provider does not answer in time it sends `expire` and `claim_refund`.
4. `openfox earning service purchases` shows each purchase's phase, status,
   required action, deadlines and costs.

## Carrying Agent Packets

The work and its result travel as Agent Packets signed by the sender's packet
controller. A receiver verifies every packet against the sender's finalized
Agent state and stores it durably before it answers, whatever carried it.

**Messenger (any hosts).** Each Agent runs a `tos-messengerd` daemon. Its
delegation's `allowed_outbound_event_classes` must include `agent.packet`, and
its Agent Packet receiver socket must point at the node's `receiver_socket`.
Set `messenger_socket` (`init --messenger-socket`).

**Direct (same host, same user).** `init --direct-peer agent_<hex>=<socket>`
(repeatable) records `direct_peers`: a packet to a listed Agent is posted to
that node's `receiver_socket` at `/v1/agent-packet`, and a `202` answer means
the packet is in the recipient's durable inbox. This is a transport **for
trials and single-operator setups on one host**:

- it gives no confidentiality beyond the socket's file permissions;
- there is no carrier-level admission or rate limiting;
- any process of that user can post to the socket. What the receiver trusts is
  the packet's signature against finalized state, exactly as with the
  Messenger; the inbox's replay handling and bounds apply unchanged.

The scope is enforced, not only stated. A send is refused when the socket path
is a symbolic link or not a socket, when another user owns the socket, when
group or others can write its directory (they could replace the socket), and,
on Linux, when the process listening on it runs as another user (the kernel's
peer credentials of the connection). `preflight` makes the same inspection of
the path. A redirect is
not followed, the request and the answer are bounded, and a failed send leaves
the packet journaled for the next retry as a failed Messenger send does. When
`direct_peers` is set, `messenger_socket` is optional: a recipient that is
neither a direct peer nor reachable through a Messenger has no route, and the
send fails. A node with neither does not start. Delivery across hosts still
needs the Messenger. `preflight` reports each peer's transport in
`transport.peers`.

Each node lists the other: the buyer the provider's Agent and receiver socket,
the provider the buyer's. The Agent ids are in each `init` report and the
provider's is in the offer file. In order:

1. provider: `init` (no transport yet), then `offer`;
2. buyer: `init --allow-provider <provider Agent> --direct-peer <provider
   Agent>=<provider receiver socket>`;
3. provider: `init` again with `--direct-peer <buyer Agent>=<buyer receiver
   socket>`, then `preflight` and `serve`;
4. buyer: `serve`, and `buy --offer`.

`serve` and `buy` are separate processes. `serve` takes each open purchase's
manifest from the Quote package the purchase stored, so it needs neither the
offer file nor a gateway to deliver a task bought with `buy --offer`.

### Relay (any hosts, end-to-end encrypted)

`init --relay-url <base URL>` (repeatable, at most 4) records `relay_urls`.
The node then carries packets through Agent Packet Relays
(`AGENT_PACKET_RELAY_V1` of the protocol specification): store-and-forward
mailboxes that hold sealed envelopes and nothing else. A packet to a peer
whose verified encryption key card the node holds is sealed to that card and
deposited at the relays the card names; every other recipient goes to a
direct peer or the Messenger as before. A relay URL is `https`, or `http` only
to `127.0.0.1`, `localhost` or `::1`; it has a lowercase host, no user, query,
fragment, escape or trailing slash. Anything else is refused by `init`, by
`preflight` and by the client.

**Relay certificates.** Verification is never turned off, and TLS 1.2 is the
minimum. By default the node verifies a relay's certificate against the
system trust store. `init --relay-ca-file <PEM file>` pins instead: the file
holds one or more certificates (certificate authorities, or a relay's own
self-signed certificate) and nothing else (a private key or any other PEM
block is refused), each valid when `init` runs. `init` copies it into
`state_dir/relay/relay-ca-<sha256>.pem` (`0600`) and records its SHA-256 as
`relay_ca_file` and `relay_ca_sha256`, so the pin is what the owner gave at
`init` whatever later happens to the original file. A new pin is written
under its own name before the configuration naming it is committed, and the
earlier file is removed only after that, so an `init` interrupted at any
point leaves a configuration whose pinned file still matches. With a pin:

- every https relay in this node's `relay_urls` is verified against the
  pinned certificates **only**; the system trust store (and `SSL_CERT_FILE`)
  is not consulted for them. One file covers all of them: a node whose
  relays use different authorities lists each in the file;
- a relay that only a peer's key card names (one not in this node's
  `relay_urls`) is verified against the system trust store, as without a
  pin. A peer card naming one of this node's own relays uses the pin. Such a
  relay is trusted through the public certificate authority system, so a
  mis-issued certificate for its name can intercept that connection; the
  packets stay end-to-end sealed, so only availability and the metadata a
  relay sees are exposed;
- a pinned file that is missing, not owner-only or no longer has the
  recorded digest stops `serve` from opening the relay carrier; it never
  falls back to the system trust store. `serve` reads the file at start, so
  a new pin takes effect at the next start.

A re-run of `init` that names neither `--relay-ca-file` nor
`--relay-system-roots` keeps the pin; `--relay-ca-file` replaces it and
`--relay-system-roots` drops it. A pin needs at least one https relay. When
the pinned authority is renewed, run `init` again with the new file.

**What a relay operator can and cannot do.** A relay has no authority and
never decrypts. It sees the recipient Agent id, the recipient's key id, the
envelope sizes and counts, the deposit, fetch and acknowledgement times and
the IP addresses of both sides; listing and download are open, so anyone who
knows an Agent id learns the same. It never sees the sender Agent, the
Capability, the Quote or any content. It can drop, delay, reorder, duplicate
or replay envelopes, refuse service and lie about status codes, which costs
availability only: the courier retries and redelivers, the durable inbox
deduplicates, and the Native Execution Gate keeps execution at most once. It
cannot read a packet (HPKE with the hybrid post-quantum MLKEM768-X25519 KEM),
forge or alter one (the inner ML-DSA-44 signature is verified against
finalized state after opening, and the AEAD covers the header), re-address an
envelope, or delete one without its acknowledgement secret.

**Sending.** The transport seals the exact signed packet JSON (sign, then
encrypt) under a fresh acknowledgement secret, journals the envelope in
`state_dir/relay/outbox` **before** the first deposit, and deposits it at the
card's relays in order, each bounded to 30 seconds. A send is done only when
one relay answers `200`, `201` or `410`; a retry after an ambiguous answer or
a restart sends the journaled bytes again, so the relay recognizes them. Before
journaled bytes are sent again, the card they were sealed to is checked: if it
was last verified 9 minutes ago or more it is verified again, and if it has
expired, was revoked or is no longer held, those bytes are never sent again;
the packet is sealed to the recipient's current valid card under a fresh
acknowledgement secret (a new envelope id), journaled, and deposited instead.
Without a valid card the send fails and the courier retries; an envelope one
relay already accepted is not spread to further relays once its card is
revoked or expired; once revoked it is withdrawn and the packet sealed again
(below). The remaining relays are deposited in the background for redundancy. A relay that
answers `409` holds other bytes under that public envelope id; it is abandoned
for that envelope, and when no relay accepted and one answered `409` the packet
is sealed again under a new id, journaled, and the courier retries with it.

**Expiry and retention.** A packet expires at its business deadline, never
later than 23 hours 55 minutes after signing:
- a task at the Accepted Quote's response deadline;
- a result and a result request at the result's retention end;
- a result acknowledgement after one hour (a lost one costs one result
  redelivery, answered with a fresh acknowledgement);
- a chat delivery acknowledgement after one hour, and a chat evidence request
  or response after one relay TTL of the peer's chat card.

A message whose deadline has passed is not signed or sent. Each relay keeps
an envelope at most its advertised `max_ttl_seconds` (1 hour on the project's
test relays, 3 hours on its production relays, never more than 24 hours). The
node reads each relay's `GET /v1/relay` description and uses it for an hour
(a failed read is retried after 5 minutes; a value older than 2 hours, an
unreadable description and a value outside 1 s to 24 h count as 24 hours).

When an accepted envelope's own expiry is later than the relays keep it, the
node replaces it at 80 % of the smallest TTL among the card's relays (never
sooner than 10 minutes): 48 minutes against 1-hour relays, 2 hours 24 minutes
against 3-hour relays. The replacement is a fresh seal of the same packet
under a new acknowledgement secret, journaled before its deposit. The old
envelope is withdrawn once a relay holds the new one. Before replacing, the
node lists the relays that accepted the envelope: if every listing succeeds
and none lists it, the recipient took it, and it is not deposited again. When
no relay of the card has a readable description, nothing is replaced early,
and the courier's own redelivery carries the message.

The Messenger daemon schedules chat generations from the TTL the carrier
reports with every `carried` answer (`relay_ttl_seconds`, the smallest of the
peer card's relays). The 24-envelope per-peer chat cap counts every
generation whose withdrawal was not confirmed until that envelope expires:
withdrawals retried after transient failures, and withdrawals that ended in
a refusal. An unreadable journal file counts as one stored envelope for every
peer until 24 hours 5 minutes after it was last written. After that, nothing
it describes can still be stored, so it is moved to `quarantine/` in the same
directory, reported, and kept for inspection.

**Receiving.** `serve` lists each relay of every key it holds every 15 seconds
(plus up to 20 % jitter), backing off to 5 minutes on errors and honouring
`Retry-After`. Each envelope is opened under the key its header names, then
handed to the same accept path as a Messenger or direct delivery: packet
decode, recipient check, `agentpacket.Verify` against finalized state, frame
decode and the durable inbox write. Only after that write is the envelope
acknowledged, at every relay that listed it. A packet that opens but is
refused for good (malformed, another recipient, a signer that is not a
finalized controller) is acknowledged too, so junk sealed to the node's key
does not hold its quota; the refusal is reported without contents. So is a
frame the inbox refuses for what it is or for its bounds (a frame conflicting
with a stored one, the open-message limit): the sender's own redelivery brings
the message again. An
unavailable chain or a failing inbox write leaves the envelope for a later
poll. An envelope that does not open, or that names a key the node does not
hold, is remembered by relay and envelope id (never by the id alone, so a junk
copy at one relay never hides the genuine envelope at another) and left to
expire. An envelope whose listing names a key id the node does not hold is
remembered without being downloaded: the key id in a listing is the relay's
unauthenticated word, and a relay that lies about it can only hide that
envelope, which it could do anyway.

Implementation bounds: the not-again memory and the memory of settled
envelope ids each hold at most 8,192 entries and forget an entry after its
listed expiry, at most 24 hours and 5 minutes; evicting one only costs a
repeated download. At most 8 cards are kept per peer Agent (the least
preferred is dropped) and at most 1,024 peers; a node holds at most 16 own
keys.

**Keys.** Each node holds HPKE private keys in `state_dir/relay/keys`, one
owner-only (`0600`) file per key, written atomically; a key is never printed,
logged or placed in a report. Each key is published by a **key card**: an
Agent Packet to the all-zero audience, signed by the node's packet controller
through tosctl, naming the public key, its validity window and the node's
relay URLs. A card is valid for 7 days; `serve` issues a successor 48 hours
before expiry (and whenever `relay_urls` changes) and keeps every private key
until 24 hours and 5 minutes after its card expired, the longest an envelope
sealed in time can wait at a relay, then destroys it. A card handed out for a
request that runs past the 7 days is issued for the full 30 days and handed
out again for any long request while it still runs at least 15 days, so a node
holds a few keys at most whatever its requests' deadlines; such a request may
outlive its card, and the newer card reaches the peer in band. Each
maintenance pass also picks up and destroys on time keys that `offer` or `buy`
wrote while `serve` ran, and rewrites the provider's offer file whenever the
card it carries is no longer the current one (a failed rewrite is retried at
the next pass).

**How cards travel.** The provider's card is in its offer file; `serve`
rewrites the offer file when it issues a successor, and the owner hands the
new file out as before. Each result also carries the provider's current card,
valid until the end of the redelivery window, so a buyer whose offer-file card
expired during a long request keeps a route back for its acknowledgement. The
buyer takes it only from a result of one of its own purchases from that
provider, verifies it like an offer-file card, and records a refused card on
the purchase (`provider_card_refused`) without refusing the result. The card
in the offer file is a long one (30 days, reissued once it runs under 15), so
a buyer that was away longer than a short card lives can still reach the
provider.

**Asking for a result again.** After the respond is final the buyer has
nothing else to send until the result arrives, so the provider's copy of the
buyer's card is not refreshed. A buyer that sees a finalized respond and has
no result sends a result request carrying its current card (valid to the end
of the result's retention): at once when it first sees that state, also after
`serve` restarts, and then at most every 6 hours until the result arrives or
the retention ends. The provider takes it only from the request's buyer and
only for a request it has responded to and still retains; it verifies the
card like a task card, keeps the newest valid one and delivers the result at
its next pass (at most one such moved delivery every 10 minutes). A result
request never admits, executes or responds. Anything else is refused and
changes nothing. A buyer away for longer than the provider card it holds can
reach the provider only after it takes a newer offer file. The buyer verifies the card against finalized state
and requires its Agent to be the Capability's **finalized owner, read from
chain** (never from the offer file) before anything is paid; it seals only to
a card verified within the last 9 minutes. A peer card that names a relay on a
loopback host is refused unless this node's own relays are on loopback (a
single-host test setup), so a verified peer cannot make the node send requests
to services on its own host. A numeric host must be four canonical decimal
octets or an IPv6 literal; short, octal, hex and integer forms such as
`127.1` are refused everywhere, in peer cards and in `--relay-url`. A name
that resolves to a loopback address through DNS is not caught: the node would
only POST a ciphertext envelope to, or list and download from, whatever
answers there, and opens nothing it gets back. The buyer's card travels inside its
signed and encrypted task; it is chosen to cover the request's response and
refund deadlines plus a day, and the provider takes it only from a task the
gate admitted and only when the card's Agent is the task's sender. Each task
redelivery and each result acknowledgement carries the buyer's then-current
card again, so a card that would expire before a long response window and
redelivery horizon end is refreshed in band; the provider takes a card from an
acknowledgement only when it is from that request's buyer for its result, and
seals to the newest valid card it holds. A card refused there is noted on the
provider's record (`detail`) without refusing the acknowledgement. A stale
offer file may still hand out an older card of the same owner: it is accepted
as long as it is valid, and of the valid cards the newest is used.

**Revoking a card.** Publishing a new card does not revoke the old one: until
its expiry a stale offer file can keep handing it out. A compromised offer-card
key stays sealable for up to 30 days, the offer card's lifetime, unless the
controller that signed it is removed. Cards are signed by the packet
controller, so the only early revocation is replacing the packet controller in
the Agent's finalized policy. Do this when a node's state directory (and so its
HPKE keys) may have been exposed. The procedure:

1. drain or finish responded requests and claim open buyer refunds before
   rotating (see the costs below);
2. create a new controller in the vault (`tosctl agent native-registry
   new-controller --name <new>`);
3. build the policy update with `tosctl agent native-registry action --kind
   update-policy --agent <agent address> --nonce <32-byte hex> --policy <next
   policy JSON: the new controller with weight 1, purposes 15, thresholds 1>
   --signer <current packet controller> --counter-signer <new>` (it builds
   and signs; it sends nothing). The policy file has the shape `init` writes
   (`threshold`, `recovery_threshold`, `recovery_timelock`, `controllers`
   with `public_key`, `weight`, `purposes`). Send the signed message from the
   owner wallet with `tosctl wallet send --from <wallet> --to <agent address>
   --amount-nanotos 2000000000 --body-boc <body> --yes` and wait until the new
   policy is finalized. `--amount-nanotos 2000000000` is the value `init` and
   `offer` attach to registry messages. The registry requires no minimum: the
   value pays this message's processing (at most about 0.014 TOS at the
   genesis basechain gas price), and the rest stays in the Agent's registry
   object; it is not refunded;
4. re-establish the node with `init` against a **new** state directory and
   `--packet-controller <new>`, keeping the rail configuration that names the
   Agent: `init` adopts that Agent ID, sends nothing, and rewrites the
   configuration with the new controller, key id and state directory. Pass
   `--messenger-carrier-socket` again, with every other chat flag the node was
   set up with (`--chat-relay-url`, `--messenger-evidence-dir`,
   `--messenger-contact-dir`, `--chat-timeout-seconds`): with that flag `init`
   rebuilds the whole `chat` section, so a flag not passed again is dropped,
   and `--chat-card-path` and `--chat-carrier-socket` default to the new state
   directory. Without it the kept section still points into the old
   directory. Then set the Messenger daemon's `relay_carriage.card_path` and
   `carry_socket_path` to the new paths. `init` on the existing state directory refuses another
   packet controller once the registration was sent (`ErrSetupInputChanged`,
   see above): rotating the packet controller in place is not supported yet
   (see the known limits below).

What it costs:

- every rail, offer, chat and contact card the old key signed stops working
  at its next verification. A provider runs `offer` again from the new state
  directory: it keeps the same Service Actor (its address does not depend on
  the packet controller: the owner wallet owns the actor and the attestor
  controller attests), registers a **new** Capability and points the actor's
  metadata at it; publish the new offer file. Buyers holding the old offer
  file are refused before paying, since its card no longer verifies. The old
  Capability stays registered: revoke it (`tosctl agent native-registry
  action --kind revoke-capability`, signed by the new packet controller, sent
  from the owner wallet). Peers need new chat contact files;
- packets already journaled and signed by the old key never verify again. As
  a provider: a request not yet responded to ends through the timeout refund
  (the buyer's node sends `expire` and `claim-refund` once the response
  deadline passes, within the refund claim window); a request already
  responded to on chain is not refunded, and its result, held only in the old
  state directory, cannot be redelivered, so finish or drain responded
  requests before rotating where possible. As a buyer: open purchases are
  recorded only in the old state directory, so the new node never expires or
  claims them; for each one, take the actor and request id from the old
  directory's purchase records and send `tosctl agent service send
  --operation expire` and then `--operation claim-refund --destination <owner
  wallet>` (`--address <actor> --request-id <id> --from <owner wallet>`)
  before its refund claim window closes, or the refund lapses;
- the new state directory starts without the old one's courier, envelope and
  purchase journals, inbox and relay keys; the old directory is kept for
  reference, not run;
- if the ML-DSA-44 key itself is compromised, the attacker holds the only
  Agent-control and recovery weight and can race the policy update or start a
  recovery: that is total identity compromise, as the relay specification
  (section 11) states, not a card revocation;
- the attestor controller is separate and is not affected.

**Known limits.** Rotating the packet controller of an established node in
place (keeping its state directory, journals and keys) is not supported; it is
a follow-up.
**Withdrawing envelopes sealed to a revoked card.** The envelope journal
keeps each envelope's acknowledgement secret and the signed packet (as the
courier outbox already does), owner-only; neither is ever logged or placed in
`status`. While an envelope stands at a relay, each background pass checks
its card (verifying it again once the last check is 9 minutes old). When the
card is refused before its own expiry (it no longer verifies against
finalized state, or is no longer held), the sender journals the withdrawal,
then acknowledges the envelope with its secret at every relay of the card
that did not answer `409` for it (an ambiguous deposit may have left it
there). `204` and `404` both mean it is gone, as does any other refusal that
cannot change (`403`, another `4xx`). Anything else is retried at a later
pass. In the same pass the packet is sealed to the recipient's current
valid card under a fresh secret, journaled before its first deposit, and
deposited at that card's relays by the background loop; if every relay of
that card answers `409` for it, it is sealed again under a fresh secret,
journaled, and deposited after the deposit backoff, as the courier does for
its own sends. Consecutive rounds of `409` at every relay count as failures:
the backoff doubles from 30 seconds to its 5-minute cap, so a relay refusing
every id costs one seal per backoff period, at most about 300 a day per
packet once at the cap. A finalized-state outage (an unreachable chain, an
unavailable tosctl) is never taken for a revocation: nothing is withdrawn or
sent until the card's standing is known. Without a valid card
the packet waits until one is learned or it expires. A packet the recipient
already took may so arrive twice; the durable inbox deduplicates it. A card
refused only because it expired is not a revocation: the recipient keeps its
key long enough to open every envelope sealed in time, so those envelopes
are left to be fetched. Bounds: at most 16 withdrawal requests per pass over
the whole journal; at most 4 envelopes still to be withdrawn per packet (past
that the oldest secret is forgotten and its envelope left to expire). A
withdrawal entry, with its secret, is deleted once every relay answered, or
when its envelope expires; the journal record, with every secret in it, is
deleted when its last envelope and, while it waits for a card, its packet
expired. `status` lists, per journaled envelope, the envelope ids still to be
withdrawn and their relays (`withdrawing`) and `awaiting_card`, never a
secret. A sender that did not keep a secret (a record from before this
change) leaves its envelopes until they expire, at most 24 hours.

**Status and preflight.** `status` adds `relay`: each relay's polling state
(last listing, last failure, consecutive failures, next poll), the held keys
(key id, validity, destruction time; never the key), the peer cards and every
journaled outgoing envelope with the relays that accepted it, answered `409`
or are still pending. `preflight` checks `relay.config`, `relay.trust` (the
trust anchor each relay is verified against; it fails when a pinned CA file
is unreadable, changed, expired or not yet valid, and warns within 30 days of
a pinned certificate's expiry), `relay.reachable`
(each relay described and the mailbox listed), `relay.key` (a key valid now
for the configured relays), `relay.card` (the own card verifies against
finalized state) and `relay.peers` (each held peer card verifies).

Setup across two hosts, in order:

1. provider: `init --relay-url <relay>`, then `offer` (the offer file now
   carries the card), `preflight` and `serve`;
2. buyer: `init --allow-provider <provider Agent> --relay-url <relay>`, then
   `serve`, and `buy --offer <file>`.

`scripts/service-front-door-e2e.sh` runs both nodes against a relay when
`E2E_RELAY_URL` names one. `scripts/service-relay-two-host-e2e.sh` runs the
sale with the buyer, the provider and the relay daemon in three Linux network
namespaces with no path between the nodes, the relay serving TLS under a
certificate authority generated for the run, and the relay stopped and
restarted twice during the sale.

#### Offer file and task fields

The offer file is a JSON object decoded strictly (unknown fields and trailing
data are refused, and only version 2 is accepted). Version 2 adds one optional
member, written after `manifest_cbor_base64`:

- `"relay_key_card_base64"`: standard base64 (RFC 4648 section 4, padded, no
  line breaks) of the exact signed Agent Packet V1 JSON bytes of the
  provider's key card packet, at most 16,384 bytes before encoding. It is
  absent when the provider has no relays. The decoder requires the packet to
  decode, its sender to be `provider_agent_id`, its recipient the all-zero
  audience, its Capability the all-zero Capability, no Quote commitment, and
  its payload a well-formed key card body; whether the card may be sealed to
  is decided only by the buyer's finalized-state and owner checks. The relay
  URLs are inside the card, under its signature, and are not repeated.

The task message header (`tos.openfox.rail-task.v1`) gains one optional last
member, `"buyer_key_card_base64"`, with the same encoding and bound, absent
when the buyer has no relays. The result message header
(`tos.openfox.rail-result.v1`) likewise gains one optional last member,
`"provider_key_card_base64"`: the provider's card, same encoding and bound,
absent when the provider has no relays. The result acknowledgement header
(`tos.openfox.rail-result-ack.v1`) gains one optional last member,
`"buyer_key_card_base64"`, with the same encoding and bound; the
acknowledgement message bound grows accordingly to 4 + 4,096 + 21,848 bytes.
The result request is frame kind 4 with message header
`{"schema":"tos.openfox.rail-result-request.v1"}` plus the optional member
`"buyer_key_card_base64"` (same encoding and bound) and no body; the request
it names is the frame's own binding (actor account, request id and request
hash), and its message bound is that of the acknowledgement. Both are inside the signed packets
and, over the relay, inside the encryption. Both headers are decoded
strictly, so a decoder that predates a member refuses a message carrying it.

### Private chat over the relays (Messenger relay carriage)

A node with a `chat` section carries the local Messenger daemon's one-to-one
chat across hosts through the same relays (`MESSENGER_RELAY_CARRIAGE_V1.md`
milestone M-R1). The daemon runs with `"transport": "agent-packet-relay"` and
`contact-files` discovery (see the Messenger `docs/RUNNING.md`); OpenFox signs,
seals and deposits each relay frame and hands every received frame back to the
daemon. OpenFox never sees chat plaintext, Messenger keys or session state.

- **Own chat key and card.** The chat lane has its own X-Wing keys
  (`state_dir/relay/chat-keys`, key files of schema
  `tos.openfox.relay-chat-key.v1`), its own peer-card store
  (`relay/chat-peers`) and its own envelope journal (`relay/chat-outbox`). No
  key serves both lanes: a rail key file is refused in the chat directory and
  the reverse, and a node holding one key id in both refuses to start.
- **Purpose at the key.** An envelope that opens under a chat key must be a
  chat packet (to this Agent, from another Agent, the zero Capability, no
  Quote, a relay frame as payload); one that opens under a rail key must carry
  an `OFR1` rail frame. Anything else is refused and relay-acknowledged before
  any finalized-state read, daemon call or write.
- **Cards only for admitted peers.** A peer's chat card is stored only when
  the daemon admitted the frame that carried it (`accepted`, `duplicate` or
  `held`, or `admitted` for an evidence frame), when it rides an ack that
  settled one of this node's copies, or from an imported contact file. A
  refused stranger's card is never stored.
- **Carriage.** `serve` answers `carrier.carry` on `chat.carrier_socket`:
  `carried` only once one relay of the peer's chat card accepted the envelope
  journaled under the daemon's idempotency key (a retry of that key resends
  the journaled envelope, or answers at once when a relay already took it),
  `no-peer-card` without a valid chat card of the peer, `peer-cap` when this
  node already keeps 24 chat envelopes for that peer (copies, every
  generation not yet withdrawn, evidence frames and its own delivery acks;
  envelopes the peer's mailbox listing no longer shows are not counted), and
  `retry` for anything that may pass later. A key whose journaled packet
  expired before any relay accepted it is signed again under the same key
  (an expired packet can never be accepted by the recipient), so a retry
  after a long outage carries rather than fails. An envelope with a deposit
  still due at one of its relays always counts towards the cap, and so does
  every envelope at a relay whose listing fails. When generation N+1 is accepted,
  generation N is withdrawn at every relay that may hold it, journaled and
  retried like the withdrawal after a card revocation; a withdrawn key is
  never deposited again. Chat packets may use the full sealed packet bound;
  rail packets keep 128 KiB.
- **Receiving.** The one poll loop lists every rail and chat relay and
  dispatches by key id. A chat frame goes to the daemon's
  `carrier.deliver` or `carrier.delivery-ack` on
  `chat.messenger_carrier_socket`; the kind-2 frame the daemon returns for a
  copy is sent back to the sender. `retry`, an unreachable daemon socket and
  unavailable finalized state leave the envelope at the relay; every other
  outcome, refusals included, is relay-acknowledged.
- **No Messenger packet transport.** A node with a `chat` section refuses to
  start with `messenger_socket` set: rail packets never travel inside chat.
- **Timeout.** `chat.timeout_seconds` (`init --chat-timeout-seconds`) bounds
  one carrier operation in both directions: 0 means 30 s, otherwise 1 to
  300. Set it to the daemon's `relay_carriage.timeout_seconds`.
- **Card signer.** The chat card is signed by the packet controller, like
  the rail and offer cards. This is a deliberate choice. The relay spec
  recommends a dedicated card-signing controller (a SHOULD), but the
  off-chain verifiers (`VerifyKeyCard`, `agentpacket.VerifyContact`,
  `agentpacket.VerifySender`) accept a signature by any controller of the
  Agent's finalized policy and check no purpose or weight. A second controller
  could therefore sign any Agent Packet and any card as the Agent, and kept in
  the same vault it would add an impersonation key while isolating little.
  A dedicated card controller becomes worthwhile only after a protocol change
  makes verifiers check a card-signing purpose. Until then, revoking a chat
  card early means replacing the packet controller, with the procedure and
  costs under "Revoking a card" above.

Setup, with the Messenger daemon configured to the same paths:

1. `init ... --relay-url <relay> --messenger-carrier-socket <daemon
   listen_socket_path> [--chat-relay-url <relay>] [--chat-carrier-socket
   <daemon carry_socket_path>] [--chat-card-path <daemon card_path>]
   --messenger-evidence-dir <daemon evidence_export_dir>
   --messenger-contact-dir <daemon contact_dir>`;
2. `openfox earning chat init --rail-config <file>` issues the chat key and a
   30-day card signed by the packet controller and writes it to the card
   path (start the daemon only after this: it refuses a missing card);
   `serve` republishes it while less than 15 days remain, and `chat
   republish` does so on demand;
3. once the daemon has published, `openfox earning chat contact export
   --rail-config <file> --out <contact>` writes the contact file
   (`tos.openfox.chat-contact.v1`, the daemon's `relay-contact.json` wrapped,
   carrying the current card);
4. the peer runs `openfox earning chat contact import --rail-config <file>
   --file <contact>`: the card is verified against finalized state and
   stored, and the relay contact goes to the daemon's contact directory,
   where the daemon verifies and commits the evidence. Importing is the
   owner's admission decision;
5. `openfox earning chat status --rail-config <file>` shows the current chat
   card, whether the card path holds it, the held chat cards and the chat
   journal; `preflight` checks the section and the published card;
6. `openfox earning chat contact remove --rail-config <file> <agent>`
   deletes that Agent's stored chat cards and the contact file its import
   wrote (for example after the daemon refused its evidence), so it stops
   occupying a card slot; a running `serve` stops sealing to it at once. An
   Agent with neither is refused. This stops only this node from sealing to
   the peer: no copy is carried to it and no delivery ack goes back to it.
   It does not remove the peer's committed relay evidence in the Messenger
   daemon, which still treats the peer as admitted and accepts its copies.
   To stop receiving from the peer, change the daemon's admission policy.

## Configuration

`--rail-config` names an owner-only (`0600`) JSON file. `init` and `offer`
write it; it can also be written by hand:

```json
{
  "network": {"network_id": "…", "genesis_root_hash": "sha256:…", "genesis_file_hash": "sha256:…"},
  "chain_global_config_file": "/…/global.config.json",
  "rpc_endpoints": ["https://…", "https://…", "https://…"],
  "registry_code_boc_file": "/…/native-registry.boc.base64",
  "registry_code_hash": "tvm-cell-sha256:…",
  "actor_code_hash": "tvm-cell-sha256:…",
  "state_dir": "/…/rail",
  "agent_id": "agent_…",
  "packet_controller": "provider-controller",
  "packet_key_id": "mldsa44:…",
  "tosctl": {"binary": "/…/tosctl", "sha256": "…", "config_path": "/…/tosctl-config.json", "vault_url_env": "VAULT_URL"},
  "wallet_name": "provider",
  "wallet_address": "0:…",
  "messenger_socket": "/…/messenger.sock",
  "direct_peers": {"agent_…": "/…/peer/rail-receiver.sock"},
  "relay_urls": ["https://relay-a.example", "https://relay-b.example"],
  "receiver_socket": "/…/rail-receiver.sock",
  "provider": {"capability_id": "cap_…", "version": "1.0.0", "manifest_file": "/…/<digest>.cbor",
               "attestor_controller": "service-attestor", "respond_budget_seconds": 120,
               "executor_socket": "/run/tos-service-executor/executor.sock",
               "offer_file": "/…/rail/setup/offer.json"},
  "buyer": {"gateway_url": "https://…", "gateway_token_file": "/…/token", "caller_id": "…",
            "policy": {"max_committed_per_purchase_nanotos": "2000000000", "max_committed_in_window_nanotos": "10000000000",
                       "window_seconds": 86400, "max_open_purchases": 4, "refund_reserve_nanotos": "300000000",
                       "allowed_providers": ["agent_…"]}}
}
```

`chain_global_config_file` is used by `offer` (tosctl derives the registry
identity domain from it). Any of `messenger_socket`, `direct_peers` and
`relay_urls` may be omitted as long as one is set. `relay_urls` is in ascending
byte order, as the key card lists it. `provider.offer_file` is the offer file
`offer` wrote; with relays, `serve` rewrites it with each successor key card.

The provider section names exactly one executor: `executor_socket`, or the
legacy `executor_binary` with `executor_sha256`, `containerd_socket` and
`fifo_dir`. A section with both, or with neither, is refused by `serve` and
fails `preflight`; the node never chooses for the owner.

## Executor

A job is a sandboxed `go test` run in a pinned image, started through a
private container runtime. Reaching that runtime is equivalent to being root
on the host, so only root may. Nothing else a provider node does needs root:
not tosctl, not the vault, not the Agent Packet listener.

### The executor service (default)

The operator installs, as root, the private container runtime and the
executor service in front of it. The steps, the unit and the service's own
statement of what it permits are in the executor repository:
[deploy/provider/README.md](https://github.com/tosnetwork/tos-ai/blob/main/deploy/provider/README.md),
section "Executor service: an unprivileged provider node". In short: the
service listens on `/run/tos-service-executor/executor.sock`, owned by root
and a dedicated group, in a directory only that group can enter, and admits
exactly one uid. The operator puts the node's user in that group (`tos-executor`
in the runbook) and sets `TOS_EXECUTOR_ALLOWED_UID` to its uid in the
service's environment file. A user newly added to the group reaches the
socket only from a new login session (or through `sg tos-executor -c …`);
`preflight` says so when that is why the socket cannot be reached. A
second provider node needs its own service instance. The service's storage
bounds are its own flags (`--min-free-bytes`, `--min-free-inodes`,
`--default-retention`, `--max-retention`). OpenFox does not install, start or
configure the service.

**The provider node then runs as that ordinary user**, with `state_dir`,
the tosctl configuration and the vault owned by it. Set `executor_socket`
(`offer` does, by default).

What the node's uid is able to make root do is exactly what the service
offers, and it is the service that enforces it:

- run the one frozen job (the pinned image, `go test ./... -count=1`, an
  unprivileged uid inside the sandbox, no network, no device, read-only root,
  no host mount), a bounded number at a time, under limits a request can only
  tighten;
- keep each job's journal record, artifact and report in the service's own
  root-only directories until a deadline, within the service's storage bounds.
  The service decides the deadline: what a request asks for is capped at the
  service's maximum (31 days after the job by default), and a request that
  asks for none gets the service's default (7 days);
- spend execution identities: an identity is run at most once, whatever its
  outcome.

A request has no field for a path, an image, a command, an argument, an
environment variable, a mount, a network, a device or a user. The node sends
the source archive bytes and four digests; it receives the outcome and the
artifact and report bytes. It never reads a file of the service.

What the node does with an answer:

- **It trusts only a root server.** Every connection is refused unless the
  kernel reports that root serves the socket.
- **It verifies every success itself**: the outcome must name exactly this
  request (Quote commitment, execution id, input digest, source digest), this
  manifest as its sandbox and the manifest's toolchain image, be a completed
  run with exit code zero, and the artifact and report bytes must have the
  sizes and SHA-256 digests the outcome states. The same Receipt and attestor
  policy checks as before follow.
- **It keeps its own copy.** The verified artifact and report are stored
  under `state_dir/executor-service/artifacts`, and delivery, redelivery and
  the manifest retention use only that copy. The node never assumes the
  service still holds a result: it asks the service to keep its copy only
  until the request's response deadline, and ignores how long the service
  says it will. The node deletes its copy after the manifest retention ends.

| Answer of the service | The request |
|---|---|
| success, verified | is attested: `executed`, then `responding` |
| `execution_failed` | failed; never attested |
| `ambiguous`, `conflict` | `unknown`: the service holds the execution id without an outcome for this request (`conflict`: bound to other commitments or other limits); never run again, never attested |
| `in_progress` | stays `executing`: the run is in flight, nothing is spent or failed; the same request is sent again until its outcome is there |
| `busy`, `unavailable` (the runtime is down, or the pinned image is not imported and unpacked), `timeout`, `storage_full`, `retention_full`, `objects_unavailable` | stays `executing`: nothing was claimed, so the execution id is not spent; the same request is sent again |
| `not_allowed`, `invalid_request`, `limits_refused` | stays `executing`, since nothing ran, and the error is logged every round: fix the service's configuration |
| no answer, a dropped connection, a response that breaks the protocol or fails a check, a server that is not root | stays `executing`; nothing in such an answer is trusted, and the same request is sent again |

Sending the same request again is always safe: the service runs an execution
id at most once and answers a repeated request from its journal, so asking
never starts a second run. `serve` asks again every round (five seconds).
"The same request" includes its limits: they are taken from the manifest the
request was admitted under, recorded with the request, and sent unchanged
every time, whatever manifest the node is configured with later.

- **Before admission.** The node asks the service to describe itself before a
  task takes its execution slot. While the service is down, not ready, would
  not run this manifest or does not answer in time, the task is not admitted:
  nothing is verified, claimed or spent, so an outage of the service (a
  restart of its unit, for example) does not use up a paid request's one
  execution. Such a task is not a failed handling and does not count toward
  the inbox's attempt cap; it waits, outside the inbox's open-message bounds
  and under the same held bounds as a paused task, and is tried again every
  round. `serve` logs one `executor not ready` line per round with the number
  waiting. The node cannot know a request's response deadline before it
  admits the task, so the wait is bounded by the inbox instead: after one
  hour the task is retired with a logged reason. Retiring claims nothing
  either. A buyer delivers an unanswered task again every ten minutes, and a
  delivery of a retired task is handled again, so the request is still
  admitted if the service is back while it can be answered; otherwise the
  buyer's refund path applies. Any other failure of a task still counts
  toward the attempt cap.
- **Restart.** A run belongs to the service and outlives the node. A node
  that stops or dies during a run finds the request `executing` when it
  starts again and sends the same request (the source archive is kept in
  `state_dir/provider/` for this). The rail gate marks every slot that was
  started when the node stopped as `ambiguous`, with the restart as its
  recorded cause, and an ambiguous slot is never attested. So the node hands
  the gate the response hash of the outcome the service recorded; the gate
  verifies the request afresh from finalized state and completes the slot
  itself (`slot_state` `completed`, the slot marked `reconciled`). Only then
  does the usual pre-respond check and `respond` follow.
  If the node died after the gate started the slot and before the service
  was asked, the request sent after the restart runs the job for the first
  time, without the gate's pre-execution check that execution and respond
  still fit: at worst the provider runs a job it can no longer be paid for,
  never a wrong attestation, since the gate verifies the request again before
  it reconciles.

  | The gate's answer to the recovered outcome | The request |
  |---|---|
  | reconciled (or the slot already holds this response hash) | `executed`, then `responding` |
  | no finalized checkpoint could be read | stays `executing`; asked again next round |
  | the slot cannot be reconciled (not ambiguous because of a restart, or it is another request's) | `unknown`, with the gate's reason in the record's `detail`; never attested |
  | the slot is completed with another response hash | `unknown`, with the reason in `detail`; never attested |
  | the verifier refuses the request (no longer pending, respond budget gone) | not attested; stays `executing` until the deadline rule below abandons it |

- **Deadline.** The node waits for an outcome only while `respond` would
  still fit: until `respond_budget_seconds` before the request's response
  deadline. After that the request is `abandoned`, the service is no longer
  asked, and the buyer's refund path applies. A run that finishes later is
  never attested.

### Legacy single-user mode

An operator who runs the node and a container runtime as **one** user can
keep the earlier arrangement: `offer --executor <binary> --containerd-socket
<socket>` (optionally `--executor-sha256`, `--fifo-dir`). OpenFox then runs
the pinned executor binary (tos-ai `software-work-execute`) as its own child
process and reads the executor's artifact store under
`state_dir/executor`. The executor accepts only a runtime socket, in a
private directory, that its own user owns, so **the node runs as the user
that owns the runtime socket**.

With a root-only runtime that user is root, for every provider command: the
pinned tosctl, the vault access and the receiver socket then run as root,
tosctl run as root refuses a configuration under a directory another user can
modify, on the same-host direct transport the buyer node has to be root too,
and `preflight` warns `process.user`. That is what the executor service
removes; use this mode only with a runtime whose socket an ordinary user owns,
or when no service can be installed. In this mode an execution that has no
outcome when the node restarts is ambiguous for good and is never attested.
