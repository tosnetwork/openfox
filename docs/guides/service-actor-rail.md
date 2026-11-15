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
- **A carrier for Agent Packets.** Across hosts that is a `tos-messengerd`
  daemon per Agent (below); on one host two nodes of one user can use the
  direct transport instead.
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
  --messenger-socket /…/messenger.sock        # or --direct-peer, below
```

The transport may be left out of the first run. Two nodes that reach each
other directly each need the other's Agent id, which only that node's `init`
produces; so `init` without a transport establishes the node, reports
`transport: missing`, and `serve`, `buy` and `preflight` refuse until `init`
is run again with `--direct-peer` or `--messenger-socket`. That second run
sends nothing.

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

   The offer file (`tos.openfox.rail-offer.v1`) holds the Capability id, the
   version, the provider Agent id, the manifest digest and the manifest bytes.
   It holds nothing secret and carries no authority; give it to buyers.
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
  "receiver_socket": "/…/rail-receiver.sock",
  "provider": {"capability_id": "cap_…", "version": "1.0.0", "manifest_file": "/…/<digest>.cbor",
               "attestor_controller": "service-attestor", "respond_budget_seconds": 120,
               "executor_socket": "/run/tos-service-executor/executor.sock"},
  "buyer": {"gateway_url": "https://…", "gateway_token_file": "/…/token", "caller_id": "…",
            "policy": {"max_committed_per_purchase_nanotos": "2000000000", "max_committed_in_window_nanotos": "10000000000",
                       "window_seconds": 86400, "max_open_purchases": 4, "refund_reserve_nanotos": "300000000",
                       "allowed_providers": ["agent_…"]}}
}
```

`chain_global_config_file` is used by `offer` (tosctl derives the registry
identity domain from it). `messenger_socket` may be omitted when
`direct_peers` is set, and `direct_peers` when `messenger_socket` is.

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
  task takes its execution slot. While the service is down, not ready or would
  not run this manifest, the task is not admitted and stays in the inbox, so
  an outage of the service does not use up a paid request's one execution.
- **Restart.** A run belongs to the service and outlives the node. A node
  that stops or dies during a run finds the request `executing` when it
  starts again, sends the same request (the source archive is kept in
  `state_dir/provider/` for this) and attests the one outcome. The rail gate
  marks every slot that was started when the node stopped as `ambiguous`
  (`slot_state` in `status`) and cannot be told the outcome; for such a
  request the node makes the same fresh finalized check before `respond`
  with the gate's verifier, and the record carries
  `recovered_after_restart`.
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
