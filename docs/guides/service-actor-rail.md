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
| owner wallet (provider) | tosctl wallet | `respond`, policy updates |
| attestor controller (`service-attestor`) | tosctl vault | the request-bound SRP2 response domain, inside `respond` |
| packet controller | tosctl vault, a controller of the node's Native Registry Agent | every Agent Packet |
| buyer wallet | tosctl wallet | `call`, `expire`, `claim_refund` |

Paid work requires a Messenger daemon for each Agent. Its delegation's
`allowed_outbound_event_classes` must include `agent.packet`, and its Agent
Packet receiver socket must point at the node's `receiver_socket`.

## Provider

1. Build the manifest (no chain effect):
   `openfox earning service manifest --provider-agent agent_… --actor 0:… --code-hash tvm-cell-sha256:… --attestor mldsa44:… --out-dir <dir>`.
   Key 12 limits the output to 1 MiB, key 17 commits to the Agent Packet
   transport binding, key 18 names the attestor and key 21 the actor with the
   pinned release code hash.
2. With tosctl, deploy the Service Actor with the attestor controller, register
   the Capability with the manifest digest, then set the actor's metadata hash
   to the value `openfox earning service metadata` prints.
3. Serve Quotes from the provider's gateway with a quote-source profile of
   transport security mode `2`: `base_url` `agent-packet:<provider Agent id>`
   and `max_request_bytes` `1048576`.
4. Run `openfox earning service serve --rail-config <file>`. For each task it
   verifies the packets and the Quote, refuses input over the quoted bound,
   admits the request once through the finalized rail gate (pending, call
   proven, lifecycle replayed, getters cross-checked, time left to execute and
   respond), re-checks immediately before execution, runs the executor, builds
   the `SoftwareWorkReceiptV1`, checks it against the attestor policy (exact
   request bindings, charge equal to the price, the runner's own outcome), re-
   checks the request is still pending, and sends `respond`. After the respond
   is final it delivers the result and redelivers it in fresh packets until the
   buyer acknowledges it or the manifest retention ends. A failed or ambiguous
   execution is never attested; the buyer's refund path applies.
   `openfox earning service status` lists the requests (see below).

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
| `process.user` | warns when running as root |
| `tosctl.pin`, `executor.pin` | the binary is missing or does not hash to its pin |
| `tosctl.config` | the tosctl configuration is missing or world-accessible |
| `tosctl.vault_env` | the variable `vault_url_env` names is unset (its value is never printed) |
| `containerd.socket` | the runtime socket is missing, not a socket, or world-accessible; it is never connected to |
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
- `requests`: every request with the fields the earlier listing printed, plus
  `slot_state` (the rail gate's record), `chain_fact` and one
  `operator_state` with a `state_reason`.

| `operator_state` | Meaning |
|---|---|
| `admitted` | the rail gate admitted the request; execution has not started |
| `executing` | the execution was handed to the executor |
| `result_available` | executed and attested locally; respond not sent, or sent and the request still pending |
| `responded` | a finalized `respond` carries this request's attested response hash (price and storage fee credited to the actor) |
| `refunded` | a finalized `expire` made the price refundable, or `claim_refund` paid it to the caller |
| `swept` | a finalized `sweep_expired_request` returned the price to the caller |
| `outcome_unknown` | anything not established: a failed or ambiguous execution awaiting expiry, a respond whose finality was not read, a chain read that failed, an incomplete history, or local and chain facts that disagree |

These are projections of local records and finalized facts, not contract
states. `status` reads one finalized checkpoint through the node's own
checkpoint fences; `--offline` skips the chain, and a failed read is reported
in `actor.error`. In both cases states the chain would decide stay
`outcome_unknown`; only a respond the node itself saw finalized before
delivering is reported as `responded`. `--records` prints only the request
list, in the earlier array shape with the added fields.

### Pause and resume

`openfox earning service pause --rail-config <file> [--reason <text>]` writes
an owner-only marker `state_dir/admission-paused`; a running `serve` checks it
before every admission, so no restart is needed. Work already admitted still
executes, responds and delivers. A task that arrives while paused is held in
the inbox, not refused and not counted against its retry cap; after
`openfox earning service resume` it is admitted if its request is still
admissible. A held task is pruned with other incomplete inbox entries after an
hour, and a request that is never answered falls to the buyer's refund path.
Pausing never touches funds. It does not stop buyers from calling the actor;
to stop new calls on chain, change the actor's policy with the owner wallet.
An unreadable marker is treated as paused.

## Buyer

`openfox earning service buy --rail-config <file> --capability-id cap_… --source <archive>`

1. Takes a Quote from the configured gateway (or `--quote-package`), verifies
   the offer at a finalized checkpoint and validates the Quote.
2. Refuses input over the quoted inline bound (at most 1 MiB) before anything
   is reserved or paid.
3. Shows the costs and applies the owner policy: the price (refunded only if no
   attested response arrives and the refund is claimed), the non-refundable
   storage fee, the 0.2 TOS admission allowance, the attached value
   `price + storage fee + 0.2 TOS`, and that a refund takes two transactions
   from the buyer wallet inside the refund window (`expire`, then
   `claim_refund`, which attaches 0.2 TOS), each paying fees.
4. Prepares and calls with the quoted terms hash.

`openfox earning service serve` then delivers the task once the call is
admitted, accepts a result only when its Receipt hashes to the finalized
attested response and binds the buyer's own request, price and provider, and
the artifact matches every digest the Receipt states, and acknowledges it. If
the provider does not answer in time it sends `expire` and `claim_refund`.
`openfox earning service purchases` shows each purchase's phase, status,
required action, deadlines and costs.

## Configuration

`--rail-config` names an owner-only (`0600`) JSON file:

```json
{
  "network": {"network_id": "…", "genesis_root_hash": "sha256:…", "genesis_file_hash": "sha256:…"},
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
  "receiver_socket": "/…/rail-receiver.sock",
  "provider": {"capability_id": "cap_…", "version": "1.0.0", "manifest_file": "/…/<digest>.cbor",
               "attestor_controller": "service-attestor", "respond_budget_seconds": 120,
               "executor_binary": "/…/software-work-execute", "executor_sha256": "…",
               "containerd_socket": "/…/containerd.sock", "fifo_dir": "/…/fifo"},
  "buyer": {"gateway_url": "https://…", "gateway_token_file": "/…/token", "caller_id": "…",
            "policy": {"max_committed_per_purchase_nanotos": "2000000000", "max_committed_in_window_nanotos": "10000000000",
                       "window_seconds": 86400, "max_open_purchases": 4, "refund_reserve_nanotos": "300000000",
                       "allowed_providers": ["agent_…"]}}
}
```

The executor runs as a separate pinned binary (tos-ai `software-work-execute`),
so the container runtime client stays outside OpenFox.
