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
   `openfox earning service status` lists the requests.

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
