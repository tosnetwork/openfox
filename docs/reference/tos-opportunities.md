# TOS opportunity discovery

OpenFox can periodically discover software-work opportunities without giving
the AgentLoop Gateway credentials, finalized-chain authority, custody, or a
payment interface. The feature is disabled by default.

The process boundary is:

```text
OpenFox opportunity scheduler
  -> owner-private Unix socket
  -> tos-service-opportunity-coordinator
       -> bounded multi-Gateway search (hint only)
       -> independent strict-majority finalized Capability read
       -> exact content-addressed canonical manifest
  -> durable local assessment journal
  -> read-only opportunities tool
```

Gateway display fields and match scores remain explicitly marked untrusted in
tool output. They may order operator review; they never authorize a Quote,
mandate, payment, execution, Receipt, or settlement. The coordinator verifies
the exact network, CapabilityID, owner AgentID, version, manifest digest,
Registry code hash and finalized checkpoint before OpenFox records a candidate
as verified.

## OpenFox configuration

Create the state directory in advance as an owner-private directory:

```sh
install -d -m 0700 /var/lib/openfox/opportunities
```

Then configure observe-only polling:

```json
"opportunity": {
  "mode": "observe",
  "coordinator_socket": "/run/openfox/opportunity.sock",
  "state_dir": "/var/lib/openfox/opportunities",
  "queries": ["bounded Go testing", "static analysis"],
  "interval_minutes": 30,
  "jitter_seconds": 120,
  "request_timeout_seconds": 10,
  "page_size": 20,
  "max_candidates": 40,
  "allowed_operations": ["static-analysis", "test"],
  "allowed_providers": [],
  "denied_providers": []
}
```

Arrays used as policy sets must be sorted and unique. Polling cannot be more
frequent than five minutes, one query returns at most 100 entries, and a cycle
retains at most 1,000 hints. Exact retries reuse the existing canonical
candidate record. A transient coordinator or chain failure remains retryable;
a finalized ownership, lifecycle, version or manifest mismatch becomes a
durable terminal rejection.

The `opportunities` AgentLoop tool only lists finalized, locally assessed
records. It has no mutation operation. `policy-gated` is a separately typed
mode and currently fails startup unless the Phase D purchase runner is
explicitly assembled; there is no unrestricted autonomous-spend mode.

## Coordinator configuration

The coordinator belongs to the native implementation module and is started
separately:

```sh
tos-service-opportunity-coordinator \
  -config /etc/openfox/opportunity-coordinator.json -check
tos-service-opportunity-coordinator \
  -config /etc/openfox/opportunity-coordinator.json
```

The configuration is a mode-0600 strict JSON document:

```json
{
  "schema": "tos.openfox.opportunity-coordinator-config.v1",
  "state_dir": "/var/lib/openfox/opportunity-coordinator",
  "socket_path": "/run/openfox/opportunity.sock",
  "network": {
    "network_id": "tos-mainnet",
    "genesis_root_hash": "sha256:<64 lowercase hex>",
    "genesis_file_hash": "sha256:<64 lowercase hex>"
  },
  "chain_endpoints": [
    "https://rpc-a.example",
    "https://rpc-b.example",
    "https://rpc-c.example"
  ],
  "chain_quorum": 2,
  "registry_code_boc_path": "/etc/openfox/native-registry-code.boc",
  "registry_code_hash": "tvm-cell-sha256:<64 lowercase hex>",
  "caller_id": "openfox-opportunity",
  "request_timeout_seconds": 10,
  "max_results": 400,
  "credential_quota_enforced": true,
  "gateways": [
    {
      "id": "gateway-a",
      "base_url": "https://gateway-a.example",
      "bearer_token_file": "/etc/openfox/gateway-a.token"
    },
    {
      "id": "gateway-b",
      "base_url": "https://gateway-b.example",
      "bearer_token_file": "/etc/openfox/gateway-b.token"
    }
  ]
}
```

Gateway entries must be sorted by ID and use distinct origins. Credential files
must be mode 0600. Remote Gateway and chain origins require HTTPS; plaintext is
accepted only for an explicitly declared loopback test endpoint. Recurring
polling is refused unless the operator declares enforced per-credential quotas
or a finite checkpoint-cache age. That declaration is deployment
configuration, not fabricated evidence that an external Gateway actually
enforces it.

The coordinator contains no wallet or `tosctl` configuration and exposes only
search and verification operations on its private socket.
