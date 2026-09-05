# PredictionMarket V1 acceptance

This runbook owns the release evidence that crosses the OpenFox, protocol,
tosctl, Agent Account V2, and PredictionMarket contract boundaries. Unit and
sandbox suites remain mandatory, but they do not replace these live gates.

## Oracle context three-node gate

`TestPredictionOracleContextThreeNodeReleaseGate` proves that the production
OpenFox observer can:

- execute one exact, owner-pinned tosctl binary;
- bind three distinct single-endpoint configurations to the same zero state;
- reproduce the deployed market address, code hash, configuration hash, rules
  hash, and selected Oracle policy hash;
- decode the exact contract-built normal or appellate context BOC; and
- obtain the same economic context from all three nodes even when their latest
  masterchain checkpoints differ.

The test is opt-in because it reads a live local chain. With the gate disabled,
the ordinary package suite compiles the test and reports a skip. Once
`OPENFOX_PREDICTION_CONTEXT_THREE_NODE_E2E=1` is set, every fixture is required;
missing binaries, files, RPC identity, or evidence output is a hard failure.

The tosctl executable must be an absolute regular file under trusted ancestry,
must not be writable by group or other principals, and must be smaller than the
production executable limit. A release binary is preferred. A local debug
binary may be copied to an owner-private directory and stripped without
changing the source revision under test.

Required environment:

```text
OPENFOX_PREDICTION_CONTEXT_THREE_NODE_E2E=1
OPENFOX_PREDICTION_TOSCTL=/absolute/trusted/tosctl
OPENFOX_PREDICTION_MARKET_DEFINITION=/absolute/market.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_1=/absolute/node-1.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_2=/absolute/node-2.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_3=/absolute/node-3.json
OPENFOX_PREDICTION_NETWORK_ID=tos:local-three-node
OPENFOX_PREDICTION_GLOBAL_ID=3
OPENFOX_PREDICTION_WORKCHAIN_ID=0
OPENFOX_PREDICTION_ZERO_STATE_ROOT_HASH=<32-byte Base64 or sha256: lowercase hex>
OPENFOX_PREDICTION_ZERO_STATE_FILE_HASH=<32-byte Base64 or sha256: lowercase hex>
OPENFOX_PREDICTION_ROUND=normal|appeal
OPENFOX_PREDICTION_ROUND_POLICY_HASH=tvm-cell-sha256:<lowercase hex>
OPENFOX_PREDICTION_REPORTER_ADDRESS=<raw admitted reporter address>
OPENFOX_PREDICTION_SOURCE_AGENT_CODE_HASH=tvm-cell-sha256:<Agent Account V2 code hash>
OPENFOX_PREDICTION_EVIDENCE_DIRECTORY=/absolute/owner-private/evidence
OPENFOX_PREDICTION_VAULT_URL=<operator-provided vault capability, when tosctl requires it>
```

Run:

```sh
GOWORK=off go test ./pkg/earning \
  -run TestPredictionOracleContextThreeNodeReleaseGate -count=1 -v
```

The gate writes
`prediction-oracle-context-<market-id>.json` atomically with mode `0600`. The
report deliberately contains no vault URL, private key, source snapshot, or
configuration path. It retains the exact context BOC, all immutable hashes,
the network-domain digest, and each observer's checkpoint.

Changing the expected round policy hash must make the gate fail before it can
claim quorum. A stale context can still be observed for audit, but
`OracleJournal.PrepareVote` rejects it at or after its deadline; this gate does
not claim that a stale context remains voteable.

## Evidence archive replicas

Each reporter must operate at least two `FileEvidenceArchiveReplica` instances
in independent failure domains with distinct signing keys admitted by the
Oracle profile. Each instance requires explicit maximum object size, object
count, and total content bytes. Capacity exhaustion fails before a receipt is
signed. Objects are keyed by their exact SHA-256 content digest, and an
existing digest cannot be rebound to different source metadata or bytes.

Retention can only increase while an object exists. Pruning removes an object
only after its inclusive `retain_until` boundary is in the past, synchronizes
the rooted directory, and only then releases in-memory capacity. Operators
must monitor the configured watermarks and provision capacity for the maximum
claim deadline plus audit-retention horizon before admitting a market.

## Remaining release gates

The context gate is one component of system acceptance, not a substitute for
the complete lifecycle. Release remains blocked until separate machine-readable
reports cover:

- real, future-height block-root entropy producing YES and NO cases;
- factual INVALID, no-proposal Oracle timeout, challenge uphold, challenge
  overturn, and challenged-proposal appellate timeout;
- Agent Account V2 signed, durable, broadcasting, source-finalized,
  destination/bounce-resolving crash points;
- cursor recovery after more than 10,000 later source and destination
  transactions;
- maximum participant/order/vote state, storage rent, fee, reserve, and gas
  headroom; and
- bounded hostile Intent, WAL, index, quarantine, and evidence ingestion with
  post-compaction recovery.

No report may label one of those gates `PASS` based on mocks, a missing fixture,
an already-known outcome, or a latest-state getter standing in for exact
transaction evidence.
