# PredictionMarket V1 acceptance

This runbook owns the release evidence that crosses the OpenFox, protocol,
tosctl, Agent Account, and PredictionMarket contract boundaries. Unit and
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
OPENFOX_PREDICTION_SOURCE_AGENT_CODE_HASH=tvm-cell-sha256:<Agent Account code hash>
OPENFOX_PREDICTION_EVIDENCE_DIRECTORY=/absolute/owner-private/evidence
OPENFOX_PREDICTION_VAULT_URL=<operator-provided vault capability, when tosctl requires it>
```

`OPENFOX_PREDICTION_TEST_MAX_CLOCK_SKEW_SECONDS` is deliberately absent from
the release configuration. It is a test-only, 120–3600 second override for an
accelerated localnet whose virtual block timestamps run ahead of wall time;
the default release freshness bound remains 120 seconds.

For the production relay profile, additionally set:

```text
OPENFOX_PREDICTION_SUBMISSION_PROFILE=agent-account-checked-call-v2
```

In that mode `OPENFOX_PREDICTION_MATCH_EXTERNAL_BOC` must be the exact,
already-submitted `agent_checked_contract_call_v2` external BOC, and
`OPENFOX_PREDICTION_MATCH_SOURCE_ADDRESS` must be its Agent Account destination.
The gate rejects a body mismatch, network mismatch, unconsumed controller
epoch/seqno, inactive source, or a source whose code is not the audited Agent
Account template on every observer. It also requires the V2 internal transport
flags on the unique source outbound. A valid report records the source template
hash and checked-call epoch, seqno, and expiry; these values are bound again
when the report is read.

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

## Future block-root entropy distribution gate

`TestPredictionFutureBlockEntropyDistributionThreeNodeReleaseGate` qualifies
the synthetic subject used by the eventual lifecycle E2E. It freezes a
contiguous historical window ending at the minimum finalized checkpoint seen
across the three nodes before issuing any sampled `lookupBlock` read. Every
block is then resolved by exact seqno on all three nodes. Root hash, file hash,
workchain, shard, and seqno must agree exactly.

The gate also reads ConfigParam 34 from each node. It decodes the returned BOC,
reconstructs every validator public key, ADNL identity, weight, and cumulative
weight, and compares those bytes with the RPC's decoded view. The three nodes
must return the same config cell hash. The future wager gate will use this
authenticated set to reject a participant trading key that is also an active
validator key.

The parity gate requires both outcomes and applies the frozen integer form of
a three-standard-deviation bound, `(EVEN - ODD)^2 <= 9 * sample_count`. This is
a subject preflight, not a proof of perfect randomness. The committed evidence
records 25 EVEN and 23 ODD results over 48 consecutively selected finalized
blocks.

Required environment:

```text
OPENFOX_PREDICTION_ENTROPY_DISTRIBUTION_THREE_NODE_E2E=1
OPENFOX_PREDICTION_TOSCTL_CONFIG_1=/absolute/node-1.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_2=/absolute/node-2.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_3=/absolute/node-3.json
OPENFOX_PREDICTION_NETWORK_ID=tos:local-three-node
OPENFOX_PREDICTION_GLOBAL_ID=3
OPENFOX_PREDICTION_WORKCHAIN_ID=0
OPENFOX_PREDICTION_ZERO_STATE_ROOT_HASH=<32-byte Base64 or sha256: lowercase hex>
OPENFOX_PREDICTION_ZERO_STATE_FILE_HASH=<32-byte Base64 or sha256: lowercase hex>
OPENFOX_PREDICTION_EVIDENCE_DIRECTORY=/absolute/owner-private/evidence
OPENFOX_PREDICTION_ENTROPY_SAMPLE_COUNT=48
```

Run:

```sh
GOWORK=off go test ./pkg/earning \
  -run TestPredictionFutureBlockEntropyDistributionThreeNodeReleaseGate \
  -count=1 -v
```

The output file is
`future-block-entropy-distribution-three-node.json`. A separate lifecycle gate
must still persist exact wager-acceptance evidence first, choose a height that
was future to every observer at that durable boundary, reject participant keys
present in ConfigParam 34, and reveal the result only after all three nodes
finalize and agree on that height. This distribution report cannot satisfy
those requirements by itself.

The acceptance harness includes the durable lock primitive used by the wager
gate below. It hashes the already-persisted accepted-wager evidence, requires two
sorted non-validator trading keys, snapshots the same active ConfigParam 34
from three distinct observers, and fixes the target to the greatest tip any
observer had already exposed plus exactly 60 blocks. Pre-lock observations may
be at most five seconds old. A process-level file lock serializes creation;
after a crash or restart, the same market and accepted-evidence digest can only
reuse the byte-identical lock and target. Different accepted evidence cannot
replace it.

## Direct-wallet contract acceptance and future reveal gate

`TestPredictionAcceptedWagerAndFutureRevealThreeNodeContractGate` proves the
contract portion of one fresh complete-set trade from immutable bytes. It
starts from the exact submitted external BOC, walks the source account's
hash-linked transaction history, requires one successful ordinary source
transaction, reconstructs its unique internal outbound message, and then
requires a successful market transaction that consumed that exact message.
The signed BUY YES and BUY NO orders must be valid, complementary, non-partial
maker/taker orders for one lot. Their prices must sum to the fixed price scale,
and their signatures, network, market, configuration hash, validity window,
and distinct trading identities are checked again offline from the evidence.

Each node independently locates both transactions. Their shard blocks are
then located by exact root hash, file hash, shard, and seqno in finalized
masterchain shard listings. The three observers must agree on the transaction
BOCs, outbound message, accounting, and market checkpoint. The accounting
must show exactly one complete set, fixed collateral conservation, and the
expected bounded cleanup liability.

After the accepted-wager report is durably written, the gate snapshots the
three observer tips and active validator set, excludes both participant keys
from that set, and atomically locks a block 60 heights beyond the greatest
observed tip. Only after every observer finalizes that height does it fetch the
same exact block from all three nodes and derive YES from an even first root
byte or NO from an odd first root byte. The reveal is bound to the exact
accepted report and future-lock file digests. Restarting cannot move or replace
either durable result.

Required environment:

```text
OPENFOX_PREDICTION_ACCEPTED_WAGER_CONTRACT_THREE_NODE_E2E=1
OPENFOX_PREDICTION_TOSCTL=/absolute/trusted/tosctl
OPENFOX_PREDICTION_MARKET_DEFINITION=/absolute/market.json
OPENFOX_PREDICTION_MATCH_EXTERNAL_BOC=/absolute/match-external.boc
OPENFOX_PREDICTION_MATCH_BODY_BOC=/absolute/match-body.boc
OPENFOX_PREDICTION_MATCH_SOURCE_ADDRESS=<canonical raw wallet address>
OPENFOX_PREDICTION_MATCH_SCAN_START_MC_SEQNO=<frozen nonzero masterchain seqno>
OPENFOX_PREDICTION_TOSCTL_CONFIG_1=/absolute/node-1.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_2=/absolute/node-2.json
OPENFOX_PREDICTION_TOSCTL_CONFIG_3=/absolute/node-3.json
OPENFOX_PREDICTION_NETWORK_ID=tos:local-three-node
OPENFOX_PREDICTION_GLOBAL_ID=3
OPENFOX_PREDICTION_WORKCHAIN_ID=0
OPENFOX_PREDICTION_ZERO_STATE_ROOT_HASH=<32-byte Base64 or sha256: lowercase hex>
OPENFOX_PREDICTION_ZERO_STATE_FILE_HASH=<32-byte Base64 or sha256: lowercase hex>
OPENFOX_PREDICTION_EVIDENCE_DIRECTORY=/absolute/owner-private/evidence
OPENFOX_PREDICTION_VAULT_URL=<operator-provided vault capability, when tosctl requires it>
```

Run:

```sh
GOWORK=off go test ./pkg/earning \
  -run TestPredictionAcceptedWagerAndFutureRevealThreeNodeContractGate \
  -count=1 -v
```

The default source profile is deliberately named `direct-wallet-contract-probe`
in the accepted report. The source wallet directly submitted the match call, so
that default proves contract execution, transaction provenance, accounting, and
one post-acceptance future-block reveal, but not the production relay path. Only
the explicit `agent-account-checked-call-v2` profile can claim the Agent Account
source boundary; it still requires separate durable-journal crash evidence.

## Evidence archive replicas

Each reporter must operate at least two `FileEvidenceArchiveReplica` instances
in independent failure domains with distinct signing keys admitted by the
Oracle profile. Each instance requires explicit maximum object size, object
count, and total content bytes. Capacity exhaustion fails before a receipt is
signed. Objects are keyed by their exact SHA-256 content digest, and an
existing digest cannot be rebound to different source metadata or bytes.

An archive replica now accepts an `ArchiveReceiptSigner`, not a raw key. The
production signer must be a narrow Vault/HSM client which returns the pinned
Ed25519 public key and signs only the archive-receipt digest; a process-local
`Ed25519ArchiveReceiptSigner` exists solely for tests and local development.
Each replica's Vault policy must permit only that digest-signing operation,
must be independently authenticated and audited, and must fail closed on a
key, identity, timeout, or signature mismatch. The archive's operator ID is
derived from the key returned by the signer at both initialization and signing
time, so a signer cannot silently rotate identity underneath a running
replica.

### Vault Transit receipt signer

`VaultTransitArchiveReceiptSigner` is the production adapter for an Ed25519
Vault Transit key. Its configuration pins the HTTPS Vault origin, Transit mount,
key name, immutable key version, and the expected 32-byte public key. It reads
the configured key version before archive initialization and verifies every
returned signature locally over the exact 32-byte archive-receipt digest.
Consequently a route change, key rotation, wrong key type, malformed response,
or signature from any other key fails closed rather than changing an archive
authority identity.

The Vault capability is process-secret input; do not put its token in a market
profile, OpenFox configuration file, report, evidence object, or command line.
For each replica, provision a distinct short-lived authenticated token with
only these paths (replace the mount and key literally; do not grant wildcards):

```hcl
path "transit/keys/oracle-replica-a" {
  capabilities = ["read"]
}
path "transit/sign/oracle-replica-a" {
  capabilities = ["update"]
}
```

Transit receives the SHA-256 receipt digest as the ordinary Ed25519 message;
the adapter does not request `prehashed`/Ed25519ph semantics, because the
protocol verifies ordinary Ed25519 signatures over that digest. Configure an
HTTPS endpoint with normal certificate validation and a non-exportable Transit
Ed25519 key. Separate replicas need distinct Transit keys, credentials,
operators, storage roots, and failure domains. Two signers or two directories
under one operator are development evidence only, not independent archival
availability.

Retention can only increase while an object exists. Pruning removes an object
only after its inclusive `retain_until` boundary is in the past, synchronizes
the rooted directory, and only then releases in-memory capacity. Operators
must monitor the configured watermarks and provision capacity for the maximum
claim deadline plus audit-retention horizon before admitting a market.

## Relay process-death recovery

`TestPredictionRelayRecoversFromProcessDeathAtDurableBoundaries` starts a
separate test process, lets it persist one normal relay transition, and ends it
with a forced process kill without running `Close` or any deferred cleanup. The parent
then reopens the real owner-private journal. It covers the signed durable
record, the pre-socket broadcasting boundary, source finality, destination
resolution, and bounce-credit resolution. Broadcasting recovery must resend
byte-identical durable BOC bytes; every post-source terminal recovery must
reject any rebroadcast.

Run it with:

```sh
GOWORK=off go test ./pkg/prediction \
  -run TestPredictionRelayRecoversFromProcessDeathAtDurableBoundaries -count=1 -v
```

This is an operating-system process-death test of OpenFox's durable relay
journal, not a substitute for an Agent Account three-node crash-injection
test. The latter must still kill the actual `tosctl`/relay process at every
chain-observation checkpoint and verify its exact transaction evidence.

### Three-node Agent Account crash injection (partial)

The TOS lifecycle harness now has an opt-in `agent-crash-recovery` scenario.
It starts three real local validators and sends `SIGKILL` to the actual
`tosctl` child only after an owner-private, fsync'd checkpoint proves one of
these durable boundaries:

- `signed`: the exact checked-call BOC and its digest are in the Agent Account
  custody journal, before it is marked broadcastable or emitted to an output
  file;
- `broadcasting`: the exact BOC is durable and the journal is in its
  pre-submission state, before the pinned RPC socket write;
- `source_finalized`: the exact source evidence is durable, before `tosctl`
  returns it to its caller.

Each kill is followed by a new `tosctl` process. The signed and broadcasting
paths must recover the byte-identical BOC; the source-finalized path must
replay the durable exact evidence without a replacement broadcast. The harness
also rejects a killed pre-submission process that advanced the Agent Account
seqno, and rejects a killed signer that wrote an executable output BOC.

Run it from the TOS checkout against a validator build:

```sh
TOS_BUILD_DIR=/absolute/path/to/build \
  /path/to/python scripts/prediction-market-v1-lifecycle-e2e.py \
  --scenario agent-crash-recovery
```

The OpenFox relay's own process-death test force-kills a real child process
after each durable relay transition, including destination and bounce credit,
then reopens the actual journal. In addition,
`TestPredictionRelayDestinationThreeNodeProcessDeathReleaseGate` combines the
real three-node source and destination resolvers with an actual forced process
death after durable destination evidence. It proves that restart is idempotent
and cannot rebroadcast the exact BOC. The remaining end-to-end crash gate is
the analogous real three-node bounce-credit path; its local forced-death test
is not a replacement for that chain-level evidence.

## Remaining release gates

The context gate is one component of system acceptance, not a substitute for
the complete lifecycle. Release remains blocked until separate machine-readable
reports cover:

- a production Agent Account checked-call v2 wager path with its own post-acceptance future
  lock and real reveal, plus a real YES case (the direct-wallet contract probe
  has produced one real NO case and the distribution preflight is complete);
- factual INVALID, no-proposal Oracle timeout, challenge uphold, challenge
  overturn, and challenged-proposal appellate timeout;
- Agent Account checked-call v2 real three-node bounce-credit crash recovery
  (the OpenFox relay journal has forced-process-death coverage at every
  durable transition; TOS signed, broadcasting, source-finalized, and OpenFox
  destination-resolving windows have three-node SIGKILL/retry evidence);
- cursor recovery after more than 10,000 later source and destination
  transactions;
- maximum participant/order/vote state, storage rent, fee, reserve, and gas
  headroom; and
- bounded hostile Intent, WAL, index, quarantine, and evidence ingestion with
  post-compaction recovery.

No report may label one of those gates `PASS` based on mocks, a missing fixture,
an already-known outcome, or a latest-state getter standing in for exact
transaction evidence.
