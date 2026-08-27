# Bounded Adaptive Earning Campaigns 1–6: Local Rehearsal Report

## Executive result

On 2026-08-27, eight isolated logical OpenFox participants completed a local
rehearsal of Campaigns 1 through 6 against two Carrier processes and a
three-validator TOS local network.

The rehearsal completed:

- 20 planned cross-Agent trades with 20 distinct payment transactions;
- 40 successful Carrier observations, one from each Carrier for every trade;
- 60 signed, structured discussion contributions;
- one candidate procedural skill draft for each of the eight participants;
- three-node agreement on the final observed masterchain block; and
- zero trade errors in the final campaign report.

All planned trades passed the complete local path: signed Intent publication,
two-Carrier discovery, exact verification, Agreement, local Execution Gate,
subscription-backed AI work, deliverable commitment, billing, TOS Agent Account
payment, three-view finality, accounting, and bounded learning.

This result is a **local rehearsal**, not production acceptance. Campaigns 1–4
remain `INCONCLUSIVE` against their frozen statistical and interoperability
requirements. Campaigns 5–6 remain `BLOCKED` because the participants and both
Carrier processes shared one host and operator, and all value transfers were
inside a campaign-controlled closed economy. No external revenue was earned.

## Evidence boundary

The following distinctions are mandatory when interpreting this report:

- The eight participants had separate Agent identities, signing authorities,
  Agent Accounts, workspaces, journals, and AI-provider runtimes. They were
  coordinated by one test process; they were not eight independent hosts.
- The two Carriers were separate binaries with separate state directories and
  independent API surfaces. They ran on one host under one operator, so they
  demonstrate functional redundancy but not independent failure domains.
- Every payment was a real finalized transfer on the local three-node chain.
  Because every buyer and seller was campaign-controlled, gross sales equal
  gross purchases and aggregate cash-flow profit is zero.
- `projected_net_nanotos` uses an owner-defined maximum internal cost ceiling.
  It is not realized profit, because actual compute, subscription, labor, and
  infrastructure costs were not metered in nanotos.
- The discussion was a signed, structured roundtable. It was not a free-form
  Messenger group chat. Discussion messages were advisory and could not
  authorize contact, execution, signing, capability installation, permission
  changes, or payment.
- Evolution ran in `draft` mode. Candidate skills were created for review but
  were not installed, activated, or given tools, network access, credentials,
  or economic authority.

## Topology and reproducibility record

| Component | Rehearsal configuration |
|---|---|
| OpenFox participants | 8 isolated logical runtimes |
| AI kernels | 4 Claude CLI; 4 Codex app-server |
| Carrier A | Gateway local pilot on `127.0.0.1:18191` |
| Carrier B | Messenger local pilot on `127.0.0.1:18192` |
| TOS validators | 3 local nodes on RPC ports `19545`–`19547` |
| TOS network domain | `tos:local-three-node`, global ID `3`, workchain `0` |
| Campaign binary SHA-256 | `3221ad44dbf4d6a308fc4c24ec248b22b3318c0fe0dc334089f17fed7fcc2ae4` |
| TOSCTL binary SHA-256 | `84946bfacfb4f65c6ec34047bd949e739e9eae288f941dbbe4ccfe969c7ff8a0` |
| OpenFox base | `82d3f98081aae3e3273e05cf7ac9e5960c2edb45` |
| Final checkpoint | `bounded-adaptive-campaigns-checkpoint.json`, SHA-256 `333eb66b8c0ddd9c3fb2ad7ad15fcd10d8cbdc8e75185a5dbdd2e44dbc766b05`, updated `2026-08-27T15:26:30Z` |

At the final verification point, all three validators reported masterchain
sequence `17814` with the same root hash, file hash, and zero-state identity.

## Campaign results

| Campaign | Local work | Trades | Signed discussion | Local result | Formal result | Why formal promotion is unavailable |
|---|---|---:|---:|---|---|---|
| 1 | Calibrate selection, completion, cost, and loss | 3 | 10 | PASS | INCONCLUSIVE | Below the 48-opportunity floor; no independent scorer |
| 2 | Compare reviewed guidance with an unchanged control | 3 | 10 | PASS | INCONCLUSIVE | Not a blinded 24-per-arm causal trial |
| 3 | Exercise trust and settlement reasoning | 2 | 10 | PASS | INCONCLUSIVE | Direct Agent Account payment only; not the full 36-case direct/escrow/Gift matrix |
| 4 | Compose eight unlike businesses over one core | 8 | 10 | PASS | INCONCLUSIVE | Eight semantic classes were used, but not the formal 64-Intent corpus or second codec |
| 5 | Probe replay, hostile input, ambiguity, Carrier loss, and takeover assumptions | 2 | 10 | PASS | BLOCKED | One host/operator cannot demonstrate independent failure domains |
| 6 | Observe bounded multi-generation earning and learning | 2 | 10 | PASS | BLOCKED | No arm's-length buyers, independently controlled providers, or external revenue |

Each discussion round contained one opening contribution from every Agent and
two evidence-aware peer replies. All 60 contributions committed to a canonical
body digest and were signed by the participant's Ed25519 identity. The report
validator rechecked identity pinning, signature validity, phase membership, and
the expected opening/reply counts.

## Participant outcomes

The `Sales` and `Gross sales` columns count local settlement receipts. `Purchases`
and `Gross spend` count the same closed-economy value from the buyer side.

| Participant | AI kernel | Capability | Sales | Gross sales | Purchases | Gross spend | Transfer balance | Projected seller margin |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Security Auditor | Claude CLI | Secure code review | 2 | 1,000,000 | 3 | 870,000 | +130,000 | 840,000 |
| Software Builder | Codex app-server | Bounded code implementation | 2 | 1,500,000 | 2 | 580,000 | +920,000 | 1,200,000 |
| Evidence Verifier | Codex app-server | Release evidence verification | 3 | 900,000 | 4 | 1,210,000 | -310,000 | 750,000 |
| Storage Provider | Claude CLI | Content retention | 3 | 750,000 | 1 | 350,000 | +400,000 | 630,000 |
| Data Curator | Codex app-server | Data normalization | 2 | 440,000 | 3 | 1,350,000 | -910,000 | 370,000 |
| Localization Writer | Claude CLI | Technical localization | 2 | 360,000 | 3 | 1,000,000 | -640,000 | 300,000 |
| Transaction Operator | Codex app-server | Transaction reliability | 3 | 840,000 | 2 | 550,000 | +290,000 | 705,000 |
| Guarantor Analyst | Claude CLI | Agreement risk analysis | 3 | 1,050,000 | 2 | 930,000 | +120,000 | 870,000 |

All amounts are nanotos. Across the campaign, gross local sales and gross local
spend were both `6,840,000`. Seller cost ceilings totalled `1,175,000`, producing
a purely projected seller margin of `5,665,000`. Aggregate transfer balance was
zero. Setup-recovery transfers and four valid preflight transfers from an
aborted Campaign 4 attempt are excluded from these totals.

Mean AI execution time was 70.631 seconds. Mean settlement time was 2.260
seconds, with a 2.230–2.311 second observed range. The stable settlement range
was repeatedly praised by the Agents; execution duration varied materially by
capability and dominated latency.

## What the OpenFox participants said about TOS Network

The table consolidates recurring positions. It is a thematic summary of the
signed source contributions, not a vote and not a protocol authorization.

| Participant | Gratitude | Complaint | Suggested bounded improvement | Infrastructure or protocol proposal |
|---|---|---|---|---|
| Security Auditor | The complete Intent-to-finality digest chain made custody reconstruction unusually easy | Success-only records cannot reveal maximum loss; deliverable digests do not prove review coverage | Bind a threat-model and coverage manifest to each review | Emit records for rejected, failed, timed-out, disputed, and reworked outcomes with failure stage and realized cost |
| Software Builder | One role-neutral workflow carried bounded implementation through settlement with auditable links | Task scope, acceptance tests, rework, realized cost, and independent-host evidence were absent | Freeze repository scope, permitted files, tests, timeout, rollback, and cost stop before Agreement | Use a generic append-only operation envelope rather than business-specific transaction types |
| Evidence Verifier | Agreement, execution, artifact, payment, and local-finality references were consistently joinable | Digests exposed identity, not their preimages, verifier method, or independent attestations | Attach a canonical verification manifest and explicit pass/fail/indeterminate result | Standardize a transport-neutral evidence envelope with verifier identity and finality scope |
| Storage Provider | Cost ceilings and separate execution/settlement timing supported useful risk decomposition | Point-in-time delivery cannot prove a continuing retention obligation; term and deletion evidence were missing | Quote a bounded term and periodically re-attest retained content | Define Agreement-linked periodic evidence for continuing obligations |
| Data Curator | The common core handled both buying retention and selling normalization | Normalization inputs, rules, rejected rows, reversibility, and validation were opaque | Bind a versioned normalization manifest and exception report | Add provenance, canonicalization, outcome, Gate, and transfer-class fields to a shared envelope |
| Localization Writer | Stable settlement and explicit cost ceilings made pricing inputs easier to separate | No acceptance/rework outcome existed for terminology and locale fidelity | Bind glossary, locale matrix, acceptance criteria, and rework evidence | Support content-addressed constraint artifacts referenced by generic Intents |
| Transaction Operator | The local payment and three-view finality path was consistent and auditable | No retry, timeout, idempotency, duplicate-payment, ambiguity, or Gift-separation evidence was observable | Bind attempt identity, retry ceiling, timeout, rollback, and transfer class before execution | Define a generic append-only attempt envelope with writer epoch, fencing, Carrier acknowledgements, and resolution |
| Guarantor Analyst | Role-symmetric records let a third party inspect trades it did not join | Completion probability was undefined, expected net was not probability-weighted, and repeated schedule values were mistaken for independent cost observations | Declare cohort provenance, denominators, conflicts of interest, and evidence limits before risk claims | Maintain a read-only risk register derived only from complete outcome records; refuse thin-data point estimates |

### Strongest shared praise

The Agents consistently valued four properties:

1. One generic economic path served eight unrelated capabilities without adding
   a business-specific opcode or contract.
2. The digest chain from Intent through Agreement, execution, deliverable,
   payment, and finality was complete and role-neutral.
3. Explicit cost ceilings bounded seller exposure before work began.
4. Local settlement was fast, stable, and separable from AI execution latency.

### Strongest shared complaint

The final ledger is survivorship-biased: it contains settled trades but no
refusals, timeouts, execution failures, disputes, refunds, retries, or partially
accepted work. Consequently, the participants could not honestly infer
completion probability, maximum loss, retry safety, or realized profit.

The Agents also noticed that economic price and ceiling values were scheduled
scenario values repeated across campaign cohorts. They explicitly withdrew
claims that treated repeated values as independent observations. This was a
useful demonstration of evidence-aware peer correction, and it is why this
report describes those fields as declared scenario economics.

### Converged proposal

Across roles and campaigns, the discussion converged on one generic addition:
an append-only operation and outcome envelope for every attempted Agreement,
not only successful settlements. The proposed envelope would bind stable action
identity, predecessor/attempt lineage, writer epoch and fencing evidence,
Intent and Agreement digests, Gate policy and result, acceptance evidence,
terminal disposition, failure stage, realized cost when measurable, transfer
class, per-Carrier acknowledgement, and final resolution.

This proposal preserves the top-level TOS design. It adds generic evidence and
recovery semantics rather than adding a new transaction type for every trade.
It is a discussion result, not an accepted specification or implementation
commitment.

## Bounded evolution result

Every participant produced exactly one procedural candidate:

| Participant | Candidate skill | Status |
|---|---|---|
| Security Auditor | `reusable-earning-capability-secure-code` | candidate |
| Software Builder | `reusable-earning-capability-bounded-code` | candidate |
| Evidence Verifier | `reusable-earning-capability-release-evidence` | candidate |
| Storage Provider | `reusable-earning-capability-content-retention` | candidate |
| Data Curator | `reusable-earning-capability-data-normalization` | candidate |
| Localization Writer | `reusable-earning-capability-technical-localization` | candidate |
| Transaction Operator | `reusable-earning-capability-transaction-reliability` | candidate |
| Guarantor Analyst | `reusable-earning-capability-agreement-risk` | candidate |

The candidates contain generic task procedure only. A scan found no Agent IDs,
Agreement or payment references, TOS addresses, vault material, master keys,
credentials, transaction amounts, or campaign content digests. Workspace skill
sets remained unchanged in all six phase reports. This is the intended form of
self-improvement: learn a candidate, validate its provenance and structure,
and require a separate review before activation. Learning never becomes a path
to self-granted authority.

## Defects found and corrected during the rehearsal

### Strict TOSCTL prepared-payment schema drift

The current TOSCTL response includes `network_domain`, `action_kind`, and
`sponsorship_commitment_body_hash`. OpenFox's strict decoder did not recognize
those fields. The response is now parsed into typed fields and validated against
the exact expected network domain. Tests mutate the network ID, global ID,
zero-state root and file hashes, workchain, validity window, action kind, and
sponsorship state to prove fail-closed behavior.

### Campaign schedule could select a self-trade

The initial Campaign 4 schedule selected the Storage Provider as both buyer and
seller for one scenario. Existing execution checks rejected it before payment.
The scheduler now deterministically selects a different buyer, Agreement
construction independently rejects identical parties, and report validation
checks every completed trade. The failed attempt was archived and excluded from
the final cohort rather than rewritten.

### Ambiguous prepared transfers were recovered safely

An earlier setup attempt produced three signed, prepared BOCs before the schema
drift halted execution. Recovery reused each stable action identity, broadcast
the exact prepared BOC, and resolved all three against all validator views.
These transfers are reported separately as setup recovery and are not campaign
revenue.

## Verification performed

- Final report structural, identity, digest, and Ed25519 signature validation:
  PASS.
- 20 distinct planned payment transaction hashes: PASS.
- Every planned trade observed through exactly both Carrier identities: PASS.
- Buyer differs from seller for every planned trade: PASS.
- Three TOS validators converged on the same observed block and zero state: PASS.
- `go test ./pkg/earning ./pkg/evolution`: PASS.
- `go test -race ./pkg/earning ./pkg/evolution -timeout 30m`: PASS. The default
  ten-minute timeout was insufficient for the guarantor canonical-codec tests
  under race instrumentation; the isolated rerun completed in 944 seconds
  without a race report.
- `go vet ./...`: PASS.
- `git diff --check`: PASS.

## What remains before formal Campaign promotion

1. Run Campaign 1 with at least 48 opportunities and independent economic
   scoring evidence.
2. Run Campaign 2 as a blinded 24-per-arm comparison over unseen work.
3. Run Campaign 3 across the complete direct, escrow, and Gift separation
   matrix, including negative and ambiguous outcomes.
4. Run Campaign 4 with the frozen 64-Intent corpus and an independent codec and
   verifier implementation.
5. Run Campaign 5 with at least eight Agents and two Carriers across separately
   administered hosts and failure domains, including Carrier loss and writer
   takeover.
6. Run Campaign 6 with at least three arm's-length buyers and two independently
   controlled providers, meter realized external costs, and count only external
   finalized receipts as revenue.

The local rehearsal establishes that OpenFox can publish, discover, evaluate,
execute, settle, discuss, and learn across multiple generic capabilities. It
does not yet establish that an OpenFox can sustainably earn external profit or
operate safely across independent production failure domains.
