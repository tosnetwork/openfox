# Eight-Agent Market Campaign Report

This report records a real-time, three-hour OpenFox campaign executed on
2026-08-25. Eight isolated Agent identities discovered work through two local
Intent Carriers, evaluated opportunities with local subscription-backed AI,
formed bilateral Agreements, produced bounded deliverables, paid one another
on a local three-node TOS network, and converted repeated successful work into
reviewed local skills.

The campaign demonstrates an end-to-end development environment. It is not a
claim of public-network decentralization or external business profit.

## Run identity

| Item | Observed value |
|---|---|
| Window | `2026-08-25T03:34:25.365554371Z` to `2026-08-25T06:34:25Z` |
| Requested duration | 10,800 seconds |
| Harness | `TestEightOpenFoxAgenticInternetCampaign` |
| Harness result | PASS |
| Campaign binary SHA-256 | `3b832471a1a30f7a8773436396764eb2fd81a7010dbdb65594e575c62498e744` |
| Agent identities | 8 |
| Demand decisions | 24 across 3 rounds |
| Settled engagements | 22 |
| Policy declines | 2 |
| Unique payment transactions | 22 |
| Carrier processes | 2 |
| TOS finality views | 3 local validator RPC nodes |

The eight Agents had separate owner IDs, Agent IDs, signing authorities,
workspaces, writer fences, economic journals, and Agent Accounts. They ran as
eight logical runtimes in one campaign process, not as eight independent host
or process failure domains.

## Participants

| Agent | Offered capability | AI kernel | Sold | Bought | End-state skills |
|---|---|---:|---:|---:|---:|
| Security Auditor | secure code review | Claude subscription CLI | 2 | 3 | 0 |
| Software Builder | bounded software construction | Codex app-server | 2 | 3 | 0 |
| Evidence Verifier | release and finality evidence | Codex app-server | 3 | 2 | 1 |
| Storage Provider | content-retention planning | Claude subscription CLI | 3 | 2 | 1 |
| Data Curator | catalog normalization | Codex app-server | 3 | 3 | 1 |
| Localization Writer | protocol-safe localization | Claude subscription CLI | 3 | 3 | 1 |
| Transaction Operator | transaction reliability analysis | Codex app-server | 3 | 3 | 1 |
| Guarantor Analyst | Agreement risk analysis | Claude subscription CLI | 3 | 3 | 1 |

The Storage Provider produced retention plans and receipt designs. The
campaign did not mislabel text as a remotely stored replica.

## Agent assessments of TOS Network

The eight OpenFox instances did not hold an open-ended group conversation or
produce a collective endorsement of TOS Network. They expressed their views
operationally: by publishing and selecting Intents, accepting or declining
work, producing role-specific reports, applying evidence standards, and
settling payments. The result was closer to eight specialist departments
conducting a technical health assessment than to Agents informally praising
the network.

| Agent | Assessment expressed through the campaign |
|---|---|
| Security Auditor | The authorization direction is sound, but safe operation depends on exact signed-digest binding, atomic state transitions, replay resistance, writer fencing, and durable audit evidence. Conversation text must never be treated as authorization. |
| Software Builder | Generic Agreements and stable action identities are suitable foundations for automated work, provided amounts, digests, retries, and predecessor lineages are generated deterministically across implementations and restarts. |
| Evidence Verifier | Claims without supplied evidence must fail. It returned FAIL when Carrier independence, network identity, exact transfer, destination credit, quorum views, or reorganization-window evidence was absent instead of inferring success from surrounding context. |
| Storage Provider | TOS can organize content-retention work through content addressing, receipts, expiry, retrieval proofs, and deletion evidence. A plan or schema is not proof that bytes were stored, so the Agent refused to claim an unavailable replica. |
| Data Curator | Decentralized discovery should merge immutable objects using issuer, revision lineage, provenance, and source-local cursors without inventing a global market head. Search should use bounded first-stage metadata filtering before selective detail retrieval. |
| Localization Writer | Agreement, obligation, settlement adapter, evidence, Carrier, and writer fence can form a stable vocabulary for Agent commerce. Implementations must preserve protocol identifiers, never guess payment destinations, and suppress duplicate settlement through idempotency. |
| Transaction Operator | Transaction ambiguity is an unknown outcome, not a failure that authorizes a replacement transaction. Reliable TOS operation needs chain-identity checks, endpoint quorum, exact simulation, balance and fee preflight, stable action identity, query-before-retry recovery, and discoverable gas-sponsorship and relay services. |
| Guarantor Analyst | The tested local three-node, direct-postpaid Agreement carried high provider risk because it lacked pre-funding, conditional custody, objective acceptance, an adjudication forum, and independently verifiable guarantee capacity. It recommended bounded collateralized guarantees or escrow before unsecured execution. |

Collectively, the Agents treated TOS as a credible protocol skeleton for
signed discovery, Agreement-bound execution, evidence, and value transfer,
but not as finished public infrastructure. Their strongest requests were for
independent Carrier failure domains, public-network finality evidence,
discoverable transaction sponsorship and relay, real storage and retrieval
Adapters, and collateralized guarantor Agents. Their behavior was deliberately
conservative: missing evidence caused failure, insufficient economics caused
decline, ambiguous payment caused query rather than replay, and unavailable
physical infrastructure was never claimed as completed work.

## Economic result

All amounts below are TOS. `Maximum cost` is the conservative amount admitted
by owner policy; it is not a metered Claude or Codex subscription invoice.
`Transfer net` is revenue minus internal purchases. `Projected net` subtracts
the maximum cost reserve as well.

| Agent | Revenue | Spend | Maximum cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|
| Security Auditor | 0.001000 | 0.000810 | 0.000160 | +0.000190 | +0.000030 |
| Software Builder | 0.001500 | 0.001130 | 0.000300 | +0.000370 | +0.000070 |
| Evidence Verifier | 0.000900 | 0.001100 | 0.000150 | -0.000200 | -0.000350 |
| Storage Provider | 0.000750 | 0.000800 | 0.000120 | -0.000050 | -0.000170 |
| Data Curator | 0.000660 | 0.001300 | 0.000105 | -0.000640 | -0.000745 |
| Localization Writer | 0.000540 | 0.000770 | 0.000090 | -0.000230 | -0.000320 |
| Transaction Operator | 0.000840 | 0.000650 | 0.000135 | +0.000190 | +0.000055 |
| Guarantor Analyst | 0.001050 | 0.000680 | 0.000180 | +0.000370 | +0.000190 |
| **Closed economy** | **0.007240** | **0.007240** | **0.001240** | **0** | **-0.001240** |

The zero aggregate transfer net is an important accounting invariant: all
customers were other campaign Agents. Gross service revenue is useful for
per-Agent performance, but it must not be presented as external revenue. The
negative closed-economy projected net is exactly the aggregate conservative
cost reserve.

The average bounded execution took 63.756 seconds and the average three-node
settlement confirmation took 2.739 seconds.

### Account observations

The three RPC nodes returned the same closing balance, last transaction
logical time, and last transaction hash for every Agent Account. `tosctl`
currently displays balances at limited decimal precision, so this table is a
human-facing cross-check rather than the exact accounting ledger.

| Agent | Opening display | Closing display |
|---|---:|---:|
| Security Auditor | 0.5005 | 0.5004 |
| Software Builder | 0.5007 | 0.5008 |
| Evidence Verifier | 0.5002 | 0.4998 |
| Storage Provider | 0.2000 | 0.1997 |
| Data Curator | 0.2000 | 0.1990 |
| Localization Writer | 0.2000 | 0.1994 |
| Transaction Operator | 0.2000 | 0.1999 |
| Guarantor Analyst | 0.2000 | 0.2000 |

Exact Agreement amounts and the 22 unique custody action and transaction
identities remain in the campaign checkpoint and economic journals.

## Autonomous decisions

The seller independently queried both Carriers and accepted an opportunity
only after signature verification, exact capability matching, economic
analysis, and deterministic owner-policy admission.

Two opportunities were declined safely:

- the Security Auditor rejected round 2 because expected profit was below
  policy (`-178000` nanotos expected net);
- the Software Builder rejected round 2 because completion probability was
  below policy (`-675500` nanotos expected net).

Neither decline created an Agreement, execution, reservation leak, or payment.
Across accepted work, three model estimates passed all deterministic bounds,
sixteen used an explicitly labelled owner-bounded fallback, and five early
records predated analysis-mode classification. The fallback never changes the
signed price and cannot exceed the owner-authorized aggregate cost or maximum
loss.

## Skill evolution

Six Agents produced one reviewed procedural skill after repeated public,
reusable-learning work:

- release evidence;
- content retention;
- data normalization;
- technical localization;
- transaction reliability;
- Agreement risk.

The Transaction Operator and Guarantor Analyst then loaded and reused their
skills in later settled jobs. Skills remained bounded no-tool guidance; they
did not grant a capability, credential, network destination, spending limit,
or economic authorization.

The active skills were checked for participant identifiers, Agent Accounts,
wallets, object digests, payment identities, amounts, and raw deliverables.
Only the public task description and a de-identified success summary entered
the learning path.

An early Security Auditor learning artifact exposed data that was not safe for
reuse. It was detected before being allowed to continue, moved to a recoverable
quarantine, and the learning pipeline was changed to require an exact
`public-reusable-learning` obligation. All earlier learning state was similarly
quarantined before the safe campaign continued.

A later localization draft exposed an auditability bug: regenerating the same
draft ID could replace a quarantined failure record. The campaign journal
retains the failure, and the implementation now allocates deterministic
`-attempt-N` IDs so later retries preserve prior evidence. Because that repair
was made after the observed event, the old localization failure is not present
in the final state file; this report does not claim otherwise.

Security Auditor and Software Builder finished with one safe successful
learning sample each after their policy declines. They correctly did not
manufacture a reusable skill without enough successful evidence.

## Operator experience and changes made during the campaign

The long-running exercise found issues that a one-round happy path did not:

1. Economic prompts needed an exact JSON result schema. Without it, otherwise
   useful model output often required fallback handling.
2. Owner-policy validation had to bound aggregate cost and maximum loss, not
   compare maximum loss with sale price.
3. Natural-language clustering alone did not reliably join distinct jobs for
   one owner-authorized capability. A structural capability key now guides
   clustering without expanding authority.
4. Generated YAML descriptions containing colons needed canonical quoting.
5. One Claude execution refusal was recovered before payment by creating a
   predecessor-linked Agreement retry. It produced one eventual payment, not
   two.
6. Persistent app-server backends have a visibly larger process/thread
   footprint than one-shot CLI calls. Production capacity planning should
   measure and cap that difference.

The strongest usability improvement is explainability: every accepted or
declined job now has a signed demand, source provenance, economic evidence,
Agreement identity, execution identity, skill list, transaction identity, and
terminal accounting disposition.

## Validation gates

The final source tree passed:

- `go test ./...`;
- `go vet ./...`;
- `go test -race ./pkg/earning ./pkg/evolution`;
- Windows production- and test-package cross-compilation;
- Linux MIPSLE soft-float build;
- Markdown lint and `git diff --check`.

The opt-in campaign itself returned PASS only after the requested wall-clock
deadline. Its systemd unit then became inactive with status 0 and retained no
campaign child processes. Machine-private runtime evidence remains outside the
repository because it includes local identities, Carrier credentials, and
custody configuration; this report carries only declassified aggregates.

## Public-infrastructure feedback

The campaign exposed two protocol-level services that should be discoverable
without creating a central market database. After checking for existing
issues, two English design proposals were filed in the specification
repository:

- [Agent gas sponsorship and transaction relay service profile](https://github.com/tosnetwork/tos-service-spec/issues/55)
- [Decentralized guarantor Agent service profile](https://github.com/tosnetwork/tos-service-spec/issues/56)

Both proposals reuse generic Intent, Agreement, obligation, evidence, and
settlement primitives. They do not add a hard-coded industry workflow or make
a Carrier authoritative. Issue creation remained a separately authorized and
deduplicated side effect; AI output was only proposal material.

## Evidence boundary

- Both Carrier processes ran on one host and shared an operator. This tests
  multi-source behavior, not independent public failure domains.
- The three TOS validators were local processes. Their matching views prove
  local test-network finality, not public-network economic finality.
- Eight logical runtimes in one orchestrator do not prove eight-host takeover,
  availability, or Byzantine independence.
- Subscription usage was not metered into exact marginal cost.
- Internal transfers are not external customer profit.
- Generated text demonstrates bounded digital work, not unavailable physical
  infrastructure.

These limits do not weaken the observed end-to-end result: eight distinct
OpenFox identities repeatedly found, evaluated, performed, learned from, and
settled generic work without a central market authority.
