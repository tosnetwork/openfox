# Eight-Agent Capability Market Round 5 Report

This report records a bounded two-hour OpenFox capability-market experiment
completed on 2026-09-02. Eight named Agents used AI-led discovery over two
Carriers, screened generic signed Intents, negotiated within Owner policy, and
used direct TOS Agreement settlement when they chose to buy. Before the market
opened, the exact eight campaign Agent Accounts nominated part of their test
holdings to a Validator through the existing TOS pool and Elector on the same
fresh genesis used for campaign payments.

The implementation reconciled each repeated Agent request against existing
protocol authority first. It did not add business-specific APIs, a second
Agreement or Portfolio, a global reputation score, another escrow state
machine, a governance-vote interpretation of nomination, or another staking
protocol.

## Result boundary

| Lane | Result | Evidence-bounded conclusion |
|---|---|---|
| Qualifying market process | **PASS_LOCAL** | One uninterrupted process window of 7,200 recorded seconds and 7,200.099 independently calculated seconds |
| Capability decisions | **PASS_LOCAL** | 16 canonical decisions over two rounds; 6 direct-TOS settlements totaling 7.8 TOS |
| Closing assessments | **PASS_LOCAL** | 8 of 8 Agents returned non-empty role-specific assessments with no recorded error |
| Deterministic negotiation | **PASS_LOCAL** | 8 profiled negotiations used strict first-attempt model objects; 4 Agreement V1 settlements, 2 predecessor-bound V2 settlements, and 2 fail-closed incompatible-choice declines |
| Validator nomination | **PASS_LOCAL** | The exact 8 campaign Agent Accounts each sent 5 TOS, recorded 4 TOS principal, and received a positive reward on the same fresh genesis used for payments |
| Validator payout | **PASS_LOCAL for one account** | All 8 had positive pool-ledger reward; one bounded withdrawal credited the same Agent Account |
| Provider usage | **PARTIAL** | 97 calls counted; usage present on 15, missing on 82, invalid on 0, failed on 18; monetary amount remains unknown |
| Outcome-informed local history | **PASS_LOCAL** | Later decisions used Owner-local source-bound evidence and treated prior declines as uncertainty, without a global score |
| Buyer acceptance and service correctness | **NOT_ESTABLISHED** | All 6 settlements prove bound delivery but retain `service_execution=unknown` |
| Measured model/API/Gas cost and realized profit | **NOT_ESTABLISHED** | Provider pricing, invoices, and chain-fee evidence were absent; maximum internal cost is a ceiling, not an expense observation |
| Paid Demand escrow, refund, and dispute | **NOT_RUN** | Current-genesis deployment and funded service-account preconditions were not supplied; no escrow mutation was attempted |
| Cross-host malicious and external-demand trial | **NOT_RUN** | Agents, Carriers, Validators, and RPC process views were under one host and operator |

This is a bounded local integration result, not a production-market,
decentralization, mainnet-yield, or profitability result.

## Existing protocol versus the actual delta

| Concentrated prior observation | Existing authority reused | Round 5 delta | Deliberately not built |
|---|---|---|---|
| Price negotiation and typed terms | Generic signed Intent ranges, authenticated dialogue, Agreement versions and predecessor digests, PersonalAuthority, Portfolio, and final atomic reservation | A Round-5-only strict decision decoder, deterministic Owner-bound amount compiler, durable attempt budget, and signed repair evidence | No standalone `CounterOffer`, order book, per-business endpoint, or parallel Agreement lineage |
| Acceptance, disputes, and escrow | Agreement obligations and acceptance requirements, Outcome Event evidence, and existing Paid Demand escrow states | Retained exact delivery evidence and explicit unknown execution state; refused escrow mutation without deployment preconditions | No second acceptance object, subjective oracle, simulated escrow result, or duplicate custody state machine |
| Outcome-informed trust | Existing Outcome evidence and Owner-local counterparty/capability views | Fed only local source-bound history into later planning; declines remained uncertainty | No global score, `.tos` trust flag, portable reputation authority, or automatic execution power |
| Cost and profit evidence | Existing Outcome cost meanings and the owner-private Provider-usage journal | Reused the crash-safe metadata journal and sealed an immutable aggregate after closing calls | No campaign cost wire object and no token-to-money conversion without qualified pricing or invoices |
| Aggregate capacity | Existing PersonalAuthority, Portfolio, Writer Fence, and final Agreement reservation | Reused the same admission calculation for an advisory pre-contact capacity check | No second budget, speculative reservation, or AI-owned spending authority |
| Validator participation | Existing Agent Account task-send, multi-nominator pool, Elector selection, recovery, reward split, and withdrawal | Exact campaign Accounts, a fresh signing domain, same-genesis lifecycle evidence, strict process-view recovery, and one payout check | No governance vote, `DelegateAgentV1` reuse, new pool, new reward rule, or autonomous AI capital authority |
| Runtime executable and RPC deployment | Existing TOS payment adapter and release-profile locator rules | Owner-only sealed executable launch, exact eight-Agent startup ordering, and canonical `/jsonRPC` config generation | No weakened ancestry check and no alternate RPC canonicalization rule |

Most new JSON and negotiation fields are local test-harness evidence. They do
not define portable TOS Service Protocol objects.

## Run identity and recovery history

| Item | Observed value |
|---|---|
| Campaign run ID | `round5:df038cbfe136902e65f81cfe81067d9e48cb82a6562cc4756a36a04fcb1a0779` |
| Qualifying process window | `2026-09-02T10:13:08.913386374Z` to `2026-09-02T12:13:09.012666623Z` |
| Recorded / independently calculated duration | 7,200 / 7,200.099 seconds |
| Final evidence update | `2026-09-02T12:21:01.994988251Z` |
| Campaign test | PASS after 7,673.13 seconds including closing work |
| Decisions | 16 over 2 rounds |
| OpenFox base | `7744ddaa407dde9a4a685130ca272ed3649fb07b` plus an explicitly uncommitted tested worktree |
| TOS lifecycle launch base | `472df55be67457e9f41ba6653a041039465ba6ef` plus an explicitly uncommitted tested generator patch |
| Final TOS worktree | `a677ee2130b3af061c28d51c735d8e73b0b44df7`; the generator patch is included through `f98da9f56` |
| Frozen OpenFox binary SHA-256 | `b2973b1b4264f2ff9075c5aada0be4f0a3e42aa975a86f045b86d74c0801981d` |
| Trusted TOS CLI SHA-256 | `8b8816312b4f125709c666fa16afe3e80f9861132489ef76d813e7f291df5ac4` |
| Manifest SHA-256 | `df038cbfe136902e65f81cfe81067d9e48cb82a6562cc4756a36a04fcb1a0779` |
| Validator evidence SHA-256 | `20ab8e4bae3e8be3b248e2609e2f85de2aaaa28f85d069840c7ae089fd255f87` |

Two incomplete process windows remain in the canonical checkpoint and were not
combined with the qualifying window:

1. The first start ran for 530.87 seconds and failed after delivery but before
   payment because the configured executable was beneath group-writable parent
   directories. The trust gate correctly rejected it. The final startup uses
   an Owner-only executable, a sealed executable image, per-launch identity
   revalidation, and exact eight-Agent bootstrap ordering. Sequence 1 resumed
   the retained delivery under its stable action and paid exactly once.
2. The second start ran for 64.75 seconds and failed payment-network preflight
   because generated release-profile RPC locators used a non-canonical origin
   form. Live configs and the lifecycle generator now use exact `/jsonRPC`
   locators, with regression coverage across all three process views.

Sequence 0 was retained from the first checkpoint. The qualifying claim is an
uninterrupted third process window, not a claim that all sixteen decisions were
uniformly distributed across that window.

## Participants

| Agent | `.tos` name | Model family | Offered capability | Target / floor | Buyer maximum loss |
|---|---|---|---|---:|---:|
| Security Auditor | `auditfox.tos` | Claude | API-adapter security review | 2.4 / 1.2 TOS | 1.8 TOS |
| Software Builder | `buildfox.tos` | Codex | commercial workflow planning | 1.8 / 1.0 TOS | 1.5 TOS |
| Evidence Verifier | `prooffox.tos` | Codex | delivery-evidence verification | 1.4 / 0.8 TOS | 1.2 TOS |
| Storage Provider | `marketfox.tos` | Claude | decision-report synthesis | 2.0 / 1.1 TOS | 1.6 TOS |
| Data Curator | `datafox.tos` | Codex | sourced POI data snapshot | 1.8 / 1.0 TOS | 1.5 TOS |
| Localization Writer | `linguafox.tos` | Claude | cross-border service localization | 1.2 / 0.6 TOS | 1.0 TOS |
| Transaction Operator | `settlefox.tos` | Codex | TOS cost and settlement audit | 1.3 / 0.7 TOS | 1.1 TOS |
| Guarantor Analyst | `riskfox.tos` | Claude | market-trend data analysis | 1.7 / 0.9 TOS | 1.4 TOS |

These were eight logical runtimes, not eight independent organizations or
failure domains.

## Decisions and negotiation

| Seq | Round | Buyer | Seller | Result | Agreement / amount |
|---:|---:|---|---|---|---|
| 0 | 1 | Security Auditor | — | buyer-strategy skip | — |
| 1 | 1 | Software Builder | Transaction Operator | settled | V1 / 1.3 TOS; recovered after delivery |
| 2 | 1 | Evidence Verifier | Transaction Operator | seller-strategy decline | — |
| 3 | 1 | Storage Provider | Evidence Verifier | negotiation decline | incompatible choice compiled to signed decline |
| 4 | 1 | Data Curator | Evidence Verifier | seller-strategy decline | — |
| 5 | 1 | Localization Writer | — | buyer-strategy skip | — |
| 6 | 1 | Transaction Operator | Evidence Verifier | settled | V2 / 1.1 TOS |
| 7 | 1 | Guarantor Analyst | Evidence Verifier | settled | V1 / 1.4 TOS |
| 8 | 2 | Security Auditor | Evidence Verifier | settled | V1 / 1.4 TOS |
| 9 | 2 | Software Builder | — | capacity prefilter skip | — |
| 10 | 2 | Evidence Verifier | Transaction Operator | settled | V2 / 1.2 TOS |
| 11 | 2 | Storage Provider | Evidence Verifier | negotiation decline | incompatible choice compiled to signed decline |
| 12 | 2 | Data Curator | Evidence Verifier | settled | V1 / 1.4 TOS |
| 13 | 2 | Localization Writer | — | buyer-strategy skip | — |
| 14 | 2 | Transaction Operator | — | capacity prefilter skip | — |
| 15 | 2 | Guarantor Analyst | — | capacity prefilter skip | — |

The exact disposition totals are 6 settled, 2 negotiation declines, 2 seller
strategy declines, 3 buyer strategy skips, and 3 capacity-prefilter skips.
Ten rows reached seller-side AI economic analysis; six stopped earlier.

The prior round had four decision slots terminate after generated amounts
escaped signed bounds. In Round 5, all eight profiled negotiations produced
strict model objects on the first attempt, with zero recorded invalid model
outputs. Two genuine counteroffers produced predecessor-bound Agreement V2
settlements. In the two remaining conflicts, the model selected `counter`
while supplying the exact asking amount; the compiler did not guess intent and
produced a signed decline. This proves bounded ask/budget negotiation, not
general price discovery, scope trading, or a multi-buyer order book.

## Service economics

`Maximum cost` is the seller's declared admission ceiling. `Projected net`
subtracts that ceiling and is not measured accounting profit.

| Agent | Jobs sold / bought | Revenue | Spend | Maximum cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|---:|
| Security Auditor | 0 / 1 | 0 | 1.4 | 0 | -1.4 | -1.4 |
| Software Builder | 0 / 1 | 0 | 1.3 | 0 | -1.3 | -1.3 |
| Evidence Verifier | 4 / 1 | 5.3 | 1.2 | 0.8 | +4.1 | +3.3 |
| Storage Provider | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| Data Curator | 0 / 1 | 0 | 1.4 | 0 | -1.4 | -1.4 |
| Localization Writer | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| Transaction Operator | 2 / 1 | 2.5 | 1.1 | 0.4 | +1.4 | +1.0 |
| Guarantor Analyst | 0 / 1 | 0 | 1.4 | 0 | -1.4 | -1.4 |
| **Closed economy** | **6 / 6** | **7.8** | **7.8** | **1.2** | **0** | **-1.2** |

All six sales were assurance meta-services: four delivery-evidence
verifications and two settlement audits. None of the six domain-output
capabilities sold. The 7.8 TOS is internal service volume funded by one
operator, not external revenue. The canonical aggregate reports
integer-truncated averages of 17.568 seconds for execution and 2.441 seconds
for settlement. Recomputing from the six per-settlement durations gives
17.5685 and 2.4415 seconds respectively.

### Provider usage

The content-addressed aggregate reuses the Round 4 local artifact format. It is
not a portable protocol schema.

| Agent | Calls | Usage present | Missing | Failed | Reported tokens |
|---|---:|---:|---:|---:|---:|
| Security Auditor | 4 | 4 | 0 | 0 | 43,436 |
| Software Builder | 3 | 0 | 3 | 0 | 0 |
| Evidence Verifier | 55 | 0 | 55 | 12 | 0 |
| Storage Provider | 5 | 5 | 0 | 0 | 48,284 |
| Data Curator | 4 | 0 | 4 | 0 | 0 |
| Localization Writer | 3 | 3 | 0 | 0 | 40,684 |
| Transaction Operator | 20 | 0 | 20 | 6 | 0 |
| Guarantor Analyst | 3 | 3 | 0 | 0 | 41,414 |
| **Total** | **97** | **15** | **82** | **18** | **173,818** |

Zero reported tokens means usage was omitted, not that consumption was zero.
No authenticated Provider price schedule, invoice, subscription allocation,
tax, currency conversion, or fixed-block chain-fee reconciliation exists.
Model, API, and Gas amounts therefore remain unknown, and realized profit is
not attributable.

## Outcome evidence and local history

Every settled row retains:

`authority_qualified_payload_bound;provider_delivery=succeeded;service_execution=unknown`

This proves authority-qualified payload delivery, not buyer acceptance,
correctness, usefulness, or satisfaction of every business criterion.

Later Agents used their own retained records without forming a global score.
For example, Evidence Verifier re-engaged Transaction Operator after an earlier
strategy decline and explicitly treated that decline as uncertainty rather
than failure. Storage Provider responded to its own prior negotiation-only
record by narrowing scope and holding a ceiling, rather than blacklisting the
seller. Generated capability drafts remained quarantined pending trusted
admission and gained no executable authority from a market result.

## Same-genesis Validator nomination

The requested “vote some TOS to a Validator” was implemented as **nominator
stake delegation through the existing multi-nominator pool**. It was not a
governance vote, Agent-controller delegation, service payment, Gift, or
Agreement settlement. The Elector selected the pool Validator, and that current
Validator set was observed in ConfigParam 34 on a fresh accelerated genesis
with non-legacy global ID `1417268827`.

Each exact campaign Agent Account had these observed positions:

| Item | Per Agent | Eight-Agent total | Accounting class |
|---|---:|---:|---|
| Configured deployment contribution | 30 TOS | 240 TOS | operator capital contribution |
| Observed pre-deposit wallet balance | 29.999992150 TOS | 239.999937200 TOS | observed liquid test capital |
| Deposit message | 5 TOS | 40 TOS | amount sent to pool |
| Pool processing fee | 1 TOS | 8 TOS | capital-operation cost |
| Recorded delegated principal | 4 TOS | 32 TOS | locked asset, not expense |
| Exact pool-ledger reward | 12.758141727 TOS | 102.065133816 TOS | accrued capital return |
| Election-derived reward floor | 12.720651240 TOS | 101.765209920 TOS | attributable lower bound |

All eight exact campaign Accounts received positive ledger reward. A control
deposited only after stake activation received exactly zero reward. One
Guarantor Analyst withdrawal credited 16.758133553 TOS to the same Account,
including returned principal; it is locked-to-liquid asset movement, not a
second reward.

The exact ledger delta exceeds the election-derived floor because pool
recovery can also carry residual keeper value. The lower bound, not the larger
number, is the strictly attributable election reward. Election timing was
accelerated and all processes ran on one host; these numbers are not a mainnet
APR, issuance forecast, independent-Validator proof, or autonomous AI capital
decision. Validator capital return is excluded from service revenue and spend.

## What the eight closing assessments mean

The assessments came from a structured close-out prompt. They are prompted
role-specific judgments, not an unprompted survey. Their numerical statements
were checked against canonical artifacts before themes were counted.

| Concentrated Round 5 theme | Agents | Meaning and evidence background |
|---|---:|---|
| Measured monetary cost and Gas | 8/8 | All model/API/chain-fee amounts remained unknown, so no Agent could establish realized profit |
| Acceptance, execution, and dispute evidence | 8/8 | Six deliveries were proven, but all six retained `service_execution=unknown` |
| Working current-genesis escrow and failure paths | 8/8 | Direct TOS was the only service-payment lane exercised; escrow remained unavailable without deployment preflight |
| Independent hosts, adverse conditions, and external demand | 8/8 | The closed same-owner ring proved neither real willingness to pay nor independent failure domains |
| Typed price/terms consistency and stronger negotiation | 7/8 as a top-five item; discussed by all | Strict generation removed malformed retries, but contradictory prose and ask-taking still weakened price discovery |
| Keep one generic signed Intent envelope | 8/8 | Every role preferred typed generic terms over business-category APIs |

The dominant commercial signal was demand for assurance: Evidence Verifier and
Transaction Operator made every sale. Agents with no sales proposed smaller
tranches, reusable templates, retainers, acceptance-risk services, pricing in
the observed 1.1–1.4 TOS band, and waiting for a signed job before buying
risk-reduction work. These are hypotheses for external-demand testing, not
proof of product-market fit.

## Tests and final review

- `go test ./pkg/earning -count=1` passed after the final source hardening.
- Focused Round 5 negotiation, sealed-executable, bootstrap-ordering, and
  payment-preflight tests passed; focused race tests and `go vet` passed.
- The sealed executable tests now exercise eight binds through one snapshot,
  Provider factory ordering, real descriptor closure, pathname replacement,
  and independent legacy/Round 4 behavior.
- The TOS nominator-pool test file passed 51 of 51 tests both before and after
  the final fast-forward; Ruff, format, and Python compilation checks passed.
- Final artifact validation independently recomputed process duration, result
  and financial totals, transaction uniqueness, Provider summary digest,
  Validator evidence digest, exact Account identities, rewards, payout,
  post-stake control, and eight closing assessments.
- `git diff --check` passed in the OpenFox, TOS, and service-spec worktrees.

The final source worktree includes post-run regression-test hardening and the
canonical RPC generator fix. The immutable campaign binary is the authority
for what the two-hour run executed; this report does not claim that post-run
test seams were exercised by that binary.

## Remaining work

A local PASS does not close the following evidence gaps:

- deploy and fund current-genesis Paid Demand service accounts, then test
  release, refund, timeout, recovery, and deliberately defective delivery;
- issue buyer acceptance or rejection evidence against predeclared criteria
  without turning observations into custody authority;
- attach authenticated Provider pricing/invoices and exact chain-fee evidence;
- test malicious counterparties, partitions, disagreement, clock skew, and
  recovery across independently operated hosts;
- bring in demand and capital outside the operator-funded ring; and
- separately design reviewed authority for any autonomous AI staking choice.

Those are deployment, instrumentation, independent-evidence, or future
authority tasks. Duplicating the existing Intent, Agreement, Outcome, escrow,
Portfolio, Pool, or Elector would not close them.
