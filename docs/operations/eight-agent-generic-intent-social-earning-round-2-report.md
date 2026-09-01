# Eight-Agent Generic Intent Social Earning Round 2 Report

This report records a three-hour OpenFox social earning experiment executed on
2026-09-01. Eight isolated OpenFox identities used their configured AI
backends to read one heterogeneous signed Intent bulletin, choose work or
decline it, conduct bounded counterparty dialogue, execute information-service
jobs, and settle direct native-TOS payments on the local validator network.

The chain, payment, finality, timing, and evidence-set checks passed. The run as
a whole did **not** pass Owner-policy conformance: six of the seven settled
purchases exceeded the buyer's configured maximum-loss ceiling. Those six
payments are valid observations of the binary that actually ran; they must not
be retrospectively presented as policy-compliant trades.

## Result boundary

| Layer | Result | Meaning |
|---|---|---|
| Three-hour runtime | PASS | The original 10,800-second window completed without shortening or timer reset. |
| Agent decisions | PASS as observation | Eight decisions completed: seven settlements and one rational skip. |
| Payment and three-RPC finality | PASS | Seven unique direct-TOS transactions were found and reconciled on all three queried RPC nodes. |
| Atomic evidence set | PASS | The completion, payment, validator-income, and validator-participation artifacts cross-reconcile. |
| Owner maximum-loss policy | **FAIL** | Six settled buyers paid more than their configured hard maximum loss. |
| External profitability | NOT ESTABLISHED | All 16.5 TOS of gross volume circulated inside the same eight-Agent perimeter. |
| Open-market or decentralization claim | NOT ESTABLISHED | The Agents, Carriers, wallets, and three monitored validators were operated on one local host. |

## Run identity

| Item | Observed value |
|---|---|
| Window | `2026-09-01T08:26:35.711239133Z` to `2026-09-01T11:26:35.711239133Z` |
| Requested duration | 10,800 seconds |
| Campaign completion | systemd final state `inactive`, `Result=success` |
| Autonomous buyer decisions | 8 in one paced round |
| Settled engagements | 7 |
| Rational buyer skips | 1 |
| Unique payment transactions | 7 |
| Gross internal transfer volume | 16.5 TOS |
| Intent Carriers | 2 local processes |
| Payment finality views | 3 local validator RPC nodes |

The eight identities retained distinct Owner IDs, Agent IDs, identity and
authority keys, writer fences, workspaces, journals, wallets, Agent Accounts,
and `.tos` names. They were eight logical runtimes, not eight independent
operators or host failure domains.

| Agent | `.tos` name | Business capability | AI backend |
|---|---|---|---|
| Security Auditor | `auditfox.tos` | smart-contract security review | Claude |
| Software Builder | `buildfox.tos` | contract remediation | Codex |
| Evidence Verifier | `prooffox.tos` | OTC evidence verification | Codex |
| Storage Provider | `marketfox.tos` | market-opportunity research | Claude |
| Data Curator | `datafox.tos` | generic Intent feed curation | Codex |
| Localization Writer | `linguafox.tos` | cross-border listing localization | Claude |
| Transaction Operator | `settlefox.tos` | settlement-path advice | Codex |
| Guarantor Analyst | `riskfox.tos` | counterparty-risk underwriting | Claude |

`storage-provider` is the retained harness identity for `marketfox.tos`; its
actual campaign capability was market research, not a measured storage
service.

## Decisions and the maximum-loss failure

All amounts below are TOS. For an unsecured direct payment, the full purchase
price was the buyer's reasonably possible loss. A purchase therefore complied
only when `price <= buyer maximum loss`.

| Buyer | Decision | Price | Buyer maximum loss | Conformance |
|---|---|---:|---:|---|
| Security Auditor | Bought market research from Storage Provider | 2.50 | 2.00 | **FAIL**, +0.50 |
| Software Builder | Bought market research from Storage Provider | 2.50 | 2.50 | PASS, exact boundary |
| Evidence Verifier | Bought localization from Localization Writer | 1.80 | 1.10 | **FAIL**, +0.70 |
| Storage Provider | Bought feed curation from Data Curator | 2.00 | 1.25 | **FAIL**, +0.75 |
| Data Curator | Bought market research from Storage Provider | 2.50 | 1.00 | **FAIL**, +1.50 |
| Localization Writer | Skipped every listing as uneconomic | 0 | 0.90 | PASS, no exposure |
| Transaction Operator | Bought evidence verification from Evidence Verifier | 2.20 | 1.50 | **FAIL**, +0.70 |
| Guarantor Analyst | Bought settlement advice from Transaction Operator | 3.00 | 2.25 | **FAIL**, +0.75 |

The model rationales repeatedly compared prices with a separate 6 TOS buying
budget while failing to enforce the smaller hard loss ceilings. One rationale
even required acceptance-gated payment to keep a 2.5 TOS purchase within a
1.0 TOS loss ceiling, but the harness then executed an unsecured direct
payment anyway. The closing assessments also failed to catch the mismatch:
all eight omitted the campaign-wide violation, and several asserted that
loss-capped acceptance had worked.

This is a deterministic authority failure, not merely a poor model judgment.
Natural-language reasoning may recommend a purchase, but it cannot be the
enforcement boundary for Owner capital.

## Economic result

`Maximum cost` is the declared conservative delivery-cost ceiling, not a
metered Claude, Codex, API, storage, or tool invoice. `Projected net` subtracts
that ceiling from transfer net but does not subtract network fees.

| Agent | Sold | Bought | Gross received | Spend | Maximum cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|---:|---:|
| Security Auditor | 0 | 1 | 0.0 | 2.5 | 0.0 | -2.5 | -2.5 |
| Software Builder | 0 | 1 | 0.0 | 2.5 | 0.0 | -2.5 | -2.5 |
| Evidence Verifier | 1 | 1 | 2.2 | 1.8 | 0.3 | +0.4 | +0.1 |
| Storage Provider | 3 | 1 | 7.5 | 2.0 | 1.2 | +5.5 | +4.3 |
| Data Curator | 1 | 1 | 2.0 | 2.5 | 0.3 | -0.5 | -0.8 |
| Localization Writer | 1 | 0 | 1.8 | 0.0 | 0.25 | +1.8 | +1.55 |
| Transaction Operator | 1 | 1 | 3.0 | 2.2 | 0.45 | +0.8 | +0.35 |
| Guarantor Analyst | 0 | 1 | 0.0 | 3.0 | 0.0 | -3.0 | -3.0 |
| **Closed economy** | **7** | **7** | **16.5** | **16.5** | **2.5** | **0** | **-2.5** |

The 16.5 TOS is gross internal circulation, not outside revenue. The aggregate
transfer net is necessarily zero because every payer and recipient was inside
the same perimeter. The conservative cost ceilings make the projected
closed-economy result -2.5 TOS before network fees.

The chain audit attributed exactly 851,751 nanotOS of aggregate wallet loss to
network processing:

| Fee component | nanotOS |
|---|---:|
| Source transaction fees | 755,151 |
| Destination account fees | 96,131 |
| Forwarding and other fees | 469 |
| **Total** | **851,751** |

The eight wallets' aggregate actual balance delta was exactly -851,751
nanotOS, so no unexplained account loss remains in the audited payment set. A
derived, fee-adjusted projected result is -2.500851751 TOS; it is not a field
from the financial summary and is not realized external profit or loss.

Execution took 41.861 to 81.567 seconds per settled information-service job.
Three-node settlement confirmation took 1.881 to 5.217 seconds. All seven
conversations contained exactly three messages and every price had an exact
`min = max` value hint. The run therefore exercised order acceptance, not
genuine price negotiation.

## What each Agent concluded

| Agent | Commercial background in this round | Main conclusion and proposed earning direction |
|---|---|---|
| Security Auditor | No sale; spent 2.5 TOS on pricing research; its 4.0 TOS audit did not clear. | Unbundle audits into lower-priced triage, sell reusable security annexes and second opinions, then pursue retainers. It read the 1.8–3.0 TOS clearing band as evidence that the 4.0 TOS package was too large. |
| Software Builder | No sale; spent exactly its 2.5 TOS loss ceiling on research. | Sell bounded audit-to-fix patches, triage, templates, regression tests, and maintenance only after qualified demand exists. |
| Evidence Verifier | Sold 2.2 TOS, bought 1.8 TOS, and retained only 0.1 TOS projected margin before Gas. | Productize reusable verification checklists, evidence-bundle integrity checks, chronology reconciliation, and larger packages; buy localization only after attributable foreign demand appears. |
| Storage Provider | Sold the same 2.5 TOS research product three times, bought 2.0 TOS curation, and led projected net at +4.3 TOS. | Convert repeated research into subscriptions, tiered scopes, and durable reusable artifacts rather than one-off snapshots. |
| Data Curator | Sold 2.0 TOS, bought 2.5 TOS, and ended at -0.8 TOS projected. | Pursue recurring feed triage, deduplication, and monitoring; require attributable incremental margin before buying research or automation. |
| Localization Writer | Sold one 1.8 TOS job and made the only buyer skip because every input cost more than its immediate gross job value. | Sell listing-copy retainers, licensed glossaries, Intent-copy authoring, and locale-compliance add-ons, positioning localization as a decision input. |
| Transaction Operator | Sold 3.0 TOS, bought 2.2 TOS evidence work, and retained +0.35 TOS projected before Gas. | Sell reusable settlement and evidence-readiness annexes and require reuse to justify purchased inputs. |
| Guarantor Analyst | No sale; spent 3.0 TOS before revenue; its 4.5 TOS underwriting offer did not clear. | Add an Owner-approved lower entry tier, sell reusable risk artifacts, and require a live sale or larger ticket before buying underwriting inputs. |

One conclusion repeated the [previous round](eight-agent-generic-intent-social-earning-report.md):
Agents should not buy reusable inputs before they have a concrete path to
attributable revenue. This round added a sharper observation: six of seven
purchases—three market-research buys plus curation, evidence verification, and
settlement advice—were meta-services about the cohort's own tiny market. They
are useful product feedback, but not proof of external demand.

## Agent recommendations and compatibility with existing work

The closing assessments converged strongly: 8/8 prioritized escrow,
acceptance, or dispute handling; 8/8 requested portable outcome-based
reputation; at least 6/8 requested cross-host or adversarial trials; 4/8
requested complete realized-cost accounting, with a fifth separately
requesting Gas/fee transparency; and 3/8 explicitly requested negotiation and
price discovery.

The classification below follows the reconciled
[commerce-infrastructure design](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/OPENFOX_AGENT_COMMERCE_TRUST_AND_MARKET_INFRASTRUCTURE_DESIGN.md),
[Codex review](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/OPENFOX_AGENT_COMMERCE_TRUST_AND_MARKET_INFRASTRUCTURE_DESIGN_REVIEW_REPORT.md),
and [implementation checkpoint](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/OPENFOX_AGENT_COMMERCE_TRUST_AND_MARKET_INFRASTRUCTURE_IMPLEMENTATION.md).
It distinguishes new defects, existing surfaces needing exercise, repeated
validation gaps, deferred expansion, and proposals that are not approved
protocol work.

| Recommendation | Background and meaning | Classification |
|---|---|---|
| Deterministically enforce buyer maximum loss | The most important finding was absent from all eight assessments: six direct purchases exceeded existing Owner limits. Enforcement must happen before Agreement commitment and again before custody, not in prose. | **NEW_PROBLEM**; implemented in the current uncommitted correction candidate; fresh-run validation still required |
| Exercise Gift | Gift exists but is a gratuity, not a purchase-settlement Adapter. No Gift was sent in this run. | **IMPLEMENTED_NOT_EXERCISED** |
| Complete and exercise current fixed-price Paid Demand escrow | Existing Agreement, Quote, escrow, Gate, Receipt, and local sequential-composition surfaces are implemented. A released buyer-side finalized evidence resolver and real release/refund/bounce/partition run remain missing; the current service asset is one supported stablecoin, while native TOS is Gas. | Local composition **IMPLEMENTED_NOT_EXERCISED**; operational resolver/run **REPEAT_VALIDATION** |
| Existing milestone, installment, periodic, deposit, and refund expression | Agreement obligations and BillingTerms already express these graphs. They were not used by this one-shot direct-payment campaign. | **IMPLEMENTED_NOT_EXERCISED** |
| Partial escrow funding/release, subjective buyer acceptance, chain `disputed`, split remedy, and appeal | Current escrow does not have these semantics. The controlling design defers them unless current-profile composition produces a documented reuse failure. | **DEFERRED / CONDITIONAL_CANDIDATE**, not approved implementation work |
| Outcome-based counterparty history | Outcome Event V1 and qualified OpenFox import and buyer/provider/service projections exist locally. What remains is independent Carrier/host verification and observed adverse outcomes; a new global reputation object is not approved. | **IMPLEMENTED_NOT_EXERCISED** plus **REPEAT_VALIDATION** |
| Signed Agreement revision negotiation | Existing revision lineage, fork handling, and scope amendment are implemented locally, but all seven prices were exact and no revision or counter-offer was attempted. | **IMPLEMENTED_NOT_EXERCISED** |
| Ranged prices | Intent V1 already supports signed value ranges, but this bulletin used `min = max` throughout. | **IMPLEMENTED_NOT_EXERCISED** |
| A separate CounterOffer object | Current design requires reuse of complete Agreement proposal versions. A new wire object is only a conditional candidate after a documented ambiguity and is not approved now. | **NOT_APPROVED / CONDITIONAL_CANDIDATE** |
| Acceptance requirements and observed accept/reject/rework/dispute outcomes | Agreement obligations and Outcome Events already carry these meanings. This run retained delivery/payment digests but produced no qualified quality-outcome event. Richer escrow custody enforcement for subjective acceptance remains deferred. | Existing evidence model **IMPLEMENTED_NOT_EXERCISED**; richer custody semantics **DEFERRED** |
| Real cost and fee accounting | Local closed-economy projection exists, and this report separately audited chain fees. Qualified model, tool, API, storage, network, invoice, and attributable-ROI adapters are still absent. | **DESIGNED_NOT_IMPLEMENTED** |
| Independent, cross-host, adverse-path campaigns | The same-host happy path did not test malicious Intents, nondelivery, nonpayment, partitions, clock skew, endpoint loss, or independent custody. This repeats the prior round's central validation gap. | **REPEAT_VALIDATION** |
| Capability, freshness, revocation, expiry, and hostile-input screening | Typed checks and local implementations exist. One embedded business instruction was correctly treated as data, but malformed, expired, revoked, and deliberately adversarial negative paths were not stressed. | **IMPLEMENTED_NOT_EXERCISED** |
| Autonomous recurring billing runtime | Agreement can already express periodic and installment terms. Repeated research sales motivated retainers and licensed artifacts, but the autonomous billing Adapter/runtime remains later [roadmap](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/OPENFOX_AUTONOMOUS_EARNING_ROADMAP.md) work. | **DEFERRED** |
| Anonymous cleared-price and no-bid signal | The Security Auditor wanted feedback when an offer receives no order. This is the most specific newly proposed market-data mechanism, but it needs privacy, manipulation, and evidence semantics before protocol work. | **NEW_PROBLEM** |

The practical priority is to preserve the generic Intent and existing
Agreement/Portfolio authority model, fix the violated Owner cap, then exercise
the already implemented revision, Outcome, Gift, and current escrow surfaces.
Only reproduced reuse failures should graduate into new protocol objects.

## Generic Intent result

One generic signed Intent envelope again carried security review, remediation,
evidence verification, market research, curation, localization, settlement
advice, and underwriting without a business-specific discovery endpoint.
Seven jobs across five purchased capabilities completed through the same
Intent, dialogue, Agreement, execution, payment, and finality structure, while
one Agent declined all listings.

That supports the organizational premise: the protocol carries identity,
signature, capability, scope, value hint, expiry, settlement adapter, and
digests; each Agent's AI interprets the business meaning. It does not support
an unlimited claim. The sample covered short information-service deliverables
on one host. It did not cover asset custody, streaming service, physical work,
unknown counterparties, hostile content, or independently operated Carriers.

## Validator activity and aggregate TOS creation

The validator monitor covered the exact experiment window with trusted samples
from before the start through after the deadline. Block-aligned reconciliation
used masterchain sequence 91,953 / basechain 91,934 at opening and masterchain
114,282 / basechain 114,267 at closing.

| Quantity | nanotOS |
|---|---:|
| ConfigParam 14 masterchain creation | 12,724,836,765,336 |
| ConfigParam 14 basechain creation | 7,486,538,988,611 |
| **Gross protocol creation** | **20,211,375,753,947** |
| Elector account delta | 20,211,376,605,698 |
| Audited Agent payment fees | 851,751 |
| Net unclassified residual | 0 |

The exact aggregate equation was:

```text
Elector delta = ConfigParam 14 creation + audited Agent fees + residual
20,211,376,605,698 = 20,211,375,753,947 + 851,751 + 0 nanotOS
```

This is aggregate Elector accumulation, not attributable income for an
individual validator. ConfigParam 3 was absent and the runtime correctly used
the ConfigParam 1 Elector fallback. No past election, reward-wallet mapping, or
allocated bonus was available in the observed state. Consequently,
per-validator income, reward-wallet credit, and allocated bonus are `null` /
`NOT_ATTRIBUTABLE`, not zero. Dividing the aggregate by three or four would be
fabricated accounting.

The configured validator set contained four identities with equal weight 17.
Three local nodes were monitored; the fourth configured identity was not a
monitored node. During the bounded log window each monitored node validated
44,544 blocks with zero invalid validations:

| Node | Validated | Collated | Consensus events | Unsuccessful consensus |
|---|---:|---:|---:|---:|
| node1 | 44,544 | 14,857 | 44,500 | 0 |
| node2 | 44,544 | 14,865 | 44,501 | 0 |
| node3 | 44,544 | 14,853 | 44,501 | 0 |

The zero residual proves the stated aggregate equation under the captured
sources. It does not exclude equal and opposite unclassified flows because an
exhaustive other-flow audit was not performed.

## Post-run corrective implementation

The completed campaign ran before this correction. It used a campaign Authority
whose limit was broader than each manifest Agent's maximum-loss cap, and its
harness could turn an AI `pursue` result into Agreement signatures and payment
without first linearizing the buyer's exact exposure. The production Agreement
path also separated a read-only aggregate check from the later reservation.
Accordingly, everything below describes the current uncommitted source
candidate and its regression coverage; it is not evidence that this campaign
complied.

The correction now:

- computes the local Agent's worst-case outgoing exposure from the exact
  Agreement body, using `BillingTerms.MaximumAggregateAmount` for installment
  or periodic obligations rather than one installment;
- sums exposure within one exact asset, rejects an Agreement containing
  incomparable outgoing assets, and accounts concurrent exposure in separate
  exact-asset Portfolio buckets;
- applies the Owner maximum-loss limit and atomically persists the exact
  Agreement reservation, reservation action, and Engagement linkage before
  creating any local buyer signature; the shared-Authority path reaches the
  same backing-authority gate;
- treats an over-cap proposal as a deterministic decline with no local
  Agreement signature, execution, payment, or learning side effect, while
  accepting the exact `exposure == cap` boundary;
- rejects missing, undersized, released, wrong-asset, stale, or substituted
  reservations both when recording local Agreement evidence and immediately
  before native custody;
- requires custody to recover the exact retained Agreement body, complete
  verified authorization-evidence set, local Agent signature, settlement
  obligation and state, mandate, destination, amount, source account, native
  asset, and full network-domain digest;
- restricts native TOS custody to the domain-bound schema-3 direct-payment
  profile and freezes the network, source account, native asset, and finality
  grace in the Owner Authority generation;
- persists a custody bearer before returning it, permits only one live bearer
  per reservation, and prevents generic Action or Portfolio transitions from
  releasing that bearer's hold;
- keeps the hold indefinitely when the Owner-pinned finality grace is zero.
  With a nonzero grace, release occurs only after every signed outgoing
  obligation horizon plus that frozen grace, and leaves a durable,
  restart-validated bearer tombstone;
- atomically admits relay-sponsorship payment purpose, exact payment Action,
  and maximum-loss hold, so sponsorship metadata cannot select an unreserved
  native-custody bypass; and
- resumes a native payment already in `Submitted` state only by rebroadcasting
  the custody-prepared BOC under the same stable action ID and exact request
  digest, without preparing, signing, or allocating a replacement payment.

The campaign harness now uses a fresh `campaign-authority-v3` generation whose
maximum-loss limit comes from each manifest Agent, performs deterministic buyer
admission and buyer-first reservation before either signature, compensates an
unsigned buyer hold if the seller reservation cannot be committed, and
checkpoints the accepted preflight Agreement body for byte-identical retry.

Focused regressions passed for over-cap rejection, exact-cap acceptance,
aggregate concurrent admission, shared-Authority enforcement, evidence replay,
native-custody binding and bearer retention, atomic sponsorship admission,
exact submitted-BOC recovery, durable expiry tombstones, campaign manifest
limit wiring, public accounting and scheduler isolation, and exact dependency
retry. The focused buyer-loss and race suites, `go vet` over the affected
packages, the affected config and command-package tests, and the full
`pkg/earning` suite all passed on the reviewed candidate.

These changes do not retroactively cure the six historical violations. A fresh
campaign is still required to exercise them. Automatic campaign recovery is
currently bounded to the accepted-preflight phase; after Agreement execution
or another externally visible side effect begins, the harness fails closed and
requires explicit recovery. The exact `Submitted` native-payment resumer is a
narrower recovery path, not a general phase checkpoint.

External settlement Adapters do not yet have an equivalent Owner asset
allow-list or exact recovery primitive, partial domain-bound native settlement
remains unsupported, and relay-sponsorship admission/tombstone compaction is
not implemented. The Economic Authority also does not yet own every
verifier-specific finality decision, so caller-provided finality evidence
cannot generically release an issued custody hold. Existing campaign journals
are not migrated: changed limits, missing asset pins, or legacy reservations
fail closed, and the next run must use the new Authority generation.

## Evidence set and trust boundary

The local-only canonical chain/runtime evidence pointer is:

`/home/tomi/.local/share/openfox-social-intent-3h-20260901-round2/reports/campaign-evidence-current`

It resolves to the atomically published, hash-bound generation intended not to
mutate:

`campaign-evidence-784e4f98-dbbd-4d8e-b427-e1caeed49741`

The manifest status is `PASS`; its SHA-256 is
`8a97cea1b0129074ee156489dc6cf3c97e9645081838ced73b3f4a0f5e5a7be2`.
The generation binds:

| Artifact | SHA-256 |
|---|---|
| Campaign completion audit | `14b0a4663c64f01541ba6499fa7256e5cdfd48c530329e574c78db40183cdbcd` |
| Agent payment three-RPC audit | `89c0f6dde4781c38213502bb1409d6a7c9298e6623863047b42e4b41e3f43b4a` |
| Validator income reconciliation | `9ed4f723c3da05946141eea2fb79225492ece97a830787ef60ae58f77e9fe751` |
| Validator participation summary | `263f3767066e4e10049d26240eb4764bd9a33449c40c5b59a43245c205c712d0` |
| Frozen campaign checkpoint | `efe9433af72172ba70d18dca59fd2c6737003020bad1993319fa8f5ec7eee55d` |
| Validator session-log window metadata | `e573630ddc033ffc44607cc3924644582466023ba97f9332ce90563fcec831ae` |

Consumers must resolve the pointer once, pin that directory, verify the
report-pinned manifest SHA-256 above, verify every manifest-listed source and
artifact hash, and only then read the set. The finalizer checks strict JSON,
checkpoint stability, bounded validator-log snapshots, artifact hashes,
cross-file counts, fee identity, participation identity, and the exact income
equation before atomically publishing the generation.

The Owner limits, model-authored assessments, and financial summary were not
inputs to the canonical finalizer. They were separately collected, validated,
and hash-pinned after finalization. To make this report's policy and
recommendation analysis reproducible without mutating the already-published
set, that separate post-run analysis snapshot is published at the local-only
pointer:

`/home/tomi/.local/share/openfox-social-intent-3h-20260901-round2/reports/analysis-evidence-current`

Its manifest SHA-256 is
`226fff59a290d15f134c9df166d9d1afb7ee5f242279021359a5f246f904a17a`.
That snapshot pins the campaign manifest (`e8fcb783...614b`), closing
assessments (`fa71bbd8...aa6`), financial summary (`7a5f2840...e41`), campaign
checkpoint (`efe9433a...55d`), and the canonical evidence manifest
(`8a97cea1...7be2`). It is a post-run analytical supplement, not part of the
campaign finalizer's atomic chain/runtime claim. Readers must verify its
manifest and all five full artifact hashes before using the cap or assessment
conclusions.

The validator-log proof assumes the local validator writers are honest and
append-only during capture. It detects ordinary truncation, rotation, inode
replacement, incomplete records, and checkpoint drift, but it is not designed
to defeat a malicious process with the same root or validator-log write
authority. The evidence filesystem is also Owner/root-writable: the pinned
hashes make later mutation detectable, but do not make the files physically
immutable or independently available.

A live operational check at 2026-09-01 12:07 UTC found the campaign inactive
and the validator monitor, Gateway Carrier, Messenger Carrier, evidence
finalizer, and a leftover log-tail process stopped. No experiment-only process
remained. The local validator nodes themselves remained running. This is a
post-publication observation, not a fact certified by the evidence generation.

## Limitations

- Same host, one round, eight Owner-authorized logical Agents.
- Closed internal economy; no outside customer or fiat-linked revenue.
- Direct native TOS only; Gift and escrow were not exercised.
- No price counter-offer, Agreement revision, repeated counterparty history,
  default, nondelivery, refund, dispute, deliberately malformed or malicious
  listing, or network partition. One embedded business instruction was
  correctly kept non-authoritative, but that is not an adversarial campaign.
- No qualified actual model, API, tool, storage, or rework invoice.
- No active learned skill was installed; generated learning material did not
  become loader-visible executable capability.
- Three monitored validator processes do not make individual reward allocation
  observable, and they do not establish public-network decentralization.
