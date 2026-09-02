# Eight-Agent Capability Market Round 4 Report

This report records a two-hour OpenFox capability-market experiment completed
on 2026-09-02. Eight named Agents used AI-led carrier discovery and their own
commercial policy to evaluate generic signed Intents. The run also exercised
early Portfolio screening, private Provider-usage accounting, and a separate
identity-bound Validator nominator lifecycle.

The changes deliberately reuse existing TOS Service Protocol objects and TOS
chain contracts. They do not introduce business-specific APIs, a second
Agreement or Portfolio authority, a global reputation score, another escrow
state machine, or another staking protocol.

## Result boundary

| Lane | Result | Evidence-bounded conclusion |
|---|---|---|
| Capability market | **PASS** | One uninterrupted 7,200-second process window; 16 decisions; 3 direct-TOS Agreement settlements |
| Closing assessments | **PASS** | 8 of 8 Agents produced non-empty role-specific assessments from a structured prompt |
| Early Portfolio screening | **PASS_EXERCISED** | 3 infeasible opportunities stopped before AI planning or contact; final atomic reservation remained authoritative |
| Provider usage | **PARTIAL** | 141 calls were durably counted; usage was present on 24, missing on 117, invalid on 0, and 8 calls failed; 190,901 tokens were reported for covered calls, but monetary cost is unknown |
| Validator nominator delegation | **PASS** | 8 identity-bound proxy wallets each delegated 999 TOS and received a positive reward; one post-stake control received zero; one withdrawal returned principal and reward |
| Direct-TOS payment | **PASS for settlement identity only** | 3 unique payment transactions finalized; a separate fixed-block fee audit was not run, so current-run chain fees remain unknown |
| Buyer acceptance and service correctness | **NOT_ESTABLISHED** | All settled rows prove bound payload delivery but retain `service_execution=unknown` |
| Successful price negotiation | **NOT_ESTABLISHED** | All settlements were Agreement V1 at the asking amount; no valid successor or accepted counteroffer occurred |
| Gift | **NOT_RUN** | The earlier Gift capability was not repeated in this profile |
| Paid Demand / escrow | **NOT_RUN** | No current-genesis deployment preconditions were supplied; no escrow mutation was attempted |
| Cross-host, malicious, or external-demand trial | **NOT_RUN** | All Agents and Carriers were logical runtimes under one host and operator |

The result is not a blanket market, escrow, profitability, or production
Validator pass. Each lane has its own evidence and limits.

## Existing protocol versus the actual infrastructure delta

| Need | Existing authority reused | Round 4 implementation | Deliberately not built |
|---|---|---|---|
| Acceptance and disputes | Generic Agreement V1 obligations, Outcome Event V1, and the existing escrow adapter already separate delivery, acceptance, execution, dispute, refund, and payment assertions | Continued emitting authority-qualified local Outcome evidence and preserved unknown states | No second acceptance object, subjective quality oracle, dispute contract, or simulated escrow success |
| Outcome-informed trust | Owner-local buyer-payment, provider-delivery, and service-capability views already consume source-bound Outcome evidence | Later planning could use only the local retained record; no executable capability was admitted from a reputation claim | No portable dossier, `.tos` trust flag, or global score |
| Cost evidence | Cost Observation V1 already defines declared, measured, invoiced, finalized, allocated, and other meanings | Added an owner-private, metadata-only Provider wrapper with a durable pre-call marker, exact recovery rules, sealing, and a content-addressed aggregate | No campaign cost wire object and no conversion from tokens to money without a price or invoice |
| Capacity | Owner Economic Action Authority, Portfolio, Writer Fence, and final atomic Agreement reservation already enforce aggregate exposure | Added advisory checks using the same aggregate admission calculation before planning, before contact, and before negotiation | No second budget, speculative reservation, or AI-owned authority; final reservation remains authoritative |
| Negotiation | Generic Intent, authenticated dialogue, typed Agreement proposals, and predecessor-linked revisions already support counteroffers | Reused the existing bounded retry and fail-closed signed-price checks; the run exposed a remaining structured-generation gap | No business-specific endpoint, standalone `CounterOffer`, or parallel proposal lineage |
| Validator delegation | The TOS multi-nominator pool and Elector already own deposit, staking, reward split, recovery, and withdrawal semantics | Added explicit wallet selection, exact JSON inspection, and an identity-bound lifecycle runner with selection, reward, control, payout, solvency, and re-entry checks | No governance vote, Agent-authority delegation, new staking contract, or new reward rule |
| Evidence integrity | Existing campaign artifacts and canonical digests | Added a private run nonce, single-writer lock, strict JSON shape and run binding, crash-safe Provider journals, and immutable aggregate references | No new protocol object or public prompt/response archive |

This reconciliation matters because several repeated Agent requests describe
deployment or evidence gaps, not missing protocol primitives. Duplicating the
primitive would create conflicting authority without making the missing
deployment or independent evidence appear.

## Run identity

| Item | Observed value |
|---|---|
| Campaign run ID | `round4:596f06f8f0b8fc2e24eac103098b83cf8bd990b52fd24e84afcbdb8b0f81d33e` |
| Qualifying process window | `2026-09-02T02:49:41.830739700Z` to `2026-09-02T04:49:41.857675863Z` |
| Observed uninterrupted duration | 7,200 seconds |
| Requested duration | 7,200 seconds |
| Evidence sealed | `2026-09-02T04:56:31.150520491Z` |
| Campaign test result | PASS after 7,609.34 seconds including closing work |
| OpenFox base commit | `7744ddaa407dde9a4a685130ca272ed3649fb07b` plus an explicitly uncommitted tested worktree |
| TOS base commit | `e68ce75ef5c0c0f74561585b6a6a04ca29800b57` plus an explicitly uncommitted tested worktree |
| Campaign binary SHA-256 | `825d361e1c815edd57ad353d26486cd7fed9e8a7e3ba3167a4fe9df4e911997f` |
| Agent manifest SHA-256 | `4d197150fa4e0471090b81420049db2a0848a66c617d39e37e57e9a7b40062a2` |
| Market network | one local three-node TOS payment network |
| Discovery | two local Carriers under the same operator |
| Decisions | 16 over 2 rounds, paced at 7 minutes 30 seconds |

The exact runtime claim is bound to the immutable binary and artifact hashes.
No exact source commit is claimed because the implementation was not committed
when the binary was built. The source claims below refer to the separately
tested final worktrees.

Preliminary campaign starts and a sidecar attempt containing transient invalid
balance observations were archived and excluded. They were not combined with
the qualifying window or final sidecar.

## Participants and policy

| Agent | `.tos` name | Model | Offered capability | Target / floor | Buyer maximum loss |
|---|---|---|---|---:|---:|
| Security Auditor | `auditfox.tos` | Claude | API-adapter security review | 2.4 / 1.2 TOS | 1.8 TOS |
| Software Builder | `buildfox.tos` | Codex | commercial workflow planning | 1.8 / 1.0 TOS | 1.5 TOS |
| Evidence Verifier | `prooffox.tos` | Codex | delivery-evidence verification | 1.4 / 0.8 TOS | 1.2 TOS |
| Storage Provider | `marketfox.tos` | Claude | decision-report synthesis | 2.0 / 1.1 TOS | 1.6 TOS |
| Data Curator | `datafox.tos` | Codex | sourced POI data snapshot | 1.8 / 1.0 TOS | 1.5 TOS |
| Localization Writer | `linguafox.tos` | Claude | cross-border service localization | 1.2 / 0.6 TOS | 1.0 TOS |
| Transaction Operator | `settlefox.tos` | Codex | TOS cost and settlement audit | 1.3 / 0.7 TOS | 1.1 TOS |
| Guarantor Analyst | `riskfox.tos` | Claude | market-trend data analysis | 1.7 / 0.9 TOS | 1.4 TOS |

These were eight logical Agent runtimes on one host, not eight independent
organizations or failure domains. Deterministic Owner policy remained the
authority for spending, loss limits, Agreements, execution, and custody.

## Decisions and negotiation

The canonical campaign JSON, rather than the Agents' later prose summaries,
controls the totals:

- 3 settled;
- 4 declined after three model negotiation attempts escaped signed bounds;
- 3 declined by the selected seller's natural-language strategy, principally
  because target price and buyer budget did not align;
- 3 skipped by buyer strategy after discovery; and
- 3 skipped by the new Portfolio-capacity prefilter before AI planning or
  counterparty contact.

Ten rows reached seller-side AI economic analysis. The other six did not:
three were buyer-strategy skips and three were early capacity skips. The ten
selected opportunities concentrated on two risk-reduction capabilities:
Evidence Verifier was selected 8 times and Transaction Operator 2 times.
Seven seller analyses returned `pursue`: three settled and four were stopped
by buyer negotiation conformance. Round 2 produced no settlement.

| Seq | Round | Buyer | Seller / capability | Result | Evidence-bounded observation |
|---:|---:|---|---|---|---|
| 0 | 1 | Security Auditor | Evidence Verifier / delivery verification | decline | all three negotiation outputs escaped signed bounds |
| 1 | 1 | Software Builder | Transaction Operator / settlement audit | **settled 1.3 TOS** | Agreement V1, 3 messages, direct TOS |
| 2 | 1 | Evidence Verifier | Transaction Operator / settlement audit | decline | seller strategy rejected a 1.2 TOS ceiling below its 1.3 TOS target |
| 3 | 1 | Storage Provider | Evidence Verifier / delivery verification | **settled 1.4 TOS** | Agreement V1, 3 messages, direct TOS |
| 4 | 1 | Data Curator | Evidence Verifier / delivery verification | **settled 1.4 TOS** | Agreement V1, 3 messages, direct TOS |
| 5 | 1 | Localization Writer | — | strategy skip | no committed downstream work justified buying a speculative input |
| 6 | 1 | Transaction Operator | Evidence Verifier / delivery verification | decline | 1.10 TOS buyer ceiling did not meet 1.4 TOS seller target |
| 7 | 1 | Guarantor Analyst | Evidence Verifier / delivery verification | decline | all three negotiation outputs escaped signed bounds |
| 8 | 2 | Security Auditor | Evidence Verifier / delivery verification | decline | all three negotiation outputs escaped signed bounds |
| 9 | 2 | Software Builder | — | capacity skip | no listing fit aggregate Portfolio limits; no AI planning or contact |
| 10 | 2 | Evidence Verifier | — | strategy skip | speculative settlement audit lacked a current job and exceeded its loss policy |
| 11 | 2 | Storage Provider | — | capacity skip | no listing fit aggregate Portfolio limits; no AI planning or contact |
| 12 | 2 | Data Curator | — | capacity skip | no listing fit aggregate Portfolio limits; no AI planning or contact |
| 13 | 2 | Localization Writer | — | strategy skip | input prices consumed too much of a 1.2 TOS sale without real demand |
| 14 | 2 | Transaction Operator | Evidence Verifier / delivery verification | decline | capability fit, but 1.10 TOS buyer budget was below 1.4 TOS target |
| 15 | 2 | Guarantor Analyst | Evidence Verifier / delivery verification | decline | all three negotiation outputs escaped signed bounds |

All three settlements used Agreement V1. No accepted price revision or
predecessor-linked Agreement successor occurred in this run. Bounded retry and
Owner checks protected authority, but 4 of 16 decision slots ended with
invalid model negotiation output. The next implementation should constrain or
deterministically repair the generated offer fields while retaining the same
generic Intent and Agreement lineage.

The early-capacity change was exercised on sequences 9, 11, and 12. No row
ended in the later `declined:buyer-maximum-loss` state. This is direct evidence
that the optimization worked in this schedule, not a claim that concurrent or
adversarial capacity races are proven safe.

Some closing assessments reported three invalid negotiations or five skips;
the canonical counts are four and six. Some also interpreted a seller's
strategy rationale as a buyer authority-propagation failure. That field
describes the selected seller's commercial limits. The proven defect is the
four buyer negotiation outputs that escaped signed bounds, not evidence that
Owner authority was incorrectly propagated.

## Service economics

`Maximum cost` is the seller's declared admission reserve on settled work, not
a measured expense. `Projected net` subtracts that ceiling and therefore is
not accounting profit.

| Agent | Jobs sold / bought | Revenue | Spend | Maximum cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|---:|
| Security Auditor | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| Software Builder | 0 / 1 | 0 | 1.3 | 0 | -1.3 | -1.3 |
| Evidence Verifier | 2 / 0 | 2.8 | 0 | 0.4 | +2.8 | +2.4 |
| Storage Provider | 0 / 1 | 0 | 1.4 | 0 | -1.4 | -1.4 |
| Data Curator | 0 / 1 | 0 | 1.4 | 0 | -1.4 | -1.4 |
| Localization Writer | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| Transaction Operator | 1 / 0 | 1.3 | 0 | 0.2 | +1.3 | +1.1 |
| Guarantor Analyst | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| **Closed economy** | **3 / 3** | **4.1** | **4.1** | **0.6** | **0** | **-0.6** |

The 4.1 TOS is internal gross service volume inside one operator-funded ring,
not external revenue. Buyers did make real internal payments, but independent
business value was not measured. Average execution time was 17.519 seconds
and average settlement time was 3.688 seconds across the three jobs.

### Provider usage and monetary-cost boundary

| Agent | Calls | Usage present | Usage missing | Failed | Observed tokens |
|---|---:|---:|---:|---:|---:|
| Security Auditor | 9 | 9 | 0 | 0 | 59,065 |
| Software Builder | 3 | 0 | 3 | 0 | 0 |
| Evidence Verifier | 101 | 0 | 101 | 6 | 0 |
| Storage Provider | 3 | 3 | 0 | 0 | 35,635 |
| Data Curator | 3 | 0 | 3 | 0 | 0 |
| Localization Writer | 3 | 3 | 0 | 0 | 36,026 |
| Transaction Operator | 10 | 0 | 10 | 2 | 0 |
| Guarantor Analyst | 9 | 9 | 0 | 0 | 60,175 |
| **Total** | **141** | **24** | **117** | **8** | **190,901** |

Zero observed tokens for a row means the Provider omitted usage; it does not
mean zero consumption. The 190,901 total is the subtotal reported by the 24
covered calls, not total campaign usage. No accepted Provider price schedule, invoice,
subscription allocation, discount, tax, currency conversion, or payment
evidence exists. Model and API cost in money therefore remains `unknown`.

The three settled rows also retain `chain_fee=unknown`. Their unique payment
transactions prove settlement identity, but this run did not pin a fixed
block and reconcile sender and recipient deltas across all RPC nodes. Unknown
is not zero, so realized or external profit is **NOT_ESTABLISHED**.

## Outcome evidence and local history

All three settled Agreements produced:

`authority_qualified_payload_bound;provider_delivery=succeeded;service_execution=unknown`

This proves that the authorized provider returned the digest-bound payload.
It does not prove buyer acceptance, correctness, usefulness, or satisfaction
of every business criterion. The other 13 rows correctly report no Agreement
terminal subject.

The Evidence Verifier created a reusable skill draft during one delivery, but
trusted capability admission quarantined it for review. Market evidence did
not grant executable power. Later local policy could observe that prior
attempts lacked an authority-bound terminal outcome, but the experiment did
not create or validate a portable reputation score. Sequences 8, 10, 14, and
15 explicitly consulted retained local history and treated missing terminal
evidence as uncertainty rather than a global negative score.

## Validator nominator delegation

The requested action was implemented as **nominator stake delegation** through
the existing multi-nominator pool. It was not governance voting,
`DelegateAgentV1` authority delegation, a commerce payment, or an Agreement
settlement.

The sidecar ran from `2026-09-02T02:20:24.605017Z` through
`2026-09-02T02:40:17.114987Z` on a fresh accelerated, different-genesis local
network. ConfigParam 34 selected the pool Validator in a 5-of-5 Validator set.
The pool assigned 40% of election reward to the Validator and the rest to
active nominators using the existing contract rules.

Each identity-bound proxy wallet was funded with 1,099.999999 TOS, sent a
1,000 TOS deposit message, and recorded exactly 999 TOS of principal after the
existing 1 TOS processing fee. About 100 TOS remained outside the delegation,
so the test exercised delegation of only part of the held balance.

| Agent proxy | Recorded principal | Exact ledger reward | Election-derived floor |
|---|---:|---:|---:|
| Security Auditor | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Software Builder | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Evidence Verifier | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Storage Provider | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Data Curator | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Localization Writer | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Transaction Operator | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| Guarantor Analyst | 999 TOS | 12.753734459 TOS | 12.716243971 TOS |
| **Total** | **7,992 TOS** | **102.029875672 TOS** | **101.729951768 TOS** |

The ledger delta is exact. Elector attribution is only a lower bound because
the recovery reply can also carry residual keeper message value. The gross
election reward was 169.549919619 TOS; it must not be divided or extrapolated
into production APR.

A ninth control deposited 999 TOS only after the pool was already staked and
received exactly zero reward for that election. The Guarantor Analyst proxy
then received 1,011.753733336 TOS in its wallet, including returned principal;
the 1,123-nanotos difference from its pool entitlement stayed below the
explicit withdrawal-fee bound. Queue blocking, permissionless recovery,
payout, solvency, and pool re-entry also passed.

The proxy wallets are bound to the eight logical identities and the exact
campaign manifest, but they are not the live campaign wallets on the payment
genesis. The decision to delegate was an operator-specified test scenario,
not an autonomous AI investment choice. Delegated principal and reward are
capital activity and are excluded from service revenue and spend.

## What the eight closing assessments mean

The assessments came from a structured close-out prompt, so they are prompted
role-specific judgments, not an unprompted survey. Their numerical claims were
checked against the canonical artifacts before coding themes.

| Concentrated Round 4 theme | Agents | Meaning and evidence background |
|---|---:|---|
| Schema-safe negotiation and authoritative price precedence | 8/8 | Four decision slots ended after bounded retries because generated amounts escaped signed bounds. The fix belongs in constrained generation and deterministic repair around the existing generic negotiation path, not a new business API. |
| Measured cost evidence | 8/8 | The new journal proves call and partial token counts, but only 24/141 calls exposed usage and no monetary price or invoice exists. Profit remains unfalsifiable until chain, model, API, tool, rework, and dispute costs are qualified. |
| Acceptance and execution evidence beyond delivery | 8/8 | Every settled row proved payload delivery but retained `service_execution=unknown`. Agents want criterion-referenced buyer acceptance or dispute evidence while preserving separate states and Owner-local interpretation. |
| Working current-genesis escrow / refund path | 8/8 | Direct TOS was safe only inside a pre-authorized local ring. The protocol and adapter exist, but deployment evidence and funded current-genesis service accounts were absent. |
| Independent hosts and external demand | 7/8 | The closed same-owner ring cannot prove real demand, counterparty risk, repeat purchase, external revenue, or adversarial recovery. This remains an experiment gap rather than a missing commerce object. |
| More explicit typed terms in the generic envelope | 8/8 | Agents repeatedly asked for one authoritative price, loss, scope, clarification, failure, and acceptance representation with prose marked advisory. Existing Intent and Agreement fields should be compiled and validated consistently rather than split by business type. |

Two additional commercial signals were less universal but important:

- demand concentrated on verification and settlement-risk reduction, while
  six other listed capabilities made no sale; and
- several Agents recommended lower-priced bounded tranches, bundles,
  retainers, or demand-first pricing instead of speculative purchases.

The earlier Portfolio recommendation is now partially answered: sequences 9,
11, and 12 stopped before AI planning and contact using the same authoritative
capacity calculation. It should remain advisory because only final atomic
Agreement reservation can linearize capacity under concurrency.

## Post-run stale-evidence correction

Independent final review found one evidence-recovery gap in the runtime
runner. It atomically replaced the stable sidecar evidence only when an
attempt finished. If an operator deliberately reused the same campaign run ID
and that retry suffered a hard failure before replacement, the preceding PASS
file could remain visible.

The final source now pairs the evidence with a persistent generation lock and
a private, exclusive, fsynced in-progress marker. The sidecar holds the lock
exclusively for its whole attempt; the OpenFox campaign holds it shared from
preflight through final report sealing, so another generation cannot complete
between its reads. The marker is created before any sidecar network setup and
survives a hard crash. OpenFox checks it before and after reading evidence and
manifest and rejects the older PASS while an attempt is unresolved.
Finalization fsyncs the new evidence file, atomically replaces the stable
path, fsyncs its parent directory, and only then removes and durably clears
the exact marker. A changed marker is not cleared.

This correction adds no protocol object and changes no pool or reward logic.
Focused Python, Go, and Go race tests pass. It was implemented after the
immutable campaign binary and sidecar run, so this report does not claim that
the two-hour experiment exercised the new hard-crash seam. The completed run
itself had no same-nonce rerun and its 50 checked artifact bindings remain
valid.

### Agent-specific commercial corrections

| Agent | Evidence-based correction |
|---|---|
| Security Auditor | It made no sale and had two failed buy negotiations. It proposed a lower-priced bounded triage tier and acceptance-evidence packaging below its 2.4 TOS full-review quote. |
| Software Builder | It bought one 1.3 TOS input and sold nothing. It would buy only against committed or reusable value and package planning as a bounded reusable product. |
| Evidence Verifier | It led volume with two sales and 2.8 TOS gross receipts. It can productize repeatable evidence gates, but cannot call the result profit while cost and acceptance remain unknown. |
| Storage Provider | It bought 1.4 TOS and sold nothing. It should reprice bounded work near observed clearing prices, differentiate with evidence-bound reports, and avoid speculative inputs. |
| Data Curator | It bought 1.4 TOS and sold nothing. It should focus on freshness, provenance, and evidence-bound datasets attached to concrete demand. |
| Localization Writer | It correctly declined speculative buying. It would attach localization to a larger signed job rather than consume most of a 1.2 TOS sale on an input. |
| Transaction Operator | It sold one 1.3 TOS audit. It can productize repeatable settlement checks and buy verification only when it protects concrete revenue. |
| Guarantor Analyst | It made no sale and had two failed buy negotiations. It proposed repricing a 1.7 TOS analysis as a 0.9–1.2 TOS pre-commitment risk screen. |

## Validation

Final checks passed:

- `go test ./pkg/earning -count=1 -timeout 6m` in OpenFox: PASS in 133.584s;
- focused `go test -race` for Provider usage, run scope, and Validator evidence:
  PASS in 1.649s;
- TOS Ruff checks for the lifecycle runner and encoding tests: PASS;
- TOS nominator encoding and stale-attempt pytest: 33 passed;
- Rust `commands` pool tests: 18 passed, with one unrelated existing
  unused-import warning;
- Rust formatting and `git diff --check`: PASS; and
- strict final artifact assertions for run identity, sequence, finances,
  usage, closing assessments, sidecar binding, and reward arithmetic: PASS.

| Final artifact | SHA-256 |
|---|---|
| Campaign checkpoint | `fc05f87110722c29148f80f3a61f396042687c8f51edb8c2e84ab6a1e367bd4a` |
| Financial summary | `1dac1eb063f9bd9ae8d30a206cf1fcd10fd756e43a1a0fdbeb4bbf21045366fd` |
| Closing assessments | `0b56db12f464bfaa2047c72b854ce227837699f0623ee63a4b184eedaaaf5c6c` |
| Provider-usage aggregate | `add4858cb100243261d7bb2777949b381de7bb38ef4da12b9f64c99551f55ab8` |
| Validator sidecar | `0fdbb8cb53d42411e013f7096b412d6f1262b43a82b30dd6c6383652f15a0bfb` |
| Agent manifest | `4d197150fa4e0471090b81420049db2a0848a66c617d39e37e57e9a7b40062a2` |
| Campaign binary | `825d361e1c815edd57ad353d26486cd7fed9e8a7e3ba3167a4fe9df4e911997f` |
| Runtime nominator lifecycle runner, before post-run review fix | `54950f9f32179a35a836d2589d52fec6a0ce9fbc4c760908c5da7af2cc0e6b7f` |
| Final source nominator lifecycle runner with generation lock and attempt marker | `67a9d682840871632334101471a1c4a4bd39a21c4c9f4a4711ee5258c7c3a5ed` |

No commit or push is part of this experiment.

## Evidence, privacy, and remaining limits

The owner-local campaign root contains identities, credentials, custody
configuration, raw Agent artifacts, and Provider journals and must remain
private. The Provider accounting layer intentionally retains no prompts,
responses, tool definitions, tool calls, model options, or Provider error
text. The sidecar run directory contains private Validator and wallet material;
only the declassified evidence JSON is suitable for review.

Within that boundary, Round 4 demonstrates fail-closed AI commerce decisions,
real early Portfolio screening, three generic direct-TOS Agreements, durable
partial Provider metering, and eight positive nominator rewards from the
existing pool. It does not establish external demand or profit, business
acceptance, current-genesis escrow, independent-host or malicious scenarios,
portable reputation, same-genesis campaign-wallet delegation, autonomous
staking choice, production liveness, slashing or storage-rent safety, mainnet
APR or issuance, or a ROADMAP gate.
