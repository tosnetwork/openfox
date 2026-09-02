# Eight-Agent Capability Market Round 3 Report

This report records a three-hour OpenFox social capability-market experiment
completed on 2026-09-01. Eight named Agents used their own AI policies to read
heterogeneous signed Intents from two local Carriers, decide whether an
opportunity was worth pursuing, negotiate with the publisher, form a bounded
Agreement where authorized, deliver a digest-bound artifact, and settle in
native TOS. Separate lanes exercised Gift gratuities and Validator reward
attribution. A read-only Paid Demand preflight failed closed before making any
chain mutation.

## Result boundary

| Lane | Result | Evidence-bounded conclusion |
|---|---|---|
| Capability market | **PASS** | One uninterrupted 10,800-second process window; 16 AI/policy decisions; 5 direct-TOS Agreement settlements |
| Payment audit | **PASS_COMPLETE** | All 5 principals, transaction identities, account deltas, and fees reconciled at fixed masterchain sequence 195734 across 3 RPC nodes |
| Closing assessments | **PASS** | 8 of 8 Agents produced candid role-specific commercial and TOS Network assessments |
| Gift | **PASS** | 8 separately authorized 0.1 TOS ring gratuities; sender and recipient finalized; no Gift discharged an Agreement |
| Paid Demand / escrow | **BLOCKED_PRECONDITION / NOT_RUN** | Current-genesis deployment evidence and active service accounts were absent; no chain mutation was attempted |
| Validator attribution | **PASS** | 35 primary elections produced 140/140 exactly recovered candidate allocations; 4 boundary rollover allocations were retained; 0 missing and 0 outstanding |

The overall result is therefore not a blanket pass for every advertised
settlement mode. Direct native-TOS Agreements, Gift, and local Validator
attribution have their own evidence. Paid Demand escrow remains unavailable in
this environment until its current-genesis preconditions are supplied.

## Run identity

| Item | Observed value |
|---|---|
| Logical checkpoint start | `2026-09-01T17:40:55.635046803Z` |
| Qualifying process window | `2026-09-01T19:19:05.505381701Z` to `2026-09-01T22:19:05.604070844Z` |
| Observed uninterrupted duration | 10,800 seconds |
| Requested duration | 10,800 seconds |
| Campaign outcome | completed; Go test PASS after 11,172.20 seconds including setup and closing work |
| Campaign binary SHA-256 | `029bbc095f78f5e65d450c27015d8e07b100abf9299183f12f8546045df526b9` |
| Source base commit | `ac625caaf132a65cee45bf59269d996c5398358f` |
| Agent identities | 8 named `.tos` identities |
| Discovery | every decision used buyer-side AI carrier discovery across 2 local Carriers |
| TOS market network | one local three-node network, RPC ports 8011–8013 |
| Decisions | 16 over 2 rounds |
| Settlements | 5 direct native-TOS Agreement payments |

The logical checkpoint predates the qualifying window because recovery kept
completed economic decisions while rejecting incomplete process windows. Only
the final uninterrupted process window is counted as the three-hour result.
Systemd reported a successful main-process exit. It subsequently killed one
leftover Tokio worker during cgroup cleanup; this was not a failed campaign
main process.

## Participants and commercial policy

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

These were eight logical Agent runtimes on one host under one operator, not
eight independent organizations or failure domains. Claude and Codex were
used as distinct local AI kernels, while deterministic owner policy remained
the final spending and maximum-loss authority.

## Decision and negotiation result

All 16 opportunities were discovered through the generic signed Intent path.
Twelve received AI economic analysis; four deliberate buyer-strategy skips did
not spend model effort on a deal analysis. The terminal dispositions were:

- 5 settled;
- 4 skipped by buyer strategy;
- 3 declined by seller natural-language strategy;
- 3 declined by aggregate buyer maximum-loss policy;
- 1 declined because expected profit was below policy.

| Seq | Round | Buyer | Seller / capability | Result | Commercial observation |
|---:|---:|---|---|---|---|
| 0 | 1 | Security Auditor | — | skip | buyer strategy found no justified purchase |
| 1 | 1 | Software Builder | Transaction Operator / settlement audit | **settled 1.3 TOS** | Agreement V1; recovered after delivery without a replacement payment |
| 2 | 1 | Evidence Verifier | Transaction Operator / settlement audit | **settled 1.2 TOS** | real counteroffer; Agreement V1→V2 with predecessor digest |
| 3 | 1 | Storage Provider | Evidence Verifier / delivery verification | **settled 1.4 TOS** | Agreement V1 |
| 4 | 1 | Data Curator | Evidence Verifier / delivery verification | **settled 1.4 TOS** | Agreement V1 |
| 5 | 1 | Localization Writer | — | skip | no downstream demand justified a speculative input |
| 6 | 1 | Transaction Operator | Evidence Verifier / delivery verification | decline | seller target and buyer economics did not align |
| 7 | 1 | Guarantor Analyst | Evidence Verifier / delivery verification | decline | contradictory 1.4 TOS headline and 1.3 TOS embedded ceiling made expected net negative |
| 8 | 2 | Security Auditor | Transaction Operator / settlement audit | **settled 1.3 TOS** | Agreement V1 |
| 9 | 2 | Software Builder | Evidence Verifier / delivery verification | decline | aggregate buyer maximum-loss gate |
| 10 | 2 | Evidence Verifier | Transaction Operator / settlement audit | decline | buyer offer below seller target |
| 11 | 2 | Storage Provider | Evidence Verifier / delivery verification | decline | aggregate buyer maximum-loss gate |
| 12 | 2 | Data Curator | Evidence Verifier / delivery verification | decline | aggregate buyer maximum-loss gate |
| 13 | 2 | Localization Writer | — | skip | no exogenous localization demand |
| 14 | 2 | Transaction Operator | Software Builder / workflow planning | decline | buyer offer below seller target |
| 15 | 2 | Guarantor Analyst | — | skip | speculative purchase lacked committed downstream revenue |

Settled conversations contained three to four messages. Sequence 2 was the
only genuine price revision. It proved signed counteroffer lineage, but the
market still exhibited shallow price discovery: most interactions either
accepted the buyer's stated budget or stopped.

## Economic result

All service amounts below exclude Gifts. `Maximum cost` is an owner-declared
admission reserve, not a measured model or API invoice. `Projected net`
subtracts that reserve; it is not accounting profit.

| Agent | Revenue | Spend | Maximum cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|
| Security Auditor | 0 | 1.3 | 0 | -1.3 | -1.3 |
| Software Builder | 0 | 1.3 | 0 | -1.3 | -1.3 |
| Evidence Verifier | 2.8 | 1.2 | 0.4 | +1.6 | +1.2 |
| Storage Provider | 0 | 1.4 | 0 | -1.4 | -1.4 |
| Data Curator | 0 | 1.4 | 0 | -1.4 | -1.4 |
| Localization Writer | 0 | 0 | 0 | 0 | 0 |
| Transaction Operator | 3.8 | 0 | 0.6 | +3.8 | +3.2 |
| Guarantor Analyst | 0 | 0 | 0 | 0 | 0 |
| **Closed economy** | **6.6** | **6.6** | **1.0** | **0** | **-1.0** |

The 6.6 TOS is internal gross service volume, not external revenue. Every TOS
of service revenue bought one of two market-risk services: three settlement
audits or two delivery-evidence verifications. None of the six substantive
domain listings sold. This is a useful demand signal inside the experiment,
but the same-host synthetic economy cannot establish product-market fit.

Five settled records reported average execution time of 13.495 seconds. One
recovered post-delivery execution did not retain a measurable execution
duration and contributed zero to that aggregate; the other four took 5.027 to
37.838 seconds. Average settlement confirmation was 2.283 seconds.

### Exact payment and fee audit

The complete audit pinned masterchain sequence 195734 and observed matching
views on RPC nodes 8011–8013. It reconciled five unique payments, exact sender
and recipient account deltas, and zero unexplained residual:

- source-side transaction fees: 495,728 nanotos;
- destination-side transaction fees: 41,202 nanotos;
- transaction-fee subtotal: 536,930 nanotos;
- forwarding/other balance impact: 335 nanotos;
- total network fee impact: **537,265 nanotos (0.000537265 TOS)**;
- internal principal net: exactly zero.

| Agent | Exact fee impact (nanotos) |
|---|---:|
| Security Auditor | 99,991 |
| Software Builder | 98,861 |
| Evidence Verifier | 114,794 |
| Storage Provider | 99,076 |
| Data Curator | 99,090 |
| Localization Writer | 0 |
| Transaction Operator | 25,453 |
| Guarantor Analyst | 0 |
| **Total** | **537,265** |

Model, subscription, external API, human-review, and opportunity costs remain
unmeasured. External profitability is therefore **NOT_ESTABLISHED** even for
the two Agents with positive internal transfer net.

## Outcome evidence and recovery

All five settled Agreements produced authority-qualified, payload-bound local
Outcome evidence:

`provider_delivery=succeeded; service_execution=unknown`

This proves that the authorized provider delivered the bound payload. It does
not prove that the business result was correct, useful, or accepted against
every criterion. Later Agents used this as weak local evidence and did not
convert it into a global reputation score.

Sequence 1 also exercised a crash seam after delivery. Recovery queried and
adopted the exact existing payment identity. It did not submit a replacement
payment. Focused tests cover buyer-only and both-sides-settled recovery seams
with the same query-before-retry invariant.

## Gift lane

A separate binary with SHA-256
`afe060ad16ba6c3cd20445f440b6629ca52c07d50a820319e8161342eaf51baf`
completed an eight-edge ring:

- 8 Gifts × 0.1 TOS = 0.8 TOS principal;
- 24 protocol messages;
- 8 unique native custody actions and transactions;
- sender and recipient both reached `finalized-paid` on every edge;
- every accounting entry was classified as `gratuity`;
- `agreement_settlement_applied=false` on all 8 entries.

Visible source and destination transaction fees totalled 916,956 nanotos
(794,681 + 122,275). Because no exact pre-Gift whole-network balance snapshot
was retained, this is a transaction-fee subtotal, not a claimed total network
fee impact. Ring Gifts net principal to zero per Agent and are excluded from
service revenue.

## Paid Demand and escrow preflight

The read-only preflight returned `BLOCKED_PRECONDITION / NOT_RUN` and made no
chain mutation. It found:

- no accepted current TOS Service V1 deployment record;
- the inspected asset master, buyer, and provider accounts uninitialized on
  all three current-chain views;
- the archived fixture pinned to a different genesis;
- no fresh current-genesis escrow fixture;
- Paid Demand and escrow gates disabled for all eight Round 3 Agents.

Contract BOC files are build artifacts, not deployment evidence. This result
must not be reported as a failed escrow transaction or as proof that the
escrow lifecycle is available.

## Validator reward-wallet and election attribution

The Validator experiment used a separate local four-process network and four
dedicated reward wallets. It is not the three-node Agent payment chain. Each
stable election required all four candidate records and four-node ConfigParam
34 consensus. Reward was attributed from each reward wallet's exact
single-election recovery transaction as:

`reward = Elector credit - 10,000 TOS recovered principal`

No reward was inferred by averaging the Elector balance or dividing an
aggregate equally among Validators.

| Item | Final observation |
|---|---|
| Ready experiment window | `2026-09-01T19:34:30.436697Z` to `2026-09-01T22:34:30.436697Z` |
| Settlement/recovery tail | `2026-09-01T22:34:30.436697Z` to `2026-09-01T22:49:30.436697Z` |
| Elections | 35 primary + 1 settlement rollover |
| Candidate allocations | 144 total: 140 primary + 4 rollover |
| Recovered primary allocations | 140 |
| Missing primary candidates | 0 |
| Outstanding allocations | 0 |
| Retained settlement rollover allocations | 4 |
| Principal recovered | 1,400,000 TOS |
| Exact credit | 1,425,141.744651108 TOS |
| Exact reward | 25,141.744651108 TOS |
| Evidence SHA-256 | `1e14546759a42cc121f764fc8c7d292d25f3df3d0ad1ffe7622086c5c05872ec` |

The per-Validator records were identical because all four Validators were
selected with equal weight in every recorded set and each produced the same
35 exact recovery records. The values below are sums of those records, not an
equal division of an Elector aggregate.

| Validator / RPC | Dedicated reward wallet | Exact primary recoveries | Retained rollover | Credit | Reward |
|---|---|---:|---:|---:|---:|
| 1 / 8131 | `-1:25d930e699707ddde39d94e2b2f15b235f45f7f3b1e0213c3efa9d96716b4f83` | 35 | 1 | 356,285.436162777 TOS | 6,285.436162777 TOS |
| 2 / 8132 | `-1:5255228f863be89864b2e69dc7998e76fa7ca48d247b995fd5f34e50671eb3e3` | 35 | 1 | 356,285.436162777 TOS | 6,285.436162777 TOS |
| 3 / 8133 | `-1:25b9b91918b9c881a56b0a9bbcd9f70ffb2a21dcc62e176a3848e26bd317e8f7` | 35 | 1 | 356,285.436162777 TOS | 6,285.436162777 TOS |
| 4 / 8134 | `-1:75cb6122316fce48c44c82d7283f45135823d2156489cde18aa2c4114724d851` | 35 | 1 | 356,285.436162777 TOS | 6,285.436162777 TOS |

This accelerated local-election profile is designed to test attribution and
recovery. Its reward rate cannot be extrapolated to mainnet APR, annual
issuance, or supply inflation.

### Validator incidents and corrections

The first three-hour attempt ran from 16:07:53 to 19:07:53 UTC and then used a
15-minute recovery tail. It recorded 35 primary elections and 140 candidate
allocations, but recovered only 136; four remained outstanding and no
settlement rollover was retained. Exact recovered principal was 1,360,000 TOS,
credit was 1,384,460.074058852 TOS, and reward was 24,460.074058852 TOS. An
older report incorrectly marked that partial state as pass.

Investigation found two faults:

1. each 20,020 TOS reward wallet could support two concurrent 10,001 TOS stake
   messages, but not the third needed at the primary-window boundary;
2. report generation did not fail closed on outstanding allocations.

The implementation now funds 30,030 TOS per reward wallet, preserves the
third concurrent stake, explicitly retains boundary rollover allocations, and
fails the report if primary candidates are missing or expected recoveries are
unattributed. A first rerun then stopped before readiness because the original
100,000 TOS test faucet could not fund the fourth enlarged wallet. It produced
zero elections and is not counted. The final rerun used an
experiment-only 136,120 TOS faucet; default launch and production supply
settings were not changed.

## What the Agents concluded

The closing assessments were generated from the core 16-decision market
record before the separate Gift and Validator results were attached. Their
statements that those lanes were absent are therefore accurate for their
input, not contradictions of the later independent lane evidence.

| Agent | Own result and commercial correction |
|---|---|
| Security Auditor | Bought 1.3 TOS, sold nothing. Its 2.4 TOS target sat above every clearing price; it proposed a ≤1.4 TOS bounded review tranche and selling acceptance/Intent hygiene. |
| Software Builder | Bought 1.3 TOS, sold nothing. It would retain bounded workflow planning but buy inputs only against committed revenue or reusable operational value. |
| Evidence Verifier | Sold 2.8 TOS and bought 1.2 TOS; +1.6 TOS transfer net before costs. It would repeat fixed-scope acceptance verification and quality gates after costs become measurable. |
| Storage Provider | Bought 1.4 TOS, sold nothing. It proposed repositioning report synthesis as acceptance-criteria packaging and adding lower-priced tiers. |
| Data Curator | Bought 1.4 TOS, sold nothing. It would sell freshness/provenance add-ons and verified bundles only where demand covers verification cost. |
| Localization Writer | Neither bought nor sold. It proposed attaching localization as a conditional rider to an already-signed job and bundling it with verification. |
| Transaction Operator | Sold 3.8 TOS; projected +3.2 TOS after declared reserves, but not measured profit. It proposed repeatable audit templates, finality checks, and duplicate-payment detection. |
| Guarantor Analyst | Neither bought nor sold. It proposed agreement-risk scoring, contract-hygiene checks, and tranche pricing instead of speculative trend-data purchases. |

The most concentrated recommendations were:

1. **Measured cost evidence (8/8).** Exact chain fee, model, API, tool, rework,
   and dispute cost must replace `unknown` before profit can be claimed.
2. **Acceptance-quality separation (8/8).** Delivery, buyer acceptance,
   service execution, dispute state, and payment finality need independent
   evidence.
3. **Untrusted settlement and broader trials (8/8 in some form).** Supply a
   current-genesis escrow preflight and exercise independent-host, external,
   failure, or adversarial counterparties.
4. **Structured generic economic terms (at least 6/8).** Keep one Intent
   envelope, but make price bands, loss caps, acceptance criteria, failure
   terms, and precedence machine-checkable.
5. **Earlier portfolio/capacity gating (at least 6/8).** Do not spend dialogue
   and Agreement work on a deal that aggregate owner exposure must reject.
6. **Real negotiation and exogenous demand.** Counteroffer rather than merely
   accept/decline, reduce discovery concentration, and add buyers who are not
   sellers in the same ring.

## Implementation produced by the experiment

The OpenFox worktree now includes:

- ranged offers and seller counteroffers with predecessor-linked Agreement
  revisions;
- aggregate buyer maximum-loss admission before payment authority;
- authority-qualified local Outcome and explicit cost-evidence states;
- strict Gift resume validation, finalized custody binding, and gratuity-only
  accounting;
- query-and-adopt recovery of an exact existing payment, never blind payment
  replay;
- bounded retries for invalid AI negotiation output followed by safe decline,
  while infrastructure failures remain fatal;
- crash-seam and end-to-end evidence tests.

The TOS worktree now includes:

- an explicit Validator election experiment mode with four RPC readiness
  checks;
- reward-wallet-to-Validator mappings, ConfigParam 34 consensus, exact
  recovery attribution, and missing-candidate failure;
- funding for three concurrent stake messages per Validator;
- an experiment-only enlarged faucet, leaving normal launch values and the
  5-billion-TOS mainnet supply tests unchanged;
- fail-closed experiment reports and focused tests.

The observed campaign binary was built at 19:18 UTC. Two current-source test
files changed at 19:44 UTC while that immutable binary was running. Runtime
claims in this report therefore come from the recorded binary hash; current
source claims come from the final post-run test suite. No hot update is
claimed.

## Recovery history

Six earlier campaign starts were excluded from the three-hour result because
they failed before an uninterrupted qualifying window:

| Attempt | Fail-closed reason |
|---|---|
| original | writer-fence defect |
| resume 1 | stale inventory |
| resume 2 | incomplete network-domain pin |
| resume 3 | `tosctl` preflight failure |
| resume 4 | stale inventory |
| resume 5 | unverified predecessor |
| resume 6 | invalid AI negotiation output after 43m35s |

Resume 7 is the only counted OpenFox process window. Preserving these failures
is important: recovery correctness is part of the experiment, while adding
short failed windows together would not satisfy a three-hour run.

## Validation gates

Final source validation:

- main OpenFox module: `go test ./...` and `go vet ./...` passed;
- 23 capability-market, Agreement revision, recovery, Outcome, cost-evidence,
  and publication tests directly covering this change passed with the race
  detector in 3.011 seconds;
- `pkg/evolution` and `pkg/agentgift` passed with the race detector;
- nested `pkg/servicebridge/nativeimpl` module: `GOWORK=off go test ./...`,
  `go vet ./...`, and `go test -race ./...` passed;
- TOS: 29 focused zero-state and Validator experiment pytest cases passed;
- TOS Ruff checks passed for the experiment script, zero-state builder, and
  their tests;
- `make lint-docs` passed for the bilingual reports.

One broader diagnostic is deliberately not presented as a pass. Running the
entire main-module `pkg/earning` package under the race detector reached the
15-minute package timeout in the unchanged
`TestGuarantorProviderIssuesReservedOfferAndLinearizesAcceptance`. The test
goroutine was runnable in TOS Service Protocol canonical JSON validation and
no data race was reported. The isolated test passed without race
instrumentation in 96.403 seconds; all 23 tests that directly cover this
change passed under race. This is a pre-existing race-build performance limit,
not evidence that the timed-out package-wide gate passed.

Repository whitespace validation also passed with `git diff --check`. No
commit or push is part of this run.

## Evidence and privacy boundary

- The campaign root contains owner-local identities, credentials, custody
  configuration, and other machine-private evidence and is not published.
- Validator run directories contain private runtime keys. The declassified
  evidence JSON says it contains no private key material, but the surrounding
  run directory must remain private.
- All eight Agents, both Carriers, three payment nodes, and four Validator
  nodes ran under one operator on one host.
- Payloads and work products were bounded and synthetic. No independent buyer
  validated business quality.
- Gifts prove the gratuity path, not service payment or Agreement discharge.
- Paid Demand and escrow were not run.
- Local accelerated Validator reward results do not establish mainnet
  issuance economics.
- Internal token revenue, projected reserve margins, and exact chain fees do
  not establish external profitability while model/API costs remain unknown.

Within those limits, the experiment demonstrates a coherent generic commerce
loop: autonomous AI discovery and refusal, bounded negotiation, signed and
versioned authority, payload-bound delivery, exact direct-TOS payment,
query-before-retry recovery, separately accounted Gifts, and exact local
Validator reward attribution.
