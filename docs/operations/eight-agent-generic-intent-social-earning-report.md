# Eight-Agent Generic Intent Social Earning Report

This report records a three-hour OpenFox social earning experiment executed on
2026-08-31. Eight isolated OpenFox identities used their configured AI backends
to read one generic signed Intent bulletin, decide independently whether a
purchase would improve their own business, conduct bounded counterparty
dialogue, and either decline or complete a direct TOS settlement on a fresh
local three-validator network.

The campaign validates a local integration and produces useful economic and
protocol feedback. It does not demonstrate public-network decentralization,
external customer demand, Gift settlement, escrow, or realized fiat profit.

## Run identity

| Item | Observed value |
|---|---|
| Original window | `2026-08-31T20:44:23.028728587Z` to `2026-08-31T23:44:23Z` |
| Requested duration | 10,800 seconds |
| Harness | `TestEightOpenFoxAutonomousMarketCampaign` |
| Harness result | PASS |
| Final-process test duration | 9,183.85 seconds after checkpoint-safe restart |
| Campaign binary SHA-256 | `0a407c10d3c0d841ef6cb2d1b0e068dbea406b5440cabc8d25676b93accae64e` |
| Trusted `tosctl` SHA-256 | `83f89d1652b1a3ae4f02e37c4df2bb0bc0931c7417027e21026cc8f0be5cafca` |
| Agent identities | 8 |
| Autonomous buyer decisions | 8 in one paced round |
| Settled engagements | 4 |
| Rational buyer declines | 4 |
| Unique payment transactions | 4 |
| Intent Carrier processes | 2 |
| TOS finality views | 3 local validator RPC nodes |

The restart did not reset the experiment clock. The checkpoint retained the
original `started_at`, completed sequences were not replayed, and the final
timer still waited until the original start plus three hours.

The eight identities had distinct owner IDs, Agent IDs, signing keys, writer
fences, workspaces, economic journals, wallets, Agent Accounts, and `.tos`
names. They were eight logical runtimes on one host, not independent host or
operator failure domains.

## Fresh chain and names

The experiment used a newly generated local network with no migrated test
state. Its zero-state hashes were:

- root: `ltXc3lKuzs6ZtgDYpnKA9CBeTzZy+SoKBapjkY79ypo=`;
- file: `m9sSggiEcNEwFpwOoTfyk9hyQnkjubO9Tb9dOsx47qk=`.

The local profile deliberately pinned its locally generated DNS Root through
ConfigParam 4 at
`-1:2775e17a6d86588d20ae00e9fb63c39d3d2d8739076f79fd6f66d4724235c67e`.
The delegated Collection was
`0:4c78141819f67d9c4616eb3810485dc095b20169f138b65b4ab6aca332986547`.
This local override is not the canonical mainnet Root vector.

Each name completed a real one-hour auction, entered `leased` state, and
received an `agent` `dns_smc_address` record:

| Name | Role | Agent Account |
|---|---|---|
| `auditfox.tos` | Security Auditor | `0:cb24f0de96718bf7ab7825e59285478e6939f5f32cb0eb8267a97526915ab053` |
| `buildfox.tos` | Software Builder | `0:a57c2a5af109585153ce3de0aeb1da63c32fece96ae55116fd579ebda45c294d` |
| `prooffox.tos` | Evidence Verifier | `0:9ed78a5bf73c74c8668505ce6ab075d89d24c24273818d41d986202c0e6fd0b4` |
| `marketfox.tos` | Market Researcher | `0:f16838c6a1b6a83cfd2ea168a4a36f09ac059fce2941a1ec0f11bec769e76f72` |
| `datafox.tos` | Intent Feed Curator | `0:6fa938897200f0c3172cfc9e68f2c907542a7f2f9b8f9bbea2283b1844c4dd9e` |
| `linguafox.tos` | Localization Writer | `0:803138060400284b0741fa80e1f863316763680268455b5640caacd447f0a34e` |
| `settlefox.tos` | Transaction Operator | `0:87004890ffeb001c6da0ffbcc832f2dd2454f22fc9b2b14e1cbb4fe95605b957` |
| `riskfox.tos` | Guarantor Analyst | `0:ff2b9d0e851aafcd80323bc059eb17ad3502cd33e7210255700f39e0c9f6de21` |

All 24 combinations of eight names and three RPC nodes resolved to the exact
expected Agent Account, reported the Root source as ConfigParam 4, and reported
the item lifecycle as `leased`.

## Participants and autonomous decisions

| Buyer | Decision | Counterparty or reason | Amount |
|---|---|---|---:|
| Security Auditor | Decline | Research had thin marginal value; every plausible purchase exceeded its 2 TOS possible-loss limit or depended on future revenue | 0 |
| Software Builder | Buy | MarketFox market-opportunity research to improve remediation scope and pricing | 2.5 |
| Evidence Verifier | Buy | MarketFox market-opportunity research to position a 2.2 TOS verification offer | 2.5 |
| Market Researcher | Buy | DataFox generic feed curation as reusable two-stage screening infrastructure | 2.0 |
| Intent Feed Curator | Decline | No demonstrated workload or near-term revenue justified buying a 5 TOS helper | 0 |
| Localization Writer | Decline | The cheapest input exceeded one 1.8 TOS job's gross revenue; no downstream localization demand existed yet | 0 |
| Transaction Operator | Decline | Every listing exceeded its 1.5 TOS maximum loss under unsecured direct payment | 0 |
| Guarantor Analyst | Buy | ProofFox evidence rubric was reusable, inspectable, and priced just below its 2.25 TOS loss cap | 2.2 |

Every accepted deal used three signed conversation messages: request,
scope-and-quote, and explicit acceptance. The messages stated that ordinary
chat did not authorize execution or collection. A later typed Agreement bound
the execution and payment.

The four declines are successful outcomes. They created no Agreement,
reservation, execution, or payment. Their reasons exposed a real price and
risk boundary more clearly than manufactured transactions would have.

## Economic result

All amounts below are TOS. `Maximum cost` is the conservative owner-policy
reserve attached to sold work, not a metered Claude or Codex invoice.
`Transfer net` is revenue minus purchases. `Projected net` also subtracts the
maximum cost reserve.

| Agent | Sold | Bought | Revenue | Spend | Maximum cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|---:|---:|
| Security Auditor | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Software Builder | 0 | 1 | 0.0 | 2.5 | 0.0 | -2.5 | -2.5 |
| Evidence Verifier | 1 | 1 | 2.2 | 2.5 | 0.3 | -0.3 | -0.6 |
| Market Researcher | 2 | 1 | 5.0 | 2.0 | 0.8 | +3.0 | +2.2 |
| Intent Feed Curator | 1 | 0 | 2.0 | 0.0 | 0.3 | +2.0 | +1.7 |
| Localization Writer | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Transaction Operator | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Guarantor Analyst | 0 | 1 | 0.0 | 2.2 | 0.0 | -2.2 | -2.2 |
| **Closed economy** | **4** | **4** | **9.2** | **9.2** | **1.4** | **0** | **-1.4** |

The aggregate transfer net is zero because every customer was another
campaign Agent. Gross revenue is not external revenue and must not be presented
as such. The negative closed-economy projected net equals the aggregate
conservative cost reserve.

Mean bounded execution time was 61.099 seconds and mean three-node settlement
confirmation was 2.045 seconds. All four accepted decisions used AI economic
analysis; declines stopped before the seller economic analysis stage.

### Exact account observations

The three RPC nodes returned identical balances, last transaction logical
times, and transaction hashes for all eight Agent Accounts. The exact final
balances were:

| Agent | Balance (nanotos) |
|---|---:|
| Security Auditor | 19,999,992,150 |
| Software Builder | 17,499,892,994 |
| Evidence Verifier | 19,699,883,029 |
| Market Researcher | 22,999,876,637 |
| Intent Feed Curator | 21,999,982,941 |
| Localization Writer | 19,999,992,150 |
| Transaction Operator | 19,999,992,150 |
| Guarantor Analyst | 17,799,890,892 |

The difference between business transfer arithmetic and exact account balance
is message and execution cost. A final network sample at masterchain sequence
28,365 returned the same root and file hashes from RPC ports 8011, 8012, and
8013.

## What the Agents learned about earning

| Agent | Main conclusion |
|---|---|
| Security Auditor | Its zero activity was economically correct. The 4 TOS audit could not clear while unsecured buyer exposure equalled the full price; it proposed milestone-split audits instead of silently discounting. |
| Software Builder | Its 2.5 TOS purchase may improve future positioning but did not produce revenue in this round. It wants audit-to-fix partnerships, paid triage, and maintenance retainers. |
| Evidence Verifier | One sale had good unit economics, but buying 2.5 TOS of research left its round cash flow at -0.3 TOS. It wants reusable verification rubrics, batch verification, and retainers. |
| Market Researcher | Two repeat sales validated a reusable information product. It proposed a shared baseline plus buyer-specific delta, subscriptions, tiered depth, and refusal-derived demand intelligence. It candidly judged its 2 TOS curation purchase weak at a feed size of seven. |
| Intent Feed Curator | One 2 TOS sale produced +1.7 TOS projected net. It refused to buy without demonstrated near-term value and wants recurring curation only when feed scale justifies it. |
| Localization Writer | Its lowest price still generated no demand, so price was not the bottleneck. It proposed selling into downstream human/foreign markets and attaching localization to an already signed deal. |
| Transaction Operator | Complete abstention followed directly from its 1.5 TOS loss cap and missing escrow. It would buy evidence or risk analysis only for a live profitable engagement with bounded exposure. |
| Guarantor Analyst | It spent before earning and called that sequencing a mistake. It proposed a cheaper owner-approved triage tier, event-triggered underwriting, reputation infrastructure, volume-linked fees, and wholesale risk scores. |

Two broad commercial lessons emerged:

1. Agents should earn or observe real demand before capitalizing inputs whose
   return depends on future rounds.
2. A loss cap becomes a hard price ceiling when direct payment leaves the full
   amount unsecured. Escrow and milestones are economic market infrastructure,
   not merely payment features.

## Generic Intent result

The generic signed Intent design worked for security review, code remediation,
OTC evidence, market research, feed curation, localization, settlement advice,
and underwriting without introducing a business-specific discovery API.

Agents consistently recommended keeping the common envelope thin and stable:
identity and signature, capability, value hint, expiry, provenance, settlement
adapter, and digest binding. Business meaning can remain signed content
interpreted by each Agent's own AI. Useful additions are cross-business rather
than per-business APIs:

- acceptance criteria and revision limits;
- exact price versus negotiable range;
- counter-offer and scope-amendment messages;
- payment timing, milestones, and supported settlement rails;
- typed optional attachments for facts that require machine validation.

This conclusion is limited to short information-service deliverables. Custody,
streaming, physical work, multi-stage delivery, and hostile content were not
tested.

## Agent assessment of TOS Network

All eight assessments converged on the same evidence boundary.

What the run supports:

- one signed discovery format carried heterogeneous businesses;
- autonomous Agents made selective, non-manufactured buy/decline decisions;
- Agreement, execution, deliverable, payment, and finality identities were
  digest-linked;
- four direct payments completed with approximately two-second confirmation;
- three RPC nodes agreed on every checked account and name binding.

What it does not support:

- no external demand or realized outside profit;
- no Gift, escrow, milestone release, refund, or dispute was exercised;
- no nondelivery, payment refusal, quality disagreement, malicious listing,
  Sybil identity, network partition, or independent-host failure occurred;
- exact asking prices were accepted, so genuine price negotiation and price
  discovery were not tested;
- a same-host, one-round, owner-authorized cohort cannot prove open-market
  security, decentralization, liquidity, or sustainable demand.

The collective verdict is that the protocol plumbing is credible for a local
information-service market, while the trust and economic layers remain
unproven.

## Highest-priority ecosystem improvements

The recurring priorities across all eight independent assessments were:

1. **Escrow and milestone settlement.** Add bounded acceptance deadlines,
   timeout/refund rules, staged release, and dispute handling. This would have
   changed the outcome of this run by admitting buyers whose loss cap was below
   the whole job price.
2. **Portable verifiable reputation.** Accumulate independently checkable
   delivery, payment, lateness, revision, diversity, and dispute evidence
   instead of self-asserted ratings.
3. **Structured acceptance and dispute evidence.** Define revision limits,
   acceptance tests, evidence submission, and deterministic remedies while
   retaining opaque deliverable content.
4. **Real negotiation and demand discovery.** Support signed counter-offers,
   price ranges, scope-for-price changes, and buyer-published demand Intents.
5. **Persistent adversarial multi-host experiments.** Run multiple rounds
   across independent owners and machines with malicious listings, failures,
   network disruption, real Gift and escrow paths, and actual cost telemetry.

## Skill evolution and the acquisition boundary

The Market Researcher produced repeated successful learning evidence. Its
model-authored draft did not become an executable skill. After the corrected
run, the draft was retained at the common content-addressed quarantine and the
loader-visible `skills` directory remained empty. The final financial summary
therefore correctly reports zero active learned skills for all Agents.

The experiment found that earning evolution had constructed its applier
without the common external capability-acquisition fence. The implementation
now:

- passes the separately administered Owner/Agent acquisition authority into
  the earning evolution recorder;
- observes exact `reserve` then `commit` acquisition transitions;
- retains generated material only in quarantine pending separate review and
  promotion;
- rejects apply mode when the new constructor has no fence;
- rejects apply mode through the legacy non-fenced constructor, preventing a
  future production bypass.

A focused ordinary and race-tested regression asserts the owner/agent scope,
phase sequence, quarantined artifact, and absence of a loader-visible skill.

## Runtime findings and repairs

The long run exposed two issues before final completion:

1. The first payment attempt failed closed because the configured `tosctl`
   executable inherited a group-writable build-tree ancestor. No payment side
   effect occurred. The exact binary was copied to an owner-only, immutable
   path with mode `0500`, re-hashed, and the campaign resumed from its
   checkpoint.
2. The first repeated-work learning attempt failed closed because the earning
   evolution recorder lacked the external acquisition fence. The trade itself
   had already settled and learning failure was non-authoritative. The fence
   was wired through production and campaign construction, the binary was
   rebuilt, and the campaign resumed without replaying completed jobs. The
   next draft was quarantined successfully.

Both failures were useful: execution and payment authority failed closed, the
checkpoint prevented duplicate economic actions, and the final run completed
without weakening policy.

## Mainnet genesis work validated alongside the run

The local experiment also exercised the DNS behavior needed for the planned
mainnet profile. The source tree now fixes canonical mainnet genesis time to
`1789434000`, or `2026-09-15 10:00:00 JST` (`01:00:00 UTC`), and refuses a
different `SOURCE_DATE_EPOCH`. The canonical zero-state pins ConfigParam 4 to
the audited TIP-1 counterfactual Root account id
`280e2d46c2bea67664609ad2df6db55ef92dd257ff5b16c3317eed59fa649a32`.
The Root still must be deployed from the byte-identical audited StateInit; a
pinned but undeployed address remains fail-closed.

## Validation gates

The final source tree passed:

- `go test ./...`;
- `go vet ./...`;
- `go test -race ./pkg/earning ./pkg/evolution -timeout=30m`;
- focused ordinary and race tests for the earning acquisition fence;
- `pytest` zero-state supply/genesis suite: 10 passed;
- `cargo test -p tos_sandbox`: 14 passed;
- `test-smartcont`: 23 passed;
- `git diff --check` in OpenFox, TOS, and documentation repositories;
- 24/24 three-node `.tos` binding checks;
- 24/24 three-node Agent Account state checks.

The default 10-minute race invocation initially timed out in an unrelated,
CPU-heavy Guarantor journal integration test while it was still serializing
state. Re-running the exact packages with a 30-minute timeout passed in
983.249 seconds for `pkg/earning` and 1.744 seconds for `pkg/evolution`; no data
race or deadlock was reported.

## Evidence location and operational end state

The complete checkpoint, financial summary, closing assessments, signed
conversation records, Carrier journals, chain control files, and Agent state
remain under:

`/home/tomi/.local/share/openfox-social-intent-3h-20260831`

The two experiment-only Carrier services were stopped after evidence capture.
The fresh three-node TOS network remained running and mutually consistent.
