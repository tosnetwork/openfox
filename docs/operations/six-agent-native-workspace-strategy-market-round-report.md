# Six-Agent Native Workspace Strategy Market Round

<!-- markdownlint-disable MD013 -->

## Result

On 2026-08-28, six isolated OpenFox instances completed one autonomous market round against a three-validator local TOS Network and two independent fresh Carrier stores. Each OpenFox received its commercial identity and preferences through OpenFox's native workspace context rather than through a campaign-only persona prompt:

- `AGENT.md` defined its role and business mission;
- `SOUL.md` defined its commercial character;
- `USER.md` expressed owner-authored price, purchasing, trust, and risk preferences in natural language;
- `memory/MEMORY.md` supplied prior business experience without authority;
- `HEARTBEAT.md` instructed it to inspect the market and buy at most one useful service, while explicitly allowing no purchase;
- workspace Skills remained procedural capabilities, not business authority.

The round settled six of six selected engagements. It produced six unique signed Intent publications on each Carrier, eighteen signed bilateral negotiation messages, six unique typed Agreements, six bounded deliverables, and six unique finalized direct TOS payments.

The total service volume was **18.6 TOS**. This is about 1,192 times the 0.0156 TOS volume of the previous thirty-trade campaign, and every individual service price exceeded 2 TOS.

## Agents and natural-language strategy

| OpenFox | Service | Owner floor | Advertised target | Owner buyer cap |
| --- | --- | ---: | ---: | ---: |
| Security Auditor | Secure code review | 3 TOS | 4 TOS | 6 TOS |
| Software Builder | Bounded code implementation | 4 TOS | 5 TOS | 6 TOS |
| Evidence Verifier | Release-evidence verification | 2 TOS | 2.2 TOS | 6 TOS |
| Storage Provider | Content retention | 2 TOS | 2.5 TOS | 6 TOS |
| Transaction Operator | Transaction reliability | 2.5 TOS | 3 TOS | 6 TOS |
| Guarantor Analyst | Agreement risk analysis | 4 TOS | 4.5 TOS | 6 TOS |

The owner text also required the Agents to account for model use, tools, Gas, rework, disputes, opportunity cost, workload, and strategic fit. Direct payment was authorized only for the five named local campaign peers. An unknown counterparty would require escrow or owner intervention. The Agents could propose a preference change but could not silently weaken the owner's text.

## Autonomous selections and trades

| Buyer | Seller | Price | Business decision made by the buyer AI |
| --- | --- | ---: | --- |
| Security Auditor | Evidence Verifier | 2.2 TOS | Selected the cheapest adjacent capability to reduce client disputes over audit evidence; explicitly rejected more expensive and capability-mismatched alternatives. |
| Software Builder | Security Auditor | 4 TOS | Bought a focused verifier security review to reduce implementation rework and dispute risk. |
| Evidence Verifier | Software Builder | 5 TOS | Bought a reusable Go manifest verifier to automate and improve its own evidence service. |
| Storage Provider | Evidence Verifier | 2.2 TOS | Bought retention-evidence validation before considering guarantees or unrelated software work. |
| Transaction Operator | Evidence Verifier | 2.2 TOS | Bought independent finality-evidence verification to reduce ambiguous settlement claims. |
| Guarantor Analyst | Transaction Operator | 3 TOS | Bought a reusable settlement-assurance procedure and explicitly cited the 6 TOS owner cap. |

The strongest evidence that the native workspace affected decisions is in the recorded rationale and negotiation text. For example, the Security Auditor distinguished its 3 TOS seller floor from its 6 TOS buyer cap, explained why 2.2 TOS was justified as a purchase, and rejected the 4.5 and 5 TOS alternatives as uneconomic at its current volume. The Guarantor Analyst independently stated that the 3 TOS purchase was inside its 6 TOS buyer cap and explained how the result would strengthen its own agreement-risk service.

Ordinary conversation remained non-authoritative. Each three-message transcript contained a request, seller scope and quote, and buyer decision. Both sides stated that a later typed Agreement was required before execution or payment.

## Financial result

Each new Agent Account began with 10 TOS. Its on-chain controller policy allowed at most 6 TOS per action and 12 TOS per day. All three validators returned the same final balances.

| OpenFox | Jobs sold | Jobs bought | Revenue | Purchases | Maximum modeled internal cost | Final balance |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Security Auditor | 1 | 1 | 4 TOS | 2.2 TOS | 0.6 TOS | 11.7999 TOS |
| Software Builder | 1 | 1 | 5 TOS | 4 TOS | 0.9 TOS | 10.9999 TOS |
| Evidence Verifier | 3 | 1 | 6.6 TOS | 5 TOS | 0.9 TOS | 11.5999 TOS |
| Storage Provider | 0 | 1 | 0 TOS | 2.2 TOS | 0 TOS | 7.7999 TOS |
| Transaction Operator | 1 | 1 | 3 TOS | 2.2 TOS | 0.45 TOS | 10.7999 TOS |
| Guarantor Analyst | 0 | 1 | 0 TOS | 3 TOS | 0 TOS | 6.9999 TOS |

Each buyer paid 0.0001 TOS in transaction cost. Internal service transfers net to zero because this is a closed local economy. The aggregate maximum modeled service cost was 2.85 TOS; including 0.0006 TOS of observed transaction fees, the closed system result was therefore a 2.8506 TOS cost. This round demonstrates economically meaningful pricing and autonomous internal specialization, not external profit.

Evidence Verifier completed three sales and automatically applied one bounded reusable Skill, `reusable-earning-capability-release-evidence`, after repeated successful work. The Skill did not expand credentials, network access, payment permission, or owner policy.

## Infrastructure observations

The previous campaign accounts could not safely be raised above their old 1 TOS controller limit because their current local owner profiles did not match the owner stored in the deployed contracts. The chain-side check rejected the update. Six new Agent Accounts were therefore created and deployed instead of bypassing owner authorization. All six report `matches_profile: true`.

The first publication attempt against the old Carrier stores was also rejected. Reusing an Agent ID with a fresh local authority journal attempted to reuse writer generation 1 with a different lease. The Carrier-side high-water fence correctly rejected that fork. The successful round used two new independent Carrier stores on ports 18291 and 18292. The old stores were neither reset nor deleted.

## Implementation exercised

The earning AI adapters now accept a hot-reloaded native `AgentContextSource`. The production earning CLI supplies `ContextBuilder.BuildSystemPromptWithCache` to:

- opportunity economic analysis;
- autonomous supply planning;
- first-contact drafting;
- bounded Agreement execution.

The campaign additionally supplied the same native context to buyer demand planning and bilateral negotiation. Because the context is read for every decision, an owner edit to `AGENT.md`, `SOUL.md`, `USER.md`, memory, or Skills becomes visible on the next call without restarting the earning worker.

Intent bodies remain untrusted data. Native workspace context does not bypass signature checks, Writer Fence, portfolio reservation, typed Agreement authorization, one-shot Execution Gate, custody policy, or payment finality verification.

## Important limitations

This round is not yet complete evidence for a fully natural-language-controlled business:

1. All six economic estimates used `bounded-owner-fallback`. Buyer demand selection and both sides of negotiation visibly used native workspace preferences, but the strict economic estimator did not return an accepted bounded estimate. The deterministic fallback still supplied the numeric execution estimate.
2. The campaign planner prompt said that buying nothing was valid, but its output schema required a seller. This run therefore did not exercise an explicit `SKIP`, `DECLINE`, or counter-offer terminal.
3. The signed price matched the target stated in `USER.md`, but the campaign harness also carried that exact amount into the signed Intent and Agreement. This does not yet prove AI-originated price discovery from natural language alone.
4. All counterparties were explicitly trusted local test peers and used direct payment. Unknown-peer escrow selection was not tested.
5. No AIPoW reward was requested for these direct-payment services; the prior campaign separately verified the native Task Escrow-to-AIPoW reward path.

The next acceptance round should remove the campaign economic fallback, permit an explicit no-action result, introduce below-floor and over-budget Intents, permit bounded counter-offers, and require at least one observed refusal before describing the earning loop as fully preference-driven.

## Post-round remediation

The first two limitations above were subsequently closed in code without rewriting the historical campaign evidence:

- `LLMEconomicEstimator` now requires an explicit `strategy_disposition` of `pursue` or `decline` plus a bounded `strategy_rationale`. The deterministic evaluator treats a strategy decline as an ineligible opportunity even when the numeric estimate is profitable.
- The campaign-specific `bounded-owner-fallback` was removed. Invalid, unavailable, or revenue-substituting AI output now fails closed and cannot create synthetic economic evidence or authorize work.
- The demand planner now has a strict `buy | skip` decision. A `skip` must contain no seller, capability, or task, is stored as `skipped:buyer-strategy` in the durable checkpoint, and performs no publication, contact, Agreement, execution, or payment.
- Parser and policy tests cover missing dispositions, profitable-but-unwanted opportunities, fallback rejection, valid no-action output, and hidden actions attached to `skip`.
- An opt-in test using the real local subscription backends passed: Codex produced an explicit no-action plan from an owner strategy, and Claude produced an explicit economic decline with signed evidence. The command was `OPENFOX_VERIFY_NATIVE_STRATEGY_AI=1 OPENFOX_SIX_AGENT_CAMPAIGN_ROOT=/home/tomi/.local/share/openfox-six-agent-native-strategy-20260828 go test ./pkg/earning -run '^TestRealNativeStrategyCanSkipAndDecline$' -count=1 -v -timeout=12m`.

The original six settled results still used the historical fallback and still do not constitute observed refusal evidence. A new market round is required before making the stronger empirical claim that a multi-Agent campaign exercised refusal and continued normally; the implementation path no longer forces a transaction while conducting that round.

## Evidence and validation

The evidence root is:

```text
/home/tomi/.local/share/openfox-six-agent-native-strategy-20260828
```

Important artifacts include:

- `reports/six-agent-autonomous-campaign-checkpoint.json`;
- `reports/six-agent-financial-summary.json`;
- `campaign/conversations/conversation-000.json` through `conversation-005.json`;
- `campaign/deliverables/`;
- `campaign/custody/`;
- each Agent's `workspace/AGENT.md`, `SOUL.md`, `USER.md`, `HEARTBEAT.md`, and `memory/MEMORY.md`.

Post-run validation passed:

- `go test ./pkg/earning ./cmd/openfox/internal/earning -count=1`;
- `go vet ./pkg/earning ./cmd/openfox/internal/earning`;
- `git diff --check`;
- six unique Agreement digests and six unique finalized payment transaction hashes;
- two independent Carrier stores containing the same six unique Intent digests;
- three-node equality for every final Agent Account balance.

The implementation and this report remain uncommitted at the end of the experiment.
