# Six-Agent Autonomous Market and AIPoW Reward Campaign

## Executive result

The campaign passed its primary acceptance target: six isolated OpenFox agents traded for more than one wall-clock hour, completed 30 independently selected service engagements, exchanged 90 signed negotiation messages, learned three reusable skills, and drove one seller through the complete AIPoW path from eligible work to a reward credited to an OpenFox-controlled Agent Account.

This was a local closed economy, not evidence of external profit. Service payments circulated among locally funded agents. The AIPoW reward was native issuance on the local three-validator network.

| Acceptance condition | Result |
| --- | --- |
| Three-validator TOS network | Pass |
| AIPoW enabled before market work | Pass |
| Two independent Carrier implementations | Pass |
| Six isolated OpenFox identities | Pass |
| Mixed local subscription-backed AI cores | Pass: three Codex app-server agents and three Claude one-shot agents |
| At least one wall-clock hour | Pass: `2026-08-28T04:09:59Z` through `2026-08-28T06:23:09Z` |
| Multiple rounds of autonomous demand selection | Pass: five rounds, 30 terminal engagements |
| Signed bilateral conversation | Pass: 90 messages across 30 transcripts |
| Unique typed Agreements and payments | Pass: 30 Agreements and 30 finalized payment transactions |
| Bounded learning | Pass: three reusable skills; no authority expansion |
| Eligible AIPoW work indexed | Pass: two settled Task Escrows from distinct payers |
| Native AIPoW mint | Pass: 40,000,000 nanotos |
| Reward claim credited to OpenFox | Pass: 10,000,000 nanotos immediate tranche |

## Test topology

The run used the following fixed source revisions. The campaign harness and local-network launcher had uncommitted test-only changes described below.

| Component | Revision | Function |
| --- | --- | --- |
| `openfox` | `18a9e867628a` | Agent planning, discovery, negotiation, Agreement, execution, payment, learning, and reporting |
| `tos` | `337417210411` | Three validators, custody CLI, Task Escrow, AIPoW commitment, settlement, distributor, and claim |
| `tos-service-gateway` | `10afba034adc` | Gateway Carrier on `127.0.0.1:18191` |
| `tos-messenger` | `f7abfb1e701a` | Messenger Carrier on `127.0.0.1:18192` |
| `aipow-scorer` | `bc517d3ff0da` | Epoch scoring and signed score-root commitment |

Validator RPC endpoints were `127.0.0.1:19661`, `:19662`, and `:19663`. The chain index and AIPoW work API ran on `127.0.0.1:19670`.

The six roles and AI boundaries were:

| Agent | Primary capability | AI backend |
| --- | --- | --- |
| Security Auditor | `secure-code-review` | Claude CLI, one-shot |
| Software Builder | `bounded-code-implementation` | Codex app-server |
| Evidence Verifier | `release-evidence-verification` | Codex app-server |
| Storage Provider | `content-retention` | Claude CLI, one-shot |
| Transaction Operator | `transaction-operation` | Codex app-server |
| Guarantor Analyst | `agreement-risk-analysis` | Claude CLI, one-shot |

Every backend was subscription-backed, read-only, single-call bounded, and configured without native tools or network authority. AI output could propose demand, scope, prices within owner-fixed bounds, and deliverable text. It could not create protocol authorization or initiate custody effects.

## Market results

All 30 terminal engagements settled. No buyer rejected a quote, so this campaign did not exercise an economic or negotiation decline terminal. Each engagement was independently visible through both configured Carriers.

| Metric | Result |
| --- | ---: |
| Settled engagements | 30 |
| Declined engagements | 0 |
| Signed messages | 90 |
| Unique conversation digests | 30 |
| Unique Agreement digests | 30 |
| Unique payment transactions | 30 |
| Service volume | 15,600,000 nanotos |
| Maximum modeled internal cost | 2,780,000 nanotos |
| Closed-economy projected net | -2,780,000 nanotos |
| Average execution latency | 78,352 ms |
| Execution latency range | 8,658–193,741 ms |
| Average settlement latency | 2,242 ms |
| Settlement latency range | 1,979–2,357 ms |

The aggregate transfer net is zero because every service payment is another local agent's spend. The negative projected net is the modeled internal cost of producing the services.

### Per-agent financial report

| Agent | Sold | Bought | Revenue | Spend | Maximum internal cost | Projected net |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Security Auditor | 13 | 5 | 0.006500 TOS | 0.002850 TOS | 0.001040 TOS | 0.002610 TOS |
| Software Builder | 9 | 5 | 0.006750 TOS | 0.002500 TOS | 0.001350 TOS | 0.002900 TOS |
| Evidence Verifier | 7 | 5 | 0.002100 TOS | 0.002500 TOS | 0.000350 TOS | -0.000750 TOS |
| Storage Provider | 1 | 5 | 0.000250 TOS | 0.001950 TOS | 0.000040 TOS | -0.001740 TOS |
| Transaction Operator | 0 | 5 | 0 TOS | 0.003500 TOS | 0 TOS | -0.003500 TOS |
| Guarantor Analyst | 0 | 5 | 0 TOS | 0.002300 TOS | 0 TOS | -0.002300 TOS |

The market was concentrated. Security Auditor and Software Builder earned 84.9 percent of service revenue. Transaction Operator and Guarantor Analyst acted only as buyers in this sample. A larger public market needs more substitutable suppliers before these prices can be interpreted as competitive.

### Emergent supply chains

The harness bounded available capabilities and prices but did not prescribe the counterparty for a turn. Buyer AI selected sellers and authored the detailed task.

- Storage Provider repeatedly bought Evidence Verifier work. Its demand evolved from a generic retention receipt to exact CID, replica-independence, challenge-freshness, byte-range, and sampling-coverage checks.
- Transaction Operator repeatedly bought Software Builder retry/finality classifiers and also bought one independent Security Auditor review.
- Guarantor Analyst repeatedly bought Security Auditor state-machine reviews and bought Evidence Verifier work for one settlement claim used as a guarantee input.
- Security Auditor and Evidence Verifier purchased work from each other. Each role therefore subjected its own output pipeline to an independent specialist.
- Software Builder repeatedly purchased Security Auditor reviews of authorization, replay, idempotency, and bounded execution.

This supports the generic Intent design: the business meaning lived in signed cards, details, negotiation, and Agreement terms. No new opcode or industry-specific state machine was needed for each service variation.

## Conversation behavior

Each engagement produced exactly three signed messages:

1. buyer request;
2. seller scope, assumptions, exclusions, and exact quote;
3. buyer accept or decline rationale.

The transcript explicitly records `agreement_authority: false`. Sellers regularly stated that a quote was not an Agreement and that they had no authority to execute or collect payment. Buyers stated that acceptance remained contingent on a later typed Agreement. This is useful evidence that richer natural-language interaction can coexist with a strict authorization boundary.

There was no free-form group chat in this campaign. The 90 messages were bilateral commercial conversations. Future social testing should add an explicitly non-authoritative group channel if the goal is to observe broader discussion of TOS Network rather than task negotiation.

## Bounded learning

Three agents created one reusable skill each after successful public, reusable-learning work:

| Agent | Learned skill |
| --- | --- |
| Security Auditor | `reusable-earning-capability-secure-code` |
| Software Builder | `reusable-earning-capability-bounded-code` |
| Evidence Verifier | `reusable-earning-capability-release-evidence` |

Later similar tasks reused the ready pattern instead of generating an unbounded number of duplicate skills. The generated skills contain generic procedure summaries only; they do not contain counterparties, payment data, credentials, private inputs, or new execution authority.

The current generated skill text is still shallow: it records a reusable workflow and validated examples but does not yet synthesize detailed domain procedures. This is safe, but its productivity value should be measured separately.

## AIPoW reward proof

The campaign direct-payment transactions were not treated as AIPoW-eligible work. Two separate, bounded follow-up verification jobs were placed in native Task Escrow so the scorer received the exact evidence profile it supports. They were not duplicate payment for the original services.

| Task | Payer | Earner | Settled value | Evidence |
| --- | --- | --- | ---: | --- |
| `0:483e…1d97` | Security buyer wallet `0:c6aa…d889` | Evidence Verifier identity `54549d…dbc1` | 20,000,000 nanotos | `Observed` |
| `0:7bb7…aff4` | Software buyer wallet `0:c384…2ad9` | Evidence Verifier identity `54549d…dbc1` | 30,000,000 nanotos | `Observed` |

The two payers are distinct. The scorer produced:

| Field | Value |
| --- | --- |
| Epoch | `27281` |
| Score root | `a928eba457d63aec91eb86e58161bfc7f7476b5cca161c14a4a667ce81014c21` |
| Earner score | `50,000,000` |
| Methodology organic settled value | `40,000,000` nanotos |
| Final commitment | `-1:8e5c520cef58cbf9801672d22125a3ce3999269bb6c76c9b398bfc0b0220c620` |
| Settlement | `-1:0cc20354ca03db51278ba39b02c4dfde38155089d6386b3bd6b6b1122a8e06c2` |
| Settlement cursor | `27282` |
| Native minted total | `40,000,000` nanotos |
| Distributor | `-1:ba468c4b726434d9d7735fedbe7e475abde6cf8d7265b30766304932aae90fbf` |
| Claim count | `1` |
| Claimed score | `50,000,000` |
| Reward allocation | `40,000,000` nanotos |
| Immediate matured tranche | `10,000,000` nanotos |

The local Settlement was originally bootstrapped with `earner_workchain=-1`, while the trading Agent Account was in workchain `0`. The Distributor therefore paid the immediate tranche to `-1:54549d…dbc1`. The same Evidence Verifier owner/controller StateInit was deployed at that address using a separate reward profile. `tosctl agent account status` then reported:

- state: `active`;
- balance: `0.41 TOS`;
- `template_matches: true`;
- `matches_profile: true`;
- the same owner, controller public key, and deployment ID as the Evidence Verifier profile.

The account received 0.40 TOS of explicit activation funding across two deployment attempts and retained the separately observed 0.01 TOS AIPoW payment. All three validator RPCs returned the same `0.41 TOS` balance, state, last transaction LT, and last transaction hash.

The local-network launcher now accepts `TOS_AIPOW_EARNER_WORKCHAIN` and rejects values other than `-1` and `0`. Future OpenFox local campaigns should boot with `TOS_AIPOW_EARNER_WORKCHAIN=0`, allowing the existing trading Agent Account to receive the reward directly.

## Safety and recovery findings

Two late-run failures were fail-closed and produced no unauthorized payment:

1. The five-round campaign exceeded a test-only shortlist limit of four opportunities per issuer. Both Carriers contained the correct signed Intent, but local policy excluded the fifth same-issuer opportunity. The campaign-specific bound was raised to eight while the overall shortlist remained 16.
2. Long model latency placed a late task roughly 52 minutes behind its planned schedule. The harness used the planned timestamp for a 50-minute billing expiry, so billing authorization correctly failed after delivery. Recovery now uses the later of scheduled time and actual start time and creates a newly authorized Agreement instead of mutating or extending the expired body.

Three deliverable blobs were produced by aborted, unpaid attempts and are not referenced by any terminal campaign result. They remain evidence of the failed attempts and must not be counted as revenue.

One initial AIPoW claim carrying the CLI's default 0.1 TOS did not change distributor claim state; a retry carrying 1 TOS succeeded. This suggests that the CLI's displayed minimum/default does not provide adequate reserve headroom under this local storage-price configuration. The claim command should preflight or estimate the required reserve instead of presenting 0.1 TOS as generally sufficient.

## User-experience assessment

What felt good:

- Buyer agents authored precise scopes and seller agents replied with useful assumptions, exclusions, and exact prices.
- Typed authorization kept fluent chat from becoming authority.
- Two independent discovery paths were observable in every completed engagement.
- Chain settlement was fast and consistent compared with model execution.
- Restart from a durable checkpoint preserved completed work.
- AIPoW produced an actual native reward, not just an off-chain score.

What needs improvement:

- Complex model work dominated latency. Quotes should expose expected delivery time and congestion risk.
- The campaign's economic estimator used `bounded-owner-fallback` for all 30 decisions. Buyer AI selected demand and counterparty, but fixed owner prices and fallback economics mean this is not evidence of fully autonomous dynamic pricing.
- The market was supplier-concentrated and produced no declines, disputes, cancellations, or quality rejection.
- Skill synthesis was safe but shallow.
- AIPoW workchain configuration must match the Agent identity domain before an epoch starts.
- AIPoW claim funding needs a deterministic preflight.
- Group discussion requires a separate non-authoritative social scenario; bilateral negotiation alone does not test community discourse.

## Evidence locations

The local evidence root is:

```text
/home/tomi/.local/share/openfox-six-agent-aipow-20260828
```

Important artifacts include:

- `reports/six-agent-autonomous-campaign-checkpoint.json`
- `reports/six-agent-financial-summary.json`
- `campaign/conversations/conversation-000.json` through `conversation-029.json`
- `campaign/deliverables/`
- `campaign/payment-evidence/`
- `aipow/scorer/aipow-commitment-epoch-27281.json`
- `aipow/scorer/score-entries-27281.json`
- `chain-control/tosctl-aipow-reward-deploy.json`

## Conclusion

The local system demonstrated a real autonomous service loop: discover through two non-authoritative Carriers, analyze, negotiate in signed natural language, promote to a typed Agreement, execute with restricted AI, deliver, settle, learn a bounded skill, index eligible work, mint an AIPoW pool, and credit a reward to an OpenFox-controlled Agent Account.

It does not yet demonstrate external profitability, open-market price discovery, adversarial dispute handling, or broad social coordination. Those should be the next campaign's explicit acceptance targets.
