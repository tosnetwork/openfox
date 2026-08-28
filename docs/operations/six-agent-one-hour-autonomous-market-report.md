# Six-OpenFox One-Hour Autonomous Market Campaign

## Executive summary

Six isolated OpenFox runtime identities operated a closed local Agent market for exactly one wall-clock hour on 28 August 2026. They generated 18 demands, discovered them through two independently stored Carriers, formed 18 typed Agreements, produced 18 accepted deliverables, and finalized 18 distinct payments through three local TOS validators.

The campaign demonstrates an end-to-end bounded autonomous commerce loop, but it does **not** yet demonstrate unconstrained autonomous business or external profit. Buyer-side demand selection and task authorship were AI-driven. Seller execution was AI-driven. Seller economic admission invoked the AI estimator, but all 18 estimates fell back to deterministic owner-bounded pricing because the model output did not satisfy the exact numeric policy contract. The market was also a closed economy funded by pre-existing local test accounts.

## Run identity and topology

| Item | Observed value |
|---|---|
| Campaign schema | `tos.openfox.six-agent-autonomous-market-campaign.v1` |
| Network | `tos:local-three-node`, global ID `3`, workchain `0` |
| Start | `2026-08-28T01:00:43.488689754Z` |
| End | `2026-08-28T02:00:43.577462519Z` |
| Requested duration | 3,600 seconds |
| Active OpenFox identities | 6 |
| Market turns | 18, paced across three rounds |
| Discovery | Gateway Carrier and Messenger Carrier, with separate state stores |
| Settlement | Direct TOS Agent Account transfer with two-of-three minimum finality quorum |
| AI backend used in the accepted run | Codex subscription backend for all six runtimes |
| Evolution mode | `draft`; learned capability candidates were never installed automatically |

The six identities had separate Agent IDs, Ed25519 identity and economic-authority keys, wallets, publication journals, portfolio ledgers, execution gates, workspaces, and evolution state. They ran as isolated logical OpenFox runtimes in one campaign process, so process-level fault isolation was not tested.

The intended three-Claude/three-Codex split could not be used because the local Claude Code session returned `401 OAuth access token has expired`. Claude's local status command still reported a logged-in Max account, but actual inference failed. The campaign therefore failed closed and explicitly switched all six fresh configurations to the authenticated Codex subscription backend. No Claude result is included in the accepted campaign evidence.

## Roles

| OpenFox | Owner-bounded capability | Market behavior |
|---|---|---|
| Security Auditor | `secure-code-review` | Bought implementation and evidence work; sold five bounded audits |
| Software Builder | `bounded-code-implementation` | Bought three audits; sold seven implementations |
| Evidence Verifier | `release-evidence-verification` | Bought storage and implementation work; sold five verification reports |
| Storage Provider | `content-retention` | Bought three verification reports; sold one retention-design engagement |
| Transaction Operator | `transaction-reliability` | Bought three retry/idempotency implementations; received no demand for its own service |
| Guarantor Analyst | `agreement-risk-analysis` | Bought three security/evidence engagements; received no demand for its own service |

Every identity acted as a buyer three times. Four identities also earned revenue as sellers. Seller selection was not round-robin: for each turn the buyer AI selected one of the five other advertised capabilities and authored the full bounded task.

## Verified outcomes

| Measure | Result |
|---|---:|
| AI-authored demand Intents | 18 |
| Unique Intent digests | 18 |
| Demands discovered through both Carriers | 18 |
| Unique Agreement digests | 18 |
| Accepted deliverables | 18 |
| Settled obligations | 18 |
| Unique payment transaction references | 18 |
| Custody tombstones in `resolved` state | 18 |
| Finality observations at 3/3 | 13 |
| Finality observations at 2/3 | 5 |
| Declines | 0 |
| Duplicate payments observed | 0 |
| Average AI execution time | 80.094 seconds |
| Average settlement time | 2.347 seconds |

After the campaign, all three validators reported `ready=true`, zero sync lag, and the same masterchain block at sequence `30334`, with the same root and file hashes.

The two Carrier stores each retained all official demands. They also retained one additional preflight demand described under incidents; this append-only residue was not counted as a settled campaign result.

## Trade flow

| # | Buyer | Seller | Bounded work selected by the buyer AI | Price (nanoTOS) |
|---:|---|---|---|---:|
| 1 | Security Auditor | Software Builder | Stable identity package for security findings | 750,000 |
| 2 | Software Builder | Security Auditor | Transaction-relayer envelope security audit | 500,000 |
| 3 | Evidence Verifier | Storage Provider | Deterministic retention receipt schema | 250,000 |
| 4 | Storage Provider | Evidence Verifier | Retention-proof claim verification | 300,000 |
| 5 | Transaction Operator | Software Builder | Ambiguous transaction retry classifier | 750,000 |
| 6 | Guarantor Analyst | Security Auditor | Guarantee verdict state-machine audit | 500,000 |
| 7 | Security Auditor | Evidence Verifier | Audit release-evidence verification | 300,000 |
| 8 | Software Builder | Security Auditor | Build handoff and artifact-substitution audit | 500,000 |
| 9 | Evidence Verifier | Software Builder | Release manifest verifier | 750,000 |
| 10 | Storage Provider | Evidence Verifier | Retention claim evidence verification | 300,000 |
| 11 | Transaction Operator | Software Builder | Quorum-aware retry classifier | 750,000 |
| 12 | Guarantor Analyst | Security Auditor | Guarantee release-path audit | 500,000 |
| 13 | Security Auditor | Software Builder | Finding identity package with revised invariants | 750,000 |
| 14 | Software Builder | Security Auditor | Relayer implementation audit | 500,000 |
| 15 | Evidence Verifier | Software Builder | Strict release-evidence verifier | 750,000 |
| 16 | Storage Provider | Evidence Verifier | Three-node retention receipt verification | 300,000 |
| 17 | Transaction Operator | Software Builder | Duplicate-transfer-safe retry classifier | 750,000 |
| 18 | Guarantor Analyst | Evidence Verifier | Agreement settlement-evidence verification | 300,000 |

The demands were not copied from the seed catalog. The owner supplied the capability catalog, price ceilings, example scopes, and safety policy; the buyer AI selected the counterparty and generated the task. Model output could not publish, sign, execute, or pay directly. Those effects remained behind typed OpenFox authorities and gates.

## Financial report

| OpenFox | Jobs sold | Jobs bought | Gross revenue | Spend | Maximum internal cost | Transfer net | Projected net |
|---|---:|---:|---:|---:|---:|---:|---:|
| Security Auditor | 5 | 3 | 2,500,000 | 1,800,000 | 400,000 | 700,000 | 300,000 |
| Software Builder | 7 | 3 | 5,250,000 | 1,500,000 | 1,050,000 | 3,750,000 | 2,700,000 |
| Evidence Verifier | 5 | 3 | 1,500,000 | 1,750,000 | 250,000 | -250,000 | -500,000 |
| Storage Provider | 1 | 3 | 250,000 | 900,000 | 40,000 | -650,000 | -690,000 |
| Transaction Operator | 0 | 3 | 0 | 2,250,000 | 0 | -2,250,000 | -2,250,000 |
| Guarantor Analyst | 0 | 3 | 0 | 1,300,000 | 0 | -1,300,000 | -1,300,000 |
| **Aggregate** | **18** | **18** | **9,500,000** | **9,500,000** | **1,740,000** | **0** | **-1,740,000** |

All amounts are nanoTOS. Gross service revenue is the sum of internal transfers, not new wealth. The closed market's transfer net is zero; after the configured maximum internal costs, projected aggregate net is negative 1,740,000 nanoTOS. The campaign therefore proves earning and settlement mechanics, not profitable external demand acquisition.

Demand concentrated on implementation, security, and evidence services. The Transaction Operator and Guarantor Analyst were active customers but earned no revenue. A real autonomous operator needs a service-publication/pricing feedback loop that can revise offers or acquire reviewed capabilities when demand remains absent; this campaign deliberately kept such changes in draft mode.

## Learning and bounded evolution

Successful seller executions produced task records for the active supply roles. Three candidate skill drafts were generated:

- `reusable-earning-capability-secure-code`
- `reusable-earning-capability-bounded-code`
- `reusable-earning-capability-release-evidence`

Each remained in `candidate` state. No workspace skill was installed, no permission was expanded, and no new capability was published from a learning draft. Storage had only one completed sale, below the configured two-task learning threshold. The two roles with no sales had no execution evidence from which to learn.

This is the intended meaning of self-improvement in the current safety model: verified outcomes may produce reviewable drafts, but model output alone cannot mutate trusted skills or economic authority.

## Incidents and fail-closed behavior

Three preflight attempts were excluded from the accepted one-hour window:

1. Missing zero-state and workchain identity variables stopped runtime construction before market effects.
2. Claude Code returned an expired OAuth-token error during the first demand plan; no Intent was published.
3. A first AI demand, Agreement, and deliverable were created, but payment was blocked because the development-build `tosctl` path had group-writable ancestors and was therefore untrusted by the custody adapter. The accepted run used the owner-private executable at `/home/tomi/openfox-campaign-secure-bin/tosctl`, SHA-256 `84946bfacfb4f65c6ec34047bd949e739e9eae288f941dbbe4ccfe969c7ff8a0`.

The third preflight left one append-only Intent and one content-addressed deliverable, but no transfer. This is useful negative evidence: failure after delivery needs an explicit Operation/Outcome record and a deterministic cancellation or write-off path; counting only settled jobs hides this economic attempt.

## User experience findings

What felt convincing:

- Generic Intent organization was sufficient. New task types emerged without adding industry-specific protocol interfaces.
- Agents naturally became both customers and suppliers, and later demands built on earlier market themes.
- Two-stage discovery kept the signed summary bounded while allowing detailed task bodies.
- Typed Agreement, execution, custody, and finality gates repeatedly stopped misconfiguration before value transfer.
- Settlement was fast relative to AI execution: about 2.35 seconds versus 80.09 seconds on average.

What still felt mechanical or incomplete:

- All six runtimes shared one process and one host.
- There was no free-form group chat. Interaction occurred through Intent publication, discovery, Agreement, delivery, learning records, and payment.
- All accepted seller decisions used `bounded-owner-fallback`; the AI economic estimator did not produce policy-valid exact numeric estimates. Full autonomous profitability judgment is therefore not yet demonstrated.
- Buyer selection favored three service categories. Two advertised capabilities received no demand, and no pricing or capability pivot was applied during the hour.
- The intended Claude/Codex heterogeneous run was reduced to Codex-only because the Claude subscription credential required interactive reauthentication.
- The campaign used local test-chain funds and generated no revenue from an external customer.

## Conclusion

The campaign proves that six OpenFox identities can autonomously author needs, locate counterparties through decentralized Carriers, form generic Agreements, execute bounded AI work, and earn or spend through TOS Agent Accounts for one continuous hour. It also demonstrates that the protocol does not need a hard-coded workflow for every service category.

The stronger claim, “OpenFox independently finds externally profitable work and continuously evolves into a better business,” remains **partially achieved**. The next acceptance campaign should require policy-valid AI economic estimates without fallback, at least one safe decline, heterogeneous authenticated AI backends, separate OpenFox processes or hosts, controlled activation of one reviewed skill draft, and at least one demand originating outside the closed test economy.

## Evidence locations

- Campaign checkpoint: `/home/tomi/.local/share/openfox-six-agent-market-20260828/reports/six-agent-autonomous-campaign-checkpoint.json`
- Financial summary: `/home/tomi/.local/share/openfox-six-agent-market-20260828/reports/six-agent-financial-summary.json`
- Carrier stores: `/home/tomi/.local/share/openfox-six-agent-market-20260828/carriers/`
- Custody tombstones: `/home/tomi/.local/share/openfox-six-agent-market-20260828/campaign/custody/`
- Execution gates and deliverables: `/home/tomi/.local/share/openfox-six-agent-market-20260828/campaign/`
- Evolution records: `/home/tomi/.local/share/openfox-six-agent-market-20260828/agents/*/state/evolution/`
