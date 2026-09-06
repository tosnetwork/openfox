# Eight-Agent Generic Intent Social-Earning Round 5 Report

Date: 2026-09-06

## Scope and evidence

This was a three-hour local, three-node TOS experiment of a generic Intent
marketplace. The eight independently configured OpenFox identities were
`cyberfox.tos`, `reviewfox.tos`, `clearfox.tos`, `btcfox.tos`, `usdtfox.tos`,
`scoutfox.tos`, `escrowfox.tos`, and `trustfox.tos`. Their roles covered source
audit, per-contract review, settlement evidence, BTC/USDT listing and
diligence, bulletin discovery, settlement routing, and counterparty risk.

The chain was freshly initialized for this run. Eight new Agent Accounts were
funded and deployed, two independent local carriers accepted the eight signed
supply Intents, and the campaign ran 24 scheduled demand-planning turns. The
machine-readable campaign checkpoint and node samples are owner-private runtime
evidence; this report records their observed aggregate facts rather than
claiming that prose is the source of truth.

## Result

The campaign completed successfully: 24 of 24 turns completed and the harness
reported `PASS`. Every turn selected `skipped:buyer-strategy`; there was no
settlement, payment, or fabricated execution.

This is a valid result, not an infrastructure failure. Each buyer reasoned
that the bulletin contained supply offers but no concrete work item, asset
counterparty, evidence bundle, contract, or settlement dispute which established
present business value. Several buyers also noted that an asking price exceeded
their owner-set loss limit. They treated a negotiable floor, relevance to a
future role, and a loss limit as insufficient grounds to create expenditure.

The experiment therefore demonstrates that generic signed Intent envelopes can
describe heterogeneous work without a per-market API and that the local owner
policy can decline ungrounded purchases. It does *not* demonstrate bilateral
negotiation, informal trusted settlement, on-chain contract settlement, or a
profitable marketplace: no concrete demand was published for an agent to buy.

One initial planning turn used the configured Claude provider before the run was
stopped and reconfigured after the provider mismatch was noticed. The persisted
24-turn checkpoint then resumed under Codex-backed templates. This is recorded
because model provenance matters when interpreting qualitative rationales.

## Node observations

The monitor took 415 samples. All three nodes repeatedly converged to the same
masterchain height and root. 69 samples observed a one-block difference while
the three HTTP requests were collected sequentially; those are sampling-time
lags, not evidence of a persistent fork, and are intentionally not described as
per-sample equality.

Validator RSS varied rather than rising monotonically: node-one ranged from
183,272 to 579,460 KiB, node-two from 183,712 to 578,716 KiB, and node-three
from 172,000 to 553,504 KiB. A three-hour fluctuating sample is not evidence
either for or against a long-horizon anonymous-memory leak. The fresh node data
directories occupied roughly 5.5 GiB after the run, including bounded session
logs and local archives.

## First-principles follow-up

The next experiment should add signed, bounded demand Intents before opening
the market: for example, a real code-review artifact with an acceptance
criterion, a settlement-evidence request tied to a prior simulated OTC
agreement, or a counterparty-screening request tied to a concrete listing.
Each must make the exact deliverable, maximum loss, expiry, acceptance evidence,
and chosen trust rail explicit. Then a decline remains meaningful, but a buyer
also has a non-fictional path to contact the issuer, negotiate within its bounds,
and choose either informal settlement or the on-chain rail.

Do not solve the absence of demand by adding domain-specific transport APIs or
by instructing an Agent to buy. The missing input is an economically meaningful
demand object, not another endpoint; the generic Intent envelope is already the
right boundary for BTC/USDT quotations, services, and evidence work.
