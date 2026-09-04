# Eight-Agent Concurrent Market and Bilateral Wager Report

This report records a run executed on 2026-09-04 against a freshly redeployed
three-node local validator network. It covers two experiments that shared the
same eight OpenFox identities and the same chain:

1. a concurrent, two-sided generic-intent market, and
2. a bilateral wager market in which Agent Accounts opened, accepted, reported
   and settled wagers against each other with no human step in the loop.

The chain-level results passed without qualification. The market-level result is
dominated by a single structural finding: **82% of all opportunities were
skipped because one purchase permanently exhausts a buyer's loss budget.** That
finding is the substance of this report; the settled trades are the smaller part
of what was learned.

## Result boundary

| Layer | Result | Meaning |
|---|---|---|
| Three-node consistency | PASS | Every sampled height returned an identical block hash on all three nodes. Zero divergence across the whole run. |
| Wager settlement | PASS | 63 wagers settled; escrow drained to zero in every one. |
| Autonomous wager lifecycle | PASS | `create` / `accept` / `result` / `settle` were all issued by Agent Account controller actions. No human step. |
| Losing-side payout (`payout=0`) | PASS | First run to reach this path. Verified from decoded escrow out-messages, not from balance deltas. |
| Two-sided stakes | PASS | Both parties fund the pot and the winner takes it; the round aborts if the pot is not fully funded. |
| Fair subject | PASS | Block-hash parity resolves near 50/50 where the block-count subject could not. |
| Verifier-less `timeout` auto-payout | PASS | Rejected inside the challenge window, paid the agent after expiry. |
| Agent's stake under an idle verifier | **FAIL** | With a verifier set and a correct result submitted, an idle adjudicator lets the creator take the whole pot at timeout. Measured. |
| Attestor signature gate | PASS | Unsigned, wrongly-signed, and rotate-then-settle attempts were all rejected; only the true attestor signature settled. |
| Agent protection without an attestor | **FAIL** | The creator settled `payout=0` on delivered work, and the agent's `dispute` was rejected — `dispute` is creator-only. |
| Validator memory | PASS | 388–540 MB per node over 9,058 s. Oscillating, no monotonic growth. |
| Market throughput | **FAIL** | 8 settlements out of 49 opportunities. 40 skipped on buyer portfolio capacity. |
| Price formation | **FAIL as a market** | The settlement price equalled the buyer's budget ceiling in 8 of 8 negotiations. The seller's floor never bound. |
| Concurrent Agent Account use | CONSTRAINT | An Agent Account serialises differing controller actions until finality is observed. Deliberate race protection, not a defect; the harness lost 2 of 8 rounds by not retrying. |
| External profitability | NOT ESTABLISHED | All volume circulated inside the same eight-agent perimeter. |
| Open-market or decentralization claim | NOT ESTABLISHED | Agents, wallets, and three validators all ran on one host. |

## Run identity

| Item | Observed value |
|---|---|
| Chain | three local validators, redeployed clean for this run |
| Validator uptime at report time | 9,058 s |
| Masterchain height at report time | 21,304 |
| Agents | 8, each with its own `.tos` identity and Agent Account (v3 template) |
| Market opportunities evaluated | 49 |
| Market settlements | 8 |
| Wagers settled | 63 (40 pipeline-validation + 23 genuinely uncertain) |

### Agent roster

| Agent | Offered capability |
|---|---|
| security-auditor | institutional-source-audit |
| software-builder | per-contract-review-piecework |
| evidence-verifier | settlement-evidence-clerking |
| storage-provider | otc-btc-listing-and-settlement-plan |
| data-curator | otc-usdt-quote-and-diligence |
| localization-writer | bulletin-intent-scouting |
| transaction-operator | trust-tier-and-settlement-routing |
| guarantor-analyst | counterparty-history-assessment |

All eight acted as both buyer and seller. All eight served as wager creator.

## What the agents actually did

The negotiations are real, not scripted. A representative exchange: the seller
quoted 2.4 TOS against a private floor of 0.9, the buyer countered at 2.1, and
the seller accepted — with both sides restating the bounded scope in their own
words and naming the boundary at which a second unit would be required.

One agent **declined** a deal on the stated ground that the opportunity
conflicted with its own natural-language strategy, and the same counterparty
pair later closed at 2.0 TOS. A refusal is a decision, not a fault; it is
recorded here as evidence that the decision layer is live.

## Finding 1 — one purchase permanently exhausts the buyer's loss budget

40 of 49 opportunities ended as `skipped:buyer-portfolio-capacity`. The cause is
mechanical and is visible in the persisted authority documents.

`MaximumLoss` serves two roles at once. It bounds what a buyer will commit to a
single engagement, and it bounds the sum across every live engagement. The
per-engagement budget is:

    buyerBudget = seller asking price
    if buyer.MaximumLoss > 0 && buyer.MaximumLoss < buyerBudget { buyerBudget = buyer.MaximumLoss }

Every seller in this profile asks at or above every buyer's ceiling, so the
budget collapses onto the ceiling, the settled amount equals the budget, and the
reservation equals the settled amount. **The first settled purchase therefore
consumes 100% of the aggregate ceiling** — not because the reservation is
mis-sized, but because one number is doing two jobs.

Parameters alone cannot fix it. A buyer's cap may not exceed its own asking
price, so holding *k* engagements requires `own_ask >= own_cap >= k * peer_ask`;
in a closed set of agents the cheapest one can never be *k* times cheaper than
itself. The two roles need separate numbers.

Observed state after one purchase each:

| Agent | Loss limit | Buy reservation | Sell reservation |
|---|---|---|---|
| security-auditor | 2.2 TOS | 2.2 TOS, `released: false` | 2.1 TOS, `released: true` |
| software-builder | 2.0 TOS | 2.0 TOS, `released: false` | 1.9 TOS, `released: true` |
| data-curator | 1.9 TOS | 1.9 TOS, `released: false` | 2.0 TOS, `released: true` |

### The hold is held on purpose — do not "fix" it by releasing early

An earlier draft of this report claimed the buy side had no release step. That
is wrong, and the correction matters more than the original claim.

`ReconcileApply` does release buyer reservations once an engagement is terminal.
It refuses while the payment authorisation is live, and says why:

    // Settlement may be recorded, but caller-provided terminal evidence
    // cannot release an offline bearer. Authority time-based cleanup will
    // free the exact hold only after the signed payment validity ends.

and the expiry path states the rule outright: *"caller-provided settlement
outcomes cannot accelerate it."* A signed payment is an **offline bearer
instrument**. Observing one on-chain settlement does not prove the instrument
cannot be presented again, so the exposure is held for the full signed horizon —
`max(payment expiry, authorisation expiry, every local outgoing obligation's
expiry) + finality grace`. In this profile the pay obligation runs 50 minutes,
which is the hour-long hold that was measured.

Releasing on settlement evidence would therefore be a security regression, not a
fix. The hold duration is correct; what was wrong was committing the entire
ceiling to one engagement.

### The fix that was applied

`MaximumSpendPerTrade` now bounds a single engagement, separately from
`MaximumLoss` bounding their sum. It defaults to zero, which preserves the old
behaviour for every profile that does not set it; the marketplace profile sets
it to a third of the ceiling, so a buyer can hold three engagements at once.

A regression test pins the property and fails on the old parameters for all
eight agents (`can hold 1 concurrent engagements`).

One thing remains worth doing and was not done: the capacity refusal is still a
silent `skipped:buyer-portfolio-capacity`, which reads as "no counterparty
wanted this" rather than "this agent is out of capacity". A configuration in
which one admissible trade can consume the whole ceiling should fail loudly at
setup instead.

## Finding 2 — the settlement price is always the buyer's budget ceiling

In 8 of 8 negotiations the settled amount equalled the buyer's budget exactly.

| Ask | Seller floor | Buyer budget | Settled | Seller surplus |
|---|---|---|---|---|
| 2.40 | 0.90 | 2.10 | 2.10 | +1.20 |
| 2.20 | 0.80 | 1.90 | 1.90 | +1.10 |
| 1.90 | 0.60 | 1.90 | 1.90 | +1.30 |
| 2.20 | 0.90 | 1.80 | 1.80 | +0.90 |
| 2.20 | 0.80 | 1.70 | 1.70 | +0.90 |
| 2.10 | 0.70 | 2.00 | 2.00 | +1.30 |
| 2.20 | 0.80 | 2.00 | 2.00 | +1.20 |
| 2.20 | 0.80 | 2.20 | 2.20 | +1.40 |

The seller's floor never bound in any round. The buyer counters at its budget,
the seller accepts anything above its floor, and the entire surplus — 0.9 to 1.4
TOS per trade — accrues to the seller. The buyer's private willingness to pay is
fully revealed and fully extracted.

**This is what makes Finding 1 fatal rather than merely inefficient.** Because
the buyer always pays its ceiling, and the reservation is sized at the ceiling,
every trade is guaranteed to be the last one that buyer can make. Fixing either
half alone leaves the market largely stalled; the two must be read together.

## Finding 3 — an Agent Account admits only one in-flight controller action

Running two wager batches concurrently produced:

    another primary controller action already owns this Agent Account sequence

whenever both batches selected the same Agent Account as creator. The whole
round was lost — 2 of 8 in the affected window.

Read from the custody journal, the rule is narrower than the message suggests. A
new action is refused when an earlier record for the same generation has not yet
reached `Resolved`, and a record reaches `Resolved` only once finalized on-chain
state has consumed that exact custody sequence. Two consequences follow:

- **Retrying the identical action is safe.** A claim matching an existing record
  with the same economic authorization returns that record instead of failing.
  Only a *different* action is refused.
- **The blocking window is issuance until observed finality**, not the whole
  lifetime of the work.

This is a deliberate safety property, not an oversight: it is what stops two
actions from racing for the same sequence number, and the alternative — letting
them through — would be considerably worse. Recorded here as an operating
constraint rather than a defect.

The practical consequence stands: an Agent Account is effectively
single-threaded across finality windows, so an economic model in which one agent
participates in several markets simultaneously must either serialise per account
or carry retry-with-backoff. A harness that treats the refusal as a lost round,
as this one did, will silently under-count throughput.

## Bilateral wager market

Wagers were expressed as Task Escrows: the creator funds, the counterparty
accepts, an attestor reports the outcome with an evidence hash, and settlement
pays either the full stake or nothing.

**Correction to the framing.** In every batch above, only the creator funded the
escrow; the counterparty paid gas alone. Winning paid it the stake, losing cost
it nothing. That is a free option, not a wager, and the batches should be read
as tests of the settlement pipeline rather than as a two-sided market. A genuine
bilateral wager is described under "Symmetric stakes" below.

**Question wagered:** whether the masterchain would produce at least N blocks in
the W seconds following acceptance. **Adjudicator:** a third Agent Account
acting as verifier, which reads the height from the same three RPC nodes and
submits a result hash plus an evidence hash binding the observed seqnos.

| Batch | Rounds | Threshold (blocks / 30 s) | Outcome |
|---|---|---|---|
| 1 | 40 | far below reachable rate | YES 40 / NO 0 |
| 2 | 49 | 62, the distribution's mode | YES 41 / NO 8 |
| 3 | 37 | 63, one above the mode | YES 5 / NO 32 |
| 4 | 29 | 64, above the whole distribution | YES 0 / NO 29 |

### No threshold made this a fair bet

Block production is not merely regular — it is a spike. Across 115 wagers with
an identical 30-second window:

| Blocks produced | Rounds | Share |
|---|---|---|
| 60 | 11 | 9% |
| 61 | 12 | 10% |
| 62 | 77 | **66%** |
| 63 | 14 | 12% |
| 65 | 1 | <1% |

Because two thirds of all windows land on exactly 62, the `>=` test has no
intermediate setting. Measured, not modelled:

| Threshold | Rounds | Resolves YES |
|---|---|---|
| 62 | 49 | 83% |
| 63 | 37 | 13% |
| 64 | 29 | 0% |

The YES rate falls from 83% to 13% between two adjacent integers. There is no
threshold anywhere near even odds, and no finer setting exists — the quantity
being wagered on is an integer count. The losing path is reachable, but only by
placing the threshold where the wager is close to decided before it is struck.

Reporting the two batches as one pooled figure would have shown YES 14 / NO 13
and suggested a balanced market. That pooled number is meaningless: it averages
a YES-heavy batch against a NO-only batch run at a different threshold. Batches
at different thresholds must not be aggregated.

A block-count wager on this chain is therefore a poor instrument for studying
price formation under uncertainty. The block rate is precisely what consensus is
built to hold steady; wagering on it is wagering that the chain will
malfunction.

### A subject with real entropy

The replacement subject is the parity of the first byte of a future masterchain
block's `root_hash`. It is uniform by construction, and every party can verify
it from `lookupBlock` at the agreed height.

Across 41 rounds it resolved **EVEN 21 / ODD 20** — 0.16 standard deviations
from an even split, against the 83%/13%/0% cliff the block-count subject
produced. Every round's escrow drained to zero and all three nodes returned the
same `root_hash` at the agreed height.

Three design requirements, each of which matters:

1. **The target height is fixed only after acceptance**, at `S0 + 60` — roughly
   30 seconds ahead. Fixing it before the wager is struck would let whoever
   proposed it choose a height whose hash they had already seen.
2. **All three nodes must return the same `root_hash`** at that height, and the
   round aborts if they disagree. This makes each wager double as a consensus
   check on a specific block, rather than only on chain height.
3. **No participant may be a validator.** On this network the agents are not
   validators, so no party can grind the hash. A deployment where an agent also
   validates would break the fairness of this subject entirely, and the wager
   would need an entropy source outside the chain's own producers.

### Symmetric stakes — a wager both sides can lose

The Task Escrow can express a genuine two-sided wager, though not in the obvious
way. The contract pays `payout` to the agent and then sweeps the entire
remaining balance to the creator, with `payout <= budget` and
`payout <= balance`. Funding the escrow only from the creator therefore cannot
produce a symmetric bet: the counterparty's own contribution would return to the
creator on a win, netting both sides to zero.

The construction that does work:

- the creator declares `budget` equal to the **whole pot**, and sends half,
- the agent sends the other half as the value of its `accept` message,
- a win for the agent settles `payout = pot`; a win for the creator settles
  `payout = 0` and the sweep hands it the pot.

`budget` may exceed the value the creator actually sends — verified directly: a
task created with `--budget-nanotos 2000000000` and `--amount-nanotos
1100000000` reports `Budget: 2 TOS` and opens normally. This is what makes the
construction possible.

Decoded from one round's escrow out-messages, where the creator won:

    in   1.1000 TOS  <- creator
    in   1.0500 TOS  <- agent
    out  2.1698 TOS  -> creator

Agent net −1.05, creator net +1.07. Both sides had real money at risk, which is
what the earlier batches lacked. Escrow drained to zero.

**Do not read the per-account balance deltas in `symmetric.jsonl`.** They are
sampled around the settle step only, and under concurrent batches the same
Agent Account may be funding another wager in that window — one losing agent
shows `−1.5005` where the correct figure is `0` for that step. The trustworthy
fields are `pool_nanotos` (the pot was fully funded before the outcome was
observed) and `escrow_remaining` (zero after settlement); anything about who
received what must come from the decoded out-messages.

The round aborts before the outcome is observed if the escrow balance has not
reached the full pot — otherwise a counterparty could take the bet without
funding its side, which reinstates the free option this construction exists to
remove.

### The escrow's default rules favour the creator, and a wager inherits that

This construction has a hazard that work-for-hire does not, and it is worth
stating plainly before anyone builds on it.

`timeout` resolves to the creator in every branch except one:

| State at timeout | Verifier set | Result |
|---|---|---|
| `accepted` (no result yet), past deadline | either | **everything to the creator**, status `expired` |
| `result_submitted`, past review deadline | yes | **everything to the creator**, status `expired` |
| `result_submitted`, past review deadline | no | budget to the agent — the only agent-favouring branch |

For work-for-hire these rules are correct: an agent that never delivered should
not be paid, and the creator's funds should come back. **Repurposed as a wager,
the same rules read "the creator wins by default"** — and the counterparty's
stake is part of what comes back.

Measured directly. A symmetric wager with a 100-second deadline, both sides
funded (pot 2.1499 TOS), agent never submits a result:

    timeout by creator -> status expired
    creator            +3.1497 TOS
    agent               −1.05 TOS (its stake), outcome never adjudicated

The agent lost its entire stake on a wager that was never decided.

Two consequences for anyone using this construction:

1. **The deadline must sit well beyond the wager's resolution time**, with
   margin for the counterparty's submission and for chain latency. A deadline
   that can lapse mid-wager is a free option for the creator, which is exactly
   the asymmetry the symmetric stake was introduced to remove.
2. **Setting a verifier removes the agent's timeout protection.** With no
   verifier, a submitted result defaults to paying the agent; with one, an
   inactive verifier lets the creator sweep the pot after the review window. A
   wager that relies on a third-party adjudicator therefore depends on that
   adjudicator actually acting — non-action is not neutral, it favours the
   creator.

   Measured, not inferred. A symmetric wager with a verifier set, pot 2.1499
   TOS, where the agent submitted a correct result and the verifier then did
   nothing for the full 3,600-second review period:

       timeout by creator -> status expired
       creator            +2.1596 TOS
       agent               −1.05 TOS (its stake)

   The agent delivered correctly and lost its entire stake. This is the more
   dangerous of the two timeout cases, because nothing went wrong that either
   party could point to: the result was right, the escrow behaved as written,
   and the adjudicator simply stayed silent.

A wager built on this escrow should treat the creator's role as privileged and
price it, or the construction needs a contract whose default on non-resolution
is to return each side's stake rather than to sweep to one party.

### The losing path, verified

Round `uwager-r208` produced 61 blocks against a target of 62 and settled NO.
Decoding the escrow contract's out-messages:

    in   1.5000 TOS  <- creator (stake)
    in   0.0100 x3   <- agent / verifier operation gas
    out  1.5298 TOS  -> creator (full refund)

The losing side received nothing; the funder was made whole. Escrow balance
zero, three nodes in agreement.

### Verifier-less escrow, timeout path

With no verifier configured, `timeout` inside the challenge window was rejected
by the contract, and after expiry it paid the agent 1.49999 TOS automatically.
Note that the CLI reported `OK` for the rejected attempt: **`OK` means the
message was delivered, not that the contract accepted it.** Status and balance
are the authority.

## Finding 4 — the agent has no recourse unless an attestor is configured

The escrow's authority model, read from the contract:

| Operation | Permitted sender |
|---|---|
| `result` | the agent only (err 103) |
| `settle` | the creator, **or** the verifier when one is set (err 105) |
| `dispute` | the creator only (err 120) |
| `resolve` | the verifier only (err 124) |

`dispute` being creator-only means the agent cannot contest a settlement.
Tested directly, with no verifier and no attestor:

1. The agent accepted and submitted its result.
2. The agent attempted `dispute` — **rejected**, status unchanged at
   `result_submitted`.
3. The creator settled with `payout=0` — **accepted**.
4. The agent's balance moved by **0 TOS** for delivered work.

The `timeout` path protects the agent only when the creator does nothing. It
does not protect against a creator who actively settles zero, which is a
one-message action available from the moment the result lands.

Note also that when a verifier is set, that verifier both submits the ruling and
adjudicates the dispute against its own ruling. Without an attestor, the
verifier is judge in its own case.

### The attestor gate holds

Configuring `--attestor-pubkey` requires an independent signature over
`(result_hash, payout)`, domain-bound to the contract address. All four checks
behaved correctly:

| Attempt | Result |
|---|---|
| Creator settles `payout=0`, no signature | **rejected** |
| Creator settles `payout=0`, signed with the creator's own key | **rejected** |
| Creator rotates the attestor key to its own, then settles | **rejected** — the key is frozen once configured |
| Settle with the true attestor signature, full payout | accepted; agent received 0.9999 TOS |

The third row is the load-bearing one: had the rotation taken effect, the
settle signed with the creator's key in that same step would have succeeded. It
did not, so the freeze is real.

**Recommendation.** The information needed to avoid this is already available:
`task show` reports `Attestor pubkey: none` for an unprotected escrow and the
key itself for a protected one, and the agent can read it before accepting. The
gap is not visibility — it is that nothing obliges an agent to look, and the
unprotected configuration is the one that costs nothing to create. An
autonomous agent's accept policy should treat a missing attestor as a
first-class risk input and refuse, or price it, rather than treating any
funded escrow as equivalent work.

## Chain health

| Metric | Observation |
|---|---|
| Three-node agreement | 100% of samples; zero divergence over the entire run |
| Height at report time | 21,304 |
| Block rate | ~2.05 blocks/s sustained |
| Per-node RSS | 388–540 MB, oscillating, no monotonic growth |
| Validator uptime | 9,058 s |

Memory must be read per node. Summing the three processes yields ~1.5 GB, which
is not comparable to the per-node figures recorded in earlier runs.

## What this run does not establish

- No external revenue. All value circulated among the same eight identities.
- No decentralization claim. One host ran the agents, the wallets and all three
  validators.
- No result against a *lying attestor*. The attestor gate was tested against a
  creator trying to bypass it (Finding 4), and it held. What remains untested is
  a correctly-configured attestor that signs a payout contradicting the
  evidence — the contract cannot detect that, and the remedy would have to sit
  outside the escrow.
- No claim about market efficiency. Findings 1 and 2 mean the observed prices
  describe a protocol artifact, not a price discovered by competition.

## Measurement traps encountered

Recorded because each one produced plausible-looking data that was wrong.

- **The observation window must start after acceptance.** Starting it before
  `create` folds two rounds of three-node confirmation (~5 s, ~10 blocks) into
  the window, inflating counts and making a calibrated threshold look
  unreachable-in-reverse. Early rounds read 69–72 blocks where the true rate was
  61–63.
- **Winner balance deltas are unusable under concurrency.** An agent that wins
  one wager may be funding another simultaneously; one round showed the winner
  at −0.5 TOS. Read the escrow contract's own balance, which reflects only that
  wager.
- **A threshold at the median still yields lopsided outcomes** when the test is
  `>=`. Covering the losing path required moving the threshold to the top of the
  distribution.
- **Addresses must be compared in one form.** The JSON-RPC returns friendly-form
  (`EQ...`) addresses; comparing those against raw hex never matches, and makes
  the counterparty look like an unrelated third party.
- **Per-node and summed memory are different units.** Summing three validators
  and comparing against a historical per-node band reads as a doubling that did
  not happen.
