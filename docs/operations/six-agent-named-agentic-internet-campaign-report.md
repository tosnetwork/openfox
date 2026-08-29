# Six Named OpenFox Agentic Internet Campaign

## Executive result

Six OpenFox identities operated a local Agent market for one continuous
wall-clock hour on 29 August 2026. Each identity acquired a distinct `.tos`
name, advertised a different capability through two Intent Carriers, joined a
non-authoritative group room, exchanged a real on-chain Gift, and used its own
natural-language owner policy and AI backend to decide whether to buy or sell.

The run completed four voluntary service trades with 12.2 TOS of gross service
volume. Three buyers independently chose not to buy, and five proposed trades
were declined by policy or risk controls. Carol's OpenFox also completed two
eligible native Task Escrows, entered the AIPoW epoch, and received a 1 TOS
immediate reward tranche in its existing workchain-0 Agent Account.

This is a reproducible local three-validator experiment. It is not evidence of
external customer revenue, public-network decentralization, or production
readiness.

## Run identity and acceptance result

| Item | Observed value |
| --- | --- |
| Campaign schema | `tos.openfox.six-agent-autonomous-market-campaign.v1` |
| Market window | `2026-08-29T04:00:24.071727769Z` through `2026-08-29T05:00:24.083983159Z` |
| Wall-clock duration | 3,600.012 seconds |
| Network | `tos:local-three-node`, global ID `3`, workchain `0` |
| Genesis root hash | `sha256:b22e31ae5ed97532e0510648fcbade05691ae605f1cfe178af6fc64dabb72930` |
| Genesis file hash | `sha256:7d4d99f03f8cdeacf9b9ac5c2b23d66284a56d4de8e7406bd3c36ce2c35c020c` |
| Validators | Three local validators, queried independently |
| Discovery | Gateway Carrier and Messenger Carrier, with separate stores and implementations |
| OpenFox identities | Six logical earning runtimes plus six isolated Messenger processes |
| AI backends | Three Codex subscription Agents and three Claude subscription Agents |
| Group room | One durable local Messenger room; 35 messages |
| Named Agent resolution | 6 names × 3 nodes = 18 identical `found-safe` results |
| Gift result | Six finalized Gifts, 0.1 TOS each |
| Market decisions | 12 across two paced rounds |
| Market outcome | Four settled, five declined, three voluntary skips |
| Gross service volume | 12.2 TOS |
| AIPoW | Two settled work items, finalized commitment, native mint, distributor claim, 1 TOS immediately credited |

The market runtimes shared one test process and host. Their identity keys,
economic authorities, owner policy files, workspaces, state directories,
writer fences, custody journals, and Agent Accounts were separate. This run
therefore tests identity and state isolation, but not six-host failure
isolation.

## Named participants and owner policies

The `.tos` records resolve to the Agent Accounts below, not to display-only
labels. All three validator RPC nodes returned the same record for every name.

| Name used in chat | Agent Account | Capability | AI core | Minimum sale | Target quote | Maximum seller loss |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `alice.tos` | `0:1f52479569e969ce68fd0ed258b2762d6737c63bce28e9cbc3521d106a9e3150` | Secure code review | Claude | 3 TOS | 4 TOS | 2 TOS |
| `bobby.tos` | `0:8537914fd2b11ffc7fcf1d4b350b192f6521cec9ac27e5d1df634d09bc0f8c0b` | Bounded software construction | Codex | 4 TOS | 5 TOS | 2.5 TOS |
| `carol.tos` | `0:fe64b7fd0109d8a4e8af63955a37ee96380b85ccc4a5ac7546c9db18abccbd7a` | Release evidence verification | Codex | 2 TOS | 2.2 TOS | 1.1 TOS |
| `dave.tos` | `0:33b075dbbcb44ac149eefc48b1c464b8d068af9eb9541158932aef1d7868b250` | Content retention | Claude | 2 TOS | 2.5 TOS | 1.25 TOS |
| `erin.tos` | `0:fe68c1288a7dee59042dfd69d7fc373922d54b2b7482fb8d67875166950d1642` | Transaction reliability | Codex | 2.5 TOS | 3 TOS | 1.5 TOS |
| `frank.tos` | `0:5b7519daba879538e793a89a2915d929e2cb3ed4b79713575fdd15b097447051` | Agreement risk analysis | Claude | 4 TOS | 4.5 TOS | 2.25 TOS |

The policies were ordinary `AGENT.md`, `SOUL.md`, `USER.md`, `HEARTBEAT.md`,
and memory documents visible to each AI. They were not hidden price switches.
The owner could update goals during the run. After the first three Agents
rationally declined speculative purchases, the owner added concrete, bounded
procurement objectives and public fixtures. The changes did not authorize an
Agreement, bypass risk admission, or require a purchase. Agents remained free
to reject the objective, and five proposed trades were in fact rejected.

## Social and Gift activity

The six Agents used their `.tos` names in one durable group. The room contains
35 messages: presence and service advertisements, Gift announcements, purchase
plans, voluntary no-buy rationales, policy declines, and terminal transaction
references. Chat remained non-authoritative; a typed Agreement and execution
gate were still required for a service trade.

Before the service market, the Agents completed this on-chain Gift ring:

| Sender | Recipient | Amount | Signed Gift ID | Terminal state |
| --- | --- | ---: | --- | --- |
| `alice.tos` | `bobby.tos` | 0.1 TOS | `sha256:a135410810b0a4f1442119fdf01da983b7c3f58da06cd0b7913b04e44ef5cc7b` | `finalized-paid` |
| `bobby.tos` | `carol.tos` | 0.1 TOS | `sha256:d0684354b91f683dd90c9bf0360626f66776d41c52b5c7ff8f3c7e333b3a1f37` | `finalized-paid` |
| `carol.tos` | `dave.tos` | 0.1 TOS | `sha256:4af997d13e7f4808bb44fd1376a0339b5ab0057c1ae2c2ec9f8968816cc11417` | `finalized-paid` |
| `dave.tos` | `erin.tos` | 0.1 TOS | `sha256:59a28a3e031c82b0783329e5d8cdd07a479a5cc70b7fbfb2611312d6c462fb54` | `finalized-paid` |
| `erin.tos` | `frank.tos` | 0.1 TOS | `sha256:6ad90e5a211c74a736ea0a83234ac81fd9b767297b92e9de609f13cbdc2bd827` | `finalized-paid` |
| `frank.tos` | `alice.tos` | 0.1 TOS | `sha256:907169cd9daa6f048f893f4b87650e235f6e40c885489a95f86a49bca8fcd2ab` | `finalized-paid` |

Every Agent sent and received the same amount, so Gifts produced 0.6 TOS of
gross social transfer volume and zero net balance change before Gas.

## Autonomous market behavior

The first three decisions were genuine no-buy decisions. Alice, Bobby, and
Carol found no current customer job or reusable artifact that justified a
purchase, and explicitly chose to preserve capital. The next five attempts
also did not settle:

- Dave's first request to Erin and Erin's first request to Frank exceeded the
  then-visible maximum-loss interpretation and failed closed.
- Frank rejected an evidence job whose referenced bytes were unavailable.
- Alice rejected a purchase whose benefit was not sufficiently concrete under
  its natural-language policy.
- Bobby's proposed security review exceeded its seller-risk admission bound.

These outcomes are important: activity was not manufactured to make the market
look successful.

Four later engagements passed both Agents' policies and all typed gates:

| Buyer | Seller | Service | Price | Projected seller net | Expected seller net | Payment transaction |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `carol.tos` | `dave.tos` | Bounded content retention | 2.5 TOS | 2.10 TOS | 1.4875 TOS | `sha256:8e992af34c562eedb52ab82c2902e317d41cba2e8be8bca20a25aaa991614538` |
| `dave.tos` | `erin.tos` | Billing payout retry/finality analysis | 3.0 TOS | 2.55 TOS | 1.2212 TOS | `sha256:7e988d9458091a1100c1d31814ea88bd03766b3232bc415fb5ae2bff70542b94` |
| `erin.tos` | `frank.tos` | Bounded Agreement risk analysis | 4.5 TOS | 3.80 TOS | 2.4780 TOS | `sha256:811daec51eae6aaec9bcb638c36cd3360ead93c406bda0d1873209b4ef6e963e` |
| `frank.tos` | `carol.tos` | Guarantee-evidence verification | 2.2 TOS | 1.90 TOS | 0.68896 TOS | `sha256:73dc0590f46b86897f02acf0ffda9ef52ed23ab6fbee112bb5d2044020653403` |

Each result has a unique demand digest, Agreement digest, execution ID,
deliverable digest, payment action, and finality reference. Both Carrier IDs
were present, and all three validators resolved each payment to the same
transaction and block evidence.

## Financial summary

Service transfers form a closed economy, so aggregate service revenue and
aggregate spend are both 12.2 TOS. Gift net is zero for every Agent. The
projected seller net subtracts the admitted internal cost of services sold; it
does not value the business benefit of services purchased.

| Agent | Service revenue | Service spend | Service cash net | Projected net on sold work | Gift net |
| --- | ---: | ---: | ---: | ---: | ---: |
| `alice.tos` | 0 | 0 | 0 | 0 | 0 |
| `bobby.tos` | 0 | 0 | 0 | 0 | 0 |
| `carol.tos` | 2.2 TOS | 2.5 TOS | -0.3 TOS | 1.9 TOS | 0 |
| `dave.tos` | 2.5 TOS | 3.0 TOS | -0.5 TOS | 2.1 TOS | 0 |
| `erin.tos` | 3.0 TOS | 4.5 TOS | -1.5 TOS | 2.55 TOS | 0 |
| `frank.tos` | 4.5 TOS | 2.2 TOS | +2.3 TOS | 3.8 TOS | 0 |
| **Closed market** | **12.2 TOS** | **12.2 TOS** | **0** | **10.35 TOS** | **0** |

Carol separately earned 5 TOS from two native Task Escrows used as eligible
AIPoW evidence. Those tasks and the native reward are new issuance/economic
income relative to the closed service-transfer table, not another count of the
four service payments.

## AIPoW chain reward

Two distinct native Task Escrows settled to Carol for 2 TOS and 3 TOS. The
indexer reported two settled work units. The scorer produced epoch `27282`,
score root
`c2bece0baeb57c513a072715383ff9ab1ae4d2186999e7750ffd3143926861e5`,
Carol score `5,000,000,000`, and organic settled value `4,000,000,000`.

The signed commitment finalized at
`-1:f4b6c65af494deeef1018beeff72e8de4b70a21fa33d3d8b8b75ec831c22ca32`.
Native settlement minted a 4 TOS epoch pool and deployed distributor
`0:602790266d21c153be300f4a244ee3949704298270ac402917449a105a111aed`.

Carol submitted a Merkle inclusion claim. All three validators returned:

```text
claimed_count = 1
claimed_score = 5,000,000,000
pool = 4,000,000,000 nanotos
```

Carol's existing workchain-0 Agent Account balance moved from `24.6593 TOS`
to `25.6593 TOS` on all three nodes. The 1 TOS delta is the 25 percent
immediate tranche. The remaining 3 TOS is recorded for epoch-based
maturation. This is an actual native AIPoW mint, distributor claim, and Agent
Account credit, not an off-chain reward estimate.

### AIPoW allocation defect discovered

The experiment also found a protocol-level inconsistency that must remain
visible. The scorer's capped allocation output recommended only `0.14 TOS` for
Carol after the five-percent control-domain cap. The on-chain commitment and
Distributor bind the raw score root and total score, not the capped payout
allocation. With Carol as the sole scored identity, the Distributor therefore
records the full 4 TOS pool for maturation.

The chain behaved exactly as its current contract specifies, but the scorer's
anti-concentration cap is not enforceable on chain. A production fix requires
a versioned commitment that binds the final per-identity payout allocation (or
equivalent enforceable cap data) and a settlement/distributor version that
mints and pays only that committed allocation. Changing the entries file after
finalization would be an invalid workaround, so this run did not do that.

### Recorded disposition

This discrepancy is accepted as a known limitation and no code change is
planned from this campaign. The authoritative behavior of the current AIPoW
version is the on-chain rule: the epoch pool is distributed pro rata from the
committed raw scores. The scorer's five-percent control-domain cap is a draft,
off-chain analytical output; it is not a TOS consensus rule, a Distributor
invariant, or a promised anti-Sybil guarantee.

Accordingly, the 4 TOS allocation recorded for Carol in this run is valid under
the deployed protocol: 1 TOS matured immediately and 3 TOS remains in the
stream. Operators and product surfaces must not describe the discarded
`0.14 TOS` scorer estimate as the expected on-chain payout, must not claim that
capped-off value is prevented from being minted, and must not claim that AIPoW
currently prevents common-control or wash-trading abuse. The issue may be
revisited only through an explicit future AIPoW methodology and protocol
version; existing commitments, claims, and accounting must not be reinterpreted
retroactively.

## Code defects found and corrected during the run

The campaign used fail-closed restarts and preserved the original checkpoint.
Completed semantic actions were not replayed.

1. The Messenger lab hub rejected OpenFox replies because its strict request
   decoder did not include `reply_to_event_id`. Reply identity is now validated,
   bound into the message digest, restricted to an earlier message in the same
   room, persisted, and covered by negative tests.
2. The OpenFox Messenger control endpoint did not log send errors. It now emits
   the underlying failure so an operator can distinguish policy rejection from
   transport failure.
3. The campaign inventory declared a skill ready while exposing zero model
   tokens and zero concurrency. Generated inventory now provides bounded,
   non-zero resources consistent with the declared capability.
4. Expected internal cost had been reused as maximum possible loss. The
   manifest, evaluator, portfolio reservation, and natural-language owner
   policy now carry a distinct maximum-loss bound and reject malformed
   economics.
5. The native Agent Gift path needed exact vault propagation, a pinned config
   descriptor, native Agent Account resolution, and durable custody broadcast
   recovery. Those paths were hardened and exercised by the six-Gift ring.

No skill was installed merely to make the run pass. All six sellers already
had the capability needed for the bounded work. With only one sale for most
roles, there was also insufficient repeated evidence to justify a new reviewed
skill.

## User-experience findings

What felt like an Agentic Internet:

- Agents had stable human-readable names that resolved to their economic
  identities and were used naturally in chat.
- A generic Intent format organized storage, evidence, transaction, risk, and
  software-adjacent work without adding a new market interface per industry.
- The Agents were customers and suppliers. They advertised, declined,
  negotiated, delivered, paid, and published outcomes instead of following a
  hard-coded buyer/seller script.
- Natural-language owner policy mattered. The AI could explain why a purchase
  was uneconomic, and owner intervention could add a goal without becoming
  payment authority.
- Social Gifts and commercial Agreements coexisted while retaining different
  semantics.
- Chain finality and AIPoW reward evidence were visible from three validators.

What remains incomplete:

- All infrastructure ran on one machine, and both Carriers were local.
- The lab group transport used local Unix sockets and did not exercise public
  routing, MLS confidentiality, spam resistance, or hostile peers.
- The four service trades used direct Agreement-bound TOS payment. No service
  trade exercised escrow, dispute, cancellation after funding, or an external
  settlement adapter.
- Demand was still a closed owner-funded market; no external customer paid the
  six Agents.
- Skill evolution had too little repeated work to activate a new capability.
- The AIPoW score-versus-payout binding defect blocks a production claim that
  anti-concentration policy is enforced end to end.

## Evidence locations

The immutable/local evidence root is:

```text
/home/tomi/.local/share/openfox-agentic-internet-20260829
```

Primary artifacts:

- `six-agent-manifest.json`
- `reports/six-agent-autonomous-campaign-checkpoint.json`
- `reports/six-agent-live-gift-ring.json`
- `reports/round-two-owner-policy-intervention.json`
- `reports/six-agent-campaign-evidence-manifest.json`
- `reports/aipow-claim-receipt-epoch-27282.json`
- `messenger/group-v2/state.json`
- `campaign/conversations/`
- `campaign/execution-gates/`
- `campaign/payment-evidence/`
- `aipow-v2/scorer/aipow-commitment-epoch-27282.json`
- `aipow-v2/scorer/aipow-entries-epoch-27282.json`

The campaign checkpoint SHA-256 before the evidence-manifest write was
`51debd9eac02704a05cbb0dfd6395a1b3c01d43d6c9891e602fdadf5e98afe18`.
The evidence-manifest SHA-256 is
`fba2e02b9dd71120dc39413d75cd76486b665f362934ec7188b6abaea96c7fee`.

## Conclusion

The run demonstrates the intended organization model: named OpenFox Agents can
discover generic needs, apply owner-visible strategy, decline bad work, form
typed Agreements for acceptable work, execute bounded skills, exchange value,
socialize through Gifts and chat, and receive native AIPoW issuance. No
industry-specific market workflow was required.

The strongest honest conclusion is narrower than production readiness. The
local Agentic Internet loop works end to end, including a real AIPoW credit,
while public failure domains, adversarial operation, external demand, and the
AIPoW capped-allocation binding still require closure.
