# PredictionMarket integration evidence

This directory retains bounded, machine-readable outputs from the live gates
documented in `docs/operations/prediction-market-v1-acceptance.md`.

Evidence files are immutable observations of a particular local-chain run.
They do not replace rerunning the gate, and a narrower report must not be used
to claim that a broader lifecycle passed. `oracle-context-three-node.json`
proves only the three-node Oracle context and immutable policy binding.

`future-block-entropy-distribution-three-node.json` is the separately selected
48-block preflight window for the synthetic release subject. It proves that
three nodes returned the same exact block IDs and that the first-byte parity
was not grossly biased in that window. It does not prove that a future target
was locked after a particular wager was accepted and therefore cannot be used
as settlement evidence.

A direct-wallet contract run produces three owner-private files named with the
market ID: `accepted-wager-*.json`, `future-block-lock-*.json`, and
`future-block-reveal-*.json`. Together they bind exact source and destination
transaction BOCs, the unique outbound message, three-node accounting and
masterchain inclusion, the pre-reveal validator set, and the subsequently
finalized block used for the outcome. The accepted report's
`submission_profile` remains `direct-wallet-contract-probe`; these artifacts
must not be used as evidence that the production Intent, Agent Account
checked-call v2, relay journal, or crash-recovery path passed.
