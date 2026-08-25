# Eight-Agent Market Campaign

The opt-in `TestEightOpenFoxAgenticInternetCampaign` integration campaign
exercises a small Agent economy against two Intent Carriers and a local
three-node TOS network. It is a wall-clock campaign rather than an accelerated
unit simulation.

## Roles

The campaign uses eight isolated OpenFox identities, workspaces, economic
authorities, writer fences, and Agent Accounts:

| Agent | Offered capability | AI backend class |
|---|---|---|
| Security Auditor | bounded security review | local subscription CLI |
| Software Builder | bounded code implementation | local subscription app-server |
| Evidence Verifier | release and finality evidence verification | local subscription app-server |
| Storage Provider | content-retention planning and receipts | local subscription CLI |
| Data Curator | catalog normalization and deduplication | local subscription app-server |
| Localization Writer | protocol-safe technical localization | local subscription CLI |
| Transaction Operator | transaction recovery and relay analysis | local subscription app-server |
| Guarantor Analyst | Agreement and coverage-risk analysis | local subscription CLI |

The storage role never claims that planning text is a stored replica. A real
storage Adapter and retrieval evidence are required before such a claim can be
made.

## Per-job path

Each job must complete this path before it appears in the financial report:

```text
buyer signs and publishes a demand Intent to both Carriers
-> seller independently searches both Carriers
-> seller verifies the issuer and exact Intent digest
-> seller AI proposes a bounded economic estimate
-> deterministic local policy admits or rejects the opportunity
-> buyer and seller authorize one canonical Agreement
-> both sides reserve aggregate exposure
-> local Gate starts one bounded execution
-> seller produces a content digest and delivery evidence
-> both sides derive the same billing obligation
-> buyer Agent Account submits one stable payment action
-> three TOS node views establish finality
-> buyer and seller apply the same evidence
-> both sides release terminal reservations
```

An AI estimate that is malformed, changes the signed revenue, or places
aggregate cost or maximum loss above the owner-authorized inventory bound
cannot authorize a trade. The campaign may use an explicitly labelled
conservative owner-bounded estimate so that model formatting variance does not
become an economic authority.

## Recovery and learning

The checkpoint records only fully settled jobs. A pre-payment failure may use
a new, predecessor-linked Agreement version after terminal reservation
reconciliation. Once payment submission starts, the harness never invents a
new semantic payment; it stops for query-based recovery.

Only public, reusable-learning obligations produce evolution records. Raw
deliverables and participant-confidential data are excluded. A generated skill
is scanned, applied locally, loaded under shared count/byte limits, and remains
non-authoritative. See [Autonomous Earning Evolution](../guides/autonomous-earning-evolution.md).

## Claims and exclusions

- Two Carrier processes prove multi-source discovery behavior, but two
  processes on one host do not prove independent public failure domains.
- Internal Agent-to-Agent service revenue is real local-chain value transfer,
  but it is not external customer profit.
- Maximum internal cost is a conservative accounting reserve, not a measured
  subscription invoice.
- A successful text deliverable does not prove that an unavailable physical or
  remote service was performed.
- External issue publication remains a separately authorized side effect. The
  campaign deduplicates repository suggestions and cites observed evidence;
  model output alone cannot create an issue.
