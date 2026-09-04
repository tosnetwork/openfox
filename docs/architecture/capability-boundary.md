# Capability Boundary and Core Decomposition

> Back to [README](README.md)

OpenFox advertises a single static binary that runs on RISC-V, ARM, MIPS, x86
and LoongArch boards, down to `$5` hardware, with a core memory footprint under
10 MB. The runtime has been growing faster than that promise. This document
gives a rule for deciding what belongs inside the binary, applies it to what is
there today, and applies it to the PredictionMarket capability that is being
designed now.

This is the outbound counterpart to [Trusted Capabilities and Mobile Owner
Control Plane](../design/trusted-capabilities-and-mobile-control-plane.md).
That document governs how a capability is **sourced, admitted and promoted**.
This one governs where a capability **lives** once we have decided to have it.
Nothing here proposes replacing the earning stack: relay, guarantor,
settlement adapters and accounting journals are reused as they are. The
question is only which process they are linked into.

Out of scope: the hook system, the routing pipeline, and the model/session
layers. Those are covered by their own documents.

## Measurements

Taken on 2026-09-04 at `pkg/earning` and its neighbours.

| Metric | Observed |
|---|---|
| Distributed binary | 36 MB |
| `pkg/earning` | 50,436 source lines, 38,199 test lines, 121 source files |
| — relay and sponsorship | 17,120 lines (33% of `earning`) |
| — guarantor | 7,792 lines (15%) |
| — authority and journals | 6,482 lines (12%) |
| Third-party packages reachable from `pkg/earning` | 190 |
| Feature build tags elsewhere in the repository | 4 (`azidentity`, `bedrock`, `whatsapp_native`, `integration`) |
| Feature build tags gating any `earning` subsystem | **0** |
| Build tags inside `pkg/earning` | 10, all Windows/Unix portability |
| Semantic action kinds today | ~19 |
| Semantic action kinds proposed by PredictionMarket V1 | **19** |

To reproduce the subsystem split:

```bash
find pkg/earning -maxdepth 1 -name '*.go' ! -name '*_test.go' -exec wc -l {} + | sort -rn
grep -rl '^//go:build' pkg/earning/
```

Two of these numbers carry the argument.

**The earning stack has no feature gating.** All ten build tags inside
`pkg/earning` select an operating system. An OpenFox on a `$5` RISC-V board
links the relay sponsorship journal and the guarantor provider whether or not it
will ever act as a relay or a guarantor.

This is not a missing capability in the build. The repository already gates
optional features this way — `azidentity`, `bedrock` and `whatsapp_native` are
existing feature tags, and `make check-build-tags` enforces the tag matrix for
the Matrix client's crypto and JSON backends. Introducing one for relay and
guarantor follows house practice rather than establishing something new.

**One proposed feature doubles the action surface.** PredictionMarket V1 adds
19 semantic action kinds to the roughly 19 that exist. A capability that
doubles the authority surface of the runtime is not "one more feature," and
should not be reviewed as one.

## The rule

Size is the symptom, not the criterion. The question to ask of any subsystem
is:

> When this code is wrong, does the owner lose **money**, or does a **task**
> come out badly?

Code in the first class defines the owner's authority boundary and must stay in
the core process. Code in the second class is replaceable, and belongs behind a
boundary where a wrong answer is caught rather than paid for.

This is the same separation the trusted-capabilities design already draws
between admission and execution, applied one level down: the core keeps what
grants authority, and delegates what merely produces results.

### What the rule keeps in core

Roughly 8,000–10,000 lines:

- `authority_journal.go`, `shared_authority.go`, `engagement_ledger.go` — who is
  authorised to spend what;
- the exposure reservation ledger, which must serialise globally across every
  capability an agent holds;
- the `Prepared → Broadcasting → Resolved` exact-BOC lifecycle and its crash
  recovery;
- multi-RPC quorum resolution and network-domain pinning;
- trading-key custody and the `tosctl` settlement sink.

These share one property: a delegated component that got them wrong would move
real funds before anything could check it. They also have to serialise against
each other — an exposure ledger that is per-capability is not an exposure
ledger.

## Three existing mechanisms, one misplaced boundary

The extraction machinery is already built and is better than the current
boundary suggests.

`pkg/mcp/capability_authorizer.go` binds every effectful tool call to an
`ExpectedEffectActionID` together with an exact request digest, and
re-validates on use. `HermeticMCPRuntimeBindings` pins a runtime with no
network broker, no credential handles, no filesystem handles and a fixed empty
environment. `pkg/skills` already carries registries, an installer, a loader
and validation.

So this is not a missing-mechanism problem. The money-touching subsystems were
simply built inside the binary instead of behind a boundary that already
existed.

| Destination | What belongs there | Why |
|---|---|---|
| **Local hermetic MCP** (compute only) | Deterministic matchers, pricing and conservation reference models, canonical encoders | No network, no credentials; the core can recompute the answer independently, so a wrong result is rejected rather than paid |
| **Remote MCP** | Oracle source adapters, evidence fetching and archiving, market discovery and indexing | Network-heavy, SSRF-exposed, and sources change often; the server carries the network, the core receives content-addressed results |
| **Skills** | The work the agent actually sells: contract review, translation, OTC quoting, evidence checking | This is what differs between agents, and is exactly what the existing registry and installer are for |
| **Separate binaries** — *not* extension points | **relay**, **guarantor** | They hold their own journals and keys and play a network role rather than offering an agent capability. Modelling them as extensions would be wrong; they should be independent components sharing the protocol packages |

The last row is the largest single move available: relay and guarantor together
are **24,912 lines, 49% of `pkg/earning`**. Removing them from the default link
set stops every edge agent paying for two roles it does not play.

## Applying this to PredictionMarket

PredictionMarket is not one more feature to place. It spans all three
destinations, and splitting it correctly is what keeps it from repeating the
history that produced the 49%.

| Component | Destination | Reasoning |
|---|---|---|
| Deterministic matcher, `quote_match` reference arithmetic, conservation model | Local hermetic MCP | Pure computation. The V1 design already requires an independent reference model for differential testing; that model and this component are the same artifact |
| Order-book index, search by market / outcome / price / remaining / expiry | Remote MCP | A projection with no authority, and its size grows with the number of markets rather than with the agent |
| Oracle source adapters, evidence archiving, SSRF controls, challenge watcher | Remote MCP | Source governance changes far more often than the agent; changing a source must not mean rebuilding the binary |
| Probability models, betting strategy, risk appetite | Skill | The differentiating part, and precisely the part that should *not* be uniform across agents |
| Trading-key custody, order authorisation, exposure reservation, exact-BOC submission | **Core** | The V1 design states the threat model as "a fully malicious OpenFox main process must not be able to sign an order on its own." That property only holds if this stays inside the authority boundary |

Of the 19 proposed action kinds, only a small group — `order.authorize`,
`collateral.deposit`, `collateral.withdraw`, `match.submit`, `position.claim` —
needs to be in the core. `resolution.report`, `resolution.challenge`,
`market.compact` and `terminal-surplus.withdraw` are **role** actions belonging
to oracle operators and keepers. Like relay and guarantor, they should ship as
separate components rather than in every agent.

## Sequence

Do the gating work before the moving work, or what is moved will be linked back
in by the next change.

1. **Introduce feature build tags so relay and guarantor can be excluded.**
   This is the only step that produces a measurement: build with and without,
   and compare binary size and dependency count. It is also far cheaper than
   any restructuring, and the tag mechanism and its `make check-build-tags`
   gate already exist — only the earning subsystems are outside them.
2. **Split relay and guarantor into their own `cmd/` binaries**, sharing the
   protocol packages rather than the process.
3. **Land PredictionMarket distributed across the table above from the start.**
   Not into `pkg/earning` with an intention to move it later — that intention
   is how the current 49% accumulated.

## What this document does not establish

The benefit of step 1 is inferred, not measured: no tag gates relay or
guarantor today, so the binary has never been built without them and the saving
is unquantified. That is the reason step 1 comes first — it converts the
central claim of this document into a number, and it should be allowed to
falsify it.

The 8,000–10,000 line estimate for the core is a reading of file
responsibilities, not the result of a compiled dependency cut. The real
boundary will move once the tags exist.
