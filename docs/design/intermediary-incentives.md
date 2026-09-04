# Why an Intermediary Carries Your Traffic

> Back to [Architecture](../architecture/README.md)

OpenFox depends on two kinds of intermediary, and only one of them is paid.

A **relay or gas sponsor** puts a transaction on chain for an Agent that cannot
or will not pay its own gas. A **Carrier** distributes and indexes the Intents
an Agent publishes so that counterparties can find them. Both sit between an
Agent and the party it wants to reach, and it is easy to talk about them as one
layer. They are not one layer. The relay has a settled economic model with
substantial machinery behind it. The Carrier does not have one at all.

This document states both positions from the code, and argues that the gap is
structural rather than an omission.

Scope: the incentive question only. The Carrier admission and trust rules are in
[Trusted Capabilities and Mobile Owner Control Plane](trusted-capabilities-and-mobile-control-plane.md);
where each subsystem should live is in [Capability Boundary and Core
Decomposition](../architecture/capability-boundary.md).

## The relay is paid, and the protocol works hard to let it move first

Relay obligations are defined in pairs in `agentrelay`:

    ObligationRelayDelivery   = "transaction_relay"
    ObligationRelayFee        = "transaction_relay_fee"
    ObligationSponsorDelivery = "gas_sponsorship"
    ObligationSponsorshipFee  = "gas_sponsorship_fee"

Delivery and payment are two obligations inside one signed Agreement, so the
relay's revenue is expressed in the same object as its duty.

Paying it is the easy half. The hard half is ordering: **the relay must first do
something irreversible** — spend its own gas and broadcast — and only then can it
be paid. Most of the relay subsystem exists to make that ordering survivable.

| Mechanism | What it prevents |
|---|---|
| The finality profile and its canonical digest are signed **before** either party authorises the Agreement | An observed-only Agreement being upgraded to a stronger terminal predicate after a transfer is seen |
| `MinimumRelayInclusionMarginSeconds = 30`, deliberately **in addition to** the finality profile's whole resolution budget | A provider starting an irreversible side effect at the edge of a technically unexpired authorisation window |
| Absence evidence — `ResolveRelayTransactionAbsence`, described in code as the "query-only S+/R- producer" | "The sponsorship landed but the transaction never did" being indistinguishable from "nothing happened" |
| Terminal accounting kept separate from the route journal, idempotent across crashes | A crash between broadcast and bookkeeping turning into a double payment or a lost obligation |

The absence producer is the interesting one. It resolves a specific compound
state — sponsorship present, relay absent — into evidence. That is what makes a
failed delivery an accountable outcome instead of an argument between two
parties with different logs.

None of this is generic infrastructure. It exists because the service being sold
is **verifiable**: a transaction is either included in a block or it is not, and
the chain answers that question the same way for everyone.

## The Carrier is not paid

Nothing in the publication path pays a Carrier. Searching the tree for any
carrier-linked fee, invoice, settlement, compensation or reward returns nothing.
A Carrier is configured with two credentials and no price:

    carrier.ReadToken   // read
    carrier.RelayToken  // publish

and the gateway states plainly what those grant:

> These tokens grant transport permissions only. They cannot create or change
> [authority].

So an Intent is carried today **because the intermediary is permitted to carry
it and its operator absorbs the cost**, not because carrying it pays. Whoever
runs the gateway funds distribution for everyone using it.

OpenFox does not extend trust to any single Carrier — `MinimumIndependentCarriers`
defaults to 2 and autonomous contact refuses to proceed below the configured
minimum, so publication fans out across independent Carriers and relies on
redundancy against a Carrier that drops or censors. That is a robustness
argument. It is not an economic one: several unpaid intermediaries are still
unpaid.

## The gap is structural

The asymmetry is not an oversight, and it will not be closed by adding a price
to the Carrier path.

**Relay delivers a verifiable service.** Inclusion is objective, cheap to check
and identical for every observer. Payment can be bound to it, absence can be
proven, and settlement can be escrowed.

**Carriage is not verifiable.** "You showed my Intent to enough of the right
counterparties" has no objective test. A Carrier that accepts a fee and files
the Intent in a private index cannot be falsified by the publisher; a Carrier
that did the work honestly cannot prove it either. **Without a decidable
delivery there is nothing to hang a payment on**, and a per-message fee would
only move the trust problem into the invoice.

This is the same constraint that governs any settled outcome here. A bilateral
wager on this network is only sound when the subject is a quantity every node
recomputes identically; a block-count subject that consensus deliberately holds
steady makes a bad one. Carriage fails the same test for the same reason.

## Directions that do not require verifying carriage

Two shapes avoid the problem instead of attacking it, and neither needs a
per-message price.

**Attribute settled trades back to the Carrier that sourced them.** Delivery of
the *trade* is verifiable and its settlement is on chain. A Carrier that earns a
share of what it demonstrably introduced is paid for an outcome rather than for
an unobservable act. The open question is attribution: an Intent that reached a
counterparty through several Carriers has no single sourcing claim, and any
split rule is a policy choice rather than a fact.

**Bond the Carrier against a challengeable service claim.** Rather than proving
each carriage, a Carrier stakes against a published commitment and anyone can
challenge a violation with evidence. This moves the burden from proving service
to proving *breach*, which is the easier direction — the same asymmetry the
escrow's challenge window already uses.

Both are sketches. Neither is implemented, and this document does not recommend
one over the other.

## What this means today

State it plainly wherever the economics of the network are described: **relay
and sponsorship have a closed economic loop; Intent distribution is currently
subsidised by whoever operates the gateway.** A deployment that assumes
third-party Carriers will appear because the protocol allows them to is assuming
something the protocol does not yet provide a reason for.
