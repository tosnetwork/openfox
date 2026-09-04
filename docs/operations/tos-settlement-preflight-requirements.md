# Preconditions for settling an OpenFox campaign on TOS

An OpenFox Agent that settles in native TOS goes through a custody payment
Adapter, a chain-control layer, and an Intent Carrier before its first
payment. Each of those enforces conditions that are correct on their own terms
and largely undocumented together. Bringing up a fresh three-node network and
an eight-Agent campaign on 2026-09-04 required clearing twelve of them, over
roughly four hours, none of which was a defect in the market logic or in the
chain.

This is the list, in the order they are hit. Every entry cost at least one
failed campaign start to find, because the error text names the check rather
than the fix.

## The payment Adapter binary

The custody Adapter refuses to launch a `tosctl` it cannot pin.

1. **Every ancestor directory must be closed to other principals.** A single
   `775` directory anywhere from `/` down to the binary fails the check. A
   repository checkout under `~/tos` is typically group-writable, so the
   binary has to be installed somewhere the owner controls outright.
2. **The binary must be at most 256 MiB.** A `cargo build` (debug) `tosctl`
   was 428 MiB and was rejected for size alone. `strip` brought the same
   binary to 52 MiB; a release build is 28.6 MiB.
3. **The binary must be current with the OpenFox build.** A `tosctl` from nine
   days earlier lacked `agent account economic-payment-corroboration-profile`
   and failed with a bare "command failed". Pin the two together.

The first two are deliberate: the Adapter spends Owner funds, so a substituted
or oversized image should not run. The third is a version-skew hazard with no
diagnostic of its own, and it has a second, worse form:

4. **The `tosctl` that deploys an Agent Account and the one that pays through
   it must be the same build.** The Agent Account contract template changed
   between two builds nine days apart. Accounts deployed by the older one stay
   active and readable, and every payment through them is refused with "Agent
   Account code does not match the supported final interface". The same skew
   also moves wallet addresses: the newer build derived a different V3R2
   address from an identical key, so the funding wallet appeared uninitialized
   with a zero balance while the funds sat at the old address.

   `tosctl agent account status --wallet <name>` reports `Template matches`,
   which answers this in one command. Nothing prompts you to ask before the
   first payment fails, hours after the deployment that caused it.

   Recovery does not overwrite: `agent account deploy` refuses to replace an
   active account, correctly. Deploy a second set under new profile names and
   leave the old accounts on chain, where the payment path will keep refusing
   them for the reason above.

## The RPC quorum identity

The payment evidence is corroborated across independent RPC views, and each
view must be identified before it is trusted.

5. **The locator must already be in canonical form.** `http://127.0.0.1:8011`
   is accepted; the same URL with a trailing slash is rejected as
   non-canonical. The check compares bytes, not URLs.
6. **Every quorum member must carry `operator_provenance`.** An endpoint URL
   is not evidence of operational independence, so the Owner has to state who
   runs each member.
7. **`operator_provenance` must be a `sha256:` digest**, not free text.

Point 6 deserves emphasis rather than a workaround. Three validators on one
host are not three operators. The honest value is a digest of an identity that
says so; writing three unrelated-looking strings would defeat the field's
entire purpose. A campaign run this way establishes cryptographic quorum and
**not** operational decentralization, and its report must say so.

## The network pin

8. **Zero-state hashes reach `tosctl` as `sha256:<hex>`, while OpenFox takes
   them as Base64.** The same two hashes are configured twice, in two
   encodings. Supplying Base64 to both is accepted by OpenFox and rejected by
   `tosctl` as a network-verification conflict, which reads like an
   unreachable node rather than a format error.

## Campaign state

The remaining conditions are not properties of a correct configuration. They
are what a repeatedly restarted campaign does to itself.

9. **The writer fence generation is monotonic.** Every prepare advances it.
   Authorized actions signed under an earlier generation stop matching the
   current fence, so a campaign restarted eight times during debugging cannot
   settle at all.
10. **Carrier state includes dotfiles.** `rm -rf <state>/*` leaves the
   `.writer-*` records behind, and the Carrier then rejects the new, lower
   generation as a stale writer. Remove and recreate the directory.
11. **Agreements expire.** Proposals retained from an earlier attempt fail as
    "premature or expired" long after the configuration that produced them was
    fixed.

Conditions 9 through 11 share one cause, and the rule that follows is simple: **do not restart a campaign in place to work
around a configuration problem.** Fix the configuration, then start from a
fresh campaign root. Restarting is what produces conditions 8 through 10, and
they are indistinguishable from real defects while you are chasing them.

## Diagnosis

12. **The Adapter discarded what `tosctl` said.** Every failure above surfaced
    as `tosctl command failed`, so each one had to be reproduced by hand,
    running the same command outside the campaign to see the real message.

That one is now fixed rather than documented: the custody Adapter keeps a
bounded 512-byte prefix of Adapter stderr and includes it in the failure,
so an operator can tell a rejected authorization from an unreachable node
without re-running anything. The bound exists so a chatty or hostile Adapter
cannot grow the error, and it is read only on the failure path.

## Checklist

Before the first campaign start:

- [ ] `tosctl` is a release build, current with the OpenFox tree, installed
      under a path whose every ancestor denies group and other write.
- [ ] The same `tosctl` build deployed every Agent Account that will be paid
      through. `agent account status` reports `Template matches: true` for
      each of them.
- [ ] `chain_rpc.urls` entries are canonical, with no trailing slash.
- [ ] Every quorum config carries an `operator_provenance` sha256 digest that
      honestly describes who operates that member.
- [ ] Zero-state hashes are Base64 for OpenFox and `sha256:<hex>` for
      `tosctl`.
- [ ] The campaign root, the Carrier state directories, and the Agent state
      are new, not reused from a previous attempt.

A single `tosctl agent account economic-payment-corroboration-profile` run
against the intended configs exercises conditions 1 through 8 in one command,
before any Agent is started. It is the cheapest way to find out whether the
environment can settle at all.

## Running the market concurrently

The campaign originally ran one trade at a time on a fixed schedule: a
round-robin queue decided who traded with whom before the run started, and a
constant interval spaced the turns. Twenty-four turns at seven and a half
minutes fills a three-hour window exactly, which is where "three hours buys
about two dozen trades" comes from. Almost none of that time is the chain —
settlement across three nodes takes about 2.5 seconds, or 0.3% of a turn. The
rest is model inference.

Letting each Agent take its own turns, and choose its own counterparty from
whoever is offering, changes what the run can show: a seller can be picked by
several buyers or by none, and throughput follows how fast Agents actually
decide. It also introduced three defects worth recording, because each one
looked like something else.

**Locks must be released by defer.** The campaign helpers report failure with
`t.Fatal`, which unwinds through `runtime.Goexit`: deferred calls run, the
statements after the call do not. Releasing an Agent's lock inline therefore
strands it the first time a job fails that way, and every buyer that needs
either side blocks behind it forever. The symptom is a process with every
thread asleep, no CPU, and no network — which reads as a hang somewhere else
entirely.

**A refusal is an answer, not a retry signal.** Removing the paced schedule
removed the only thing limiting how often a buyer was asked. An Agent whose
portfolio capacity is full refuses in milliseconds, so the loop asked again
immediately: one run produced 11,516 refusals against 8 trades, at 212% CPU,
writing a 9.5 MB report that buried the trades that did happen. Refusals need
a backoff, and an Agent that refuses several times in a row has finished
trading for that run.

**Check which test reads the flag.** The concurrent driver is selected by an
environment variable, and there are two similarly named campaign tests. Adding
the switch to the one that does not run costs a full startup to discover,
because the symptom — one turn, then a process sitting quietly in the other
loop's timer — is indistinguishable from the deadlock above.

## Monitoring that would have caught these

All three defects, and the earlier configuration failures, ran with the
service reporting `active`. Liveness is not health here. What distinguishes a
working run from each observed failure:

| Signal | Threshold | Catches |
|---|---|---|
| No turns in five minutes, CPU under 5%, running over ten minutes | stall | deadlock; driver never invoked |
| Over fifty turns in five minutes with under 5% settling | spin | refusal storm |
| CPU above 150% | runaway | refusal storm |
| Report file above 5 MB | bloat | refusal storm |
| Over thirty minutes with turns but no settlement | dead market | payment path broken |
| Any block-hash disagreement between the three nodes | fork | consensus |

The report threshold matters: the observed failure wrote 9.5 MB, so a 20 MB
limit would not have fired. Set thresholds from what a real failure produced,
not from what seems large.

One more trap: a health check that reads `journalctl --since '-10 min'`
straddles a restart and reports the previous run's counters. Anchor it to the
service's own `ActiveEnterTimestamp` and cross-check its numbers once against
a direct count before trusting it.
