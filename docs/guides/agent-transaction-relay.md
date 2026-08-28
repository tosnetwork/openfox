# Agent Transaction Relay Assurance

OpenFox treats a relay service mode and its assurance level as independent
configuration dimensions:

| Service mode | Side effects |
|---|---|
| `relay_exact` | Submit the exact owner-authorized signed transaction bytes. |
| `sponsor_only` | Execute the Agreement-bound gas sponsorship obligation. |
| `sponsor_and_relay` | Execute sponsorship and then submit the exact transaction. |

| Assurance level | Operational guarantee |
|---|---|
| `trusted-local` | One explicitly trusted route. All transaction, network, action, fee, journal, and unknown-outcome checks still apply. |
| `authorized-single-provider` | One authenticated, SPKI-pinned Provider route with signed Intent, Quote, Agreement, admission, and resolution evidence. |
| `autonomous-decentralized` | At least two independently discovered and attested Providers, durable owner-wide routing, bounded attempts, and independently retrievable rollback-resistant finality evidence. |

Set the level explicitly in the owner-controlled earning configuration:

```json
{
  "earning": {
    "gates": {
      "agent_relay": true,
      "agreement": true,
      "execution": true
    },
    "agent_relay": {
      "enabled": true,
      "role": "client",
      "assurance_level": "authorized-single-provider",
      "client_attempt_journal_directory": "/var/lib/openfox/relay-attempts",
      "client_route_journal_directory": "/var/lib/openfox/relay-routes",
      "client_terminal_accounting_directory": "/var/lib/openfox/relay-terminal-accounting"
    }
  }
}
```

The remaining network, signed profile, TLS, provenance, journal, fee, and
admission fields are mandatory and are validated by `EarningSettings.Validate`.
Sponsorship additionally requires the direct-payment custody gate.

## Readiness semantics

OpenFox does not use a global "production accepted" flag:

- A pair is enabled as soon as the owner-selected concrete dependencies for
  that pair are present. No campaign count, deployment age, production-history
  certificate, or unrelated mode is a prerequisite.

- `openfox earning relay client-check` verifies the configured network,
  signed profile, mTLS identity, SPKI provenance, and durable transport
  journals. It reports `transport_ready`; it does not claim execution
  readiness.
- `openfox earning relay provider-check` verifies owner configuration, signed
  profile, pricing, TLS material, and the pinned network. It reports
  `configuration_ready`; the Provider runtime checks actual service objects
  when it opens.
- `PlanRelayClientCapability` and `PlanRelayProviderCapabilities` return the
  exact ready or missing `(mode, assurance_level)` pairs.
- `EnableRelayClient` returns the operational client gate only when the
  coordinator that will execute the transaction supplies every dependency for
  that pair.
- `OpenRelayProviderHTTPRuntime` takes an explicit `EnabledModes` subset. A
  missing sponsorship dependency blocks only sponsorship pairs and cannot
  disable a complete `relay_exact` pair. The HTTP boundary rejects a request
  that changes the selected mode or assurance level.

`autonomous-decentralized` sponsorship uses two-Provider quote competition and
selection, but V1 does not fail over after an ambiguous sponsorship. Only
`autonomous-decentralized + relay_exact` supports successor-route failover,
because every successor submits the same immutable signed BOC. A sponsorship
successor remains disabled until absence of the exact top-up can be proven.

Sponsorship readiness is evidence-specific. `trusted-local` and
`authorized-single-provider` may use either validator-finalized top-up evidence
or an owner-enabled, bounded RPC-corroboration adapter. RPC corroboration first
produces the explicit nonterminal `observed_unproven` state. For
`sponsor_and_relay`, the Provider must freshly recheck the credited balance,
source sequence, transaction expiry, and every signed authorization before it
may broadcast the byte-exact client transaction. The observation never
recognizes revenue, releases sponsorship exposure, reports validator finality,
or permits a replacement top-up.

The lower-assurance terminal predicate is explicit rather than inferred from
`observed_unproven`. The signed request, Quote, and Agreement must select the
exact finality profile URI
`tos.sponsorship.client-corroborated-terminal.v1` and its canonical digest.
After the requester independently re-queries its own frozen RPC quorum, the
top-up may become `corroborated_terminal` with evidence class
`client_corroborated`. The truthful terminal outcomes are
`corroborated_sponsorship_only` or, when the client transaction separately has
either validator finality or the exact pre-authorized
`provider_corroborated` terminal evidence,
`corroborated_success`. The combined outcome is selected from both signed
component evidence classes, never inferred from the service mode alone. They never become
`finalized_sponsorship_only` or `finalized_success`, and they never satisfy
`autonomous-decentralized`.

The corroboration adapter is ready only when the concrete custody path supplies
all of the following:

- an immutable Provider snapshot for the initial observation and recovery;
- a typed Provider terminal producer that attaches the bounded canonical proof
  bundle;
- a distinct requester-owned snapshot frozen before Quote/admission;
- an independent requester re-query verifier for the exact payment, source
  account/sequence/expiry, signed BOC, destination credit, quorum winner, and
  signed terminal profile.

The shipped `tosctl` adapter supplies the observation, frozen-snapshot,
corroborated-terminal, scoped absence-producer, and requester re-query seams.
Those library components enable a lower-assurance sponsorship pair only when
the application constructs the complete Provider processor and requester
composite verifier and the no-side-effect capability preflight succeeds for
the exact signed tuple. The diagnostic `client-check` and `provider-check`
commands intentionally construct only transport/configuration state and do
not claim that execution wiring exists. OpenFox never turns an available
binary command or a partial adapter into a ready pair. Provider and requester
snapshot identities may differ because they bind private credentials and
configuration bytes, but both must reproduce the same signed release
descriptor, network, endpoints, operator provenance, and threshold. A merely
self-consistent or Provider-signed proof bundle is insufficient without the
requester-owned re-query. `autonomous-decentralized` rejects this RPC-only
terminal class and instead requires independently verifiable,
validator-authenticated portable sponsorship proof.

Every client relay attempt also carries an immutable client finality snapshot
frozen before Quote. Restart recovery verifies the old attempt against that
snapshot, not against the current endpoint configuration; rotating from
configuration A to B affects only new Quotes. Missing, mutated, or
capability-mismatched snapshots fail closed. Verified terminal routes are
compacted from the bounded active journal into small owner-private, sharded
lifetime tombstones. The complete BOC, Agreement and proof artifact is kept in
a separately content-addressed bounded recovery cache. It is not evictable
until the independent terminal-accounting journal durably commits the exact
mode, assurance, Agreement, fee/sponsorship deltas, outcome, artifact digest,
and evidence digest, and returns an idempotent receipt plus monotonic revision.
The route tombstone then binds that receipt before archival. A crash before
the accounting commit, or between commit and acknowledgement, replays the same
record and retains the full artifact. Active routes and unacknowledged terminal
artifacts reserve bounded recovery capacity before the first Provider side
effect. Thus completed and accounted business does not exhaust a lifetime
route count, sensitive full artifacts do not accumulate without bound, and an
old stable action can never be rebound after archival.

Provider sponsorship recovery follows the same action-local rule. Its
protected snapshot freezes the owner-private evidence-registry root, custody
wallet namespace, Provider source account, complete network domain, manifest,
and referenced configuration files. A restarted process may use configuration
B for new Quotes, but an action admitted under configuration A resolves only
through A's frozen locators and custody identity. Current process defaults
cannot redirect an old action; missing frozen material leaves it ambiguous and
never authorizes a replacement top-up.

The shipped owner-private file Authority, Provider journal, route journal, and
terminal-accounting journal
are crash-durable and process-locked, so they are valid concrete dependencies
for `trusted-local` and `authorized-single-provider`. They deliberately report
that they are not rollback-resistant: restoring an old filesystem snapshot
could erase an admission, exposure, route-head, or `submit_started` high-water.
Consequently they never enable an `autonomous-decentralized` pair. An external
monotonic implementation can enable that level only when the actual admission,
Provider-journal, route-journal, and terminal-accounting objects implement the corresponding
linearizable and rollback-resistant capability interfaces; a detached status
boolean cannot upgrade a local journal.

No assurance level relaxes exact BOC, complete TOS network-domain, underlying
action, Agreement, Writer Fence, fee ceiling, durable admission, or ambiguous
outcome handling. Lower assurance means fewer liveness and independent-proof
guarantees, not permission to spend or mutate a transaction without authority.
