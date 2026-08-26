package earning

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

func TestRelayTerminalAccountingCommitAndHandoffAreCrashIdempotent(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	attempt := fixture.attempt(t)
	profileDigest, err := agentrelay.RelayServiceProfileDigest(fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	provenance := RelayProviderProvenance{ProviderAgentID: fixture.profile.ProviderAgentID,
		IntentDigest: fixture.verified.IntentDigest(), ProfileDigest: profileDigest,
		OperatorDomain: "operator:test", FailureDomain: "failure:test", EndpointOrigin: "https://relay.example",
		CertificatePinDigest: relayTestDigest("1"), ImplementationEvidenceHash: relayTestDigest("2")}
	routeDirectory := filepath.Join(t.TempDir(), "routes")
	accountingDirectory := filepath.Join(t.TempDir(), "accounting")
	for _, directory := range []string{routeDirectory, accountingDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	routes, err := OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	accounting, err := OpenDurableRelayTerminalAccountingJournal(accountingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := routes.Bind(fixture.prepared, []RelayProviderProvenance{provenance}, provenance,
		attempt, 1, fixture.now)
	if err == nil {
		// Bind intentionally requires independent decentralized candidates; this
		// lower-scoped test uses the dedicated one-provider dispatch fence.
		t.Fatal("decentralized Bind unexpectedly accepted one Provider")
	}
	record, _, err = routes.BindSingle(fixture.prepared, provenance, attempt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, _ := agentrelay.RelayExecutionRequestDigest(attempt.Execution)
	if record, err = routes.MarkSubmitStarted(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	resolution, evidence := relayTerminalAbsent(t, fixture, attempt.Execution)
	result := RelayExecutionResult{Resolution: resolution, Evidence: &evidence}
	if record, err = routes.RecordTerminal(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, result, fixture.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	reference, err := RelayTerminalHandoffReferenceForRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := accounting.CommitRelayTerminalHandoff(context.Background(), reference,
		attempt, result, fixture.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	report, found, err := accounting.RelayTerminalFinancialReport(reference.StableActionID)
	if err != nil || !found || report.AccountingReceiptDigest != receipt.ReceiptDigest ||
		report.AccountingRevision != receipt.Revision ||
		report.RelayObligationID != attempt.Execution.RelayObligationID ||
		report.SponsorshipObligationID != "" ||
		!reflect.DeepEqual(report.FeeObligationIDs, attempt.Execution.FeeObligationIDs) ||
		report.RelayFulfillment != RelayComponentUnfulfilled ||
		report.SponsorshipFulfillment != RelayComponentNotApplicable ||
		len(report.FeeAccounting) != 1 || report.FeeAccounting[0].Status != RelayFeeNotDue ||
		!report.ClientFeeReservationReleased || report.ClientSponsorshipReservationReleased ||
		report.ProviderSponsorshipDisposition != RelaySponsorshipNotApplicable {
		t.Fatalf("terminal accounting report lost its exact obligation projection: found=%v report=%+v err=%v",
			found, report, err)
	}
	replayed, err := accounting.CommitRelayTerminalHandoff(context.Background(), reference,
		attempt, result, fixture.now.Add(20*time.Second))
	if err != nil || !reflect.DeepEqual(receipt, replayed) {
		t.Fatalf("accounting retry changed its durable receipt: first=%+v replay=%+v err=%v", receipt, replayed, err)
	}
	ack := RelayTerminalHandoffAcknowledgement{Reference: reference,
		AccountingReceiptDigest: receipt.ReceiptDigest, AccountingRevision: receipt.Revision,
		AcknowledgedAt: time.Unix(int64(receipt.RecordedAtUnix), 0).UTC()}
	if err := routes.AcknowledgeTerminalHandoff(ack); err != nil {
		t.Fatal(err)
	}
	markerPath, err := routes.terminalArtifactHandoffPath(reference.ProtectedArtifactDigest, false)
	if err != nil || os.Remove(markerPath) != nil {
		t.Fatalf("simulate crash before handoff sidecar: %v", err)
	}
	// The retry wall clock is deliberately different. Receipt+revision are the
	// idempotency identity; the tombstone restores the original ACK timestamp.
	ack.AcknowledgedAt = fixture.now.Add(time.Hour)
	if err := routes.AcknowledgeTerminalHandoff(ack); err != nil {
		t.Fatalf("crash retry did not reconstruct exact handoff sidecar: %v", err)
	}
	if err := accounting.Close(); err != nil {
		t.Fatal(err)
	}
	accounting, err = OpenDurableRelayTerminalAccountingJournal(accountingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err = accounting.CommitRelayTerminalHandoff(context.Background(), reference,
		attempt, result, fixture.now.Add(2*time.Hour))
	if err != nil || !reflect.DeepEqual(receipt, replayed) {
		t.Fatalf("accounting restart changed its receipt: first=%+v replay=%+v err=%v", receipt, replayed, err)
	}
	if err := routes.AcknowledgeTerminalHandoff(RelayTerminalHandoffAcknowledgement{Reference: reference,
		AccountingReceiptDigest: relayTestDigest("f"), AccountingRevision: receipt.Revision,
		AcknowledgedAt: fixture.now.Add(3 * time.Hour)}); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("conflicting accounting receipt replaced terminal handoff: %v", err)
	}
	_ = accounting.Close()
	_ = routes.Close()
}

func TestRelayTerminalAccountingBindsExactTerminalFailoverHop(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	hopA := cloneRelayAttempt(harness.plan.Attempt)
	hopADigest, err := agentrelay.RelayExecutionRequestDigest(hopA.Execution)
	if err != nil {
		t.Fatal(err)
	}
	harness.preparePending(t, true)
	harness.takeover(t)
	accepted, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{})
	if err != nil || accepted.Resolution.Body.State != commerce.ActionAccepted {
		t.Fatalf("successor route did not become the current submitted hop: state=%s err=%v",
			accepted.Resolution.Body.State, err)
	}
	route, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	hopB, found := route.Current()
	if !found || len(route.Hops) != 2 || hopB.Generation != 2 ||
		hopB.Provider.ProviderAgentID != harness.second.profile.ProviderAgentID ||
		hopB.RelayExecutionDigest == hopADigest {
		t.Fatalf("terminal test route did not advance to an independent second hop: %+v", route)
	}
	resolution, evidence := relayTerminalAbsent(t, harness.second, hopB.Attempt.Execution)
	result := RelayExecutionResult{Resolution: resolution, Evidence: &evidence}
	route, err = harness.routes.RecordTerminal(route.StableActionID, route.ExactRequestDigest,
		hopB.Generation, hopB.RelayExecutionDigest, result, harness.clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	reference, err := RelayTerminalHandoffReferenceForRecord(route)
	if err != nil {
		t.Fatal(err)
	}
	if reference.RelayExecutionDigest != hopB.RelayExecutionDigest ||
		reference.ProviderAgentID != hopB.Provider.ProviderAgentID || reference.RouteGeneration != hopB.Generation ||
		reference.TerminalResolutionDigest != route.Hops[1].TerminalResolutionDigest {
		t.Fatalf("handoff reference did not bind the exact terminal hop: %+v", reference)
	}

	accountingDirectory := filepath.Join(t.TempDir(), "accounting")
	if err := os.Mkdir(accountingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	accounting, err := OpenDurableRelayTerminalAccountingJournal(accountingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accounting.Close() })

	// A valid terminal result from hop B cannot be paired with hop A's
	// Agreement/execution, even though the underlying semantic action identity
	// is intentionally stable across both attempts.
	if _, err := accounting.CommitRelayTerminalHandoff(t.Context(), reference,
		hopA, result, harness.clock.Add(2*time.Second)); err == nil {
		t.Fatal("hop A attempt was accounted against hop B terminal evidence")
	}
	substituted := reference
	substituted.RelayExecutionDigest = hopADigest
	substituted.ProviderAgentID = hopA.Execution.ProviderQuote.Body.ProviderAgentID
	substituted.RouteGeneration = 1
	if _, err := accounting.CommitRelayTerminalHandoff(t.Context(), substituted,
		hopA, result, harness.clock.Add(2*time.Second)); err == nil {
		t.Fatal("hop A reference substitution accepted hop B terminal evidence")
	}
	if _, found, err := accounting.RelayTerminalFinancialReport(reference.StableActionID); err != nil || found {
		t.Fatalf("rejected cross-hop input created an accounting record: found=%v err=%v", found, err)
	}

	receipt, err := accounting.CommitRelayTerminalHandoff(t.Context(), reference,
		hopB.Attempt, result, harness.clock.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := accounting.CommitRelayTerminalHandoff(t.Context(), reference,
		hopB.Attempt, result, harness.clock.Add(time.Hour))
	if err != nil || !reflect.DeepEqual(receipt, replayed) {
		t.Fatalf("exact terminal-hop replay changed the accounting receipt: first=%+v replay=%+v err=%v",
			receipt, replayed, err)
	}
	report, found, err := accounting.RelayTerminalFinancialReport(reference.StableActionID)
	if err != nil || !found || report.RelayExecutionDigest != hopB.RelayExecutionDigest ||
		report.ProviderAgentID != hopB.Provider.ProviderAgentID || report.RouteGeneration != hopB.Generation ||
		report.TerminalResolutionDigest != reference.TerminalResolutionDigest {
		t.Fatalf("accounting report lost terminal-hop identity: found=%v report=%+v err=%v", found, report, err)
	}

	badAcknowledgement := RelayTerminalHandoffAcknowledgement{Reference: substituted,
		AccountingReceiptDigest: receipt.ReceiptDigest, AccountingRevision: receipt.Revision,
		AcknowledgedAt: time.Unix(int64(receipt.RecordedAtUnix), 0).UTC()}
	if err := harness.routes.AcknowledgeTerminalHandoff(badAcknowledgement); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("route tombstone accepted a cross-hop accounting acknowledgement: %v", err)
	}
	badAcknowledgement.Reference = reference
	if err := harness.routes.AcknowledgeTerminalHandoff(badAcknowledgement); err != nil {
		t.Fatalf("route tombstone rejected the exact terminal-hop acknowledgement: %v", err)
	}
}

func TestRelayTerminalAccountingProjectsAllCombinedFulfillmentQuadrants(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorAndRelay)
	attempt := fixture.attempt(t)
	cases := []struct {
		name        string
		outcome     agentrelay.TerminalOutcome
		relay       RelayComponentFulfillment
		sponsorship RelayComponentFulfillment
		disposition RelaySponsorshipFinancialDisposition
	}{
		{name: "both-fulfilled", outcome: agentrelay.OutcomeCorroboratedSuccess,
			relay: RelayComponentFulfilled, sponsorship: RelayComponentFulfilled,
			disposition: RelaySponsorshipReimbursementUnresolved},
		{name: "sponsorship-only", outcome: agentrelay.OutcomeCorroboratedSponsorshipOnly,
			relay: RelayComponentUnfulfilled, sponsorship: RelayComponentFulfilled,
			disposition: RelaySponsorshipReimbursementUnresolved},
		{name: "relay-only", outcome: agentrelay.OutcomeCorroboratedRelayOnly,
			relay: RelayComponentFulfilled, sponsorship: RelayComponentUnfulfilled,
			disposition: RelaySponsorshipNotIncurred},
		{name: "neither-fulfilled", outcome: agentrelay.OutcomeCorroboratedAbsent,
			relay: RelayComponentUnfulfilled, sponsorship: RelayComponentUnfulfilled,
			disposition: RelaySponsorshipNotIncurred},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			relay, sponsorship, err := relayTerminalComponentFulfillment(
				agentrelay.ModeSponsorAndRelay, test.outcome)
			if err != nil || relay != test.relay || sponsorship != test.sponsorship {
				t.Fatalf("wrong component projection: relay=%s sponsorship=%s err=%v", relay, sponsorship, err)
			}
			disposition, err := relaySponsorshipFinancialDisposition(sponsorship)
			if err != nil || disposition != test.disposition {
				t.Fatalf("wrong Provider sponsorship disposition: disposition=%s err=%v", disposition, err)
			}
			fees, err := relayTerminalFeeAccountingForAttempt(attempt, relay, sponsorship)
			if err != nil || len(fees) != 2 {
				t.Fatalf("fee projection failed: fees=%+v err=%v", fees, err)
			}
			for _, fee := range fees {
				expected := RelayFeeNotDue
				if fee.Kind == agentrelay.ObligationRelayFee && relay == RelayComponentFulfilled ||
					fee.Kind == agentrelay.ObligationSponsorshipFee && sponsorship == RelayComponentFulfilled {
					expected = RelayFeeDue
				}
				if fee.Status != expected {
					t.Fatalf("fee %s/%s had status %s, want %s", fee.ObligationID, fee.Kind, fee.Status, expected)
				}
			}
		})
	}

	mutated := attempt
	mutated.Execution.ProviderQuote.Body.FeeLines = append([]agentrelay.FeeLine(nil),
		attempt.Execution.ProviderQuote.Body.FeeLines...)
	mutated.Agreement.Body.Obligations = append([]commerce.AgreementObligation(nil),
		attempt.Agreement.Body.Obligations...)
	feeID := mutated.Execution.FeeObligationIDs[0]
	originalFeeKind := ""
	for index := range mutated.Agreement.Body.Obligations {
		if mutated.Agreement.Body.Obligations[index].ObligationID == feeID {
			originalFeeKind = mutated.Agreement.Body.Obligations[index].Kind
			mutated.Agreement.Body.Obligations[index].Kind = "unknown_fee_semantic"
		}
	}
	for index := range mutated.Execution.ProviderQuote.Body.FeeLines {
		if mutated.Execution.ProviderQuote.Body.FeeLines[index].Kind == originalFeeKind {
			mutated.Execution.ProviderQuote.Body.FeeLines[index].Kind = "unknown_fee_semantic"
		}
	}
	if _, err := relayTerminalFeeAccountingForAttempt(mutated,
		RelayComponentFulfilled, RelayComponentFulfilled); err == nil {
		t.Fatal("unknown fee semantics were silently projected")
	}
	if err := relayTerminalServiceObligationsMatchAttempt(attempt); err != nil {
		t.Fatalf("valid exact service-obligation projection was rejected: %v", err)
	}
	mutated = cloneRelayAttempt(attempt)
	for index := range mutated.Agreement.Body.Obligations {
		if mutated.Agreement.Body.Obligations[index].ObligationID == mutated.Execution.RelayObligationID {
			mutated.Agreement.Body.Obligations[index].Subject = []byte("unrelated-service-binding")
		}
	}
	if err := relayTerminalServiceObligationsMatchAttempt(mutated); err == nil {
		t.Fatal("accounting accepted a relay-delivery obligation detached from the exact Agreement binding")
	}
}
