package earning

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

type relayCapabilitySponsorshipResolver struct {
	capabilities             RelaySponsorshipEvidenceCapabilities
	unsupportedProfileDigest string
}

type relayCapabilityModeEvidenceSource struct {
	delegate                          agentrelay.IndependentFinalityEvidenceSource
	modes                             map[agentrelay.Mode]bool
	rejectSponsorshipComponentAbsence bool
	rejectTransactionComponentAbsence bool
}

type relayCapabilityAutonomousProviderJournal struct{ agentrelay.Journal }

func (relayCapabilityAutonomousProviderJournal) HasLinearizableRelayProviderJournal() bool {
	return true
}

func (relayCapabilityAutonomousProviderJournal) HasRollbackResistantRelayProviderJournalHighWater() bool {
	return true
}

type relayCapabilityAutonomousRouteJournal struct{ *DurableRelayRouteJournal }

func (relayCapabilityAutonomousRouteJournal) HasRollbackResistantRelayRouteHighWater() bool {
	return true
}

type relayCapabilityAutonomousTerminalAccounting struct {
	*DurableRelayTerminalAccountingJournal
}

func (relayCapabilityAutonomousTerminalAccounting) HasRollbackResistantRelayTerminalAccountingHighWater() bool {
	return true
}

func relayCapabilityTerminalAccounting(t *testing.T) *DurableRelayTerminalAccountingJournal {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "relay-terminal-accounting")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayTerminalAccountingJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func relayCapabilitySingleDependencies(t *testing.T,
	coordinator *RelayCoordinator) RelayClientCapabilityDependencies {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "single-owner-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routes.Close() })
	return RelayClientCapabilityDependencies{SingleProvider: coordinator,
		SingleProviderRouteJournal: routes,
		SingleProviderProvenance:   relayCapabilityProvenance(t, *coordinator)[0],
		TerminalAccounting:         relayCapabilityTerminalAccounting(t)}
}

func (source relayCapabilityModeEvidenceSource) Evidence(ctx context.Context,
	record agentrelay.Record) (agentrelay.RelayFinalityEvidenceBody, error) {
	return source.delegate.Evidence(ctx, record)
}

func (source relayCapabilityModeEvidenceSource) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	return source.modes[capability.Mode] && source.delegate.SupportsRelayEvidenceCapability(capability)
}

func (source relayCapabilityModeEvidenceSource) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return source.modes[capability.Mode] && source.delegate.SupportsRelayDualAbsenceEvidence(capability)
}

func (source relayCapabilityModeEvidenceSource) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return !source.rejectSponsorshipComponentAbsence && source.modes[capability.Mode] &&
		source.delegate.SupportsRelaySponsorshipComponentAbsenceEvidence(capability)
}

func (source relayCapabilityModeEvidenceSource) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return !source.rejectTransactionComponentAbsence && source.modes[capability.Mode] &&
		source.delegate.SupportsRelayTransactionComponentAbsenceEvidence(capability)
}

func (source relayCapabilityModeEvidenceSource) HasRetrievableIndependentProofs() bool {
	return source.delegate.HasRetrievableIndependentProofs()
}

func (source relayCapabilityModeEvidenceSource) HasRollbackResistantCheckpoint() bool {
	return source.delegate.HasRollbackResistantCheckpoint()
}

func (source relayCapabilityModeEvidenceSource) HasRollbackResistantTerminalCommitment() bool {
	return source.delegate.HasRollbackResistantTerminalCommitment()
}

func (resolver relayCapabilitySponsorshipResolver) ResolveRelaySponsorshipEvidence(context.Context,
	agentrelay.RelayExecutionRequest, commerce.AgreementPaymentRequest) (agentrelay.SponsorshipResolution, error) {
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}, nil
}

func (resolver relayCapabilitySponsorshipResolver) RelaySponsorshipEvidenceCapabilities() RelaySponsorshipEvidenceCapabilities {
	return resolver.capabilities
}

func (resolver relayCapabilitySponsorshipResolver) SupportsRelaySponsorshipTerminalFinalityProfile(
	profile agentrelay.FinalityProfile, _ *RelaySponsorshipEvidenceSnapshot) bool {
	return resolver.unsupportedProfileDigest == "" || profile.ProfileDigest != resolver.unsupportedProfileDigest
}

func (relayCapabilitySponsorshipResolver) PrepareRecovery(context.Context, agentrelay.RelayExecutionRequest,
	commerce.AgentAgreement, commerce.AgreementObligation) (agentrelay.SponsorshipRecoveryHandle, error) {
	return agentrelay.SponsorshipRecoveryHandle{}, nil
}

func (relayCapabilitySponsorshipResolver) EnsureFinalized(context.Context, agentrelay.RelayExecutionRequest,
	commerce.AgentAgreement, commerce.AgreementObligation,
	agentrelay.SponsorshipRecoveryHandle) (agentrelay.SponsorshipResolution, error) {
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}, nil
}

func (relayCapabilitySponsorshipResolver) ResolveFinalized(context.Context, agentrelay.RelayExecutionRequest,
	agentrelay.SponsorshipRecoveryHandle) (agentrelay.SponsorshipResolution, error) {
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}, nil
}

func (relayCapabilitySponsorshipResolver) ResolveRelayDualAbsence(context.Context,
	agentrelay.RelayExecutionRequest, agentrelay.SponsorshipRecoveryHandle,
	[]agentrelay.RelayAbsenceObservationReference, string, []byte) (agentrelay.SponsorshipResolution, error) {
	return agentrelay.SponsorshipResolution{Status: agentrelay.SponsorshipResolutionUnknown}, nil
}

func (relayCapabilitySponsorshipResolver) ResolveRelayTransactionAbsence(context.Context,
	agentrelay.RelayExecutionRequest, agentrelay.SponsorshipRecoveryHandle,
	agentrelay.TerminalOutcome) (agentrelay.ChainResolution, error) {
	return agentrelay.ChainResolution{}, nil
}

func (relayCapabilitySponsorshipResolver) VerifyRelaySponsorshipCreditObservation(context.Context,
	agentrelay.RelaySponsorshipCreditObservation, agentrelay.RelayExecutionRequest,
	commerce.AgreementPaymentRequest) error {
	return nil
}

func (relayCapabilitySponsorshipResolver) VerifySponsorshipCreditObservation(context.Context,
	agentrelay.RelaySponsorshipCreditObservation, agentrelay.SponsorshipReleaseProfile) error {
	return nil
}

func (relayCapabilitySponsorshipResolver) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func (relayCapabilitySponsorshipResolver) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func (relayCapabilitySponsorshipResolver) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func TestRelayClientCapabilityLevelsAreOperationalAndOrthogonalToMode(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	coordinator := relayTestCoordinator(t, fixture, &relayFunctionTransport{authenticatedResolve: true})
	dependencies := relayCapabilitySingleDependencies(t, &coordinator)
	for _, level := range []agentrelay.AssuranceLevel{
		agentrelay.AssuranceTrustedLocal,
		agentrelay.AssuranceAuthorizedSingleProvider,
	} {
		capability := PlanRelayClientCapability(level, agentrelay.ModeRelayExact, dependencies)
		if !capability.Ready || len(capability.Missing) != 0 {
			t.Fatalf("concrete %s/relay_exact capability was not enabled: %+v", level, capability)
		}
		client, err := EnableRelayClient(level, agentrelay.ModeRelayExact, dependencies)
		got := client.Capability()
		if err != nil || got.Mode != capability.Mode || got.AssuranceLevel != capability.AssuranceLevel ||
			got.Ready != capability.Ready || len(got.Missing) != 0 {
			t.Fatalf("enabled capability differs from its plan: client=%+v err=%v", client, err)
		}
		prepared := fixture.prepared
		prepared.QuoteBody.AssuranceLevel = level
		prepared.QuoteBody.Mode = agentrelay.ModeSponsorOnly
		if _, err := client.Prepare(context.Background(), prepared); err == nil {
			t.Fatal("enabled relay_exact capability accepted a sponsor_only request")
		}
		foreign := fixture.attempt(t)
		if _, err := client.Submit(context.Background(), &EnabledRelayPlan{Single: &foreign}); err == nil {
			t.Fatal("enabled capability accepted an attempt signed for another assurance level")
		}
	}
}

func TestLowerRelayExactLostResponseRestartsFromOwnerRouteAndAccountsOnce(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	var submitted agentrelay.RelayExecutionRequest
	submits, resolves, evidenceCalls := 0, 0, 0
	terminalReady, providerLost := false, false
	transport := relayFunctionTransport{authenticatedResolve: true, quote: service.Quote,
		submit: func(_ context.Context, execution agentrelay.RelayExecutionRequest,
			_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			submitted = execution
			return agentrelay.SignedRelayResolution{}, ErrRelaySubmissionAmbiguous
		},
		resolve: func(_ context.Context, _ agentrelay.ResolveCall,
			execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			resolves++
			if providerLost {
				return agentrelay.SignedRelayResolution{}, errors.New("provider unavailable")
			}
			if !terminalReady {
				return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
			}
			resolution, _ := relayTerminalAbsent(t, fixture, execution)
			return resolution, nil
		},
		evidence: func(_ context.Context, _ agentrelay.EvidenceCall,
			execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			evidenceCalls++
			if providerLost {
				return agentrelay.SignedRelayFinalityEvidence{}, errors.New("provider unavailable")
			}
			_, evidence := relayTerminalAbsent(t, fixture, execution)
			return evidence, nil
		}}
	coordinator := relayTestCoordinator(t, fixture, transport)
	routeDirectory := filepath.Join(t.TempDir(), "lower-relay-routes")
	if err := os.Mkdir(routeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	accounting := relayCapabilityTerminalAccounting(t)
	provenance := relayCapabilityProvenance(t, coordinator)[0]
	dependencies := func() RelayClientCapabilityDependencies {
		return RelayClientCapabilityDependencies{SingleProvider: &coordinator,
			SingleProviderRouteJournal: routes, SingleProviderProvenance: provenance,
			TerminalAccounting: accounting}
	}
	client, err := EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeRelayExact, dependencies())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(t.Context(), plan); !errors.Is(err, ErrRelaySubmissionAmbiguous) || submits != 1 {
		t.Fatalf("lost response was not durably ambiguous: submits=%d err=%v", submits, err)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err = OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	client, err = EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeRelayExact, dependencies())
	if err != nil {
		t.Fatal(err)
	}
	plan, err = client.Prepare(t.Context(), fixture.prepared)
	if err != nil || plan.Single == nil || submitted.SchemaVersion == 0 {
		t.Fatalf("restart lost exact lower relay attempt: plan=%+v err=%v", plan, err)
	}
	terminalReady = true
	result, err := client.Submit(t.Context(), plan)
	if err != nil || result.Evidence == nil || submits != 1 || resolves == 0 || evidenceCalls != 1 {
		t.Fatalf("restart did not query and account exact terminal pair: submits=%d resolves=%d evidence=%d err=%v",
			submits, resolves, evidenceCalls, err)
	}
	report, found, err := accounting.RelayTerminalFinancialReport(
		fixture.prepared.UnderlyingAction.StableActionID)
	if err != nil || !found || report.TerminalOutcome != result.Evidence.Body.Outcome ||
		report.AccountingRevision == 0 {
		t.Fatalf("lower relay terminal result did not reach accounting: found=%v report=%+v err=%v", found, report, err)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	providerLost = true
	routes, err = OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	client, err = EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeRelayExact, dependencies())
	if err != nil {
		t.Fatal(err)
	}
	plan, err = client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := client.Submit(t.Context(), plan)
	if err != nil || replayed.Evidence == nil || submits != 1 || evidenceCalls != 1 {
		t.Fatalf("durable lower relay result required Provider recovery after restart: submits=%d evidence=%d err=%v",
			submits, evidenceCalls, err)
	}
}

func TestRelayAutonomousCapabilityRequiresConcreteDecentralizedCoordinator(t *testing.T) {
	first := newRelayTestFixture(t, "agent:provider-one", nil, "https://relay-one.example")
	second := newRelayTestFixture(t, "agent:provider-two", nil, "https://relay-two.example")
	firstCoordinator := relayTestCoordinator(t, first, &relayFunctionTransport{authenticatedResolve: true})
	secondCoordinator := relayTestCoordinator(t, second, &relayFunctionTransport{authenticatedResolve: true})
	dependencies := RelayClientCapabilityDependencies{SingleProvider: &firstCoordinator}
	capability := PlanRelayClientCapability(agentrelay.AssuranceAutonomousDecentralized,
		agentrelay.ModeRelayExact, dependencies)
	if capability.Ready || !containsRelayMissing(capability.Missing, "decentralized-coordinator") {
		t.Fatalf("single Provider was mislabeled decentralized: %+v", capability)
	}
	directory := filepath.Join(t.TempDir(), "routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	orchestrator := &DecentralizedRelayCoordinator{
		Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator},
		Selector: RelayProviderSelectorFunc(func(context.Context, []RelayQuoteCandidate) (int, error) {
			return 0, nil
		}),
		ProvenanceVerifier: RelayProviderProvenanceVerifierFunc(func(context.Context,
			VerifiedRelayServiceProfile) (RelayProviderProvenance, error) {
			return RelayProviderProvenance{}, nil
		}),
		AgentResolver: first.resolver,
		RouteJournal:  relayCapabilityAutonomousRouteJournal{journal}, MaximumRouteAttempts: 2,
	}
	capability = PlanRelayClientCapability(agentrelay.AssuranceAutonomousDecentralized,
		agentrelay.ModeRelayExact, RelayClientCapabilityDependencies{Decentralized: orchestrator})
	if capability.Ready || !containsRelayMissing(capability.Missing, "independent-provider-provenance") {
		t.Fatalf("a verifier seam without concrete independent provenance was mislabeled ready: %+v", capability)
	}
	dependencies = RelayClientCapabilityDependencies{Decentralized: orchestrator,
		DecentralizedProvenance: relayCapabilityProvenance(t, firstCoordinator, secondCoordinator),
		TerminalAccounting:      relayCapabilityAutonomousTerminalAccounting{relayCapabilityTerminalAccounting(t)}}
	capability = PlanRelayClientCapability(agentrelay.AssuranceAutonomousDecentralized,
		agentrelay.ModeRelayExact, dependencies)
	if !capability.Ready || len(capability.Missing) != 0 {
		t.Fatalf("concrete two-Provider capability was not enabled: %+v", capability)
	}
	if _, err := EnableRelayClient(agentrelay.AssuranceAutonomousDecentralized,
		agentrelay.ModeRelayExact, dependencies); err != nil {
		t.Fatalf("autonomous capability remained blanket-disabled: %v", err)
	}
}

func TestRelayAutonomousCapabilityRejectsRollbackablePersonalAdmissionAuthority(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	coordinator := relayTestCoordinator(t, fixture, &relayFunctionTransport{authenticatedResolve: true})
	coordinator.SideEffectAdmission = &PersonalRelaySideEffectAuthority{}
	missing := relayCoordinatorCapabilityMissing(&coordinator,
		agentrelay.AssuranceAutonomousDecentralized, agentrelay.ModeRelayExact)
	if !containsRelayMissing(missing, "rollback-resistant-side-effect-admission") {
		t.Fatalf("rollbackable personal authority was mislabeled autonomous: %v", missing)
	}
}

func TestRelayAutonomousProviderCapabilityRejectsRollbackableJournal(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	report := PlanRelayProviderCapabilities(service, agentrelay.AssuranceAutonomousDecentralized)
	if report.Ready() || len(report.Capabilities) == 0 ||
		!containsRelayMissing(report.Capabilities[0].Missing, "rollback-resistant-provider-journal") {
		t.Fatalf("rollbackable Provider journal was mislabeled autonomous: %+v", report)
	}
}

func TestRelayAuthorizedCapabilityRejectsGenericUnauthenticatedTransport(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	coordinator := relayTestCoordinator(t, fixture, &relayFunctionTransport{})
	dependencies := relayCapabilitySingleDependencies(t, &coordinator)
	trusted := PlanRelayClientCapability(agentrelay.AssuranceTrustedLocal, agentrelay.ModeRelayExact,
		dependencies)
	authorized := PlanRelayClientCapability(agentrelay.AssuranceAuthorizedSingleProvider, agentrelay.ModeRelayExact,
		dependencies)
	if !trusted.Ready || authorized.Ready ||
		!containsRelayMissing(authorized.Missing, "authenticated-provider-transport") {
		t.Fatalf("transport trust was mislabeled: trusted=%+v authorized=%+v", trusted, authorized)
	}
}

func TestRelayAutonomousSponsorshipUsesDecentralizedSelectionWithoutSuccessorFailover(t *testing.T) {
	first := newRelayTestFixture(t, "agent:sponsor-one", nil, "https://relay-one.example")
	second := newRelayTestFixture(t, "agent:sponsor-two", nil, "https://relay-two.example")
	first.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	second.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	firstCoordinator := relayTestCoordinator(t, first, &relayFunctionTransport{authenticatedResolve: true})
	secondCoordinator := relayTestCoordinator(t, second, &relayFunctionTransport{authenticatedResolve: true})
	directory := filepath.Join(t.TempDir(), "sponsor-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	orchestrator := &DecentralizedRelayCoordinator{Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator},
		Selector: RelayProviderSelectorFunc(func(context.Context, []RelayQuoteCandidate) (int, error) { return 0, nil }),
		ProvenanceVerifier: RelayProviderProvenanceVerifierFunc(func(context.Context,
			VerifiedRelayServiceProfile) (RelayProviderProvenance, error) {
			return RelayProviderProvenance{}, nil
		}),
		AgentResolver: first.resolver, RouteJournal: journal, MaximumRouteAttempts: 2}
	capability := PlanRelayClientCapability(agentrelay.AssuranceAutonomousDecentralized,
		agentrelay.ModeSponsorOnly, RelayClientCapabilityDependencies{Decentralized: orchestrator,
			DecentralizedProvenance:  relayCapabilityProvenance(t, firstCoordinator, secondCoordinator),
			SponsorshipReleasePolicy: firstCoordinator.SponsorshipReleasePolicy})
	if capability.Ready || capability.FailoverEnabled ||
		!containsRelayMissing(capability.Missing, "rollback-resistant-route-journal") {
		t.Fatalf("rollbackable local route journal was mislabeled autonomous sponsorship: %+v", capability)
	}
}

func TestRelayProviderCapabilityOnlyRequiresPortableAnchorsForAutonomousLevel(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	service := fixture.service(relayCapabilityAutonomousProviderJournal{agentrelay.NewMemoryJournal()},
		&relayTestBroadcaster{})
	service.EvidenceSource = relayNonPortableEvidenceSource{relayTestEvidenceSource{now: fixture.now}}
	for _, level := range []agentrelay.AssuranceLevel{
		agentrelay.AssuranceTrustedLocal,
		agentrelay.AssuranceAuthorizedSingleProvider,
	} {
		report := PlanRelayProviderCapabilities(service, level)
		if !report.Ready() {
			t.Fatalf("%s was gated on autonomous-only proof anchors: %+v", level, report)
		}
	}
	report := PlanRelayProviderCapabilities(service, agentrelay.AssuranceAutonomousDecentralized)
	if report.Ready() || !containsRelayMissing(report.Capabilities[0].Missing, "retrievable-independent-proofs") {
		t.Fatalf("autonomous capability accepted local-only evidence: %+v", report)
	}
}

func TestRelayProviderSponsorshipCapabilityUsesExactAssuranceEvidenceDisjunction(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorAndRelay)
	service := fixture.service(relayCapabilityAutonomousProviderJournal{agentrelay.NewMemoryJournal()},
		&relayTestBroadcaster{})

	observedPolicy := RelaySponsorshipReleasePolicy{EvidenceClass: agentrelay.SponsorshipReleaseObservedUnproven,
		ProfileURI: agentrelay.RPCCorroborationEvidenceProfileURI, ProfileDigest: relayTestDigest("6")}
	finalizedPolicy := RelaySponsorshipReleasePolicy{EvidenceClass: agentrelay.SponsorshipReleaseValidatorFinality,
		ProfileURI: fixture.finality.ProfileURI, ProfileDigest: fixture.finality.ProfileDigest}
	setCapabilities := func(capabilities RelaySponsorshipEvidenceCapabilities) {
		resolver := relayCapabilitySponsorshipResolver{capabilities: capabilities}
		service.Sponsorship = resolver
		service.SponsorshipObservationVerifier = resolver
	}
	setCapabilities(RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{observedPolicy},
		FreshBalanceSequenceRecheck: true, TerminalEvidence: true})
	for _, level := range []agentrelay.AssuranceLevel{
		agentrelay.AssuranceTrustedLocal,
		agentrelay.AssuranceAuthorizedSingleProvider,
	} {
		report := PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service, level, observedPolicy)
		if !report.Ready() {
			t.Fatalf("%s did not enable bounded observed sponsorship with a fresh recheck: %+v", level, report)
		}
	}
	report := PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service,
		agentrelay.AssuranceAutonomousDecentralized, observedPolicy)
	if report.Ready() ||
		!containsRelayMissing(report.Capabilities[0].Missing, "owner-sponsorship-release-policy") {
		t.Fatalf("autonomous sponsorship accepted nonportable RPC corroboration: %+v", report)
	}

	setCapabilities(RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{observedPolicy},
		TerminalEvidence: true})
	report = PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service,
		agentrelay.AssuranceAuthorizedSingleProvider, observedPolicy)
	if report.Ready() ||
		!containsRelayMissing(report.Capabilities[0].Missing, "fresh-sponsorship-balance-sequence-recheck") {
		t.Fatalf("observed sponsorship without a fresh balance/sequence recheck was enabled: %+v", report)
	}

	setCapabilities(RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{finalizedPolicy},
		TerminalEvidence: true})
	report = PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service,
		agentrelay.AssuranceAuthorizedSingleProvider, finalizedPolicy)
	if !report.Ready() {
		t.Fatalf("exact finalized sponsorship evidence remained blanket-disabled: %+v", report)
	}

	setCapabilities(RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{finalizedPolicy},
		TerminalEvidence: true, PortableFinalityEvidence: true})
	report = PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service,
		agentrelay.AssuranceAutonomousDecentralized, finalizedPolicy)
	if !report.Ready() {
		t.Fatalf("portable finalized autonomous sponsorship remained blanket-disabled: %+v", report)
	}
}

func TestRelayProviderRequiresModeQualifiedTerminalEvidenceAtEveryAssurance(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	service := fixture.service(agentrelay.NewMemoryJournal(), nil)
	observedPolicy := RelaySponsorshipReleasePolicy{EvidenceClass: agentrelay.SponsorshipReleaseObservedUnproven,
		ProfileURI: agentrelay.RPCCorroborationEvidenceProfileURI, ProfileDigest: relayTestDigest("6")}
	resolver := relayCapabilitySponsorshipResolver{
		capabilities: RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{observedPolicy},
			FreshBalanceSequenceRecheck: true, TerminalEvidence: true},
	}
	service.Sponsorship = resolver
	service.SponsorshipObservationVerifier = resolver
	service.EvidenceSource = relayCapabilityModeEvidenceSource{delegate: relayTestEvidenceSource{now: fixture.now},
		modes: map[agentrelay.Mode]bool{agentrelay.ModeRelayExact: true}}
	report := PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service, agentrelay.AssuranceTrustedLocal, observedPolicy)
	if report.Ready() || !containsRelayMissing(report.Capabilities[0].Missing, "exact-finality-evidence-capability") {
		t.Fatalf("sponsorship was enabled with an exact-relay-only terminal evidence source: %+v", report)
	}
	service.EvidenceSource = relayCapabilityModeEvidenceSource{delegate: relayTestEvidenceSource{now: fixture.now},
		modes: map[agentrelay.Mode]bool{agentrelay.ModeSponsorOnly: true}}
	report = PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service, agentrelay.AssuranceTrustedLocal, observedPolicy)
	if !report.Ready() {
		t.Fatalf("mode-qualified lower-assurance sponsorship remained disabled: %+v", report)
	}
}

func TestRelayProviderSponsorshipRejectsAnySelectableUnsupportedFinalityProfile(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	unsupported := fixture.sponsorshipFinality
	unsupported.ProfileDigest = relayTestDigest("8")
	unsupported.MinimumConfirmationDepth++
	fixture.profile.FinalityProfiles = append(fixture.profile.FinalityProfiles, unsupported)
	service := fixture.service(agentrelay.NewMemoryJournal(), nil)
	policy := relaySponsorshipReleasePolicyFromRequest(fixture.prepared.QuoteBody)
	resolver := relayCapabilitySponsorshipResolver{unsupportedProfileDigest: unsupported.ProfileDigest,
		capabilities: RelaySponsorshipEvidenceCapabilities{SupportedReleasePolicies: []RelaySponsorshipReleasePolicy{policy},
			FreshBalanceSequenceRecheck: true, TerminalEvidence: true}}
	service.Sponsorship = resolver
	report := PlanRelayProviderCapabilitiesWithSponsorshipPolicy(service,
		agentrelay.AssuranceAuthorizedSingleProvider, policy)
	if report.Ready() || len(report.Capabilities) == 0 ||
		!containsRelayMissing(report.Capabilities[0].Missing, "terminal-sponsorship-profile") {
		t.Fatalf("Provider advertised readiness while its QuotePolicy could select an unsupported profile: %+v", report)
	}
}

func TestRelayClientObservedSponsorshipIsExplicitAndNeverUpgradesAutonomousAssurance(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:sponsor", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	coordinator := relayTestCoordinator(t, fixture, &relayFunctionTransport{authenticatedResolve: true})
	coordinator.SponsorshipEvidenceVerifier = nil
	coordinator.SponsorshipReleasePolicy = RelaySponsorshipReleasePolicy{}
	directory := filepath.Join(t.TempDir(), "single-sponsor-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routeJournal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer routeJournal.Close()
	dependencies := RelayClientCapabilityDependencies{SingleProvider: &coordinator,
		SingleProviderRouteJournal: routeJournal,
		SingleProviderProvenance:   relayCapabilityProvenance(t, coordinator)[0],
		TerminalAccounting:         relayCapabilityTerminalAccounting(t)}

	capability := PlanRelayClientCapability(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeSponsorOnly, dependencies)
	if capability.Ready ||
		!containsRelayMissing(capability.Missing, "owner-sponsorship-release-policy") {
		t.Fatalf("lower-assurance observed sponsorship was enabled without its owner decision: %+v", capability)
	}
	observedPolicy := RelaySponsorshipReleasePolicy{EvidenceClass: agentrelay.SponsorshipReleaseObservedUnproven,
		ProfileURI: agentrelay.RPCCorroborationEvidenceProfileURI, ProfileDigest: relayTestDigest("6")}
	coordinator.SponsorshipReleasePolicy = observedPolicy
	dependencies.SingleProvider = &coordinator
	dependencies.SponsorshipReleasePolicy = observedPolicy
	capability = PlanRelayClientCapability(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeSponsorOnly, dependencies)
	if capability.Ready ||
		!containsRelayMissing(capability.Missing, "sponsorship-transaction-evidence-verifier") {
		t.Fatalf("observed sponsorship was enabled without its eventual terminal verifier: %+v", capability)
	}
	coordinator.SponsorshipEvidenceVerifier = relayTestSponsorshipEvidenceVerifier{}
	dependencies.SingleProvider = &coordinator
	capability = PlanRelayClientCapability(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeSponsorOnly, dependencies)
	if !capability.Ready {
		t.Fatalf("owner-enabled observed sponsorship with terminal verification remained disabled: %+v", capability)
	}

	// The same boolean is deliberately ignored for autonomous assurance. The
	// child coordinator itself must carry a portable finalized-proof verifier.
	missing := relayCoordinatorCapabilityMissing(&coordinator,
		agentrelay.AssuranceAutonomousDecentralized, agentrelay.ModeSponsorOnly)
	if !containsRelayMissing(missing, "owner-sponsorship-release-policy") {
		t.Fatalf("owner-enabled RPC corroboration upgraded autonomous assurance: %v", missing)
	}
}

func TestEnabledSingleProviderSponsorshipFirstDispatchAndRestartNeverCreatesSecondTopUp(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:sponsor", nil, "https://sponsor.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	provider := fixture.service(agentrelay.NewMemoryJournal(), nil)
	submits := 0
	transport := &relayFunctionTransport{authenticatedResolve: true, quote: provider.Quote,
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			return agentrelay.SignedRelayResolution{}, errors.New("response lost after provider dispatch")
		}, resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		}, evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		}}
	coordinator := relayTestCoordinator(t, fixture, transport)
	directory := filepath.Join(t.TempDir(), "single-provider-sponsor-route")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	provenance := relayCapabilityProvenance(t, coordinator)[0]
	dependencies := RelayClientCapabilityDependencies{SingleProvider: &coordinator,
		SingleProviderRouteJournal: routes, SingleProviderProvenance: provenance,
		SponsorshipReleasePolicy: coordinator.SponsorshipReleasePolicy,
		TerminalAccounting:       relayCapabilityTerminalAccounting(t)}
	client, err := EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeSponsorOnly, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(t.Context(), plan); err == nil || submits != 1 {
		t.Fatalf("first owner-fenced sponsorship dispatch was not left ambiguous: submits=%d err=%v", submits, err)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err = OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	dependencies.SingleProviderRouteJournal = routes
	client, err = EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeSponsorOnly, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(t.Context(), plan); !errors.Is(err, ErrRelaySubmissionAmbiguous) || submits != 1 {
		t.Fatalf("provider 404 after restart authorized another sponsorship: submits=%d err=%v", submits, err)
	}
}

func TestEnabledSingleProviderSponsorshipCrashAfterRouteMarkBeforeSocketIsQueryOnly(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:sponsor", nil, "https://sponsor.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	provider := fixture.service(agentrelay.NewMemoryJournal(), nil)
	submits := 0
	transport := &relayFunctionTransport{authenticatedResolve: true, quote: provider.Quote,
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			return agentrelay.SignedRelayResolution{}, errors.New("must not dispatch after recovery mark")
		}, resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		}, evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		}}
	coordinator := relayTestCoordinator(t, fixture, transport)
	directory := filepath.Join(t.TempDir(), "single-provider-sponsor-mark")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	dependencies := RelayClientCapabilityDependencies{SingleProvider: &coordinator,
		SingleProviderRouteJournal: routes, SingleProviderProvenance: relayCapabilityProvenance(t, coordinator)[0],
		SponsorshipReleasePolicy: coordinator.SponsorshipReleasePolicy,
		TerminalAccounting:       relayCapabilityTerminalAccounting(t)}
	client, err := EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeSponsorOnly, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(plan.Single.Execution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := routes.MarkSubmitStarted(plan.SinglePrepared.UnderlyingAction.StableActionID,
		plan.SinglePrepared.UnderlyingAction.ExactRequestDigest, plan.SingleRouteGeneration,
		executionDigest, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(t.Context(), plan); !errors.Is(err, ErrRelaySubmissionAmbiguous) || submits != 0 {
		t.Fatalf("crash-before-socket recovery created a sponsorship dispatch: submits=%d err=%v", submits, err)
	}
}

func TestLowerRelayExactCrashAfterRouteMarkRebroadcastsOnlyTheFrozenBOC(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	provider := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	submits := 0
	var submittedBytes []byte
	transport := &relayFunctionTransport{authenticatedResolve: true, quote: provider.Quote,
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		submit: func(_ context.Context, execution agentrelay.RelayExecutionRequest,
			_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			submittedBytes = append([]byte(nil), execution.SignedTransactionBytes...)
			digest, err := agentrelay.RelayExecutionRequestDigest(execution)
			if err != nil {
				return agentrelay.SignedRelayResolution{}, err
			}
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: fixture.profile.ProviderAgentID, Network: execution.QuoteRequest.Body.Network,
				AssuranceLevel:       execution.QuoteRequest.Body.AssuranceLevel,
				StableActionID:       execution.AuthorizedAction.StableActionID,
				ExactRequestDigest:   execution.AuthorizedAction.ExactRequestDigest,
				RelayExecutionDigest: digest, State: commerce.ActionAccepted, StateRevision: 2,
				TransactionReference: relayTestDigest("a"), ObservedAtUnix: uint64(fixture.now.Unix()),
				ExpiresAtUnix: uint64(fixture.now.Add(time.Minute).Unix())}, fixture.providerKey)
		}}
	coordinator := relayTestCoordinator(t, fixture, transport)
	directory := filepath.Join(t.TempDir(), "relay-mark-before-socket")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	accounting := relayCapabilityTerminalAccounting(t)
	provenance := relayCapabilityProvenance(t, coordinator)[0]
	dependencies := func() RelayClientCapabilityDependencies {
		return RelayClientCapabilityDependencies{SingleProvider: &coordinator,
			SingleProviderRouteJournal: routes, SingleProviderProvenance: provenance,
			TerminalAccounting: accounting}
	}
	client, err := EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeRelayExact, dependencies())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(plan.Single.Execution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := routes.MarkSubmitStarted(plan.SinglePrepared.UnderlyingAction.StableActionID,
		plan.SinglePrepared.UnderlyingAction.ExactRequestDigest, plan.SingleRouteGeneration,
		executionDigest, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err = OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	client, err = EnableRelayClient(agentrelay.AssuranceAuthorizedSingleProvider,
		agentrelay.ModeRelayExact, dependencies())
	if err != nil {
		t.Fatal(err)
	}
	plan, err = client.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Submit(t.Context(), plan)
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || submits != 1 ||
		!bytes.Equal(submittedBytes, fixture.prepared.ExactSignedBOC) {
		t.Fatalf("crash-before-socket recovery did not rebroadcast exactly once: submits=%d state=%s err=%v",
			submits, result.Resolution.Body.State, err)
	}
}

func containsRelayMissing(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func relayCapabilityProvenance(t *testing.T, coordinators ...RelayCoordinator) []RelayProviderProvenance {
	t.Helper()
	result := make([]RelayProviderProvenance, 0, len(coordinators))
	for index, coordinator := range coordinators {
		profile := coordinator.VerifiedProfile.Profile()
		profileDigest, err := agentrelay.RelayServiceProfileDigest(profile)
		if err != nil {
			t.Fatal(err)
		}
		origin, err := relayProfileEndpointOrigin(profile.Endpoints)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, RelayProviderProvenance{ProviderAgentID: profile.ProviderAgentID,
			IntentDigest: coordinator.VerifiedProfile.IntentDigest(), ProfileDigest: profileDigest,
			OperatorDomain: "operator:" + string(rune('a'+index)), FailureDomain: "failure:" + string(rune('a'+index)),
			EndpointOrigin: origin, CertificatePinDigest: relayTestDigest(string(rune('a' + index))),
			ImplementationEvidenceHash: relayTestDigest(string(rune('c' + index)))})
	}
	return result
}
