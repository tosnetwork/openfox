package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

type unavailableReauthorizationAuthority struct {
	inner testRelayReauthorizationAuthority
}

func (authority unavailableReauthorizationAuthority) AdmitRelaySideEffects(context.Context,
	agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("authority request interrupted before linearization")
}

func (authority unavailableReauthorizationAuthority) ResolveRelaySideEffectAdmission(context.Context,
	agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("authority recovery transport is unavailable")
}

func (authority unavailableReauthorizationAuthority) reauthorizeUnlinearizedRelayAdmission(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor,
	execution agentrelay.RelayExecutionRequest) (relayAdmissionReauthorization, error) {
	return authority.inner.reauthorizeUnlinearizedRelayAdmission(ctx, descriptor, execution)
}

type observingReauthorizationAuthority struct {
	inner    testRelayReauthorizationAuthority
	admits   int
	resolves int
}

type testRelayReauthorizationAuthority interface {
	AdmitRelaySideEffects(context.Context,
		agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error)
	ResolveRelaySideEffectAdmission(context.Context,
		agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error)
	relayAdmissionReauthorizer
}

func (authority *observingReauthorizationAuthority) AdmitRelaySideEffects(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	authority.admits++
	return authority.inner.AdmitRelaySideEffects(ctx, descriptor)
}

func (authority *observingReauthorizationAuthority) ResolveRelaySideEffectAdmission(ctx context.Context,
	lookup agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	authority.resolves++
	return authority.inner.ResolveRelaySideEffectAdmission(ctx, lookup)
}

func (authority *observingReauthorizationAuthority) reauthorizeUnlinearizedRelayAdmission(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor,
	execution agentrelay.RelayExecutionRequest) (relayAdmissionReauthorization, error) {
	return authority.inner.reauthorizeUnlinearizedRelayAdmission(ctx, descriptor, execution)
}

type relayReauthorizationHarness struct {
	clock        time.Time
	first        *relayTestFixture
	second       *relayTestFixture
	authority    *PersonalAuthority
	bound        *PersonalRelaySideEffectAuthority
	firstWriter  commerce.WriterFence
	routes       *DurableRelayRouteJournal
	routeDir     string
	orchestrator DecentralizedRelayCoordinator
	plan         *DecentralizedRelayPlan
	submits      int
}

func newRelayReauthorizationHarness(t *testing.T) *relayReauthorizationHarness {
	t.Helper()
	first := newRelayTestFixture(t, "agent:sponsor-one", nil, "https://rebase-one.example")
	harness := &relayReauthorizationHarness{clock: first.now, first: first}
	authorityDir := privateTempDir(t)
	authority, err := OpenPersonalAuthority(authorityDir, "owner:client", "agent:client", "authority:client",
		first.authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return harness.clock }
	firstWriter, err := authority.AcquireWriter(t.Context(), "instance:writer-one", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := authority.BindRelaySideEffectAuthority(firstWriter)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := clonePreparedRelayTransaction(first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	prepared.WriterFence = firstWriter
	oldAction := prepared.UnderlyingAction
	prepared.UnderlyingAction, err = commerce.BuildAuthorizedAction(oldAction.OwnerID, oldAction.AgentID,
		oldAction.ActionKind, prepared.SemanticFields, prepared.UnderlyingActionRequest, firstWriter,
		oldAction.PolicyRevision, oldAction.MandateDigest, oldAction.ApprovalDigest,
		oldAction.ExpectedPriorState, firstWriter.Body.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	prepared.UnderlyingAction, err = authority.SignAction(prepared.UnderlyingAction, firstWriter)
	if err != nil {
		t.Fatal(err)
	}
	prepared.QuoteBody.StableActionID = prepared.UnderlyingAction.StableActionID
	prepared.QuoteBody.ExactRequestDigest = prepared.UnderlyingAction.ExactRequestDigest
	first.prepared = prepared
	first.resolver.setCurrentWriter(firstWriter)

	_, secondKey, _ := ed25519.GenerateKey(nil)
	second := newRelayTestFixture(t, "agent:sponsor-two", secondKey, "https://rebase-two.example")
	second.clientKey, second.authorityKey = first.clientKey, first.authorityKey
	first.resolver.agents[second.profile.ProviderAgentID] = secondKey.Public().(ed25519.PublicKey)
	second.resolver = relayTestResolver{agents: map[string]ed25519.PublicKey{
		"agent:client":                 first.clientKey.Public().(ed25519.PublicKey),
		second.profile.ProviderAgentID: secondKey.Public().(ed25519.PublicKey)},
		authorityKey: first.authorityKey.Public().(ed25519.PublicKey), current: first.resolver.current}

	firstService := first.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	firstTransport := relayFunctionTransport{quote: firstService.Quote,
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("first route is made ambiguous by the test journal")
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		}}
	firstCoordinator := relayTestCoordinator(t, first, firstTransport)
	firstCoordinator.SideEffectAdmission = bound
	firstCoordinator.FenceResolver = authority
	firstCoordinator.Now = func() time.Time { return harness.clock }

	secondService := second.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	harness.second, harness.authority, harness.bound, harness.firstWriter = second, authority, bound, firstWriter
	secondTransport := relayFunctionTransport{quote: secondService.Quote,
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		submit: func(_ context.Context, request agentrelay.RelayExecutionRequest,
			_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			harness.submits++
			digest, _ := agentrelay.RelayExecutionRequestDigest(request)
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: second.profile.ProviderAgentID, Network: request.QuoteRequest.Body.Network,
				AssuranceLevel:     request.QuoteRequest.Body.AssuranceLevel,
				StableActionID:     request.AuthorizedAction.StableActionID,
				ExactRequestDigest: request.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: digest,
				State: commerce.ActionAccepted, StateRevision: 2, TransactionReference: "tx:rebased",
				ObservedAtUnix: uint64(harness.clock.Unix()),
				ExpiresAtUnix:  uint64(harness.clock.Add(time.Minute).Unix())}, second.providerKey)
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		}}
	secondCoordinator := relayTestCoordinator(t, second, secondTransport)
	secondCoordinator.SideEffectAdmission = bound
	secondCoordinator.FenceResolver = authority
	secondCoordinator.Now = func() time.Time { return harness.clock }

	routeDir := filepath.Join(t.TempDir(), "relay-rebase-routes")
	if err := os.Mkdir(routeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(routeDir)
	if err != nil {
		t.Fatal(err)
	}
	harness.routes, harness.routeDir = routes, routeDir
	harness.orchestrator = DecentralizedRelayCoordinator{Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator},
		Selector:           RelayProviderSelectorFunc(func(context.Context, []RelayQuoteCandidate) (int, error) { return 0, nil }),
		ProvenanceVerifier: relayTestIndependentProvenanceVerifier(), AgentResolver: firstCoordinator.AgentResolver,
		RouteJournal: routes, MaximumRouteAttempts: 2}
	harness.plan, err = harness.orchestrator.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = harness.routes.Close()
		_ = harness.authority.Close()
	})
	return harness
}

func (harness *relayReauthorizationHarness) preparePending(t *testing.T, started bool) RelayAttempt {
	t.Helper()
	route, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := route.Current()
	route, err = harness.routes.MarkSubmitStarted(route.StableActionID, route.ExactRequestDigest, 1,
		current.RelayExecutionDigest, harness.clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	current, _ = route.Current()
	principal := current.Attempt.Execution.AdmissionReceipt.Body.AuthenticatedPrincipal
	authDigest, _ := relayTransportAuthenticationDigest(current.Provider, principal)
	networkDigest, _ := agentrelay.NetworkDomainDigest(current.Attempt.Execution.QuoteRequest.Body.Network)
	transactionDigest, _ := agentrelay.RelayTransactionIdentityDigest(current.Attempt.Execution.QuoteRequest.Body)
	query := relayRouteResolveQueryAttempt{SchemaVersion: 1, RouteGeneration: 1,
		ProviderAgentID: current.Provider.ProviderAgentID, ProviderProfileDigest: current.Provider.ProfileDigest,
		AuthenticatedPrincipal: principal, TransportAuthenticationDigest: authDigest,
		NetworkDigest: networkDigest, TransactionIdentityDigest: transactionDigest,
		StableActionID: route.StableActionID, ExactRequestDigest: route.ExactRequestDigest,
		RelayExecutionDigest: current.RelayExecutionDigest, Outcome: relayResolveRemoteUnknown,
		StartedAtUnix:   uint64(harness.clock.Add(time.Second).Unix()),
		CompletedAtUnix: uint64(harness.clock.Add(time.Second).Unix())}
	route, err = harness.routes.recordResolveQuery(route.StableActionID, route.ExactRequestDigest, 1, query)
	if err != nil {
		t.Fatal(err)
	}
	secondIndex := -1
	for index, candidate := range harness.plan.candidates {
		if candidate.Coordinator != nil && candidate.Coordinator.VerifiedProfile.Profile().ProviderAgentID == harness.second.profile.ProviderAgentID {
			secondIndex = index
			break
		}
	}
	if secondIndex < 0 {
		t.Fatal("second relay candidate is absent")
	}
	draft, err := harness.plan.candidates[secondIndex].Coordinator.buildAttempt(t.Context(),
		harness.plan.candidates[secondIndex].Quoted)
	if err != nil {
		t.Fatal(err)
	}
	route, err = harness.routes.PrepareSwitch(route.StableActionID, route.ExactRequestDigest, 1,
		current.RelayExecutionDigest, harness.plan.provenance[secondIndex], draft, harness.clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if started {
		route, err = harness.routes.MarkPendingAdmissionStarted(route.StableActionID, route.ExactRequestDigest, 1,
			route.PendingSwitch.AdmissionRevision, route.PendingSwitch.AdmissionEnvelopeDigest,
			harness.clock.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	return cloneRelayAttempt(route.PendingSwitch.Attempt)
}

func (harness *relayReauthorizationHarness) takeover(t *testing.T) commerce.WriterFence {
	t.Helper()
	harness.clock = harness.clock.Add(3 * time.Second) // supersede the old lease while immutable execution windows remain live
	fence, err := harness.authority.AcquireWriter(t.Context(), "instance:writer-two",
		[]string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	harness.first.resolver.setCurrentWriter(fence)
	bound, err := harness.authority.BindRelaySideEffectAuthority(fence)
	if err != nil {
		t.Fatal(err)
	}
	harness.bound = bound
	for _, coordinator := range harness.orchestrator.Providers {
		coordinator.SideEffectAdmission = bound
	}
	return fence
}

func (harness *relayReauthorizationHarness) restartRoutes(t *testing.T) {
	t.Helper()
	if err := harness.routes.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(harness.routeDir)
	if err != nil {
		t.Fatal(err)
	}
	harness.routes = routes
	harness.orchestrator.RouteJournal = routes
}

func TestRelaySuccessorReauthorizationBeforeAdmissionStartSurvivesCrashRestart(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	oldDraft := harness.preparePending(t, false)
	newFence := harness.takeover(t)
	second := harness.orchestrator.Providers[1]
	second.SideEffectAdmission = unavailableReauthorizationAuthority{inner: harness.bound}
	if _, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{}); err == nil {
		t.Fatal("crash after atomic rebase/start was not surfaced")
	}
	stored, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil || stored.PendingSwitch == nil || !stored.PendingSwitch.AdmissionStarted ||
		stored.PendingSwitch.Rebase == nil || stored.PendingSwitch.AdmissionRevision != 2 ||
		stored.PendingSwitch.Attempt.Execution.WriterFence.Body.LeaseID != newFence.Body.LeaseID ||
		reflect.DeepEqual(stored.PendingSwitch.Attempt.Execution.AuthorizedAction, oldDraft.Execution.AuthorizedAction) {
		t.Fatalf("credential-only rebase was not durably started: pending=%+v err=%v", stored.PendingSwitch, err)
	}
	if !bytes.Equal(stored.PendingSwitch.Attempt.Execution.SignedTransactionBytes, oldDraft.Execution.SignedTransactionBytes) ||
		!reflect.DeepEqual(stored.PendingSwitch.Attempt.Agreement, oldDraft.Agreement) {
		t.Fatal("rebase changed the exact BOC or Agreement")
	}
	harness.restartRoutes(t)
	second.SideEffectAdmission = harness.bound
	resumed, err := harness.orchestrator.Prepare(t.Context(), harness.first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	result, err := harness.orchestrator.Failover(t.Context(), resumed, RelayExecutionResult{})
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || harness.submits != 1 ||
		resumed.Attempt.Execution.AdmissionReceipt.Body.WriterGeneration != newFence.Body.WriterGeneration {
		t.Fatalf("restart did not recover rebased admission: result=%+v submits=%d err=%v",
			result.Resolution.Body, harness.submits, err)
	}
}

func TestRelaySuccessorReauthorizationAfterStartedAuthoritativeNotFound(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	oldDraft := harness.preparePending(t, true)
	newFence := harness.takeover(t)
	observed := &observingReauthorizationAuthority{inner: harness.bound}
	harness.orchestrator.Providers[1].SideEffectAdmission = observed
	result, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{})
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || harness.submits != 1 ||
		observed.resolves != 1 || observed.admits != 1 {
		t.Fatalf("typed not-found did not permit safe rebase: result=%+v err=%v", result.Resolution.Body, err)
	}
	currentRoute, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	current, found := currentRoute.Current()
	if err != nil || !found || len(currentRoute.Hops) != 2 ||
		current.Attempt.Execution.AdmissionReceipt.Body.WriterGeneration != newFence.Body.WriterGeneration ||
		!bytes.Equal(current.Attempt.Execution.SignedTransactionBytes, oldDraft.Execution.SignedTransactionBytes) ||
		!reflect.DeepEqual(current.Attempt.Agreement, oldDraft.Agreement) {
		t.Fatalf("reauthorized route changed immutable work: route=%+v err=%v", currentRoute, err)
	}
}

func TestRelaySuccessorReceiptFoundAfterTakeoverNeverRebases(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	oldDraft := harness.preparePending(t, true)
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(oldDraft.Execution,
		oldDraft.Execution.QuoteRequest.Body.RequesterAgentID, harness.plan.Attempt.Execution.AdmissionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := harness.bound.AdmitRelaySideEffects(t.Context(), descriptor)
	if err != nil {
		t.Fatal(err)
	}
	newFence := harness.takeover(t)
	observed := &observingReauthorizationAuthority{inner: harness.bound}
	harness.orchestrator.Providers[1].SideEffectAdmission = observed
	result, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{})
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || harness.submits != 1 ||
		observed.resolves != 1 || observed.admits != 0 {
		t.Fatalf("linearized old receipt did not drain exactly: result=%+v err=%v", result.Resolution.Body, err)
	}
	if !reflect.DeepEqual(harness.plan.Attempt.Execution.AdmissionReceipt, issued) ||
		harness.plan.Attempt.Execution.AdmissionReceipt.Body.WriterGeneration == newFence.Body.WriterGeneration {
		t.Fatal("found receipt was replaced by a takeover reauthorization")
	}
	if _, err := harness.bound.ResolveRelaySideEffectAdmission(t.Context(), descriptor.Lookup()); err != nil {
		t.Fatalf("original admission receipt disappeared: %v", err)
	}
}

func TestRelaySuccessorAmbiguousAuthorityResolveNeverRebases(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	harness.preparePending(t, true)
	harness.takeover(t)
	second := harness.orchestrator.Providers[1]
	second.SideEffectAdmission = unavailableReauthorizationAuthority{inner: harness.bound}
	before, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{}); err == nil {
		t.Fatal("ambiguous authority recovery unexpectedly rebased")
	}
	after, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil || !reflect.DeepEqual(before, after) || after.PendingSwitch.Rebase != nil || harness.submits != 0 {
		t.Fatalf("ambiguous Resolve mutated pending admission: before=%+v after=%+v submits=%d err=%v",
			before.PendingSwitch, after.PendingSwitch, harness.submits, err)
	}
}

func TestRelaySuccessorRepeatedTakeoverReauthorizesHistoricalRebase(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	harness.preparePending(t, false)
	harness.takeover(t)
	second := harness.orchestrator.Providers[1]
	second.SideEffectAdmission = unavailableReauthorizationAuthority{inner: harness.bound}
	if _, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{}); err == nil {
		t.Fatal("first takeover did not stop after the durably rebased admission")
	}
	firstRebase, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil || firstRebase.PendingSwitch == nil || firstRebase.PendingSwitch.Rebase == nil ||
		firstRebase.PendingSwitch.AdmissionRevision != 2 {
		t.Fatalf("first takeover rebase is not durable: pending=%+v err=%v", firstRebase.PendingSwitch, err)
	}
	thirdFence := harness.takeover(t)
	result, err := harness.orchestrator.Failover(t.Context(), harness.plan, RelayExecutionResult{})
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || harness.submits != 1 {
		t.Fatalf("second takeover could not reauthorize the historical rebase: result=%+v err=%v",
			result.Resolution.Body, err)
	}
	current, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
		harness.plan.base.UnderlyingAction.ExactRequestDigest)
	hop, found := current.Current()
	if err != nil || !found || hop.Attempt.Execution.AdmissionReceipt.Body.WriterGeneration !=
		thirdFence.Body.WriterGeneration {
		t.Fatalf("repeated takeover did not consume the current writer receipt: route=%+v err=%v", current, err)
	}
}

func TestRelayAdmissionReauthorizationExpiryCannotExtendOldAction(t *testing.T) {
	execution := agentrelay.RelayExecutionRequest{
		AuthorizedAction:       commerce.AuthorizedAction{ExpiresAtUnix: 10},
		ExpiresAtUnix:          20,
		AgreementExpiresAtUnix: 30,
		ProviderQuote: agentrelay.SignedProviderRelayQuote{Body: agentrelay.ProviderRelayQuoteBody{
			AssuranceLevel: agentrelay.AssuranceAutonomousDecentralized, ExpiresAtUnix: 40,
		}},
		QuoteRequest: agentrelay.SignedRelayQuoteRequest{Body: agentrelay.RelayQuoteRequestBody{
			AssuranceLevel: agentrelay.AssuranceAutonomousDecentralized, TransactionValidUntilUnix: 50,
		}},
	}
	fence := commerce.WriterFence{Body: commerce.WriterFenceBody{ExpiresAtUnix: 60}}
	if expiry := relayAdmissionReauthorizationExpiry(execution, fence); expiry != 10 {
		t.Fatalf("reauthorization extended the old action expiry: got %d want 10", expiry)
	}
}

func TestPersonalRelayAdmissionCapabilityIsBoundToExactCurrentWriter(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	oldDraft := harness.preparePending(t, true)
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(oldDraft.Execution,
		oldDraft.Execution.QuoteRequest.Body.RequesterAgentID, harness.plan.Attempt.Execution.AdmissionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	stale := harness.bound
	currentFence := harness.takeover(t)
	if _, err := stale.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution); err == nil {
		t.Fatal("stale local relay capability reauthorized the takeover writer")
	}
	authorization, err := harness.bound.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution)
	if err != nil || authorization.Body.NewWriterGeneration != currentFence.Body.WriterGeneration ||
		authorization.Body.NewWriterLeaseID != currentFence.Body.LeaseID {
		t.Fatalf("current local relay capability could not reauthorize: authorization=%+v err=%v",
			authorization.Body, err)
	}
	rebasedExecution := oldDraft.Execution
	rebasedExecution.AuthorizedAction = authorization.AuthorizedAction
	rebasedExecution.WriterFence = authorization.WriterFence
	rebasedAttempt := oldDraft
	rebasedAttempt.Execution = rebasedExecution
	predecessor := harness.plan.Attempt.Execution.AdmissionReceipt
	if err := verifyRelayAdmissionReauthorization(authorization, oldDraft, rebasedAttempt, predecessor); err != nil {
		t.Fatalf("canonical relay reauthorization did not verify: %v", err)
	}
	withoutSignaturePrefix := authorization
	withoutSignaturePrefix.Signature = withoutSignaturePrefix.Signature[len("ed25519:"):]
	if err := verifyRelayAdmissionReauthorization(withoutSignaturePrefix, oldDraft, rebasedAttempt, predecessor); err == nil {
		t.Fatal("relay reauthorization accepted a non-canonical signature encoding")
	}
	rebasedDescriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(rebasedExecution,
		rebasedExecution.QuoteRequest.Body.RequesterAgentID, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.AdmitRelaySideEffects(t.Context(), rebasedDescriptor); err == nil {
		t.Fatal("stale local capability admitted the current writer's descriptor")
	}
	receipt, err := harness.bound.AdmitRelaySideEffects(t.Context(), rebasedDescriptor)
	if err != nil || receipt.Body.WriterGeneration != currentFence.Body.WriterGeneration {
		t.Fatalf("current local capability could not admit its exact descriptor: receipt=%+v err=%v", receipt.Body, err)
	}
}

func TestRelayAdmissionJournalDoesNotPublishFailedPersistence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows directory ACLs do not model Unix write-bit failure")
	}
	t.Run("mark-started", func(t *testing.T) {
		harness := newRelayReauthorizationHarness(t)
		harness.preparePending(t, false)
		before, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
			harness.plan.base.UnderlyingAction.ExactRequestDigest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(harness.routeDir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(harness.routeDir, 0o700) // best-effort cleanup after assertion failures
		_, mutationErr := harness.routes.MarkPendingAdmissionStarted(before.StableActionID,
			before.ExactRequestDigest, 1, before.PendingSwitch.AdmissionRevision,
			before.PendingSwitch.AdmissionEnvelopeDigest, harness.clock.Add(2*time.Second))
		if err := os.Chmod(harness.routeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if mutationErr == nil {
			t.Fatal("read-only route directory did not fail persistence")
		}
		after, err := harness.routes.Resolve(before.StableActionID, before.ExactRequestDigest)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatalf("failed start persistence mutated live memory: before=%+v after=%+v err=%v",
				before.PendingSwitch, after.PendingSwitch, err)
		}
	})
	t.Run("rebase", func(t *testing.T) {
		harness := newRelayReauthorizationHarness(t)
		harness.preparePending(t, false)
		harness.takeover(t)
		before, err := harness.routes.Resolve(harness.plan.base.UnderlyingAction.StableActionID,
			harness.plan.base.UnderlyingAction.ExactRequestDigest)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := before.Current()
		draft := cloneRelayAttempt(before.PendingSwitch.Attempt)
		rebased, authorization, err := harness.orchestrator.Providers[1].reauthorizePendingAttempt(t.Context(),
			draft, current.Attempt.Execution.AdmissionReceipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(harness.routeDir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(harness.routeDir, 0o700) // best-effort cleanup after assertion failures
		_, mutationErr := harness.routes.RebasePendingAdmission(before.StableActionID,
			before.ExactRequestDigest, current.Generation, before.PendingSwitch.AdmissionRevision,
			before.PendingSwitch.AdmissionEnvelopeDigest, rebased, authorization, harness.clock)
		if err := os.Chmod(harness.routeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if mutationErr == nil {
			t.Fatal("read-only route directory did not fail rebase persistence")
		}
		after, err := harness.routes.Resolve(before.StableActionID, before.ExactRequestDigest)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatalf("failed rebase persistence mutated live memory: before=%+v after=%+v err=%v",
				before.PendingSwitch, after.PendingSwitch, err)
		}
	})
}

func TestSharedAuthorityReauthorizationIsBoundToTakeoverMTLSInstance(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	oldDraft := harness.preparePending(t, true)
	harness.takeover(t)
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(oldDraft.Execution,
		oldDraft.Execution.QuoteRequest.Body.RequesterAgentID, harness.plan.Attempt.Execution.AdmissionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	certificateTime := time.Now().UTC().Truncate(time.Second)
	caCert, caKey, _ := issueTestCertificate(t, nil, nil, "relay-reauthorization-ca", true, nil, certificateTime)
	_, _, serverCertificate := issueTestCertificate(t, caCert, caKey, "authority.test", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, certificateTime)
	_, _, staleClientCertificate := issueTestCertificate(t, caCert, caKey, "writer-one", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, certificateTime)
	_, _, currentClientCertificate := issueTestCertificate(t, caCert, caKey, "writer-two", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, certificateTime)
	staleSPKI, err := SharedAuthorityClientSPKI(&staleClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	currentSPKI, err := SharedAuthorityClientSPKI(&currentClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	server := &SharedAuthorityServer{Backing: harness.authority,
		ClientsBySPKI: map[string]SharedAuthorityClientGrant{
			staleSPKI: {OwnerID: "owner:client", AgentID: "agent:client",
				InstanceID: "instance:writer-one", Scopes: []string{"payment.direct"}},
			currentSPKI: {OwnerID: "owner:client", AgentID: "agent:client",
				InstanceID: "instance:writer-two", Scopes: []string{"payment.direct"}},
		}}
	testServer := httptest.NewUnstartedServer(server.Handler())
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(caCert)
	serverTLS, err := NewSharedAuthorityServerTLSConfig(serverCertificate, clientRoots)
	if err != nil {
		t.Fatal(err)
	}
	testServer.TLS = serverTLS
	testServer.StartTLS()
	defer testServer.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(caCert)
	newClient := func(certificate tls.Certificate) *SharedAuthorityClient {
		t.Helper()
		httpClient, clientErr := NewSharedAuthorityHTTPClient(certificate, serverRoots, "authority.test", 5*time.Second)
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		client, clientErr := NewSharedAuthorityClient(testServer.URL+"/v1/economic-authority", httpClient,
			"authority:client", harness.first.authorityKey.Public().(ed25519.PublicKey))
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		return client
	}
	staleClient, currentClient := newClient(staleClientCertificate), newClient(currentClientCertificate)
	if _, err := staleClient.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution); err == nil {
		t.Fatal("stale mTLS instance reauthorized the takeover writer")
	}
	authorization, err := currentClient.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution)
	if err != nil || authorization.Body.NewWriterGeneration != harness.bound.writerGeneration {
		t.Fatalf("current mTLS instance could not reauthorize: generation=%d err=%v",
			authorization.Body.NewWriterGeneration, err)
	}
}

func TestPersonalAuthorityAdmissionTakeoverRaceHasOneLinearizationPath(t *testing.T) {
	harness := newRelayReauthorizationHarness(t)
	oldDraft := harness.preparePending(t, true)
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionSuccessorDescriptor(oldDraft.Execution,
		oldDraft.Execution.QuoteRequest.Body.RequesterAgentID, harness.plan.Attempt.Execution.AdmissionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	admitResult := make(chan error, 1)
	type takeoverOutcome struct {
		fence commerce.WriterFence
		err   error
	}
	takeoverResult := make(chan takeoverOutcome, 1)
	staleBound := harness.bound
	go func() {
		<-start
		_, admitErr := staleBound.AdmitRelaySideEffects(context.Background(), descriptor)
		admitResult <- admitErr
	}()
	go func() {
		<-start
		fence, takeoverErr := harness.authority.AcquireWriter(context.Background(), "instance:race-winner",
			[]string{"payment.direct"}, 10*time.Minute)
		if takeoverErr == nil {
			harness.first.resolver.setCurrentWriter(fence)
		}
		takeoverResult <- takeoverOutcome{fence: fence, err: takeoverErr}
	}()
	close(start)
	admitErr, takeover := <-admitResult, <-takeoverResult
	if takeover.err != nil {
		t.Fatal(takeover.err)
	}
	currentBound, err := harness.authority.BindRelaySideEffectAuthority(takeover.fence)
	if err != nil {
		t.Fatal(err)
	}
	_, resolveErr := staleBound.ResolveRelaySideEffectAdmission(t.Context(), descriptor.Lookup())
	if resolveErr == nil {
		if admitErr != nil {
			t.Fatalf("receipt exists although Admit reported failure: %v", admitErr)
		}
		if _, err := currentBound.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution); err == nil {
			t.Fatal("linearized receipt was reauthorized")
		}
		return
	}
	if !errors.Is(resolveErr, agentrelay.ErrRelayUnknown) || admitErr == nil {
		t.Fatalf("race produced neither receipt nor definitive stale-writer rejection: admit=%v resolve=%v", admitErr, resolveErr)
	}
	if _, err := staleBound.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution); err == nil {
		t.Fatal("stale local relay capability impersonated the takeover writer")
	}
	if _, err := currentBound.reauthorizeUnlinearizedRelayAdmission(t.Context(), descriptor, oldDraft.Execution); err != nil {
		t.Fatalf("takeover-first path could not reauthorize definitive not-found: %v", err)
	}
}
