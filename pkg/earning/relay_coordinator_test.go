package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type relayRotatingFinalitySnapshot struct {
	Capability agentrelay.RelayEvidenceCapability `json:"capability"`
	Revision   string                             `json:"revision"`
}

type relayRotatingFinalityVerifier struct {
	relayTestFinalityVerifier
	current string
}

func TestRelayClientFinalitySnapshotSurvivesConfigRotationAndRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	coordinator := relayTestCoordinator(t, fixture, relayFunctionTransport{
		quote: service.Quote, authenticatedResolve: true})
	verifier := &relayRotatingFinalityVerifier{relayTestFinalityVerifier: relayTestFinalityVerifier{
		dualAbsence: true, portable: true}, current: "config-a"}
	coordinator.FinalityVerifier = verifier

	quotedA, err := coordinator.Quote(t.Context(), fixture.prepared)
	if err != nil || quotedA.ClientFinalityEvidenceSnapshot == nil {
		t.Fatalf("config A snapshot was not frozen before Quote: snapshot=%+v err=%v",
			quotedA.ClientFinalityEvidenceSnapshot, err)
	}
	attemptA, err := coordinator.Authorize(t.Context(), quotedA)
	if err != nil {
		t.Fatal(err)
	}
	verifier.current = "config-b"

	directory := filepath.Join(t.TempDir(), "relay-finality-snapshot-route")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	provenance := relayCapabilityProvenance(t, coordinator)[0]
	if _, _, err := routes.BindSingle(fixture.prepared, provenance, attemptA, fixture.now); err != nil {
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
	restored, err := routes.Resolve(attemptA.Execution.AuthorizedAction.StableActionID,
		attemptA.Execution.AuthorizedAction.ExactRequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	hop, found := restored.Current()
	if !found || hop.Attempt.ClientFinalityEvidenceSnapshot == nil ||
		hop.Attempt.ClientFinalityEvidenceSnapshot.Identity != attemptA.ClientFinalityEvidenceSnapshot.Identity ||
		coordinator.validateAttempt(t.Context(), hop.Attempt, fixture.now) != nil {
		t.Fatalf("config A attempt was stranded after config B rotation/restart: hop=%+v", hop)
	}
	_, evidence := relayTerminalAbsent(t, fixture, hop.Attempt.Execution)
	if err := coordinator.verifyIndependentFinality(t.Context(), hop.Attempt, evidence); err != nil {
		t.Fatalf("config A frozen verifier could not finish after config B became current: %v", err)
	}

	quotedB, err := coordinator.Quote(t.Context(), fixture.prepared)
	if err != nil || quotedB.ClientFinalityEvidenceSnapshot == nil ||
		quotedB.ClientFinalityEvidenceSnapshot.Identity == quotedA.ClientFinalityEvidenceSnapshot.Identity {
		t.Fatalf("new Quote did not freeze rotated config B: A=%+v B=%+v err=%v",
			quotedA.ClientFinalityEvidenceSnapshot, quotedB.ClientFinalityEvidenceSnapshot, err)
	}
	mutated := cloneRelayAttempt(hop.Attempt)
	mutated.ClientFinalityEvidenceSnapshot.Opaque[0] ^= 0x01
	if err := coordinator.validateAttempt(t.Context(), mutated, fixture.now); err == nil {
		t.Fatal("mutated client finality snapshot survived attempt validation")
	}
	missing := cloneRelayAttempt(hop.Attempt)
	missing.ClientFinalityEvidenceSnapshot = nil
	if err := coordinator.validateAttempt(t.Context(), missing, fixture.now); err == nil {
		t.Fatal("missing client finality snapshot survived attempt validation")
	}
}

func (verifier *relayRotatingFinalityVerifier) FreezeRelayFinalityEvidenceSnapshot(_ context.Context,
	capability agentrelay.RelayEvidenceCapability) ([]byte, error) {
	if verifier.current == "" || !verifier.SupportsRelayEvidenceCapability(capability) {
		return nil, errors.New("rotating verifier current config is unavailable")
	}
	return codec.Marshal(relayRotatingFinalitySnapshot{Capability: capability, Revision: verifier.current})
}

func (verifier *relayRotatingFinalityVerifier) ValidateRelayFinalityEvidenceSnapshot(
	capability agentrelay.RelayEvidenceCapability, raw []byte) error {
	var frozen relayRotatingFinalitySnapshot
	if codec.Unmarshal(raw, &frozen) != nil || !reflect.DeepEqual(frozen.Capability, capability) ||
		(frozen.Revision != "config-a" && frozen.Revision != "config-b") {
		return errors.New("rotating verifier snapshot is invalid")
	}
	return nil
}

func (verifier *relayRotatingFinalityVerifier) VerifyRelayFinalityFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence, raw []byte) error {
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil || verifier.ValidateRelayFinalityEvidenceSnapshot(capability, raw) != nil {
		return errors.New("rotating verifier snapshot does not bind the execution")
	}
	return verifier.VerifyRelayFinality(ctx, execution, evidence)
}

type relayFunctionTransport struct {
	quote                func(context.Context, agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error)
	submit               func(context.Context, agentrelay.RelayExecutionRequest, commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error)
	resolve              func(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error)
	evidence             func(context.Context, agentrelay.EvidenceCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error)
	authenticatedResolve bool
}

func (transport relayFunctionTransport) relayProviderTransportAuthorized() bool {
	return transport.authenticatedResolve
}

func (transport relayFunctionTransport) resolveForFailover(ctx context.Context, call agentrelay.ResolveCall,
	execution agentrelay.RelayExecutionRequest, provider RelayProviderProvenance,
	authenticatedPrincipal string) (agentrelay.SignedRelayResolution, string, bool, error) {
	if !transport.authenticatedResolve {
		return agentrelay.SignedRelayResolution{}, "", false, errors.New("controlled test transport is not authenticated")
	}
	digest, err := relayTransportAuthenticationDigest(provider, authenticatedPrincipal)
	if err != nil {
		return agentrelay.SignedRelayResolution{}, "", false, err
	}
	resolution, resolveErr := transport.resolve(ctx, call, execution)
	return resolution, digest, true, resolveErr
}

type ambiguousRelayAdmissionAuthority struct {
	inner        agentrelay.RelaySideEffectAdmissionAuthority
	admitCalls   int
	resolveCalls int
}

func (authority *ambiguousRelayAdmissionAuthority) HasLinearizableRelayAdmission() bool {
	capability, ok := authority.inner.(RelayAutonomousAdmissionAssurance)
	return ok && capability.HasLinearizableRelayAdmission()
}

func (authority *ambiguousRelayAdmissionAuthority) HasRollbackResistantRelayAdmissionHighWater() bool {
	capability, ok := authority.inner.(RelayAutonomousAdmissionAssurance)
	return ok && capability.HasRollbackResistantRelayAdmissionHighWater()
}

type crashedRelayAdmissionAuthority struct {
	inner agentrelay.RelaySideEffectAdmissionAuthority
}

func (authority crashedRelayAdmissionAuthority) HasLinearizableRelayAdmission() bool {
	capability, ok := authority.inner.(RelayAutonomousAdmissionAssurance)
	return ok && capability.HasLinearizableRelayAdmission()
}

func (authority crashedRelayAdmissionAuthority) HasRollbackResistantRelayAdmissionHighWater() bool {
	capability, ok := authority.inner.(RelayAutonomousAdmissionAssurance)
	return ok && capability.HasRollbackResistantRelayAdmissionHighWater()
}

func (authority crashedRelayAdmissionAuthority) AdmitRelaySideEffects(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if _, err := authority.inner.AdmitRelaySideEffects(ctx, descriptor); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("process crashed after successor receipt commit")
}

func (authority crashedRelayAdmissionAuthority) ResolveRelaySideEffectAdmission(context.Context,
	agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("process unavailable before admission recovery")
}

func (authority *ambiguousRelayAdmissionAuthority) AdmitRelaySideEffects(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	authority.admitCalls++
	if _, err := authority.inner.AdmitRelaySideEffects(ctx, descriptor); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("admission response was lost after commit")
}

func (authority *ambiguousRelayAdmissionAuthority) ResolveRelaySideEffectAdmission(ctx context.Context,
	lookup agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	authority.resolveCalls++
	return authority.inner.ResolveRelaySideEffectAdmission(ctx, lookup)
}

func (transport relayFunctionTransport) Quote(ctx context.Context,
	request agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error) {
	return transport.quote(ctx, request)
}

func (transport relayFunctionTransport) Submit(ctx context.Context, request agentrelay.RelayExecutionRequest,
	agreement commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
	return transport.submit(ctx, request, agreement)
}

func (transport relayFunctionTransport) Resolve(ctx context.Context, call agentrelay.ResolveCall,
	execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
	return transport.resolve(ctx, call, execution)
}

func (transport relayFunctionTransport) Evidence(ctx context.Context, call agentrelay.EvidenceCall,
	request agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
	return transport.evidence(ctx, call, request)
}

func TestRelayCoordinatorRejectsPreparedBOCMutationBeforeQuote(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	quotes := 0
	transport := relayFunctionTransport{
		quote: func(context.Context, agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error) {
			quotes++
			return agentrelay.SignedProviderRelayQuote{}, errors.New("must not be called")
		},
		submit: func(context.Context, agentrelay.RelayExecutionRequest, commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("must not be called")
		},
		resolve: func(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("must not be called")
		},
		evidence: func(context.Context, agentrelay.EvidenceCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("must not be called")
		},
	}
	coordinator := relayTestCoordinator(t, fixture, transport)
	mutated := fixture.prepared
	mutated.ExactSignedBOC = append([]byte(nil), mutated.ExactSignedBOC...)
	mutated.ExactSignedBOC[0] ^= 0xff
	if _, err := coordinator.Prepare(t.Context(), mutated); err == nil || quotes != 0 {
		t.Fatalf("mutated prepared BOC reached a provider quote endpoint: quotes=%d err=%v", quotes, err)
	}
}

func TestRelayAdmissionReceiptDrainsAfterTakeoverAndFencesNewRoute(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	broadcaster := &relayTestBroadcaster{result: agentrelay.BroadcastResult{Status: agentrelay.BroadcastAccepted,
		TransactionReference: "tx:admitted-before-takeover"}}
	provider := fixture.service(agentrelay.NewMemoryJournal(), broadcaster)
	submits := 0
	transport := relayFunctionTransport{
		quote: provider.Quote,
		submit: func(ctx context.Context, request agentrelay.RelayExecutionRequest,
			agreement commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			record, err := provider.Submit(ctx, request, agreement)
			if err != nil {
				return agentrelay.SignedRelayResolution{}, err
			}
			return provider.SignedResolution(record)
		},
		resolve: func(ctx context.Context, call agentrelay.ResolveCall,
			_ agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			record, err := provider.Resolve(ctx, call.StableActionID, call.ExactRequestDigest)
			if err != nil {
				return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
			}
			return provider.SignedResolution(record)
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not used")
		},
	}
	coordinator := relayTestCoordinator(t, fixture, transport)
	attempt, err := coordinator.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	oldFence := attempt.Execution.WriterFence
	if !fixture.now.Before(time.Unix(int64(oldFence.Body.ExpiresAtUnix), 0)) {
		t.Fatal("test does not use an unexpired old writer lease")
	}
	fixture.resolver.setCurrentWriter(fixture.takeoverFence(t))

	result, err := coordinator.Submit(t.Context(), attempt)
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || submits != 1 || broadcaster.submits != 1 {
		t.Fatalf("pre-takeover admission did not drain exactly once: state=%s submits=%d broadcasts=%d err=%v",
			result.Resolution.Body.State, submits, broadcaster.submits, err)
	}
	if _, err := coordinator.Submit(t.Context(), attempt); err != nil || submits != 1 || broadcaster.submits != 1 {
		t.Fatalf("exact admitted retry was not idempotent: submits=%d broadcasts=%d err=%v", submits, broadcaster.submits, err)
	}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptor(attempt.Execution)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.ProviderAgentID = "agent:unadmitted-new-route"
	if _, err := fixture.admission.AdmitRelaySideEffects(t.Context(), descriptor); err == nil {
		t.Fatal("superseded writer minted a new provider-route admission")
	}
	fixture.admission.mu.Lock()
	receiptCount := len(fixture.admission.receipts)
	fixture.admission.mu.Unlock()
	if receiptCount != 1 {
		t.Fatalf("takeover changed the admission ledger: receipts=%d", receiptCount)
	}
}

func TestRelayCoordinatorRecoversAmbiguousAdmissionWithoutNewSemanticAction(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	provider := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	transport := relayFunctionTransport{quote: provider.Quote,
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("not used")
		},
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not used")
		}}
	coordinator := relayTestCoordinator(t, fixture, transport)
	ambiguous := &ambiguousRelayAdmissionAuthority{inner: fixture.admission}
	coordinator.SideEffectAdmission = ambiguous
	attempt, err := coordinator.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous.admitCalls != 1 || ambiguous.resolveCalls != 1 ||
		attempt.Execution.AdmissionReceipt.Body.AdmissionSequence != 1 {
		t.Fatalf("ambiguous admission was not recovered exactly: admit=%d resolve=%d sequence=%d",
			ambiguous.admitCalls, ambiguous.resolveCalls, attempt.Execution.AdmissionReceipt.Body.AdmissionSequence)
	}
	fixture.admission.mu.Lock()
	receiptCount, nextSequence := len(fixture.admission.receipts), fixture.admission.next
	fixture.admission.mu.Unlock()
	if receiptCount != 1 || nextSequence != 2 {
		t.Fatalf("ambiguous recovery allocated another admission: receipts=%d next=%d", receiptCount, nextSequence)
	}
}

func TestRelayAdmissionBindsSponsorAndCombinedActionsToOneProviderRoute(t *testing.T) {
	for _, mode := range []agentrelay.Mode{agentrelay.ModeSponsorOnly, agentrelay.ModeSponsorAndRelay} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newRelayTestFixture(t, "agent:provider-one", nil, "https://one.example")
			fixture.enableSponsorship(t, mode)
			attempt := fixture.attempt(t)
			descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptor(attempt.Execution)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.ProviderAgentID = "agent:provider-two"
			if _, err := fixture.admission.AdmitRelaySideEffects(t.Context(), descriptor); !errors.Is(err, agentrelay.ErrRelayConflict) {
				t.Fatalf("%s action minted a second provider-route receipt: %v", mode, err)
			}
			fixture.admission.mu.Lock()
			receiptCount := len(fixture.admission.receipts)
			fixture.admission.mu.Unlock()
			if receiptCount != 1 {
				t.Fatalf("%s action has %d route receipts", mode, receiptCount)
			}
		})
	}
}

func TestRelayCoordinatorSponsorshipRequiresRouteAdmissionOrSignedProviderRecord(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:sponsor", nil, "https://sponsor.example")
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	providerPrepared, submits := false, 0
	var attempt RelayAttempt
	transport := relayFunctionTransport{
		quote: service.Quote,
		resolve: func(_ context.Context, call agentrelay.ResolveCall,
			execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			executionDigest, _ := agentrelay.RelayExecutionRequestDigest(execution)
			if !providerPrepared {
				return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
			}
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: fixture.profile.ProviderAgentID, Network: fixture.profile.NetworkDomains[0],
				AssuranceLevel:     execution.QuoteRequest.Body.AssuranceLevel,
				StableActionID:     call.StableActionID,
				ExactRequestDigest: call.ExactRequestDigest, RelayExecutionDigest: executionDigest,
				State: commerce.ActionPrepared, StateRevision: 1, ObservedAtUnix: uint64(fixture.now.Unix()),
				ExpiresAtUnix: uint64(fixture.now.Add(time.Minute).Unix())}, fixture.providerKey)
		},
		submit: func(_ context.Context, request agentrelay.RelayExecutionRequest,
			_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			digest, _ := agentrelay.RelayExecutionRequestDigest(request)
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID:    fixture.profile.ProviderAgentID,
				Network:            request.QuoteRequest.Body.Network,
				AssuranceLevel:     request.QuoteRequest.Body.AssuranceLevel,
				StableActionID:     request.AuthorizedAction.StableActionID,
				ExactRequestDigest: request.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: digest,
				State: commerce.ActionAccepted, StateRevision: 2, ObservedAtUnix: uint64(fixture.now.Unix()),
				ExpiresAtUnix: uint64(fixture.now.Add(time.Minute).Unix())}, fixture.providerKey)
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		},
	}
	coordinator := relayTestCoordinator(t, fixture, transport)
	var err error
	attempt, err = coordinator.Prepare(t.Context(), fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Submit(t.Context(), attempt); !errors.Is(err, ErrRelaySubmissionAmbiguous) || submits != 0 {
		t.Fatalf("provider 404 authorized a direct sponsorship retry: submits=%d err=%v", submits, err)
	}
	providerPrepared = true
	result, err := coordinator.Submit(t.Context(), attempt)
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || submits != 1 {
		t.Fatalf("signed exact PREPARED provider record did not resume idempotently: result=%+v submits=%d err=%v",
			result, submits, err)
	}
}

func TestRelayCoordinatorRequiresIndependentFinalityBeforeFailover(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	attempt := fixture.attempt(t)
	resolution, evidence := relayTerminalAbsent(t, fixture, attempt.Execution)
	evidenceCalls := 0
	transport := relayFunctionTransport{
		quote: func(context.Context, agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error) {
			return agentrelay.SignedProviderRelayQuote{}, errors.New("not used")
		},
		submit: func(context.Context, agentrelay.RelayExecutionRequest, commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("not used")
		},
		resolve: func(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return resolution, nil
		},
		evidence: func(context.Context, agentrelay.EvidenceCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			evidenceCalls++
			return evidence, nil
		},
	}
	coordinator := relayTestCoordinator(t, fixture, transport)
	coordinator.FinalityVerifier = nil
	if result, err := coordinator.Submit(t.Context(), attempt); err == nil || result.Evidence != nil || evidenceCalls != 0 {
		t.Fatalf("provider statement became chain truth without verifier: result=%+v calls=%d err=%v", result, evidenceCalls, err)
	}
	coordinator.FinalityVerifier = relayTestFinalityVerifier{dualAbsence: true, portable: true,
		verify: func(context.Context, agentrelay.RelayExecutionRequest,
			agentrelay.SignedRelayFinalityEvidence) error {
			return errors.New("checkpoint quorum disagrees")
		}}
	if result, err := coordinator.Submit(t.Context(), attempt); err == nil || result.Evidence != nil || evidenceCalls != 1 {
		t.Fatalf("failed independent finality was accepted: result=%+v calls=%d err=%v", result, evidenceCalls, err)
	}
	coordinator.FinalityVerifier = relayTestFinalityVerifier{dualAbsence: true, portable: true,
		verify: func(_ context.Context, request agentrelay.RelayExecutionRequest,
			verified agentrelay.SignedRelayFinalityEvidence) error {
			if request.ProviderQuote.Body.RelayFinalityProfile == nil ||
				verified.Body.Network != request.QuoteRequest.Body.Network ||
				verified.Body.RelayFinalizedCheckpointSequence != 100 ||
				len(verified.Body.RelayObservationDigests) < int(request.ProviderQuote.Body.RelayFinalityProfile.MinimumObservers) {
				return errors.New("wrong independent checkpoint")
			}
			return nil
		}}
	originalEvidence := evidence
	mutatedBody := evidence.Body
	mutatedBody.RelayObservationDigests = append([]string(nil), evidence.Body.RelayObservationDigests...)
	mutatedBody.RelayObservationDigests[0] = relayTestDigest("0")
	mutatedEvidence, signErr := agentrelay.SignRelayFinalityEvidence(mutatedBody, fixture.providerKey)
	if signErr != nil {
		t.Fatal(signErr)
	}
	evidence = mutatedEvidence
	if result, err := coordinator.Submit(t.Context(), attempt); err == nil || result.Evidence != nil {
		t.Fatalf("resolution was paired with a different observation set: result=%+v err=%v", result, err)
	}
	evidence = originalEvidence
	result, err := coordinator.Submit(t.Context(), attempt)
	if err != nil || result.Evidence == nil || !RelayFailoverPermitted(result) {
		t.Fatalf("finalized absence did not permit explicit failover: result=%+v err=%v", result, err)
	}
	unknown := RelayExecutionResult{Resolution: agentrelay.SignedRelayResolution{Body: agentrelay.RelayResolutionBody{State: commerce.ActionSubmitted}}}
	if RelayFailoverPermitted(unknown) {
		t.Fatal("provider loss or unknown status permitted failover without finalized absence")
	}
}

func TestDecentralizedRelayRecoversReceiptChainedSuccessorAfterCrashAndSourceLoss(t *testing.T) {
	first := newRelayTestFixture(t, "agent:provider-one", nil, "https://one.example")
	firstService := first.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	firstQuoteCalls, firstAgreementCalls, firstResolveCalls := 0, 0, 0
	firstTransport := relayFunctionTransport{
		quote: func(ctx context.Context, request agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error) {
			firstQuoteCalls++
			raw, _ := codec.Marshal(request)
			if bytes.Contains(raw, first.prepared.ExactSignedBOC) {
				return agentrelay.SignedProviderRelayQuote{}, errors.New("candidate quote disclosed executable BOC")
			}
			return firstService.Quote(ctx, request)
		},
		submit: func(context.Context, agentrelay.RelayExecutionRequest, commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("terminal absence should resolve before submit")
		},
		resolve: func(_ context.Context, call agentrelay.ResolveCall, execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			executionDigest, _ := agentrelay.RelayExecutionRequestDigest(execution)
			firstResolveCalls++
			if firstResolveCalls > 1 {
				return agentrelay.SignedRelayResolution{}, errors.New("prior provider and database are offline")
			}
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: first.profile.ProviderAgentID, Network: first.profile.NetworkDomains[0],
				AssuranceLevel:     execution.QuoteRequest.Body.AssuranceLevel,
				StableActionID:     call.StableActionID,
				ExactRequestDigest: call.ExactRequestDigest, RelayExecutionDigest: executionDigest,
				State: commerce.ActionTerminal, StateRevision: 3, TerminalOutcome: agentrelay.OutcomeFinalizedAbsent,
				EvidenceSetDigest: relayEvidenceSetDigest(t, []string{relayTestDigest("1"), relayTestDigest("2"), relayTestDigest("3")}),
				ObservedAtUnix:    uint64(first.now.Unix()),
				ExpiresAtUnix:     uint64(first.now.Add(time.Minute).Unix())}, first.providerKey)
		},
		evidence: func(_ context.Context, _ agentrelay.EvidenceCall,
			request agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			_, evidence := relayTerminalAbsent(t, first, request)
			return evidence, nil
		},
	}
	firstCoordinator := relayTestCoordinator(t, first, firstTransport)
	firstAuthorizer := firstCoordinator.AgreementAuthorizer
	firstCoordinator.AgreementAuthorizer = RelayAgreementAuthorizerFunc(func(ctx context.Context,
		request agentrelay.SignedRelayQuoteRequest, quote agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error) {
		firstAgreementCalls++
		return firstAuthorizer.AuthorizeRelayAgreement(ctx, request, quote)
	})

	_, secondProviderKey, _ := ed25519.GenerateKey(nil)
	second := newRelayTestFixture(t, "agent:provider-two", secondProviderKey, "https://two.example")
	second.clientKey, second.authorityKey = first.clientKey, first.authorityKey
	second.resolver = relayTestResolver{agents: map[string]ed25519.PublicKey{
		"agent:client":       first.clientKey.Public().(ed25519.PublicKey),
		"agent:provider-two": secondProviderKey.Public().(ed25519.PublicKey)},
		authorityKey: first.authorityKey.Public().(ed25519.PublicKey), current: first.resolver.current}
	// Provider routes share the requester's one Action Authority. A second
	// provider is not a second writer/high-water domain.
	second.admission = first.admission
	secondService := second.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	secondQuoteCalls, secondAgreementCalls, submits := 0, 0, 0
	secondTransport := relayFunctionTransport{
		quote: func(ctx context.Context, request agentrelay.SignedRelayQuoteRequest) (agentrelay.SignedProviderRelayQuote, error) {
			secondQuoteCalls++
			raw, _ := codec.Marshal(request)
			if bytes.Contains(raw, first.prepared.ExactSignedBOC) {
				return agentrelay.SignedProviderRelayQuote{}, errors.New("candidate quote disclosed executable BOC")
			}
			return secondService.Quote(ctx, request)
		},
		resolve: func(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		submit: func(_ context.Context, request agentrelay.RelayExecutionRequest,
			_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			submits++
			digest, _ := agentrelay.RelayExecutionRequestDigest(request)
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: "agent:provider-two", Network: request.QuoteRequest.Body.Network,
				AssuranceLevel:     request.QuoteRequest.Body.AssuranceLevel,
				StableActionID:     request.AuthorizedAction.StableActionID,
				ExactRequestDigest: request.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: digest,
				State: commerce.ActionAccepted, StateRevision: 2, TransactionReference: "tx:second-provider",
				ObservedAtUnix: uint64(second.now.Unix()), ExpiresAtUnix: uint64(second.now.Add(time.Minute).Unix())}, second.providerKey)
		},
		evidence: func(context.Context, agentrelay.EvidenceCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		},
	}
	secondCoordinator := relayTestCoordinator(t, second, secondTransport)
	secondAuthorizer := secondCoordinator.AgreementAuthorizer
	secondCoordinator.AgreementAuthorizer = RelayAgreementAuthorizerFunc(func(ctx context.Context,
		request agentrelay.SignedRelayQuoteRequest, quote agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error) {
		secondAgreementCalls++
		return secondAuthorizer.AuthorizeRelayAgreement(ctx, request, quote)
	})
	selectorCalls := 0
	routeDirectory := filepath.Join(t.TempDir(), "relay-routes")
	if err := os.Mkdir(routeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	routeJournal, err := OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer routeJournal.Close()
	provenanceVerifier := RelayProviderProvenanceVerifierFunc(func(_ context.Context,
		verified VerifiedRelayServiceProfile) (RelayProviderProvenance, error) {
		profile := verified.Profile()
		profileDigest, digestErr := agentrelay.RelayServiceProfileDigest(profile)
		origin, originErr := relayProfileEndpointOrigin(profile.Endpoints)
		if digestErr != nil || originErr != nil {
			return RelayProviderProvenance{}, errors.Join(digestErr, originErr)
		}
		suffix := "1"
		implementation := "a"
		if profile.ProviderAgentID == "agent:provider-two" {
			suffix = "2"
			implementation = "b"
		}
		return RelayProviderProvenance{ProviderAgentID: profile.ProviderAgentID,
			IntentDigest: verified.IntentDigest(), ProfileDigest: profileDigest,
			OperatorDomain: "operator:" + suffix, FailureDomain: "failure:" + suffix,
			EndpointOrigin: origin, CertificatePinDigest: relayTestDigest(suffix),
			ImplementationEvidenceHash: relayTestDigest(implementation)}, nil
	})
	orchestrator := DecentralizedRelayCoordinator{Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator},
		ProvenanceVerifier: provenanceVerifier, AgentResolver: firstCoordinator.AgentResolver,
		RouteJournal: routeJournal, MaximumRouteAttempts: 2,
		Selector: RelayProviderSelectorFunc(func(context.Context, []RelayQuoteCandidate) (int, error) {
			selectorCalls++
			return 0, nil
		})}
	plan, err := orchestrator.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if firstQuoteCalls != 1 || secondQuoteCalls != 1 || firstAgreementCalls != 1 || secondAgreementCalls != 0 ||
		plan.Attempt.Execution.QuoteRequest.Body.RequestID == first.prepared.QuoteBody.RequestID {
		t.Fatalf("decentralized quote/selection boundary failed: quotes=%d/%d agreements=%d/%d route=%q",
			firstQuoteCalls, secondQuoteCalls, firstAgreementCalls, secondAgreementCalls,
			plan.Attempt.Execution.QuoteRequest.Body.RequestID)
	}
	firstResult, err := orchestrator.Submit(t.Context(), plan)
	if err != nil || !RelayFailoverPermitted(firstResult) {
		t.Fatalf("first provider lacks safe terminal failover proof: %v", err)
	}
	unknown := RelayExecutionResult{Resolution: agentrelay.SignedRelayResolution{Body: agentrelay.RelayResolutionBody{
		State: commerce.ActionSubmitted}}}
	if _, err := orchestrator.Failover(t.Context(), plan, unknown); err == nil {
		t.Fatal("ambiguous provider state permitted sponsorship/relay failover")
	}
	credited := firstResult
	creditedEvidence := *credited.Evidence
	creditedEvidence.Body.SponsorshipTransferReference = "tx:already-funded"
	credited.Evidence = &creditedEvidence
	if RelayFailoverPermitted(credited) {
		t.Fatal("finalized absence attempted a second provider after a sponsorship transfer")
	}
	// The prior Provider's short-lived status response has expired and its
	// endpoint now fails. Durable independently verified chain evidence, not an
	// online Provider refresh, authorizes the source-loss failover.
	firstCoordinator.Now = func() time.Time { return first.now.Add(2 * time.Minute) }
	firstReceipt := plan.Attempt.Execution.AdmissionReceipt
	secondCoordinator.SideEffectAdmission = crashedRelayAdmissionAuthority{inner: first.admission}
	if _, err := orchestrator.Failover(t.Context(), plan, firstResult); err == nil || submits != 0 {
		t.Fatalf("simulated crash did not stop between successor receipt and route commit: submits=%d err=%v", submits, err)
	}
	if firstResolveCalls != 1 {
		t.Fatalf("failover consulted the removed prior provider after independently verified finality: resolves=%d", firstResolveCalls)
	}
	if secondAgreementCalls != 1 || selectorCalls != 2 {
		t.Fatalf("relay successor did not use owner selection and one exact Agreement: agreements=%d selector_calls=%d",
			secondAgreementCalls, selectorCalls)
	}
	// Receipt issuance is the linearization point. A takeover after issuance
	// must prevent any new stale-writer receipt while still allowing recovery
	// and drain of this exact already-authorized successor.
	first.resolver.setCurrentWriter(first.takeoverFence(t))
	if err := routeJournal.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedRoutes, err := OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedRoutes.Close()
	orchestrator.RouteJournal = reopenedRoutes
	secondCoordinator.SideEffectAdmission = first.admission
	resumed, err := orchestrator.Prepare(t.Context(), first.prepared)
	if err != nil || resumed.Attempt.Execution.ProviderQuote.Body.ProviderAgentID != "agent:provider-one" ||
		!bytes.Equal(resumed.Attempt.Execution.SignedTransactionBytes, first.prepared.ExactSignedBOC) || selectorCalls != 2 {
		t.Fatalf("restart did not recover the pending successor route: provider=%q selector_calls=%d err=%v",
			resumed.Attempt.Execution.ProviderQuote.Body.ProviderAgentID, selectorCalls, err)
	}
	recoveredTerminal, err := orchestrator.Submit(t.Context(), resumed)
	if err != nil || recoveredTerminal.Evidence == nil {
		t.Fatalf("restart did not recover the prior terminal evidence: %v", err)
	}
	if _, err := orchestrator.Failover(t.Context(), resumed, recoveredTerminal); err != nil || submits != 1 {
		t.Fatalf("restart did not recover and consume the exact successor receipt: submits=%d err=%v", submits, err)
	}
	predecessorDigest, err := agentrelay.RelaySideEffectAdmissionReceiptBodyDigest(firstReceipt.Body)
	if err != nil || resumed.Attempt.Execution.AdmissionReceipt.Body.RouteAttempt != 2 ||
		resumed.Attempt.Execution.AdmissionReceipt.Body.PredecessorReceiptDigest != predecessorDigest ||
		resumed.Attempt.Execution.AdmissionReceipt.Body.TransactionIdentityDigest != firstReceipt.Body.TransactionIdentityDigest {
		t.Fatalf("relay successor receipt did not preserve its exact transaction lineage: %+v err=%v",
			resumed.Attempt.Execution.AdmissionReceipt.Body, err)
	}
}

func TestDecentralizedRelayExactQueryFailoverSurvivesCrashRestartAndProviderRemoval(t *testing.T) {
	first := newRelayTestFixture(t, "agent:sponsor-one", nil, "https://relay-one.example")
	firstService := first.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	clock := first.now
	firstResolveCalls, firstSubmitCalls := 0, 0
	firstTransport := relayFunctionTransport{authenticatedResolve: true, quote: firstService.Quote,
		resolve: func(_ context.Context, call agentrelay.ResolveCall,
			execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			firstResolveCalls++
			clock = clock.Add(time.Second)
			first.admission.now = clock
			if firstResolveCalls < 3 {
				return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
			}
			executionDigest, _ := agentrelay.RelayExecutionRequestDigest(execution)
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: first.profile.ProviderAgentID, Network: execution.QuoteRequest.Body.Network,
				AssuranceLevel: execution.QuoteRequest.Body.AssuranceLevel,
				StableActionID: call.StableActionID, ExactRequestDigest: call.ExactRequestDigest,
				RelayExecutionDigest: executionDigest, State: commerce.ActionSubmitted, StateRevision: 2,
				ObservedAtUnix: uint64(clock.Unix()), ExpiresAtUnix: uint64(clock.Add(time.Second).Unix())},
				first.providerKey)
		},
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			firstSubmitCalls++
			return agentrelay.SignedRelayResolution{}, fmt.Errorf("%w: provider database and submit response were lost",
				ErrRelaySubmissionAmbiguous)
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("provider database is unavailable")
		}}
	firstCoordinator := relayTestCoordinator(t, first, firstTransport)
	firstCoordinator.Now = func() time.Time { return clock }

	_, secondKey, _ := ed25519.GenerateKey(nil)
	second := newRelayTestFixture(t, "agent:sponsor-two", secondKey, "https://relay-two.example")
	second.clientKey, second.authorityKey = first.clientKey, first.authorityKey
	second.resolver = relayTestResolver{agents: map[string]ed25519.PublicKey{
		"agent:client": first.clientKey.Public().(ed25519.PublicKey), "agent:sponsor-two": secondKey.Public().(ed25519.PublicKey)},
		authorityKey: first.authorityKey.Public().(ed25519.PublicKey), current: first.resolver.current}
	second.admission = first.admission
	secondService := second.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	secondSubmits := 0
	secondTransport := relayFunctionTransport{quote: secondService.Quote,
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		submit: func(_ context.Context, request agentrelay.RelayExecutionRequest,
			_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			secondSubmits++
			digest, _ := agentrelay.RelayExecutionRequestDigest(request)
			return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
				ProviderAgentID: "agent:sponsor-two", Network: request.QuoteRequest.Body.Network,
				AssuranceLevel:     request.QuoteRequest.Body.AssuranceLevel,
				StableActionID:     request.AuthorizedAction.StableActionID,
				ExactRequestDigest: request.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: digest,
				State: commerce.ActionAccepted, StateRevision: 2, TransactionReference: "tx:query-failover",
				ObservedAtUnix: uint64(second.now.Unix()), ExpiresAtUnix: uint64(second.now.Add(time.Minute).Unix())},
				second.providerKey)
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
		}}
	secondCoordinator := relayTestCoordinator(t, second, secondTransport)
	secondCoordinator.Now = func() time.Time { return clock }

	routeDirectory := filepath.Join(t.TempDir(), "query-failover-routes")
	if err := os.Mkdir(routeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator := DecentralizedRelayCoordinator{
		Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator}, Selector: RelayProviderSelectorFunc(
			func(context.Context, []RelayQuoteCandidate) (int, error) { return 0, nil }),
		ProvenanceVerifier: relayTestIndependentProvenanceVerifier(), AgentResolver: firstCoordinator.AgentResolver,
		RouteJournal:         routes,
		MaximumRouteAttempts: 2,
	}
	plan, err := orchestrator.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt := plan.Attempt.Execution.AdmissionReceipt
	if _, err := orchestrator.Submit(t.Context(), plan); !errors.Is(err, ErrRelaySubmissionAmbiguous) ||
		firstSubmitCalls != 1 {
		t.Fatalf("first Provider did not enter an ambiguous exact-relay state: submits=%d err=%v", firstSubmitCalls, err)
	}
	unauthenticated := firstTransport
	unauthenticated.authenticatedResolve = false
	firstCoordinator.Transport = unauthenticated
	resolveCallsBefore := firstResolveCalls
	if _, err := orchestrator.Failover(t.Context(), plan, RelayExecutionResult{}); err == nil {
		t.Fatal("unsealed/pre-dispatch Resolve path created a relay successor")
	}
	beforeGate, err := routes.Resolve(first.prepared.UnderlyingAction.StableActionID,
		first.prepared.UnderlyingAction.ExactRequestDigest)
	if err != nil || beforeGate.Hops[0].FailoverQueryAttempt != nil || firstResolveCalls != resolveCallsBefore {
		t.Fatalf("failed authenticated dispatch mutated the query gate: calls=%d/%d route=%+v err=%v",
			firstResolveCalls, resolveCallsBefore, beforeGate, err)
	}
	firstCoordinator.Transport = firstTransport
	secondCoordinator.SideEffectAdmission = crashedRelayAdmissionAuthority{inner: first.admission}
	if _, err := orchestrator.Failover(t.Context(), plan, RelayExecutionResult{}); err == nil || secondSubmits != 0 {
		t.Fatalf("crash after successor receipt issuance was not preserved: submits=%d err=%v", secondSubmits, err)
	}
	stored, err := routes.Resolve(first.prepared.UnderlyingAction.StableActionID,
		first.prepared.UnderlyingAction.ExactRequestDigest)
	if err != nil || stored.PendingSwitch == nil || !stored.PendingSwitch.AdmissionStarted ||
		stored.PendingSwitch.CumulativeServiceFeeAtomicAfter != "6" || stored.CumulativeServiceFeeAtomic != "3" ||
		stored.Hops[0].FailoverQueryAttempt == nil ||
		stored.Hops[0].FailoverQueryAttempt.Outcome != relayResolveAmbiguous {
		t.Fatalf("query, fee reservation, and admission ambiguity were not durable: route=%+v err=%v", stored, err)
	}
	if firstResolveCalls < 3 {
		t.Fatalf("failover skipped the authenticated post-ambiguity Resolve attempt: calls=%d", firstResolveCalls)
	}
	clock = clock.Add(2 * time.Second) // expire the cached status, not the admission receipt
	first.resolver.setCurrentWriter(first.takeoverFence(t))
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	rawRoute, err := os.ReadFile(filepath.Join(routeDirectory, relayRouteJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	var tamperedDocument relayRouteJournalDocument
	if err := json.Unmarshal(rawRoute, &tamperedDocument); err != nil {
		t.Fatal(err)
	}
	query := tamperedDocument.Records[0].Hops[0].FailoverQueryAttempt
	if query == nil || query.Resolution == nil || len(query.Resolution.Signature) == 0 {
		t.Fatal("signed ambiguous query was not available for tamper recovery test")
	}
	signature := query.Resolution.Signature
	last := byte('0')
	if signature[len(signature)-1] == '0' {
		last = '1'
	}
	query.Resolution.Signature = signature[:len(signature)-1] + string(last)
	tamperedDigest, err := relayRouteResolveQueryAttemptDigest(*query)
	if err != nil {
		t.Fatal(err)
	}
	tamperedDocument.Records[0].Hops[0].FailoverQueryAttemptDigest = tamperedDigest
	tamperedDocument.Records[0].PendingSwitch.FailoverGateDigest = tamperedDigest
	tamperedDirectory := filepath.Join(t.TempDir(), "tampered-query-route")
	if err := os.Mkdir(tamperedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	tamperedRaw, err := json.Marshal(tamperedDocument)
	if err != nil || os.WriteFile(filepath.Join(tamperedDirectory, relayRouteJournalFile), tamperedRaw, 0o600) != nil {
		t.Fatalf("write tampered relay route: %v", err)
	}
	tamperedRoutes, err := OpenDurableRelayRouteJournal(tamperedDirectory)
	if err != nil {
		t.Fatalf("shape-valid tampered query should reach historical authorization verification: %v", err)
	}
	tamperedOrchestrator := orchestrator
	tamperedOrchestrator.Providers = []*RelayCoordinator{&secondCoordinator}
	tamperedOrchestrator.RouteJournal = tamperedRoutes
	tamperedPlan, err := tamperedOrchestrator.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tamperedOrchestrator.Failover(t.Context(), tamperedPlan, RelayExecutionResult{}); err == nil {
		t.Fatal("tampered persisted Provider query signature survived restart authorization")
	}
	if err := tamperedRoutes.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err = OpenDurableRelayRouteJournal(routeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	// Simulate complete source removal: the prior Provider coordinator and its
	// status database are absent, not merely returning an HTTP error.
	orchestrator.Providers = []*RelayCoordinator{&secondCoordinator}
	orchestrator.RouteJournal = routes
	orchestrator.MaximumRouteAttempts = 1 // lower policy cannot revoke an already-started admission
	secondCoordinator.SideEffectAdmission = first.admission
	resumed, err := orchestrator.Prepare(t.Context(), first.prepared)
	if err != nil || resumed.candidates[resumed.selected].Coordinator != nil {
		t.Fatalf("restart did not recover the owner-local query gate without the old Provider: err=%v", err)
	}
	result, err := orchestrator.Failover(t.Context(), resumed, RelayExecutionResult{})
	if err != nil || result.Resolution.Body.State != commerce.ActionAccepted || secondSubmits != 1 {
		t.Fatalf("exact receipt-chained successor did not drain after restart/takeover: result=%+v submits=%d err=%v",
			result.Resolution.Body, secondSubmits, err)
	}
	orchestrator.MaximumRouteAttempts = agentrelay.MaxRelayRouteAttempts
	if _, err := orchestrator.Failover(t.Context(), resumed, RelayExecutionResult{}); err == nil {
		t.Fatal("raising the current policy expanded the immutable two-attempt route ceiling")
	}
	finalRoute, err := routes.Resolve(first.prepared.UnderlyingAction.StableActionID,
		first.prepared.UnderlyingAction.ExactRequestDigest)
	predecessorDigest, digestErr := agentrelay.RelaySideEffectAdmissionReceiptBodyDigest(firstReceipt.Body)
	current, found := finalRoute.Current()
	if err != nil || digestErr != nil || !found || len(finalRoute.Hops) != 2 ||
		finalRoute.CumulativeServiceFeeAtomic != "6" || current.Attempt.Execution.AdmissionReceipt.Body.RouteAttempt != 2 ||
		current.Attempt.Execution.AdmissionReceipt.Body.PredecessorReceiptDigest != predecessorDigest ||
		current.Attempt.Execution.AdmissionReceipt.Body.TransactionIdentityDigest != firstReceipt.Body.TransactionIdentityDigest ||
		!bytes.Equal(current.Attempt.Execution.SignedTransactionBytes, first.prepared.ExactSignedBOC) {
		t.Fatalf("recovered successor changed route/fee/transaction identity: route=%+v err=%v/%v", finalRoute, err, digestErr)
	}
}

func TestDecentralizedRelayFailoverRejectsCumulativeFeeBeforeAgreement(t *testing.T) {
	first := newRelayTestFixture(t, "agent:sponsor-one", nil, "https://fee-one.example")
	firstService := first.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	firstTransport := relayFunctionTransport{quote: firstService.Quote,
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("not used")
		},
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not used")
		}}
	firstCoordinator := relayTestCoordinator(t, first, firstTransport)
	_, secondKey, _ := ed25519.GenerateKey(nil)
	second := newRelayTestFixture(t, "agent:sponsor-two", secondKey, "https://fee-two.example")
	second.clientKey, second.authorityKey = first.clientKey, first.authorityKey
	second.resolver = relayTestResolver{agents: map[string]ed25519.PublicKey{
		"agent:client": first.clientKey.Public().(ed25519.PublicKey), "agent:sponsor-two": secondKey.Public().(ed25519.PublicKey)},
		authorityKey: first.authorityKey.Public().(ed25519.PublicKey), current: first.resolver.current}
	second.admission = first.admission
	secondService := second.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	secondService.QuotePolicy = relayTestQuotePolicy{fee: "8", intent: second.verified.IntentDigest()}
	secondTransport := relayFunctionTransport{quote: secondService.Quote,
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("must not submit")
		},
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("must not request evidence")
		}}
	secondCoordinator := relayTestCoordinator(t, second, secondTransport)
	secondAgreementCalls := 0
	secondAuthorizer := secondCoordinator.AgreementAuthorizer
	secondCoordinator.AgreementAuthorizer = RelayAgreementAuthorizerFunc(func(ctx context.Context,
		request agentrelay.SignedRelayQuoteRequest, quote agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error) {
		secondAgreementCalls++
		return secondAuthorizer.AuthorizeRelayAgreement(ctx, request, quote)
	})
	directory := filepath.Join(t.TempDir(), "fee-cap-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	routes, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	orchestrator := DecentralizedRelayCoordinator{Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator},
		Selector:           RelayProviderSelectorFunc(func(context.Context, []RelayQuoteCandidate) (int, error) { return 0, nil }),
		ProvenanceVerifier: relayTestIndependentProvenanceVerifier(), AgentResolver: firstCoordinator.AgentResolver,
		RouteJournal: routes, MaximumRouteAttempts: 2}
	plan, err := orchestrator.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, _ := agentrelay.RelayExecutionRequestDigest(plan.Attempt.Execution)
	route, err := routes.MarkSubmitStarted(plan.base.UnderlyingAction.StableActionID,
		plan.base.UnderlyingAction.ExactRequestDigest, 1, executionDigest, first.now.Add(time.Second))
	current, _ := route.Current()
	principal := current.Attempt.Execution.AdmissionReceipt.Body.AuthenticatedPrincipal
	authDigest, _ := relayTransportAuthenticationDigest(current.Provider, principal)
	networkDigest, _ := agentrelay.NetworkDomainDigest(current.Attempt.Execution.QuoteRequest.Body.Network)
	transactionDigest, _ := agentrelay.RelayTransactionIdentityDigest(current.Attempt.Execution.QuoteRequest.Body)
	query := relayRouteResolveQueryAttempt{SchemaVersion: 1, RouteGeneration: 1,
		ProviderAgentID: current.Provider.ProviderAgentID, ProviderProfileDigest: current.Provider.ProfileDigest,
		AuthenticatedPrincipal: principal, TransportAuthenticationDigest: authDigest, NetworkDigest: networkDigest,
		TransactionIdentityDigest: transactionDigest, StableActionID: route.StableActionID,
		ExactRequestDigest: route.ExactRequestDigest, RelayExecutionDigest: current.RelayExecutionDigest,
		Outcome: relayResolveRemoteUnknown, StartedAtUnix: uint64(first.now.Add(2 * time.Second).Unix()),
		CompletedAtUnix: uint64(first.now.Add(3 * time.Second).Unix())}
	if _, err := routes.recordResolveQuery(route.StableActionID, route.ExactRequestDigest, 1, query); err != nil {
		t.Fatal(err)
	}
	if _, err := orchestrator.Failover(t.Context(), plan, RelayExecutionResult{}); err == nil {
		t.Fatal("cumulative Provider fees above the signed request cap admitted a successor")
	}
	stored, err := routes.Resolve(route.StableActionID, route.ExactRequestDigest)
	if err != nil || secondAgreementCalls != 0 || stored.PendingSwitch != nil ||
		stored.CumulativeServiceFeeAtomic != "3" || stored.MaximumCumulativeServiceFeeAtomic != "10" {
		t.Fatalf("fee-cap rejection occurred after Agreement/admission or mutated exposure: calls=%d route=%+v err=%v",
			secondAgreementCalls, stored, err)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	singleDirectory := filepath.Join(t.TempDir(), "single-attempt-policy")
	if err := os.Mkdir(singleDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	singleRoutes, err := OpenDurableRelayRouteJournal(singleDirectory)
	if err != nil {
		t.Fatal(err)
	}
	singleAttempt := orchestrator
	singleAttempt.RouteJournal, singleAttempt.MaximumRouteAttempts = singleRoutes, 1
	singlePlan, err := singleAttempt.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	singleDigest, _ := agentrelay.RelayExecutionRequestDigest(singlePlan.Attempt.Execution)
	if _, err := singleRoutes.MarkSubmitStarted(singlePlan.base.UnderlyingAction.StableActionID,
		singlePlan.base.UnderlyingAction.ExactRequestDigest, 1, singleDigest, first.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := singleRoutes.Close(); err != nil {
		t.Fatal(err)
	}
	singleRoutes, err = OpenDurableRelayRouteJournal(singleDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer singleRoutes.Close()
	singleAttempt.RouteJournal = singleRoutes
	singlePlan, err = singleAttempt.Prepare(t.Context(), first.prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singleAttempt.Failover(t.Context(), singlePlan, RelayExecutionResult{}); err == nil {
		t.Fatal("one-attempt owner policy admitted a second Provider after restart")
	}
	singleStored, err := singleRoutes.Resolve(singlePlan.base.UnderlyingAction.StableActionID,
		singlePlan.base.UnderlyingAction.ExactRequestDigest)
	if err != nil || singleStored.MaximumRouteAttempts != 1 || singleStored.PendingSwitch != nil ||
		singleStored.Hops[0].FailoverQueryAttempt != nil {
		t.Fatalf("one-attempt cap mutated side effects before rejection: route=%+v err=%v", singleStored, err)
	}
}

func TestDecentralizedRelaySponsorshipLostResponseRestartAndBlocksUnsafeSuccessor(t *testing.T) {
	for _, mode := range []agentrelay.Mode{agentrelay.ModeSponsorOnly, agentrelay.ModeSponsorAndRelay} {
		t.Run(string(mode), func(t *testing.T) {
			first := newRelayTestFixture(t, "agent:sponsor-one", nil, "https://sponsor-one.example")
			first.enableSponsorship(t, mode)
			firstService := first.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
			var submitted agentrelay.RelayExecutionRequest
			submitCalls, providerLost, finalReady := 0, false, false
			firstTransport := relayFunctionTransport{
				quote: firstService.Quote,
				submit: func(_ context.Context, request agentrelay.RelayExecutionRequest,
					_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
					submitCalls++
					submitted = request
					return agentrelay.SignedRelayResolution{}, ErrRelaySubmissionAmbiguous
				},
				resolve: func(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
					if providerLost {
						return agentrelay.SignedRelayResolution{}, errors.New("selected provider is offline")
					}
					if !finalReady || submitted.SchemaVersion == 0 {
						return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
					}
					resolution, _ := relaySponsorshipTerminalAbsent(t, first, submitted)
					return resolution, nil
				},
				evidence: func(_ context.Context, _ agentrelay.EvidenceCall,
					request agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
					if providerLost {
						return agentrelay.SignedRelayFinalityEvidence{}, errors.New("selected provider is offline")
					}
					_, evidence := relaySponsorshipTerminalAbsent(t, first, request)
					return evidence, nil
				},
			}
			firstCoordinator := relayTestCoordinator(t, first, firstTransport)

			_, secondProviderKey, _ := ed25519.GenerateKey(nil)
			second := newRelayTestFixture(t, "agent:sponsor-two", secondProviderKey, "https://sponsor-two.example")
			second.enableSponsorship(t, mode)
			second.clientKey, second.authorityKey = first.clientKey, first.authorityKey
			second.resolver = relayTestResolver{agents: map[string]ed25519.PublicKey{
				"agent:client": first.clientKey.Public().(ed25519.PublicKey), "agent:sponsor-two": secondProviderKey.Public().(ed25519.PublicKey)},
				authorityKey: first.authorityKey.Public().(ed25519.PublicKey), current: first.resolver.current}
			second.admission = first.admission
			secondService := second.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
			secondSubmits := 0
			secondTransport := relayFunctionTransport{
				quote: secondService.Quote,
				resolve: func(context.Context, agentrelay.ResolveCall, agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
					return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
				},
				submit: func(_ context.Context, request agentrelay.RelayExecutionRequest,
					_ commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
					secondSubmits++
					digest, _ := agentrelay.RelayExecutionRequestDigest(request)
					return agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
						ProviderAgentID: second.profile.ProviderAgentID, Network: request.QuoteRequest.Body.Network,
						AssuranceLevel:     request.QuoteRequest.Body.AssuranceLevel,
						StableActionID:     request.AuthorizedAction.StableActionID,
						ExactRequestDigest: request.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: digest,
						State: commerce.ActionAccepted, StateRevision: 2, ObservedAtUnix: uint64(second.now.Unix()),
						ExpiresAtUnix: uint64(second.now.Add(time.Minute).Unix())}, second.providerKey)
				},
				evidence: func(context.Context, agentrelay.EvidenceCall,
					agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
					return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not terminal")
				},
			}
			secondCoordinator := relayTestCoordinator(t, second, secondTransport)

			routeDirectory := filepath.Join(t.TempDir(), "sponsorship-routes")
			if err := os.Mkdir(routeDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			routes, err := OpenDurableRelayRouteJournal(routeDirectory)
			if err != nil {
				t.Fatal(err)
			}
			provenance := relayTestIndependentProvenanceVerifier()
			orchestrator := DecentralizedRelayCoordinator{Providers: []*RelayCoordinator{&firstCoordinator, &secondCoordinator},
				ProvenanceVerifier: provenance, AgentResolver: firstCoordinator.AgentResolver,
				RouteJournal: routes, MaximumRouteAttempts: 2,
				Selector: RelayProviderSelectorFunc(func(context.Context, []RelayQuoteCandidate) (int, error) { return 0, nil })}
			plan, err := orchestrator.Prepare(t.Context(), first.prepared)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := orchestrator.Submit(t.Context(), plan); !errors.Is(err, ErrRelaySubmissionAmbiguous) || submitCalls != 1 {
				t.Fatalf("lost response was not left ambiguous: submits=%d err=%v", submitCalls, err)
			}
			if err := routes.Close(); err != nil {
				t.Fatal(err)
			}
			routes, err = OpenDurableRelayRouteJournal(routeDirectory)
			if err != nil {
				t.Fatal(err)
			}
			defer routes.Close()
			orchestrator.RouteJournal = routes
			resumed, err := orchestrator.Prepare(t.Context(), first.prepared)
			if err != nil {
				t.Fatal(err)
			}
			// The first provider applied an ambiguous request but then lost its
			// action database. A 404/unknown response is not absence proof and
			// must never cause a second sponsorship dispatch.
			if _, err := orchestrator.Submit(t.Context(), resumed); !errors.Is(err, ErrRelaySubmissionAmbiguous) ||
				submitCalls != 1 || secondSubmits != 0 {
				t.Fatalf("missing sponsor record caused an unsafe retry: first=%d second=%d err=%v",
					submitCalls, secondSubmits, err)
			}
			terminalAtUnix := submitted.QuoteRequest.Body.TransactionValidUntilUnix +
				uint64(submitted.ProviderQuote.Body.SponsorshipTerminalProfile.ReorgWindowSeconds) + 1
			if submitted.ProviderQuote.Body.RelayFinalityProfile != nil {
				relayAt := submitted.QuoteRequest.Body.TransactionValidUntilUnix +
					uint64(submitted.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds) + 1
				if relayAt > terminalAtUnix {
					terminalAtUnix = relayAt
				}
			}
			firstCoordinator.Now = func() time.Time {
				return time.Unix(int64(terminalAtUnix), 0).UTC()
			}
			finalReady = true
			terminal, err := orchestrator.Submit(t.Context(), resumed)
			if err != nil || terminal.Evidence == nil || !relayFailoverPermittedForExecution(terminal, resumed.Attempt.Execution) ||
				submitCalls != 1 || secondSubmits != 0 {
				t.Fatalf("restart did not resolve the original sponsor first: first=%d second=%d terminal=%+v err=%v",
					submitCalls, secondSubmits, terminal, err)
			}
			// Crash after receiving terminal evidence but before accounting, then
			// lose the selected provider and its database. The owner route journal
			// must reconstruct and independently reverify the exact result without
			// another provider status/evidence request.
			if err := routes.Close(); err != nil {
				t.Fatal(err)
			}
			providerLost = true
			routes, err = OpenDurableRelayRouteJournal(routeDirectory)
			if err != nil {
				t.Fatal(err)
			}
			defer routes.Close()
			orchestrator.RouteJournal = routes
			recoveredPlan, err := orchestrator.Prepare(t.Context(), first.prepared)
			if err != nil {
				t.Fatal(err)
			}
			recoveredTerminal, err := orchestrator.Submit(t.Context(), recoveredPlan)
			if err != nil || recoveredTerminal.Evidence == nil || submitCalls != 1 || secondSubmits != 0 {
				t.Fatalf("durable terminal evidence did not survive provider/database loss: first=%d second=%d err=%v",
					submitCalls, secondSubmits, err)
			}
			if _, err := orchestrator.Failover(t.Context(), recoveredPlan, recoveredTerminal); !errors.Is(err, ErrRelaySuccessorAdmissionNotEnabled) || secondSubmits != 0 || submitCalls != 1 {
				t.Fatalf("V1 minted a second sponsorship route without a canonical successor transition: first=%d second=%d err=%v",
					submitCalls, secondSubmits, err)
			}
			if !bytes.Equal(recoveredPlan.Attempt.Execution.SignedTransactionBytes, first.prepared.ExactSignedBOC) ||
				recoveredPlan.Attempt.Execution.AuthorizedAction.StableActionID != first.prepared.UnderlyingAction.StableActionID {
				t.Fatal("sponsorship recovery changed the exact transaction or semantic action identity")
			}
		})
	}
}

func relayTestIndependentProvenanceVerifier() RelayProviderProvenanceVerifier {
	return RelayProviderProvenanceVerifierFunc(func(_ context.Context,
		verified VerifiedRelayServiceProfile) (RelayProviderProvenance, error) {
		profile := verified.Profile()
		profileDigest, digestErr := agentrelay.RelayServiceProfileDigest(profile)
		origin, originErr := relayProfileEndpointOrigin(profile.Endpoints)
		if digestErr != nil || originErr != nil {
			return RelayProviderProvenance{}, errors.Join(digestErr, originErr)
		}
		suffix, implementation := "one", "a"
		if profile.ProviderAgentID == "agent:sponsor-two" {
			suffix, implementation = "two", "b"
		}
		return RelayProviderProvenance{ProviderAgentID: profile.ProviderAgentID,
			IntentDigest: verified.IntentDigest(), ProfileDigest: profileDigest,
			OperatorDomain: "operator:" + suffix, FailureDomain: "failure:" + suffix,
			EndpointOrigin: origin, CertificatePinDigest: relayTestDigest(map[string]string{"one": "1", "two": "2"}[suffix]),
			ImplementationEvidenceHash: relayTestDigest(implementation)}, nil
	})
}

func relaySponsorshipTerminalAbsent(t *testing.T, fixture *relayTestFixture,
	execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, agentrelay.SignedRelayFinalityEvidence) {
	t.Helper()
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	sponsorshipStableID, sponsorshipExactDigest := relayTestDigest("7"), relayTestDigest("8")
	validUntil := uint64(fixture.now.Add(90 * time.Second).Unix())
	if execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		t.Fatal("sponsorship terminal profile is missing")
	}
	terminalProfile := *execution.ProviderQuote.Body.SponsorshipTerminalProfile
	checkpointUnix := validUntil + uint64(terminalProfile.ReorgWindowSeconds) + 1
	transactionReorg := terminalProfile.ReorgWindowSeconds
	if execution.ProviderQuote.Body.RelayFinalityProfile != nil {
		transactionReorg = execution.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds
	}
	transactionCheckpoint := execution.QuoteRequest.Body.TransactionValidUntilUnix + uint64(transactionReorg) + 1
	if transactionCheckpoint > checkpointUnix {
		checkpointUnix = transactionCheckpoint
	}
	makeSet := func(kind agentrelay.RelayAbsenceObservationKind,
		conclusion agentrelay.RelayAbsenceConclusion, proofs []string) []agentrelay.RelayAbsenceObservationReference {
		observers := []string{"observer:a", "observer:b", "observer:c"}
		domains := []string{"operator:a", "operator:b", "operator:c"}
		values := make([]agentrelay.RelayAbsenceObservationReference, len(observers))
		for index := range values {
			values[index] = agentrelay.RelayAbsenceObservationReference{SchemaVersion: 1, ObservationKind: kind,
				Conclusion: conclusion, ProviderAgentID: fixture.profile.ProviderAgentID, NetworkDigest: networkDigest,
				RelayStableActionID:     execution.AuthorizedAction.StableActionID,
				RelayExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest,
				RelayExecutionDigest:    executionDigest, SponsorshipStableActionID: sponsorshipStableID,
				SponsorshipExactRequestDigest: sponsorshipExactDigest, SponsorshipValidUntilUnix: validUntil,
				SignedTransactionDigest:   execution.QuoteRequest.Body.SignedTransactionDigest,
				SignedTransactionCellHash: execution.QuoteRequest.Body.SignedTransactionCellHash,
				TerminalProfileURI:        terminalProfile.ProfileURI,
				TerminalProfileDigest:     terminalProfile.ProfileDigest,
				TerminalEvidenceClass:     terminalProfile.TerminalEvidenceClass,
				FinalizedCheckpointID:     "checkpoint:sponsorship-expired", FinalizedCheckpointSequence: 200,
				FinalizedCheckpointUnix: checkpointUnix, ObserverID: observers[index], OperatorDomainID: domains[index],
				ObservationEvidenceProfileURI:    execution.QuoteRequest.Body.SponsorshipReleaseProfileURI,
				ObservationEvidenceProfileDigest: execution.QuoteRequest.Body.SponsorshipReleaseProfileDigest,
				ObservationDigest:                relayTestDigest(proofs[index]),
				ObservedAtUnix:                   checkpointUnix}
		}
		sort.Slice(values, func(left, right int) bool {
			leftDigest, _ := agentrelay.RelayAbsenceObservationReferenceDigest(values[left])
			rightDigest, _ := agentrelay.RelayAbsenceObservationReferenceDigest(values[right])
			return leftDigest < rightDigest
		})
		return values
	}
	sponsorship := makeSet(agentrelay.AbsenceObservationSponsorshipAction,
		agentrelay.AbsenceConclusionExpiredWithoutInclusion, []string{"1", "2", "3"})
	transaction := makeSet(agentrelay.AbsenceObservationClientTransaction,
		agentrelay.AbsenceConclusionAbsent, []string{"4", "5", "6"})
	if execution.QuoteRequest.Body.Mode == agentrelay.ModeSponsorOnly {
		transaction = nil
	}
	observationDigests := make([]string, 0, len(sponsorship)+len(transaction))
	for _, reference := range append(append([]agentrelay.RelayAbsenceObservationReference(nil), sponsorship...), transaction...) {
		digest, digestErr := agentrelay.RelayAbsenceObservationReferenceDigest(reference)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		observationDigests = append(observationDigests, digest)
	}
	sort.Strings(observationDigests)
	resolution, err := agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
		ProviderAgentID: fixture.profile.ProviderAgentID, Network: execution.QuoteRequest.Body.Network,
		AssuranceLevel:     execution.QuoteRequest.Body.AssuranceLevel,
		StableActionID:     execution.AuthorizedAction.StableActionID,
		ExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: executionDigest,
		State: commerce.ActionTerminal, StateRevision: 3, TerminalOutcome: agentrelay.OutcomeFinalizedAbsent,
		SponsorshipStableActionID: sponsorshipStableID, SponsorshipExactRequestDigest: sponsorshipExactDigest,
		SponsorshipValidUntilUnix: validUntil, EvidenceSetDigest: relayEvidenceSetDigest(t, observationDigests),
		ObservedAtUnix: checkpointUnix,
		ExpiresAtUnix:  checkpointUnix + 60}, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	body := execution.QuoteRequest.Body
	var relayProfile *agentrelay.FinalityProfile
	if body.Mode == agentrelay.ModeSponsorAndRelay {
		if execution.ProviderQuote.Body.RelayFinalityProfile == nil {
			t.Fatal("combined terminal evidence lacks its relay profile")
		}
		copy := *execution.ProviderQuote.Body.RelayFinalityProfile
		relayProfile = &copy
	}
	absenceProofBundleDigest, absenceProofBundle := relayTestAbsenceProofBundle(t, sponsorship, transaction)
	evidence, err := agentrelay.SignRelayFinalityEvidence(agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: fixture.profile.ProviderAgentID, Network: body.Network,
		AssuranceLevel: body.AssuranceLevel,
		StableActionID: execution.AuthorizedAction.StableActionID, ExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest,
		RelayExecutionDigest: executionDigest, SignedTransactionDigest: body.SignedTransactionDigest,
		SignedTransactionCellHash: body.SignedTransactionCellHash, SourceAccount: body.SourceAccount,
		SourceSequence: body.SourceSequence, TransactionValidUntilUnix: body.TransactionValidUntilUnix,
		SponsorshipStableActionID:     sponsorshipStableID,
		SponsorshipExactRequestDigest: sponsorshipExactDigest, SponsorshipValidUntilUnix: validUntil,
		SponsorshipAbsenceObservations: sponsorship, TransactionAbsenceObservations: transaction,
		AbsenceProofBundleDigest: absenceProofBundleDigest, AbsenceProofBundle: absenceProofBundle,
		RelayFinalityProfile:       relayProfile,
		SponsorshipTerminalProfile: &terminalProfile,
		Outcome:                    agentrelay.OutcomeFinalizedAbsent, ObservedAtUnix: checkpointUnix,
		SigningAuthorityAtUnix: checkpointUnix}, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	return resolution, evidence
}

func relayTestAbsenceProofBundle(t *testing.T, sponsorship,
	transaction []agentrelay.RelayAbsenceObservationReference) (string, []byte) {
	t.Helper()
	payload, err := codec.Marshal(map[string]any{"schema": "tos.test.relay-absence-payload.v1"})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := codec.DigestCanonical(agentrelay.RelayAbsenceProofPayloadDomainV1, payload)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	scope := agentrelay.RelayAbsenceProofDual
	if len(transaction) == 0 {
		scope = agentrelay.RelayAbsenceProofSponsorshipOnly
	} else if len(sponsorship) == 0 {
		scope = agentrelay.RelayAbsenceProofTransactionOnly
	}
	bundle, err := codec.Marshal(agentrelay.RelayAbsenceProofBundleV1{SchemaVersion: 1,
		ProofScope: scope, ProofProfileURI: agentrelay.RelayAbsenceTOSRPCProofProfileURI,
		ProofProfileDigest: profileDigest, ProofPayloadDigest: payloadDigest, ProofPayload: payload,
		SponsorshipAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil), sponsorship...),
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil), transaction...)})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agentrelay.RelayAbsenceProofBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return digest, bundle
}

func relayTerminalAbsent(t *testing.T, fixture *relayTestFixture,
	execution agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, agentrelay.SignedRelayFinalityEvidence) {
	t.Helper()
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	observationDigests := []string{relayTestDigest("1"), relayTestDigest("2"), relayTestDigest("3")}
	resolution, err := agentrelay.SignRelayResolution(agentrelay.RelayResolutionBody{SchemaVersion: 1,
		ProviderAgentID: fixture.profile.ProviderAgentID, Network: execution.QuoteRequest.Body.Network,
		AssuranceLevel:     execution.QuoteRequest.Body.AssuranceLevel,
		StableActionID:     execution.AuthorizedAction.StableActionID,
		ExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest, RelayExecutionDigest: executionDigest,
		State: commerce.ActionTerminal, StateRevision: 3, TerminalOutcome: agentrelay.OutcomeFinalizedAbsent,
		EvidenceSetDigest: relayEvidenceSetDigest(t, observationDigests), ObservedAtUnix: uint64(fixture.now.Unix()),
		ExpiresAtUnix: uint64(fixture.now.Add(time.Minute).Unix())}, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	quoted := execution.QuoteRequest.Body
	if execution.ProviderQuote.Body.RelayFinalityProfile == nil {
		t.Fatal("relay terminal profile is missing")
	}
	terminalProfile := *execution.ProviderQuote.Body.RelayFinalityProfile
	evidenceBody := agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: fixture.profile.ProviderAgentID, Network: quoted.Network,
		AssuranceLevel: quoted.AssuranceLevel,
		StableActionID: execution.AuthorizedAction.StableActionID, ExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest,
		RelayExecutionDigest: executionDigest, SignedTransactionDigest: quoted.SignedTransactionDigest,
		SignedTransactionCellHash: quoted.SignedTransactionCellHash, SourceAccount: quoted.SourceAccount,
		SourceSequence: quoted.SourceSequence, TransactionValidUntilUnix: quoted.TransactionValidUntilUnix,
		RelayTerminalEvidenceClass: terminalProfile.TerminalEvidenceClass,
		RelayFinalizedCheckpointID: "checkpoint:test", RelayFinalizedCheckpointSequence: 100,
		RelayFinalizedCheckpointUnix: uint64(fixture.now.Unix()),
		RelayConfirmationDepth:       terminalProfile.MinimumConfirmationDepth,
		RelayFinalityProfile:         &terminalProfile,
		RelayObservationDigests:      observationDigests,
		Outcome:                      agentrelay.OutcomeFinalizedAbsent, ObservedAtUnix: uint64(fixture.now.Unix()),
		SigningAuthorityAtUnix: uint64(fixture.now.Unix())}
	setRelayPortableProof(&evidenceBody, true)
	evidence, err := agentrelay.SignRelayFinalityEvidence(evidenceBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	return resolution, evidence
}

func relayEvidenceSetDigest(t *testing.T, values []string) string {
	t.Helper()
	digest, err := agentrelay.RelayEvidenceSetDigest(values)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestRelayResolutionReferenceMatchesCorroboratedTerminalOutcomes(t *testing.T) {
	observationDigests := []string{relayTestDigest("1"), relayTestDigest("2")}
	evidenceSetDigest := relayEvidenceSetDigest(t, observationDigests)
	baseEvidence := agentrelay.RelayFinalityEvidenceBody{
		SponsorshipStableActionID:     relayTestDigest("3"),
		SponsorshipExactRequestDigest: relayTestDigest("4"),
		SponsorshipValidUntilUnix:     1_800_000_100,
		SponsorshipTransferReference:  "tx:sponsorship",
		SponsorshipTransactionEvidence: &agentrelay.RelaySponsorshipTransactionEvidence{
			ObservationDigests: observationDigests,
		},
	}
	baseResolution := agentrelay.RelayResolutionBody{
		SponsorshipStableActionID:     baseEvidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: baseEvidence.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:     baseEvidence.SponsorshipValidUntilUnix,
		SponsorshipTransferReference:  baseEvidence.SponsorshipTransferReference,
		EvidenceSetDigest:             evidenceSetDigest,
	}

	sponsorshipOnly := baseEvidence
	sponsorshipOnly.Outcome = agentrelay.OutcomeCorroboratedSponsorshipOnly
	sponsorshipOnlyResolution := baseResolution
	sponsorshipOnlyResolution.TransactionReference = sponsorshipOnly.SponsorshipTransferReference
	if !relayResolutionReferenceMatchesEvidence(sponsorshipOnlyResolution, sponsorshipOnly) {
		t.Fatal("corroborated sponsorship-only resolution did not bind the exact top-up reference")
	}
	sponsorshipOnlyResolution.TransactionReference = "tx:unrelated"
	if relayResolutionReferenceMatchesEvidence(sponsorshipOnlyResolution, sponsorshipOnly) {
		t.Fatal("corroborated sponsorship-only resolution accepted an unrelated reference")
	}

	mixed := baseEvidence
	mixed.Outcome = agentrelay.OutcomeCorroboratedSuccess
	mixed.SubmittedTransactionHash = "tx:client"
	mixedResolution := baseResolution
	mixedResolution.TransactionReference = mixed.SubmittedTransactionHash
	if !relayResolutionReferenceMatchesEvidence(mixedResolution, mixed) {
		t.Fatal("mixed corroborated/finalized resolution did not bind the exact client transaction")
	}
	mixedResolution.TransactionReference = mixed.SponsorshipTransferReference
	if relayResolutionReferenceMatchesEvidence(mixedResolution, mixed) {
		t.Fatal("mixed corroborated/finalized resolution confused the top-up with the client transaction")
	}

	relayOnly := agentrelay.RelayFinalityEvidenceBody{
		Outcome:                       agentrelay.OutcomeCorroboratedRelayOnly,
		SponsorshipStableActionID:     baseEvidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: baseEvidence.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:     baseEvidence.SponsorshipValidUntilUnix,
		SubmittedTransactionHash:      "tx:client-only",
		RelayObservationDigests:       observationDigests,
	}
	relayOnlyResolution := agentrelay.RelayResolutionBody{
		SponsorshipStableActionID:     relayOnly.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: relayOnly.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:     relayOnly.SponsorshipValidUntilUnix,
		EvidenceSetDigest:             relayEvidenceSetDigest(t, observationDigests),
		TransactionReference:          relayOnly.SubmittedTransactionHash,
	}
	if !relayResolutionReferenceMatchesEvidence(relayOnlyResolution, relayOnly) {
		t.Fatal("corroborated relay-only resolution did not bind the exact client transaction")
	}
	relayOnlyResolution.TransactionReference = "tx:unrelated"
	if relayResolutionReferenceMatchesEvidence(relayOnlyResolution, relayOnly) {
		t.Fatal("corroborated relay-only resolution accepted an unrelated transaction")
	}
}

var _ RelayTransport = relayFunctionTransport{}
