package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type relayTestResolver struct {
	agents       map[string]ed25519.PublicKey
	authorityKey ed25519.PublicKey
	current      *relayTestWriterState
}

type relayTestWriterState struct {
	mu    sync.RWMutex
	fence commerce.WriterFence
}

func (resolver relayTestResolver) AuthorizeRelayKey(_ agentrelay.NetworkDomain, agentID string,
	key ed25519.PublicKey, _ time.Time) error {
	wanted := resolver.agents[agentID]
	if wanted == nil || !wanted.Equal(key) {
		return errors.New("unknown Agent key")
	}
	return nil
}

func (resolver relayTestResolver) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, at time.Time) error {
	return resolver.AuthorizeRelayKey(agentrelay.NetworkDomain{}, agentID, key, at)
}

func (resolver relayTestResolver) AuthorizeFenceKey(authorityID string, key ed25519.PublicKey, _ time.Time) error {
	if authorityID != "authority:client" || resolver.authorityKey == nil || !resolver.authorityKey.Equal(key) {
		return errors.New("unknown fence authority")
	}
	return nil
}

func (resolver relayTestResolver) ConfirmCurrentWriterFence(fence commerce.WriterFence, now time.Time) error {
	if resolver.current == nil {
		return errors.New("writer authority currentness is unavailable")
	}
	resolver.current.mu.RLock()
	wanted, wantedErr := commerce.WriterFenceDigest(resolver.current.fence)
	resolver.current.mu.RUnlock()
	got, gotErr := commerce.WriterFenceDigest(fence)
	if wantedErr != nil || gotErr != nil || wanted != got ||
		!now.UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("writer lease was superseded")
	}
	return nil
}

func (resolver relayTestResolver) setCurrentWriter(fence commerce.WriterFence) {
	resolver.current.mu.Lock()
	defer resolver.current.mu.Unlock()
	resolver.current.fence = fence
}

type relayTestAdmissionAuthority struct {
	mu       sync.Mutex
	key      ed25519.PrivateKey
	resolver relayTestResolver
	now      time.Time
	next     uint64
	receipts map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt
	bindings map[string]string
}

func (*relayTestAdmissionAuthority) HasLinearizableRelayAdmission() bool { return true }

func (*relayTestAdmissionAuthority) HasRollbackResistantRelayAdmissionHighWater() bool { return true }

func (authority *relayTestAdmissionAuthority) AdmitRelaySideEffects(_ context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.resolver.ConfirmCurrentWriterFence(descriptor.WriterFence, authority.now); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if err := agentrelay.ValidateRelaySideEffectAdmissionDescriptor(descriptor, authority.resolver, authority.now); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if descriptor.RouteAttempt > maximumRelayRouteHops {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
	}
	key, err := agentrelay.RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if authority.bindings == nil {
		authority.bindings = map[string]string{}
	}
	bindingKey := relayAdmissionStableBindingKey(descriptor.OwnerID, descriptor.AgentID, descriptor.StableActionID)
	if existing, found := authority.receipts[key]; found {
		return existing, nil
	}
	priorLookup, hasPrior := authority.bindings[bindingKey]
	if !hasPrior {
		if descriptor.RouteAttempt != 1 || descriptor.PredecessorReceiptDigest != "" {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
		}
	} else {
		predecessor, found := authority.receipts[priorLookup]
		if !found || agentrelay.ValidateRelaySideEffectAdmissionRouteTransition(predecessor, descriptor) != nil {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
		}
	}
	sequence := authority.next
	if sequence == 0 {
		sequence = 1
	}
	start := uint64(authority.now.Add(agentrelay.MaxRelayAdmissionStartDelay * time.Second).Unix())
	if descriptor.StartNotAfterCapUnix < start {
		start = descriptor.StartNotAfterCapUnix
	}
	body, err := agentrelay.BuildRelaySideEffectAdmissionReceiptBody(descriptor, sequence,
		uint64(authority.now.Unix()), start)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	receipt, err := agentrelay.SignRelaySideEffectAdmissionReceipt(body, authority.key)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.next = sequence + 1
	authority.receipts[key] = receipt
	authority.bindings[bindingKey] = key
	return receipt, nil
}

func (authority *relayTestAdmissionAuthority) ResolveRelaySideEffectAdmission(_ context.Context,
	lookup agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	key, err := agentrelay.RelaySideEffectAdmissionLookupDigest(lookup)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	receipt, found := authority.receipts[key]
	if !found {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayUnknown
	}
	return receipt, nil
}

type relayTestInspector struct {
	inspected agentrelay.InspectedTransaction
}

func (inspector relayTestInspector) InspectTransaction(context.Context, agentrelay.RelayQuoteRequestBody, agentrelay.TransactionProfile,
	[]byte, agentrelay.TransactionInspectionPhase) (agentrelay.InspectedTransaction, error) {
	return inspector.inspected, nil
}

type relayTestBinder struct {
	destination string
	value       string
}

func (binder relayTestBinder) VerifyActionTransaction(request agentrelay.RelayExecutionRequest,
	inspected agentrelay.InspectedTransaction) error {
	if request.AuthorizedAction.ActionKind != "payment.direct" || inspected.Destination != binder.destination ||
		inspected.ValueAtomic != binder.value || inspected.AuthorizedAgentID != request.AuthorizedAction.AgentID {
		return errors.New("transaction does not realize payment.direct")
	}
	return nil
}

type relayTestQuotePolicy struct {
	fee    string
	intent string
}

func (policy relayTestQuotePolicy) Quote(_ context.Context, profile agentrelay.RelayServiceProfile,
	request agentrelay.SignedRelayQuoteRequest, now time.Time) (agentrelay.ProviderRelayQuoteBody, error) {
	requestDigest, _ := agentrelay.RelayQuoteRequestDigest(request.Body)
	profileDigest, _ := agentrelay.RelayServiceProfileDigest(profile)
	var relayFinality, sponsorshipFinality *agentrelay.FinalityProfile
	if request.Body.Mode != agentrelay.ModeSponsorOnly {
		selected, found := relayFinalityProfile(profile.FinalityProfiles,
			request.Body.RelayFinalityProfileURI, request.Body.RelayFinalityProfileDigest)
		if !found {
			return agentrelay.ProviderRelayQuoteBody{}, errors.New("missing relay terminal profile")
		}
		relayFinality = &selected
	}
	if request.Body.Mode != agentrelay.ModeRelayExact {
		selected, found := relayFinalityProfile(profile.FinalityProfiles,
			request.Body.SponsorshipTerminalProfileURI, request.Body.SponsorshipTerminalProfileDigest)
		if !found {
			return agentrelay.ProviderRelayQuoteBody{}, errors.New("missing sponsorship terminal profile")
		}
		sponsorshipFinality = &selected
	}
	feeLines := []agentrelay.FeeLine{{Kind: agentrelay.ObligationRelayFee,
		Amount: agentrelay.AssetAmount{Asset: request.Body.MaximumServiceFee.Asset, AmountAtomic: policy.fee}}}
	if request.Body.Mode == agentrelay.ModeSponsorOnly {
		feeLines[0].Kind = agentrelay.ObligationSponsorshipFee
	} else if request.Body.Mode == agentrelay.ModeSponsorAndRelay {
		feeLines = []agentrelay.FeeLine{
			{Kind: agentrelay.ObligationSponsorshipFee,
				Amount: agentrelay.AssetAmount{Asset: request.Body.MaximumServiceFee.Asset, AmountAtomic: policy.fee}},
			{Kind: agentrelay.ObligationRelayFee,
				Amount: agentrelay.AssetAmount{Asset: request.Body.MaximumServiceFee.Asset, AmountAtomic: policy.fee}},
		}
	}
	body := agentrelay.ProviderRelayQuoteBody{SchemaVersion: 1, QuoteID: "quote:" + strings.TrimPrefix(requestDigest, "sha256:")[:32],
		QuoteRequestDigest: requestDigest, ServiceProfileDigest: profileDigest, ProviderAgentID: profile.ProviderAgentID,
		Mode: request.Body.Mode, AssuranceLevel: request.Body.AssuranceLevel,
		SponsorshipReleaseEvidenceClass:  request.Body.SponsorshipReleaseEvidenceClass,
		SponsorshipReleaseProfileURI:     request.Body.SponsorshipReleaseProfileURI,
		SponsorshipReleaseProfileDigest:  request.Body.SponsorshipReleaseProfileDigest,
		RelayTerminalEvidenceClass:       request.Body.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: request.Body.SponsorshipTerminalEvidenceClass, FeeLines: feeLines,
		MaximumNetworkFeeAtomic:       request.Body.MaximumNetworkFeeAtomic,
		MaximumTransactionValueAtomic: request.Body.MaximumTransactionValueAtomic,
		MaximumRequestBytes:           profile.MaximumRequestBytes, RelayFinalityProfile: relayFinality,
		SponsorshipTerminalProfile: sponsorshipFinality,
		StatusEndpoint:             profile.Endpoints.ResolveURL, ProviderPolicyRevision: profile.PolicyRevision,
		OfferIntentDigest: policy.intent, ValidFromUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(4 * time.Minute).Unix())}
	if request.Body.RequestedSponsorship != nil {
		reserved := *request.Body.RequestedSponsorship
		body.ReservedSponsorship = &reserved
	}
	return body, nil
}

type relayTestBroadcaster struct {
	submits    int
	payloads   [][]byte
	result     agentrelay.BroadcastResult
	submitErr  error
	resolution agentrelay.ChainResolution
}

func (broadcaster *relayTestBroadcaster) SubmitExact(_ context.Context,
	request agentrelay.RelayExecutionRequest) (agentrelay.BroadcastResult, error) {
	broadcaster.submits++
	broadcaster.payloads = append(broadcaster.payloads, append([]byte(nil), request.SignedTransactionBytes...))
	return broadcaster.result, broadcaster.submitErr
}

func (broadcaster *relayTestBroadcaster) Resolve(context.Context, agentrelay.Record) (agentrelay.ChainResolution, error) {
	return broadcaster.resolution, nil
}

type relayTestEvidenceSource struct{ now time.Time }

func (relayTestEvidenceSource) SupportsRelayEvidenceCapability(capability agentrelay.RelayEvidenceCapability) bool {
	return capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func (source relayTestEvidenceSource) SupportsRelayEvidenceRendering(
	capability agentrelay.RelayEvidenceCapability) bool {
	return source.SupportsRelayEvidenceCapability(capability)
}

func (relayTestEvidenceSource) SupportsRelayDualAbsenceEvidence(agentrelay.RelayEvidenceCapability) bool {
	return true
}

func (relayTestEvidenceSource) SupportsRelaySponsorshipComponentAbsenceEvidence(
	agentrelay.RelayEvidenceCapability) bool {
	return true
}

func (relayTestEvidenceSource) SupportsRelayTransactionComponentAbsenceEvidence(
	agentrelay.RelayEvidenceCapability) bool {
	return true
}

func (relayTestEvidenceSource) HasRetrievableIndependentProofs() bool { return true }

func (relayTestEvidenceSource) HasRollbackResistantCheckpoint() bool { return true }

func (relayTestEvidenceSource) HasRollbackResistantTerminalCommitment() bool { return true }

func (source relayTestEvidenceSource) Evidence(_ context.Context,
	record agentrelay.Record) (agentrelay.RelayFinalityEvidenceBody, error) {
	request := record.ExecutionRequest()
	body := request.QuoteRequest.Body
	evidence := agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: request.ProviderQuote.Body.ProviderAgentID, Network: body.Network,
		AssuranceLevel: body.AssuranceLevel,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest, SignedTransactionDigest: body.SignedTransactionDigest,
		SignedTransactionCellHash: body.SignedTransactionCellHash, SourceAccount: body.SourceAccount,
		SourceSequence: body.SourceSequence, TransactionValidUntilUnix: body.TransactionValidUntilUnix,
		Outcome:        record.TerminalOutcome,
		ObservedAtUnix: uint64(source.now.Unix())}
	if profile := request.ProviderQuote.Body.RelayFinalityProfile; profile != nil {
		evidence.RelayTerminalEvidenceClass = profile.TerminalEvidenceClass
		setRelayPortableProof(&evidence,
			profile.TerminalEvidenceClass == agentrelay.RelayTerminalValidatorFinality)
		evidence.RelayFinalizedCheckpointID = "checkpoint:test"
		evidence.RelayFinalizedCheckpointSequence = 100
		evidence.RelayFinalizedCheckpointUnix = uint64(source.now.Unix())
		evidence.RelayConfirmationDepth = profile.MinimumConfirmationDepth
		copy := *profile
		evidence.RelayFinalityProfile = &copy
		evidence.RelayObservationDigests = []string{relayTestDigest("1"), relayTestDigest("2"), relayTestDigest("3")}
	}
	if profile := request.ProviderQuote.Body.SponsorshipTerminalProfile; profile != nil {
		copy := *profile
		evidence.SponsorshipTerminalProfile = &copy
		evidence.SponsorshipStableActionID = record.SponsorshipStableActionID
		evidence.SponsorshipExactRequestDigest = record.SponsorshipExactRequestDigest
		evidence.SponsorshipValidUntilUnix = record.SponsorshipValidUntilUnix
		evidence.SponsorshipTransferReference = record.SponsorshipTransferReference
		evidence.SponsorshipTransactionEvidence = record.SponsorshipTransactionEvidence
	}
	return evidence, nil
}

func setRelayPortableProof(body *agentrelay.RelayFinalityEvidenceBody, value bool) {
	field := reflect.ValueOf(body).Elem().FieldByName("RelayValidatorAuthenticatedPortableProof")
	if !field.IsValid() || !field.CanSet() {
		panic("relay portable-proof field is unavailable")
	}
	if field.Kind() == reflect.Pointer {
		copy := value
		field.Set(reflect.ValueOf(&copy))
		return
	}
	if field.Kind() != reflect.Bool {
		panic("relay portable-proof field has an unsupported Go representation")
	}
	field.SetBool(value)
}

type relayTestFinalityVerifier struct {
	verify                            func(context.Context, agentrelay.RelayExecutionRequest, agentrelay.SignedRelayFinalityEvidence) error
	supports                          func(agentrelay.RelayEvidenceCapability) bool
	dualAbsence                       bool
	rejectSponsorshipComponentAbsence bool
	rejectTransactionComponentAbsence bool
	portable                          bool
}

func (verifier relayTestFinalityVerifier) VerifyRelayFinality(ctx context.Context,
	request agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence) error {
	if verifier.verify != nil {
		return verifier.verify(ctx, request, evidence)
	}
	return nil
}

func (verifier relayTestFinalityVerifier) SupportsRelayEvidenceCapability(
	capability agentrelay.RelayEvidenceCapability) bool {
	if verifier.supports != nil {
		return verifier.supports(capability)
	}
	return capability.UnderlyingActionKind == relayV1UnderlyingActionKind
}

func (verifier relayTestFinalityVerifier) SupportsRelayDualAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.dualAbsence && verifier.SupportsRelayEvidenceCapability(capability)
}

func (verifier relayTestFinalityVerifier) SupportsRelaySponsorshipComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.dualAbsence && !verifier.rejectSponsorshipComponentAbsence &&
		verifier.SupportsRelayEvidenceCapability(capability)
}

func (verifier relayTestFinalityVerifier) SupportsRelayTransactionComponentAbsenceEvidence(
	capability agentrelay.RelayEvidenceCapability) bool {
	return verifier.dualAbsence && !verifier.rejectTransactionComponentAbsence &&
		verifier.SupportsRelayEvidenceCapability(capability)
}

func (verifier relayTestFinalityVerifier) HasIndependentPortableRelayFinalityProofs() bool {
	return verifier.portable
}

func (verifier relayTestFinalityVerifier) FreezeRelayFinalityEvidenceSnapshot(_ context.Context,
	capability agentrelay.RelayEvidenceCapability) ([]byte, error) {
	if !verifier.SupportsRelayEvidenceCapability(capability) {
		return nil, errors.New("unsupported test relay evidence capability")
	}
	return codec.Marshal(capability)
}

func (verifier relayTestFinalityVerifier) ValidateRelayFinalityEvidenceSnapshot(
	capability agentrelay.RelayEvidenceCapability, raw []byte) error {
	var frozen agentrelay.RelayEvidenceCapability
	if len(raw) == 0 || codec.Unmarshal(raw, &frozen) != nil || !reflect.DeepEqual(frozen, capability) ||
		!verifier.SupportsRelayEvidenceCapability(capability) {
		return errors.New("test relay finality snapshot conflicts with capability")
	}
	return nil
}

func (verifier relayTestFinalityVerifier) VerifyRelayFinalityFromSnapshot(ctx context.Context,
	execution agentrelay.RelayExecutionRequest, evidence agentrelay.SignedRelayFinalityEvidence, raw []byte) error {
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil || verifier.ValidateRelayFinalityEvidenceSnapshot(capability, raw) != nil {
		return errors.New("test relay finality snapshot is invalid")
	}
	return verifier.VerifyRelayFinality(ctx, execution, evidence)
}

type relayTestFixture struct {
	now                 time.Time
	clientKey           ed25519.PrivateKey
	providerKey         ed25519.PrivateKey
	authorityKey        ed25519.PrivateKey
	resolver            relayTestResolver
	network             agentrelay.NetworkDomain
	transaction         agentrelay.TransactionProfile
	finality            agentrelay.FinalityProfile
	sponsorshipFinality agentrelay.FinalityProfile
	asset               agentrelay.AssetIdentity
	profile             agentrelay.RelayServiceProfile
	verified            VerifiedRelayServiceProfile
	inspector           relayTestInspector
	binder              relayTestBinder
	admission           *relayTestAdmissionAuthority
	prepared            PreparedRelayTransaction
}

func newRelayTestFixture(t *testing.T, providerID string, providerKey ed25519.PrivateKey,
	endpointOrigin string) *relayTestFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	if providerKey == nil {
		_, providerKey, _ = ed25519.GenerateKey(rand.Reader)
	}
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	resolver := relayTestResolver{agents: map[string]ed25519.PublicKey{"agent:client": clientKey.Public().(ed25519.PublicKey),
		providerID: providerKey.Public().(ed25519.PublicKey)}, authorityKey: authorityKey.Public().(ed25519.PublicKey),
		current: &relayTestWriterState{}}
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42, ZeroStateRootHash: relayTestDigest("1"),
		ZeroStateFileHash: relayTestDigest("2"), WorkchainID: 0}
	transaction := agentrelay.TransactionProfile{ProfileURI: "tos.signed-external-boc.v1", ProfileDigest: relayTestDigest("3"),
		MaximumSignedBytes: agentrelay.MaxSignedTransactionBytes, InspectableSourceSequence: true, InspectableTransactionExpiry: true}
	finality := agentrelay.FinalityProfile{ProfileURI: "tos.depth-quorum.v1", ProfileDigest: relayTestDigest("4"),
		TerminalEvidenceClass:    agentrelay.RelayTerminalValidatorFinality,
		MinimumConfirmationDepth: 2, MinimumObservers: 3, MinimumOperatorDomains: 2,
		ReorgWindowSeconds: 10, MaximumResolutionSeconds: 30}
	asset := agentrelay.AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet", Unit: "nanotos"}
	profile := agentrelay.RelayServiceProfile{SchemaVersion: 1, ProfileID: "profile:" + providerID, Revision: 1,
		ProviderAgentID: providerID, NetworkDomains: []agentrelay.NetworkDomain{network},
		SupportedModes: []agentrelay.Mode{agentrelay.ModeRelayExact},
		SupportedAssuranceLevels: []agentrelay.AssuranceLevel{agentrelay.AssuranceAuthorizedSingleProvider,
			agentrelay.AssuranceAutonomousDecentralized, agentrelay.AssuranceTrustedLocal},
		TransactionProfiles: []agentrelay.TransactionProfile{transaction},
		FinalityProfiles:    []agentrelay.FinalityProfile{finality}, FeeAssets: []agentrelay.AssetIdentity{asset},
		ExposureLimits: []agentrelay.ExposureLimit{{Asset: asset, MaximumPerRequestAtomic: "1000", MaximumOutstandingAtomic: "10000"}},
		AdmissionLimits: agentrelay.AdmissionLimits{MaximumQuoteReservations: 64, MaximumActiveExecutions: 32,
			MaximumActivePerRequester: 8, MaximumQuoteRequestsPerWindow: 4096,
			MaximumQuoteRequestsPerRequesterWindow: 1024, QuoteRequestWindowSeconds: 60},
		MaximumRequestBytes: agentrelay.MaxSignedTransactionBytes,
		Endpoints: agentrelay.ServiceEndpoints{QuoteURL: endpointOrigin + "/quote", SubmitURL: endpointOrigin + "/submit",
			ResolveURL: endpointOrigin + "/resolve", EvidenceURL: endpointOrigin + "/evidence"},
		PolicyRevision: 1, CreatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	intent := relayProfileIntent(t, profile, providerKey, now)
	policy := RelayOwnerPolicy{NetworkDomains: []agentrelay.NetworkDomain{network}, Modes: []agentrelay.Mode{agentrelay.ModeRelayExact},
		TransactionProfiles: []agentrelay.TransactionProfile{transaction}, FinalityProfiles: []agentrelay.FinalityProfile{finality},
		MaximumSignedBytes: agentrelay.MaxSignedTransactionBytes,
		MaximumServiceFees: []agentrelay.AssetAmount{{Asset: asset, AmountAtomic: "10"}}}
	verified, err := VerifyDiscoveredRelayServiceProfile(intent, resolver, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("exact signed TOS BOC fixture")
	payloadDigest, _ := agentrelay.SignedTransactionDigest(payload)
	networkDigest, _ := agentrelay.NetworkDomainDigest(network)
	underlyingRequest := []byte{0xa1, 0x01, 0x02}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:client"), "agent_id": commerce.ID("agent:client"),
		"agreement_body_digest": commerce.Digest32(relayTestDigest("5")), "obligation_instance_id": commerce.Digest32(relayTestDigest("6")),
		"payer_id": commerce.ID("agent:client"), "payee_id": commerce.ID("agent:merchant"), "network_id": commerce.ID("tos:testnet"),
		"asset_digest": commerce.Digest32(relayTestDigest("a")), "amount_atomic": commerce.ID("25"),
		"destination_digest": commerce.Digest32(relayTestDigest("b"))}
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:client", AgentID: "agent:client",
		InstanceID: "instance:client", LeaseID: "lease:client", WriterGeneration: 1,
		IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix()),
		AuthorityID: "authority:client", Scope: []string{"payment.direct"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver.setCurrentWriter(fence)
	action, err := commerce.BuildAuthorizedAction("owner:client", "agent:client", "payment.direct", fields, underlyingRequest,
		fence, 1, relayTestDigest("c"), "", "unknown", uint64(now.Add(8*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(action, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	authorityDigest := relayTestDigest("7")
	destination := "0:" + strings.Repeat("2", 64)
	quoteBody := agentrelay.RelayQuoteRequestBody{SchemaVersion: 1, RequestID: "request:one", RequesterAgentID: "agent:client",
		ProviderAgentID: providerID, Network: network, Mode: agentrelay.ModeRelayExact,
		AssuranceLevel:               agentrelay.AssuranceAutonomousDecentralized,
		SourceAccount:                "0:" + strings.Repeat("1", 64),
		SourceAccountAuthorityDigest: authorityDigest, TransactionProfileURI: transaction.ProfileURI,
		TransactionProfileDigest: transaction.ProfileDigest, UnderlyingActionKind: action.ActionKind,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		SignedTransactionDigest: payloadDigest, SignedTransactionCellHash: relayTestCellDigest("d"), SignedTransactionSize: uint32(len(payload)),
		TransactionIntentDigest: relayTestDigest("e"), SourceSequence: 7,
		TransactionValidUntilUnix: uint64(now.Add(10 * time.Minute).Unix()),
		MaximumServiceFee:         agentrelay.AssetAmount{Asset: asset, AmountAtomic: "10"}, MaximumNetworkFeeAtomic: "100",
		MaximumTransactionValueAtomic: "25", RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		RelayFinalityProfileURI: finality.ProfileURI, RelayFinalityProfileDigest: finality.ProfileDigest,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(5 * time.Minute).Unix())}
	inspector := relayTestInspector{inspected: agentrelay.InspectedTransaction{NetworkDigest: networkDigest,
		SourceAccount: quoteBody.SourceAccount, SourceAccountAuthorityDigest: authorityDigest, AuthorizedAgentID: "agent:client",
		ControllerEpoch: 1, SourceSequence: quoteBody.SourceSequence, ValidUntilUnix: quoteBody.TransactionValidUntilUnix,
		Destination: destination, ValueAtomic: "25", TransactionIntentDigest: quoteBody.TransactionIntentDigest,
		SignedTransactionCellHash: quoteBody.SignedTransactionCellHash, MaximumNetworkFeeAtomic: "90",
		MaximumTransactionValueAtomic: "25"}}
	admission := &relayTestAdmissionAuthority{key: authorityKey, resolver: resolver, now: now, next: 1,
		receipts: map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt{}, bindings: map[string]string{}}
	return &relayTestFixture{now: now, clientKey: clientKey, providerKey: providerKey, authorityKey: authorityKey,
		resolver: resolver, network: network, transaction: transaction, finality: finality,
		sponsorshipFinality: finality, asset: asset,
		profile: profile, verified: verified, inspector: inspector, binder: relayTestBinder{destination: destination, value: "25"},
		admission: admission,
		prepared: PreparedRelayTransaction{QuoteBody: quoteBody, ExactSignedBOC: payload, UnderlyingAction: action,
			WriterFence: fence, SemanticFields: fields, UnderlyingActionRequest: underlyingRequest}}
}

func (fixture *relayTestFixture) enableSponsorship(t *testing.T, mode agentrelay.Mode) {
	t.Helper()
	if mode != agentrelay.ModeSponsorOnly && mode != agentrelay.ModeSponsorAndRelay {
		t.Fatal("test sponsorship mode is invalid")
	}
	fixture.profile.SupportedModes = []agentrelay.Mode{mode}
	fixture.prepared.QuoteBody.Mode = mode
	if mode == agentrelay.ModeSponsorOnly {
		fixture.prepared.QuoteBody.RelayTerminalEvidenceClass = ""
		fixture.prepared.QuoteBody.RelayFinalityProfileURI = ""
		fixture.prepared.QuoteBody.RelayFinalityProfileDigest = ""
	}
	requested := agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: "5"}
	fixture.prepared.QuoteBody.RequestedSponsorship = &requested
	if fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass == "" {
		fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseValidatorFinality
		fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = fixture.sponsorshipFinality.ProfileURI
		fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = fixture.sponsorshipFinality.ProfileDigest
	}
	fixture.prepared.QuoteBody.SponsorshipTerminalEvidenceClass = fixture.sponsorshipFinality.TerminalEvidenceClass
	fixture.prepared.QuoteBody.SponsorshipTerminalProfileURI = fixture.sponsorshipFinality.ProfileURI
	fixture.prepared.QuoteBody.SponsorshipTerminalProfileDigest = fixture.sponsorshipFinality.ProfileDigest
	profiles := []agentrelay.FinalityProfile{fixture.sponsorshipFinality}
	if mode == agentrelay.ModeSponsorAndRelay && fixture.finality != fixture.sponsorshipFinality {
		profiles = append(profiles, fixture.finality)
	}
	sort.Slice(profiles, func(left, right int) bool {
		return relayFinalityProfileKey(profiles[left]) < relayFinalityProfileKey(profiles[right])
	})
	fixture.profile.FinalityProfiles = profiles
	intent := relayProfileIntent(t, fixture.profile, fixture.providerKey, fixture.now)
	policy := RelayOwnerPolicy{NetworkDomains: []agentrelay.NetworkDomain{fixture.network}, Modes: []agentrelay.Mode{mode},
		TransactionProfiles: []agentrelay.TransactionProfile{fixture.transaction},
		FinalityProfiles:    append([]agentrelay.FinalityProfile(nil), profiles...),
		MaximumSignedBytes:  agentrelay.MaxSignedTransactionBytes,
		MaximumServiceFees:  []agentrelay.AssetAmount{{Asset: fixture.asset, AmountAtomic: "10"}}}
	verified, err := VerifyDiscoveredRelayServiceProfile(intent, fixture.resolver, policy, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.verified = verified
}

func (fixture *relayTestFixture) enableClientCorroboratedTerminalProfile() {
	fixture.sponsorshipFinality = fixture.finality
	fixture.sponsorshipFinality.ProfileURI = RelayClientCorroboratedTerminalProfileURI
	fixture.sponsorshipFinality.ProfileDigest = relayTestDigest("9")
	fixture.sponsorshipFinality.TerminalEvidenceClass = agentrelay.SponsorshipTerminalClientCorroborated
	fixture.sponsorshipFinality.MinimumConfirmationDepth = 1
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = relayTestDigest("8")
}

func (fixture *relayTestFixture) takeoverFence(t *testing.T) commerce.WriterFence {
	t.Helper()
	body := fixture.prepared.WriterFence.Body
	body.InstanceID = "instance:takeover"
	body.LeaseID = "lease:takeover"
	body.WriterGeneration++
	body.IssuedAtUnix = uint64(fixture.now.Unix())
	fence, err := commerce.SignWriterFence(body, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

func (fixture *relayTestFixture) service(journal agentrelay.Journal,
	broadcaster agentrelay.ExactTransactionBroadcaster) *agentrelay.ProviderService {
	service := &agentrelay.ProviderService{Profile: fixture.profile, SigningKey: fixture.providerKey,
		AgentResolver: fixture.resolver, FenceResolver: fixture.resolver, Inspector: fixture.inspector,
		ActionBinder: fixture.binder, AgreementVerifier: commerce.AgentSignatureEvidenceVerifier{Resolver: fixture.resolver},
		QuotePolicy: relayTestQuotePolicy{fee: "3", intent: fixture.verified.IntentDigest()}, Journal: journal,
		Broadcaster: broadcaster, EvidenceSource: relayTestEvidenceSource{now: fixture.now}, Now: func() time.Time { return fixture.now }}
	// Presence on the fixed protocol branch is mandatory. Reflection keeps this
	// test fixture compilable against the immediately preceding reviewed module
	// commit until dependency-order landing publishes the new field.
	field := reflect.ValueOf(service).Elem().FieldByName("AdmissionAuthority")
	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(fixture.admission))
	}
	return service
}

func (fixture *relayTestFixture) agreementAuthorizer(t *testing.T) RelayAgreementAuthorizer {
	t.Helper()
	return RelayAgreementAuthorizerFunc(func(_ context.Context, request agentrelay.SignedRelayQuoteRequest,
		quote agentrelay.SignedProviderRelayQuote) (RelayAgreementMaterial, error) {
		binding, err := agentrelay.CompileRelayAgreementBinding(request, quote)
		if err != nil {
			return RelayAgreementMaterial{}, err
		}
		subject, _ := agentrelay.RelayAgreementBindingBytes(binding)
		clientObligations := make([]string, 0, len(quote.Body.FeeLines))
		providerObligations := make([]string, 0, 2)
		obligations := make([]commerce.AgreementObligation, 0, len(quote.Body.FeeLines)+2)
		relayObligationID, sponsorshipObligationID := "", ""
		if request.Body.Mode != agentrelay.ModeSponsorOnly {
			relayObligationID = "obligation:relay"
			providerObligations = append(providerObligations, relayObligationID)
			obligations = append(obligations, commerce.AgreementObligation{ObligationID: relayObligationID,
				Kind: agentrelay.ObligationRelayDelivery, ObligorAgentID: fixture.profile.ProviderAgentID,
				BeneficiaryAgentID: "agent:client", SubjectContentType: agentrelay.AgreementBindingContentType,
				Subject: subject, ConfidentialityPolicy: "participants", CancellationPolicy: "before-submit",
				DisputePolicy: "evidence-v1", AuthorizationPredicateIDs: []string{"predicate:provider"}})
		}
		if request.Body.Mode != agentrelay.ModeRelayExact {
			if quote.Body.ReservedSponsorship == nil {
				return RelayAgreementMaterial{}, errors.New("sponsorship quote lacks a reserved amount")
			}
			sponsorshipObligationID = "obligation:sponsorship"
			providerObligations = append(providerObligations, sponsorshipObligationID)
			amount := quote.Body.ReservedSponsorship
			obligations = append(obligations, commerce.AgreementObligation{ObligationID: sponsorshipObligationID,
				Kind: agentrelay.ObligationSponsorDelivery, ObligorAgentID: fixture.profile.ProviderAgentID,
				BeneficiaryAgentID: "agent:client", SubjectContentType: agentrelay.AgreementBindingContentType,
				Subject: subject, Amount: &commerce.AgreementAmount{AssetNamespace: amount.Asset.AssetNamespace,
					AssetIdentifier: amount.Asset.AssetIdentifier, AmountAtomic: amount.AmountAtomic, Unit: amount.Asset.Unit},
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1",
				SettlementAdapterURI:      agentrelay.DirectPaymentAdapterURI,
				SettlementParameters:      []byte("source-account-bound-by-quote-digest"),
				AuthorizationPredicateIDs: []string{"predicate:provider"},
				ExpiresAtUnix:             uint64(fixture.now.Add(3 * time.Minute).Unix())})
		}
		feeObligationIDs := make([]string, 0, len(quote.Body.FeeLines))
		for _, line := range quote.Body.FeeLines {
			obligationID := "obligation:fee:" + line.Kind
			feeObligationIDs = append(feeObligationIDs, obligationID)
			clientObligations = append(clientObligations, obligationID)
			amount := line.Amount
			obligations = append(obligations, commerce.AgreementObligation{ObligationID: obligationID, Kind: line.Kind,
				ObligorAgentID: "agent:client", BeneficiaryAgentID: fixture.profile.ProviderAgentID,
				SubjectContentType: agentrelay.AgreementBindingContentType, Subject: subject,
				Amount: &commerce.AgreementAmount{AssetNamespace: amount.Asset.AssetNamespace,
					AssetIdentifier: amount.Asset.AssetIdentifier, AmountAtomic: amount.AmountAtomic, Unit: amount.Asset.Unit},
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1",
				SettlementAdapterURI: agentrelay.DirectPaymentAdapterURI, SettlementParameters: []byte("destination=provider"),
				AuthorizationPredicateIDs: []string{"predicate:client"}})
		}
		sort.Strings(clientObligations)
		sort.Strings(providerObligations)
		sort.Strings(feeObligationIDs)
		body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:relay-service", Version: 1,
			NetworkContext: "tos:testnet", Participants: []commerce.AgreementParticipant{
				{AgentID: "agent:client", Roles: []string{"client"}}, {AgentID: fixture.profile.ProviderAgentID, Roles: []string{"provider"}}},
			TermsContentType: agentrelay.AgreementBindingContentType, Terms: subject,
			Obligations: obligations,
			AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
				{PredicateID: "predicate:client", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:client"},
					RoleScope: []string{"client"}, ObligationIDs: clientObligations, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
					EvidenceProfileVersion: 1, EvidenceProfileDigest: commerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())},
				{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: fixture.profile.ProviderAgentID},
					RoleScope: []string{"provider"}, ObligationIDs: providerObligations, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
					EvidenceProfileVersion: 1, EvidenceProfileDigest: commerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())}},
			ValidFromUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(7 * time.Minute).Unix())}
		body, err = commerce.PrepareAgreementTargets(body)
		if err != nil {
			return RelayAgreementMaterial{}, err
		}
		bodyDigest, _ := commerce.AgreementBodyDigest(body)
		var evidence []commerce.AgreementAuthorizationEvidence
		for index, key := range []ed25519.PrivateKey{fixture.clientKey, fixture.providerKey} {
			predicate := body.AuthorizationPredicates[index]
			acceptance, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
				AgreementVersion: body.Version, AgreementBodyDigest: bodyDigest, AcceptingSubject: predicate.AuthoritySubject,
				AcceptedRoles: predicate.RoleScope, PredicateIDs: []string{predicate.PredicateID},
				EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest}, ExpiresAtUnix: predicate.ExpiresAtUnix}, key)
			if signErr != nil {
				return RelayAgreementMaterial{}, signErr
			}
			converted, evidenceErr := commerce.AgentSignatureEvidence(body, acceptance)
			if evidenceErr != nil {
				return RelayAgreementMaterial{}, evidenceErr
			}
			evidence = append(evidence, converted)
		}
		return RelayAgreementMaterial{Agreement: commerce.AgentAgreement{Body: body, AuthorizationEvidence: evidence},
			RelayObligationID: relayObligationID, SponsorshipObligationID: sponsorshipObligationID,
			FeeObligationIDs:       feeObligationIDs,
			ExecutionExpiresAtUnix: uint64(fixture.now.Add(3 * time.Minute).Unix())}, nil
	})
}

func (fixture *relayTestFixture) attempt(t *testing.T) RelayAttempt {
	t.Helper()
	signed, err := agentrelay.SignRelayQuoteRequest(fixture.prepared.QuoteBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	service := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	quote, err := service.Quote(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	material, err := fixture.agreementAuthorizer(t).AuthorizeRelayAgreement(t.Context(), signed, quote)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := commerce.AgreementBodyDigest(material.Agreement.Body)
	wireFields, _ := commerce.ExportSemanticFields(fixture.prepared.UnderlyingAction.ActionKind, fixture.prepared.SemanticFields)
	execution := agentrelay.RelayExecutionRequest{SchemaVersion: 1, QuoteRequest: signed, ProviderQuote: quote,
		SignedTransactionBytes: append([]byte(nil), fixture.prepared.ExactSignedBOC...),
		AgreementBodyDigest:    digest, AgreementExpiresAtUnix: material.Agreement.Body.ExpiresAtUnix,
		RelayObligationID: material.RelayObligationID, SponsorshipObligationID: material.SponsorshipObligationID,
		FeeObligationIDs:        append([]string(nil), material.FeeObligationIDs...),
		UnderlyingActionRequest: append([]byte(nil), fixture.prepared.UnderlyingActionRequest...), SemanticFields: wireFields,
		AuthorizedAction: fixture.prepared.UnderlyingAction, WriterFence: fixture.prepared.WriterFence,
		CreatedAtUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: material.ExecutionExpiresAtUnix}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptor(execution)
	if err != nil {
		t.Fatal(err)
	}
	execution.AdmissionReceipt, err = fixture.admission.AdmitRelaySideEffects(t.Context(), descriptor)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil {
		t.Fatal(err)
	}
	verifier := relayTestFinalityVerifier{dualAbsence: true, portable: true}
	opaque, err := verifier.FreezeRelayFinalityEvidenceSnapshot(t.Context(), capability)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := newRelayClientEvidenceSnapshot(capability, opaque, true, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	return RelayAttempt{Execution: execution, Agreement: material.Agreement,
		ClientFinalityEvidenceSnapshot: snapshot}
}

func relayTestRefreshAdmission(t *testing.T, fixture *relayTestFixture,
	execution *agentrelay.RelayExecutionRequest) {
	t.Helper()
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptor(*execution)
	if err != nil {
		t.Fatal(err)
	}
	execution.AdmissionReceipt, err = fixture.admission.AdmitRelaySideEffects(t.Context(), descriptor)
	if err != nil {
		t.Fatal(err)
	}
}

func relayProfileIntent(t *testing.T, profile agentrelay.RelayServiceProfile, key ed25519.PrivateKey,
	now time.Time) commerce.SignedAgentIntent {
	t.Helper()
	content, err := codec.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: profile.NetworkDomains[0].NetworkID,
		IssuerAgentID: profile.ProviderAgentID, Audience: "public:indexable", ObjectID: profile.ProfileID, Revision: profile.Revision,
		CreatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: profile.ExpiresAtUnix,
		Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: "Exact transaction relay",
			IntentModes: []commerce.IntentMode{commerce.IntentOffer}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
			TaxonomyPaths: []string{"tos.taxonomy.v1/service/transaction-relay"},
			Keywords:      []commerce.IntentKeyword{{Text: "relay", Language: "en"}}, ValueState: commerce.ValueNegotiable,
			Schedule: commerce.IntentSchedule{Flexibility: "ongoing"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: agentrelay.ServiceProfileContentType,
				ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), ContentSize: uint64(len(content)), InlineContent: content},
			ReplyRoutes:        []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: profile.ProviderAgentID}},
			RequiredExtensions: []string{agentrelay.ProfileURI}}}
	signed, err := commerce.SignIntent(body, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func relayTestDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func relayTestCellDigest(character string) string {
	return "tvm-cell-sha256:" + strings.Repeat(character, 64)
}
