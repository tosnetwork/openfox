package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestTOSCTLRelayAbsenceCapabilityIsExactAndSponsorOnlyDoesNotRequireDual(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	root := privateTempDir(t)
	paths := tosctlSponsorshipTestConfigs(t, root, fixture.network)
	policy, _, err := buildTOSCTLSponsorshipEvidenceProfile(paths, fixture.network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = policy.EvidenceClass
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = policy.ProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = policy.ProfileDigest
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	execution := fixture.attempt(t).Execution
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil {
		t.Fatal(err)
	}
	stockDigest, err := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if err != nil || capability.AbsenceProofProfileURI != agentrelay.RelayAbsenceTOSRPCProofProfileURI ||
		capability.AbsenceProofProfileDigest != stockDigest {
		t.Fatalf("execution did not select the stock bounded absence verifier profile: %+v err=%v", capability, err)
	}

	sink := &TOSCTLPaymentSink{Executable: "/usr/bin/tosctl", ConfigPath: paths[0],
		Wallet: "provider", SourceAccount: "0:sponsor", FeeReserveNanoTOS: 1,
		QuorumConfigPaths: paths[1:], MaximumTransactions: 1000, EvidenceDirectory: root,
		RelayNetworkDomain: &fixture.network, NetworkGlobalID: fixture.network.GlobalID,
		RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{fixture.sponsorshipFinality},
		Now:                           func() time.Time { return fixture.now }}
	sink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		if len(args) < 3 {
			return nil, errors.New("short tosctl command")
		}
		switch args[2] {
		case "economic-payment-corroboration-profile":
			return tosctlSnapshotCapability(t, root, paths, fixture.network, 1000), nil
		case "economic-payment-sponsorship-dual-absence-capability":
			role := relayTestCLIFlag(args, "--role")
			return tosctlRelayAbsenceCapabilityFixture(t, root, paths, capability, role,
				relayTestCLIFlag(args, "--corroboration-snapshot-identity")), nil
		default:
			return nil, errors.New("unexpected tosctl command: " + args[2])
		}
	}

	if !sink.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, nil) {
		t.Fatal("exact sponsor-only Provider component producer was not directly enabled")
	}
	if sink.SupportsRelayDualAbsenceEvidence(capability, nil) {
		t.Fatal("sponsor-only capability falsely required or advertised a client-transaction absence component")
	}
	verifier := &TOSCTLRelayFinalityVerifier{Sponsorship: sink}
	if !verifier.SupportsRelayEvidenceCapability(capability) ||
		!verifier.SupportsRelaySponsorshipComponentAbsenceEvidence(capability) ||
		verifier.SupportsRelayDualAbsenceEvidence(capability) ||
		verifier.SupportsRelayTransactionComponentAbsenceEvidence(capability) {
		t.Fatalf("sponsor-only requester capability was not scoped exactly: %+v", capability)
	}

	mutated := capability
	mutated.AbsenceProofProfileDigest = relayTestDigest("f")
	if sink.SupportsRelaySponsorshipComponentAbsenceEvidence(mutated, nil) ||
		verifier.SupportsRelayEvidenceCapability(mutated) {
		t.Fatal("an owner/model-substituted absence verifier profile was accepted")
	}
	mutated = capability
	mutated.AssuranceLevel = agentrelay.AssuranceAutonomousDecentralized
	if sink.SupportsRelaySponsorshipComponentAbsenceEvidence(mutated, nil) ||
		verifier.SupportsRelayEvidenceCapability(mutated) {
		t.Fatal("RPC corroboration was upgraded to autonomous assurance")
	}
}

func TestTOSCTLRelaySponsorOnlyAbsenceResolvesThroughProcessor(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	root := privateTempDir(t)
	paths := tosctlSponsorshipTestConfigs(t, root, fixture.network)
	policy, _, err := buildTOSCTLSponsorshipEvidenceProfile(paths, fixture.network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = policy.EvidenceClass
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = policy.ProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = policy.ProfileDigest
	execution, agreement, obligation := relaySponsorshipFixtureForMode(t, fixture, agentrelay.ModeSponsorOnly)
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil {
		t.Fatal(err)
	}

	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityDirectory := filepath.Join(root, "authority")
	if err := os.Mkdir(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:provider",
		fixture.profile.ProviderAgentID, "authority:provider", authorityKey, relaySponsorshipTestLimits(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.domain-bound"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	absenceNow := time.Unix(int64(maxUint64(
		execution.QuoteRequest.Body.TransactionValidUntilUnix+
			uint64(execution.ProviderQuote.Body.SponsorshipTerminalProfile.ReorgWindowSeconds)+1,
		uint64(fixture.now.Unix()))), 0).UTC()
	sink := &TOSCTLPaymentSink{Authority: authority, Executable: "/usr/bin/tosctl", ConfigPath: paths[0],
		Wallet: "provider", SourceAccount: "0:sponsor", NetworkGlobalID: fixture.network.GlobalID,
		FeeReserveNanoTOS: 1, RelayNetworkDomain: &fixture.network, QuorumConfigPaths: paths[1:],
		MaximumTransactions: 1000, EvidenceDirectory: root, RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{fixture.sponsorshipFinality},
		Now:                           func() time.Time { return absenceNow }}
	sink.RelayNetworkPreflight = func(context.Context, string, agentrelay.NetworkDomain) error { return nil }
	var recoveryToken relaySponsorshipRecoveryToken
	var componentRaw []byte
	sink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		if len(args) < 3 {
			return nil, errors.New("short tosctl command")
		}
		switch args[2] {
		case "economic-payment-corroboration-profile":
			return tosctlSnapshotCapability(t, root, paths, fixture.network, 1000), nil
		case "economic-payment-sponsorship-dual-absence-capability":
			return tosctlRelayAbsenceCapabilityFixture(t, root, paths, capability,
				relayTestCLIFlag(args, "--role"), relayTestCLIFlag(args, "--corroboration-snapshot-identity")), nil
		case "economic-payment-sponsorship-corroborated-terminal":
			paymentDigest, _ := commerce.AgreementPaymentRequestDigest(recoveryToken.Payment)
			canonical, _, _ := commerce.PaymentAuthorizationMaterial(recoveryToken.Payment)
			exactDigest, _ := commerce.ExactRequestDigest(canonical)
			return mustJSON(t, tosctlRelaySponsorshipTerminalUnknown{
				Schema: tosctlRelaySponsorshipFinalitySchema, State: "unknown", Category: "not_mature",
				Reason:                        "quorum checkpoint has not crossed the selected chain-time reorg window",
				StableActionID:                recoveryToken.Payment.StableActionID,
				AgreementPaymentRequestDigest: paymentDigest, SponsorshipExactRequestDigest: exactDigest,
				CustodyState: "broadcasting", ChainSideEffect: false, CustodySideEffect: false}), nil
		case "economic-payment-sponsorship-component-absence":
			return componentRaw, nil
		default:
			return nil, errors.New("unexpected tosctl command: " + args[2])
		}
	}
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, EvidenceResolver: sink, AbsenceResolver: sink, TransactionEvidenceVerifier: sink,
		NetworkDomain: fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1,
		WriterFence: fence, Now: func() time.Time { return fixture.now }}
	recovery, err := processor.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	recoveryToken, err = decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil || recoveryToken.EvidenceSnapshot == nil {
		t.Fatalf("decode sponsor-only recovery token: token=%+v err=%v", recoveryToken, err)
	}
	componentRaw, _, _, _, _ = tosctlRelayAbsenceWireFixture(t, sink, execution, recoveryToken.Payment,
		*recoveryToken.EvidenceSnapshot, agentrelay.RelayAbsenceProofSponsorshipOnly, nil, "")
	processor.Now = func() time.Time { return absenceNow }
	resolution, err := processor.ResolveFinalized(t.Context(), execution, recovery)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionCorroboratedAbsent ||
		len(resolution.SponsorshipAbsenceObservations) == 0 || len(resolution.TransactionAbsenceObservations) != 0 {
		t.Fatalf("sponsor-only processor rejected its exact absence proof: resolution=%+v err=%v", resolution, err)
	}

	wrongScope := resolution
	wrongScope.TransactionAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil),
		wrongScope.SponsorshipAbsenceObservations...)
	if err := processor.validateTypedSponsorshipResolution(t.Context(), execution, recoveryToken.Payment,
		recoveryToken.EvidenceSnapshot, wrongScope); err == nil {
		t.Fatal("sponsor-only processor accepted a nonexistent transaction absence component")
	}
	transactionOnly := resolution
	transactionOnly.TransactionAbsenceObservations = transactionOnly.SponsorshipAbsenceObservations
	transactionOnly.SponsorshipAbsenceObservations = nil
	combinedExecution := execution
	combinedExecution.QuoteRequest.Body.Mode = agentrelay.ModeSponsorAndRelay
	if err := processor.validateTypedSponsorshipResolution(t.Context(), combinedExecution, recoveryToken.Payment,
		recoveryToken.EvidenceSnapshot, transactionOnly); err == nil {
		t.Fatal("combined processor accepted transaction-only absence evidence")
	}
}

func TestTOSCTLRelayCompositeSkipsBaseOnlyForExactPreSubmitSponsorshipOnly(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.finality.TerminalEvidenceClass = agentrelay.RelayTerminalProviderCorroborated
	fixture.finality.ProfileURI = "tos.relay.provider-corroborated-terminal.v1"
	fixture.finality.ProfileDigest = relayTestDigest("e")
	fixture.prepared.QuoteBody.RelayTerminalEvidenceClass = fixture.finality.TerminalEvidenceClass
	fixture.prepared.QuoteBody.RelayFinalityProfileURI = fixture.finality.ProfileURI
	fixture.prepared.QuoteBody.RelayFinalityProfileDigest = fixture.finality.ProfileDigest
	fixture.enableClientCorroboratedTerminalProfile()
	root := privateTempDir(t)
	paths := tosctlSponsorshipTestConfigs(t, root, fixture.network)
	policy, _, err := buildTOSCTLSponsorshipEvidenceProfile(paths, fixture.network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = policy.EvidenceClass
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = policy.ProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = policy.ProfileDigest
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	capability, err := relayEvidenceCapabilityForExecution(execution)
	if err != nil {
		t.Fatal(err)
	}
	sink := &TOSCTLPaymentSink{ConfigPath: paths[0], QuorumConfigPaths: paths[1:],
		MaximumTransactions: 1000, EvidenceDirectory: root, RelayNetworkDomain: &fixture.network,
		RelaySponsorshipReleasePolicy: policy}
	sink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		if len(args) >= 3 && args[2] == "economic-payment-corroboration-profile" {
			return tosctlSnapshotCapability(t, root, paths, fixture.network, 1000), nil
		}
		return nil, errors.New("unexpected tosctl command")
	}
	snapshot, err := sink.ensureCurrentRelaySponsorshipSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	baseCalls := 0
	baseErr := errors.New("base relay verifier observed a relay claim")
	base := relayTestFinalityVerifier{dualAbsence: true,
		verify: func(context.Context, agentrelay.RelayExecutionRequest,
			agentrelay.SignedRelayFinalityEvidence) error {
			baseCalls++
			return baseErr
		}}
	baseSnapshot, err := base.FreezeRelayFinalityEvidenceSnapshot(t.Context(), capability)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := codec.Marshal(tosctlRelayClientFinalitySnapshot{SchemaVersion: 1, Capability: capability,
		RelayComponent: baseSnapshot, SponsorshipEvidence: pointerRelaySponsorshipSnapshot(snapshot.frozenClient())})
	if err != nil {
		t.Fatal(err)
	}
	verifier := &TOSCTLRelayFinalityVerifier{RelayComponent: base, Sponsorship: sink}
	recovery, sponsorshipEvidence := relayJournalSponsorshipEvidence(t, fixture, execution, agreement, obligation,
		[]byte("exact pre-submit verifier fixture"))
	sponsorshipEvidence = relayJournalClientCorroboratedEvidence(t, sponsorshipEvidence)
	sponsorshipEvidence.ObservationDigests = []string{relayTestDigest("1"), relayTestDigest("2"), relayTestDigest("3")}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	relayProfile := *execution.ProviderQuote.Body.RelayFinalityProfile
	sponsorshipProfile := *execution.ProviderQuote.Body.SponsorshipTerminalProfile
	evidence, err := agentrelay.SignRelayFinalityEvidence(agentrelay.RelayFinalityEvidenceBody{SchemaVersion: 1,
		ProviderAgentID: execution.ProviderQuote.Body.ProviderAgentID, Network: execution.QuoteRequest.Body.Network,
		AssuranceLevel: execution.QuoteRequest.Body.AssuranceLevel,
		StableActionID: execution.AuthorizedAction.StableActionID, ExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest,
		RelayExecutionDigest: executionDigest, SignedTransactionDigest: execution.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash: execution.QuoteRequest.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix: execution.QuoteRequest.Body.TransactionValidUntilUnix,
		SourceAccount:             execution.QuoteRequest.Body.SourceAccount, SourceSequence: execution.QuoteRequest.Body.SourceSequence,
		SponsorshipStableActionID: recovery.StableActionID, SponsorshipExactRequestDigest: recovery.ExactRequestDigest,
		SponsorshipValidUntilUnix:      recovery.ValidUntilUnix,
		SponsorshipTransferReference:   sponsorshipEvidence.SubmittedTransactionHash,
		SponsorshipTransactionEvidence: &sponsorshipEvidence, SponsorshipTerminalProfile: &sponsorshipProfile,
		RelayFinalityProfile: &relayProfile, Outcome: agentrelay.OutcomeCorroboratedSponsorshipOnly,
		ObservedAtUnix: uint64(fixture.now.Unix()), SigningAuthorityAtUnix: uint64(fixture.now.Unix())}, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyRelayFinalityFromSnapshot(t.Context(), execution, evidence, raw); err != nil || baseCalls != 0 {
		t.Fatalf("exact pre-submit sponsorship-only result reached relay verifier: calls=%d err=%v", baseCalls, err)
	}
	autonomous := capability
	autonomous.AssuranceLevel = agentrelay.AssuranceAutonomousDecentralized
	if relayEvidenceMaySkipTerminalRelayVerification(autonomous, evidence.Body) {
		t.Fatal("autonomous combined result accepted an absence-free sponsorship-only shortcut")
	}
	evidence.Body.SubmittedTransactionHash = "tx:client-claim"
	if err := verifier.VerifyRelayFinalityFromSnapshot(t.Context(), execution, evidence, raw); !errors.Is(err, baseErr) || baseCalls != 1 {
		t.Fatalf("relay-positive claim bypassed frozen base verifier: calls=%d err=%v", baseCalls, err)
	}
	evidence.Body.SubmittedTransactionHash = ""
	evidence.Body.TransactionAbsenceObservations = []agentrelay.RelayAbsenceObservationReference{{ObservationDigest: relayTestDigest("f")}}
	if err := verifier.VerifyRelayFinalityFromSnapshot(t.Context(), execution, evidence, raw); !errors.Is(err, baseErr) || baseCalls != 2 {
		t.Fatalf("relay-negative claim bypassed frozen base verifier: calls=%d err=%v", baseCalls, err)
	}
}

func pointerRelaySponsorshipSnapshot(snapshot RelaySponsorshipEvidenceSnapshot) *RelaySponsorshipEvidenceSnapshot {
	return &snapshot
}

func TestTOSCTLRelayDualAbsencePreservesFrozenComponentAndUsesQueryOnlyPromotion(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.finality.TerminalEvidenceClass = agentrelay.RelayTerminalProviderCorroborated
	fixture.finality.ProfileURI = "tos.relay.provider-corroborated-terminal.v1"
	fixture.finality.ProfileDigest = relayTestDigest("e")
	fixture.prepared.QuoteBody.RelayTerminalEvidenceClass = fixture.finality.TerminalEvidenceClass
	fixture.prepared.QuoteBody.RelayFinalityProfileURI = fixture.finality.ProfileURI
	fixture.prepared.QuoteBody.RelayFinalityProfileDigest = fixture.finality.ProfileDigest
	fixture.enableClientCorroboratedTerminalProfile()
	root := privateTempDir(t)
	paths := tosctlSponsorshipTestConfigs(t, root, fixture.network)
	policy, _, err := buildTOSCTLSponsorshipEvidenceProfile(paths, fixture.network, 1000)
	if err != nil {
		t.Fatal(err)
	}
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = policy.EvidenceClass
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = policy.ProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = policy.ProfileDigest
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)

	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityDirectory := filepath.Join(root, "authority")
	if err := os.Mkdir(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:provider",
		fixture.profile.ProviderAgentID, "authority:provider", authorityKey, relaySponsorshipTestLimits(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.domain-bound"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	absenceNow := time.Unix(int64(maxUint64(
		execution.QuoteRequest.Body.TransactionValidUntilUnix+uint64(execution.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds)+1,
		uint64(fixture.now.Unix()))), 0).UTC()
	sink := &TOSCTLPaymentSink{Authority: authority, Executable: "/usr/bin/tosctl", ConfigPath: paths[0],
		Wallet: "provider", SourceAccount: "0:sponsor", NetworkGlobalID: fixture.network.GlobalID,
		FeeReserveNanoTOS:  1,
		RelayNetworkDomain: &fixture.network, QuorumConfigPaths: paths[1:], MaximumTransactions: 1000,
		EvidenceDirectory: root, RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{fixture.sponsorshipFinality},
		Now:                           func() time.Time { return absenceNow }}
	sink.RelayNetworkPreflight = func(context.Context, string, agentrelay.NetworkDomain) error { return nil }
	var componentRaw, dualRaw []byte
	var recoveryToken relaySponsorshipRecoveryToken
	dualCalls := 0
	sink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		if len(args) < 3 {
			return nil, errors.New("short tosctl command")
		}
		switch args[2] {
		case "economic-payment-corroboration-profile":
			return tosctlSnapshotCapability(t, root, paths, fixture.network, 1000), nil
		case "economic-payment-sponsorship-dual-absence-capability":
			capability, capabilityErr := relayEvidenceCapabilityForExecution(execution)
			if capabilityErr != nil {
				return nil, capabilityErr
			}
			return tosctlRelayAbsenceCapabilityFixture(t, root, paths, capability,
				relayTestCLIFlag(args, "--role"), relayTestCLIFlag(args, "--corroboration-snapshot-identity")), nil
		case "economic-payment-sponsorship-dual-absence":
			dualCalls++
			if relayTestCLIFlag(args, "--existing-sponsorship-proof-bundle-cbor") == "" {
				return nil, errors.New("dual promotion lost its protected predecessor")
			}
			return dualRaw, nil
		case "economic-payment-sponsorship-corroborated-terminal":
			paymentDigest, _ := commerce.AgreementPaymentRequestDigest(recoveryToken.Payment)
			canonical, _, _ := commerce.PaymentAuthorizationMaterial(recoveryToken.Payment)
			exactDigest, _ := commerce.ExactRequestDigest(canonical)
			return mustJSON(t, tosctlRelaySponsorshipTerminalUnknown{
				Schema: tosctlRelaySponsorshipFinalitySchema, State: "unknown", Category: "not_mature",
				Reason:                        "quorum checkpoint has not crossed the selected chain-time reorg window",
				StableActionID:                recoveryToken.Payment.StableActionID,
				AgreementPaymentRequestDigest: paymentDigest, SponsorshipExactRequestDigest: exactDigest,
				CustodyState: "broadcasting", ChainSideEffect: false, CustodySideEffect: false}), nil
		case "economic-payment-sponsorship-component-absence":
			return componentRaw, nil
		default:
			return nil, errors.New("unexpected tosctl command: " + args[2])
		}
	}
	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, EvidenceResolver: sink, AbsenceResolver: sink, TransactionEvidenceVerifier: sink,
		NetworkDomain: fixture.network, NativeAsset: fixture.asset, PolicyRevision: 1,
		WriterFence: fence, Now: func() time.Time { return fixture.now }}
	capability, capabilityErr := relayEvidenceCapabilityForExecution(execution)
	if capabilityErr != nil || !sink.SupportsRelaySponsorshipComponentAbsenceEvidence(capability, nil) ||
		!sink.SupportsRelayDualAbsenceEvidence(capability, nil) {
		t.Fatalf("fixture sink is not ready for the exact combined absence tuple: capability=%+v err=%v",
			capability, capabilityErr)
	}
	recovery, err := processor.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil || token.EvidenceSnapshot == nil {
		t.Fatalf("decode frozen dual-absence recovery: token=%+v err=%v", token, err)
	}
	recoveryToken = token
	processor.Now = func() time.Time { return absenceNow }
	builtComponentRaw, componentPayload, componentRefs, componentDigest, componentBundle :=
		tosctlRelayAbsenceWireFixture(t, sink, execution, token.Payment, *token.EvidenceSnapshot,
			agentrelay.RelayAbsenceProofSponsorshipOnly, nil, "")
	componentRaw = builtComponentRaw
	component, err := sink.decodeRelaySponsorshipAbsence(execution, token.Payment, *token.EvidenceSnapshot, componentRaw)
	if err != nil || component.ProofBundleDigest != componentDigest ||
		!reflect.DeepEqual(component.SponsorshipAbsenceObservations, componentRefs) {
		t.Fatalf("decode exact sponsorship component: component=%+v err=%v", component, err)
	}
	checkpoint, err := processor.ResolveFinalized(t.Context(), execution, recovery)
	if err != nil || checkpoint.Status != agentrelay.SponsorshipResolutionCorroboratedAbsent ||
		len(checkpoint.SponsorshipAbsenceObservations) == 0 || len(checkpoint.TransactionAbsenceObservations) != 0 {
		t.Fatalf("combined processor rejected its valid S- checkpoint: resolution=%+v err=%v", checkpoint, err)
	}
	dualRaw, _, _, _, _ = tosctlRelayAbsenceWireFixture(t, sink, execution, token.Payment,
		*token.EvidenceSnapshot, agentrelay.RelayAbsenceProofDual, &componentPayload, componentDigest)
	resolution, err := processor.ResolveRelayDualAbsence(t.Context(), execution, recovery,
		componentRefs, componentDigest, componentBundle)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionCorroboratedAbsent ||
		len(resolution.TransactionAbsenceObservations) == 0 || dualCalls != 1 ||
		!reflect.DeepEqual(resolution.SponsorshipAbsenceObservations, componentRefs) {
		t.Fatalf("dual promotion did not preserve exact S- evidence: calls=%d resolution=%+v err=%v",
			dualCalls, resolution, err)
	}
	mutated := append([]agentrelay.RelayAbsenceObservationReference(nil), componentRefs...)
	mutated[0].ObservationDigest = relayTestDigest("f")
	if _, err := processor.ResolveRelayDualAbsence(t.Context(), execution, recovery,
		mutated, componentDigest, componentBundle); err == nil || dualCalls != 1 {
		t.Fatal("mutated predecessor reached the dual query boundary")
	}
}

func relayTestCLIFlag(args []string, name string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return ""
}

func tosctlRelayAbsenceCapabilityFixture(t *testing.T, root string, paths []string,
	capability agentrelay.RelayEvidenceCapability, role, snapshotIdentity string) []byte {
	t.Helper()
	var snapshot tosctlRelaySponsorshipCapability
	if err := json.Unmarshal(tosctlSnapshotCapability(t, root, paths, capability.Network, 1000), &snapshot); err != nil {
		t.Fatal(err)
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(capability.Network)
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON(t, tosctlRelayAbsenceCapability{
		Schema: tosctlRelaySponsorshipAbsenceCapabilitySchema, State: "ready", Role: role,
		Mode: capability.Mode, AssuranceLevel: capability.AssuranceLevel,
		NetworkDomain: capability.Network, NetworkDigest: networkDigest,
		UnderlyingActionKind:             capability.UnderlyingActionKind,
		TransactionProfileURI:            capability.TransactionProfileURI,
		TransactionProfileDigest:         capability.TransactionProfileDigest,
		SponsorshipReleaseEvidenceClass:  capability.SponsorshipReleaseProfile.EvidenceClass,
		SponsorshipReleaseProfileURI:     capability.SponsorshipReleaseProfile.ProfileURI,
		SponsorshipReleaseProfileDigest:  capability.SponsorshipReleaseProfile.ProfileDigest,
		SponsorshipTerminalEvidenceClass: capability.SponsorshipTerminalEvidenceClass,
		SponsorshipTerminalProfile:       *capability.SponsorshipTerminalProfile,
		RelayTerminalEvidenceClass:       capability.RelayTerminalEvidenceClass,
		RelayFinalityProfile:             capability.RelayFinalityProfile,
		SnapshotIdentity:                 snapshotIdentity,
		SnapshotMembers:                  snapshot.MemberCount, SnapshotThreshold: snapshot.EvidenceProfile.Threshold,
		AbsenceProofProfileURI:        capability.AbsenceProofProfileURI,
		AbsenceProofProfileDigest:     capability.AbsenceProofProfileDigest,
		DualAbsence:                   capability.Mode == agentrelay.ModeSponsorAndRelay,
		SponsorshipComponentAbsence:   true,
		TransactionComponentAbsence:   capability.Mode == agentrelay.ModeSponsorAndRelay,
		AllReachableComponentOutcomes: true, ProducerSupported: true, IndependentVerifierSupported: true,
		ValidatorAuthenticatedPortableProof: false, AutonomousDecentralizedSupported: false, SideEffect: false,
	})
}

func tosctlRelayAbsenceWireFixture(t *testing.T, sink *TOSCTLPaymentSink,
	execution agentrelay.RelayExecutionRequest, payment commerce.AgreementPaymentRequest,
	frozen RelaySponsorshipEvidenceSnapshot, scope agentrelay.RelayAbsenceProofScope,
	predecessor *tosctlRelayAbsencePayload, predecessorDigest string) ([]byte, tosctlRelayAbsencePayload,
	[]agentrelay.RelayAbsenceObservationReference, string, []byte) {
	t.Helper()
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(payment)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := commerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		t.Fatal(err)
	}
	paymentExactDigest, err := commerce.ExactRequestDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(frozen.SnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if decodeStrictJSON(manifestRaw, &manifest) != nil {
		t.Fatal("decode frozen sponsorship snapshot")
	}
	makeReferences := func(kind agentrelay.RelayAbsenceObservationKind,
		conclusion agentrelay.RelayAbsenceConclusion, profile agentrelay.FinalityProfile,
		seed string) []agentrelay.RelayAbsenceObservationReference {
		values := make([]agentrelay.RelayAbsenceObservationReference, 3)
		checkpoint := uint64(sink.Now().Unix())
		digestSeed := byte('a')
		if kind == agentrelay.AbsenceObservationClientTransaction {
			digestSeed = 'd'
		}
		for index := range values {
			values[index] = agentrelay.RelayAbsenceObservationReference{SchemaVersion: 1,
				ObservationKind: kind, Conclusion: conclusion,
				ProviderAgentID: execution.ProviderQuote.Body.ProviderAgentID, NetworkDigest: networkDigest,
				RelayStableActionID:     execution.AuthorizedAction.StableActionID,
				RelayExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest,
				RelayExecutionDigest:    executionDigest, SponsorshipStableActionID: payment.StableActionID,
				SponsorshipExactRequestDigest: paymentExactDigest, SponsorshipValidUntilUnix: payment.ExpiresAtUnix,
				SignedTransactionDigest:   execution.QuoteRequest.Body.SignedTransactionDigest,
				SignedTransactionCellHash: execution.QuoteRequest.Body.SignedTransactionCellHash,
				TerminalProfileURI:        profile.ProfileURI, TerminalProfileDigest: profile.ProfileDigest,
				TerminalEvidenceClass:       profile.TerminalEvidenceClass,
				FinalizedCheckpointID:       "checkpoint:" + seed,
				FinalizedCheckpointSequence: 100, FinalizedCheckpointUnix: checkpoint,
				ObserverID:                       "observer:" + string(rune('a'+index)),
				OperatorDomainID:                 "operator:" + string(rune('a'+index)),
				ObservationEvidenceProfileURI:    frozen.ProfileURI,
				ObservationEvidenceProfileDigest: frozen.ProfileDigest,
				ObservationDigest:                relayTestDigest(string(rune(digestSeed + byte(index)))), ObservedAtUnix: checkpoint}
			if _, digestErr := agentrelay.RelayAbsenceObservationReferenceDigest(values[index]); digestErr != nil {
				t.Fatalf("build %s absence reference %d: %+v: %v", kind, index, values[index], digestErr)
			}
		}
		sort.Slice(values, func(left, right int) bool {
			leftDigest, _ := agentrelay.RelayAbsenceObservationReferenceDigest(values[left])
			rightDigest, _ := agentrelay.RelayAbsenceObservationReferenceDigest(values[right])
			return leftDigest < rightDigest
		})
		return values
	}
	sponsorship := makeReferences(agentrelay.AbsenceObservationSponsorshipAction,
		agentrelay.AbsenceConclusionExpiredWithoutInclusion,
		*execution.ProviderQuote.Body.SponsorshipTerminalProfile, "s")
	var transaction []agentrelay.RelayAbsenceObservationReference
	if scope == agentrelay.RelayAbsenceProofDual {
		transaction = makeReferences(agentrelay.AbsenceObservationClientTransaction,
			agentrelay.AbsenceConclusionAbsent, *execution.ProviderQuote.Body.RelayFinalityProfile, "t")
	}
	evidenceSet, err := relayAbsenceReferenceSetDigest(sponsorship, transaction)
	if err != nil {
		t.Fatal(err)
	}
	payload := tosctlRelayAbsencePayload{Schema: "tosctl.agent-account.agreement-payment-sponsorship-dual-absence-proof-bundle.v1",
		ProofScope: scope, ProviderSnapshotIdentity: frozen.SnapshotIdentity,
		EvidenceProfileURI: frozen.ProfileURI, EvidenceProfileDigest: frozen.ProfileDigest,
		EvidenceProfile: manifest.EvidenceProfile, NetworkDomain: execution.QuoteRequest.Body.Network,
		NetworkDigest: networkDigest, AgreementPaymentRequest: payment,
		AgreementPaymentRequestDigest: paymentDigest, SponsorshipStableActionID: payment.StableActionID,
		SponsorshipExactRequestDigest: paymentExactDigest, SponsorshipValidUntilUnix: payment.ExpiresAtUnix,
		SignedTopUpTransactionBOC:      []byte("exact signed top-up BOC"),
		SignedTopUpTransactionDigest:   sha256Digest([]byte("exact signed top-up BOC")),
		SignedTopUpTransactionCellHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
		ProviderSponsorSourceAccount:   sink.SourceAccount, ProviderSponsorSourceSequence: 7,
		RelayExecutionRequestDigest: executionDigest,
		RelayStableActionID:         execution.AuthorizedAction.StableActionID,
		RelayExactRequestDigest:     execution.AuthorizedAction.ExactRequestDigest,
		ProviderAgentID:             execution.ProviderQuote.Body.ProviderAgentID, Mode: execution.QuoteRequest.Body.Mode,
		AssuranceLevel:                  execution.QuoteRequest.Body.AssuranceLevel,
		SignedTransactionDigest:         execution.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash:       execution.QuoteRequest.Body.SignedTransactionCellHash,
		SignedTransactionSourceAccount:  execution.QuoteRequest.Body.SourceAccount,
		SignedTransactionSourceSequence: execution.QuoteRequest.Body.SourceSequence,
		TransactionValidUntilUnix:       execution.QuoteRequest.Body.TransactionValidUntilUnix,
		SponsorshipTerminalProfile:      *execution.ProviderQuote.Body.SponsorshipTerminalProfile,
		RelayFinalityProfile:            execution.ProviderQuote.Body.RelayFinalityProfile,
		SponsorshipObservations:         []map[string]any{{"observer": "a"}, {"observer": "b"}, {"observer": "c"}},
		SponsorshipAbsenceObservations:  sponsorship, TransactionAbsenceObservations: transaction,
		EvidenceSetDigest: evidenceSet, ProducedAtUnix: uint64(sink.Now().Unix())}
	state, outcome, custodyState, custodySideEffect := "corroborated_sponsorship_absent",
		"corroborated_sponsorship_absent_component", "resolved", true
	if scope == agentrelay.RelayAbsenceProofDual {
		if predecessor == nil {
			t.Fatal("dual fixture has no protected predecessor")
		}
		payload.SignedTopUpTransactionBOC = append([]byte(nil), predecessor.SignedTopUpTransactionBOC...)
		payload.SignedTopUpTransactionDigest = predecessor.SignedTopUpTransactionDigest
		payload.SignedTopUpTransactionCellHash = predecessor.SignedTopUpTransactionCellHash
		payload.ProviderSponsorSourceAccount = predecessor.ProviderSponsorSourceAccount
		payload.ProviderSponsorSourceSequence = predecessor.ProviderSponsorSourceSequence
		payload.SponsorshipObservations = append([]map[string]any(nil), predecessor.SponsorshipObservations...)
		payload.SponsorshipAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil),
			predecessor.SponsorshipAbsenceObservations...)
		sponsorship = payload.SponsorshipAbsenceObservations
		evidenceSet, err = relayAbsenceReferenceSetDigest(sponsorship, transaction)
		if err != nil {
			t.Fatal(err)
		}
		payload.EvidenceSetDigest = evidenceSet
		payload.Outcome = string(agentrelay.OutcomeCorroboratedAbsent)
		payload.TransactionObservations = []map[string]any{{"observer": "a"}, {"observer": "b"}, {"observer": "c"}}
		state, outcome, custodyState, custodySideEffect = "corroborated_absent",
			string(agentrelay.OutcomeCorroboratedAbsent), "resolved_sponsorship_component", false
	} else {
		payload.Outcome = outcome
	}
	payloadCBOR, err := codec.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := codec.DigestCanonical(agentrelay.RelayAbsenceProofPayloadDomainV1, payloadCBOR)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := agentrelay.RelayAbsenceProofBundleV1{SchemaVersion: 1, ProofScope: scope,
		ProofProfileURI: agentrelay.RelayAbsenceTOSRPCProofProfileURI, ProofProfileDigest: profileDigest,
		ProofPayloadDigest: payloadDigest, ProofPayload: payloadCBOR,
		SponsorshipAbsenceObservations: sponsorship, TransactionAbsenceObservations: transaction}
	bundle, err := codec.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := agentrelay.RelayAbsenceProofBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	result := tosctlRelayAbsenceTerminal{Schema: tosctlRelaySponsorshipComponentAbsenceSchema,
		State: state, Outcome: outcome, TerminalEvidenceClass: agentrelay.SponsorshipTerminalClientCorroborated,
		NetworkDomain: execution.QuoteRequest.Body.Network, NetworkDigest: networkDigest,
		AgreementPaymentRequestDigest: paymentDigest, SponsorshipStableActionID: payment.StableActionID,
		SponsorshipExactRequestDigest: paymentExactDigest, SponsorshipValidUntilUnix: payment.ExpiresAtUnix,
		RelayStableActionID:            execution.AuthorizedAction.StableActionID,
		RelayExactRequestDigest:        execution.AuthorizedAction.ExactRequestDigest,
		RelayExecutionRequestDigest:    executionDigest,
		SignedTopUpTransactionDigest:   payload.SignedTopUpTransactionDigest,
		SignedTopUpTransactionCellHash: payload.SignedTopUpTransactionCellHash,
		SignedTransactionDigest:        execution.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash:      execution.QuoteRequest.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix:      execution.QuoteRequest.Body.TransactionValidUntilUnix,
		SponsorshipTerminalProfile:     *execution.ProviderQuote.Body.SponsorshipTerminalProfile,
		RelayFinalityProfile:           execution.ProviderQuote.Body.RelayFinalityProfile,
		ProviderSnapshotIdentity:       frozen.SnapshotIdentity, EvidenceProfileURI: frozen.ProfileURI,
		EvidenceProfileDigest: frozen.ProfileDigest, SponsorshipAbsenceObservations: sponsorship,
		TransactionAbsenceObservations: transaction, EvidenceSetDigest: evidenceSet,
		ProofBundleDigestAlgorithm: tosctlRelayAbsenceDigestMethod,
		ProofBundleDigestDomain:    agentrelay.RelayAbsenceProofBundleDomainV1,
		ProofBundleDigest:          bundleDigest, PredecessorSponsorshipProofBundleDigest: predecessorDigest,
		ProofBundleCBOR: bundle, ProofBundle: wrapper, ProofPayload: mustJSON(t, payload),
		ProducedAtUnix: uint64(sink.Now().Unix()), CustodyState: custodyState,
		ChainSideEffect: false, CustodySideEffect: custodySideEffect}
	if scope == agentrelay.RelayAbsenceProofDual {
		result.Schema = tosctlRelaySponsorshipDualAbsenceSchema
	}
	return mustJSON(t, result), payload, sponsorship, bundleDigest, bundle
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}
