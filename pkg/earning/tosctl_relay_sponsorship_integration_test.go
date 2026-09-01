package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestObservedSponsorshipUsesFrozenCorroborationWithoutGenericFinalityLoop(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.sponsorshipFinality.MinimumConfirmationDepth = 1
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
	const providerWalletA = "provider-a"
	const providerSourceA = "0:sponsor-a"
	const feeReserveA = uint64(1)

	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityDirectory := filepath.Join(root, "authority")
	if err := os.Mkdir(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:provider",
		fixture.profile.ProviderAgentID, "authority:provider", authorityKey,
		relaySponsorshipTestLimits(t, fixture, providerSourceA))
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "relay-provider", []string{"payment.domain-bound"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var payment commerce.AgreementPaymentRequest
	var frozen RelaySponsorshipEvidenceSnapshot
	commandCalls := map[string]int{}
	broadcastsSent := 0
	broadcastStableIDs := []string{}
	terminalReady := false
	var frozenPrimaryConfig string
	sink := &TOSCTLPaymentSink{Authority: authority, Executable: "/usr/bin/tosctl", ConfigPath: paths[0],
		Wallet: providerWalletA, SourceAccount: providerSourceA, NetworkGlobalID: fixture.network.GlobalID,
		RelayNetworkDomain: &fixture.network, RelayNetworkPreflight: func(context.Context, string,
			agentrelay.NetworkDomain) error {
			return nil
		}, RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{fixture.sponsorshipFinality},
		FeeReserveNanoTOS:             feeReserveA, QuorumConfigPaths: paths[1:], MaximumTransactions: 1000,
		EvidenceDirectory: root, ResolveAttempts: 1, ResolveInterval: time.Millisecond,
		Now: func() time.Time { return fixture.now }}
	sink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		if len(args) < 3 {
			return nil, errors.New("short tosctl command")
		}
		command := args[2]
		commandCalls[command]++
		switch command {
		case "economic-payment-corroboration-profile":
			return tosctlSnapshotCapability(t, root, paths, fixture.network, 1000), nil
		case "economic-payment-prepare":
			boc := []byte("sponsored-payment-boc")
			bocDigest := sha256.Sum256(boc)
			validUntil, _ := strconv.ParseUint(relayTestCLIFlag(args, "--valid-until"), 10, 32)
			if relayTestCLIFlag(args, "--wallet") != providerWalletA ||
				relayTestCLIFlag(args, "--fee-reserve-nanotos") != strconv.FormatUint(feeReserveA, 10) ||
				relayTestCLIFlag(args, "-c") != frozenPrimaryConfig {
				return nil, errors.New("prepared sponsorship borrowed rotated custody identity")
			}
			amount, _ := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
			return mustJSON(t, tosctlPaymentPrepared{Schema: "tosctl.agent-account.agreement-payment-prepared.v1",
				StableActionID: payment.StableActionID, AgreementBodyDigest: payment.AgreementBodyDigest,
				ObligationInstanceID: payment.ObligationInstanceID, Account: providerSourceA,
				Target: string(payment.Destination), AmountNanoTOS: amount, ControllerEpoch: 1, Seqno: 7,
				NetworkGlobalID: fixture.network.GlobalID, NetworkDomain: fixture.network,
				ValidUntil: uint32(validUntil), ActionKind: "agent-task-send",
				SponsorshipCommitmentBodyHash: testStringPointer("tvm-cell-sha256:" + strings.Repeat("1", 64)),
				ExactSignedBOC:                base64.StdEncoding.EncodeToString(boc), ExactSignedBOCDigest: "sha256:" + hex.EncodeToString(bocDigest[:])}), nil
		case "economic-payment-broadcast":
			if relayTestCLIFlag(args, "--wallet") != providerWalletA ||
				relayTestCLIFlag(args, "-c") != frozenPrimaryConfig {
				return nil, errors.New("broadcast sponsorship borrowed rotated custody identity")
			}
			for index := range args {
				if args[index] == "--stable-action-id" && index+1 < len(args) {
					broadcastStableIDs = append(broadcastStableIDs, args[index+1])
				}
			}
			broadcastsSent++
			return mustJSON(t, tosctlPaymentBroadcast{Schema: "tosctl.agent-account.agreement-payment-broadcast.v1",
				StableActionID: payment.StableActionID, Account: providerSourceA,
				ExactSignedBOCDigest: relayTestDigest("d"), State: "broadcasting"}), nil
		case "economic-payment-corroborate":
			if commandCalls["economic-payment-prepare"] != 1 || broadcastsSent < 1 {
				return nil, errors.New("corroboration ran before the exact top-up was submitted")
			}
			return tosctlObservedSponsorshipResult(t, execution, payment, sink, frozen), nil
		case "economic-payment-sponsorship-corroborated-terminal":
			if relayTestCLIFlag(args, "--wallet") != providerWalletA ||
				relayTestCLIFlag(args, "-c") != frozenPrimaryConfig {
				return nil, errors.New("terminal sponsorship borrowed rotated custody identity")
			}
			if !terminalReady {
				paymentDigest, _ := commerce.AgreementPaymentRequestDigest(payment)
				canonical, _, _ := commerce.PaymentAuthorizationMaterial(payment)
				exactDigest, _ := commerce.ExactRequestDigest(canonical)
				return mustJSON(t, tosctlRelaySponsorshipTerminalUnknown{
					Schema: tosctlRelaySponsorshipFinalitySchema, State: "unknown", Category: "not_mature",
					Reason:         "quorum checkpoint has not crossed the selected chain-time reorg window",
					StableActionID: payment.StableActionID, AgreementPaymentRequestDigest: paymentDigest,
					SponsorshipExactRequestDigest: exactDigest, CustodyState: "broadcasting",
					ChainSideEffect: false, CustodySideEffect: false}), nil
			}
			return tosctlFinalizedSponsorshipResult(t, execution, payment, sink, frozen), nil
		case "economic-payment-resolve":
			return nil, errors.New("ordinary finalized resolver must not run for observed sponsorship")
		default:
			return nil, errors.New("unexpected tosctl command: " + command)
		}
	}

	processor := &AgreementSponsorshipProcessor{Engine: &Engine{OwnerID: "owner:provider",
		AgentID: fixture.profile.ProviderAgentID, MandateDigest: relayTestDigest("a"),
		Gates: FeatureGates{DirectPayment: true}, Authority: authority, Now: func() time.Time { return fixture.now }},
		Sink: sink, EvidenceResolver: sink, AbsenceResolver: relayTestSponsorshipAbsenceResolver{},
		TransactionEvidenceVerifier: sink,
		NetworkDomain:               fixture.network, NativeAsset: fixture.asset,
		PolicyRevision: 1, WriterFence: fence, Now: func() time.Time { return fixture.now }}
	recovery, err := processor.PrepareRecovery(t.Context(), execution, agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	token, err := decodeRelaySponsorshipRecoveryHandle(recovery, execution)
	if err != nil || token.EvidenceSnapshot == nil {
		t.Fatalf("recovery token did not bind a frozen corroboration snapshot: token=%+v err=%v", token, err)
	}
	payment, frozen = token.Payment, *token.EvidenceSnapshot
	if frozen.SchemaVersion != 2 || frozen.RegistryRoot == "" || frozen.CustodyWallet != providerWalletA ||
		frozen.ProviderSourceAccount != providerSourceA || frozen.FeeReserveNanoTOS != feeReserveA {
		t.Fatalf("provider recovery token omitted exact frozen custody locators: %+v", frozen)
	}
	manifestBytes, readManifestErr := os.ReadFile(frozen.SnapshotPath)
	var frozenManifest tosctlRelaySponsorshipSnapshotManifest
	if readManifestErr != nil || decodeStrictJSON(manifestBytes, &frozenManifest) != nil ||
		len(frozenManifest.Members) == 0 {
		t.Fatal("read frozen provider snapshot manifest")
	}
	frozenPrimaryConfig = filepath.Join(filepath.Dir(frozen.SnapshotPath), frozenManifest.Members[0].ConfigPath)
	// Rotate every mutable semantic locator before the first custody prepare.
	// The admitted A action must still use only A's frozen root/config, wallet,
	// source account, network, native asset, and fee reserve; B affects only new
	// actions frozen after this point.
	rotatedRoot := privateTempDir(t)
	rotatedNetwork := fixture.network
	rotatedNetwork.NetworkID = "tos:rotated-testnet"
	rotatedNetwork.GlobalID = -44
	rotatedNetwork.ZeroStateRootHash = relayTestDigest("1")
	rotatedNetwork.ZeroStateFileHash = relayTestDigest("2")
	rotatedPaths := tosctlSponsorshipTestConfigs(t, rotatedRoot, rotatedNetwork)
	rotatedPolicy, _, buildErr := buildTOSCTLSponsorshipEvidenceProfile(rotatedPaths, rotatedNetwork, 1000)
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	sink.ConfigPath, sink.QuorumConfigPaths, sink.EvidenceDirectory = rotatedPaths[0], rotatedPaths[1:], rotatedRoot
	sink.Wallet, sink.SourceAccount, sink.FeeReserveNanoTOS = "provider-b", "0:sponsor-b", 99
	sink.NetworkGlobalID, sink.RelayNetworkDomain = rotatedNetwork.GlobalID, &rotatedNetwork
	sink.RelaySponsorshipReleasePolicy = rotatedPolicy
	processor.NetworkDomain = rotatedNetwork
	processor.NativeAsset = agentrelay.AssetIdentity{AssetNamespace: "tos", AssetIdentifier: "rotated", Unit: "nano"}
	preflightCalls := 0
	sink.RelayNetworkPreflight = func(_ context.Context, configPath string, network agentrelay.NetworkDomain) error {
		preflightCalls++
		if configPath != frozenPrimaryConfig || network != fixture.network {
			return errors.New("old sponsorship recovery switched to rotated network configuration")
		}
		return nil
	}
	// Simulate a crash after local owner admission but before custody prepared
	// any BOC. Recovery must query first, observe Unknown, and then perform the
	// one exact prepare/submit; PREPARED is not an ambiguity boundary.
	material, err := processor.prepareSponsorshipPayment(t.Context(), execution, agreement, obligation, &frozen)
	if err != nil {
		t.Fatal(err)
	}
	signedAction, err := authority.SignAction(material.action, fence)
	if err != nil {
		t.Fatal(err)
	}
	preparedResolution, _, err := authority.AdmitRelaySponsorshipPayment(signedAction, material.fields,
		material.canonical, fence, material.payment, material.purpose)
	if err != nil || preparedResolution.State != commerce.ActionPrepared {
		t.Fatalf("seed PREPARED crash boundary: resolution=%+v err=%v", preparedResolution, err)
	}
	resolution, err := processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recovery)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionObservedUnproven ||
		resolution.CreditObservation == nil {
		t.Fatalf("observed sponsorship did not complete its bounded typed path: resolution=%+v err=%v", resolution, err)
	}
	if commandCalls["economic-payment-prepare"] != 1 || commandCalls["economic-payment-broadcast"] != 1 ||
		commandCalls["economic-payment-corroborate"] != 2 || commandCalls["economic-payment-resolve"] != 0 {
		t.Fatalf("observed path entered a generic finality loop or repeated custody: calls=%v", commandCalls)
	}
	if preflightCalls == 0 {
		t.Fatal("old sponsorship recovery did not preflight its frozen network/config")
	}

	// Restart/ambiguity recovery may resubmit the byte-identical custody BOC,
	// but it never prepares, signs, allocates a sequence for, or broadcasts a
	// replacement top-up.
	resolution, err = processor.EnsureFinalized(t.Context(), execution, agreement, obligation, recovery)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionObservedUnproven ||
		commandCalls["economic-payment-prepare"] != 1 || commandCalls["economic-payment-broadcast"] != 2 ||
		broadcastsSent != 2 || len(broadcastStableIDs) != 2 ||
		broadcastStableIDs[0] != payment.StableActionID || broadcastStableIDs[1] != payment.StableActionID ||
		commandCalls["economic-payment-corroborate"] != 3 {
		t.Fatalf("observed restart created a second top-up: calls=%v resolution=%+v err=%v",
			commandCalls, resolution, err)
	}

	// Terminal recovery is chain-query-only. It may atomically journal the exact
	// custody winner before stdout, but it must not mint another release
	// observation or chain side effect, and it converges the same owner-authorized
	// payment result without letting caller-verified evidence release or mutate
	// the authority-owned bearer lifecycle. The action remains SUBMITTED until
	// a future authority-internal verifier can establish exact finality.
	corroborationCalls := commandCalls["economic-payment-corroborate"]
	resolution, err = processor.ResolveFinalized(t.Context(), execution, recovery)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionUnknown ||
		commandCalls["economic-payment-corroborate"] != corroborationCalls ||
		authority.Resolve(token.PaymentActionStableID, token.PaymentActionExactRequestDigest).State != commerce.ActionSubmitted {
		t.Fatalf("immature terminal query regenerated release evidence: calls=%v resolution=%+v err=%v",
			commandCalls, resolution, err)
	}
	terminalReady = true
	resolution, err = processor.ResolveFinalized(t.Context(), execution, recovery)
	actionResolution := authority.Resolve(token.PaymentActionStableID, token.PaymentActionExactRequestDigest)
	if err != nil || resolution.Status != agentrelay.SponsorshipResolutionCorroboratedTerminal ||
		resolution.TransactionEvidence == nil || commandCalls["economic-payment-sponsorship-corroborated-terminal"] != 2 ||
		commandCalls["economic-payment-corroborate"] != corroborationCalls ||
		actionResolution.State != commerce.ActionSubmitted ||
		actionResolution.SinkReference != "" || len(actionResolution.EvidenceRefs) != 0 {
		t.Fatalf("observed sponsorship did not converge through the terminal-only query: calls=%v action=%+v resolution=%+v err=%v",
			commandCalls, actionResolution, resolution, err)
	}
	expected, err := relaySponsorshipEvidenceContext(execution, *resolution.TransactionEvidence)
	if err != nil {
		t.Fatal(err)
	}
	remoteBundleOnlyVerifier := &TOSCTLPaymentSink{RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{fixture.sponsorshipFinality},
		Now:                           func() time.Time { return fixture.now }}
	if err := remoteBundleOnlyVerifier.VerifySponsorshipTransactionEvidence(t.Context(),
		*resolution.TransactionEvidence, expected, fixture.sponsorshipFinality); err == nil {
		t.Fatal("a self-consistent Provider bundle passed without client-owned re-query or portable proof evidence")
	}

	// The concrete requester verifier freezes its own quorum snapshot before a
	// Quote and independently re-queries the chain effect. Public locator
	// identities deliberately ignore private API keys and JSON formatting,
	// while each local snapshot still binds its exact private bytes.
	clientRoot := privateTempDir(t)
	clientPaths := tosctlSponsorshipTestConfigs(t, clientRoot, fixture.network)
	for _, path := range clientPaths {
		raw, readErr := os.ReadFile(path)
		if readErr != nil || os.WriteFile(path, append(raw, '\n'), 0o600) != nil {
			t.Fatal("prepare independently formatted client RPC config")
		}
	}
	var clientFrozen RelaySponsorshipEvidenceSnapshot
	clientSink := &TOSCTLPaymentSink{Executable: "/usr/bin/tosctl", ConfigPath: clientPaths[0],
		QuorumConfigPaths: clientPaths[1:], MaximumTransactions: 1000, EvidenceDirectory: clientRoot,
		RelayNetworkDomain: &fixture.network, NetworkGlobalID: fixture.network.GlobalID,
		RelaySponsorshipReleasePolicy: policy,
		RelayTerminalFinalityProfiles: []agentrelay.FinalityProfile{fixture.sponsorshipFinality},
		Now:                           func() time.Time { return fixture.now }}
	clientSink.Run = func(_ context.Context, args []string, _ []string) ([]byte, error) {
		if len(args) < 3 {
			return nil, errors.New("short client tosctl command")
		}
		switch args[2] {
		case "economic-payment-corroboration-profile":
			return tosctlSnapshotCapability(t, clientRoot, clientPaths, fixture.network, 1000), nil
		case "economic-payment-sponsorship-proof-verify":
			return tosctlVerifiedSponsorshipProofResult(t, *resolution.TransactionEvidence,
				fixture.sponsorshipFinality, clientFrozen, clientSink), nil
		default:
			return nil, errors.New("unexpected client tosctl command: " + args[2])
		}
	}
	if !clientSink.SupportsRelaySponsorshipTransactionEvidence(
		agentrelay.AssuranceAuthorizedSingleProvider, policy, fixture.sponsorshipFinality) {
		t.Fatal("concrete client-owned re-query verifier did not advertise the exact signed predicate")
	}
	clientFrozen, err = clientSink.FreezeRelaySponsorshipClientEvidenceSnapshot(t.Context(),
		execution.QuoteRequest.Body)
	if err != nil || clientFrozen.SnapshotIdentity == frozen.SnapshotIdentity {
		t.Fatalf("client snapshot did not separate private bytes from the shared public profile: provider=%s client=%s err=%v",
			frozen.SnapshotIdentity, clientFrozen.SnapshotIdentity, err)
	}
	if err := clientSink.VerifySponsorshipTransactionEvidenceFromSnapshot(t.Context(),
		*resolution.TransactionEvidence, expected, fixture.sponsorshipFinality, clientFrozen); err != nil {
		t.Fatalf("client-owned RPC quorum did not independently reproduce the exact sponsorship: %v", err)
	}
	oldClientFrozen := clientFrozen
	rotated, err := os.ReadFile(clientPaths[0])
	if err != nil || os.WriteFile(clientPaths[0], append(rotated, ' '), 0o600) != nil {
		t.Fatal("rotate client quorum config")
	}
	clientFrozen, err = clientSink.FreezeRelaySponsorshipClientEvidenceSnapshot(t.Context(),
		execution.QuoteRequest.Body)
	if err != nil || clientFrozen.SnapshotIdentity == oldClientFrozen.SnapshotIdentity ||
		!clientSink.SupportsRelaySponsorshipTransactionEvidence(
			agentrelay.AssuranceAuthorizedSingleProvider, policy, fixture.sponsorshipFinality) {
		t.Fatalf("private config formatting changed the public predicate or not the local snapshot: old=%s new=%s err=%v",
			oldClientFrozen.SnapshotIdentity, clientFrozen.SnapshotIdentity, err)
	}
	clientFrozen = oldClientFrozen
	if err := clientSink.VerifySponsorshipTransactionEvidenceFromSnapshot(t.Context(),
		*resolution.TransactionEvidence, expected, fixture.sponsorshipFinality, oldClientFrozen); err != nil {
		t.Fatalf("old funded action was stranded by client config rotation: %v", err)
	}

	registryDirectory := filepath.Join(root, "client-chain-effect-registry")
	if err := os.Mkdir(registryDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenDurableRelayRouteJournal(registryDirectory)
	if err != nil {
		t.Fatal(err)
	}
	terminalEvidence := *resolution.TransactionEvidence
	if err := registry.BindSponsorshipChainEffect(execution, terminalEvidence, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := registry.BindSponsorshipChainEffect(execution, terminalEvidence, fixture.now); err != nil {
		t.Fatalf("exact sponsorship effect replay was not idempotent: %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err = OpenDurableRelayRouteJournal(registryDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	replacementAgreementDigest := relayTestDigest("7")
	replacementObligation := commerce.SettlementObligation{AgreementBodyDigest: replacementAgreementDigest,
		AgreementObligationID: payment.AgreementObligationID, ObligationInstanceID: relayTestDigest("6"), Sequence: 1,
		PayerAgentID: payment.PayerAgentID, PayeeAgentID: payment.PayeeAgentID, Amount: payment.Amount,
		MaximumAggregateAmount: payment.Amount, ExpiresAtUnix: payment.ExpiresAtUnix,
		SettlementAdapterURI: payment.SettlementAdapterURI, SettlementParametersDigest: relayTestDigest("5"),
		MandateDigest: relayTestDigest("4"), StableActionID: relayTestDigest("3")}
	replacementPayment, err := commerce.BuildDomainBoundAgreementPaymentRequest(payment.OwnerID, payment.AgentID,
		payment.NetworkID, payment.NetworkDomainDigest, payment.Destination, replacementObligation)
	if err != nil {
		t.Fatal(err)
	}
	replacementPaymentDigest, err := commerce.AgreementPaymentRequestDigest(replacementPayment)
	if err != nil {
		t.Fatal(err)
	}
	replacementCanonical, _, err := commerce.PaymentAuthorizationMaterial(replacementPayment)
	if err != nil {
		t.Fatal(err)
	}
	replacementExactDigest, err := commerce.ExactRequestDigest(replacementCanonical)
	if err != nil {
		t.Fatal(err)
	}
	replayedEffect := terminalEvidence
	replayedEffect.AgreementPaymentRequest = replacementPayment
	replayedEffect.AgreementPaymentRequestDigest = replacementPaymentDigest
	replayedEffect.SponsorshipStableActionID = replacementPayment.StableActionID
	replayedEffect.SponsorshipExactRequestDigest = replacementExactDigest
	replayedExecution := execution
	replayedExecution.AgreementBodyDigest = replacementAgreementDigest
	if err := registry.BindSponsorshipChainEffect(replayedExecution, replayedEffect, fixture.now.Add(time.Second)); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("old genuine chain effect was reusable for a new Agreement after restart: %v", err)
	}
}

func testStringPointer(value string) *string { return &value }

func tosctlSponsorshipTestConfigs(t *testing.T, root string, network agentrelay.NetworkDomain) []string {
	t.Helper()
	paths := make([]string, 3)
	for index := range paths {
		paths[index] = filepath.Join(root, "rpc-"+string(rune('a'+index))+".json")
		raw := tosctlProfileConfig(t, "https://rpc-"+string(rune('a'+index))+".example/jsonRPC",
			"sha256:"+strings.Repeat(string(rune('a'+index)), 64))
		if err := os.WriteFile(paths[index], raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = network
	return paths
}

func tosctlObservedSponsorshipResult(t *testing.T, execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest, sink *TOSCTLPaymentSink,
	frozen RelaySponsorshipEvidenceSnapshot) []byte {
	t.Helper()
	manifestRaw, err := os.ReadFile(frozen.SnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if err := decodeStrictJSON(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	network := manifest.NetworkDomain
	providerSource := frozen.ProviderSourceAccount
	if providerSource == "" {
		providerSource = sink.SourceAccount
	}
	transactionHash := relayTestDigest("4")
	observations := make([]tosctlPaymentObservation, len(manifest.EvidenceProfile.Members))
	for index, member := range manifest.EvidenceProfile.Members {
		observations[index] = tosctlPaymentObservation{Endpoint: member.Endpoint,
			LocatorIdentityDigest: member.LocatorIdentityDigest,
			OperatorProvenance:    member.OperatorProvenance, TransactionHash: transactionHash,
			TransactionLT: 77, TransactionUTime: uint64(sink.Now().Unix()),
			TransactionBOCDigest:       relayTestDigest("5"),
			SourceOutboundMessageHash:  "tvm-cell-sha256:" + strings.Repeat("6", 64),
			DestinationCreditReference: relayTestDigest("8"), BlockWorkchain: network.WorkchainID,
			DestinationTransactionHash: relayTestDigest("8"), DestinationTransactionLT: 78,
			DestinationTransactionUTime:     uint64(sink.Now().Unix()),
			DestinationTransactionBOCDigest: relayTestDigest("7"),
			DestinationBlockWorkchain:       network.WorkchainID,
			DestinationBlockShard:           -1, DestinationBlockSeqno: 10,
			DestinationBlockRootHash: relayTestDigest("e"), DestinationBlockFileHash: relayTestDigest("f"),
			DestinationCreditAtomic: payment.Amount.AmountAtomic, DestinationCreditFirst: true,
			DestinationTransactionAborted: false, DestinationBouncePresent: false,
			DestinationCreditObservedExact: true,
			BlockShard:                     -1, BlockSeqno: 9, BlockRootHash: relayTestDigest("9"),
			BlockFileHash: relayTestDigest("a"), NetworkGlobalID: network.GlobalID,
			ZeroStateWorkchain: -1, ZeroStateShard: -1,
			ZeroStateRootHash:            network.ZeroStateRootHash,
			ZeroStateFileHash:            network.ZeroStateFileHash,
			ObservedMasterchainWorkchain: -1, ObservedMasterchainShard: -1,
			ObservedMasterchainSeqno: 12, ObservedMasterchainRootHash: relayTestDigest("b"),
			ObservedMasterchainFileHash: relayTestDigest("c"),
			ObservedMasterchainGenUTime: uint64(sink.Now().Unix()), FinalityProven: false}
	}
	digests := make([]string, 0, len(observations))
	for _, observation := range observations {
		digest, err := tosctlRustFramedDigest(tosctlSponsorshipObservationDomain, observation)
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	paymentDigest, _ := commerce.AgreementPaymentRequestDigest(payment)
	canonical, _, _ := commerce.PaymentAuthorizationMaterial(payment)
	exactDigest, _ := commerce.ExactRequestDigest(canonical)
	amount, _ := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
	winner := observations[0]
	result := tosctlRelaySponsorshipObserved{Schema: "tosctl.agent-account.agreement-payment-rpc-corroboration.v2",
		StableActionID: payment.StableActionID, SponsorshipStableActionID: payment.StableActionID,
		SponsorshipExactRequestDigest: exactDigest, AgreementPaymentRequestDigest: paymentDigest,
		AgreementBodyDigest: payment.AgreementBodyDigest, ObligationInstanceID: payment.ObligationInstanceID,
		ProviderSponsorSourceAccount: providerSource, ProviderSponsorSourceSequence: 0,
		ProviderSponsorValidUntilUnix: payment.ExpiresAtUnix, SignedTopUpTransactionDigest: relayTestDigest("d"),
		SignedTopUpTransactionCellHash:       "tvm-cell-sha256:" + strings.Repeat("e", 64),
		SponsorshipPaymentCommitmentCellHash: "tvm-cell-sha256:" + strings.Repeat("f", 64),
		DestinationSourceAccount:             string(payment.Destination), Destination: string(payment.Destination),
		AmountNanoTOS: amount, NetworkGlobalID: network.GlobalID, NetworkDomain: network,
		SubmittedTransactionHash: transactionHash, SourceExecutionReference: transactionHash,
		DestinationCreditReferences: []string{winner.DestinationCreditReference},
		EvidenceProfileURI:          manifest.EvidenceProfileURI, EvidenceProfileDigest: manifest.EvidenceProfileDigest,
		EvidenceProfile: manifest.EvidenceProfile, CorroborationSnapshot: frozen.SnapshotPath,
		CorroborationSnapshotIdentity: frozen.SnapshotIdentity,
		ObservedCheckpointID: "masterchain:-1:-1:12:" + winner.ObservedMasterchainRootHash + ":" +
			winner.ObservedMasterchainFileHash,
		ObservedCheckpointSequence: 12, ObservedCheckpointUnix: winner.ObservedMasterchainGenUTime,
		ObservationDigests: digests, ObservedAtUnix: uint64(sink.Now().Unix()),
		Quorum: tosctlQuorum{Members: uint32(len(observations)), Threshold: manifest.EvidenceProfile.Threshold,
			Agreeing: uint32(len(observations))}, Evidence: winner, Observations: observations,
		Failures: []string{}, Finality: "unproven", State: "observed_unproven", CustodyState: "broadcasting",
		MissingProof: "validator-authenticated proof unavailable"}
	_ = execution
	return mustJSON(t, result)
}

func tosctlFinalizedSponsorshipResult(t *testing.T, execution agentrelay.RelayExecutionRequest,
	payment commerce.AgreementPaymentRequest, sink *TOSCTLPaymentSink,
	frozen RelaySponsorshipEvidenceSnapshot) []byte {
	t.Helper()
	var observed tosctlRelaySponsorshipObserved
	if err := decodeStrictJSON(tosctlObservedSponsorshipResult(t, execution, payment, sink, frozen), &observed); err != nil {
		t.Fatal(err)
	}
	transactionUnix := uint64(sink.Now().Add(-20 * time.Second).Unix())
	checkpointUnix := uint64(sink.Now().Unix())
	for index := range observed.Observations {
		observed.Observations[index].TransactionUTime = transactionUnix
		observed.Observations[index].DestinationTransactionUTime = transactionUnix
		observed.Observations[index].ObservedMasterchainGenUTime = checkpointUnix
	}
	observed.Evidence = observed.Observations[0]
	observed.ObservedCheckpointUnix = checkpointUnix
	observed.ObservationDigests = observed.ObservationDigests[:0]
	for _, observation := range observed.Observations {
		digest, err := tosctlRustFramedDigest(tosctlSponsorshipObservationDomain, observation)
		if err != nil {
			t.Fatal(err)
		}
		observed.ObservationDigests = append(observed.ObservationDigests, digest)
	}
	sort.Strings(observed.ObservationDigests)

	paymentDigest, err := commerce.AgreementPaymentRequestDigest(payment)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := commerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		t.Fatal(err)
	}
	exactDigest, err := commerce.ExactRequestDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	if execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		t.Fatal("sponsorship terminal profile is missing")
	}
	finality := *execution.ProviderQuote.Body.SponsorshipTerminalProfile
	finalityCBOR, err := codec.Marshal(finality)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(frozen.SnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if err := decodeStrictJSON(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	winner := observed.Evidence
	checkpointID := "masterchain:" + checkpointSuffix(winner)
	evidence := agentrelay.RelaySponsorshipTransactionEvidence{SchemaVersion: 1,
		TerminalEvidenceClass:               agentrelay.SponsorshipTerminalClientCorroborated,
		ValidatorAuthenticatedPortableProof: false,
		NetworkDigest:                       networkDigest, AgreementPaymentRequest: payment,
		AgreementPaymentRequestDigest: paymentDigest, SponsorshipStableActionID: payment.StableActionID,
		SponsorshipExactRequestDigest: exactDigest, ProviderSponsorSourceAccount: frozen.ProviderSourceAccount,
		ProviderSponsorSourceSequence:        observed.ProviderSponsorSourceSequence,
		ProviderSponsorValidUntilUnix:        payment.ExpiresAtUnix,
		SignedTopUpTransactionDigest:         observed.SignedTopUpTransactionDigest,
		SignedTopUpTransactionCellHash:       observed.SignedTopUpTransactionCellHash,
		SponsorshipPaymentCommitmentCellHash: observed.SponsorshipPaymentCommitmentCellHash,
		DestinationSourceAccount:             string(payment.Destination), Amount: *execution.ProviderQuote.Body.ReservedSponsorship,
		SubmittedTransactionHash: winner.TransactionHash, SourceExecutionReference: winner.TransactionHash,
		DestinationCreditReferences: []string{winner.DestinationCreditReference},
		FinalizedCheckpointID:       checkpointID, FinalizedCheckpointSequence: uint64(winner.ObservedMasterchainSeqno),
		FinalizedCheckpointUnix: winner.ObservedMasterchainGenUTime, ConfirmationDepth: 1,
		SponsorshipTerminalProfileDigest: finality.ProfileDigest,
		ObservationDigests:               append([]string(nil), observed.ObservationDigests...),
		ObservedAtUnix:                   uint64(sink.Now().Unix())}
	proof := tosctlRelaySponsorshipProofBundle{Schema: tosctlRelaySponsorshipProofSchema,
		AgreementPaymentRequest: payment, AgreementPaymentRequestDigest: paymentDigest,
		SponsorshipStableActionID: payment.StableActionID, SponsorshipExactRequestDigest: exactDigest,
		ProviderSponsorSourceAccount:         frozen.ProviderSourceAccount,
		ProviderSponsorSourceSequence:        observed.ProviderSponsorSourceSequence,
		ProviderSponsorValidUntilUnix:        payment.ExpiresAtUnix,
		DestinationSourceAccount:             string(payment.Destination),
		SignedTopUpTransactionBOC:            []byte("signed top-up fixture BOC"),
		SignedTopUpTransactionCellHash:       observed.SignedTopUpTransactionCellHash,
		SponsorshipPaymentCommitmentCellHash: observed.SponsorshipPaymentCommitmentCellHash,
		NetworkDigest:                        networkDigest, NetworkDomain: execution.QuoteRequest.Body.Network,
		FinalityProfile: finality, FinalityProfileCBORDigest: sha256Digest(finalityCBOR),
		SponsorshipReleaseProfileURI:    manifest.EvidenceProfileURI,
		SponsorshipReleaseProfileDigest: manifest.EvidenceProfileDigest,
		SponsorshipReleaseProfile:       manifest.EvidenceProfile,
		CorroborationSnapshotIdentity:   frozen.SnapshotIdentity, ConfirmationDepth: 1,
		TerminalEvidenceClass:               agentrelay.SponsorshipTerminalClientCorroborated,
		ValidatorAuthenticatedPortableProof: false,
		Quorum:                              observed.Quorum, ObservationDigests: append([]string(nil), observed.ObservationDigests...),
		Observations: append([]tosctlPaymentObservation(nil), observed.Observations...),
		Failures:     append([]string(nil), observed.Failures...), FinalizedCheckpointID: checkpointID,
		FinalizedCheckpointSequence: uint64(winner.ObservedMasterchainSeqno),
		FinalizedCheckpointUnix:     winner.ObservedMasterchainGenUTime}
	proof.SignedTopUpTransactionDigest = sha256Digest(proof.SignedTopUpTransactionBOC)
	evidence.SignedTopUpTransactionDigest = proof.SignedTopUpTransactionDigest
	proofCBOR, err := codec.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(proofCBOR)
	if err != nil {
		t.Fatal(err)
	}
	evidence.ProofBundle, evidence.ProofBundleDigest = proofCBOR, proofDigest
	operators := make([]string, 0, len(observed.Observations))
	for _, observation := range observed.Observations {
		operators = append(operators, observation.OperatorProvenance)
	}
	sort.Strings(operators)
	return mustJSON(t, tosctlRelaySponsorshipFinality{Schema: tosctlRelaySponsorshipFinalitySchema,
		StableActionID: payment.StableActionID, AgreementPaymentRequestDigest: paymentDigest,
		SponsorshipExactRequestDigest: exactDigest, NetworkDomain: execution.QuoteRequest.Body.Network,
		NetworkDigest: networkDigest, FinalityProfileURI: finality.ProfileURI,
		FinalityProfileDigest: finality.ProfileDigest, FinalityProfile: finality,
		FinalityProfileCBORDigest:       sha256Digest(finalityCBOR),
		SponsorshipReleaseProfileURI:    manifest.EvidenceProfileURI,
		SponsorshipReleaseProfileDigest: manifest.EvidenceProfileDigest,
		SponsorshipReleaseProfile:       manifest.EvidenceProfile,
		CorroborationSnapshot:           frozen.SnapshotPath, CorroborationSnapshotIdentity: frozen.SnapshotIdentity,
		ProviderSnapshotIdentity: frozen.SnapshotIdentity,
		OperatorProvenance:       operators, ProofBundleDigestAlgorithm: tosctlRelaySponsorshipDigestMethod,
		ProofBundleDigestDomain: tosctlRelaySponsorshipProofDomain, ProofBundleDigest: proofDigest,
		ProofBundle: mustJSON(t, proof), ProofBundleCBOR: proofCBOR, Quorum: observed.Quorum,
		Evidence: winner, Observations: observed.Observations, Failures: observed.Failures,
		SponsorshipTransactionEvidence: evidence, ObservedAtUnix: uint64(sink.Now().Unix()),
		SponsorshipPaymentCommitmentCellHash: observed.SponsorshipPaymentCommitmentCellHash,
		State:                                "corroborated_terminal", CustodyState: "resolved", ChainSideEffect: false,
		CustodySideEffect: true, TerminalEvidenceClass: agentrelay.SponsorshipTerminalClientCorroborated,
		AssuranceScope:                      tosctlRelaySponsorshipAssuranceScope,
		ValidatorAuthenticatedPortableProof: false})
}

func tosctlVerifiedSponsorshipProofResult(t *testing.T,
	evidence agentrelay.RelaySponsorshipTransactionEvidence, finality agentrelay.FinalityProfile,
	frozen RelaySponsorshipEvidenceSnapshot, sink *TOSCTLPaymentSink) []byte {
	t.Helper()
	var proof tosctlRelaySponsorshipProofBundle
	if err := codec.Unmarshal(evidence.ProofBundle, &proof); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(frozen.SnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest tosctlRelaySponsorshipSnapshotManifest
	if err := decodeStrictJSON(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	observations := append([]tosctlPaymentObservation(nil), proof.Observations...)
	digests := make([]string, 0, len(observations))
	for _, observation := range observations {
		digest, digestErr := tosctlRustFramedDigest(tosctlSponsorshipObservationDomain, observation)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	operators := make([]string, 0, len(observations))
	for _, observation := range observations {
		operators = append(operators, observation.OperatorProvenance)
	}
	sort.Strings(operators)
	finalityCBOR, err := codec.Marshal(finality)
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON(t, tosctlRelaySponsorshipProofVerification{
		Schema:                        tosctlRelaySponsorshipProofVerificationSchema,
		ProofBundleDigestAlgorithm:    tosctlRelaySponsorshipDigestMethod,
		ProofBundleDigestDomain:       tosctlRelaySponsorshipProofDomain,
		ProofBundleDigest:             evidence.ProofBundleDigest,
		AgreementPaymentRequestDigest: evidence.AgreementPaymentRequestDigest,
		SponsorshipStableActionID:     evidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: evidence.SponsorshipExactRequestDigest,
		NetworkDigest:                 evidence.NetworkDigest, FinalityProfileDigest: finality.ProfileDigest,
		FinalityProfileCBORDigest:            sha256Digest(finalityCBOR),
		SponsorshipReleaseProfileURI:         manifest.EvidenceProfileURI,
		SponsorshipReleaseProfileDigest:      manifest.EvidenceProfileDigest,
		ProviderSnapshotIdentity:             proof.CorroborationSnapshotIdentity,
		ClientSnapshotIdentity:               frozen.SnapshotIdentity,
		ProviderSponsorSourceAccount:         evidence.ProviderSponsorSourceAccount,
		ProviderSponsorControllerEpoch:       1,
		ProviderSponsorSourceSequence:        evidence.ProviderSponsorSourceSequence,
		ProviderSponsorValidUntilUnix:        evidence.ProviderSponsorValidUntilUnix,
		SignedTopUpTransactionDigest:         evidence.SignedTopUpTransactionDigest,
		SignedTopUpTransactionCellHash:       evidence.SignedTopUpTransactionCellHash,
		SponsorshipPaymentCommitmentCellHash: evidence.SponsorshipPaymentCommitmentCellHash,
		DestinationSourceAccount:             evidence.DestinationSourceAccount, AmountAtomic: evidence.Amount.AmountAtomic,
		ConfirmationDepth:     evidence.ConfirmationDepth,
		TerminalEvidenceClass: agentrelay.SponsorshipTerminalClientCorroborated,
		OperatorProvenance:    operators,
		Quorum: tosctlQuorum{Members: uint32(len(observations)), Threshold: manifest.EvidenceProfile.Threshold,
			Agreeing: uint32(len(observations))},
		ObservationDigests: digests, Evidence: observations[0], Observations: observations, Failures: []string{},
		VerifiedAtUnix: uint64(sink.Now().Unix()), State: "corroborated_terminal_verified",
		AssuranceScope:                      tosctlRelaySponsorshipClientAssuranceScope,
		ValidatorAuthenticatedPortableProof: false, ChainSideEffect: false, CustodySideEffect: false})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
