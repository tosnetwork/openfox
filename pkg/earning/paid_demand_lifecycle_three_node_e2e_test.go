package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	"github.com/tosnetwork/tos-messenger/pkg/economicaction"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	threeNodeBuyerAccount    = "0:56ec4f04ad66184f4fecef3776a219745ac5d9acd3288129d28aa9e4c47e5670"
	threeNodeProviderAccount = "0:6947f92e3d5605e2e6bfbbd307a70918945bb2836237455aec1644aa3f23ae0c"
	threeNodeAssetMaster     = "0:9592a7f9df238f96d08cc3485047e080b3e2c9f7d96e5db662269dc95271033c"
	threeNodeAssetMasterCode = "tvm-cell-sha256:18d5b6e780ff0bb451254c2c760d09d6e485638cd1407abb97078752c3c1c9ee"
	threeNodeAssetWalletCode = "tvm-cell-sha256:8f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68"
	threeNodeRegistryCode    = "tvm-cell-sha256:600f2fda83462bc86a1c32af930c35a4fc8f80f1d2966f5593ceba217a91ffa0"
)

type lifecycleBridgeSink struct {
	store   *economicaction.Store
	deliver func(OutboundMessage) error
}

func (sink *lifecycleBridgeSink) Submit(_ context.Context, action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, exactRequest []byte, message OutboundMessage) (commerce.ActionResolution, error) {
	if sink == nil || sink.store == nil {
		return commerce.ActionResolution{}, errors.New("Messenger economic boundary is unavailable")
	}
	resolution, err := sink.store.Admit(action, fence, fields, exactRequest, time.Now().UTC())
	if err != nil || resolution.State != commerce.ActionPrepared {
		return resolution, err
	}
	resolution, err = sink.store.Submit(action.StableActionID, action.ExactRequestDigest)
	if err != nil {
		return resolution, err
	}
	if sink.deliver != nil {
		if err := sink.deliver(message); err != nil {
			return commerce.ActionResolution{}, err
		}
	}
	return sink.store.Accept(action.StableActionID, action.ExactRequestDigest,
		"three-node:event:"+strings.TrimPrefix(action.StableActionID, "sha256:"))
}

func (sink *lifecycleBridgeSink) ResolveAction(_ context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	if sink == nil || sink.store == nil {
		return commerce.ActionResolution{}, errors.New("Messenger economic boundary is unavailable")
	}
	return sink.store.Resolve(actionID, requestDigest)
}

type lifecycleNativeFixtureEvidence struct {
	ProviderAgentID  string `json:"provider_agent_id"`
	CapabilityID     string `json:"capability_id"`
	RegistryCodeHash string `json:"registry_code_hash"`
	TaskVersion      string `json:"task_version"`
	TaskManifest     string `json:"task_manifest_digest"`
}

type lifecycleContactDraft struct{}

func (lifecycleContactDraft) DraftContact(context.Context, CandidateAssessment) ([]byte, time.Duration, error) {
	return []byte("I can buy this exact bounded security review under the advertised Paid Demand terms."), 2 * time.Hour, nil
}

// TestPaidDemandAutonomousLifecycleThreeNode is the executable acceptance
// campaign for the complete OpenFox A -> OpenFox B lifecycle. It is opt-in
// because it deploys and funds a fresh escrow on the caller's three-node TOS
// network. Provider Agent/Capability authorization, escrow, buyer acceptance,
// stablecoin funding, release, exact wallet credit, and every finality
// observation use the three independent nodes.
func TestPaidDemandAutonomousLifecycleThreeNode(t *testing.T) {
	if os.Getenv("OPENFOX_PAID_DEMAND_LIFECYCLE_THREE_NODE_E2E") != "1" {
		t.Skip("set OPENFOX_PAID_DEMAND_LIFECYCLE_THREE_NODE_E2E=1 for the live lifecycle campaign")
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tosRepository := mustEnv(t, "OPENFOX_TOS_REPO")
	network := &nativev1.NetworkDomain{NetworkId: "tos:local-three-node",
		GenesisRootHash: "sha256:c1219a54e2535252bd31275b962f70e605b5f22f6cd09b615f203082a5eb1308",
		GenesisFileHash: "sha256:22b2a7bcc471c3da0ddaea29ff9df2611ff6081198969989703e728ff98fa130"}
	custodyNetwork := &commerce.CustodyNetworkDomain{NetworkID: network.NetworkId, GlobalID: 3,
		ZeroStateRootHash: network.GenesisRootHash, ZeroStateFileHash: network.GenesisFileHash, WorkchainID: 0}
	endpoints := []string{mustEnv(t, "OPENFOX_TOS_RPC_1"), mustEnv(t, "OPENFOX_TOS_RPC_2"), mustEnv(t, "OPENFOX_TOS_RPC_3")}
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId, Endpoints: endpoints, Quorum: 3})
	if err != nil {
		t.Fatal(err)
	}
	escrowCode := lifecycleCell(t, filepath.Join(tosRepository, "crypto/smartcont/tos-service-stablecoin-escrow-v2.boc.base64"))
	walletCode := lifecycleCell(t, filepath.Join(tosRepository, "crypto/smartcont/test-usdt-wallet-code.boc.base64"))
	if got := "tvm-cell-sha256:" + hex.EncodeToString(walletCode.Hash()); got != threeNodeAssetWalletCode {
		t.Fatalf("stablecoin wallet code hash=%s", got)
	}
	checkpoint := privateTempDir(t)
	escrowResolver, err := toschain.NewEscrowResolver(chain, network,
		"tvm-cell-sha256:"+hex.EncodeToString(escrowCode.Hash()), filepath.Join(checkpoint, "escrow.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	assetResolver, err := toschain.NewStablecoinResolver(chain, network, filepath.Join(checkpoint, "asset.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	registryCodeRaw, err := os.ReadFile(filepath.Join(tosRepository, "crypto/smartcont/tos-service-native-registry-v1.boc.base64"))
	if err != nil {
		t.Fatal(err)
	}
	locator, err := nativecore.NewLocator(network, 0, strings.TrimSpace(string(registryCodeRaw)), threeNodeRegistryCode)
	if err != nil {
		t.Fatal(err)
	}
	nativeResolver, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(checkpoint, "native.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	nativeClient, err := toschain.NewDirectNativeClient(nativeResolver)
	if err != nil {
		t.Fatal(err)
	}
	nativeFixture := lifecycleConfigureNativeFixture(t, "", "", filepath.Join(checkpoint, "native-base.json"))
	if nativeFixture.RegistryCodeHash != threeNodeRegistryCode {
		t.Fatalf("Native fixture registry hash=%s", nativeFixture.RegistryCodeHash)
	}

	providerID := nativeFixture.ProviderAgentID
	buyerID := "agent_" + strings.TrimPrefix(threeNodeDigest("lifecycle-buyer"), "sha256:")
	capabilityID := nativeFixture.CapabilityID
	capabilityVersion := fmt.Sprintf("job-%x", now.UnixNano())
	providerAuthorityKey := lifecycleKey("provider-economic-authority")
	buyerAuthorityKey := lifecycleKey("tos.openfox.three-node-payment-authority.v1")
	provider, err := OpenPersonalAuthority(privateTempDir(t), "owner:provider", providerID,
		"authority:provider", providerAuthorityKey, PortfolioLimits{ComputeUnits: 100, ReceivableAtomic: 1_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	buyer, err := OpenPersonalAuthority(privateTempDir(t), "owner:buyer", buyerID,
		"authority:openfox-three-node-e2e", buyerAuthorityKey,
		PortfolioLimits{SpendAtomic: 1_000_000_000, LockedCapitalAtomic: 1_000_000_000, MaximumLossAtomic: 1_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	defer buyer.Close()
	providerFence, err := provider.AcquireWriter(ctx, "provider-runtime", []string{"provider.offer", "portfolio.reserve",
		"execution.prepare", "execution.start", "delivery.release", "billing.materialize", "billing.resolve", "escrow.transition"}, 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	buyerFence, err := buyer.AcquireWriter(ctx, "buyer-runtime", []string{"messenger.contact", "portfolio.reserve",
		"agreement.authorize", "escrow.transition"}, 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	providerEngine := &Engine{OwnerID: "owner:provider", AgentID: providerID, MandateDigest: threeNodeDigest("provider-mandate"),
		Gates: FeatureGates{Agreement: true, Execution: true, TOSEscrow: true}, Authority: provider}
	buyerEngine := &Engine{OwnerID: "owner:buyer", AgentID: buyerID, MandateDigest: threeNodeDigest("buyer-mandate"),
		Gates: FeatureGates{Contact: true, Agreement: true, TOSEscrow: true}, Authority: buyer}

	executionKey := lifecycleKey("provider-execution")
	public := paiddemand.PublicTermsV1{SchemaVersion: 1, ProviderWallet: threeNodeProviderAccount,
		AssetMasterAddress: threeNodeAssetMaster, AssetMasterCodeHash: threeNodeAssetMasterCode,
		AssetWalletCodeHash: threeNodeAssetWalletCode, AssetDecimals: 6, CapabilityID: capabilityID,
		CapabilityVersion: capabilityVersion, ExecutionSignerEd25519: executionKey.Public().(ed25519.PublicKey),
		TransportBinding: nativecore.TransportBindingV1{SecurityMode: nativecore.TransportLoopbackHTTP,
			MaxRequestBytes: 1 << 20, BaseURL: "http://127.0.0.1:8080"},
		ExecutionProfileURI: paiddemand.ExecutionManifestProfileV1, FundingWindowSeconds: 600,
		ExecutionWindowSeconds: 1800, RefundDelaySeconds: 600}
	publicCanonical, err := paiddemand.CanonicalPublicTerms(public)
	if err != nil {
		t.Fatal(err)
	}
	providerIdentityKey := lifecycleKey("provider-intent")
	intent := lifecycleSupplyIntent(t, network.NetworkId, providerID, publicCanonical, now, providerIdentityKey)
	intentDigest, _ := commerce.IntentBodyDigest(intent.Body)
	store, err := OpenPaidDemandNegotiationStore(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	compiler := PaidDemandSupplyAgreementCompiler{Network: network, BuyerWallet: threeNodeBuyerAccount, Store: store}
	application := commerce.IntentApplication{SchemaVersion: 1, IntentDigest: intentDigest,
		IntentIssuerAgentID: providerID, ApplicantAgentID: buyerID,
		Message:          "Buy one bounded review for 5000000 atomic units.",
		SettlementOffers: []commerce.SettlementPreference{{AdapterURI: paiddemand.SettlementAdapterURI, Parameters: publicCanonical}},
		ProposedAmount: &commerce.AgreementAmount{AssetNamespace: "tos.contract", AssetIdentifier: threeNodeAssetMaster,
			AmountAtomic: "5000000", Unit: "atomic"}, ExpiresAtUnix: uint64(now.Add(75 * time.Minute).Unix())}
	candidate := CandidateAssessment{IntentDigest: intentDigest, Intent: intent, CarrierIDs: []string{"carrier:a", "carrier:b"},
		Decision: EconomicDecision{Eligible: true, ExpectedRevenueAtomic: "5000000"}, Inventory: lifecycleInventory("owner:buyer", buyerID, now)}
	body, packageCanonical, err := compiler.CompileSupplyAgreement(ctx, buyerID, candidate, application,
		now.Add(75*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(body)
	if _, err := buyer.RecordAgreementProposal(body, buyerID, "event:buyer-proposal", threeNodeDigest("buyer-proposal")); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.RecordAgreementProposal(body, buyerID, "event:provider-inbox", threeNodeDigest("provider-inbox")); err != nil {
		t.Fatal(err)
	}
	packageValue, err := paiddemand.DecodeCanonicalNegotiationPackage(packageCanonical)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := paiddemand.ValidateNegotiationPackageOnNetwork(body, public, packageValue, network, now)
	if err != nil {
		t.Fatal(err)
	}
	updatedNativeFixture := lifecycleConfigureNativeFixture(t, capabilityVersion, proposal.ManifestDigest,
		filepath.Join(checkpoint, "native-task-version.json"))
	if updatedNativeFixture.ProviderAgentID != providerID || updatedNativeFixture.CapabilityID != capabilityID ||
		updatedNativeFixture.TaskVersion != capabilityVersion || updatedNativeFixture.TaskManifest != proposal.ManifestDigest {
		t.Fatal("Native task Capability version differs from the Agreement execution manifest")
	}
	lifecycleWaitNativeVersion(t, ctx, nativeResolver, providerID, capabilityID, capabilityVersion, proposal.ManifestDigest)
	providerOfferKey := lifecycleKey("provider-offer")
	offerPolicy := ProviderOfferAuthorityPolicy{AgentID: providerID, PublicKey: providerOfferKey.Public().(ed25519.PublicKey),
		AgentGeneration: 1, ControllerPolicyDigest: threeNodeDigest("provider-controller"), DelegationDigest: threeNodeDigest("provider-delegation"),
		ScopeBoundsDigest: threeNodeDigest("provider-offer-scope"), OwnerMandateDigest: providerEngine.MandateDigest,
		IssuanceAuthorityReferenceDigest: threeNodeDigest("provider-offer-authority")}
	offerAuthorities := PinnedProviderOfferAuthorities{Policies: map[string]ProviderOfferAuthorityPolicy{providerID: offerPolicy}}
	escrowEvidence := paiddemand.QuorumBuyerAcceptVerifier{Resolver: escrowResolver, Network: network,
		ProviderOffers: offerAuthorities, Timeout: 30 * time.Second}
	paidEvidence := commerce.PaidDemandQuoteEvidenceVerifier{Native: paiddemand.NativeEvidenceVerifier{
		ProviderOffers: offerAuthorities, BuyerAccepts: escrowEvidence}}
	evidenceRouter := AgreementEvidenceRouter{Profiles: map[string]ExternalAgreementEvidenceVerifier{
		commerce.EvidenceProfilePaidDemandQuote: paidEvidence}}

	providerMessengerStore, err := economicaction.Open(privateTempDir(t), map[string]ed25519.PublicKey{
		"authority:provider": providerAuthorityKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	providerSink := &lifecycleBridgeSink{store: providerMessengerStore}
	providerEngine.Sink = providerSink
	providerSink.deliver = func(message OutboundMessage) error {
		if message.Kind != "agreement.provider-offer" {
			return nil
		}
		var offer commerce.SignedProviderOffer
		if codec.Unmarshal(message.Payload, &offer) != nil {
			return errors.New("bridge received invalid Provider Offer")
		}
		subject := commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: providerID}
		digest, _ := commerce.ProviderOfferDigest(offer)
		evidence, buildErr := commerce.PaidDemandEvidenceFromBinding(body, subject, offer.Binding,
			"provider_offer", message.Payload, uint64(time.Now().Unix()), digest)
		if buildErr != nil {
			return buildErr
		}
		_, buildErr = buyer.RecordAgreementEvidence(agreementDigest, evidence, evidenceRouter)
		return buildErr
	}
	providerService := PaidDemandProviderService{Engine: providerEngine,
		Signer:        PolicyProviderOfferSigner{Policy: offerPolicy, Key: providerOfferKey, TTL: 2 * time.Hour},
		OfferResolver: offerAuthorities, Evidence: evidenceRouter, PolicyRevision: 1}
	reservation := ExposureReservation{ReservationID: "reservation:" + agreementDigest[7:], AgreementDigest: agreementDigest,
		ComputeUnits: 1, ReceivableAtomic: 5_000_000}
	if _, _, err := providerEngine.ReserveAgreement(ctx, agreementDigest, reservation, allowSettlement{}, 1, providerFence); err != nil {
		t.Fatal(err)
	}
	offer, _, _, err := providerService.IssueOffer(ctx, packageValue.Binding, buyerID, providerFence)
	if err != nil {
		t.Fatal(err)
	}

	configPath := mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG")
	executable := mustEnv(t, "OPENFOX_TOSCTL")
	vaultURL := mustEnv(t, "VAULT_URL")
	buyerCustodyDirectory := filepath.Join(checkpoint, "buyer-custody")
	providerCustodyDirectory := filepath.Join(checkpoint, "provider-custody")
	lifecycleBindAgentWallet(t, executable, configPath, vaultURL, "payer-agent", "buyer-runtime",
		"authority:openfox-three-node-e2e", buyerAuthorityKey, buyerCustodyDirectory)
	lifecycleBindAgentWallet(t, executable, configPath, vaultURL, "provider-agent", "provider-runtime",
		"authority:provider", providerAuthorityKey, providerCustodyDirectory)
	deployer, err := buyersdk.NewTOSCTLPaidDemandEscrowDeployer(buyersdk.TOSCTLPaidDemandEscrowDeployerConfig{
		BinaryPath: executable, ConfigPath: configPath, WalletName: "operator-funder",
		RelayerAddress:  "0:3a1b3f9b233abda0afc5657f53bc6bea9d577f622d294805017d3e226560ebc1",
		AttachedNanoTOS: 200_000_000, Timeout: 15 * time.Second, VaultURL: vaultURL})
	if err != nil {
		t.Fatal(err)
	}
	buyerSender, err := buyersdk.NewTOSCTLWalletActionSender(buyersdk.TOSCTLWalletActionSenderConfig{
		BinaryPath: executable, ConfigPath: configPath, WalletName: "payer-agent", FeeReserveNanoTOS: 50_000_000,
		VaultURL: vaultURL, JournalDirectory: buyerCustodyDirectory})
	if err != nil {
		t.Fatal(err)
	}
	providerSender, err := buyersdk.NewTOSCTLWalletActionSender(buyersdk.TOSCTLWalletActionSenderConfig{
		BinaryPath: executable, ConfigPath: configPath, WalletName: "provider-agent", FeeReserveNanoTOS: 50_000_000,
		VaultURL: vaultURL, JournalDirectory: providerCustodyDirectory})
	if err != nil {
		t.Fatal(err)
	}
	paidBuyer, err := buyersdk.NewPaidDemandBuyer(buyersdk.PaidDemandBuyerConfig{NativeClient: nativeClient,
		AssetResolver: assetResolver, Network: network, RegistryCodeHash: threeNodeRegistryCode,
		BuyerAddress: threeNodeBuyerAccount, AssetWalletCode: walletCode,
		BudgetLimits:   buyersdk.BudgetLimits{Window: time.Hour, MaxPurchases: 2, MaxPerPurchaseAtomic: "10000000", MaxTotalAtomic: "20000000"},
		EscrowResolver: escrowResolver, ProviderOfferResolver: offerAuthorities, EscrowCode: escrowCode, Deployer: deployer,
		ActionSender: buyerSender, EffectAuthorizer: PaidDemandCustodyAuthorizer{Engine: buyerEngine, Fence: buyerFence,
			PolicyRevision: 1, NetworkDomain: custodyNetwork},
		OwnerID: buyerEngine.OwnerID, AgentID: buyerID, CallerID: buyerID, NetworkGlobalID: 3, ActionNanoTOS: 100_000_000,
		PollInterval: time.Second, FinalityTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	purchase, err := paidBuyer.PreparePurchase(ctx, buyersdk.PaidDemandPurchaseInput{Agreement: body, ProviderOffer: offer,
		Proposal: proposal, ManifestCanonical: packageValue.ManifestCanonical, EscrowTerms: packageValue.EscrowTerms,
		ExecutionSignerEd25519: packageValue.ExecutionSignerEd25519, TransportBinding: packageValue.TransportBinding,
		ExecutionDeadlineUnix: packageValue.ExecutionDeadlineUnix})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prepared agreement=%s escrow=%s", agreementDigest, purchase.Escrow.Address)
	deployed, err := paidBuyer.Deploy(ctx, purchase)
	if err != nil || deployed == nil || deployed.State == nil || deployed.State.Status != nativecore.EscrowStatusPendingAcceptanceV2 {
		t.Fatalf("escrow deployment state=%+v err=%v", deployed, err)
	}
	t.Logf("deployed checkpoint=%d tx=%s", deployed.Reference.FinalizedCheckpoint, deployed.Reference.TransactionHash)
	buyerMessengerStore, err := economicaction.Open(privateTempDir(t), map[string]ed25519.PublicKey{
		"authority:openfox-three-node-e2e": buyerAuthorityKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	buyerSink := &lifecycleBridgeSink{store: buyerMessengerStore}
	buyerEngine.Sink = buyerSink
	buyerSink.deliver = func(message OutboundMessage) error {
		if message.Kind != "agreement.evidence" {
			return nil
		}
		var evidence commerce.AgreementAuthorizationEvidence
		if codec.Unmarshal(message.Payload, &evidence) != nil {
			return errors.New("bridge received invalid buyer evidence")
		}
		_, recordErr := provider.RecordAgreementEvidence(agreementDigest, evidence, evidenceRouter)
		return recordErr
	}
	if _, _, err := buyerEngine.ReserveAgreement(ctx, agreementDigest,
		ExposureReservation{ReservationID: reservation.ReservationID, AgreementDigest: agreementDigest,
			SpendAtomic: 5_000_000, LockedCapitalAtomic: 5_000_000, MaximumLossAtomic: 5_000_000},
		allowSettlement{}, 1, buyerFence); err != nil {
		t.Fatal(err)
	}
	funded, buyerRecord, err := (PaidDemandBuyerService{Engine: buyerEngine, Runtime: paidBuyer,
		Verifier: evidenceRouter, PolicyRevision: 1}).AcceptAndFund(ctx, purchase, providerID, buyerFence)
	if err != nil || funded == nil || funded.State == nil || funded.State.Status != nativecore.EscrowStatusFundedV2 || buyerRecord.State != EngagementReady {
		status := uint8(255)
		if funded != nil && funded.State != nil {
			status = funded.State.Status
		}
		t.Fatalf("buyer accept/fund state=%v record=%s err=%v", status, buyerRecord.State, err)
	}

	providerRecord, found := provider.Engagement(agreementDigest)
	if !found || providerRecord.State != EngagementReserved && providerRecord.State != EngagementReady ||
		len(providerRecord.Agreement.AuthorizationEvidence) != 2 {
		authorizationErr := commerce.ValidateAgreementAuthorization(providerRecord.Agreement, evidenceRouter, time.Now().UTC())
		t.Fatalf("provider buyer-evidence state=%s evidence=%d found=%v authorization_error=%v", providerRecord.State,
			len(providerRecord.Agreement.AuthorizationEvidence), found, authorizationErr)
	}
	planner := BoundedEngagementPlanner{OwnerID: providerEngine.OwnerID, AgentID: providerID, ComputeUnitsPerExecution: 1}
	planned, err := planner.PlanEngagement(ctx, providerRecord, lifecycleInventory(providerEngine.OwnerID, providerID, time.Now()), providerFence)
	if err != nil {
		t.Fatal(err)
	}
	localGate, err := commercegate.Open(privateTempDir(t), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer localGate.Close()
	nativeGate := PaidDemandNativeGate{Directory: privateTempDir(t), Store: store, PublicTerms: public, Network: network,
		EscrowResolver: escrowResolver, NativeResolver: nativeResolver, RegistryCodeHash: threeNodeRegistryCode,
		EscrowCode: escrowCode, AssetWalletCode: walletCode, OfferAuthorities: offerAuthorities}
	prerequisite := AdapterPrerequisitePolicy{LocalAgentID: providerID, PrepaidAdapters: []string{paiddemand.SettlementAdapterURI},
		Funding: PaidDemandFundingPrerequisite{Resolver: escrowResolver, Network: network, ProviderOffers: offerAuthorities}}
	outcomeDigest := threeNodeDigest("completed-security-review:" + agreementDigest)
	executed, err := (ExecutionService{Engine: providerEngine, Gate: localGate, Prerequisite: prerequisite,
		Native: nativeGate, Runner: successRunner{digest: outcomeDigest}}).Execute(ctx, agreementDigest, planned.ExecutionPlan, 1, providerFence)
	if err != nil || executed.State != EngagementExecutionSucceeded {
		t.Fatalf("provider execution state=%s err=%v", executed.State, err)
	}
	delivered, err := providerEngine.Deliver(ctx, agreementDigest, planned.ExecutionObligationID, buyerID,
		outcomeDigest, acceptedDelivery{}, 1, providerFence)
	if err != nil || delivered.State != EngagementDelivered {
		t.Fatalf("delivery state=%s err=%v", delivered.State, err)
	}
	created, settling, err := (BillingService{Engine: providerEngine}).MaterializeAfterDelivery(agreementDigest, 1, providerFence)
	if err != nil || len(created) != 1 || settling.State != EngagementSettling {
		t.Fatalf("billing created=%d state=%s err=%v", len(created), settling.State, err)
	}
	settlement := PaidDemandProviderSettlement{Engine: providerEngine, Store: store, Network: network, PublicTerms: public,
		EscrowResolver: escrowResolver, AssetResolver: assetResolver, OfferAuthorities: offerAuthorities,
		EscrowCode: escrowCode, AssetWalletCode: walletCode, ExecutionKey: executionKey, ActionSender: providerSender,
		Authorizer: PaidDemandCustodyAuthorizer{Engine: providerEngine, Fence: providerFence,
			PolicyRevision: 1, NetworkDomain: custodyNetwork},
		NetworkGlobalID: 3, ActionNanoTOS: 100_000_000, PollInterval: time.Second, FinalityTimeout: 2 * time.Minute}
	settled, err := settlement.ResolveReceivable(ctx, settling, 1, providerFence)
	if err != nil || !settled {
		t.Fatalf("provider release/credit: settled=%v err=%v", settled, err)
	}
	terminal, found := provider.Engagement(agreementDigest)
	if !found || terminal.State != EngagementSettled {
		t.Fatalf("terminal provider engagement=%+v", terminal)
	}
	resolved, found, err := escrowResolver.ResolveFinalizedV2(ctx, purchase.Escrow.Address)
	if err != nil || !found || resolved.State.Status != nativecore.EscrowStatusReleasePendingV2 ||
		resolved.Reference.FinalizedCheckpoint == 0 {
		t.Fatalf("terminal escrow=%+v found=%v err=%v", resolved, found, err)
	}
	t.Logf("autonomous lifecycle settled agreement=%s escrow=%s checkpoint=%d tx=%s",
		agreementDigest, purchase.Escrow.Address, resolved.Reference.FinalizedCheckpoint, resolved.Reference.TransactionHash)
}

func lifecycleSupplyIntent(t *testing.T, network, providerID string, public []byte, now time.Time,
	key ed25519.PrivateKey) commerce.SignedAgentIntent {
	t.Helper()
	detail := []byte("Perform one bounded source-code security review and return a content-addressed report.")
	detailHash := sha256.Sum256(detail)
	nonce := sha256.Sum256([]byte(now.String() + providerID))
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: network, IssuerAgentID: providerID,
		Audience: "public:indexable", ObjectID: "intent:" + hex.EncodeToString(nonce[:]), Revision: 1,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix()),
		Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: "Bounded source-code security review",
			IntentModes: []commerce.IntentMode{commerce.IntentOffer}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
			TaxonomyPaths: []string{"tos.taxonomy.v1/service/security/review"}, Keywords: []commerce.IntentKeyword{{Text: "review", Language: "en"}, {Text: "security", Language: "en"}},
			ValueState: commerce.ValueSpecified, ValueHints: []commerce.ValueHint{{Role: "price", AssetNamespace: "tos.contract",
				AssetIdentifier: threeNodeAssetMaster, AmountKind: "exact", MinimumDecimal: "5000000", MaximumDecimal: "5000000", Unit: "atomic"}},
			Schedule: commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"},
			CapabilityHints: []commerce.CapabilityHint{{CapabilityNamespace: "tos.native", CapabilityIdentifier: "security-review", Relation: "offered"}}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(detailHash[:]),
				ContentSize: uint64(len(detail)), InlineContent: detail},
			SettlementPreferences: []commerce.SettlementPreference{{AdapterURI: paiddemand.SettlementAdapterURI, Parameters: public}},
			ReplyRoutes:           []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: providerID}}}}
	signed, err := commerce.SignIntent(body, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func lifecycleInventory(owner, agent string, now time.Time) InventorySnapshot {
	return InventorySnapshot{OwnerID: owner, AgentID: agent, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1,
		PolicyRevision: 1, ConsistencyToken: "three-node:" + agent,
		Capabilities: []Capability{{Namespace: "openfox.skill", Identifier: "security-review", Version: "1",
			State: CapabilityReady, Authority: owner, EvidenceDigest: threeNodeDigest("capability:" + agent),
			RevocationGeneration: 1, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		SupportedSettlementAdapters: []string{paiddemand.SettlementAdapterURI}}
}

func lifecycleKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func lifecycleCell(t *testing.T, path string) *cell.Cell {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	value, err := cell.FromBOC(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func lifecycleBindAgentWallet(t *testing.T, executable, configPath, vaultURL, wallet, runner, authorityID string,
	key ed25519.PrivateKey, journalDirectory string) {
	t.Helper()
	if err := os.MkdirAll(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "agent", "wallet", "bind-runtime", "--name", wallet,
		"--runner-id", runner, "--endpoint", "local://openfox/earning", "--economic-authority-id", authorityID,
		"--economic-authority-public-key", hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		"--economic-custody-journal-directory", journalDirectory, "-c", configPath, "--format", "json")
	command.Env = append(os.Environ(), "VAULT_URL="+vaultURL)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bind %s runtime: %v: %s", wallet, err, output)
	}
}

func lifecycleConfigureNativeFixture(t *testing.T, version, manifestDigest, evidencePath string) lifecycleNativeFixtureEvidence {
	t.Helper()
	tosRepository := mustEnv(t, "OPENFOX_TOS_REPO")
	python := os.Getenv("OPENFOX_TOS_PYTHON")
	if python == "" {
		python = filepath.Join(tosRepository, ".venv/bin/python")
	}
	script := os.Getenv("OPENFOX_NATIVE_FIXTURE_SCRIPT")
	if script == "" {
		script = filepath.Join(tosRepository, "scripts/tos-service-paid-demand-native-fixture.py")
	}
	arguments := []string{script, "--network-id", "tos:local-three-node", "--evidence", evidencePath}
	if version != "" || manifestDigest != "" {
		arguments = append(arguments, "--add-version", "--version", version, "--manifest-digest", manifestDigest)
	}
	command := exec.Command(python, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("configure live Native Agent/Capability: %v: %s", err, output)
	}
	var evidence lifecycleNativeFixtureEvidence
	if json.Unmarshal(bytes.TrimSpace(output), &evidence) != nil || evidence.ProviderAgentID == "" ||
		evidence.CapabilityID == "" || evidence.RegistryCodeHash == "" {
		t.Fatalf("Native fixture emitted invalid evidence: %s", output)
	}
	return evidence
}

func lifecycleWaitNativeVersion(t *testing.T, ctx context.Context, resolver executiongate.NativeResolver, providerID,
	capabilityID, version, manifestDigest string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	last := "no observation"
	for time.Now().Before(deadline) {
		provider, providerFound, _, providerErr := resolver.ResolveFinalizedState(ctx, providerID, "")
		capability, capabilityFound, _, capabilityErr := resolver.ResolveFinalizedState(ctx, capabilityID, "")
		last = fmt.Sprintf("provider_error=%v capability_error=%v provider=%+v capability=%+v",
			providerErr, capabilityErr, provider, capability)
		if providerErr == nil && capabilityErr == nil && providerFound && capabilityFound && provider != nil && provider.GetAgent() != nil &&
			!provider.GetAgent().Tombstoned && capability != nil && capability.GetCapability() != nil &&
			capability.GetCapability().OwnerAgentId == providerID && !capability.GetCapability().Tombstoned {
			for _, item := range capability.GetCapability().Versions {
				if item != nil && item.Version == version && item.ManifestDigest == manifestDigest && !item.Revoked {
					return
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("three-node quorum did not resolve live Native Capability version %s: %s", version, last)
}

var _ executiongate.NativeResolver = (*toschain.SimplifiedNativeResolver)(nil)
