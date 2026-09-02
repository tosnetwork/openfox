package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const paidDemandPaymentEvidenceProfile = "tos.escrow.paid-demand.payment-evidence.v1"

type ReceivableSettlementService interface {
	ResolveReceivable(context.Context, EngagementRecord, uint64, commerce.WriterFence) (bool, error)
}

type PaidDemandEscrowPaymentEvidenceV1 struct {
	SchemaVersion         uint16 `json:"schema_version"`
	AgreementBodyDigest   string `json:"agreement_body_digest"`
	AgreementObligationID string `json:"agreement_obligation_id"`
	EscrowAddress         string `json:"escrow_address"`
	QuoteCommitment       string `json:"quote_commitment"`
	ReceiptCommitment     string `json:"receipt_commitment"`
	EscrowCheckpoint      uint64 `json:"escrow_checkpoint"`
	EscrowTransactionHash string `json:"escrow_transaction_hash"`
	EscrowWalletAddress   string `json:"escrow_wallet_address"`
	ProviderWalletAddress string `json:"provider_wallet_address"`
	ReleaseQueryID        uint64 `json:"release_query_id"`
	WalletCheckpoint      uint64 `json:"wallet_checkpoint"`
	WalletTransactionHash string `json:"wallet_transaction_hash"`
	WalletTransactionTime uint64 `json:"wallet_transaction_time"`
	ProviderBalanceAtomic string `json:"provider_balance_atomic"`
	SettledAtomicAmount   string `json:"settled_atomic_amount"`
}

type PaidDemandProviderSettlement struct {
	Engine           *Engine
	Store            *PaidDemandNegotiationStore
	Network          *nativev1.NetworkDomain
	PublicTerms      paiddemand.PublicTermsV1
	EscrowResolver   *toschain.EscrowResolver
	AssetResolver    *toschain.StablecoinResolver
	OfferAuthorities commerce.ProviderOfferKeyResolver
	EscrowCode       *cell.Cell
	AssetWalletCode  *cell.Cell
	ExecutionKey     ed25519.PrivateKey
	ActionSender     buyersdk.WalletActionSender
	Authorizer       buyersdk.CustodyEffectAuthorizer
	NetworkGlobalID  int32
	ActionNanoTOS    uint64
	PollInterval     time.Duration
	FinalityTimeout  time.Duration
}

func (service PaidDemandProviderSettlement) ResolveReceivable(ctx context.Context, record EngagementRecord,
	policyRevision uint64, fence commerce.WriterFence) (bool, error) {
	if !hasLocalPaidDemandReceivable(record, service.Engine) {
		return false, nil
	}
	if service.Store == nil || service.Network == nil || service.EscrowResolver == nil || service.AssetResolver == nil ||
		service.OfferAuthorities == nil || service.EscrowCode == nil || service.AssetWalletCode == nil ||
		len(service.ExecutionKey) != ed25519.PrivateKeySize || service.ActionSender == nil || service.Authorizer == nil ||
		service.NetworkGlobalID == 0 || service.ActionNanoTOS == 0 {
		return false, errors.New("Paid Demand Provider settlement is incomplete")
	}
	packageValue, found, err := service.Store.Get(record.AgreementDigest)
	if err != nil || !found {
		if err == nil {
			err = errors.New("Paid Demand settlement has no negotiation package")
		}
		return false, err
	}
	verificationTime := paidDemandOfferVerificationTime(record, packageValue.Binding)
	proposal, err := paiddemand.ValidateNegotiationPackageOnNetwork(record.Agreement.Body, service.PublicTerms,
		packageValue, service.Network, verificationTime)
	if err != nil {
		return false, err
	}
	offer, found, err := paidDemandProviderOffer(record, packageValue.Binding.ProviderAgentID)
	if err != nil || !found {
		if err == nil {
			err = errors.New("Paid Demand settlement has no Provider Offer")
		}
		return false, err
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(packageValue.ExecutionSignerEd25519)
	if err != nil {
		return false, err
	}
	quote, commitment, err := paiddemand.BuildAcceptedQuote(paiddemand.QuoteBuildInput{Agreement: record.Agreement.Body,
		ProviderOffer: offer, ProviderOfferResolver: service.OfferAuthorities, Network: service.Network, Proposal: proposal,
		ExecutionSignerAuthorization: "sha256:" + hex.EncodeToString(authorization.Hash()), EscrowTerms: packageValue.EscrowTerms,
		ExecutionDeadlineUnix: packageValue.ExecutionDeadlineUnix, Now: time.Unix(int64(offer.Context.ValidFromUnix), 0).UTC()})
	if err != nil {
		return false, err
	}
	escrow, err := nativecore.BuildEscrowStateInitV2(0, service.EscrowCode, nativecore.EscrowInitV2{Network: service.Network,
		AcceptedQuote: quote, Terms: packageValue.EscrowTerms, ExecutionSignerEd25519: packageValue.ExecutionSignerEd25519,
		TransportBinding: packageValue.TransportBinding, AssetMasterAddress: service.PublicTerms.AssetMasterAddress,
		AssetWalletCode: service.AssetWalletCode})
	if err != nil || escrow.QuoteCommitment != commitment {
		return false, errors.New("Paid Demand settlement could not reconstruct escrow")
	}
	work, payment, runtime, ledger, err := service.paidDemandSettlementInputs(record)
	if err != nil {
		return false, err
	}
	inputDigest, sourceDigest, err := paidDemandExecutionInputs(record.Agreement.Body, work.ObligationID)
	if err != nil {
		return false, err
	}
	resultDigest := runtime.ExecutionEvidence[0]
	evaluationDigest, _ := codec.Digest("tos.execution-result-evaluation.v1", struct {
		Agreement, Obligation, Execution, Result string
	}{record.AgreementDigest, work.ObligationID, runtime.ExecutionID, resultDigest})
	executorDigest, _ := codec.Digest("tos.execution-environment.v1", struct {
		Manifest, Capability, Version string
	}{proposal.ManifestDigest, proposal.CapabilityId, proposal.CapabilityVersion})
	isolationDigest, _ := codec.Digest("tos.execution-isolation.v1", struct {
		Agreement, Execution, Input string
	}{record.AgreementDigest, runtime.ExecutionID, inputDigest})
	receipt, receiptCommitment, err := paiddemand.BuildExecutionReceiptV1(paiddemand.ExecutionReceiptV1{
		QuoteCommitment: commitment, ExecutionID: runtime.ExecutionID, InputSetDigest: inputDigest,
		ResultDigest: resultDigest, ArtifactSetDigest: resultDigest, EvaluationDigest: evaluationDigest,
		SourceSetDigest: sourceDigest, ExecutorDigest: executorDigest, IsolationDigest: isolationDigest,
		ChargedAtomicAmount: payment.Amount.AmountAtomic, ProviderAgentID: service.Engine.AgentID,
		CompletedAtUnix: runtime.ExecutionCompletedAtUnix})
	if err != nil {
		return false, err
	}
	resolved, found, err := service.EscrowResolver.ResolveFinalizedV2(ctx, escrow.Address)
	if err != nil || !found || resolved == nil || resolved.State == nil {
		if err == nil {
			err = errors.New("Paid Demand escrow is unavailable for release")
		}
		return false, err
	}
	if resolved.State.Status == nativecore.EscrowStatusFundedV2 {
		if err := service.submitRelease(ctx, record, payment, escrow, resolved.State, quote, receipt, receiptCommitment); err != nil {
			resolved, _, _ = service.waitForRelease(ctx, escrow.Address, commitment, receiptCommitment)
			if resolved == nil {
				return false, err
			}
		}
	} else if resolved.State.Status != nativecore.EscrowStatusReleasePendingV2 || resolved.State.ReceiptCommitment != receiptCommitment {
		return false, errors.New("Paid Demand escrow is not funded or carries another settlement")
	}
	resolved, found, err = service.waitForRelease(ctx, escrow.Address, commitment, receiptCommitment)
	if err != nil || !found {
		return false, err
	}
	queryID := stableQueryID("release", resolved.State.QuoteCommitment)
	assetObservation, found, err := service.AssetResolver.ResolveExactCredit(ctx, proposal.MaximumPrice.Asset,
		escrow.Address, packageValue.Binding.ProviderWallet, queryID, payment.Amount.AmountAtomic,
		uint64(resolved.FinalizedAt.Unix()))
	if err != nil || !found || assetObservation == nil {
		if err == nil {
			err = errors.New("exact Provider stablecoin credit is not finalized")
		}
		return false, err
	}
	if resolved.FinalizedAt.Unix() <= 0 || assetObservation.FinalizedCheckpoint < resolved.Reference.FinalizedCheckpoint ||
		assetObservation.TransactionTime < uint64(resolved.FinalizedAt.Unix()) ||
		!atLeastAtomic(assetObservation.RecipientBalanceAtomic, payment.Amount.AmountAtomic) || assetObservation.TransactionHash == "" ||
		assetObservation.SourceOwnerAddress != escrow.Address || assetObservation.QueryID != queryID ||
		assetObservation.AmountAtomic != payment.Amount.AmountAtomic {
		return false, errors.New("Provider stablecoin credit is not independently finalized")
	}
	paymentRequest, err := commerce.BuildAgreementPaymentRequest(service.Engine.OwnerID, service.Engine.AgentID,
		service.Network.NetworkId, []byte(packageValue.Binding.ProviderWallet), ledger.Obligation)
	if err != nil {
		return false, err
	}
	payload := PaidDemandEscrowPaymentEvidenceV1{SchemaVersion: 1, AgreementBodyDigest: record.AgreementDigest,
		AgreementObligationID: payment.ObligationID, EscrowAddress: escrow.Address, QuoteCommitment: commitment,
		ReceiptCommitment: receiptCommitment, EscrowCheckpoint: resolved.Reference.FinalizedCheckpoint,
		EscrowTransactionHash: resolved.Reference.TransactionHash, EscrowWalletAddress: assetObservation.SourceWalletAddress,
		ProviderWalletAddress: packageValue.Binding.ProviderWallet, ReleaseQueryID: queryID,
		WalletCheckpoint: assetObservation.FinalizedCheckpoint, WalletTransactionHash: assetObservation.TransactionHash,
		WalletTransactionTime: assetObservation.TransactionTime, ProviderBalanceAtomic: assetObservation.RecipientBalanceAtomic,
		SettledAtomicAmount: resolved.State.SettledAtomicAmount}
	canonicalEvidence, err := codec.Marshal(payload)
	if err != nil {
		return false, err
	}
	requestDigest, _ := commerce.AgreementPaymentRequestDigest(paymentRequest)
	evidence := commerce.AgreementPaymentEvidence{PaymentRequestDigest: requestDigest, StableActionID: paymentRequest.StableActionID,
		ExactTransferReference: assetObservation.TransactionHash, AdapterEvidenceProfile: paidDemandPaymentEvidenceProfile,
		ResolvedState: "finalized", ResolvedAtUnix: assetObservation.TransactionTime,
		FinalityReference: resolved.Reference.TransactionHash, Evidence: canonicalEvidence}
	verifier := PaidDemandEscrowPaymentVerifier{Escrow: service.EscrowResolver, Asset: service.AssetResolver,
		Network: service.Network, Offers: service.OfferAuthorities, Agreement: record.Agreement.Body, Proposal: proposal}
	_, _, err = (BillingService{Engine: service.Engine}).ApplyPayment(paymentRequest, evidence, verifier, policyRevision, fence)
	return err == nil, err
}

func (service PaidDemandProviderSettlement) submitRelease(ctx context.Context, record EngagementRecord,
	payment commerce.AgreementObligation, escrow nativecore.EscrowIdentityV1, state *nativecore.EscrowStateV2,
	quote, receipt *cell.Cell, receiptCommitment string) error {
	queryID := stableQueryID("release", state.QuoteCommitment)
	charged, _ := new(big.Int).SetString(payment.Amount.AmountAtomic, 10)
	intent, err := nativecore.BuildEscrowSettlementIntentV1(escrow.Address, quote, receipt, charged, queryID)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(service.ExecutionKey, intent.Hash())
	body, err := nativecore.BuildEscrowReleaseBodyV1(queryID, receipt, signature)
	if err != nil {
		return err
	}
	bodyHash := "tvm-cell-sha256:" + hex.EncodeToString(body.Hash())
	expected, _ := codec.Digest("tos.escrow.expected-state.v1", struct {
		Quote  string `json:"quote"`
		Status uint8  `json:"status"`
	}{state.QuoteCommitment, nativecore.EscrowStatusFundedV2})
	quoteSemantic := "sha256:" + strings.TrimPrefix(state.QuoteCommitment, "tvm-cell-sha256:")
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.Engine.OwnerID), "agent_id": commerce.ID(service.Engine.AgentID),
		"quote_commitment": commerce.Digest32(quoteSemantic), "escrow_account_id": commerce.ID(escrow.Address),
		"transition_kind": commerce.Kind("release"), "expected_state_digest": commerce.Digest32(expected)}
	request := struct {
		SchemaVersion, ExpectedStatus                                                              uint16
		AgreementDigest, ObligationID, EscrowAddress, QuoteCommitment, ReceiptCommitment, BodyHash string
		AmountNanoTOS                                                                              uint64
	}{1, uint16(nativecore.EscrowStatusFundedV2), record.AgreementDigest, payment.ObligationID, escrow.Address,
		state.QuoteCommitment, receiptCommitment, bodyHash, service.ActionNanoTOS}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return err
	}
	expires := minUint64(state.ExecutionDeadline, uint64(service.Engine.now().UTC().Add(2*time.Minute).Unix()))
	authorization, err := service.Authorizer.AuthorizeCustodyEffect(ctx, buyersdk.CustodyEffectRequest{ActionKind: "escrow.release",
		SemanticFields: fields, CanonicalRequest: canonical, AgreementDigest: record.AgreementDigest,
		ObligationID: payment.ObligationID, SourceAccount: state.ProviderAddress, NetworkID: service.Network.NetworkId,
		NetworkGlobalID: service.NetworkGlobalID, Destination: escrow.Address, AmountNanoTOS: service.ActionNanoTOS,
		BodyHash: bodyHash, StateInitHashOrZero: zeroSHA256Digest(), ExpiresAtUnix: expires})
	if err != nil {
		return err
	}
	prepared, err := service.ActionSender.PrepareWalletAction(ctx, buyersdk.WalletActionIntent{StableActionID: authorization.StableActionID,
		NetworkID: service.Network.NetworkId, TransitionKind: authorization.ActionKind, Destination: escrow.Address,
		AmountNanoTOS: service.ActionNanoTOS, BodyBOCBase64: base64.StdEncoding.EncodeToString(body.ToBOCWithOptions(cell.BOCSerializeOptions{})),
		BodyHash: bodyHash, ValidUntilUnix: uint32(minUint64(expires, uint64(^uint32(0)))), Authorization: authorization})
	if err != nil {
		return err
	}
	if err := service.ActionSender.BroadcastWalletAction(ctx, prepared); err != nil {
		return err
	}
	if resolver, ok := service.ActionSender.(buyersdk.WalletActionResolver); ok {
		return resolver.ResolveWalletAction(ctx, prepared)
	}
	return nil
}

func (service PaidDemandProviderSettlement) waitForRelease(ctx context.Context, address, quote, receipt string) (*toschain.FinalizedEscrowV2, bool, error) {
	interval, timeout := service.PollInterval, service.FinalityTimeout
	if interval == 0 {
		interval = time.Second
	}
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	call, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		resolved, found, err := service.EscrowResolver.ResolveFinalizedV2(call, address)
		if err == nil && found && resolved != nil && resolved.State != nil && resolved.State.Status == nativecore.EscrowStatusReleasePendingV2 &&
			resolved.State.QuoteCommitment == quote && resolved.State.ReceiptCommitment == receipt && resolved.Reference != nil {
			return resolved, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-call.Done():
			timer.Stop()
			return nil, false, errors.New("Paid Demand release finality remains unresolved")
		case <-timer.C:
		}
	}
}

type PaidDemandEscrowPaymentVerifier struct {
	Escrow    *toschain.EscrowResolver
	Asset     *toschain.StablecoinResolver
	Network   *nativev1.NetworkDomain
	Offers    commerce.ProviderOfferKeyResolver
	Agreement commerce.AgentAgreementBody
	Proposal  *nativev1.QuoteProposalV1
}

func (verifier PaidDemandEscrowPaymentVerifier) VerifyPaymentEvidence(request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence, now time.Time) error {
	if evidence.AdapterEvidenceProfile != paidDemandPaymentEvidenceProfile || request.SettlementAdapterURI != paiddemand.SettlementAdapterURI ||
		verifier.Escrow == nil || verifier.Asset == nil || verifier.Network == nil || verifier.Offers == nil || verifier.Proposal == nil {
		return errors.New("unsupported Paid Demand payment evidence")
	}
	var payload PaidDemandEscrowPaymentEvidenceV1
	if codec.Unmarshal(evidence.Evidence, &payload) != nil || payload.SchemaVersion != 1 ||
		payload.AgreementBodyDigest != request.AgreementBodyDigest || payload.AgreementObligationID != request.AgreementObligationID ||
		payload.ProviderWalletAddress != string(request.Destination) || payload.SettledAtomicAmount != request.Amount.AmountAtomic ||
		payload.ReleaseQueryID == 0 || payload.EscrowWalletAddress == "" ||
		payload.WalletTransactionHash != evidence.ExactTransferReference || payload.EscrowTransactionHash != evidence.FinalityReference {
		return errors.New("Paid Demand payment evidence binding mismatch")
	}
	resolved, found, err := verifier.Escrow.ResolveFinalizedV2(context.Background(), payload.EscrowAddress)
	if err != nil || !found || resolved == nil || resolved.State == nil || resolved.Reference == nil ||
		resolved.State.Status != nativecore.EscrowStatusReleasePendingV2 || resolved.State.QuoteCommitment != payload.QuoteCommitment ||
		resolved.State.ReceiptCommitment != payload.ReceiptCommitment || resolved.State.SettledAtomicAmount != request.Amount.AmountAtomic ||
		resolved.Reference.FinalizedCheckpoint < payload.EscrowCheckpoint || resolved.Reference.TransactionHash != payload.EscrowTransactionHash ||
		resolved.FinalizedAt.Unix() <= 0 {
		return errors.New("Paid Demand escrow release is not independently finalized")
	}
	observation, found, err := verifier.Asset.ResolveExactCredit(context.Background(), verifier.Proposal.MaximumPrice.Asset,
		payload.EscrowAddress, payload.ProviderWalletAddress, payload.ReleaseQueryID, request.Amount.AmountAtomic,
		uint64(resolved.FinalizedAt.Unix()))
	if err != nil || !found || observation == nil || observation.FinalizedCheckpoint < payload.WalletCheckpoint ||
		observation.FinalizedCheckpoint < resolved.Reference.FinalizedCheckpoint ||
		observation.TransactionHash != payload.WalletTransactionHash || observation.TransactionTime != payload.WalletTransactionTime ||
		observation.SourceWalletAddress != payload.EscrowWalletAddress ||
		!atLeastAtomic(observation.RecipientBalanceAtomic, request.Amount.AmountAtomic) || payload.WalletTransactionTime > uint64(now.Unix()) {
		return errors.New("Paid Demand Provider credit is not independently finalized")
	}
	return nil
}

func (service PaidDemandProviderSettlement) paidDemandSettlementInputs(record EngagementRecord) (commerce.AgreementObligation,
	commerce.AgreementObligation, ObligationRuntimeRecord, SettlementLedgerRecord, error) {
	provider := service.Engine.AgentID
	var work, payment commerce.AgreementObligation
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount == nil && obligation.ObligorAgentID == provider {
			work = obligation
		}
		if obligation.Amount != nil && obligation.BeneficiaryAgentID == provider && obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI {
			payment = obligation
		}
	}
	runtime, found := record.ObligationRuntime[work.ObligationID]
	if work.ObligationID == "" || payment.ObligationID == "" || !found || runtime.ExecutionID == "" || len(runtime.ExecutionEvidence) != 1 ||
		runtime.ExecutionCompletedAtUnix == 0 ||
		(runtime.State != ObligationDelivered && runtime.State != ObligationExecutionSucceeded) {
		return work, payment, runtime, SettlementLedgerRecord{}, errors.New("Paid Demand work has no one exact successful delivery")
	}
	for _, ledger := range service.Engine.Authority.SettlementSnapshot(record.AgreementDigest) {
		if ledger.Obligation.AgreementObligationID == payment.ObligationID && ledger.Obligation.PayeeAgentID == provider &&
			ledger.Obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI {
			return work, payment, runtime, ledger, nil
		}
	}
	return work, payment, runtime, SettlementLedgerRecord{}, errors.New("Paid Demand billing obligation is not supplied")
}

func hasLocalPaidDemandReceivable(record EngagementRecord, engine *Engine) bool {
	if engine == nil {
		return false
	}
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount != nil && obligation.BeneficiaryAgentID == engine.AgentID && obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI {
			return true
		}
	}
	return false
}

func atLeastAtomic(value, minimum string) bool {
	left, leftOK := new(big.Int).SetString(value, 10)
	right, rightOK := new(big.Int).SetString(minimum, 10)
	return leftOK && rightOK && left.Sign() >= 0 && right.Sign() > 0 && left.Cmp(right) >= 0
}

func stableQueryID(kind, commitment string) uint64 {
	hash := sha256.Sum256([]byte(kind + "\x00" + commitment))
	value := uint64(0)
	for _, item := range hash[:8] {
		value = value<<8 | uint64(item)
	}
	if value == 0 {
		return 1
	}
	return value
}

var _ ReceivableSettlementService = PaidDemandProviderSettlement{}
var _ commerce.PaymentEvidenceVerifier = PaidDemandEscrowPaymentVerifier{}
