package earning

import (
	"context"
	"errors"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

type PaidDemandBuyerRuntime interface {
	Deploy(context.Context, *buyersdk.PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error)
	Accept(context.Context, *buyersdk.PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error)
	Fund(context.Context, *buyersdk.PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error)
	BuyerAcceptEvidence(*buyersdk.PreparedPaidDemandPurchase, *toschain.FinalizedEscrowV2) (commerce.AgreementAuthorizationEvidence, error)
}

type PaidDemandBuyerService struct {
	Engine         *Engine
	Runtime        PaidDemandBuyerRuntime
	Verifier       commerce.AgreementEvidenceVerifier
	PolicyRevision uint64
}

// AcceptAndFund executes the buyer half of the released escrow profile. It
// requires a prior Portfolio reservation and verified Provider Offer, sends
// the finalized wallet acceptance as typed Agreement evidence, and leaves an
// ambiguous funding attempt in funding_pending rather than rebroadcasting with
// a new identity.
func (service PaidDemandBuyerService) AcceptAndFund(ctx context.Context, purchase *buyersdk.PreparedPaidDemandPurchase,
	providerAgentID string, fence commerce.WriterFence) (*toschain.FinalizedEscrowV2, EngagementRecord, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Runtime == nil || service.Verifier == nil ||
		purchase == nil || providerAgentID == "" || purchase.AgreementDigest == "" ||
		!service.Engine.permits("tos-escrow", service.Engine.Gates.TOSEscrow, true) || !service.Engine.Gates.Agreement {
		return nil, EngagementRecord{}, errors.New("Paid Demand buyer service is disabled or incomplete")
	}
	record, found := service.Engine.Authority.Engagement(purchase.AgreementDigest)
	if !found || record.ReservationID == "" || !hasLiveAgreementReservation(service.Engine.Authority, record.ReservationID, record.AgreementDigest) ||
		providerAgentID != purchase.ProviderOffer.Binding.ProviderAgentID || !hasPaidDemandProfileEvidence(record, providerAgentID) ||
		(record.State != EngagementAuthorizing && record.State != EngagementReserved && record.State != EngagementFundingPending && record.State != EngagementReady) {
		return nil, EngagementRecord{}, errors.New("Paid Demand buyer has no reserved Agreement and verified Provider Offer")
	}
	if _, err := service.Runtime.Deploy(ctx, purchase); err != nil {
		return nil, record, err
	}
	accepted, err := service.Runtime.Accept(ctx, purchase)
	if err != nil {
		return nil, record, err
	}
	evidence, err := service.Runtime.BuyerAcceptEvidence(purchase, accepted)
	if err != nil {
		return nil, record, err
	}
	if _, record, err = service.Engine.SendAgreementEvidence(ctx, evidence, providerAgentID, service.Verifier,
		service.PolicyRevision, fence); err != nil {
		return nil, record, err
	}
	if record.State == EngagementReserved {
		record, err = service.Engine.Authority.transitionEngagement(record.AgreementDigest, EngagementReserved,
			EngagementFundingPending, "", nil)
		if err != nil {
			return nil, record, err
		}
	}
	if record.State == EngagementReady {
		funded, fundErr := service.Runtime.Fund(ctx, purchase)
		return funded, record, fundErr
	}
	if record.State != EngagementFundingPending {
		return nil, record, errors.New("Paid Demand Agreement did not enter funding_pending")
	}
	funded, err := service.Runtime.Fund(ctx, purchase)
	if err != nil {
		return nil, record, err
	}
	if funded == nil || funded.State == nil || funded.Reference == nil ||
		funded.Reference.FinalizedCheckpoint == 0 || funded.Reference.TransactionHash == "" {
		return nil, record, errors.New("Paid Demand funding returned no finalized evidence")
	}
	evidenceDigest, err := codec.Digest("tos.paid-demand-finalized-funding.v1", struct {
		AgreementDigest string `json:"agreement_digest"`
		EscrowAddress   string `json:"escrow_address"`
		QuoteCommitment string `json:"quote_commitment"`
		Checkpoint      uint64 `json:"checkpoint"`
		TransactionHash string `json:"transaction_hash"`
		FundedAtomic    string `json:"funded_atomic"`
	}{purchase.AgreementDigest, purchase.Escrow.Address, purchase.QuoteCommitment,
		funded.Reference.FinalizedCheckpoint, funded.Reference.TransactionHash, funded.State.FundedAtomicAmount})
	if err != nil {
		return nil, record, err
	}
	record, err = service.Engine.Authority.transitionEngagement(record.AgreementDigest, EngagementFundingPending,
		EngagementReady, "", []string{evidenceDigest})
	return funded, record, err
}

var _ PaidDemandBuyerRuntime = (*buyersdk.PaidDemandBuyer)(nil)
