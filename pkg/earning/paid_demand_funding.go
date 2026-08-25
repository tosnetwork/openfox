package earning

import (
	"context"
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// PaidDemandFundingPrerequisite independently re-resolves the chain before a
// provider starts work. Messenger evidence locates the account but is never
// accepted as proof of funding by itself.
type PaidDemandFundingPrerequisite struct {
	Resolver interface {
		ResolveFinalizedV2(context.Context, string) (*toschain.FinalizedEscrowV2, bool, error)
	}
	Network        *nativev1.NetworkDomain
	ProviderOffers commerce.ProviderOfferKeyResolver
}

func (verifier PaidDemandFundingPrerequisite) ResolveFundingPrerequisite(ctx context.Context,
	record EngagementRecord, obligation commerce.AgreementObligation) ([]string, error) {
	if verifier.Resolver == nil || verifier.Network == nil || verifier.ProviderOffers == nil ||
		ctx == nil || record.AgreementDigest == "" || obligation.Amount == nil ||
		obligation.SettlementAdapterURI != paiddemand.SettlementAdapterURI {
		return nil, errors.New("Paid Demand funding verifier is incomplete")
	}
	for _, authorization := range record.Agreement.AuthorizationEvidence {
		if authorization.EvidenceProfileURI != commerce.EvidenceProfilePaidDemandQuote {
			continue
		}
		var profile commerce.PaidDemandQuoteEvidence
		if codec.Unmarshal(authorization.Evidence, &profile) != nil || profile.EvidenceKind != "buyer_accept" ||
			profile.Binding.AgreementBodyDigest != record.AgreementDigest ||
			!containsString(profile.Binding.AgreementObligationIDs, obligation.ObligationID) {
			continue
		}
		var locator paiddemand.BuyerAcceptNativeEvidenceV1
		if codec.Unmarshal(profile.NativeEvidence, &locator) != nil {
			continue
		}
		resolved, found, err := verifier.Resolver.ResolveFinalizedV2(ctx, locator.EscrowAddress)
		if err != nil || !found || resolved == nil || resolved.State == nil || resolved.Reference == nil ||
			resolved.State.Status != nativecore.EscrowStatusFundedV2 || resolved.State.AcceptedAtUnix == 0 ||
			resolved.Reference.FinalizedCheckpoint < locator.ObservedCheckpoint {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("Paid Demand escrow is not quorum-finalized as funded")
		}
		terms := nativecore.EscrowTermsV1{BuyerAddress: resolved.State.BuyerAddress,
			ProviderAddress: resolved.State.ProviderAddress, FundingDeadline: resolved.State.FundingDeadline,
			RefundAvailableAt: resolved.State.RefundAvailableAt}
		quote, _, err := paiddemand.VerifyAcceptedQuote(resolved.State.AcceptedQuote, record.Agreement.Body,
			verifier.Network, terms, verifier.ProviderOffers,
			time.Unix(int64(resolved.State.AcceptedAtUnix), 0).UTC())
		if err != nil || quote.Terms.Proposal.MaximumPrice == nil || quote.Terms.Proposal.MaximumPrice.Asset == nil ||
			quote.Terms.Proposal.MaximumPrice.AtomicAmount != obligation.Amount.AmountAtomic ||
			resolved.State.FundedAtomicAmount != obligation.Amount.AmountAtomic {
			return nil, errors.New("Paid Demand finalized funding differs from the Agreement obligation")
		}
		evidence, err := codec.Digest("tos.paid-demand-execution-funding-prerequisite.v1", struct {
			AgreementDigest string `json:"agreement_digest"`
			ObligationID    string `json:"obligation_id"`
			EscrowAddress   string `json:"escrow_address"`
			QuoteCommitment string `json:"quote_commitment"`
			Checkpoint      uint64 `json:"checkpoint"`
			TransactionHash string `json:"transaction_hash"`
			FundedAtomic    string `json:"funded_atomic"`
		}{record.AgreementDigest, obligation.ObligationID, locator.EscrowAddress,
			resolved.State.QuoteCommitment, resolved.Reference.FinalizedCheckpoint,
			resolved.Reference.TransactionHash, resolved.State.FundedAtomicAmount})
		if err != nil {
			return nil, err
		}
		return []string{evidence}, nil
	}
	return nil, errors.New("Paid Demand Agreement has no verified buyer acceptance locator")
}

var _ FundingEvidenceResolver = PaidDemandFundingPrerequisite{}
