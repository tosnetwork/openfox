package earning

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type PaidDemandPurchasePreparer interface {
	PreparePurchase(context.Context, buyersdk.PaidDemandPurchaseInput) (*buyersdk.PreparedPaidDemandPurchase, error)
}

// PaidDemandBuyerAutonomy is the profile-specific promotion boundary from a
// verified Provider Offer to a custody-authorized on-chain acceptance. It does
// not infer economic terms from chat: every native input is reconstructed from
// the owner-private canonical negotiation package that was sent with the
// original Intent application.
type PaidDemandBuyerAutonomy struct {
	Engine       *Engine
	Inventory    InventorySource
	Policy       AgreementAdmissionPolicy
	Store        *PaidDemandNegotiationStore
	Preparer     PaidDemandPurchasePreparer
	Buyer        PaidDemandBuyerService
	Network      *nativev1.NetworkDomain
	PublicTerms  paiddemand.PublicTermsV1
	Prerequisite SettlementPrerequisiteChecker
	Fence        WriterFenceProvider
	Now          func() time.Time
}

func (service PaidDemandBuyerAutonomy) Process(ctx context.Context, maximum uint32) (uint32, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Inventory == nil || service.Policy == nil ||
		service.Store == nil || service.Preparer == nil || service.Buyer.Engine != service.Engine || service.Network == nil ||
		service.Prerequisite == nil || service.Fence == nil || maximum == 0 || maximum > 1000 {
		return 0, errors.New("Paid Demand buyer autonomy is incomplete or unbounded")
	}
	now := service.Engine.now()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	inventory, err := service.Inventory.Snapshot(ctx)
	if err != nil || inventory.Validate(now) != nil || inventory.AgentID != service.Engine.AgentID {
		return 0, errors.New("Paid Demand buyer autonomy has no fresh local Inventory")
	}
	advanced := uint32(0)
	for _, snapshot := range service.Engine.Authority.EngagementSnapshot() {
		if advanced >= maximum || !paidDemandBuyerCandidate(snapshot, service.Engine.AgentID) {
			continue
		}
		packageValue, found, getErr := service.Store.Get(snapshot.AgreementDigest)
		if getErr != nil {
			return advanced, getErr
		}
		if !found {
			// A foreign proposal cannot cause a purchase without the exact
			// package this buyer constructed and durably retained.
			continue
		}
		proposal, validateErr := paiddemand.ValidateNegotiationPackageOnNetwork(snapshot.Agreement.Body,
			service.PublicTerms, packageValue, service.Network, now)
		if validateErr != nil {
			return advanced, validateErr
		}
		offer, offerFound, offerErr := paidDemandProviderOffer(snapshot, packageValue.Binding.ProviderAgentID)
		if offerErr != nil {
			return advanced, offerErr
		}
		if !offerFound {
			continue
		}
		decision, evaluateErr := service.Policy.EvaluateAgreement(ctx, snapshot, inventory, now)
		if evaluateErr != nil {
			return advanced, evaluateErr
		}
		if !decision.Accept {
			continue
		}
		fence, fenceErr := service.Fence(ctx)
		if fenceErr != nil {
			return advanced, fenceErr
		}
		if snapshot.ReservationID == "" {
			reservation, reserveErr := paidDemandBuyerReservation(snapshot, service.Engine.AgentID)
			if reserveErr != nil {
				return advanced, reserveErr
			}
			_, snapshot, reserveErr = service.Engine.ReserveAgreement(ctx, snapshot.AgreementDigest, reservation,
				service.Prerequisite, inventory.PolicyRevision, fence)
			if reserveErr != nil {
				return advanced, reserveErr
			}
		}
		purchase, prepareErr := service.Preparer.PreparePurchase(ctx, buyersdk.PaidDemandPurchaseInput{
			Agreement:              snapshot.Agreement.Body,
			ProviderOffer:          offer,
			Proposal:               proposal,
			ManifestCanonical:      packageValue.ManifestCanonical,
			EscrowTerms:            packageValue.EscrowTerms,
			ExecutionSignerEd25519: packageValue.ExecutionSignerEd25519,
			TransportBinding:       packageValue.TransportBinding,
			ExecutionDeadlineUnix:  packageValue.ExecutionDeadlineUnix,
		})
		if prepareErr != nil {
			return advanced, prepareErr
		}
		if _, _, runErr := service.Buyer.AcceptAndFund(ctx, purchase,
			packageValue.Binding.ProviderAgentID, fence); runErr != nil {
			return advanced, runErr
		}
		advanced++
	}
	return advanced, nil
}

func paidDemandBuyerCandidate(record EngagementRecord, localAgentID string) bool {
	if record.State != EngagementProposed && record.State != EngagementAuthorizing && record.State != EngagementReserved &&
		record.State != EngagementFundingPending && record.State != EngagementReady {
		return false
	}
	for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
		if predicate.AuthoritySubject.SubjectKind == "wallet" && predicate.AuthoritySubject.RepresentedAgentID == localAgentID &&
			predicate.EvidenceProfileURI == commerce.EvidenceProfilePaidDemandQuote &&
			predicate.EvidenceProfileVersion == 1 && predicate.EvidenceProfileDigest == commerce.PaidDemandQuoteProfileDigest() {
			return true
		}
	}
	return false
}

func paidDemandProviderOffer(record EngagementRecord, providerAgentID string) (commerce.SignedProviderOffer, bool, error) {
	for _, evidence := range record.Agreement.AuthorizationEvidence {
		if evidence.AuthoritySubject.SubjectKind != "agent" || evidence.AuthoritySubject.SubjectIdentifier != providerAgentID ||
			evidence.EvidenceProfileURI != commerce.EvidenceProfilePaidDemandQuote ||
			evidence.EvidenceContentType != commerce.PaidDemandProviderOfferContentType {
			continue
		}
		var profile commerce.PaidDemandQuoteEvidence
		if codec.Unmarshal(evidence.Evidence, &profile) != nil || profile.EvidenceKind != "provider_offer" {
			return commerce.SignedProviderOffer{}, false, errors.New("stored Paid Demand Provider Offer evidence is invalid")
		}
		var offer commerce.SignedProviderOffer
		if codec.Unmarshal(profile.NativeEvidence, &offer) != nil {
			return commerce.SignedProviderOffer{}, false, errors.New("stored Paid Demand Provider Offer is not canonical")
		}
		offerBindingDigest, offerDigestErr := commerce.PaidDemandQuoteBindingDigest(offer.Binding)
		profileBindingDigest, profileDigestErr := commerce.PaidDemandQuoteBindingDigest(profile.Binding)
		if offerDigestErr != nil || profileDigestErr != nil ||
			offerBindingDigest != profileBindingDigest {
			return commerce.SignedProviderOffer{}, false, errors.New("stored Paid Demand Provider Offer differs from its binding")
		}
		return offer, true, nil
	}
	return commerce.SignedProviderOffer{}, false, nil
}

func paidDemandBuyerReservation(record EngagementRecord, buyerAgentID string) (ExposureReservation, error) {
	var total uint64
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount == nil || obligation.ObligorAgentID != buyerAgentID ||
			obligation.SettlementAdapterURI != paiddemand.SettlementAdapterURI {
			continue
		}
		amount, err := strconv.ParseUint(obligation.Amount.AmountAtomic, 10, 64)
		if err != nil || amount == 0 || total > math.MaxUint64-amount {
			return ExposureReservation{}, errors.New("Paid Demand buyer exposure is invalid or exceeds uint64")
		}
		total += amount
	}
	if total == 0 {
		return ExposureReservation{}, errors.New("Paid Demand Agreement has no buyer payment exposure")
	}
	return ExposureReservation{ReservationID: "reservation:" + record.AgreementDigest[7:],
		AgreementDigest: record.AgreementDigest, SpendAtomic: total, LockedCapitalAtomic: total,
		MaximumLossAtomic: total}, nil
}

var _ PaidDemandPurchasePreparer = (*buyersdk.PaidDemandBuyer)(nil)
