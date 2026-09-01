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

type PaidDemandFundingAdmissionDisposition uint8

const (
	PaidDemandFundingNotApplicable PaidDemandFundingAdmissionDisposition = iota + 1
	PaidDemandFundingDeferred
	PaidDemandFundingAdmitted
)

type PaidDemandFundingAdmissionDecision struct {
	Disposition PaidDemandFundingAdmissionDisposition
}

// PaidDemandFundingAdmission is an optional, local routing and admission
// boundary for a purchase that has otherwise passed the ordinary Paid Demand
// policy. NotApplicable and Deferred are ordinary skip results. An error is
// reserved for invalid or conflicting authority state and fails the run.
// This interface does not add anything to the Agreement or Paid Demand wire
// formats.
type PaidDemandFundingAdmission interface {
	DecidePaidDemandFunding(context.Context, EngagementRecord) (PaidDemandFundingAdmissionDecision, error)
}

// PaidDemandFundingAdmissionRouter permits several independent local
// compositions to share one autonomy loop. Exactly one route may claim a
// candidate; overlapping routes fail closed.
type PaidDemandFundingAdmissionRouter struct {
	Admissions []PaidDemandFundingAdmission
}

func (router PaidDemandFundingAdmissionRouter) DecidePaidDemandFunding(ctx context.Context,
	record EngagementRecord) (PaidDemandFundingAdmissionDecision, error) {
	decision := PaidDemandFundingAdmissionDecision{Disposition: PaidDemandFundingNotApplicable}
	claimed := false
	for _, admission := range router.Admissions {
		if admission == nil {
			return PaidDemandFundingAdmissionDecision{}, errors.New("Paid Demand funding admission route is nil")
		}
		candidate, err := admission.DecidePaidDemandFunding(ctx, record)
		if err != nil {
			return PaidDemandFundingAdmissionDecision{}, err
		}
		switch candidate.Disposition {
		case PaidDemandFundingNotApplicable:
			continue
		case PaidDemandFundingDeferred, PaidDemandFundingAdmitted:
			if claimed {
				return PaidDemandFundingAdmissionDecision{}, errors.New("Paid Demand funding candidate matches overlapping admission routes")
			}
			claimed, decision = true, candidate
		default:
			return PaidDemandFundingAdmissionDecision{}, errors.New("Paid Demand funding admission returned an invalid disposition")
		}
	}
	return decision, nil
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
	// FundingAdmission is nil for the ordinary independent-Agreement path.
	// A local composition, such as a sequential objective-milestone plan, may
	// install an additional fail-closed check immediately before reservation.
	FundingAdmission PaidDemandFundingAdmission
	Fence            WriterFenceProvider
	Now              func() time.Time
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
		fundingAllowed, admitErr := paidDemandFundingAdmissionAllows(ctx, service.FundingAdmission, snapshot)
		if admitErr != nil {
			return advanced, admitErr
		}
		if !fundingAllowed {
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

func paidDemandFundingAdmissionAllows(ctx context.Context, admission PaidDemandFundingAdmission,
	record EngagementRecord) (bool, error) {
	if admission == nil {
		return true, nil
	}
	decision, err := admission.DecidePaidDemandFunding(ctx, record)
	if err != nil {
		return false, err
	}
	switch decision.Disposition {
	case PaidDemandFundingNotApplicable, PaidDemandFundingDeferred:
		return false, nil
	case PaidDemandFundingAdmitted:
		return true, nil
	default:
		return false, errors.New("Paid Demand funding admission returned an invalid disposition")
	}
}

func paidDemandBuyerCandidate(record EngagementRecord, localAgentID string) bool {
	if record.NegotiationAmbiguous {
		return false
	}
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
	if !canonicalSHA256(record.AgreementDigest) || buyerAgentID == "" {
		return ExposureReservation{}, errors.New("Paid Demand buyer exposure has an invalid Agreement binding")
	}
	var total uint64
	var asset *commerce.AssetIdentityV1
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount == nil || obligation.ObligorAgentID != buyerAgentID ||
			obligation.SettlementAdapterURI != paiddemand.SettlementAdapterURI {
			continue
		}
		candidateAsset := commerce.AssetIdentityV1{AssetNamespace: obligation.Amount.AssetNamespace,
			AssetIdentifier: obligation.Amount.AssetIdentifier, Unit: obligation.Amount.Unit}
		if commerce.ValidateAssetIdentityV1(candidateAsset) != nil {
			return ExposureReservation{}, errors.New("Paid Demand buyer exposure has an invalid asset")
		}
		if asset != nil && *asset != candidateAsset {
			return ExposureReservation{}, errors.New("Paid Demand Agreement mixes buyer payment assets")
		}
		if asset == nil {
			selected := candidateAsset
			asset = &selected
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
		AgreementDigest: record.AgreementDigest, Asset: asset, SpendAtomic: total, LockedCapitalAtomic: total,
		MaximumLossAtomic: total}, nil
}

var _ PaidDemandPurchasePreparer = (*buyersdk.PaidDemandBuyer)(nil)
