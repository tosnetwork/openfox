package earning

import (
	"context"
	"errors"
	"strconv"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type PaidDemandApplicationHandler struct {
	Engine       *Engine
	Provider     *PaidDemandProviderService
	Network      *nativev1.NetworkDomain
	Store        *PaidDemandNegotiationStore
	Prerequisite SettlementPrerequisiteChecker
	ComputeUnits uint64
	Now          func() time.Time
}

// HandleDemandApplication is deliberately driven by the application package,
// not by chat prose. It revalidates the buyer-built native projection against
// the exact proposed Agreement, reserves aggregate provider exposure, then and
// only then emits the signed Provider Offer.
func (handler PaidDemandApplicationHandler) HandleDemandApplication(ctx context.Context, intent commerce.SignedAgentIntent,
	application commerce.IntentApplication, body commerce.AgentAgreementBody, inventory InventorySnapshot,
	fence commerce.WriterFence) error {
	if handler.Engine == nil || handler.Provider == nil || handler.Store == nil || handler.Prerequisite == nil ||
		ctx == nil || application.ApplicantAgentID == "" || inventory.AgentID != handler.Engine.AgentID {
		return errors.New("Paid Demand application handler is incomplete")
	}
	publicCanonical := paidDemandPreferenceParameters(intent.Body.Payload.SettlementPreferences)
	public, err := paiddemand.DecodeCanonicalPublicTerms(publicCanonical)
	if err != nil {
		return err
	}
	packageCanonical := paidDemandPreferenceParameters(application.SettlementOffers)
	packageValue, err := paiddemand.DecodeCanonicalNegotiationPackage(packageCanonical)
	if err != nil || packageValue.Binding.ProviderAgentID != handler.Engine.AgentID ||
		packageValue.Binding.BuyerAgentID != application.ApplicantAgentID ||
		packageValue.Binding.DemandMutationDigest != application.IntentDigest {
		return errors.New("Paid Demand application package participants or Intent binding mismatch")
	}
	if handler.Network == nil {
		return errors.New("Paid Demand application has no pinned network domain")
	}
	if _, err := paiddemand.ValidateNegotiationPackageOnNetwork(body, public, packageValue, handler.Network, handler.now()); err != nil {
		return err
	}
	if err := handler.Store.Put(packageValue.AgreementBodyDigest, packageCanonical); err != nil {
		return err
	}
	receivable, found := paidDemandReceivable(body, handler.Engine.AgentID, application.ApplicantAgentID)
	if !found {
		return errors.New("Paid Demand Agreement has no bounded provider receivable")
	}
	compute := handler.ComputeUnits
	if compute == 0 {
		compute = 1
	}
	reservation := ExposureReservation{ReservationID: "reservation:" + packageValue.AgreementBodyDigest[7:],
		AgreementDigest: packageValue.AgreementBodyDigest, ComputeUnits: compute, ReceivableAtomic: receivable,
		MaximumLossAtomic: 0}
	if _, record, err := handler.Engine.ReserveAgreement(ctx, packageValue.AgreementBodyDigest, reservation,
		handler.Prerequisite, inventory.PolicyRevision, fence); err != nil {
		return err
	} else if record.ReservationID != reservation.ReservationID {
		return errors.New("Paid Demand reservation identity changed")
	}
	_, resolution, _, err := handler.Provider.IssueOffer(ctx, packageValue.Binding, application.ApplicantAgentID, fence)
	if err != nil || resolution.State != commerce.ActionAccepted && resolution.State != commerce.ActionTerminal {
		if err == nil {
			err = errors.New("Paid Demand Provider Offer remains unresolved")
		}
		return err
	}
	return nil
}

func (handler PaidDemandApplicationHandler) now() time.Time {
	if handler.Now != nil {
		return handler.Now().UTC()
	}
	return time.Now().UTC()
}

func paidDemandReceivable(body commerce.AgentAgreementBody, providerAgentID, buyerAgentID string) (uint64, bool) {
	var total uint64
	for _, obligation := range body.Obligations {
		if obligation.Amount == nil || obligation.SettlementAdapterURI != paiddemand.SettlementAdapterURI ||
			obligation.ObligorAgentID != buyerAgentID || obligation.BeneficiaryAgentID != providerAgentID {
			continue
		}
		value, err := strconv.ParseUint(obligation.Amount.AmountAtomic, 10, 64)
		if err != nil || value == 0 || ^uint64(0)-total < value {
			return 0, false
		}
		total += value
	}
	return total, total != 0
}

var _ DemandApplicationProfileHandler = PaidDemandApplicationHandler{}
