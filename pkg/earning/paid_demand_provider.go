package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const PaidDemandProviderOfferContentType = "application/vnd.tos.paid-demand-provider-offer.v1+cbor"

// ProviderOfferSigner is deliberately narrower than an Agent identity signer:
// it can sign only the released Provider Offer object.
type ProviderOfferSigner interface {
	SignProviderOffer(commerce.PaidDemandQuoteBindingBody, time.Time) (commerce.SignedProviderOffer, error)
}

type LocalProviderOfferSigner struct {
	Context commerce.ProviderProofContext
	Key     ed25519.PrivateKey
}

func (signer LocalProviderOfferSigner) SignProviderOffer(binding commerce.PaidDemandQuoteBindingBody,
	now time.Time) (commerce.SignedProviderOffer, error) {
	if len(signer.Key) != ed25519.PrivateKeySize || signer.Context.ValidFromUnix > uint64(now.UTC().Unix()) ||
		!now.UTC().Before(time.Unix(int64(signer.Context.ExpiresAtUnix), 0).UTC()) {
		return commerce.SignedProviderOffer{}, errors.New("Provider Offer signing capability is unavailable or outside its validity")
	}
	return commerce.SignProviderOffer(binding, signer.Context, signer.Key)
}

type PaidDemandProviderService struct {
	Engine         *Engine
	Signer         ProviderOfferSigner
	OfferResolver  commerce.ProviderOfferKeyResolver
	Evidence       commerce.AgreementEvidenceVerifier
	PolicyRevision uint64
	Now            func() time.Time
}

// IssueOffer publishes one exact Provider Offer only after the provider's
// aggregate exposure has been durably reserved. The offer itself supplies the
// body-bound Provider authorization predicate; the buyer wallet still has to
// accept the same Quote on chain before the Agreement becomes fully agreed.
func (service PaidDemandProviderService) IssueOffer(ctx context.Context, binding commerce.PaidDemandQuoteBindingBody,
	recipientAgentID string, fence commerce.WriterFence) (commerce.SignedProviderOffer, commerce.ActionResolution, EngagementRecord, error) {
	empty := commerce.SignedProviderOffer{}
	if service.Engine == nil || service.Engine.Authority == nil || service.Engine.Sink == nil || service.Signer == nil ||
		service.OfferResolver == nil || service.Evidence == nil || recipientAgentID == "" ||
		!service.Engine.permits("tos-escrow", service.Engine.Gates.TOSEscrow, true) {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, errors.New("Paid Demand Provider Offer is disabled or incomplete")
	}
	now := service.Engine.now()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	record, found := service.Engine.Authority.Engagement(binding.AgreementBodyDigest)
	if !found || record.ReservationID == "" ||
		(record.State != EngagementAuthorizing && record.State != EngagementReserved) ||
		binding.ProviderAgentID != service.Engine.AgentID || binding.BuyerAgentID != recipientAgentID ||
		commerce.ValidatePaidDemandAgreementBinding(record.Agreement.Body, binding) != nil ||
		!now.Before(time.Unix(int64(binding.AcceptByUnix), 0).UTC()) ||
		!hasLiveAgreementReservation(service.Engine.Authority, record.ReservationID, binding.AgreementBodyDigest) {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, errors.New("Provider Offer has no exact live Agreement reservation")
	}
	offer, err := service.Signer.SignProviderOffer(binding, now)
	if err != nil || commerce.VerifyProviderOffer(offer, service.OfferResolver, now) != nil {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, errors.New("Provider Offer signing proof is invalid")
	}
	bindingDigest, err := commerce.PaidDemandQuoteBindingDigest(binding)
	if err != nil {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, err
	}
	canonicalOffer, err := codec.Marshal(offer)
	if err != nil {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, err
	}
	message := OutboundMessage{Kind: "agreement.provider-offer", RecipientAgentIDs: []string{recipientAgentID},
		ContentType: PaidDemandProviderOfferContentType, Payload: canonicalOffer}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: []string{recipientAgentID}, EventKind: message.Kind,
		ContentType: message.ContentType, Payload: append([]byte(nil), canonicalOffer...)})
	if err != nil {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.Engine.OwnerID),
		"agent_id": commerce.ID(service.Engine.AgentID), "agreement_body_digest": commerce.Digest32(binding.AgreementBodyDigest),
		"demand_mutation_digest": commerce.Digest32(binding.DemandMutationDigest), "buyer_agent_id": commerce.ID(binding.BuyerAgentID),
		"provider_offer_id": commerce.ID(binding.ProviderOfferID), "binding_digest": commerce.Digest32(bindingDigest)}
	action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "provider.offer", fields,
		effectRequest, fence, service.PolicyRevision, service.Engine.MandateDigest, "", "reserved",
		minUint64(binding.AcceptByUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = service.Engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return empty, commerce.ActionResolution{}, EngagementRecord{}, err
	}
	admitted, err := service.Engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil {
		return empty, admitted, EngagementRecord{}, err
	}
	if admitted.State == commerce.ActionAccepted || admitted.State == commerce.ActionTerminal {
		current, exists := service.Engine.Authority.Engagement(binding.AgreementBodyDigest)
		if !exists || !hasPaidDemandProfileEvidence(current, service.Engine.AgentID) {
			return empty, admitted, EngagementRecord{}, errors.New("completed Provider Offer lacks durable Agreement evidence")
		}
		return offer, admitted, current, nil
	}
	if admitted.State != commerce.ActionPrepared {
		return empty, admitted, EngagementRecord{}, errors.New("Provider Offer action is not prepared")
	}
	resolved, err := service.Engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		recovered, resolveErr := service.Engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return empty, admitted, EngagementRecord{}, err
		}
		resolved = recovered
	}
	resolved, err = service.Engine.recordResolution(action, resolved)
	if err != nil || resolved.State != commerce.ActionAccepted && resolved.State != commerce.ActionTerminal {
		if err == nil {
			err = errors.New("Provider Offer remains unresolved")
		}
		return empty, resolved, EngagementRecord{}, err
	}
	offerDigest, err := commerce.ProviderOfferDigest(offer)
	if err != nil {
		return empty, resolved, EngagementRecord{}, err
	}
	subject := commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
		SubjectIdentifier: service.Engine.AgentID}
	evidence, err := commerce.PaidDemandEvidenceFromBinding(record.Agreement.Body, subject, binding, "provider_offer",
		canonicalOffer, uint64(now.Unix()), offerDigest)
	if err != nil {
		return empty, resolved, EngagementRecord{}, err
	}
	record, err = service.Engine.Authority.RecordAgreementEvidence(binding.AgreementBodyDigest, evidence, service.Evidence)
	return offer, resolved, record, err
}

func hasLiveAgreementReservation(authority EconomicAuthority, reservationID, agreementDigest string) bool {
	_, _, reservations := authority.Snapshot()
	for _, reservation := range reservations {
		if reservation.ReservationID == reservationID && reservation.AgreementDigest == agreementDigest && !reservation.Released {
			return true
		}
	}
	return false
}

func hasPaidDemandProfileEvidence(record EngagementRecord, agentID string) bool {
	for _, evidence := range record.Agreement.AuthorizationEvidence {
		if evidence.AuthoritySubject.SubjectKind == "agent" && evidence.AuthoritySubject.SubjectIdentifier == agentID &&
			evidence.EvidenceProfileURI == commerce.EvidenceProfilePaidDemandQuote {
			return true
		}
	}
	return false
}
