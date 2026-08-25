package earning

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-messenger/pkg/fault"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// AgreementCoordinator promotes only typed, body-bound Messenger events into
// the owner-private engagement ledger. It does not invoke the model and it
// completes the inbox lease only after the durable write succeeds.
type AgreementCoordinator struct {
	Inbox              AgreementInbox
	Authority          EconomicAuthority
	Verifier           commerce.AgreementEvidenceVerifier
	ApplicationHandler IntentApplicationHandler
}

type IntentApplicationHandler interface {
	HandleIntentApplication(context.Context, ClaimedAgreementEvent) error
}

func (coordinator AgreementCoordinator) HandleNext(ctx context.Context) (bool, EngagementRecord, error) {
	if coordinator.Authority == nil || coordinator.Verifier == nil {
		return false, EngagementRecord{}, errors.New("Agreement coordinator is not fully configured")
	}
	event, err := coordinator.Inbox.ClaimNext(ctx)
	if err != nil || event == nil {
		return false, EngagementRecord{}, err
	}
	var record EngagementRecord
	switch event.Kind {
	case "intent.application":
		if event.Application == nil || coordinator.ApplicationHandler == nil {
			err = errors.New("Intent application has no bounded negotiation handler")
		} else {
			err = coordinator.ApplicationHandler.HandleIntentApplication(ctx, *event)
		}
	case "agreement.propose":
		var body commerce.AgentAgreementBody
		if event.Proposal == nil || codec.Unmarshal(event.Proposal.CanonicalBody, &body) != nil {
			err = errors.New("Agreement proposal body is invalid")
		} else {
			record, err = coordinator.Authority.RecordAgreementProposal(body, event.SenderAgentID, event.EventID, event.SemanticActionID)
		}
	case "agreement.accept":
		if event.Acceptance == nil {
			err = errors.New("Agreement acceptance body is absent")
			break
		}
		prior, found := coordinator.Authority.Engagement(event.Acceptance.AgreementBodyDigest)
		if !found {
			err = errors.New("Agreement acceptance arrived before its exact proposal")
			break
		}
		acceptance, decodeErr := commerce.DecodeSignedAgreementAcceptance(event.Acceptance.CanonicalAcceptance)
		if decodeErr != nil || acceptance.Body.AcceptingSubject.SubjectIdentifier != event.SenderAgentID {
			err = errors.New("Agreement acceptance signer does not match the authenticated sender")
			break
		}
		evidence, evidenceErr := commerce.AgentSignatureEvidence(prior.Agreement.Body, acceptance)
		if evidenceErr != nil {
			err = evidenceErr
			break
		}
		record, err = coordinator.Authority.RecordAgreementEvidence(prior.AgreementDigest, evidence, coordinator.Verifier)
	case "agreement.evidence":
		if event.Evidence == nil {
			err = errors.New("Agreement evidence body is absent")
			break
		}
		var evidence commerce.AgreementAuthorizationEvidence
		if codec.Unmarshal(event.Evidence.CanonicalEvidence, &evidence) != nil ||
			!evidenceSenderMatches(evidence.AuthoritySubject, event.SenderAgentID) {
			err = errors.New("Agreement evidence authority does not match the authenticated sender")
			break
		}
		record, err = coordinator.Authority.RecordAgreementEvidence(evidence.AgreementBodyDigest, evidence, coordinator.Verifier)
	case "agreement.provider-offer":
		if event.ProviderOffer == nil {
			err = errors.New("Provider Offer body is absent")
			break
		}
		var offer commerce.SignedProviderOffer
		if codec.Unmarshal(event.ProviderOffer.CanonicalOffer, &offer) != nil || offer.Binding.ProviderAgentID != event.SenderAgentID {
			err = errors.New("Provider Offer signer does not match the authenticated sender")
			break
		}
		prior, found := coordinator.Authority.Engagement(offer.Binding.AgreementBodyDigest)
		if !found {
			err = errors.New("Provider Offer arrived before its exact Agreement")
			break
		}
		subject := commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
			SubjectIdentifier: event.SenderAgentID}
		observedAt := coordinator.Authority.AuthorityNow().UTC()
		if observedAt.IsZero() || observedAt.Unix() < 0 {
			err = errors.New("Agreement authority returned no valid observation time")
			break
		}
		evidence, evidenceErr := commerce.PaidDemandEvidenceFromBinding(prior.Agreement.Body, subject, offer.Binding,
			"provider_offer", event.ProviderOffer.CanonicalOffer, uint64(observedAt.Unix()),
			event.ProviderOffer.ProviderOfferDigest)
		if evidenceErr != nil {
			err = evidenceErr
			break
		}
		record, err = coordinator.Authority.RecordAgreementEvidence(prior.AgreementDigest, evidence, coordinator.Verifier)
	case "agreement.withdraw":
		if event.Withdrawal == nil {
			err = errors.New("Agreement withdrawal body is absent")
			break
		}
		record, err = coordinator.Authority.ObserveAgreementWithdrawal(event.Withdrawal.AgreementBodyDigest,
			event.Withdrawal.ProposalActionID, event.SenderAgentID, event.EventID)
	case "agreement.delivery":
		if event.Delivery == nil {
			err = errors.New("Agreement delivery body is absent")
			break
		}
		record, err = coordinator.Authority.ObserveAgreementDelivery(event.Delivery.AgreementBodyDigest,
			event.Delivery.ObligationID, event.Delivery.DeliverableManifestDigest, event.SenderAgentID, event.EventID)
	default:
		err = errors.New("Agreement coordinator received another event kind")
	}
	if err != nil {
		_ = coordinator.Inbox.Reject(ctx, event.EventID, event.LeaseID, fault.CodeNotAuthentic)
		return true, EngagementRecord{}, err
	}
	if err := coordinator.Inbox.Complete(ctx, event); err != nil {
		return true, record, err
	}
	return true, record, nil
}

func evidenceSenderMatches(subject commerce.AgreementAuthoritySubject, senderAgentID string) bool {
	if subject.SubjectKind == "agent" {
		return subject.SubjectIdentifier == senderAgentID
	}
	return subject.RepresentedAgentID == senderAgentID
}
