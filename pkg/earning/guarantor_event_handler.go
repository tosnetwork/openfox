package earning

import (
	"context"
	"errors"
	"fmt"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

// GuarantorFirmOfferPlanner freezes the complete Agreement and coverage terms
// before the Provider reserves exposure or signs anything. Implementations may
// consult an AI underwriter, but retries for the same exact request must return
// the same semantic proposal or a deliberate, new negotiation revision.
type GuarantorFirmOfferPlanner interface {
	PlanFirmOffer(context.Context, *ClaimedCommerceProfileEvent,
		guarantor.AuthorizedCoverageQuoteRequestV1) (GuarantorIssueOfferInput, error)
}

type GuarantorFirmOfferPlannerFunc func(context.Context, *ClaimedCommerceProfileEvent,
	guarantor.AuthorizedCoverageQuoteRequestV1) (GuarantorIssueOfferInput, error)

func (planner GuarantorFirmOfferPlannerFunc) PlanFirmOffer(ctx context.Context, event *ClaimedCommerceProfileEvent,
	request guarantor.AuthorizedCoverageQuoteRequestV1) (GuarantorIssueOfferInput, error) {
	return planner(ctx, event, request)
}

// GuarantorUnhandledEventHandler receives authenticated, canonical objects
// that are not Provider-side mutation requests. A client-role implementation
// uses this boundary to journal Provider receipts. Returning nil means the
// object was durably consumed; an absent handler retains the Messenger lease.
type GuarantorUnhandledEventHandler interface {
	HandleUnhandledGuarantorEvent(context.Context, *ClaimedCommerceProfileEvent, any) error
}

type GuarantorUnhandledEventHandlerFunc func(context.Context, *ClaimedCommerceProfileEvent, any) error

func (handler GuarantorUnhandledEventHandlerFunc) HandleUnhandledGuarantorEvent(ctx context.Context,
	event *ClaimedCommerceProfileEvent, object any) error {
	return handler(ctx, event, object)
}

// GuarantorProviderEventHandler is the concrete, replay-safe bridge from the
// generic Messenger inbox to the Provider lifecycle. It never interprets chat
// and never treats receipt delivery as authority. Every mutation is delegated
// to GuarantorProviderCoordinator, which enforces the current writer, exact
// request identity, portfolio admission, and portable result evidence.
type GuarantorProviderEventHandler struct {
	Coordinator        *GuarantorProviderCoordinator
	Engine             *Engine
	Fence              WriterFenceProvider
	Planner            GuarantorFirmOfferPlanner
	Unhandled          GuarantorUnhandledEventHandler
	ImmutablePublisher guarantor.ImmutableCommerceObjectPublisher
	PolicyRevision     uint64
	MaximumEventTTL    time.Duration
}

func (handler *GuarantorProviderEventHandler) HandleGuarantorProfileEvent(ctx context.Context,
	event *ClaimedCommerceProfileEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if handler == nil || handler.Coordinator == nil || handler.Engine == nil || handler.Fence == nil ||
		handler.PolicyRevision == 0 || event == nil || event.SenderAgentID == "" {
		return errors.New("Guarantor Provider event handler is incomplete")
	}
	object, err := decodeGuarantorCarriageObject(event)
	if err != nil {
		return PermanentGuarantorEventError{Err: err}
	}
	switch value := object.(type) {
	case *guarantor.AuthorizedCoverageQuoteRequestV1:
		return handler.handleQuoteRequest(ctx, event, *value)
	case *guarantor.AuthorizedCoverageAcceptanceRequestV1:
		return handler.handleAcceptanceRequest(ctx, event, *value)
	case *guarantor.AuthorizedCoverageClaimV1:
		return handler.handleClaim(ctx, event, *value)
	case *guarantor.AuthorizedClaimDecisionV1:
		return handler.handleDecision(ctx, event, *value)
	case *guarantor.AuthorizedCoverageCancellationRequestV1:
		return handler.handleCancellation(ctx, event, *value)
	default:
		if handler.Unhandled == nil {
			return errors.New("Guarantor object requires a durable client-role handler")
		}
		return handler.Unhandled.HandleUnhandledGuarantorEvent(ctx, event, object)
	}
}

func decodeGuarantorCarriageObject(event *ClaimedCommerceProfileEvent) (any, error) {
	if event == nil || len(event.CanonicalObjectBytes) == 0 {
		return nil, errors.New("Guarantor event has no canonical object")
	}
	if err := (guarantor.CommerceObjectVerifierV1{}).VerifyCommerceObject(event.ProfileEvent.ProfileURI,
		event.ProfileEvent.ProfileVersion, event.ProfileEvent.ObjectKind, event.ProfileEvent.ObjectContentType,
		event.ProfileEvent.ObjectDigest, event.CanonicalObjectBytes); err != nil {
		return nil, fmt.Errorf("reverify Guarantor carriage object: %w", err)
	}
	registryKind := ""
	for _, entry := range guarantor.ReleasedCommerceCarriageObjectsV1() {
		if entry.ObjectKind == event.ProfileEvent.ObjectKind {
			registryKind = entry.RegistryKind
			break
		}
	}
	if registryKind == "" {
		return nil, errors.New("Guarantor event object kind is not released for carriage")
	}
	object, err := guarantor.DecodeRegisteredObjectV1(registryKind, event.CanonicalObjectBytes)
	if err != nil {
		return nil, fmt.Errorf("decode exact Guarantor object: %w", err)
	}
	return object, nil
}

func (handler *GuarantorProviderEventHandler) handleQuoteRequest(ctx context.Context,
	event *ClaimedCommerceProfileEvent, request guarantor.AuthorizedCoverageQuoteRequestV1) error {
	if handler.Planner == nil {
		return errors.New("Guarantor Provider has no owner-approved firm-offer planner")
	}
	if request.Body.GuarantorAgentID != handler.Coordinator.AgentID ||
		request.Body.RequesterAgentID != event.SenderAgentID {
		return PermanentGuarantorEventError{Err: errors.New("Guarantor quote transport subject differs from its signed request")}
	}
	input, err := handler.Planner.PlanFirmOffer(ctx, event, request)
	if err != nil {
		return err
	}
	requestDigest, digestErr := guarantor.QuoteRequestDigest(request)
	inputDigest, inputDigestErr := guarantor.QuoteRequestDigest(input.Request)
	if digestErr != nil || inputDigestErr != nil || inputDigest != requestDigest {
		return PermanentGuarantorEventError{Err: errors.New("firm-offer planner substituted the quote request")}
	}
	fence, err := handler.Fence(ctx)
	if err != nil {
		return err
	}
	offer, _, err := handler.Coordinator.IssueFirmOffer(ctx, input, fence)
	if err != nil {
		return err
	}
	return handler.send(ctx, event.SenderAgentID, "firm-offer", offer,
		input.Agreement, []string{input.CoverageObligationID}, input.ExpiresAtUnix, fence)
}

func (handler *GuarantorProviderEventHandler) handleAcceptanceRequest(ctx context.Context,
	event *ClaimedCommerceProfileEvent, request guarantor.AuthorizedCoverageAcceptanceRequestV1) error {
	if request.Body.AcceptingSubject != event.SenderAgentID &&
		!guarantorAgreementHasParticipant(request.CoverageAgreementBody, event.SenderAgentID) {
		return PermanentGuarantorEventError{Err: errors.New("Guarantor acceptance transport subject differs from its signed request")}
	}
	offer, found := handler.Coordinator.Journal.FirmOfferByDigest(request.Body.AuthorizedFirmOfferEnvelopeDigest)
	if !found {
		return errors.New("Guarantor acceptance references an offer not retained by this Provider")
	}
	fence, err := handler.Fence(ctx)
	if err != nil {
		return err
	}
	now := handler.Coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() {
		return errors.New("Guarantor acceptance has no authority time")
	}
	receipt, _, err := handler.Coordinator.AcceptCoverage(ctx, GuarantorAcceptCoverageInput{Offer: offer,
		Request: request, CoverageObligationID: offer.Body.CoverageObligationID, ReceivedAtUnix: uint64(now.Unix())}, fence)
	if err != nil {
		return err
	}
	return handler.send(ctx, event.SenderAgentID, "acceptance-receipt", receipt,
		request.CoverageAgreementBody, []string{offer.Body.CoverageObligationID}, request.Body.ExpiresAtUnix, fence)
}

func (handler *GuarantorProviderEventHandler) handleClaim(ctx context.Context,
	event *ClaimedCommerceProfileEvent, claim guarantor.AuthorizedCoverageClaimV1) error {
	if claim.Body.ClaimantSubject != event.SenderAgentID && claim.Body.BeneficiaryAgentID != event.SenderAgentID {
		return PermanentGuarantorEventError{Err: errors.New("Guarantor claim transport subject is not an authorized claimant")}
	}
	fence, err := handler.Fence(ctx)
	if err != nil {
		return err
	}
	result, err := handler.Coordinator.AdmitClaim(ctx, claim.Body.CoverageAgreementBodyDigest, claim, fence)
	if err != nil {
		return err
	}
	if err = handler.sendWithoutAgreement(ctx, event.SenderAgentID, "claim-ingress-receipt", result.IngressReceipt,
		claim.Body.CoverageAgreementBodyDigest, []string{claim.Body.CoverageObligationID}, claim.Body.ExpiresAtUnix, fence); err != nil {
		return err
	}
	return handler.sendWithoutAgreement(ctx, event.SenderAgentID, "claim-admission-receipt", result.AdmissionReceipt,
		claim.Body.CoverageAgreementBodyDigest, []string{claim.Body.CoverageObligationID}, claim.Body.ExpiresAtUnix, fence)
}

func (handler *GuarantorProviderEventHandler) handleDecision(ctx context.Context,
	event *ClaimedCommerceProfileEvent, decision guarantor.AuthorizedClaimDecisionV1) error {
	if !containsString(decision.Body.DecisionAuthoritySubjects, event.SenderAgentID) {
		return PermanentGuarantorEventError{Err: errors.New("Guarantor decision transport subject is not a declared Decision Authority")}
	}
	fence, err := handler.Fence(ctx)
	if err != nil {
		return err
	}
	result, err := handler.Coordinator.AdmitClaimDecision(ctx, GuarantorAdmitDecisionInput{
		AgreementDigest: decision.Body.CoverageAgreementBodyDigest, Decision: decision}, fence)
	if err != nil {
		return err
	}
	return handler.sendWithoutAgreement(ctx, event.SenderAgentID, "claim-decision-admission-receipt", result.Receipt,
		decision.Body.CoverageAgreementBodyDigest, []string{decision.Body.CoverageObligationID}, decision.Body.ExpiresAtUnix, fence)
}

func (handler *GuarantorProviderEventHandler) handleCancellation(ctx context.Context,
	event *ClaimedCommerceProfileEvent, request guarantor.AuthorizedCoverageCancellationRequestV1) error {
	if request.Body.RequesterSubject != event.SenderAgentID &&
		!guarantorAgreementHasParticipant(request.CoverageAgreementBody, event.SenderAgentID) {
		return PermanentGuarantorEventError{Err: errors.New("Guarantor cancellation transport subject differs from its signed request")}
	}
	fence, err := handler.Fence(ctx)
	if err != nil {
		return err
	}
	now := handler.Coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() {
		return errors.New("Guarantor cancellation has no authority time")
	}
	receipt, _, err := handler.Coordinator.CancelCoverage(ctx, GuarantorCancelCoverageInput{
		Request: request, AdmittedAtUnix: uint64(now.Unix())}, fence)
	if err != nil {
		return err
	}
	agreementDigest, err := commerce.AgreementBodyDigest(request.CoverageAgreementBody)
	if err != nil {
		return err
	}
	return handler.sendWithoutAgreement(ctx, event.SenderAgentID, "cancellation-receipt", receipt,
		agreementDigest, []string{request.Body.CoverageObligationID}, request.Body.ExpiresAtUnix, fence)
}

func guarantorAgreementHasParticipant(agreement commerce.AgentAgreementBody, agentID string) bool {
	for _, participant := range agreement.Participants {
		if participant.AgentID == agentID {
			return true
		}
	}
	return false
}

func (handler *GuarantorProviderEventHandler) send(ctx context.Context, recipient, kind string, object any,
	agreement commerce.AgentAgreementBody, obligationIDs []string, objectExpiry uint64, fence commerce.WriterFence) error {
	digest, err := commerce.AgreementBodyDigest(agreement)
	if err != nil {
		return err
	}
	return handler.sendWithoutAgreement(ctx, recipient, kind, object, digest, obligationIDs, objectExpiry, fence)
}

func (handler *GuarantorProviderEventHandler) sendWithoutAgreement(ctx context.Context, recipient, kind string,
	object any, agreementDigest string, obligationIDs []string, objectExpiry uint64, fence commerce.WriterFence) error {
	now := handler.Coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("Guarantor outbound event has no authority time")
	}
	expires := objectExpiry
	ttl := handler.MaximumEventTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if ttl < time.Second || ttl > 30*24*time.Hour {
		return errors.New("Guarantor outbound event TTL is invalid or unbounded")
	}
	maximumExpiry := uint64(now.Add(ttl).Unix())
	if expires == 0 || expires > maximumExpiry {
		expires = maximumExpiry
	}
	created := uint64(now.Unix())
	if expires <= created {
		return errors.New("Guarantor outbound object is already expired")
	}
	event, err := guarantor.BuildCommerceProfileEventV1(ctx, kind, object, guarantor.CommerceEventContextV1{
		AgreementBodyDigest: agreementDigest, ObligationIDs: append([]string(nil), obligationIDs...),
		CreatedAtUnix: created, ExpiresAtUnix: expires}, handler.ImmutablePublisher)
	if err != nil {
		return err
	}
	resolution, err := handler.Engine.SendCommerceProfileEvent(ctx, recipient, event,
		guarantor.CommerceObjectVerifierV1{}, handler.PolicyRevision, fence)
	if err != nil {
		return err
	}
	if resolution.State != commerce.ActionTerminal && resolution.State != commerce.ActionAccepted {
		return errors.New("Guarantor outbound event did not reach a terminal Messenger result")
	}
	return nil
}
