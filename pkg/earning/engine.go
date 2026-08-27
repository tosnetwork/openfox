package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type FeatureGates struct {
	ObserveOnly        bool `json:"observe_only"`
	Publication        bool `json:"publication"`
	Contact            bool `json:"contact"`
	Agreement          bool `json:"agreement"`
	Execution          bool `json:"execution"`
	DirectPayment      bool `json:"direct_payment"`
	ExternalSettlement bool `json:"external_settlement"`
	TOSEscrow          bool `json:"tos_escrow"`
	AgentGuarantor     bool `json:"agent_guarantor"`
}

// AuthorizeAgreement signs every body-bound Agent-signature predicate for this
// Agent as one complete evidence group and sends the typed acceptance through
// Messenger's economic side-effect boundary.
func (engine *Engine) AuthorizeAgreement(ctx context.Context, agreementDigest, recipientAgentID string,
	identityKey ed25519.PrivateKey, verifier commerce.AgreementEvidenceVerifier, policyRevision uint64,
	fence commerce.WriterFence) (commerce.ActionResolution, EngagementRecord, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || !engine.permits("agreement", engine.Gates.Agreement, true) ||
		len(identityKey) != ed25519.PrivateKeySize || verifier == nil || recipientAgentID == "" {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement authorization is disabled or incomplete")
	}
	record, found := engine.Authority.Engagement(agreementDigest)
	if !found || record.State == EngagementCancelled || record.State == EngagementFailed {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement is not active")
	}
	subject := commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: engine.AgentID}
	var predicateIDs, targets []string
	var profileDigest string
	for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
		if predicate.AuthoritySubject == subject && predicate.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature {
			if profileDigest != "" && profileDigest != predicate.EvidenceProfileDigest {
				return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agent predicates use inconsistent evidence profiles")
			}
			profileDigest = predicate.EvidenceProfileDigest
			predicateIDs = append(predicateIDs, predicate.PredicateID)
			targets = append(targets, predicate.EvidenceTargetProjectionDigest)
		}
	}
	if len(predicateIDs) == 0 {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement has no Agent-signature predicates for this Agent")
	}
	var roles []string
	for _, participant := range record.Agreement.Body.Participants {
		if participant.AgentID == engine.AgentID {
			roles = append([]string(nil), participant.Roles...)
		}
	}
	acceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: record.Agreement.Body.AgreementID,
		AgreementVersion: record.Agreement.Body.Version, AgreementBodyDigest: record.AgreementDigest, AcceptingSubject: subject,
		AcceptedRoles: roles, PredicateIDs: predicateIDs, EvidenceTargetProjectionDigests: targets,
		ExpiresAtUnix: minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix)}, identityKey)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	evidence, err := commerce.AgentSignatureEvidence(record.Agreement.Body, acceptance)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	record, err = engine.Authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	canonicalAcceptance, err := codec.Marshal(acceptance)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	message := OutboundMessage{Kind: "agreement.accept", RecipientAgentIDs: []string{recipientAgentID},
		ContentType: commerce.AgreementAcceptanceContentType, Payload: canonicalAcceptance}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: []string{recipientAgentID}, EventKind: message.Kind, ContentType: message.ContentType, Payload: canonicalAcceptance})
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	subjectDigest, _ := codec.Digest("tos.agreement-authority-subject.v1", subject)
	predicateDigest, _ := codec.Digest("tos.agreement-predicate-set.v1", predicateIDs)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"agreement_body_digest": commerce.Digest32(record.AgreementDigest), "authority_subject_digest": commerce.Digest32(subjectDigest),
		"predicate_set_digest": commerce.Digest32(predicateDigest), "evidence_profile_digest": commerce.Digest32(profileDigest)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "agreement.authorize", fields, effectRequest, fence,
		policyRevision, engine.MandateDigest, "", "authorization-unsent", minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil {
		return admitted, record, err
	}
	if admitted.State == commerce.ActionAccepted || admitted.State == commerce.ActionTerminal {
		return admitted, record, nil
	}
	if admitted.State != commerce.ActionPrepared {
		return admitted, record, errors.New("Agreement authorization is not prepared")
	}
	resolved, err := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		if recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest); resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, record, err
		} else {
			resolved = recovered
		}
	}
	resolved, err = engine.recordResolution(action, resolved)
	return resolved, record, err
}

// SendAgreementEvidence sends one already profile-verified, body-bound
// authorization evidence object. It is used for non-generic profiles such as
// finalized wallet acceptance and cannot turn prose into authorization.
func (engine *Engine) SendAgreementEvidence(ctx context.Context, evidence commerce.AgreementAuthorizationEvidence,
	recipientAgentID string, verifier commerce.AgreementEvidenceVerifier, policyRevision uint64,
	fence commerce.WriterFence) (commerce.ActionResolution, EngagementRecord, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || verifier == nil || recipientAgentID == "" ||
		!engine.permits("agreement", engine.Gates.Agreement, true) || !evidenceSenderMatches(evidence.AuthoritySubject, engine.AgentID) {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement evidence send is disabled or not locally authorized")
	}
	record, found := engine.Authority.Engagement(evidence.AgreementBodyDigest)
	if !found {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement evidence has no exact local body")
	}
	updated, err := engine.Authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	canonical, err := codec.Marshal(evidence)
	if err != nil {
		return commerce.ActionResolution{}, updated, err
	}
	message := OutboundMessage{Kind: "agreement.evidence", RecipientAgentIDs: []string{recipientAgentID},
		ContentType: evidence.EvidenceContentType, Payload: canonical}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: []string{recipientAgentID}, EventKind: message.Kind,
		ContentType: message.ContentType, Payload: canonical})
	if err != nil {
		return commerce.ActionResolution{}, updated, err
	}
	subjectDigest, err := codec.Digest("tos.agreement-authority-subject.v1", evidence.AuthoritySubject)
	if err != nil {
		return commerce.ActionResolution{}, updated, err
	}
	predicateDigest, err := codec.Digest("tos.agreement-predicate-set.v1", evidence.PredicateIDs)
	if err != nil {
		return commerce.ActionResolution{}, updated, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"agreement_body_digest": commerce.Digest32(record.AgreementDigest), "authority_subject_digest": commerce.Digest32(subjectDigest),
		"predicate_set_digest": commerce.Digest32(predicateDigest), "evidence_profile_digest": commerce.Digest32(evidence.EvidenceProfileDigest)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "agreement.authorize", fields, effectRequest,
		fence, policyRevision, engine.MandateDigest, "", "authorization-unsent",
		minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.ActionResolution{}, updated, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil {
		return admitted, updated, err
	}
	if admitted.State == commerce.ActionAccepted || admitted.State == commerce.ActionTerminal {
		return admitted, updated, nil
	}
	if admitted.State != commerce.ActionPrepared {
		return admitted, updated, errors.New("Agreement evidence action is not prepared")
	}
	resolved, err := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, updated, err
		}
		resolved = recovered
	}
	resolved, err = engine.recordResolution(action, resolved)
	return resolved, updated, err
}

func minUint64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func (gates FeatureGates) permitsSideEffect(enabled bool) bool { return !gates.ObserveOnly && enabled }

func (engine *Engine) permits(scope string, enabled, createsCommitment bool) bool {
	return engine != nil && engine.Gates.permitsSideEffect(enabled) &&
		(engine.Operations == nil || engine.Operations.Permits(scope, createsCommitment))
}

type OutboundMessage struct {
	Kind              string   `json:"kind"`
	RecipientAgentIDs []string `json:"recipient_agent_ids"`
	ContentType       string   `json:"content_type"`
	Payload           []byte   `json:"payload"`
}

type AuthorizedSink interface {
	Submit(context.Context, commerce.AuthorizedAction, commerce.WriterFence, map[string]commerce.SemanticValue, []byte, OutboundMessage) (commerce.ActionResolution, error)
	ResolveAction(context.Context, string, string) (commerce.ActionResolution, error)
}

type PublicationSink interface {
	PublishIntent(context.Context, commerce.AuthorizedAction, commerce.WriterFence, map[string]commerce.SemanticValue,
		[]byte, commerce.SignedAgentIntent) (commerce.ActionResolution, error)
	WithdrawIntent(context.Context, commerce.AuthorizedAction, commerce.WriterFence, map[string]commerce.SemanticValue,
		[]byte, commerce.SignedAgentIntentWithdrawal) (commerce.ActionResolution, error)
	ResolveAction(context.Context, string, string) (commerce.ActionResolution, error)
}

func (engine *Engine) WithdrawIntent(ctx context.Context, carrierID string, withdrawal commerce.SignedAgentIntentWithdrawal,
	policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	sink := engine.publicationSink(carrierID)
	if engine == nil || engine.Authority == nil || sink == nil || !engine.permits("publication", engine.Gates.Publication, false) ||
		withdrawal.Body.IssuerAgentID != engine.AgentID || engine.Collector.Authority == nil {
		return commerce.ActionResolution{}, errors.New("Intent withdrawal is disabled or incomplete")
	}
	if err := commerce.VerifyIntentWithdrawal(withdrawal, engine.Collector.Authority, engine.now()); err != nil {
		return commerce.ActionResolution{}, err
	}
	canonical, err := codec.Marshal(withdrawal)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	operationDigest, err := codec.Digest("tos.agent-intent-withdrawal-operation.v1", withdrawal)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"carrier_id": commerce.ID(carrierID), "intent_object_id": commerce.ID(withdrawal.Body.ObjectID),
		"withdrawn_revision": commerce.U64(withdrawal.Body.IntentRevision), "withdrawal_operation_digest": commerce.Digest32(operationDigest)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "publication.withdraw", fields, canonical, fence,
		policyRevision, engine.MandateDigest, "", "published", minUint64(withdrawal.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil || admitted.State != commerce.ActionPrepared {
		return admitted, err
	}
	resolved, err := sink.WithdrawIntent(ctx, action, fence, fields, canonical, withdrawal)
	if err != nil {
		if recovered, resolveErr := sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest); resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, err
		} else {
			resolved = recovered
		}
	}
	return engine.recordResolution(action, resolved)
}

type Engine struct {
	OwnerID                    string
	AgentID                    string
	MandateDigest              string
	MinimumIndependentCarriers int
	Gates                      FeatureGates
	Collector                  Collector
	Authority                  EconomicAuthority
	Sink                       AuthorizedSink
	PublicationSink            PublicationSink
	PublicationSinks           map[string]PublicationSink
	Operations                 *OperationalController
	Now                        func() time.Time
}

type SettlementPrerequisiteChecker interface {
	ValidateSettlementPrerequisite(context.Context, string, commerce.AgreementObligation) error
}

// ReserveAgreement fixes Adapter prerequisites before capacity or exposure is
// committed and performs action admission, aggregate limit checking,
// reservation, and lifecycle transition atomically in PersonalAuthority.
func (engine *Engine) ReserveAgreement(ctx context.Context, agreementDigest string, reservation ExposureReservation,
	checker SettlementPrerequisiteChecker, policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, EngagementRecord, error) {
	if engine == nil || engine.Authority == nil || checker == nil || !engine.permits("portfolio", true, true) ||
		agreementDigest == "" || reservation.AgreementDigest != agreementDigest {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement reservation is incomplete")
	}
	record, found := engine.Authority.Engagement(agreementDigest)
	if !found || !engagementEligibleForReservation(record, engine.AgentID) {
		return commerce.ActionResolution{}, EngagementRecord{}, errors.New("Agreement is not eligible for ordinary or Provider pre-authorization reservation")
	}
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount != nil {
			if err := checker.ValidateSettlementPrerequisite(ctx, agreementDigest, obligation); err != nil {
				return commerce.ActionResolution{}, EngagementRecord{}, err
			}
		}
	}
	portfolioRevision, _, _ := engine.Authority.Snapshot()
	request := PortfolioReservationRequest{Reservation: reservation, TargetPortfolioRevision: portfolioRevision + 1}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	scopeDigest, err := codec.Digest("tos.portfolio-reservation-scope.v1", reservation)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "reservation_scope_digest": commerce.Digest32(scopeDigest),
		"target_revision": commerce.U64(request.TargetPortfolioRevision)}
	expiresAt := minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix)
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "portfolio.reserve", fields, canonical, fence,
		policyRevision, engine.MandateDigest, "", "agreed", expiresAt)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.ActionResolution{}, EngagementRecord{}, err
	}
	return engine.Authority.ReserveEngagement(action, fields, canonical, fence, request)
}

type ContactRequest struct {
	RecipientAgentID string `json:"recipient_agent_id"`
	IntentDigest     string `json:"intent_digest"`
	MediaType        string `json:"media_type"`
	Body             []byte `json:"body"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
}

func (engine *Engine) PublishIntent(ctx context.Context, carrierID string, intent commerce.SignedAgentIntent,
	policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	publicationSink := engine.publicationSink(carrierID)
	if engine == nil || engine.Authority == nil || publicationSink == nil || !engine.permits("publication", engine.Gates.Publication, true) ||
		carrierID == "" || engine.Collector.Authority == nil || intent.Body.IssuerAgentID != engine.AgentID {
		return commerce.ActionResolution{}, errors.New("Intent publication is disabled or has no issuer authority")
	}
	now := engine.now()
	if err := commerce.VerifyIntent(intent, engine.Collector.Authority, now); err != nil {
		return commerce.ActionResolution{}, err
	}
	canonical, err := codec.Marshal(intent)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	operationDigest, err := codec.Digest("tos.agent-intent-publication-operation.v1", intent)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"carrier_id": commerce.ID(carrierID), "intent_object_id": commerce.ID(intent.Body.ObjectID),
		"revision": commerce.U64(intent.Body.Revision), "operation_digest": commerce.Digest32(operationDigest)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "publication.publish", fields, canonical, fence,
		policyRevision, engine.MandateDigest, "", "not-published", minUint64(intent.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil || admitted.State != commerce.ActionPrepared {
		return admitted, err
	}
	resolved, err := publicationSink.PublishIntent(ctx, action, fence, fields, canonical, intent)
	if err != nil {
		queried, resolveErr := publicationSink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr != nil || queried.State == commerce.ActionUnknown {
			return admitted, err
		}
		resolved = queried
	}
	return engine.recordResolution(action, resolved)
}

func (engine *Engine) publicationSink(carrierID string) PublicationSink {
	if engine == nil {
		return nil
	}
	if sink := engine.PublicationSinks[carrierID]; sink != nil {
		return sink
	}
	return engine.PublicationSink
}

func (engine *Engine) Scout(ctx context.Context, query IntentQuery) ([]CandidateAssessment, error) {
	if engine == nil {
		return nil, errors.New("earning engine is unavailable")
	}
	return engine.Collector.Collect(ctx, query)
}

func (engine *Engine) Contact(ctx context.Context, candidate CandidateAssessment, request ContactRequest,
	fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || !engine.permits("contact", engine.Gates.Contact, true) ||
		!candidate.Decision.Eligible || candidate.IntentDigest == "" || candidate.IntentDigest != request.IntentDigest ||
		request.RecipientAgentID != candidate.Intent.Body.IssuerAgentID || request.MediaType == "" || len(request.Body) == 0 || len(request.Body) > 128<<10 {
		return commerce.ActionResolution{}, errors.New("autonomous contact is disabled or not authorized by the selected opportunity")
	}
	minimum := engine.MinimumIndependentCarriers
	if minimum == 0 {
		minimum = 2
	}
	if len(uniqueSorted(candidate.CarrierIDs)) < minimum {
		return commerce.ActionResolution{}, errors.New("autonomous contact requires independent Carrier corroboration")
	}
	now := engine.now()
	if request.ExpiresAtUnix <= uint64(now.Unix()) || request.ExpiresAtUnix > uint64(now.Add(24*time.Hour).Unix()) {
		return commerce.ActionResolution{}, errors.New("contact request expiry is invalid")
	}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	effectDigest, err := commerce.DownstreamEffectDescriptorDigest(canonical)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	instance, err := engine.Authority.AllocateInstance(commerce.AuthorityInstanceAllocationRequest{OwnerID: engine.OwnerID, AgentID: engine.AgentID,
		PurposeKind: "contact", MandateDigest: engine.MandateDigest, ApprovalDigestOrZero: zeroSHA256Digest(),
		DownstreamEffectDescriptorDigest: effectDigest, PredecessorAuthorityInstanceID: zeroSHA256Digest()}, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"recipient_agent_id": commerce.ID(request.RecipientAgentID), "intent_reference_digest": commerce.Digest32(request.IntentDigest),
		"authority_instance_id": commerce.Digest32(instance.AuthorityInstanceID)}
	eventKind := "text"
	if request.MediaType == commerce.IntentApplicationContentType {
		application, decodeErr := commerce.DecodeIntentApplication(request.Body)
		if decodeErr != nil || application.IntentDigest != candidate.IntentDigest || application.IntentIssuerAgentID != request.RecipientAgentID ||
			application.ApplicantAgentID != engine.AgentID || application.ExpiresAtUnix != request.ExpiresAtUnix {
			return commerce.ActionResolution{}, errors.New("typed Intent application does not match the selected opportunity")
		}
		eventKind = "intent.application"
	}
	message := OutboundMessage{Kind: eventKind, RecipientAgentIDs: []string{request.RecipientAgentID}, ContentType: request.MediaType, Payload: append([]byte(nil), request.Body...)}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), message.RecipientAgentIDs...), EventKind: message.Kind,
		ContentType: message.ContentType, Payload: append([]byte(nil), message.Payload...)})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "messenger.contact", fields, effectRequest, fence,
		candidate.Inventory.PolicyRevision, engine.MandateDigest, "", "no-contact", request.ExpiresAtUnix)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	if admitted.State != commerce.ActionPrepared {
		return admitted, nil
	}
	resolved, submitErr := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if submitErr != nil {
		queried, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr == nil && queried.State != commerce.ActionUnknown {
			resolved = queried
		} else {
			return admitted, submitErr
		}
	}
	return engine.recordResolution(action, resolved)
}

// SendTypedApplication sends a non-Agreement-authorizing control object under
// the generic repeat-instance Messenger action. The event kind remains typed
// and is interpreted only by its dedicated coordinator on receipt.
func (engine *Engine) SendTypedApplication(ctx context.Context, recipientAgentID, eventKind, contentType string,
	payload []byte, conversationScope any, policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || !engine.permits("private-handoff", engine.Gates.Execution, false) ||
		recipientAgentID == "" || len(payload) == 0 || len(payload) > 128<<10 {
		return commerce.ActionResolution{}, errors.New("typed economic control send is disabled or invalid")
	}
	switch eventKind {
	case "private.handoff.challenge", "private.handoff.acknowledgement", "private.handoff.status", "private.handoff.delete":
	default:
		return commerce.ActionResolution{}, errors.New("typed control event kind is not permitted by this surface")
	}
	message := OutboundMessage{Kind: eventKind, RecipientAgentIDs: []string{recipientAgentID}, ContentType: contentType,
		Payload: append([]byte(nil), payload...)}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), message.RecipientAgentIDs...), EventKind: eventKind, ContentType: contentType,
		Payload: append([]byte(nil), payload...)})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	effectDigest, err := commerce.DownstreamEffectDescriptorDigest(effectRequest)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	instance, err := engine.Authority.AllocateInstance(commerce.AuthorityInstanceAllocationRequest{OwnerID: engine.OwnerID, AgentID: engine.AgentID,
		PurposeKind: "messenger.send", MandateDigest: engine.MandateDigest, ApprovalDigestOrZero: zeroSHA256Digest(),
		DownstreamEffectDescriptorDigest: effectDigest, PredecessorAuthorityInstanceID: zeroSHA256Digest()}, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	recipientDigest, err := codec.Digest("tos.messenger-recipient-set.v1", []string{recipientAgentID})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	scopeDigest, err := codec.Digest("tos.messenger-conversation-scope.v1", conversationScope)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"recipient_set_digest": commerce.Digest32(recipientDigest), "conversation_scope_digest": commerce.Digest32(scopeDigest),
		"authority_instance_id": commerce.Digest32(instance.AuthorityInstanceID)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "messenger.send", fields, effectRequest, fence,
		policyRevision, engine.MandateDigest, "", "unsent", fence.Body.ExpiresAtUnix)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil || admitted.State != commerce.ActionPrepared {
		return admitted, err
	}
	resolved, err := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		if recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest); resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, err
		} else {
			resolved = recovered
		}
	}
	return engine.recordResolution(action, resolved)
}

// SendCommerceProfileEvent sends one already-authorized profile object through
// Messenger's generic non-model carriage. This method authorizes transport
// only; it neither creates nor upgrades authority for the embedded object.
func (engine *Engine) SendCommerceProfileEvent(ctx context.Context, recipientAgentID string,
	event commerce.CommerceProfileEventV1, verifier commerce.CommerceObjectVerifier, policyRevision uint64,
	fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || verifier == nil || recipientAgentID == "" ||
		!engine.permits("agent-guarantor", engine.Gates.AgentGuarantor, true) {
		return commerce.ActionResolution{}, errors.New("commerce profile send is disabled or incomplete")
	}
	now := engine.now()
	if err := commerce.VerifyCommerceProfileEventV1(event, now, verifier); err != nil {
		return commerce.ActionResolution{}, err
	}
	canonicalEvent, err := commerce.CanonicalCommerceProfileEventV1(event, now)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	message := OutboundMessage{Kind: "commerce.profile-event", RecipientAgentIDs: []string{recipientAgentID},
		ContentType: commerce.CommerceProfileEventContentType, Payload: canonicalEvent}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), message.RecipientAgentIDs...), EventKind: message.Kind,
		ContentType: message.ContentType, Payload: append([]byte(nil), message.Payload...)})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	effectDigest, err := commerce.DownstreamEffectDescriptorDigest(effectRequest)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	instance, err := engine.Authority.AllocateInstance(commerce.AuthorityInstanceAllocationRequest{OwnerID: engine.OwnerID,
		AgentID: engine.AgentID, PurposeKind: "messenger.send", MandateDigest: engine.MandateDigest,
		ApprovalDigestOrZero: zeroSHA256Digest(), DownstreamEffectDescriptorDigest: effectDigest,
		PredecessorAuthorityInstanceID: zeroSHA256Digest()}, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	recipientDigest, err := codec.Digest("tos.messenger-recipient-set.v1", []string{recipientAgentID})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	scopeDigest, err := codec.Digest("tos.messenger-conversation-scope.v1", struct {
		ProfileURI   string `json:"profile_uri"`
		ObjectKind   string `json:"object_kind"`
		ObjectDigest string `json:"object_digest"`
	}{event.ProfileURI, event.ObjectKind, event.ObjectDigest})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"recipient_set_digest": commerce.Digest32(recipientDigest), "conversation_scope_digest": commerce.Digest32(scopeDigest),
		"authority_instance_id": commerce.Digest32(instance.AuthorityInstanceID)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "messenger.send", fields,
		effectRequest, fence, policyRevision, engine.MandateDigest, "", "unsent",
		minUint64(event.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil || admitted.State != commerce.ActionPrepared {
		return admitted, err
	}
	resolved, err := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		if recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID,
			action.ExactRequestDigest); resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, err
		} else {
			resolved = recovered
		}
	}
	return engine.recordResolution(action, resolved)
}

func (engine *Engine) ProposeAgreement(ctx context.Context, body commerce.AgentAgreementBody, recipients []string,
	policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || !engine.permits("agreement", engine.Gates.Agreement, true) {
		return commerce.ActionResolution{}, errors.New("Agreement proposal is disabled")
	}
	if err := commerce.ValidateAgreementBody(body); err != nil {
		return commerce.ActionResolution{}, err
	}
	digest, err := commerce.AgreementBodyDigest(body)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	recipients = uniqueSorted(recipients)
	if len(recipients) != 1 {
		return commerce.ActionResolution{}, errors.New("one direct counterparty is required per Agreement proposal action")
	}
	recipientDigest, err := codec.Digest("tos.agreement-recipient-set.v1", recipients)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"agreement_body_digest": commerce.Digest32(digest), "recipient_set_digest": commerce.Digest32(recipientDigest)}
	now := engine.now()
	expiresAt := uint64(now.Add(time.Hour).Unix())
	if fence.Body.ExpiresAtUnix < expiresAt {
		expiresAt = fence.Body.ExpiresAtUnix
	}
	message := OutboundMessage{Kind: "agreement.propose", RecipientAgentIDs: recipients,
		ContentType: "application/vnd.tos.agent-agreement-body.v1+cbor", Payload: canonical}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), message.RecipientAgentIDs...), EventKind: message.Kind,
		ContentType: message.ContentType, Payload: append([]byte(nil), message.Payload...)})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "agreement.propose", fields, effectRequest, fence,
		policyRevision, engine.MandateDigest, "", "negotiating", expiresAt)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil || admitted.State != commerce.ActionPrepared {
		return admitted, err
	}
	resolved, err := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		if recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest); resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, err
		} else {
			resolved = recovered
		}
	}
	resolved, err = engine.recordResolution(action, resolved)
	if err != nil {
		return resolved, err
	}
	if resolved.State == commerce.ActionAccepted || resolved.State == commerce.ActionTerminal {
		eventID := resolved.SinkReference
		if eventID == "" {
			eventID = action.StableActionID
		}
		if _, err := engine.Authority.RecordAgreementProposal(body, engine.AgentID, eventID, action.StableActionID); err != nil {
			return resolved, err
		}
	}
	return resolved, nil
}

func zeroSHA256Digest() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func (engine *Engine) recordResolution(action commerce.AuthorizedAction, resolution commerce.ActionResolution) (commerce.ActionResolution, error) {
	if resolution.StableActionID != action.StableActionID || resolution.ExactRequestDigest != action.ExactRequestDigest || resolution.State == commerce.ActionUnknown {
		return commerce.ActionResolution{}, errors.New("side-effect sink returned an unrelated or unknown resolution")
	}
	return engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest, resolution.State, resolution.SinkReference, resolution.EvidenceRefs)
}

func (engine *Engine) now() time.Time {
	if engine.Now != nil {
		return engine.Now().UTC()
	}
	return time.Now().UTC()
}

func uniqueSorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if value == "" || write > 0 && result[write-1] == value {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}
