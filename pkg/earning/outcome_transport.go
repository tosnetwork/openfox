package earning

import (
	"context"
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type OutcomePublicationSink interface {
	PublishOperation(context.Context, commerce.AuthorizedAction, commerce.WriterFence,
		commerce.OperationCarrierRequestV1) (commerce.ActionResolution, error)
	ResolveAction(context.Context, string, string) (commerce.ActionResolution, error)
}

// OutcomePublicationPolicy is the owner-controlled declassification boundary.
// The generic publication gate alone is intentionally insufficient because a
// valid signed Outcome can still contain private evidence or linkable fields.
type OutcomePublicationPolicy interface {
	AuthorizeOutcomePublication(commerce.OperationCarrierRequestV1) error
}

type PublicOutcomePublicationPolicyV1 struct {
	AllowedAudiencePolicyDigests map[string]struct{}
	AllowedAssertionProfiles     map[string]struct{}
	AllowExtensions              bool
}

func (policy PublicOutcomePublicationPolicyV1) AuthorizeOutcomePublication(request commerce.OperationCarrierRequestV1) error {
	if _, allowed := policy.AllowedAudiencePolicyDigests[request.AudiencePolicyDigest]; !allowed {
		return errors.New("outcome audience policy is not approved for public disclosure")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	var body commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil || envelope.Body.AudienceDescriptor != "public" ||
		codec.Unmarshal(request.EventPayload, &body) != nil {
		return errors.New("outcome is not a public Agent Operation")
	}
	if _, allowed := policy.AllowedAssertionProfiles[body.AssertionProfileURI]; !allowed {
		return errors.New("outcome assertion profile is not approved for public disclosure")
	}
	if !policy.AllowExtensions && len(request.Artifacts.ExtensionSet.Extensions) != 0 {
		return errors.New("public outcome extensions require an explicit disclosure policy")
	}
	for _, item := range request.Artifacts.EvidenceManifest.EvidenceItems {
		if item.Visibility != "public" || item.AudienceDigest != request.AudiencePolicyDigest {
			return errors.New("public outcome references broader or private evidence")
		}
	}
	return nil
}

func (engine *Engine) PublishOutcome(ctx context.Context, request commerce.OperationCarrierRequestV1,
	policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	sink := engine.outcomePublicationSink(request.CarrierID)
	if engine == nil || engine.Authority == nil || sink == nil || engine.OutcomePublicationPolicy == nil ||
		!engine.permits("publication", engine.Gates.Publication, false) ||
		commerce.ValidateOperationCarrierRequestV1(request) != nil {
		return commerce.ActionResolution{}, errors.New("outcome publication is disabled or invalid")
	}
	if err := engine.OutcomePublicationPolicy.AuthorizeOutcomePublication(request); err != nil {
		return commerce.ActionResolution{}, err
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != engine.AgentID || request.CarrierID == "" {
		return commerce.ActionResolution{}, errors.New("outcome publication does not belong to this Agent")
	}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1(engine.OwnerID, engine.AgentID, request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	expiresAt := fence.Body.ExpiresAtUnix
	if envelope.Body.ExpiresAtUnix != 0 {
		expiresAt = minUint64(expiresAt, envelope.Body.ExpiresAtUnix)
	}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "operation.publish", fields, canonical, fence,
		policyRevision, engine.MandateDigest, "", "not-published", expiresAt)
	if err == nil {
		action, err = engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil {
		return admitted, err
	}
	if admitted.State == commerce.ActionTerminal {
		recovered, resolveErr := sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr == nil && recovered.State != commerce.ActionUnknown {
			return recovered, nil
		}
		if resolveErr != nil {
			return admitted, resolveErr
		}
	}
	if admitted.State != commerce.ActionPrepared && admitted.State != commerce.ActionTerminal {
		return admitted, errors.New("outcome publication is not prepared")
	}
	resolved, err := sink.PublishOperation(ctx, action, fence, request)
	if err != nil {
		recovered, resolveErr := sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, err
		}
		resolved = recovered
	}
	if admitted.State == commerce.ActionTerminal {
		if resolved.State != commerce.ActionTerminal || resolved.StableActionID != action.StableActionID || resolved.ExactRequestDigest != action.ExactRequestDigest {
			return admitted, errors.New("recovered outcome Carrier did not preserve the terminal Action identity")
		}
		return resolved, nil
	}
	return engine.recordResolution(action, resolved)
}

func (engine *Engine) SendOutcomePrivate(ctx context.Context, request commerce.OperationPrivateRequestV1,
	policyRevision uint64, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if engine == nil || engine.Authority == nil || engine.Sink == nil || !engine.permits("contact", engine.Gates.Contact, false) ||
		commerce.ValidateOperationPrivateRequestV1(request) != nil {
		return commerce.ActionResolution{}, errors.New("private outcome send is disabled or invalid")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != engine.AgentID {
		return commerce.ActionResolution{}, errors.New("private outcome does not belong to this Agent")
	}
	privateCanonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	message := OutboundMessage{Kind: "operation.outcome", RecipientAgentIDs: append([]string(nil), request.RecipientAgentIDs...),
		ContentType: "application/vnd.tos.operation-outcome-private+cbor", Payload: privateCanonical}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), request.RecipientAgentIDs...), EventKind: message.Kind, ContentType: message.ContentType, Payload: privateCanonical})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields, err := commerce.OperationPrivateSendSemanticFieldsV1(engine.OwnerID, engine.AgentID, request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	expiresAt := fence.Body.ExpiresAtUnix
	if envelope.Body.ExpiresAtUnix != 0 {
		expiresAt = minUint64(expiresAt, envelope.Body.ExpiresAtUnix)
	}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "operation.private-send", fields, effectRequest, fence,
		policyRevision, engine.MandateDigest, "", "unsent", expiresAt)
	if err == nil {
		action, err = engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil {
		return admitted, err
	}
	if admitted.State == commerce.ActionAccepted || admitted.State == commerce.ActionTerminal {
		recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr == nil && recovered.State != commerce.ActionUnknown {
			return recovered, nil
		}
		if resolveErr != nil {
			return admitted, resolveErr
		}
	}
	if admitted.State != commerce.ActionPrepared && admitted.State != commerce.ActionAccepted && admitted.State != commerce.ActionTerminal {
		return admitted, errors.New("private outcome send is not prepared")
	}
	resolved, err := engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
	if err != nil {
		recovered, resolveErr := engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolveErr != nil || recovered.State == commerce.ActionUnknown {
			return admitted, err
		}
		resolved = recovered
	}
	if admitted.State == commerce.ActionAccepted || admitted.State == commerce.ActionTerminal {
		if resolved.StableActionID != action.StableActionID || resolved.ExactRequestDigest != action.ExactRequestDigest ||
			(resolved.State != commerce.ActionAccepted && resolved.State != commerce.ActionTerminal) {
			return admitted, errors.New("recovered private outcome send did not preserve the accepted Action identity")
		}
		return resolved, nil
	}
	return engine.recordResolution(action, resolved)
}

func (engine *Engine) outcomePublicationSink(carrierID string) OutcomePublicationSink {
	if engine == nil {
		return nil
	}
	if engine.OutcomePublicationSinks != nil {
		return engine.OutcomePublicationSinks[carrierID]
	}
	return nil
}

type OutcomeCarrierResult struct {
	Request          commerce.OperationCarrierRequestV1    `json:"request"`
	EventBody        commerce.OperationOutcomeEventBodyV1  `json:"event_body"`
	ActorAgentID     string                                `json:"actor_agent_id"`
	StoredAtUnix     uint64                                `json:"stored_at_unix"`
	CarrierSequence  uint64                                `json:"carrier_sequence"`
	Provenance       string                                `json:"provenance"`
	Receipt          commerce.OperationSubmissionReceiptV1 `json:"receipt"`
	CarrierPublicKey string                                `json:"carrier_public_key"`
}

type OutcomeCarrierPage struct {
	CarrierID string                 `json:"carrier_id"`
	Results   []OutcomeCarrierResult `json:"results"`
	Next      string                 `json:"next_cursor,omitempty"`
}

type OutcomeCarrierQuery struct {
	EventKinds           []commerce.OperationOutcomeEventKind
	AssertionProfileURIs []string
	SubjectProfileURI    string
	SubjectID            string
	ActorAgentID         string
	Limit                uint32
	Cursor               string
	Wait                 time.Duration
}

type OutcomeCarrier interface {
	ID() string
	SearchOutcomes(context.Context, OutcomeCarrierQuery) (OutcomeCarrierPage, error)
}
