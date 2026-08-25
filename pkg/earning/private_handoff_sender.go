package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type PrivateContentUploader interface {
	Upload(context.Context, commerce.SignedPrivateHandoffChallenge, commerce.SignedPrivateHandoffAuthorization,
		[]byte) (commerce.SignedPrivateHandoffAcknowledgement, error)
}

type PrivateHandoffSenderService struct {
	Engine    *Engine
	Uploader  PrivateContentUploader
	Resolver  commerce.HandoffAuthorityResolver
	SenderKey ed25519.PrivateKey
}

// Send releases only encrypted, Agreement-bound bytes. The disclosure action
// is derived before encryption (its stable ID is AAD), then signed only after
// the exact authorization control message exists. The receiver-selected bulk
// ingress cannot be replaced by remote content or model output.
func (service PrivateHandoffSenderService) Send(ctx context.Context, challenge commerce.SignedPrivateHandoffChallenge,
	mediaType string, canonicalPaths []string, plaintext []byte, maximumExpanded uint64, compressionProfile string,
	policyRevision uint64, fence commerce.WriterFence) (commerce.SignedPrivateHandoffAuthorization,
	commerce.SignedPrivateHandoffAcknowledgement, commerce.ActionResolution, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Engine.Sink == nil || service.Uploader == nil ||
		service.Resolver == nil || len(service.SenderKey) != ed25519.PrivateKeySize ||
		!service.Engine.permits("private-handoff", service.Engine.Gates.Execution, false) || len(plaintext) == 0 {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{},
			errors.New("private handoff sender is disabled or incomplete")
	}
	now := service.Engine.now()
	if err := commerce.VerifyPrivateHandoffChallenge(challenge, service.Resolver, now); err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	if challenge.Body.SenderAgentID != service.Engine.AgentID || challenge.Body.Direction != "input" {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{},
			errors.New("private handoff challenge addresses another sender or direction")
	}
	record, found := service.Engine.Authority.Engagement(challenge.Body.AgreementBodyDigest)
	if !found || record.State != EngagementReserved && record.State != EngagementFundingPending && record.State != EngagementReady {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{},
			errors.New("private handoff has no active reserved Agreement")
	}
	allowed := false
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == challenge.Body.ObligationID && obligation.ObligorAgentID == service.Engine.AgentID &&
			obligation.BeneficiaryAgentID == challenge.Body.ReceiverAgentID {
			for _, extension := range obligation.RequiredExtensions {
				allowed = allowed || extension == "tos.private-handoff.v1"
			}
		}
	}
	if !allowed {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{},
			errors.New("Agreement does not authorize this private disclosure")
	}
	plainDigest := sha256.Sum256(plaintext)
	manifest := commerce.PrivateContentManifest{ContentDigest: "sha256:" + hex.EncodeToString(plainDigest[:]), MediaType: mediaType,
		FileCount: uint32(len(canonicalPaths)), CanonicalPaths: append([]string(nil), canonicalPaths...), PlaintextBytes: uint64(len(plaintext)),
		MaximumExpandedBytes: maximumExpanded, CompressionProfileURI: compressionProfile}
	manifestDigest, err := codec.Digest("tos.private-content-manifest.v1", manifest)
	if err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.Engine.OwnerID), "agent_id": commerce.ID(service.Engine.AgentID),
		"agreement_body_digest": commerce.Digest32(challenge.Body.AgreementBodyDigest), "obligation_id": commerce.ID(challenge.Body.ObligationID),
		"recipient_id": commerce.ID(challenge.Body.ReceiverAgentID), "content_digest": commerce.Digest32(manifest.ContentDigest),
		"purpose_digest": commerce.Digest32(challenge.Body.PurposeDigest)}
	actionID, _, err := commerce.DeriveStableActionID("disclosure.release", fields)
	if err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	ciphertext, authorization, err := commerce.SealPrivateContent(challenge, manifest, plaintext, actionID, service.SenderKey)
	if err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	canonicalAuthorization, err := codec.Marshal(authorization)
	if err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	message := OutboundMessage{Kind: "private.handoff.authorization", RecipientAgentIDs: []string{challenge.Body.ReceiverAgentID},
		ContentType: "application/vnd.tos.private-handoff-authorization.v1+cbor", Payload: canonicalAuthorization}
	effectRequest, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: append([]string(nil), message.RecipientAgentIDs...), EventKind: message.Kind,
		ContentType: message.ContentType, Payload: append([]byte(nil), message.Payload...)})
	if err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "disclosure.release", fields,
		effectRequest, fence, policyRevision, service.Engine.MandateDigest, "", "challenge_issued",
		minUint64(challenge.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil || action.StableActionID != actionID {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{},
			errors.New("private disclosure identity is inconsistent")
	}
	action, err = service.Engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.SignedPrivateHandoffAuthorization{}, commerce.SignedPrivateHandoffAcknowledgement{}, commerce.ActionResolution{}, err
	}
	resolution, err := service.Engine.Authority.Admit(action, fields, effectRequest, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionAccepted {
		return authorization, commerce.SignedPrivateHandoffAcknowledgement{}, resolution, errors.New("private disclosure action was not admitted")
	}
	if resolution.State == commerce.ActionPrepared {
		resolution, err = service.Engine.Sink.Submit(ctx, action, fence, fields, effectRequest, message)
		if err != nil {
			if recovered, resolveErr := service.Engine.Sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest); resolveErr != nil || recovered.State == commerce.ActionUnknown {
				return authorization, commerce.SignedPrivateHandoffAcknowledgement{}, resolution, err
			} else {
				resolution = recovered
			}
		}
		if _, err = service.Engine.recordResolution(action, resolution); err != nil {
			return authorization, commerce.SignedPrivateHandoffAcknowledgement{}, resolution, err
		}
	}
	acknowledgement, err := service.Uploader.Upload(ctx, challenge, authorization, ciphertext)
	if err != nil {
		return authorization, commerce.SignedPrivateHandoffAcknowledgement{}, resolution, err
	}
	if err := commerce.VerifyPrivateHandoffAcknowledgement(acknowledgement, service.Resolver, now); err != nil ||
		acknowledgement.Record.SenderDisclosureActionID != action.StableActionID || acknowledgement.Record.ContentManifestDigest != manifestDigest {
		return authorization, commerce.SignedPrivateHandoffAcknowledgement{}, resolution, errors.New("private handoff acknowledgement does not bind the disclosure")
	}
	ackDigest, _ := commerce.PrivateHandoffAcknowledgementDigest(acknowledgement)
	resolution, err = service.Engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, "private-handoff:"+challenge.Body.HandoffID, []string{ackDigest})
	return authorization, acknowledgement, resolution, err
}
