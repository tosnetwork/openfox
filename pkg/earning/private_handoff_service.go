package earning

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/privateingress"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type PrivateIngress interface {
	IssueChallenge(commerce.PrivateHandoffChallengeBody) (commerce.SignedPrivateHandoffChallenge, error)
	Accept(context.Context, string, commerce.SignedPrivateHandoffAuthorization, []byte,
		commerce.AuthorizedAction, commerce.WriterFence) (commerce.AcceptedPrivateContentRecord, error)
	Acknowledge(commerce.AcceptedPrivateContentRecord) (commerce.SignedPrivateHandoffAcknowledgement, error)
}

type PrivateHandoffService struct {
	Engine  *Engine
	Ingress PrivateIngress
}

func (service PrivateHandoffService) IssueChallenge(agreementDigest, obligationID, senderAgentID,
	handoffID, purposeDigest, ingressProfile, ingressInstance, retentionDigest string,
	maximumPlaintext uint64, maximumFiles uint32, mediaTypes []string, expiresAt, deleteNotAfter time.Time,
	fence commerce.WriterFence) (commerce.SignedPrivateHandoffChallenge, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Ingress == nil ||
		!service.Engine.permits("private-handoff", service.Engine.Gates.Execution, false) {
		return commerce.SignedPrivateHandoffChallenge{}, errors.New("private handoff is disabled")
	}
	now := service.Engine.now()
	if err := service.Engine.Authority.ConfirmCurrentWriterFence(fence, now); err != nil {
		return commerce.SignedPrivateHandoffChallenge{}, err
	}
	record, found := service.Engine.Authority.Engagement(agreementDigest)
	if !found || record.State != EngagementReserved && record.State != EngagementFundingPending && record.State != EngagementReady {
		return commerce.SignedPrivateHandoffChallenge{}, errors.New("private handoff has no reserved Agreement")
	}
	valid := false
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID && obligation.ObligorAgentID == senderAgentID &&
			obligation.BeneficiaryAgentID == service.Engine.AgentID {
			for _, extension := range obligation.RequiredExtensions {
				valid = valid || extension == "tos.private-handoff.v1"
			}
		}
	}
	if !valid || maximumPlaintext > ^uint64(0)-16 {
		return commerce.SignedPrivateHandoffChallenge{}, errors.New("Agreement does not authorize this private input")
	}
	body := commerce.PrivateHandoffChallengeBody{SchemaVersion: 1, HandoffID: handoffID,
		AgreementBodyDigest: agreementDigest, ObligationID: obligationID, SenderAgentID: senderAgentID,
		ReceiverAgentID: service.Engine.AgentID, Direction: "input", PurposeDigest: purposeDigest,
		IngressProfileURI: ingressProfile, IngressInstanceID: ingressInstance, MaximumPlaintextBytes: maximumPlaintext,
		MaximumCiphertextBytes: maximumPlaintext + 16, MaximumFiles: maximumFiles, AcceptedMediaTypes: append([]string(nil), mediaTypes...),
		RetentionPolicyDigest: retentionDigest, IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(expiresAt.UTC().Unix()),
		DeleteNotAfterUnix: uint64(deleteNotAfter.UTC().Unix())}
	return service.Ingress.IssueChallenge(body)
}

func (service PrivateHandoffService) IssueAndSendChallenge(ctx context.Context, agreementDigest, obligationID, senderAgentID,
	handoffID, purposeDigest, ingressProfile, ingressInstance, retentionDigest string,
	maximumPlaintext uint64, maximumFiles uint32, mediaTypes []string, expiresAt, deleteNotAfter time.Time,
	policyRevision uint64, fence commerce.WriterFence) (commerce.SignedPrivateHandoffChallenge, commerce.ActionResolution, error) {
	challenge, err := service.IssueChallenge(agreementDigest, obligationID, senderAgentID, handoffID, purposeDigest,
		ingressProfile, ingressInstance, retentionDigest, maximumPlaintext, maximumFiles, mediaTypes, expiresAt, deleteNotAfter, fence)
	if err != nil {
		return commerce.SignedPrivateHandoffChallenge{}, commerce.ActionResolution{}, err
	}
	canonical, err := codec.Marshal(challenge)
	if err != nil {
		return commerce.SignedPrivateHandoffChallenge{}, commerce.ActionResolution{}, err
	}
	resolution, err := service.Engine.SendTypedApplication(ctx, senderAgentID, "private.handoff.challenge",
		"application/vnd.tos.private-handoff-challenge.v1+cbor", canonical,
		struct {
			AgreementDigest string `json:"agreement_digest"`
			HandoffID       string `json:"handoff_id"`
		}{agreementDigest, handoffID}, policyRevision, fence)
	return challenge, resolution, err
}

func (service PrivateHandoffService) Accept(ctx context.Context, challenge commerce.SignedPrivateHandoffChallenge,
	authorization commerce.SignedPrivateHandoffAuthorization, ciphertext []byte, policyRevision uint64,
	fence commerce.WriterFence) (commerce.SignedPrivateHandoffAcknowledgement, EngagementRecord, error) {
	if service.Engine == nil || service.Engine.Authority == nil || service.Ingress == nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, errors.New("private handoff is unavailable")
	}
	challengeDigest, err := commerce.PrivateHandoffChallengeDigest(challenge.Body)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	canonical, fields, err := privateingress.UploadAuthorizationMaterial(service.Engine.OwnerID, service.Engine.AgentID, challenge, authorization)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "content.upload", fields, canonical,
		fence, policyRevision, service.Engine.MandateDigest, "", "challenge_issued",
		minUint64(challenge.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	action, err = service.Engine.Authority.SignAction(action, fence)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	resolution, err := service.Engine.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionAccepted {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, errors.New("private upload action was not admitted")
	}
	accepted, err := service.Ingress.Accept(ctx, challengeDigest, authorization, ciphertext, action, fence)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	acknowledgement, err := service.Ingress.Acknowledge(accepted)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	ackDigest, err := commerce.PrivateHandoffAcknowledgementDigest(acknowledgement)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
	}
	if resolution.State == commerce.ActionPrepared {
		if _, err := service.Engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionAccepted, "private-ingress:"+challengeDigest, []string{ackDigest}); err != nil {
			return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, err
		}
	}
	engagement, err := service.Engine.Authority.BindAcceptedPrivateInput(challenge.Body.AgreementBodyDigest,
		challenge.Body.ObligationID, accepted)
	return acknowledgement, engagement, err
}

func (service PrivateHandoffService) AcceptAndSendAcknowledgement(ctx context.Context,
	challenge commerce.SignedPrivateHandoffChallenge, authorization commerce.SignedPrivateHandoffAuthorization,
	ciphertext []byte, policyRevision uint64, fence commerce.WriterFence) (commerce.SignedPrivateHandoffAcknowledgement,
	EngagementRecord, commerce.ActionResolution, error) {
	acknowledgement, engagement, err := service.Accept(ctx, challenge, authorization, ciphertext, policyRevision, fence)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, EngagementRecord{}, commerce.ActionResolution{}, err
	}
	canonical, err := codec.Marshal(acknowledgement)
	if err != nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, engagement, commerce.ActionResolution{}, err
	}
	resolution, err := service.Engine.SendTypedApplication(ctx, challenge.Body.SenderAgentID, "private.handoff.acknowledgement",
		"application/vnd.tos.private-handoff-acknowledgement.v1+cbor", canonical,
		struct {
			AgreementDigest string `json:"agreement_digest"`
			HandoffID       string `json:"handoff_id"`
		}{challenge.Body.AgreementBodyDigest, challenge.Body.HandoffID}, policyRevision, fence)
	return acknowledgement, engagement, resolution, err
}

func AcceptedInputSetDigest(records []commerce.AcceptedPrivateContentRecord) (string, error) {
	return codec.Digest("tos.accepted-private-input-set.v1", records)
}

type BoundAcceptedPrivateInput struct {
	ObligationID string                                `json:"obligation_id"`
	Record       commerce.AcceptedPrivateContentRecord `json:"record"`
}

type BoundPrivateHandoffChallenge struct {
	ObligationID    string `json:"obligation_id"`
	ChallengeDigest string `json:"challenge_digest"`
	SendActionID    string `json:"send_action_id"`
}

func AcceptedInputSetDigestForObligation(records []BoundAcceptedPrivateInput, obligationID string) (string, error) {
	if obligationID == "" {
		return "", errors.New("private input obligation is absent")
	}
	var selected []commerce.AcceptedPrivateContentRecord
	for _, bound := range records {
		if bound.ObligationID == obligationID {
			selected = append(selected, bound.Record)
		}
	}
	return AcceptedInputSetDigest(selected)
}

func AcceptedExecutionInputSetDigest(record EngagementRecord, executionObligationID string) (string, bool, int, error) {
	if _, found := obligationByID(record, executionObligationID); !found {
		return "", false, 0, errors.New("execution obligation is absent")
	}
	reachable := map[string]bool{}
	var visit func(string) error
	visit = func(obligationID string) error {
		if reachable[obligationID] {
			return nil
		}
		obligation, found := obligationByID(record, obligationID)
		if !found {
			return errors.New("execution input dependency is absent")
		}
		reachable[obligationID] = true
		for _, dependency := range obligation.DependsOnObligationIDs {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(executionObligationID); err != nil {
		return "", false, 0, err
	}
	required := false
	for obligationID := range reachable {
		obligation, _ := obligationByID(record, obligationID)
		for _, extension := range obligation.RequiredExtensions {
			if extension == "tos.private-handoff.v1" {
				required = true
			}
		}
	}
	var selected []BoundAcceptedPrivateInput
	for _, input := range record.BoundPrivateInputs {
		if reachable[input.ObligationID] {
			selected = append(selected, input)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].ObligationID+"\x00"+selected[i].Record.ChallengeDigest <
			selected[j].ObligationID+"\x00"+selected[j].Record.ChallengeDigest
	})
	if !required && len(selected) == 0 {
		// Public/profile-bound inputs are already committed by the exact
		// execution obligation. Reuse that commitment so the local Gate and
		// any chain-specific Gate authorize the same bytes rather than two
		// unrelated notions of an empty input set.
		execution, _ := obligationByID(record, executionObligationID)
		committed := ""
		for _, extension := range execution.RequiredExtensions {
			if strings.HasPrefix(extension, "tos.input.") {
				candidate := "sha256:" + strings.TrimPrefix(extension, "tos.input.")
				if committed != "" && committed != candidate {
					return "", false, 0, errors.New("execution obligation has conflicting input commitments")
				}
				committed = candidate
			}
		}
		if committed != "" && containsString(execution.AttachmentDigests, committed) {
			return committed, false, 0, nil
		}
	}
	digest, err := codec.Digest("tos.accepted-execution-input-set.v1", selected)
	return digest, required, len(selected), err
}
