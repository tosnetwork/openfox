package earning

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/fault"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type PrivateHandoffContent struct {
	MediaType             string
	CanonicalPaths        []string
	Plaintext             []byte
	MaximumExpandedBytes  uint64
	CompressionProfileURI string
}

type PrivateHandoffContentSource interface {
	ContentForChallenge(context.Context, commerce.SignedPrivateHandoffChallenge) (PrivateHandoffContent, error)
}

type PrivateHandoffReceiverPolicy struct {
	IngressProfileURI     string
	IngressInstanceID     string
	PurposeDigest         string
	RetentionPolicyDigest string
	MaximumPlaintextBytes uint64
	MaximumFiles          uint32
	AcceptedMediaTypes    []string
	ChallengeTTL          time.Duration
	RetentionTTL          time.Duration
}

func (policy PrivateHandoffReceiverPolicy) validate() error {
	if policy.IngressProfileURI == "" || policy.IngressInstanceID == "" || !canonicalSHA256(policy.PurposeDigest) ||
		!canonicalSHA256(policy.RetentionPolicyDigest) || policy.MaximumPlaintextBytes == 0 || policy.MaximumPlaintextBytes > 1<<30 ||
		policy.MaximumFiles == 0 || policy.MaximumFiles > 10000 || len(policy.AcceptedMediaTypes) == 0 || len(policy.AcceptedMediaTypes) > 64 ||
		policy.ChallengeTTL < time.Minute || policy.ChallengeTTL > 24*time.Hour || policy.RetentionTTL < policy.ChallengeTTL ||
		policy.RetentionTTL > 90*24*time.Hour {
		return errors.New("private handoff receiver policy is invalid or unbounded")
	}
	if !sort.StringsAreSorted(policy.AcceptedMediaTypes) {
		return errors.New("private handoff media types must be sorted")
	}
	for index, value := range policy.AcceptedMediaTypes {
		if value == "" || index > 0 && policy.AcceptedMediaTypes[index-1] == value {
			return errors.New("private handoff media types are invalid or duplicated")
		}
	}
	return nil
}

// PrivateHandoffAutonomy closes the control-plane loop around the existing
// sender and receiver primitives. Receiver challenges are derived from exact
// Agreement obligations; sender bytes come only from a local owner-configured
// source. Messenger events never carry bulk plaintext or select a file path.
type PrivateHandoffAutonomy struct {
	Engine         *Engine
	Inbox          PrivateHandoffInbox
	Receiver       *PrivateHandoffService
	ReceiverPolicy PrivateHandoffReceiverPolicy
	Sender         *PrivateHandoffSenderService
	Content        PrivateHandoffContentSource
	Fence          WriterFenceProvider
	PolicyRevision uint64
	Health         func() error
}

func (service *PrivateHandoffAutonomy) Process(ctx context.Context, maximum uint32) (uint32, error) {
	if service == nil || service.Engine == nil || service.Engine.Authority == nil || service.Fence == nil ||
		maximum == 0 || maximum > 1000 {
		return 0, errors.New("private handoff autonomy is incomplete or unbounded")
	}
	if service.Health != nil {
		if err := service.Health(); err != nil {
			return 0, err
		}
	}
	processed := uint32(0)
	if service.Receiver != nil {
		if err := service.ReceiverPolicy.validate(); err != nil {
			return 0, err
		}
		for _, record := range service.Engine.Authority.EngagementSnapshot() {
			if processed >= maximum {
				break
			}
			if record.State != EngagementReserved && record.State != EngagementFundingPending && record.State != EngagementReady {
				continue
			}
			for _, obligation := range record.Agreement.Body.Obligations {
				if processed >= maximum || obligation.BeneficiaryAgentID != service.Engine.AgentID ||
					!containsString(obligation.RequiredExtensions, "tos.private-handoff.v1") || hasBoundInput(record, obligation.ObligationID) ||
					hasIssuedChallenge(record, obligation.ObligationID) {
					continue
				}
				fence, err := service.Fence(ctx)
				if err != nil {
					return processed, err
				}
				now := service.Engine.now()
				handoffID, err := codec.Digest("tos.private-handoff-id.v1", struct {
					AgreementDigest string `json:"agreement_digest"`
					ObligationID    string `json:"obligation_id"`
					ReceiverAgentID string `json:"receiver_agent_id"`
				}{record.AgreementDigest, obligation.ObligationID, service.Engine.AgentID})
				if err != nil {
					return processed, err
				}
				handoffID = "handoff:" + handoffID[len("sha256:"):]
				challenge, resolution, err := service.Receiver.IssueAndSendChallenge(ctx, record.AgreementDigest,
					obligation.ObligationID, obligation.ObligorAgentID, handoffID, service.ReceiverPolicy.PurposeDigest,
					service.ReceiverPolicy.IngressProfileURI, service.ReceiverPolicy.IngressInstanceID,
					service.ReceiverPolicy.RetentionPolicyDigest, service.ReceiverPolicy.MaximumPlaintextBytes,
					service.ReceiverPolicy.MaximumFiles, service.ReceiverPolicy.AcceptedMediaTypes,
					now.Add(service.ReceiverPolicy.ChallengeTTL), now.Add(service.ReceiverPolicy.RetentionTTL),
					service.PolicyRevision, fence)
				if err != nil {
					return processed, err
				}
				if resolution.State != commerce.ActionAccepted && resolution.State != commerce.ActionTerminal {
					return processed, errors.New("private handoff challenge send remains ambiguous")
				}
				challengeDigest, err := commerce.PrivateHandoffChallengeDigest(challenge.Body)
				if err != nil {
					return processed, err
				}
				if _, err := service.Engine.Authority.RecordPrivateHandoffChallenge(record.AgreementDigest,
					obligation.ObligationID, challengeDigest, resolution.StableActionID); err != nil {
					return processed, err
				}
				processed++
			}
		}
	}
	for processed < maximum && service.Inbox.Client != nil {
		event, err := service.Inbox.ClaimNext(ctx)
		if err != nil {
			return processed, err
		}
		if event == nil {
			break
		}
		if event.Challenge == nil {
			// Authorization and acknowledgement are advisory Messenger
			// copies. The receiver ingress journal and verified HTTP
			// acknowledgement are the authoritative acceptance path.
			if err := service.Inbox.Complete(ctx, event); err != nil {
				return processed, err
			}
			processed++
			continue
		}
		if service.Sender == nil || service.Content == nil {
			_ = service.Inbox.Reject(ctx, event.EventID, event.LeaseID, fault.CodeApprovalRequired)
			return processed, errors.New("private handoff challenge arrived without an owner-configured sender source")
		}
		var challenge commerce.SignedPrivateHandoffChallenge
		if err := codec.Unmarshal(event.Challenge.CanonicalChallenge, &challenge); err != nil {
			_ = service.Inbox.Reject(ctx, event.EventID, event.LeaseID, fault.CodeNotAuthentic)
			return processed, err
		}
		content, err := service.Content.ContentForChallenge(ctx, challenge)
		if err != nil {
			return processed, err
		}
		fence, err := service.Fence(ctx)
		if err != nil {
			return processed, err
		}
		_, _, resolution, err := service.Sender.Send(ctx, challenge, content.MediaType, content.CanonicalPaths,
			content.Plaintext, content.MaximumExpandedBytes, content.CompressionProfileURI, service.PolicyRevision, fence)
		zeroPrivateContent(content.Plaintext)
		if err != nil {
			return processed, err
		}
		if resolution.State != commerce.ActionTerminal {
			return processed, errors.New("private disclosure did not reach verified terminal acknowledgement")
		}
		if err := service.Inbox.Complete(ctx, event); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func hasBoundInput(record EngagementRecord, obligationID string) bool {
	for _, input := range record.BoundPrivateInputs {
		if input.ObligationID == obligationID {
			return true
		}
	}
	return false
}

func hasIssuedChallenge(record EngagementRecord, obligationID string) bool {
	for _, challenge := range record.PrivateHandoffChallenges {
		if challenge.ObligationID == obligationID {
			return true
		}
	}
	return false
}

func zeroPrivateContent(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
