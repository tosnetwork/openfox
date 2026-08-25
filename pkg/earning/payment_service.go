package earning

import (
	"context"
	"errors"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type AgreementPaymentSink interface {
	SubmitPayment(context.Context, commerce.AuthorizedAction, commerce.WriterFence,
		map[string]commerce.SemanticValue, []byte, commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error)
	ResolvePayment(context.Context, commerce.AgreementPaymentRequest) (commerce.AgreementPaymentEvidence, error)
}

type PaymentService struct {
	Engine             *Engine
	Sink               AgreementPaymentSink
	Verifier           commerce.PaymentEvidenceVerifier
	ExternalSettlement bool
}

func (service PaymentService) Pay(ctx context.Context, request commerce.AgreementPaymentRequest,
	policyRevision uint64, fence commerce.WriterFence) (commerce.AgreementPaymentEvidence, SettlementLedgerRecord, EngagementRecord, error) {
	gate := service.Engine != nil && service.Engine.Gates.DirectPayment
	scope := "payment"
	actionKind := "payment.direct"
	if service.Engine != nil && service.ExternalSettlement {
		gate = service.Engine.Gates.ExternalSettlement
		scope = "external-settlement"
		actionKind = "settlement.external"
	}
	if service.Engine == nil || service.Engine.Authority == nil || service.Sink == nil || service.Verifier == nil ||
		!service.Engine.permits(scope, gate, false) || request.PayerAgentID != service.Engine.AgentID ||
		(service.ExternalSettlement && request.SchemaVersion != 2) || (!service.ExternalSettlement && request.SchemaVersion != 1) {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("direct Agreement payment is disabled or not this Agent's obligation")
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, actionKind, fields, canonical,
		fence, policyRevision, service.Engine.MandateDigest, "", "pending", minUint64(request.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = service.Engine.Authority.SignAction(action, fence)
	}
	if err != nil || action.StableActionID != request.StableActionID {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("payment action identity mismatch")
	}
	admitted, err := service.Engine.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	if admitted.State != commerce.ActionPrepared {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("payment is not in prepared state")
	}
	evidence, err := service.Sink.SubmitPayment(ctx, action, fence, fields, canonical, request)
	if err != nil {
		evidence, _ = service.Sink.ResolvePayment(ctx, request)
		if evidence.PaymentRequestDigest == "" {
			return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, err
		}
	}
	if err := commerce.VerifyAgreementPaymentEvidence(request, evidence, service.Verifier, service.Engine.now()); err != nil {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	evidenceDigest, _ := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	if _, err := service.Engine.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionAccepted, evidence.ExactTransferReference, []string{evidenceDigest}); err != nil {
		return commerce.AgreementPaymentEvidence{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	billing := BillingService{Engine: service.Engine}
	ledger, engagement, err := billing.ApplyPayment(request, evidence, service.Verifier, policyRevision, fence)
	return evidence, ledger, engagement, err
}
