package earning

import (
	"context"
	"errors"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type DeliveryReleaseRequest struct {
	AgreementBodyDigest       string `json:"agreement_body_digest"`
	ObligationID              string `json:"obligation_id"`
	RecipientAgentID          string `json:"recipient_agent_id"`
	DeliverableManifestDigest string `json:"deliverable_manifest_digest"`
}

func (service BillingService) ApplyPayment(request commerce.AgreementPaymentRequest, evidence commerce.AgreementPaymentEvidence,
	verifier commerce.PaymentEvidenceVerifier, policyRevision uint64, fence commerce.WriterFence) (SettlementLedgerRecord, EngagementRecord, error) {
	if service.Engine == nil || service.Engine.Authority == nil || verifier == nil ||
		!service.Engine.permits("billing", true, false) {
		return SettlementLedgerRecord{}, EngagementRecord{}, errors.New("payment reconciliation is unavailable")
	}
	now := service.Engine.now()
	if err := commerce.VerifyAgreementPaymentEvidence(request, evidence, verifier, now); err != nil {
		return SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	var ledger *SettlementLedgerRecord
	for _, candidate := range service.Engine.Authority.SettlementSnapshot(request.AgreementBodyDigest) {
		if candidate.Obligation.ObligationInstanceID == request.ObligationInstanceID {
			copy := candidate
			ledger = &copy
			break
		}
	}
	if ledger == nil || ledger.Obligation.AgreementObligationID != request.AgreementObligationID ||
		ledger.Obligation.PayerAgentID != request.PayerAgentID || ledger.Obligation.PayeeAgentID != request.PayeeAgentID ||
		ledger.Obligation.SettlementAdapterURI != request.SettlementAdapterURI {
		return SettlementLedgerRecord{}, EngagementRecord{}, errors.New("payment request differs from the materialized obligation")
	}
	evidenceDigest, err := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	if err != nil {
		return SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	preview, err := commerce.ApplyPayment(ledger.State, ledger.Obligation, evidenceDigest, request.Amount, now)
	if err != nil {
		return SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	requestBody := BillingResolutionRequest{ObligationInstanceID: request.ObligationInstanceID, PaymentEvidenceDigest: evidenceDigest,
		PaidAmount: request.Amount, ResolvedAtUnix: evidence.ResolvedAtUnix}
	canonical, err := codec.Marshal(requestBody)
	if err != nil {
		return SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	evidenceSetDigest, _ := codec.Digest("tos.billing-evidence-set.v1", preview.AppliedPaymentEvidence)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.Engine.OwnerID), "agent_id": commerce.ID(service.Engine.AgentID),
		"obligation_instance_id": commerce.Digest32(request.ObligationInstanceID), "target_state": commerce.State(string(preview.State)),
		"evidence_set_digest": commerce.Digest32(evidenceSetDigest)}
	expiresAt := minUint64(request.ExpiresAtUnix, fence.Body.ExpiresAtUnix)
	action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "billing.resolve", fields, canonical,
		fence, policyRevision, service.Engine.MandateDigest, "", string(ledger.State.State), expiresAt)
	if err != nil {
		return SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	action, err = service.Engine.Authority.SignAction(action, fence)
	if err != nil {
		return SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	_, updated, engagement, err := service.Engine.Authority.ApplySettlementPayment(action, fields, canonical, fence, requestBody)
	return updated, engagement, err
}

// MarkOverdue never treats timeout as payment. It preserves the receivable and
// promotes the engagement to unpaid only after the exact obligation deadline.
func (service BillingService) MarkOverdue(agreementDigest string, now time.Time, policyRevision uint64,
	fence commerce.WriterFence) (EngagementRecord, error) {
	if service.Engine == nil || service.Engine.Authority == nil {
		return EngagementRecord{}, errors.New("billing is unavailable")
	}
	record, found := service.Engine.Authority.Engagement(agreementDigest)
	if !found || record.State != EngagementSettling {
		return EngagementRecord{}, errors.New("engagement is not awaiting settlement")
	}
	ledgers := service.Engine.Authority.SettlementSnapshot(agreementDigest)
	for _, ledger := range ledgers {
		if ledger.State.State == commerce.SettlementPaid {
			continue
		}
		if ledger.Obligation.DueAtUnix == 0 || now.UTC().Before(time.Unix(int64(ledger.Obligation.DueAtUnix), 0).UTC()) {
			return EngagementRecord{}, errors.New("an outstanding obligation is not overdue")
		}
	}
	for _, ledger := range ledgers {
		if ledger.State.State == commerce.SettlementPaid || ledger.State.State == commerce.SettlementOverdue {
			continue
		}
		evidence, err := codec.Digest("tos.settlement-overdue-observation.v1", struct {
			Agreement, Obligation string
			StateRevision         uint64
			At                    uint64
		}{agreementDigest, ledger.Obligation.ObligationInstanceID, ledger.State.StateRevision, uint64(now.UTC().Unix())})
		if err != nil {
			return EngagementRecord{}, err
		}
		preview, err := commerce.ResolveSettlementState(ledger.State, ledger.Obligation, commerce.SettlementOverdue, evidence, now)
		if err != nil {
			return EngagementRecord{}, err
		}
		evidenceSetDigest, _ := codec.Digest("tos.billing-evidence-set.v1", preview.EvidenceRefs)
		request := BillingStateTransitionRequest{ObligationInstanceID: ledger.Obligation.ObligationInstanceID,
			ExpectedStateRevision: ledger.State.StateRevision, TargetState: commerce.SettlementOverdue,
			EvidenceDigest: evidence, ObservedAtUnix: uint64(now.UTC().Unix())}
		canonical, err := codec.Marshal(request)
		if err != nil {
			return EngagementRecord{}, err
		}
		fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.Engine.OwnerID), "agent_id": commerce.ID(service.Engine.AgentID),
			"obligation_instance_id": commerce.Digest32(request.ObligationInstanceID), "target_state": commerce.State(string(request.TargetState)),
			"evidence_set_digest": commerce.Digest32(evidenceSetDigest)}
		action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "billing.resolve", fields,
			canonical, fence, policyRevision, service.Engine.MandateDigest, "", string(ledger.State.State), fence.Body.ExpiresAtUnix)
		if err == nil {
			action, err = service.Engine.Authority.SignAction(action, fence)
		}
		if err != nil {
			return EngagementRecord{}, err
		}
		_, _, record, err = service.Engine.Authority.ResolveSettlementState(action, fields, canonical, fence, request)
		if err != nil {
			return EngagementRecord{}, err
		}
	}
	return record, nil
}

type DeliverySink interface {
	AuthorizationRequest(DeliveryReleaseRequest) ([]byte, error)
	SubmitDelivery(context.Context, commerce.AuthorizedAction, commerce.WriterFence,
		map[string]commerce.SemanticValue, []byte, DeliveryReleaseRequest) (commerce.ActionResolution, error)
	ResolveAction(context.Context, string, string) (commerce.ActionResolution, error)
}

func (engine *Engine) Deliver(ctx context.Context, agreementDigest, obligationID, recipientAgentID, manifestDigest string,
	sink DeliverySink, policyRevision uint64, fence commerce.WriterFence) (EngagementRecord, error) {
	if engine == nil || engine.Authority == nil || sink == nil || !engine.permits("delivery", engine.Gates.Execution, false) {
		return EngagementRecord{}, errors.New("delivery is unavailable")
	}
	record, found := engine.Authority.Engagement(agreementDigest)
	runtime, runtimeFound := record.ObligationRuntime[obligationID]
	if !found || !runtimeFound || runtime.State != ObligationExecutionSucceeded {
		return EngagementRecord{}, errors.New("delivery has no successful execution predecessor")
	}
	validObligation := false
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID && obligation.ObligorAgentID == engine.AgentID && obligation.BeneficiaryAgentID == recipientAgentID {
			validObligation = true
		}
	}
	if !validObligation {
		return EngagementRecord{}, errors.New("delivery recipient or obligation differs from the Agreement")
	}
	request := DeliveryReleaseRequest{AgreementBodyDigest: agreementDigest, ObligationID: obligationID,
		RecipientAgentID: recipientAgentID, DeliverableManifestDigest: manifestDigest}
	canonical, err := sink.AuthorizationRequest(request)
	if err != nil {
		return EngagementRecord{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"agreement_body_digest": commerce.Digest32(agreementDigest), "obligation_id": commerce.ID(obligationID),
		"recipient_id": commerce.ID(recipientAgentID), "deliverable_manifest_digest": commerce.Digest32(manifestDigest)}
	action, err := commerce.BuildAuthorizedAction(engine.OwnerID, engine.AgentID, "delivery.release", fields, canonical, fence,
		policyRevision, engine.MandateDigest, "", "execution_succeeded", minUint64(record.Agreement.Body.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err != nil {
		return EngagementRecord{}, err
	}
	action, err = engine.Authority.SignAction(action, fence)
	if err != nil {
		return EngagementRecord{}, err
	}
	admitted, err := engine.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil {
		return EngagementRecord{}, err
	}
	if admitted.State != commerce.ActionPrepared {
		return EngagementRecord{}, errors.New("delivery action is not prepared")
	}
	resolved, err := sink.SubmitDelivery(ctx, action, fence, fields, canonical, request)
	if err != nil {
		resolved, _ = sink.ResolveAction(ctx, action.StableActionID, action.ExactRequestDigest)
		if resolved.State == commerce.ActionUnknown {
			return EngagementRecord{}, err
		}
	}
	if _, err := engine.recordResolution(action, resolved); err != nil {
		return EngagementRecord{}, err
	}
	evidence := append([]string(nil), resolved.EvidenceRefs...)
	if len(evidence) == 0 {
		evidence = []string{manifestDigest}
	}
	return engine.Authority.transitionObligation(agreementDigest, obligationID, ObligationExecutionSucceeded,
		ObligationDelivered, runtime.ExecutionID, evidence, "")
}

type AcceptanceEvidenceVerifier interface {
	VerifyAcceptanceEvidence(EngagementRecord, commerce.AgreementObligation) ([]string, error)
}

type BillingService struct {
	Engine     *Engine
	Acceptance AcceptanceEvidenceVerifier
}

func (service BillingService) MaterializeAfterDelivery(agreementDigest string, policyRevision uint64,
	fence commerce.WriterFence) ([]SettlementLedgerRecord, EngagementRecord, error) {
	if service.Engine == nil || service.Engine.Authority == nil ||
		!service.Engine.permits("billing", true, false) {
		return nil, EngagementRecord{}, errors.New("billing is unavailable")
	}
	record, found := service.Engine.Authority.Engagement(agreementDigest)
	if !found || record.State == EngagementProposed || record.State == EngagementAuthorizing || record.State == EngagementAgreed ||
		record.State == EngagementCancelled || record.State == EngagementFailed || record.State == EngagementAmbiguous {
		return nil, EngagementRecord{}, errors.New("billing has no verified delivery predecessor")
	}
	existing := service.Engine.Authority.SettlementSnapshot(agreementDigest)
	materialized := make(map[string]bool)
	for _, ledger := range existing {
		materialized[ledger.Obligation.ObligationInstanceID] = true
	}
	var created []SettlementLedgerRecord
	for _, agreementObligation := range record.Agreement.Body.Obligations {
		if agreementObligation.Amount == nil || !obligationDependenciesSatisfied(record, agreementObligation) {
			continue
		}
		if len(agreementObligation.AcceptanceEvidenceRequirements) > 0 {
			if service.Acceptance == nil {
				return nil, EngagementRecord{}, errors.New("payment obligation acceptance evidence is unresolved")
			}
			evidence, err := service.Acceptance.VerifyAcceptanceEvidence(record, agreementObligation)
			if err != nil || len(evidence) == 0 {
				return nil, EngagementRecord{}, errors.New("payment obligation acceptance evidence is unresolved")
			}
		}
		instances, err := commerce.MaterializeSettlementObligations(service.Engine.OwnerID, service.Engine.AgentID, agreementDigest,
			agreementObligation.ObligationID, service.Engine.MandateDigest, agreementObligation)
		if err != nil {
			return nil, EngagementRecord{}, err
		}
		for _, obligation := range instances {
			alreadyMaterialized := materialized[obligation.ObligationInstanceID]
			canonical, err := codec.Marshal(obligation)
			if err != nil {
				return nil, EngagementRecord{}, err
			}
			fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(service.Engine.OwnerID), "agent_id": commerce.ID(service.Engine.AgentID),
				"agreement_body_digest": commerce.Digest32(agreementDigest), "agreement_obligation_id": commerce.ID(obligation.AgreementObligationID),
				"sequence": commerce.U64(obligation.Sequence)}
			expiresAt := obligation.ExpiresAtUnix
			if expiresAt == 0 {
				expiresAt = record.Agreement.Body.ExpiresAtUnix
			}
			expiresAt = minUint64(expiresAt, fence.Body.ExpiresAtUnix)
			action, err := commerce.BuildAuthorizedAction(service.Engine.OwnerID, service.Engine.AgentID, "billing.materialize", fields,
				canonical, fence, policyRevision, service.Engine.MandateDigest, "", "delivered", expiresAt)
			if err != nil {
				return nil, EngagementRecord{}, err
			}
			action, err = service.Engine.Authority.SignAction(action, fence)
			if err != nil {
				return nil, EngagementRecord{}, err
			}
			_, ledger, err := service.Engine.Authority.MaterializeSettlement(action, fields, canonical, fence, obligation)
			if err != nil {
				return nil, EngagementRecord{}, err
			}
			if !alreadyMaterialized {
				created = append(created, ledger)
				materialized[obligation.ObligationInstanceID] = true
			}
		}
	}
	if len(created) == 0 && len(existing) == 0 && !hasValueObligation(record) && allNonValueObligationsDelivered(record) {
		evidence, _ := codec.Digest("tos.unpaid-agreement-complete.v1", agreementDigest)
		completed, err := service.Engine.Authority.completeNoPaymentEngagement(agreementDigest, evidence)
		return nil, completed, err
	}
	sort.Slice(created, func(i, j int) bool {
		return created[i].Obligation.ObligationInstanceID < created[j].Obligation.ObligationInstanceID
	})
	record, _ = service.Engine.Authority.Engagement(agreementDigest)
	return created, record, nil
}

func hasValueObligation(record EngagementRecord) bool {
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount != nil {
			return true
		}
	}
	return false
}

func allNonValueObligationsDelivered(record EngagementRecord) bool {
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.Amount != nil {
			continue
		}
		runtime := record.ObligationRuntime[obligation.ObligationID]
		if runtime.State != ObligationDelivered && runtime.State != ObligationSettled {
			return false
		}
	}
	return true
}
