package earning

import (
	"context"
	"errors"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// GuarantorPayoutService is deliberately separate from claim adjudication.
// A signed approval cannot move value: payment additionally requires an exact
// materialized obligation, the current writer, a payment gate and sink-side
// terminal evidence.
type GuarantorPayoutService struct {
	Coordinator *GuarantorProviderCoordinator
	Sink        AgreementPaymentSink
	Verifier    commerce.PaymentEvidenceVerifier
	Enabled     bool
	// FailureInjector is used by crash-recovery tests. Production callers leave
	// it nil; the persisted submitted state remains the recovery boundary.
	FailureInjector func(string) error
}

func (service GuarantorPayoutService) Pay(ctx context.Context, agreementDigest, claimID,
	obligationInstanceID, networkID string, fence commerce.WriterFence) (commerce.AgreementPaymentEvidence,
	commerce.ActionResolution, guarantor.ClaimRecord, error) {
	if err := ctx.Err(); err != nil {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	coordinator := service.Coordinator
	if !service.Enabled || coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil ||
		service.Sink == nil || service.Verifier == nil || !canonicalSHA256(agreementDigest) ||
		!canonicalSHA256(claimID) || !canonicalSHA256(obligationInstanceID) || networkID == "" {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{},
			errors.New("Guarantor payout is disabled or incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout writer is stale")
	}
	var coverage GuarantorCoveragePosition
	_, _, coverages := coordinator.Journal.Snapshot()
	for _, candidate := range coverages {
		if candidate.Record.CoverageAgreementBodyDigest == agreementDigest {
			coverage = candidate
		}
	}
	materialized, found := coverage.MaterializedPayouts[claimID]
	if !found {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout was not materialized")
	}
	var obligation commerce.SettlementObligation
	for _, candidate := range materialized.Obligations {
		if candidate.ObligationInstanceID == obligationInstanceID {
			obligation = candidate
		}
	}
	if obligation.ObligationInstanceID == "" || uint64(now.Unix()) < obligation.NotBeforeUnix ||
		uint64(now.Unix()) >= obligation.ExpiresAtUnix {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout obligation is unavailable or outside its window")
	}
	lineIndex := payoutLineIndex(materialized, obligationInstanceID)
	if lineIndex < 0 {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout materialization is inconsistent")
	}
	destination := coverage.Terms.PayoutTemplate.PayoutDestinationBinding.PayoutDestination
	destinationDigest, err := commerce.PayoutDestinationDigestV1(destination)
	if err != nil || destinationDigest != materialized.MaterializedLines[lineIndex].ClaimPayoutLine.PayoutDestinationDigest ||
		destination.SettlementAdapterProfile != coverage.Terms.SelectedPayoutAdapterProfile ||
		destination.Asset != coverage.Terms.CoverageAsset {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout destination differs from the accepted Agreement")
	}
	request, err := buildGuarantorPaymentRequest(coordinator, coverage.Terms, networkID, destination, obligation)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	_, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	actionRequest := guarantor.GuarantorAgreementPaymentActionBodyV1{SchemaVersion: 1, PaymentRequest: request,
		SettlementObligation: obligation, MaterializedPayoutObligationSet: materialized}
	canonical, err := codec.Marshal(actionRequest)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	if prior, paid := coverage.PayoutEvidence[obligationInstanceID]; paid {
		execution, executionFound := coverage.PayoutExecutionEvidence[obligationInstanceID]
		if !executionFound || guarantor.VerifyGuarantorPayoutExecutionEvidenceV1(execution, request, obligation,
			materialized, coverage.Terms, coordinator.Resolver, coordinator.Authority, service.Verifier, now) != nil {
			return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("stored Guarantor payout evidence is invalid")
		}
		exactRequestDigest, _ := commerce.ExactRequestDigest(canonical)
		resolution := coordinator.Authority.Resolve(request.StableActionID, exactRequestDigest)
		record := coverage.Claims[claimID]
		if resolution.State == commerce.ActionPrepared {
			evidenceDigest, digestErr := codec.Digest("tos.agreement-payment-evidence.v1", prior)
			if digestErr != nil {
				return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, digestErr
			}
			resolution, err = coordinator.Authority.Transition(request.StableActionID, exactRequestDigest,
				commerce.ActionTerminal, prior.ExactTransferReference, []string{evidenceDigest})
			if err != nil {
				return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
			}
		}
		if resolution.State != commerce.ActionTerminal {
			return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, errors.New("stored Guarantor payout has no matching authority result")
		}
		return prior, resolution, record, nil
	}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, commerce.PaymentActionKind(request), fields,
		canonical, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", "prepared",
		minUint64(request.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil || action.StableActionID != request.StableActionID {
		return commerce.AgreementPaymentEvidence{}, commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout action identity mismatch")
	}
	priorResolution := coordinator.Authority.Resolve(action.StableActionID, action.ExactRequestDigest)
	if priorResolution.State == commerce.ActionConflict {
		return commerce.AgreementPaymentEvidence{}, priorResolution, guarantor.ClaimRecord{},
			errors.New("Guarantor payout action conflicts with retained authority state")
	}
	resolution, err := coordinator.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil || (resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionSubmitted &&
		resolution.State != commerce.ActionAccepted && resolution.State != commerce.ActionTerminal) {
		return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{},
			firstError(err, errors.New("Guarantor payout action was not prepared"))
	}
	var evidence commerce.AgreementPaymentEvidence
	var submitErr error
	if priorResolution.State == commerce.ActionUnknown {
		if resolution.State != commerce.ActionPrepared {
			return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{},
				errors.New("new Guarantor payout did not enter prepared state")
		}
		resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionSubmitted, "", nil)
		if err != nil {
			return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
		}
		evidence, submitErr = service.Sink.SubmitPayment(ctx, action, fence, fields, canonical, request)
		if submitErr != nil {
			evidence, _ = service.Sink.ResolvePayment(ctx, request)
			if evidence.PaymentRequestDigest == "" {
				return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, submitErr
			}
		}
		if service.FailureInjector != nil {
			if injected := service.FailureInjector("after_external_payout_before_terminal_commit"); injected != nil {
				return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, injected
			}
		}
	} else {
		// Any retained prepared/submitted/accepted state may represent an
		// externally completed transfer whose response was lost. Querying is the
		// only safe automatic recovery. Resubmission requires a separate typed
		// Adapter capability and is deliberately not inferred here.
		evidence, submitErr = service.Sink.ResolvePayment(ctx, request)
		if submitErr != nil || evidence.PaymentRequestDigest == "" {
			return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{},
				firstError(submitErr, errors.New("ambiguous Guarantor payout remains unresolved at the selected Adapter"))
		}
	}
	if err := commerce.VerifyAgreementPaymentEvidence(request, evidence, service.Verifier, now); err != nil {
		return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
	}
	evidenceDigest, _ := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	if resolution.State != commerce.ActionTerminal {
		resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionTerminal, evidence.ExactTransferReference, []string{evidenceDigest})
		if err != nil {
			return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
		}
	}
	stage, err := coordinator.buildGuarantorStage(coverage.Terms, "payout_execution",
		"application/vnd.tos.service.agent-guarantor-agreement-payment-action.v1+cbor", canonical,
		action, resolution, fence, now)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
	}
	execution := guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1{SchemaVersion: 1,
		ObligationInstanceID: obligationInstanceID, StageActionAdmissionEvidence: stage,
		AgreementPaymentEvidence: evidence}
	if err := guarantor.VerifyGuarantorPayoutExecutionEvidenceV1(execution, request, obligation, materialized,
		coverage.Terms, coordinator.Resolver, coordinator.Authority, service.Verifier, now); err != nil {
		return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
	}
	record, err := coordinator.Journal.RecordTerminalPayout(agreementDigest, claimID, obligationInstanceID,
		request.Amount.AmountAtomic, request, evidence, execution)
	if err != nil {
		return commerce.AgreementPaymentEvidence{}, resolution, guarantor.ClaimRecord{}, err
	}
	return evidence, resolution, record, nil
}

// RecordDefault closes one materialized payout only when the Agreement-selected
// Adapter verifier proves a terminal default for the exact domain-bound payment
// request.  Expiry, a local timeout, or a Guarantor-authored ledger entry can
// never call this path successfully.
func (service GuarantorPayoutService) RecordDefault(ctx context.Context, agreementDigest, claimID,
	obligationInstanceID, networkID string, evidence commerce.AgreementPaymentEvidence,
	fence commerce.WriterFence) (commerce.ActionResolution, guarantor.ClaimRecord, error) {
	if err := ctx.Err(); err != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	coordinator := service.Coordinator
	defaultVerifier, verifierOK := service.Verifier.(guarantor.PayoutDefaultEvidenceVerifier)
	if !service.Enabled || !verifierOK || coordinator == nil || coordinator.Authority == nil ||
		coordinator.Journal == nil || !canonicalSHA256(agreementDigest) || !canonicalSHA256(claimID) ||
		!canonicalSHA256(obligationInstanceID) || networkID == "" {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default admission is disabled or incomplete")
	}
	now := coordinator.Authority.AuthorityNow().UTC()
	if now.IsZero() || coordinator.Authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default writer is stale")
	}
	coverage, err := coordinator.coveragePosition(agreementDigest)
	if err != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	materialized, found := coverage.MaterializedPayouts[claimID]
	if !found {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout was not materialized")
	}
	var obligation commerce.SettlementObligation
	for _, candidate := range materialized.Obligations {
		if candidate.ObligationInstanceID == obligationInstanceID {
			obligation = candidate
		}
	}
	lineIndex := payoutLineIndex(materialized, obligationInstanceID)
	if obligation.ObligationInstanceID == "" || lineIndex < 0 {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default obligation is absent")
	}
	destination := coverage.Terms.PayoutTemplate.PayoutDestinationBinding.PayoutDestination
	destinationDigest, err := commerce.PayoutDestinationDigestV1(destination)
	if err != nil || destinationDigest != materialized.MaterializedLines[lineIndex].ClaimPayoutLine.PayoutDestinationDigest ||
		destination.SettlementAdapterProfile != coverage.Terms.SelectedPayoutAdapterProfile ||
		destination.Asset != coverage.Terms.CoverageAsset {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default destination differs from the Agreement")
	}
	request, err := buildGuarantorPaymentRequest(coordinator, coverage.Terms, networkID, destination, obligation)
	if err != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	if err := defaultVerifier.VerifyGuarantorPayoutDefaultEvidence(request, evidence, obligation, coverage.Terms, now); err != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	_, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	actionRequest := guarantor.GuarantorAgreementPaymentActionBodyV1{SchemaVersion: 1, PaymentRequest: request,
		SettlementObligation: obligation, MaterializedPayoutObligationSet: materialized}
	canonical, err := codec.Marshal(actionRequest)
	if err != nil {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, err
	}
	exactRequestDigest, err := commerce.ExactRequestDigest(canonical)
	if err != nil || len(fields) == 0 {
		return commerce.ActionResolution{}, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default request identity is invalid")
	}
	resolution := coordinator.Authority.Resolve(request.StableActionID, exactRequestDigest)
	if resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionTerminal {
		return resolution, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default has no exact previously admitted payment attempt")
	}
	evidenceDigest, err := codec.Digest("tos.agreement-payment-evidence.v1", evidence)
	if err != nil {
		return resolution, guarantor.ClaimRecord{}, err
	}
	if resolution.State == commerce.ActionPrepared {
		resolution, err = coordinator.Authority.Transition(request.StableActionID, exactRequestDigest,
			commerce.ActionTerminal, evidence.ExactTransferReference, []string{evidenceDigest})
		if err != nil {
			return resolution, guarantor.ClaimRecord{}, err
		}
	}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID,
		commerce.PaymentActionKind(request), fields, canonical, fence, coordinator.PolicyRevision,
		coordinator.MandateDigest, "", "prepared", minUint64(request.ExpiresAtUnix, fence.Body.ExpiresAtUnix))
	if err == nil {
		action, err = coordinator.Authority.SignAction(action, fence)
	}
	if err != nil || action.StableActionID != request.StableActionID {
		return resolution, guarantor.ClaimRecord{}, errors.New("Guarantor payout-default action identity mismatch")
	}
	stage, err := coordinator.buildGuarantorStage(coverage.Terms, "payout_execution",
		"application/vnd.tos.service.agent-guarantor-agreement-payment-action.v1+cbor", canonical,
		action, resolution, fence, now)
	if err != nil {
		return resolution, guarantor.ClaimRecord{}, err
	}
	execution := guarantor.AuthorizedGuarantorPayoutExecutionEvidenceV1{SchemaVersion: 1,
		ObligationInstanceID: obligationInstanceID, StageActionAdmissionEvidence: stage,
		AgreementPaymentEvidence: evidence}
	if err := guarantor.VerifyGuarantorPayoutExecutionEvidenceV1(execution, request, obligation, materialized,
		coverage.Terms, coordinator.Resolver, coordinator.Authority, service.Verifier, now); err != nil {
		return resolution, guarantor.ClaimRecord{}, err
	}
	record, err := coordinator.Journal.RecordTerminalPayoutDefault(agreementDigest, claimID,
		obligationInstanceID, request, evidence, execution)
	return resolution, record, err
}

func buildGuarantorPaymentRequest(coordinator *GuarantorProviderCoordinator, terms guarantor.CoverageTermsV1,
	networkID string, destination commerce.PayoutDestinationV1,
	obligation commerce.SettlementObligation) (commerce.AgreementPaymentRequest, error) {
	bound, err := guarantor.FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "payout_execution")
	if err != nil {
		return commerce.AgreementPaymentRequest{}, err
	}
	operation, err := guarantor.StageOperationBindingForAuthorityV1(bound)
	if err != nil {
		return commerce.AgreementPaymentRequest{}, err
	}
	switch operation.ActionKind {
	case "payment.direct":
		return commerce.BuildAgreementPaymentRequest(coordinator.OwnerID, coordinator.AgentID,
			networkID, destination.DestinationBytes, obligation)
	case "payment.domain-bound":
		return commerce.BuildDomainBoundAgreementPaymentRequest(coordinator.OwnerID, coordinator.AgentID, networkID,
			destination.NetworkOrSystemDigest, destination.DestinationBytes, obligation)
	case "settlement.external":
		if operation.OperationPurpose != "guarantor-payout" {
			return commerce.AgreementPaymentRequest{}, errors.New("collateral-backed Guarantor payout requires its atomic composite Adapter")
		}
		return commerce.BuildExternalAgreementPaymentRequestAmount(coordinator.OwnerID, coordinator.AgentID,
			networkID, destination.NetworkOrSystemDigest, terms.SelectedPayoutAdapterProfile.ProfileDigest,
			destination.DestinationBytes, obligation, obligation.Amount)
	default:
		return commerce.AgreementPaymentRequest{}, errors.New("Agreement selected an unsupported Guarantor payout route")
	}
}

func payoutLineIndex(set guarantor.MaterializedPayoutObligationSetV1, obligationID string) int {
	for index, obligation := range set.Obligations {
		if obligation.ObligationInstanceID == obligationID && index < len(set.MaterializedLines) {
			return index
		}
	}
	return -1
}
