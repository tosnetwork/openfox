package earning

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type BillingResolutionRequest struct {
	ObligationInstanceID  string                   `json:"obligation_instance_id"`
	PaymentEvidenceDigest string                   `json:"payment_evidence_digest"`
	PaidAmount            commerce.AgreementAmount `json:"paid_amount"`
	ResolvedAtUnix        uint64                   `json:"resolved_at_unix"`
}

type BillingStateTransitionRequest struct {
	ObligationInstanceID  string                   `json:"obligation_instance_id"`
	ExpectedStateRevision uint64                   `json:"expected_state_revision"`
	TargetState           commerce.SettlementState `json:"target_state"`
	EvidenceDigest        string                   `json:"evidence_digest"`
	ObservedAtUnix        uint64                   `json:"observed_at_unix"`
}

func (authority *PersonalAuthority) ResolveSettlementState(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	request BillingStateTransitionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error) {
	if authority == nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("settlement authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	ledger, found := authority.doc.SettlementLedger[request.ObligationInstanceID]
	if !found || ledger.State.StateRevision != request.ExpectedStateRevision || request.ObservedAtUnix == 0 ||
		request.ObservedAtUnix > uint64(authority.now().UTC().Unix()) {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("settlement transition has a stale or absent obligation")
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("stale writer cannot resolve settlement state")
	}
	updated, err := commerce.ResolveSettlementState(ledger.State, ledger.Obligation, request.TargetState, request.EvidenceDigest,
		time.Unix(int64(request.ObservedAtUnix), 0).UTC())
	if err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	evidenceSetDigest, err := codec.Digest("tos.billing-evidence-set.v1", updated.EvidenceRefs)
	if err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	expectedFields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(authority.doc.OwnerID), "agent_id": commerce.ID(authority.doc.AgentID),
		"obligation_instance_id": commerce.Digest32(request.ObligationInstanceID), "target_state": commerce.State(string(request.TargetState)),
		"evidence_set_digest": commerce.Digest32(evidenceSetDigest)}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "billing.resolve" || !reflect.DeepEqual(fields, expectedFields) ||
		commerce.VerifyAuthorizedAction(action, expectedFields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("settlement transition action is not exact or authorized")
	}
	if prior, exists := authority.doc.Actions[action.StableActionID]; exists {
		engagement := authority.doc.Engagements[ledger.Obligation.AgreementBodyDigest]
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("settlement transition identity conflicts")
		}
		return prior, ledger, engagement, nil
	}
	ledger.State = updated
	next := cloneAuthorityDocument(authority.doc)
	next.SettlementLedger[request.ObligationInstanceID] = ledger
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, EvidenceRefs: []string{request.EvidenceDigest}, StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	classification := AccountingClassification("")
	switch request.TargetState {
	case commerce.SettlementOverdue:
		classification = AccountingOverdueBalance
	case commerce.SettlementDisputed:
		classification = AccountingDispute
	case commerce.SettlementWrittenOff:
		classification = AccountingWriteOff
	}
	if classification != "" {
		accountingBody := AccountingEntryBody{SchemaVersion: 1, OwnerID: next.OwnerID, AgentID: next.AgentID,
			Classification: classification, AgreementBodyDigest: ledger.Obligation.AgreementBodyDigest,
			AgreementObligationID: ledger.Obligation.AgreementObligationID, ObligationInstanceID: ledger.Obligation.ObligationInstanceID,
			Amount: &ledger.State.OutstandingAmount, SourceReference: request.EvidenceDigest, EvidenceRefs: []string{request.EvidenceDigest},
			ObservedAtUnix: request.ObservedAtUnix}
		if entryID, entryErr := AccountingEntryID(accountingBody); entryErr == nil {
			next.Accounting[entryID] = AccountingEntry{EntryID: entryID, Body: accountingBody, WriterGeneration: fence.Body.WriterGeneration}
		} else {
			return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, entryErr
		}
	}
	engagement := next.Engagements[ledger.Obligation.AgreementBodyDigest]
	if request.TargetState == commerce.SettlementOverdue {
		allInstanceTerminal := true
		runtimeChanged := false
		var obligationEvidence []string
		for _, candidate := range next.SettlementLedger {
			if candidate.Obligation.AgreementBodyDigest == engagement.AgreementDigest &&
				candidate.Obligation.AgreementObligationID == ledger.Obligation.AgreementObligationID {
				allInstanceTerminal = allInstanceTerminal && (candidate.State.State == commerce.SettlementOverdue || candidate.State.State == commerce.SettlementPaid)
				obligationEvidence = append(obligationEvidence, candidate.State.EvidenceRefs...)
			}
		}
		if allInstanceTerminal {
			initializeObligationRuntime(&engagement)
			runtime := engagement.ObligationRuntime[ledger.Obligation.AgreementObligationID]
			runtime.State, runtime.StateRevision = ObligationOverdue, runtime.StateRevision+1
			runtime.SettlementEvidence = appendUniqueSorted(runtime.SettlementEvidence, obligationEvidence...)
			runtime.LastTransitionAtUnix = request.ObservedAtUnix
			engagement.ObligationRuntime[ledger.Obligation.AgreementObligationID] = runtime
			runtimeChanged = true
		}
		allOverdueOrPaid := true
		for _, candidate := range next.SettlementLedger {
			if candidate.Obligation.AgreementBodyDigest == engagement.AgreementDigest {
				allOverdueOrPaid = allOverdueOrPaid && (candidate.State.State == commerce.SettlementOverdue || candidate.State.State == commerce.SettlementPaid)
			}
		}
		if allOverdueOrPaid {
			engagement.StateRevision++
			engagement.SettlementEvidence = appendUniqueSorted(engagement.SettlementEvidence, request.EvidenceDigest)
			engagement.LastTransitionAtUnix = request.ObservedAtUnix
			refreshEngagementProjection(&engagement)
			next.Engagements[engagement.AgreementDigest] = engagement
		} else if runtimeChanged {
			engagement.StateRevision++
			engagement.LastTransitionAtUnix = request.ObservedAtUnix
			refreshEngagementProjection(&engagement)
			next.Engagements[engagement.AgreementDigest] = engagement
		}
	}
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	authority.doc = next
	return resolution, ledger, engagement, nil
}

func (authority *PersonalAuthority) MaterializeSettlement(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	obligation commerce.SettlementObligation) (commerce.ActionResolution, SettlementLedgerRecord, error) {
	if err := commerce.ValidateSettlementObligation(obligation); err != nil || action.StableActionID != obligation.StableActionID {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, errors.New("settlement obligation identity is invalid")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, err
	}
	engagement, found := authority.doc.Engagements[obligation.AgreementBodyDigest]
	initializeObligationRuntime(&engagement)
	agreementObligation, obligationFound := obligationByID(engagement, obligation.AgreementObligationID)
	runtime := engagement.ObligationRuntime[obligation.AgreementObligationID]
	if !found || !obligationFound || agreementObligation.Amount == nil ||
		(runtime.State != ObligationPending && runtime.State != ObligationSettling) ||
		!obligationDependenciesSatisfied(engagement, agreementObligation) {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, errors.New("settlement cannot be materialized before verified delivery")
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, errors.New("stale writer cannot materialize billing")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "billing.materialize" || commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, errors.New("billing materialization action is not authorized")
	}
	if prior, exists := authority.doc.Actions[action.StableActionID]; exists {
		ledger, present := authority.doc.SettlementLedger[obligation.ObligationInstanceID]
		if prior.ExactRequestDigest != action.ExactRequestDigest || !present {
			return commerce.ActionResolution{}, SettlementLedgerRecord{}, errors.New("billing materialization retry conflicts")
		}
		return prior, ledger, nil
	}
	state, err := commerce.NewSettlementState(obligation)
	if err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, err
	}
	ledger := SettlementLedgerRecord{Obligation: obligation, State: state}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, StateRevision: 1}
	next := cloneAuthorityDocument(authority.doc)
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	next.SettlementLedger[obligation.ObligationInstanceID] = ledger
	if runtime.State == ObligationPending {
		runtime.State = ObligationSettling
		runtime.StateRevision++
		runtime.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
		engagement.ObligationRuntime[obligation.AgreementObligationID] = runtime
		engagement.StateRevision++
		engagement.LastTransitionAtUnix = runtime.LastTransitionAtUnix
		refreshEngagementProjection(&engagement)
		next.Engagements[engagement.AgreementDigest] = engagement
	}
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, err
	}
	authority.doc = next
	return resolution, ledger, nil
}

func (authority *PersonalAuthority) SettlementSnapshot(agreementDigest string) []SettlementLedgerRecord {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return nil
	}
	result := make([]SettlementLedgerRecord, 0)
	for _, record := range authority.doc.SettlementLedger {
		if record.Obligation.AgreementBodyDigest == agreementDigest {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Obligation.ObligationInstanceID < result[j].Obligation.ObligationInstanceID
	})
	return result
}

func (authority *PersonalAuthority) ApplySettlementPayment(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	request BillingResolutionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	ledger, found := authority.doc.SettlementLedger[request.ObligationInstanceID]
	if !found || request.ResolvedAtUnix == 0 || request.ResolvedAtUnix > uint64(authority.now().UTC().Unix()) {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("payment resolution has no materialized obligation")
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("stale writer cannot resolve billing")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "billing.resolve" || commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("billing resolution action is not authorized")
	}
	if prior, exists := authority.doc.Actions[action.StableActionID]; exists {
		engagement := authority.doc.Engagements[ledger.Obligation.AgreementBodyDigest]
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, errors.New("billing resolution identity conflicts")
		}
		return prior, ledger, engagement, nil
	}
	updated, err := commerce.ApplyPayment(ledger.State, ledger.Obligation, request.PaymentEvidenceDigest, request.PaidAmount,
		time.Unix(int64(request.ResolvedAtUnix), 0).UTC())
	if err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	ledger.State = updated
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, EvidenceRefs: []string{request.PaymentEvidenceDigest}, StateRevision: 1}
	next := cloneAuthorityDocument(authority.doc)
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	next.SettlementLedger[request.ObligationInstanceID] = ledger
	classification := AccountingPartialPayment
	if updated.State == commerce.SettlementPaid {
		if ledger.Obligation.PayeeAgentID == next.AgentID {
			classification = AccountingSettledRevenue
		} else {
			classification = AccountingSettledExpense
		}
	}
	accountingBody := AccountingEntryBody{SchemaVersion: 1, OwnerID: next.OwnerID, AgentID: next.AgentID,
		Classification: classification, AgreementBodyDigest: ledger.Obligation.AgreementBodyDigest,
		AgreementObligationID: ledger.Obligation.AgreementObligationID, ObligationInstanceID: ledger.Obligation.ObligationInstanceID,
		Amount: &request.PaidAmount, SourceReference: request.PaymentEvidenceDigest, EvidenceRefs: []string{request.PaymentEvidenceDigest},
		ObservedAtUnix: request.ResolvedAtUnix}
	entryID, entryErr := AccountingEntryID(accountingBody)
	if entryErr != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, entryErr
	}
	next.Accounting[entryID] = AccountingEntry{EntryID: entryID, Body: accountingBody, WriterGeneration: fence.Body.WriterGeneration}
	engagement := next.Engagements[ledger.Obligation.AgreementBodyDigest]
	allObligationPaid := true
	var obligationEvidence []string
	for _, candidate := range next.SettlementLedger {
		if candidate.Obligation.AgreementBodyDigest == engagement.AgreementDigest &&
			candidate.Obligation.AgreementObligationID == ledger.Obligation.AgreementObligationID {
			allObligationPaid = allObligationPaid && candidate.State.State == commerce.SettlementPaid
			obligationEvidence = append(obligationEvidence, candidate.State.AppliedPaymentEvidence...)
		}
	}
	if allObligationPaid {
		initializeObligationRuntime(&engagement)
		runtime := engagement.ObligationRuntime[ledger.Obligation.AgreementObligationID]
		runtime.State, runtime.StateRevision = ObligationSettled, runtime.StateRevision+1
		runtime.SettlementEvidence = appendUniqueSorted(runtime.SettlementEvidence, obligationEvidence...)
		runtime.LastTransitionAtUnix = request.ResolvedAtUnix
		engagement.ObligationRuntime[ledger.Obligation.AgreementObligationID] = runtime
	}
	allPaid := true
	var evidence []string
	for _, candidate := range next.SettlementLedger {
		if candidate.Obligation.AgreementBodyDigest == engagement.AgreementDigest {
			allPaid = allPaid && candidate.State.State == commerce.SettlementPaid
			evidence = append(evidence, candidate.State.AppliedPaymentEvidence...)
		}
	}
	if allPaid {
		sort.Strings(evidence)
		engagement.SettlementEvidence = evidence
		engagement.StateRevision++
		engagement.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
		refreshEngagementProjection(&engagement)
		next.Engagements[engagement.AgreementDigest] = engagement
	} else if allObligationPaid {
		engagement.StateRevision++
		engagement.LastTransitionAtUnix = request.ResolvedAtUnix
		refreshEngagementProjection(&engagement)
		next.Engagements[engagement.AgreementDigest] = engagement
	}
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, SettlementLedgerRecord{}, EngagementRecord{}, err
	}
	authority.doc = next
	return resolution, ledger, engagement, nil
}
