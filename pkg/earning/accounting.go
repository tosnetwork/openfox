package earning

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type AccountingClassification string

const (
	AccountingQuotedValue      AccountingClassification = "quoted_value"
	AccountingAcceptedValue    AccountingClassification = "accepted_value"
	AccountingReservedExposure AccountingClassification = "reserved_exposure"
	AccountingActualCost       AccountingClassification = "actual_cost"
	AccountingPartialPayment   AccountingClassification = "partial_payment"
	AccountingSettledRevenue   AccountingClassification = "settled_revenue"
	AccountingSettledExpense   AccountingClassification = "settled_expense"
	AccountingOverdueBalance   AccountingClassification = "overdue_balance"
	AccountingRefund           AccountingClassification = "refund"
	AccountingDispute          AccountingClassification = "dispute"
	AccountingWriteOff         AccountingClassification = "write_off"
	AccountingGratuity         AccountingClassification = "gratuity"
)

type AccountingEntryBody struct {
	SchemaVersion         uint16                    `json:"schema_version"`
	OwnerID               string                    `json:"owner_id"`
	AgentID               string                    `json:"agent_id"`
	Classification        AccountingClassification  `json:"classification"`
	AgreementBodyDigest   string                    `json:"agreement_body_digest,omitempty"`
	AgreementObligationID string                    `json:"agreement_obligation_id,omitempty"`
	ObligationInstanceID  string                    `json:"obligation_instance_id,omitempty"`
	Amount                *commerce.AgreementAmount `json:"amount,omitempty"`
	ComputeUnits          uint64                    `json:"compute_units,omitempty"`
	SourceReference       string                    `json:"source_reference"`
	EvidenceRefs          []string                  `json:"evidence_refs"`
	ObservedAtUnix        uint64                    `json:"observed_at_unix"`
}

type AccountingEntry struct {
	EntryID          string              `json:"entry_id"`
	Body             AccountingEntryBody `json:"body"`
	WriterGeneration uint64              `json:"writer_generation"`
}

func AccountingEntryID(body AccountingEntryBody) (string, error) {
	if err := validateAccountingEntryBody(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.openfox.accounting-entry-body.v1", body)
}

func validateAccountingEntryBody(body AccountingEntryBody) error {
	if body.SchemaVersion != 1 || body.OwnerID == "" || body.AgentID == "" || body.SourceReference == "" ||
		body.ObservedAtUnix == 0 || len(body.EvidenceRefs) == 0 || len(body.EvidenceRefs) > 64 {
		return errors.New("accounting entry is incomplete or unbounded")
	}
	switch body.Classification {
	case AccountingQuotedValue, AccountingAcceptedValue, AccountingReservedExposure, AccountingActualCost,
		AccountingPartialPayment, AccountingSettledRevenue, AccountingSettledExpense, AccountingOverdueBalance,
		AccountingRefund, AccountingDispute, AccountingWriteOff, AccountingGratuity:
	default:
		return errors.New("accounting classification is unknown")
	}
	if body.Classification == AccountingGratuity && (body.AgreementBodyDigest != "" || body.AgreementObligationID != "" || body.ObligationInstanceID != "") {
		return errors.New("Gift gratuity cannot be attributed as Agreement settlement")
	}
	if body.Classification != AccountingGratuity && body.Classification != AccountingActualCost && body.AgreementBodyDigest == "" {
		return errors.New("commercial accounting entry lacks its Agreement")
	}
	if body.AgreementBodyDigest != "" && !canonicalSHA256(body.AgreementBodyDigest) ||
		body.ObligationInstanceID != "" && !canonicalSHA256(body.ObligationInstanceID) {
		return errors.New("accounting Agreement identity is invalid")
	}
	if body.Amount == nil && body.ComputeUnits == 0 {
		return errors.New("accounting entry has no measured value")
	}
	if body.Amount != nil {
		amount := *body.Amount
		if commerce.ValidateAgreementAmount(amount) != nil {
			return errors.New("accounting amount is invalid")
		}
	}
	if !sort.StringsAreSorted(body.EvidenceRefs) {
		return errors.New("accounting evidence is not canonical")
	}
	for index, evidence := range body.EvidenceRefs {
		if !canonicalSHA256(evidence) || index > 0 && evidence == body.EvidenceRefs[index-1] {
			return errors.New("accounting evidence is invalid or duplicated")
		}
	}
	return nil
}

func (authority *PersonalAuthority) RecordAccounting(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	entry AccountingEntry) (commerce.ActionResolution, AccountingEntry, error) {
	if authority == nil || validateAccountingEntryBody(entry.Body) != nil || entry.WriterGeneration != fence.Body.WriterGeneration {
		return commerce.ActionResolution{}, AccountingEntry{}, errors.New("accounting entry is invalid")
	}
	wantID, err := AccountingEntryID(entry.Body)
	if err != nil || entry.EntryID != wantID {
		return commerce.ActionResolution{}, AccountingEntry{}, errors.New("accounting identity mismatch")
	}
	canonical, err := codec.Marshal(entry)
	if err != nil || !reflect.DeepEqual(canonical, canonicalRequest) {
		return commerce.ActionResolution{}, AccountingEntry{}, errors.New("accounting request is not canonical")
	}
	evidenceSetDigest, _ := codec.Digest("tos.accounting-evidence-set.v1", entry.Body.EvidenceRefs)
	expected := map[string]commerce.SemanticValue{"owner_id": commerce.ID(entry.Body.OwnerID), "agent_id": commerce.ID(entry.Body.AgentID),
		"entry_id": commerce.Digest32(entry.EntryID), "classification": commerce.Kind(string(entry.Body.Classification)),
		"evidence_set_digest": commerce.Digest32(evidenceSetDigest)}
	if !reflect.DeepEqual(fields, expected) {
		return commerce.ActionResolution{}, AccountingEntry{}, errors.New("accounting semantic key mismatch")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || !authority.now().UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return commerce.ActionResolution{}, AccountingEntry{}, errors.New("stale writer cannot record accounting")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "accounting.record" || commerce.VerifyAuthorizedAction(action, expected, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, AccountingEntry{}, errors.New("accounting action is not authorized")
	}
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		existing, present := authority.doc.Accounting[entry.EntryID]
		if prior.ExactRequestDigest != action.ExactRequestDigest || !present || !reflect.DeepEqual(existing, entry) {
			return commerce.ActionResolution{}, AccountingEntry{}, errors.New("accounting retry conflicts")
		}
		return prior, existing, nil
	}
	next := cloneAuthorityDocument(authority.doc)
	next.Accounting[entry.EntryID] = entry
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, EvidenceRefs: append([]string(nil), entry.Body.EvidenceRefs...), StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, AccountingEntry{}, err
	}
	authority.doc = next
	return resolution, entry, nil
}

func (authority *PersonalAuthority) AccountingSnapshot() []AccountingEntry {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	result := make([]AccountingEntry, 0, len(authority.doc.Accounting))
	for _, entry := range authority.doc.Accounting {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].EntryID < result[j].EntryID })
	return result
}

type AccountingService struct{ Engine *Engine }

func (service AccountingService) Record(ctx context.Context, body AccountingEntryBody,
	policyRevision uint64, fence commerce.WriterFence) (AccountingEntry, error) {
	if service.Engine == nil || service.Engine.Authority == nil || !service.Engine.permits("accounting", true, false) || ctx == nil || ctx.Err() != nil {
		return AccountingEntry{}, errors.New("accounting is unavailable")
	}
	body.OwnerID, body.AgentID = service.Engine.OwnerID, service.Engine.AgentID
	entryID, err := AccountingEntryID(body)
	if err != nil {
		return AccountingEntry{}, err
	}
	entry := AccountingEntry{EntryID: entryID, Body: body, WriterGeneration: fence.Body.WriterGeneration}
	canonical, err := codec.Marshal(entry)
	if err != nil {
		return AccountingEntry{}, err
	}
	evidenceSetDigest, _ := codec.Digest("tos.accounting-evidence-set.v1", body.EvidenceRefs)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(body.OwnerID), "agent_id": commerce.ID(body.AgentID),
		"entry_id": commerce.Digest32(entryID), "classification": commerce.Kind(string(body.Classification)),
		"evidence_set_digest": commerce.Digest32(evidenceSetDigest)}
	action, err := commerce.BuildAuthorizedAction(body.OwnerID, body.AgentID, "accounting.record", fields, canonical, fence,
		policyRevision, service.Engine.MandateDigest, "", "absent", fence.Body.ExpiresAtUnix)
	if err == nil {
		action, err = service.Engine.Authority.SignAction(action, fence)
	}
	if err != nil {
		return AccountingEntry{}, err
	}
	_, recorded, err := service.Engine.Authority.RecordAccounting(action, fields, canonical, fence, entry)
	return recorded, err
}

func (service AccountingService) RecordGift(ctx context.Context, amount commerce.AgreementAmount,
	signedGiftDigest, finalizedTransferDigest string, observedAt time.Time, policyRevision uint64,
	fence commerce.WriterFence) (AccountingEntry, error) {
	evidence := []string{signedGiftDigest, finalizedTransferDigest}
	sort.Strings(evidence)
	return service.Record(ctx, AccountingEntryBody{SchemaVersion: 1, Classification: AccountingGratuity, Amount: &amount,
		SourceReference: "agent-gift", EvidenceRefs: evidence, ObservedAtUnix: uint64(observedAt.UTC().Unix())}, policyRevision, fence)
}
