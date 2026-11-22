package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// A plan is the exact action a coordinator prepared before a side effect, kept
// so that a crash is recovered by replaying that action instead of deriving a
// second one. Replaying it needs the action's semantic fields: they derive its
// stable identity and the authority checks them again on admission. Their
// values have no exported form, so the document stores them in the transport
// form, in registry order, in the same document write as the rest of the
// plan. A plan whose fields cannot be exported or imported is not stored and
// is not loaded.

// encodeGuarantorPlan encodes plan with its semantic fields in transport form.
// plan is passed as a type without methods, so its own encoding is the plain
// field-by-field one; its semantic-fields member is then replaced.
func encodeGuarantorPlan(plan any, actionKind string, fields map[string]commerce.SemanticValue) ([]byte, error) {
	wire, err := commerce.ExportSemanticFields(actionKind, fields)
	if err != nil {
		return nil, fmt.Errorf("export Guarantor plan semantic fields: %w", err)
	}
	object, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(object, &members); err != nil {
		return nil, err
	}
	encodedFields, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	members[guarantorPlanFieldsMember] = encodedFields
	return json.Marshal(members)
}

// guarantorPlanFieldsMember is the document member holding a plan's semantic
// fields.
const guarantorPlanFieldsMember = "semantic_fields"

// decodeGuarantorPlan decodes a plan document into plan, a pointer to a type
// without methods, and returns its semantic fields' transport form; plan's own
// semantic fields are left unset for the caller to import. Unknown and
// repeated members, a missing field list and trailing data are refused.
func decodeGuarantorPlan(raw []byte, plan any) ([]commerce.SemanticFieldValue, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	encodedFields, found := members[guarantorPlanFieldsMember]
	if !found {
		return nil, errors.New("Guarantor plan has no semantic fields")
	}
	var wire []commerce.SemanticFieldValue
	if err := decodeStrictJSON(encodedFields, &wire); err != nil {
		return nil, fmt.Errorf("decode Guarantor plan semantic fields: %w", err)
	}
	delete(members, guarantorPlanFieldsMember)
	rest, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	if err := decodeStrictJSON(rest, plan); err != nil {
		return nil, err
	}
	return wire, nil
}

// importGuarantorPlanFields rebuilds a plan's semantic fields from their
// transport form for the plan's own action kind.
func importGuarantorPlanFields(actionKind string, wire []commerce.SemanticFieldValue) (map[string]commerce.SemanticValue, error) {
	fields, err := commerce.ImportSemanticFields(actionKind, wire)
	if err != nil {
		return nil, fmt.Errorf("import Guarantor plan semantic fields: %w", err)
	}
	return fields, nil
}

// The four plan types encode and decode through the helpers above. Each
// method's local type has the plan's fields and none of its methods.

func (plan GuarantorPreAcceptanceReleasePlan) MarshalJSON() ([]byte, error) {
	type fieldsOnly GuarantorPreAcceptanceReleasePlan
	return encodeGuarantorPlan(fieldsOnly(plan), plan.Action.ActionKind, plan.Fields)
}

func (plan *GuarantorPreAcceptanceReleasePlan) UnmarshalJSON(raw []byte) error {
	type fieldsOnly GuarantorPreAcceptanceReleasePlan
	var decoded fieldsOnly
	wire, err := decodeGuarantorPlan(raw, &decoded)
	if err != nil {
		return err
	}
	fields, err := importGuarantorPlanFields(decoded.Action.ActionKind, wire)
	if err != nil {
		return err
	}
	*plan = GuarantorPreAcceptanceReleasePlan(decoded)
	plan.Fields = fields
	return nil
}

func (plan GuarantorFirmOfferIssuancePlan) MarshalJSON() ([]byte, error) {
	type fieldsOnly GuarantorFirmOfferIssuancePlan
	return encodeGuarantorPlan(fieldsOnly(plan), plan.Action.ActionKind, plan.Fields)
}

func (plan *GuarantorFirmOfferIssuancePlan) UnmarshalJSON(raw []byte) error {
	type fieldsOnly GuarantorFirmOfferIssuancePlan
	var decoded fieldsOnly
	wire, err := decodeGuarantorPlan(raw, &decoded)
	if err != nil {
		return err
	}
	fields, err := importGuarantorPlanFields(decoded.Action.ActionKind, wire)
	if err != nil {
		return err
	}
	*plan = GuarantorFirmOfferIssuancePlan(decoded)
	plan.Fields = fields
	return nil
}

func (plan GuarantorExposureReleasePlan) MarshalJSON() ([]byte, error) {
	type fieldsOnly GuarantorExposureReleasePlan
	return encodeGuarantorPlan(fieldsOnly(plan), plan.Action.ActionKind, plan.Fields)
}

func (plan *GuarantorExposureReleasePlan) UnmarshalJSON(raw []byte) error {
	type fieldsOnly GuarantorExposureReleasePlan
	var decoded fieldsOnly
	wire, err := decodeGuarantorPlan(raw, &decoded)
	if err != nil {
		return err
	}
	fields, err := importGuarantorPlanFields(decoded.Action.ActionKind, wire)
	if err != nil {
		return err
	}
	*plan = GuarantorExposureReleasePlan(decoded)
	plan.Fields = fields
	return nil
}

func (plan GuarantorCoverageResolutionPlan) MarshalJSON() ([]byte, error) {
	type fieldsOnly GuarantorCoverageResolutionPlan
	return encodeGuarantorPlan(fieldsOnly(plan), plan.Action.ActionKind, plan.Fields)
}

func (plan *GuarantorCoverageResolutionPlan) UnmarshalJSON(raw []byte) error {
	type fieldsOnly GuarantorCoverageResolutionPlan
	var decoded fieldsOnly
	wire, err := decodeGuarantorPlan(raw, &decoded)
	if err != nil {
		return err
	}
	fields, err := importGuarantorPlanFields(decoded.Action.ActionKind, wire)
	if err != nil {
		return err
	}
	*plan = GuarantorCoverageResolutionPlan(decoded)
	plan.Fields = fields
	return nil
}

// guarantorPlanFieldValues is a plan's semantic fields in transport form,
// keyed by field name, for comparing them with the objects the plan refers to.
type guarantorPlanFieldValues map[string]commerce.SemanticFieldValue

// text reports whether the named field is a text field holding want.
func (values guarantorPlanFieldValues) text(name, want string) bool {
	value, found := values[name]
	return found && value.Number == nil && want != "" && value.Text == want
}

// number reports whether the named field is a number field holding want.
func (values guarantorPlanFieldValues) number(name string, want uint64) bool {
	value, found := values[name]
	return found && value.Number != nil && value.Text == "" && *value.Number == want
}

// validateGuarantorPlanAction checks what every stored plan must satisfy,
// whatever it plans: its action is of the expected kind and belongs to this
// journal's owner and Agent, its semantic fields derive the action's stable
// identity, and its canonical request has the action's exact request digest.
// It returns the fields in transport form.
func validateGuarantorPlanAction(ownerID, agentID, actionKind string, action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte) (guarantorPlanFieldValues, error) {
	if action.ActionKind != actionKind || action.OwnerID != ownerID || action.AgentID != agentID {
		return nil, errors.New("Guarantor plan action has another kind, owner or Agent")
	}
	wire, err := commerce.ExportSemanticFields(actionKind, fields)
	if err != nil {
		return nil, fmt.Errorf("Guarantor plan semantic fields are invalid: %w", err)
	}
	stableActionID, _, err := commerce.DeriveStableActionID(actionKind, fields)
	if err != nil || stableActionID != action.StableActionID {
		return nil, errors.New("Guarantor plan semantic fields do not derive its stable action identity")
	}
	requestDigest, err := commerce.ExactRequestDigest(canonicalRequest)
	if err != nil || requestDigest != action.ExactRequestDigest {
		return nil, errors.New("Guarantor plan canonical request does not have its exact request digest")
	}
	values := make(guarantorPlanFieldValues, len(wire))
	for _, value := range wire {
		values[value.Name] = value
	}
	if !values.text("owner_id", ownerID) || !values.text("agent_id", agentID) {
		return nil, errors.New("Guarantor plan semantic fields name another owner or Agent")
	}
	return values, nil
}

// validateGuarantorPlanFence requires a plan's writer fence to be the one its
// action was authorized under.
func validateGuarantorPlanFence(action commerce.AuthorizedAction, fence commerce.WriterFence) error {
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil || fenceDigest != action.WriterFenceDigest || fence.Body.WriterGeneration != action.WriterGeneration {
		return errors.New("Guarantor plan writer fence is not the one its action was authorized under")
	}
	if _, err := commerce.AuthorizedActionDigest(action); err != nil {
		return fmt.Errorf("Guarantor plan action: %w", err)
	}
	return nil
}

// validatePreAcceptanceReleasePlan checks an expired offer's release plan
// against the offer position holding it: the stored non-acceptance evidence
// the release is for, the reservation it releases and, once released, the
// stored release receipt.
func validatePreAcceptanceReleasePlan(ownerID, agentID string, position GuarantorOfferPosition,
	plan GuarantorPreAcceptanceReleasePlan) error {
	values, err := validateGuarantorPlanAction(ownerID, agentID, "portfolio.release", plan.Action, plan.Fields,
		plan.CanonicalRequest)
	if err != nil {
		return err
	}
	if (position.Record.Status != guarantor.OfferExpired && position.Record.Status != guarantor.OfferReleased) ||
		position.NonAcceptanceEvidence == nil {
		return errors.New("Guarantor pre-acceptance release plan has no expired offer with non-acceptance evidence")
	}
	// The envelope digests are computed directly: this checks that the plan
	// belongs to the stored evidence. Whether the evidence itself is valid is
	// the protocol verifier's check, made wherever the evidence is used.
	evidenceDigest, err := guarantor.Digest(guarantor.OfferNonAcceptanceDomain, *position.NonAcceptanceEvidence)
	if err != nil {
		return fmt.Errorf("Guarantor pre-acceptance release plan: stored non-acceptance evidence: %w", err)
	}
	plannedDigest, err := guarantor.Digest(guarantor.OfferNonAcceptanceDomain,
		plan.RequestBody.AuthorizedNonAcceptanceEvidence)
	if err != nil || plannedDigest != evidenceDigest {
		return errors.New("Guarantor pre-acceptance release plan is for other non-acceptance evidence than the stored one")
	}
	target, overflow := addUint64(plan.BasePortfolioRevision, 1)
	if overflow || plan.TargetPortfolioRevision != target || plan.ReleasedAtUnix == 0 ||
		plan.RequestBody.ExpectedPortfolioRevision != plan.BasePortfolioRevision ||
		plan.RequestBody.TargetPortfolioRevision != plan.TargetPortfolioRevision {
		return errors.New("Guarantor pre-acceptance release plan revisions or time are inconsistent")
	}
	if !values.text("reservation_id", position.Record.ReservationID) ||
		!values.number("target_revision", plan.TargetPortfolioRevision) ||
		!values.text("terminal_evidence_set_digest", evidenceDigest) {
		return errors.New("Guarantor pre-acceptance release plan semantic fields differ from its offer")
	}
	if receipt := position.PreAcceptanceReleaseReceipt; receipt != nil &&
		(receipt.Body.StableActionID != plan.Action.StableActionID ||
			receipt.Body.ExactRequestDigest != plan.Action.ExactRequestDigest ||
			receipt.Body.NonAcceptanceEvidenceDigest != evidenceDigest ||
			receipt.Body.BasePortfolioRevision != plan.BasePortfolioRevision ||
			receipt.Body.ReleasedPortfolioRevision != plan.TargetPortfolioRevision ||
			receipt.Body.ReleasedAtUnix != plan.ReleasedAtUnix) {
		return errors.New("Guarantor pre-acceptance release plan differs from the stored release receipt")
	}
	return nil
}

// validateExposureReleasePlan checks a coverage's exposure-release plan
// against the coverage position holding it: the stored terminal claim set the
// release is for, the reservation it releases and, once released, the stored
// release receipt.
func validateExposureReleasePlan(ownerID, agentID, agreementDigest string, position GuarantorCoveragePosition,
	plan GuarantorExposureReleasePlan) error {
	values, err := validateGuarantorPlanAction(ownerID, agentID, "portfolio.release", plan.Action, plan.Fields,
		plan.CanonicalRequest)
	if err != nil {
		return err
	}
	if err := validateGuarantorPlanFence(plan.Action, plan.WriterFence); err != nil {
		return err
	}
	if position.TerminalClaimSet == nil || plan.CreatedAtUnix == 0 || plan.RequestBody.TargetPortfolioRevision == 0 {
		return errors.New("Guarantor exposure-release plan has no stored terminal claim set, time or target revision")
	}
	terminalDigest, err := guarantor.TerminalClaimSetDigestV1(*position.TerminalClaimSet)
	if err != nil {
		return fmt.Errorf("Guarantor exposure-release plan: stored terminal claim set: %w", err)
	}
	request, err := guarantor.Canonical(plan.RequestBody)
	if err != nil || !bytes.Equal(request, plan.CanonicalRequest) ||
		plan.RequestBody.ReservationID != position.Record.ReservationID ||
		plan.RequestBody.AgreementDigest != agreementDigest ||
		plan.RequestBody.TerminalEvidenceSetDigest != terminalDigest {
		return errors.New("Guarantor exposure-release plan request differs from its coverage or terminal claim set")
	}
	if !values.text("reservation_id", position.Record.ReservationID) ||
		!values.number("target_revision", plan.RequestBody.TargetPortfolioRevision) ||
		!values.text("terminal_evidence_set_digest", terminalDigest) {
		return errors.New("Guarantor exposure-release plan semantic fields differ from its coverage")
	}
	if receipt := position.ExposureReleaseReceipt; receipt != nil {
		dispositionDigest, err := guarantor.ExposureDispositionComputationDigestV1(plan.Disposition)
		if err != nil || receipt.Body.ExposureDispositionComputationDigest != dispositionDigest ||
			receipt.Body.StableActionID != plan.Action.StableActionID ||
			receipt.Body.ExactRequestDigest != plan.Action.ExactRequestDigest ||
			receipt.Body.TerminalClaimSetEvidenceDigest != terminalDigest ||
			receipt.Body.ReleasedReleaseStateRevision != plan.RequestBody.TargetPortfolioRevision {
			return errors.New("Guarantor exposure-release plan differs from the stored release receipt")
		}
	}
	return nil
}

// validateCoverageResolutionPlan checks a coverage's resolution plan against
// the coverage position holding it: the stored exposure-release receipt the
// resolution is for, the terminal state the stored terminal claim set names
// and, once resolved, the stored coverage resolution.
func validateCoverageResolutionPlan(ownerID, agentID, agreementDigest string, position GuarantorCoveragePosition,
	plan GuarantorCoverageResolutionPlan) error {
	values, err := validateGuarantorPlanAction(ownerID, agentID, "conditional.obligation.transition", plan.Action,
		plan.Fields, plan.CanonicalRequest)
	if err != nil {
		return err
	}
	if err := validateGuarantorPlanFence(plan.Action, plan.WriterFence); err != nil {
		return err
	}
	if position.ExposureReleaseReceipt == nil || position.TerminalClaimSet == nil || plan.CreatedAtUnix == 0 {
		return errors.New("Guarantor coverage-resolution plan has no stored exposure release, terminal claim set or time")
	}
	releaseDigest, err := guarantor.ExposureReleaseReceiptDigestV1(*position.ExposureReleaseReceipt)
	if err != nil {
		return fmt.Errorf("Guarantor coverage-resolution plan: stored exposure release: %w", err)
	}
	targetStatus, targetState, err := guarantorTerminalCoverageTarget(position.TerminalClaimSet.Body.ResolutionTargetTerminalState)
	if err != nil || plan.TargetStatus != targetStatus || plan.TargetState != targetState {
		return errors.New("Guarantor coverage-resolution plan targets another state than the stored terminal claim set")
	}
	targetRevision, overflow := addUint64(plan.RequestBody.ExpectedRevision, 1)
	request, err := guarantor.Canonical(plan.RequestBody)
	if err != nil || overflow || !bytes.Equal(request, plan.CanonicalRequest) || plan.RequestBody.SchemaVersion != 1 ||
		plan.RequestBody.ExposureReleaseReceiptDigest != releaseDigest ||
		plan.RequestBody.TargetRevision != targetRevision {
		return errors.New("Guarantor coverage-resolution plan request differs from its stored exposure release")
	}
	if !values.text("agreement_body_digest", agreementDigest) ||
		!values.text("obligation_id", position.Record.CoverageObligationID) ||
		!values.number("expected_state_revision", plan.RequestBody.ExpectedRevision) ||
		!values.text("target_state", plan.TargetState) || !values.text("evidence_set_digest", releaseDigest) {
		return errors.New("Guarantor coverage-resolution plan semantic fields differ from its coverage")
	}
	resolution := position.CoverageResolution
	if resolution == nil {
		if position.Record.CoverageRevision != plan.RequestBody.ExpectedRevision {
			return errors.New("Guarantor coverage-resolution plan expects another coverage revision than the stored one")
		}
		return nil
	}
	if resolution.Body.StableActionID != plan.Action.StableActionID ||
		resolution.Body.ExactRequestDigest != plan.Action.ExactRequestDigest ||
		resolution.Body.TerminalState != plan.TargetState ||
		resolution.Body.ExposureReleaseReceiptDigest != releaseDigest ||
		resolution.Body.PriorCoverageRevision != plan.RequestBody.ExpectedRevision ||
		resolution.Body.ResolvedCoverageRevision != plan.RequestBody.TargetRevision {
		return errors.New("Guarantor coverage-resolution plan differs from the stored coverage resolution")
	}
	return nil
}

// validateFirmOfferIssuancePlan checks a firm-offer issuance plan against the
// offer and exposure admission receipt it carries and, once the offer is
// reserved, against the stored offer position.
func validateFirmOfferIssuancePlan(ownerID, agentID string, plan GuarantorFirmOfferIssuancePlan,
	stored *GuarantorOfferPosition) error {
	if !canonicalSHA256(plan.AuthorityInstanceID) || !canonicalSHA256(plan.AdmissionDomainID) ||
		!canonicalSHA256(plan.OfferDigest) || !canonicalSHA256(plan.ReceiptDigest) ||
		plan.Reservation.ReservationID == "" {
		return errors.New("Guarantor firm-offer issuance plan is invalid")
	}
	values, err := validateGuarantorPlanAction(ownerID, agentID, "commercial.quote.issue", plan.Action, plan.Fields,
		plan.CanonicalRequest)
	if err != nil {
		return err
	}
	offerDigest, offerErr := guarantor.FirmOfferDigest(plan.Offer)
	receiptDigest, receiptErr := guarantor.ExposureAdmissionReceiptDigestV1(plan.Offer.ExposureAdmissionReceipt)
	requestDigest, requestErr := guarantor.QuoteRequestDigest(plan.Offer.AuthorizedQuoteRequest)
	if offerErr != nil || receiptErr != nil || requestErr != nil || offerDigest != plan.OfferDigest ||
		receiptDigest != plan.ReceiptDigest || plan.Offer.Body.ExposureAdmissionReceiptDigest != plan.ReceiptDigest ||
		plan.Offer.Body.OfferID != plan.AuthorityInstanceID ||
		plan.Offer.Body.ReservationID != plan.Reservation.ReservationID ||
		plan.Offer.ExposureAdmissionReceipt.Body.StableActionID != plan.Action.StableActionID ||
		plan.Offer.ExposureAdmissionReceipt.Body.ExactRequestDigest != plan.Action.ExactRequestDigest ||
		plan.Position.Record.OfferID != plan.AuthorityInstanceID ||
		plan.Position.Record.ReservationID != plan.Reservation.ReservationID {
		return errors.New("Guarantor firm-offer issuance plan binding is invalid")
	}
	if !values.text("authority_instance_id", plan.AuthorityInstanceID) ||
		!values.text("agreement_body_digest", plan.Offer.Body.CoverageAgreementBodyDigest) ||
		!values.text("quote_request_digest", requestDigest) {
		return errors.New("Guarantor firm-offer issuance plan semantic fields differ from its offer")
	}
	if plan.Position.AuthorizedFirmOffer == nil {
		return errors.New("Guarantor firm-offer issuance plan position has no offer")
	}
	if digest, err := guarantor.FirmOfferDigest(*plan.Position.AuthorizedFirmOffer); err != nil || digest != plan.OfferDigest {
		return errors.New("Guarantor firm-offer issuance plan position carries another offer")
	}
	if stored != nil && stored.AuthorizedFirmOffer != nil {
		if digest, err := guarantor.FirmOfferDigest(*stored.AuthorizedFirmOffer); err != nil || digest != plan.OfferDigest {
			return errors.New("Guarantor firm-offer issuance plan differs from the stored offer")
		}
	}
	return nil
}

// validateGuarantorPlans checks every plan in a document against the objects
// stored beside it. A journal loads only when all of them pass, so a plan that
// was changed on disk, or that no longer belongs to its stored receipts, is
// refused before anything can resume from it.
func validateGuarantorPlans(doc guarantorJournalDocument) error {
	for offerID, position := range doc.Offers {
		if position.PreAcceptanceReleasePlan == nil {
			continue
		}
		if err := validatePreAcceptanceReleasePlan(doc.OwnerID, doc.AgentID, position,
			*position.PreAcceptanceReleasePlan); err != nil {
			return fmt.Errorf("offer %s: %w", offerID, err)
		}
	}
	for planID, plan := range doc.FirmOfferIssuancePlans {
		var stored *GuarantorOfferPosition
		if position, found := doc.Offers[planID]; found {
			stored = &position
		}
		if planID != plan.AuthorityInstanceID {
			return fmt.Errorf("firm-offer issuance plan %s is stored under another identity", planID)
		}
		if err := validateFirmOfferIssuancePlan(doc.OwnerID, doc.AgentID, plan, stored); err != nil {
			return fmt.Errorf("firm-offer issuance plan %s: %w", planID, err)
		}
	}
	for agreementDigest, position := range doc.Coverages {
		if position.ExposureReleasePlan != nil {
			if err := validateExposureReleasePlan(doc.OwnerID, doc.AgentID, agreementDigest, position,
				*position.ExposureReleasePlan); err != nil {
				return fmt.Errorf("coverage %s: %w", agreementDigest, err)
			}
		}
		if position.CoverageResolutionPlan != nil {
			if err := validateCoverageResolutionPlan(doc.OwnerID, doc.AgentID, agreementDigest, position,
				*position.CoverageResolutionPlan); err != nil {
				return fmt.Errorf("coverage %s: %w", agreementDigest, err)
			}
		}
	}
	return nil
}
