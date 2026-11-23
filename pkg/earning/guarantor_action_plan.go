package earning

import (
	"errors"
	"fmt"
	"sort"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// GuarantorActionPlan is the action a coordinator call prepared for one head
// of the journal: the acceptance of an offer, the activation of a coverage,
// a claim's ingress, a decision's admission and so on. It is stored before
// the authority sees the action. The authority then admits the action and
// makes it terminal, and the commit that stores the call's receipt removes
// the plan in the same document write.
//
// A call that stops anywhere in between, with the action unknown, prepared or
// terminal at the authority, is repeated with the same request and resumes
// from the plan: it takes the plan's action, the writer fence the action was
// authorized under and the plan's time, asks the authority only for what it
// has not done yet, and builds the receipt the first call would have built.
// That holds whichever writer generation repeats the call and whatever time
// it has: the plan is the record of what was prepared, and a request rebuilt
// at another time would be another request. A different request for the same
// head is refused while the plan's action is known to the authority.
type GuarantorActionPlan struct {
	// Kind names the coordinator call the plan belongs to.
	Kind string `json:"kind"`
	// ScopeID is the coverage Agreement digest the head belongs to, or the
	// offer identity for an acceptance, which precedes its coverage.
	ScopeID string `json:"scope_id"`
	// SubjectID names the head inside the scope: a claim, or a claim revision.
	// It is empty for a head there is one of per scope.
	SubjectID        string                            `json:"subject_id,omitempty"`
	Action           commerce.AuthorizedAction         `json:"authorized_action"`
	WriterFence      commerce.WriterFence              `json:"writer_fence"`
	Fields           map[string]commerce.SemanticValue `json:"semantic_fields"`
	CanonicalRequest []byte                            `json:"canonical_request"`
	// PreparedAtUnix is the time of the call that prepared the plan. A resumed
	// call uses it wherever the first call used its own time.
	PreparedAtUnix uint64 `json:"prepared_at_unix"`
}

// The kinds of action plan, one per coordinator call that makes an authority
// action terminal before it commits its receipt.
const (
	guarantorPlanCoverageAcceptance   = "coverage_acceptance"
	guarantorPlanCoverageActivation   = "coverage_activation"
	guarantorPlanClaimIngress         = "claim_ingress"
	guarantorPlanClaimAdmission       = "claim_admission"
	guarantorPlanDecisionAdmission    = "decision_admission"
	guarantorPlanClaimTransition      = "claim_transition"
	guarantorPlanDecisionApplication  = "decision_application"
	guarantorPlanCoverageCancellation = "coverage_cancellation"
	guarantorPlanNonActivation        = "non_activation"
	guarantorPlanNonActivationRelease = "non_activation_release"
	guarantorPlanClaimFilingClose     = "claim_filing_close"
	guarantorPlanCoverageClosure      = "coverage_closure"
)

// guarantorActionPlanKind is what the journal knows about one kind of action
// plan: the kind of the action it holds and whether its scope is an offer.
type guarantorActionPlanKind struct {
	actionKind  string
	offerScoped bool
}

var guarantorActionPlanKinds = map[string]guarantorActionPlanKind{
	guarantorPlanCoverageAcceptance:   {actionKind: "conditional.obligation.transition", offerScoped: true},
	guarantorPlanCoverageActivation:   {actionKind: "conditional.obligation.transition"},
	guarantorPlanClaimIngress:         {actionKind: "conditional.claim.ingress"},
	guarantorPlanClaimAdmission:       {actionKind: "conditional.claim.submit"},
	guarantorPlanDecisionAdmission:    {actionKind: "conditional.claim-decision.admit"},
	guarantorPlanClaimTransition:      {actionKind: "conditional.claim.transition"},
	guarantorPlanDecisionApplication:  {actionKind: "conditional.claim.decide"},
	guarantorPlanCoverageCancellation: {actionKind: "conditional.obligation.transition"},
	guarantorPlanNonActivation:        {actionKind: "conditional.obligation.transition"},
	guarantorPlanNonActivationRelease: {actionKind: "portfolio.release"},
	guarantorPlanClaimFilingClose:     {actionKind: "conditional.claim-filing.close"},
	guarantorPlanCoverageClosure:      {actionKind: "conditional.obligation.transition"},
}

// guarantorActionPlanKey is the key an action plan is stored under. A kind
// and a scope are fixed-form, so the three parts cannot be confused whatever
// the subject holds.
func guarantorActionPlanKey(kind, scopeID, subjectID string) string {
	return kind + "/" + scopeID + "/" + subjectID
}

func (plan GuarantorActionPlan) MarshalJSON() ([]byte, error) {
	type fieldsOnly GuarantorActionPlan
	return encodeGuarantorPlan(fieldsOnly(plan), plan.Action.ActionKind, plan.Fields)
}

func (plan *GuarantorActionPlan) UnmarshalJSON(raw []byte) error {
	type fieldsOnly GuarantorActionPlan
	var decoded fieldsOnly
	wire, err := decodeGuarantorPlan(raw, &decoded)
	if err != nil {
		return err
	}
	fields, err := importGuarantorPlanFields(decoded.Action.ActionKind, wire)
	if err != nil {
		return err
	}
	*plan = GuarantorActionPlan(decoded)
	plan.Fields = fields
	return nil
}

// validateGuarantorActionPlan checks an action plan against the document that
// holds it, when the plan is stored and when the journal loads: its kind is
// known, it is stored under its own key, its action is of that kind's action
// kind and belongs to this journal, its fields derive the action's stable
// identity, its request has the action's request digest, its writer fence is
// the one the action was authorized under, and the offer or coverage it is
// scoped to exists and is the one its fields name.
//
// The plan's time must lie where the receipt built at it can verify: inside
// the lease of the plan's writer fence, with the clock skew a verifier
// allows before its issue, and before the action expires. Nothing signs the
// time itself, so a time moved inside that interval is not detected here; a
// resumed call rebuilds its request at the plan's time, and a request that
// depends on the time then no longer has the plan's request digest and is
// refused. Not bound here either, as for the other plans: the action's
// authorization metadata outside its stable identity and request digest. The
// authority verified the action when it admitted it, and a resumed call asks
// the authority for the action by the identity and digest checked here.
func validateGuarantorActionPlan(doc guarantorJournalDocument, key string, plan GuarantorActionPlan) error {
	kind, known := guarantorActionPlanKinds[plan.Kind]
	if !known || key != guarantorActionPlanKey(plan.Kind, plan.ScopeID, plan.SubjectID) ||
		!canonicalSHA256(plan.ScopeID) || !validGuarantorUnix(plan.PreparedAtUnix) {
		return errors.New("Guarantor action plan kind, key, scope or time is invalid")
	}
	values, err := validateGuarantorPlanAction(doc.OwnerID, doc.AgentID, kind.actionKind, plan.Action, plan.Fields,
		plan.CanonicalRequest)
	if err != nil {
		return err
	}
	if err = validateGuarantorPlanFence(plan.Action, plan.WriterFence); err != nil {
		return err
	}
	if !guarantorPlanTimeInLease(plan.PreparedAtUnix, plan.Action, plan.WriterFence) {
		return errors.New("Guarantor action plan time lies outside the lease of its writer fence")
	}
	if kind.offerScoped {
		offer, found := doc.Offers[plan.ScopeID]
		if !found {
			return errors.New("Guarantor action plan is scoped to an offer the journal does not hold")
		}
		if !values.text("agreement_body_digest", offer.Record.AgreementDigest) {
			return errors.New("Guarantor action plan semantic fields name another coverage Agreement than its offer")
		}
		return nil
	}
	coverage, found := doc.Coverages[plan.ScopeID]
	if !found {
		return errors.New("Guarantor action plan is scoped to a coverage the journal does not hold")
	}
	// A release names the reservation it releases; every other action names
	// the coverage Agreement.
	if kind.actionKind == "portfolio.release" {
		if !values.text("reservation_id", coverage.Record.ReservationID) {
			return errors.New("Guarantor action plan semantic fields name another reservation than its coverage")
		}
		return nil
	}
	if !values.text("agreement_body_digest", plan.ScopeID) {
		return errors.New("Guarantor action plan semantic fields name another coverage Agreement than its scope")
	}
	return nil
}

// checkedActionResolver is an authority that reports when it could not
// answer whether it holds an action.
type checkedActionResolver interface {
	ResolveChecked(stableActionID, exactRequestDigest string) (commerce.ActionResolution, error)
}

// resolveGuarantorAction asks authority what it holds for an action. An
// authority that could not answer returns an error: that says nothing about
// the action, and a plan is never discarded or built on it. An authority that
// cannot tell the two apart is asked with Resolve, which reports a failure as
// a state no caller builds on.
func resolveGuarantorAction(authority EconomicAuthority, stableActionID, exactRequestDigest string,
) (commerce.ActionResolution, error) {
	if authority == nil {
		return commerce.ActionResolution{}, errors.New("Guarantor action authority is unavailable")
	}
	if checked, ok := authority.(checkedActionResolver); ok {
		return checked.ResolveChecked(stableActionID, exactRequestDigest)
	}
	return authority.Resolve(stableActionID, exactRequestDigest), nil
}

// ResolveGuarantorAction is resolveGuarantorAction for an operator command
// that shows an action's state: an authority that could not answer is an
// error, never a state.
func ResolveGuarantorAction(authority EconomicAuthority, stableActionID, exactRequestDigest string,
) (commerce.ActionResolution, error) {
	return resolveGuarantorAction(authority, stableActionID, exactRequestDigest)
}

// guarantorPlanTimeInLease reports whether at, a Unix second, is a time at
// which action under fence verifies: not earlier than the fence's issue less
// the clock skew a verifier allows, and before both the fence's and the
// action's expiry.
func guarantorPlanTimeInLease(at uint64, action commerce.AuthorizedAction, fence commerce.WriterFence) bool {
	skew := uint64(commerce.MaxIntentClockSkew / time.Second)
	earliest := uint64(0)
	if fence.Body.IssuedAtUnix > skew {
		earliest = fence.Body.IssuedAtUnix - skew
	}
	return at >= earliest && at < fence.Body.ExpiresAtUnix && at < action.ExpiresAtUnix
}

// ActionPlans returns every stored action plan as private copies, ordered by
// the key each is stored under. An error means the journal could not be read.
func (journal *GuarantorJournal) ActionPlans() ([]GuarantorActionPlan, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return nil, err
	}
	if len(journal.doc.ActionPlans) == 0 {
		return nil, nil
	}
	doc, err := journal.workingCopy()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(doc.ActionPlans))
	for key := range doc.ActionPlans {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	plans := make([]GuarantorActionPlan, 0, len(keys))
	for _, key := range keys {
		plans = append(plans, doc.ActionPlans[key])
	}
	return plans, nil
}

// ActionPlan returns the stored action plan of one head as a private copy,
// and whether there is one. An error means the journal could not be read: it
// says nothing about the plan, and a caller must not treat it as "no plan".
func (journal *GuarantorJournal) ActionPlan(kind, scopeID, subjectID string) (GuarantorActionPlan, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.readable(); err != nil {
		return GuarantorActionPlan{}, false, err
	}
	key := guarantorActionPlanKey(kind, scopeID, subjectID)
	if _, found := journal.doc.ActionPlans[key]; !found {
		return GuarantorActionPlan{}, false, nil
	}
	doc, err := journal.workingCopy()
	if err != nil {
		return GuarantorActionPlan{}, false, err
	}
	plan, found := doc.ActionPlans[key]
	return plan, found, nil
}

// PrepareActionPlan stores the action plan of one head. The same plan stored
// again changes nothing; another plan for a head that has one is refused, so
// a head never holds two prepared actions.
func (journal *GuarantorJournal) PrepareActionPlan(plan GuarantorActionPlan) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	key := guarantorActionPlanKey(plan.Kind, plan.ScopeID, plan.SubjectID)
	// The plan is checked exactly as a load checks it, so nothing is stored
	// that a restart would refuse.
	if err = validateGuarantorActionPlan(next, key, plan); err != nil {
		return err
	}
	if existing, found := next.ActionPlans[key]; found {
		if sameJSON(existing, plan) {
			return nil
		}
		return errors.New("Guarantor action plan conflicts with the plan stored for its head")
	}
	if next.ActionPlans == nil {
		next.ActionPlans = map[string]GuarantorActionPlan{}
	}
	next.ActionPlans[key] = plan
	next.Revision++
	return journal.commit(next)
}

// DiscardUnadmittedActionPlan removes the action plan of one head when the
// authority has never seen its action, so nothing was done under it. A plan
// whose action the authority knows is never discarded: it is resumed.
func (journal *GuarantorJournal) DiscardUnadmittedActionPlan(kind, scopeID, subjectID string,
	authority EconomicAuthority,
) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	if authority == nil {
		return errors.New("Guarantor action plan discard has no authority to ask")
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	key := guarantorActionPlanKey(kind, scopeID, subjectID)
	plan, found := next.ActionPlans[key]
	if !found {
		return nil
	}
	resolution, err := resolveGuarantorAction(authority, plan.Action.StableActionID, plan.Action.ExactRequestDigest)
	if err != nil {
		return fmt.Errorf("Guarantor action plan is kept while its authority cannot say whether it holds the "+
			"action: %w", err)
	}
	if resolution.State != commerce.ActionUnknown {
		return errors.New("an admitted Guarantor action plan cannot be discarded")
	}
	delete(next.ActionPlans, key)
	next.Revision++
	return journal.commit(next)
}

// DiscardRejectedActionPlan removes the action plan of one head after the
// authority rejected its action: the call it belonged to has ended without a
// receipt and the head is free for another request.
func (journal *GuarantorJournal) DiscardRejectedActionPlan(kind, scopeID, subjectID string,
	rejection commerce.ActionResolution,
) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return err
	}
	next, err := journal.workingCopy()
	if err != nil {
		return err
	}
	key := guarantorActionPlanKey(kind, scopeID, subjectID)
	plan, found := next.ActionPlans[key]
	if !found {
		return nil
	}
	if rejection.State != commerce.ActionRejected || rejection.StableActionID != plan.Action.StableActionID ||
		rejection.ExactRequestDigest != plan.Action.ExactRequestDigest {
		return errors.New("Guarantor action plan is discarded only by the rejection of its own action")
	}
	delete(next.ActionPlans, key)
	next.Revision++
	return journal.commit(next)
}

// AbandonPreparedActionPlan gives up the action plan of one head whose action
// the authority holds as prepared: the authority rejects the action first,
// and the plan is discarded after, so a stop between the two leaves a plan of
// a rejected action, which the next call or abandonment discards. A plan
// whose action the authority never saw, or has already rejected, is only
// discarded. A plan whose action is terminal is refused: its receipt is
// completed by repeating its request, never abandoned. The caller holds fence,
// the current writer fence, which must not be older than the plan's.
//
// The rejection is final for the action's stable identity: the authority
// keeps it, so the same request cannot be admitted again for that head.
func (journal *GuarantorJournal) AbandonPreparedActionPlan(kind, scopeID, subjectID string,
	authority EconomicAuthority, fence commerce.WriterFence, now time.Time,
) (GuarantorActionPlan, commerce.ActionResolution, error) {
	if authority == nil {
		return GuarantorActionPlan{}, commerce.ActionResolution{},
			errors.New("Guarantor action plan abandonment has no authority to ask")
	}
	plan, found, err := journal.ActionPlan(kind, scopeID, subjectID)
	if err != nil {
		return GuarantorActionPlan{}, commerce.ActionResolution{}, err
	}
	if !found {
		return GuarantorActionPlan{}, commerce.ActionResolution{},
			errors.New("Guarantor journal holds no action plan for that head")
	}
	if err = authority.ConfirmCurrentWriterFence(fence, now); err != nil {
		return plan, commerce.ActionResolution{}, fmt.Errorf("Guarantor action plan abandonment writer: %w", err)
	}
	if fence.Body.WriterGeneration < plan.Action.WriterGeneration {
		return plan, commerce.ActionResolution{}, errors.New("stale writer cannot abandon a Guarantor action plan")
	}
	resolution, err := resolveGuarantorAction(authority, plan.Action.StableActionID, plan.Action.ExactRequestDigest)
	if err != nil {
		return plan, commerce.ActionResolution{}, err
	}
	switch resolution.State {
	case commerce.ActionUnknown:
		return plan, resolution, journal.DiscardUnadmittedActionPlan(kind, scopeID, subjectID, authority)
	case commerce.ActionRejected:
		return plan, resolution, journal.DiscardRejectedActionPlan(kind, scopeID, subjectID, resolution)
	case commerce.ActionPrepared:
		rejected, transitionErr := authority.Transition(plan.Action.StableActionID, plan.Action.ExactRequestDigest,
			commerce.ActionRejected, "", nil)
		if transitionErr != nil {
			return plan, resolution, fmt.Errorf("reject the prepared Guarantor action: %w", transitionErr)
		}
		return plan, rejected, journal.DiscardRejectedActionPlan(kind, scopeID, subjectID, rejected)
	case commerce.ActionTerminal:
		return plan, resolution, errors.New(
			"Guarantor action is terminal at its authority; repeat its request to commit the receipt instead")
	default:
		return plan, resolution, fmt.Errorf(
			"Guarantor action plan cannot be abandoned while its authority reports %s", resolution.State)
	}
}

// guarantorPlannedAction is one head's action inside a coordinator call: the
// plan a repeated call resumes from, or nothing for a first call.
type guarantorPlannedAction struct {
	kind, scopeID, subjectID string
	// resume is the stored plan whose action the authority already knows.
	resume *GuarantorActionPlan
}

// resuming reports whether the call continues a stored plan.
func (planned guarantorPlannedAction) resuming() bool { return planned.resume != nil }

// plannedAction looks up the action plan of one head for a coordinator call
// made under fence. A plan whose action the authority never saw is discarded:
// nothing was done under it, and the call starts again as a first call. A
// plan whose action is prepared or terminal at the authority is returned to be
// resumed with its own action, fence and time, by its own writer generation or
// a newer one. An authority that cannot be reached or reports any other state
// leaves the plan as it is and the call fails; it is repeated once the
// authority answers.
func (coordinator *GuarantorProviderCoordinator) plannedAction(kind, scopeID, subjectID string,
	fence commerce.WriterFence,
) (guarantorPlannedAction, error) {
	planned := guarantorPlannedAction{kind: kind, scopeID: scopeID, subjectID: subjectID}
	plan, found, err := coordinator.Journal.ActionPlan(kind, scopeID, subjectID)
	if err != nil || !found {
		return planned, err
	}
	resolution, err := resolveGuarantorAction(coordinator.Authority, plan.Action.StableActionID,
		plan.Action.ExactRequestDigest)
	if err != nil {
		return planned, fmt.Errorf("Guarantor action plan cannot be resumed until its authority answers: %w", err)
	}
	switch resolution.State {
	case commerce.ActionUnknown:
		return planned, coordinator.Journal.DiscardUnadmittedActionPlan(kind, scopeID, subjectID, coordinator.Authority)
	case commerce.ActionRejected:
		// The call the plan belonged to rejected its action and stopped
		// before removing the plan. It has no receipt; the head is free.
		return planned, coordinator.Journal.DiscardRejectedActionPlan(kind, scopeID, subjectID, resolution)
	case commerce.ActionPrepared, commerce.ActionTerminal:
		if !guarantorPlanTimeInLease(plan.PreparedAtUnix, plan.Action, plan.WriterFence) {
			return planned, errors.New("stored Guarantor action plan has an invalid time")
		}
		if fence.Body.WriterGeneration < plan.Action.WriterGeneration {
			return planned, errors.New("stale writer cannot recover a Guarantor action plan")
		}
		planned.resume = &plan
		return planned, nil
	default:
		return planned, fmt.Errorf(
			"Guarantor action plan cannot be resumed while its authority reports %s; repeat the request when "+
				"the authority answers", resolution.State)
	}
}

// at returns the time a call uses: the plan's when it resumes one, so that
// the request and the receipt are the ones the first call built, and now
// otherwise.
func (planned guarantorPlannedAction) at(now time.Time) time.Time {
	if planned.resume != nil {
		return time.Unix(int64(planned.resume.PreparedAtUnix), 0).UTC()
	}
	return now
}

// atUnix is at for a call whose time is a Unix second in its input.
func (planned guarantorPlannedAction) atUnix(now uint64) uint64 {
	if planned.resume != nil {
		return planned.resume.PreparedAtUnix
	}
	return now
}

// fence returns the writer fence the call's action is authorized under: the
// plan's when it resumes one, and the caller's current fence otherwise. The
// caller's fence was confirmed current before the plan was looked up; the
// plan's fence is the one the prepared action and its receipt verify under at
// the plan's time.
func (planned guarantorPlannedAction) fence(current commerce.WriterFence) commerce.WriterFence {
	if planned.resume != nil {
		return planned.resume.WriterFence
	}
	return current
}

// authorize returns the call's authorized action. A first call builds and
// signs it under fence. A resumed call returns the plan's action, and only if
// the request of this call is the plan's: the same action kind, the same
// stable identity derived from fields and the same request digest. A
// different request for a head whose plan the authority knows is refused.
func (coordinator *GuarantorProviderCoordinator) authorizePlannedAction(planned guarantorPlannedAction,
	ownerID, agentID, actionKind string, fields map[string]commerce.SemanticValue, request []byte,
	fence commerce.WriterFence, expectedPriorState string, expiresAtUnix uint64,
) (commerce.AuthorizedAction, error) {
	if planned.resume == nil {
		action, err := commerce.BuildAuthorizedAction(ownerID, agentID, actionKind, fields, request, fence,
			coordinator.PolicyRevision, coordinator.MandateDigest, "", expectedPriorState, expiresAtUnix)
		if err != nil {
			return commerce.AuthorizedAction{}, err
		}
		return coordinator.Authority.SignAction(action, fence)
	}
	stableActionID, _, err := commerce.DeriveStableActionID(actionKind, fields)
	if err != nil {
		return commerce.AuthorizedAction{}, err
	}
	requestDigest, err := commerce.ExactRequestDigest(request)
	if err != nil {
		return commerce.AuthorizedAction{}, err
	}
	stored := planned.resume.Action
	if stored.ActionKind != actionKind || stored.OwnerID != ownerID || stored.AgentID != agentID ||
		stored.StableActionID != stableActionID || stored.ExactRequestDigest != requestDigest {
		return commerce.AuthorizedAction{}, errors.New(
			"Guarantor request conflicts with the action already prepared for its head; repeat that request first")
	}
	return stored, nil
}

// admitPlannedAction makes the authority know the call's action. A first call
// stores the plan and then admits the action, in that order: a stop between
// the two leaves a plan the authority never saw, which the next call
// discards. A resumed call asks the authority what it holds. The result is
// prepared or terminal; anything else is returned with an error.
func (coordinator *GuarantorProviderCoordinator) admitPlannedAction(planned guarantorPlannedAction,
	action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte,
	fence commerce.WriterFence, now time.Time,
) (commerce.ActionResolution, error) {
	return coordinator.admitPlannedActionBy(planned, action, fields, request, fence, now,
		func() (commerce.ActionResolution, error) {
			return coordinator.Authority.Admit(action, fields, request, fence, nil)
		})
}

// admitPlannedActionBy is admitPlannedAction with admit as the authority call
// that first makes the action known: an admission, or a call that admits the
// action and applies its effect in one step.
func (coordinator *GuarantorProviderCoordinator) admitPlannedActionBy(planned guarantorPlannedAction,
	action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte,
	fence commerce.WriterFence, now time.Time, admit func() (commerce.ActionResolution, error),
) (commerce.ActionResolution, error) {
	var resolution commerce.ActionResolution
	if planned.resume != nil {
		var err error
		resolution, err = resolveGuarantorAction(coordinator.Authority, action.StableActionID,
			action.ExactRequestDigest)
		if err != nil {
			return commerce.ActionResolution{}, err
		}
	} else {
		if now.Unix() <= 0 {
			return commerce.ActionResolution{}, errors.New("Guarantor action plan time is outside the supported range")
		}
		// An action the authority knows always has a plan, because the plan is
		// stored first. One it knows without a plan was prepared under a time
		// and fence this call cannot recover, so nothing is built on it.
		prior, err := resolveGuarantorAction(coordinator.Authority, action.StableActionID, action.ExactRequestDigest)
		if err != nil {
			return commerce.ActionResolution{}, err
		}
		if prior.State != commerce.ActionUnknown {
			return prior, fmt.Errorf(
				"Guarantor action is already %s at its authority and the journal holds no plan for it", prior.State)
		}
		plan := GuarantorActionPlan{
			Kind: planned.kind, ScopeID: planned.scopeID, SubjectID: planned.subjectID, Action: action,
			WriterFence: fence, Fields: fields, CanonicalRequest: request, PreparedAtUnix: uint64(now.Unix()),
		}
		if err = coordinator.Journal.PrepareActionPlan(plan); err != nil {
			return commerce.ActionResolution{}, err
		}
		resolution, err = admit()
		if err != nil {
			return resolution, err
		}
	}
	if resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionTerminal {
		return resolution, errors.New("Guarantor action is neither prepared nor terminal at its authority")
	}
	return resolution, nil
}

// settlePlannedAction makes the call's action terminal with sinkReference and
// evidenceRefs, the digests of what the call is about to commit. An action
// that is already terminal was settled by an earlier run of this call: its
// recorded result must be exactly this one, or the receipt this run rebuilt
// is not the one that run settled, and nothing is signed or committed for it.
func (coordinator *GuarantorProviderCoordinator) settlePlannedAction(resolution commerce.ActionResolution,
	action commerce.AuthorizedAction, sinkReference string, evidenceRefs []string,
) (commerce.ActionResolution, error) {
	switch resolution.State {
	case commerce.ActionPrepared:
		return coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
			commerce.ActionTerminal, sinkReference, evidenceRefs)
	case commerce.ActionTerminal:
		if resolution.SinkReference != sinkReference || !sameJSON(resolution.EvidenceRefs, evidenceRefs) {
			return resolution, errors.New(
				"Guarantor terminal action result conflicts with the receipt rebuilt for it")
		}
		return resolution, nil
	default:
		return resolution, errors.New("Guarantor action is neither prepared nor terminal at its authority")
	}
}
