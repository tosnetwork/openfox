package earning

import (
	"errors"
	"sync"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// OutcomeRecordingAuthority decorates the existing linearizable economic
// authority. Every action-bearing mutation and subsequent state transition is
// shadow-written to the immutable outcome journal. The economic mutation is
// always committed first; a capture error is returned explicitly so recovery
// retries the same stable Action rather than inventing a replacement.
type OutcomeRecordingAuthority struct {
	EconomicAuthority
	Recorder ActionOutcomeRecorder
	mu       sync.RWMutex
	actions  map[string]commerce.AuthorizedAction
}

func NewOutcomeRecordingAuthority(authority EconomicAuthority, recorder ActionOutcomeRecorder) *OutcomeRecordingAuthority {
	return &OutcomeRecordingAuthority{EconomicAuthority: authority, Recorder: recorder,
		actions: make(map[string]commerce.AuthorizedAction)}
}

func (*OutcomeRecordingAuthority) recordsOutcomesAtAuthorityBoundary() {}

func (authority *OutcomeRecordingAuthority) remember(action commerce.AuthorizedAction) {
	authority.mu.Lock()
	authority.actions[action.StableActionID] = action
	authority.mu.Unlock()
}

func (authority *OutcomeRecordingAuthority) capture(action commerce.AuthorizedAction,
	resolution commerce.ActionResolution, err error) (commerce.ActionResolution, error) {
	// A sink may return both a stable negative/conflict resolution and an
	// operational error. The resolution is evidence and must not disappear
	// merely because the happy path failed. Zero/unknown/unrelated responses do
	// not qualify and remain ordinary errors.
	qualified := commerce.ValidateActionResolution(resolution) == nil && resolution.State != commerce.ActionUnknown &&
		resolution.StableActionID == action.StableActionID && resolution.ExactRequestDigest == action.ExactRequestDigest
	if err != nil && !qualified {
		return resolution, err
	}
	authority.remember(action)
	if authority.Recorder != nil {
		if captureErr := authority.Recorder.RecordActionResolution(action, resolution, authority.AuthorityNow()); captureErr != nil {
			if err != nil {
				return resolution, errors.Join(err, captureErr)
			}
			return resolution, captureErr
		}
	}
	return resolution, err
}

func (authority *OutcomeRecordingAuthority) Admit(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	reservation *ExposureReservation) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.Admit(action, fields, request, fence, reservation)
	return authority.capture(action, resolution, err)
}

func (authority *OutcomeRecordingAuthority) Transition(stableActionID, requestDigest string,
	state commerce.ActionResolutionState, sinkReference string, evidence []string) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.Transition(stableActionID, requestDigest, state, sinkReference, evidence)
	authority.mu.RLock()
	action, found := authority.actions[stableActionID]
	authority.mu.RUnlock()
	if !found {
		if resolver, ok := authority.EconomicAuthority.(interface {
			ResolveAuthorizedAction(string, string) (commerce.AuthorizedAction, bool)
		}); ok {
			action, found = resolver.ResolveAuthorizedAction(stableActionID, requestDigest)
		}
	}
	if !found || action.ExactRequestDigest != requestDigest {
		if err != nil {
			return resolution, err
		}
		return resolution, errOutcomeCommittedWithoutAction
	}
	return authority.capture(action, resolution, err)
}

func (authority *OutcomeRecordingAuthority) ReleaseReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.ReleaseReservation(action, fields, request, fence)
	return authority.capture(action, resolution, err)
}

func (authority *OutcomeRecordingAuthority) ReleaseGuarantorReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	realizedLoss, retainedLiability uint64) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.ReleaseGuarantorReservation(action, fields, request, fence, realizedLoss, retainedLiability)
	return authority.capture(action, resolution, err)
}

func (authority *OutcomeRecordingAuthority) ReserveEngagement(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	reservation PortfolioReservationRequest) (commerce.ActionResolution, EngagementRecord, error) {
	resolution, record, err := authority.EconomicAuthority.ReserveEngagement(action, fields, request, fence, reservation)
	resolution, captureErr := authority.capture(action, resolution, err)
	return resolution, record, captureErr
}

func (authority *OutcomeRecordingAuthority) AdmitScheduleTransition(action commerce.AuthorizedAction,
	request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.AdmitScheduleTransition(action, request, fence)
	return authority.capture(action, resolution, err)
}

func (authority *OutcomeRecordingAuthority) AdmitDependencyTransition(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	transition DependencyTransitionRequest) (commerce.ActionResolution, error) {
	resolution, err := authority.EconomicAuthority.AdmitDependencyTransition(action, fields, request, fence, transition)
	return authority.capture(action, resolution, err)
}

func (authority *OutcomeRecordingAuthority) ResolveSettlementState(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	transition BillingStateTransitionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error) {
	resolution, ledger, engagement, err := authority.EconomicAuthority.ResolveSettlementState(action, fields, request, fence, transition)
	resolution, captureErr := authority.capture(action, resolution, err)
	return resolution, ledger, engagement, captureErr
}

func (authority *OutcomeRecordingAuthority) MaterializeSettlement(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	obligation commerce.SettlementObligation) (commerce.ActionResolution, SettlementLedgerRecord, error) {
	resolution, ledger, err := authority.EconomicAuthority.MaterializeSettlement(action, fields, request, fence, obligation)
	resolution, captureErr := authority.capture(action, resolution, err)
	return resolution, ledger, captureErr
}

func (authority *OutcomeRecordingAuthority) ApplySettlementPayment(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	transition BillingResolutionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error) {
	resolution, ledger, engagement, err := authority.EconomicAuthority.ApplySettlementPayment(action, fields, request, fence, transition)
	resolution, captureErr := authority.capture(action, resolution, err)
	return resolution, ledger, engagement, captureErr
}

func (authority *OutcomeRecordingAuthority) RecordAccounting(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	entry AccountingEntry) (commerce.ActionResolution, AccountingEntry, error) {
	resolution, recorded, err := authority.EconomicAuthority.RecordAccounting(action, fields, request, fence, entry)
	resolution, captureErr := authority.capture(action, resolution, err)
	return resolution, recorded, captureErr
}

var errOutcomeCommittedWithoutAction = &outcomeCaptureError{"economic Action resolution committed but its exact AuthorizedAction is unavailable for immutable outcome capture"}

type outcomeCaptureError struct{ message string }

func (failure *outcomeCaptureError) Error() string { return failure.message }

var _ EconomicAuthority = (*OutcomeRecordingAuthority)(nil)
