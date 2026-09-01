package earning

import (
	"errors"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// ObligationRuntimeState is a local evidence projection. It never changes the
// signed Agreement or authorizes an effect.
type ObligationRuntimeState string

const (
	ObligationPending            ObligationRuntimeState = "pending"
	ObligationReady              ObligationRuntimeState = "ready"
	ObligationExecutionPrepared  ObligationRuntimeState = "execution_prepared"
	ObligationExecuting          ObligationRuntimeState = "executing"
	ObligationExecutionSucceeded ObligationRuntimeState = "execution_succeeded"
	ObligationDelivered          ObligationRuntimeState = "delivered"
	ObligationSettling           ObligationRuntimeState = "settling"
	ObligationSettled            ObligationRuntimeState = "settled"
	ObligationOverdue            ObligationRuntimeState = "overdue"
	ObligationCancelled          ObligationRuntimeState = "cancelled"
	ObligationFailed             ObligationRuntimeState = "failed"
	ObligationAmbiguous          ObligationRuntimeState = "ambiguous"
)

type ObligationRuntimeRecord struct {
	ObligationID             string                 `json:"obligation_id"`
	State                    ObligationRuntimeState `json:"state"`
	StateRevision            uint64                 `json:"state_revision"`
	ExecutionID              string                 `json:"execution_id,omitempty"`
	ExecutionEvidence        []string               `json:"execution_evidence,omitempty"`
	DeliveryEvidence         []string               `json:"delivery_evidence,omitempty"`
	DeliveryEventID          string                 `json:"delivery_event_id,omitempty"`
	SettlementEvidence       []string               `json:"settlement_evidence,omitempty"`
	ExecutionCompletedAtUnix uint64                 `json:"execution_completed_at_unix,omitempty"`
	LastTransitionAtUnix     uint64                 `json:"last_transition_at_unix"`
}

func initializeObligationRuntime(record *EngagementRecord) {
	if record.ObligationRuntime == nil {
		record.ObligationRuntime = make(map[string]ObligationRuntimeRecord, len(record.Agreement.Body.Obligations))
	}
	for _, obligation := range record.Agreement.Body.Obligations {
		if _, found := record.ObligationRuntime[obligation.ObligationID]; found {
			continue
		}
		state := ObligationPending
		// Migrate legacy single-obligation journals without inventing new
		// evidence. Only states backed by the legacy evidence fields advance.
		if len(record.Agreement.Body.Obligations) == 1 {
			switch record.State {
			case EngagementExecutionPrepared:
				state = ObligationExecutionPrepared
			case EngagementExecuting:
				state = ObligationExecuting
			case EngagementExecutionSucceeded:
				state = ObligationExecutionSucceeded
			case EngagementDelivered:
				state = ObligationDelivered
			case EngagementSettling:
				state = ObligationSettling
			case EngagementSettled:
				state = ObligationSettled
			case EngagementUnpaid:
				state = ObligationOverdue
			case EngagementCancelled:
				state = ObligationCancelled
			case EngagementFailed:
				state = ObligationFailed
			case EngagementAmbiguous:
				state = ObligationAmbiguous
			}
		}
		record.ObligationRuntime[obligation.ObligationID] = ObligationRuntimeRecord{
			ObligationID: obligation.ObligationID, State: state, StateRevision: 1,
			ExecutionID: record.ExecutionID, ExecutionEvidence: append([]string(nil), record.ExecutionEvidence...),
			DeliveryEvidence: append([]string(nil), record.DeliveryEvidence...), DeliveryEventID: record.DeliveryEventID,
			SettlementEvidence: append([]string(nil), record.SettlementEvidence...), LastTransitionAtUnix: record.LastTransitionAtUnix,
		}
	}
}

func validateObligationRuntime(record EngagementRecord) error {
	if len(record.ObligationRuntime) != len(record.Agreement.Body.Obligations) {
		return errors.New("engagement obligation runtime cardinality differs from Agreement")
	}
	for _, obligation := range record.Agreement.Body.Obligations {
		runtime, found := record.ObligationRuntime[obligation.ObligationID]
		if !found || runtime.ObligationID != obligation.ObligationID || runtime.StateRevision == 0 || runtime.LastTransitionAtUnix == 0 ||
			!knownObligationRuntimeState(runtime.State) {
			return errors.New("engagement obligation runtime is invalid")
		}
	}
	return nil
}

func knownObligationRuntimeState(state ObligationRuntimeState) bool {
	switch state {
	case ObligationPending, ObligationReady, ObligationExecutionPrepared, ObligationExecuting,
		ObligationExecutionSucceeded, ObligationDelivered, ObligationSettling, ObligationSettled,
		ObligationOverdue, ObligationCancelled, ObligationFailed, ObligationAmbiguous:
		return true
	default:
		return false
	}
}

func obligationByID(record EngagementRecord, obligationID string) (commerce.AgreementObligation, bool) {
	for _, obligation := range record.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID {
			return obligation, true
		}
	}
	return commerce.AgreementObligation{}, false
}

func obligationDependenciesSatisfied(record EngagementRecord, obligation commerce.AgreementObligation) bool {
	for _, dependencyID := range obligation.DependsOnObligationIDs {
		dependency, found := record.ObligationRuntime[dependencyID]
		if !found {
			return false
		}
		switch dependency.State {
		case ObligationDelivered, ObligationSettled:
		default:
			return false
		}
	}
	return true
}

func (authority *PersonalAuthority) transitionObligation(agreementDigest, obligationID string,
	expected, target ObligationRuntimeState, executionID string, evidence []string, eventID string) (EngagementRecord, error) {
	if authority == nil || !allowedObligationTransition(expected, target) {
		return EngagementRecord{}, errors.New("obligation runtime transition is not allowed")
	}
	evidence = append([]string(nil), evidence...)
	sort.Strings(evidence)
	for index, digest := range evidence {
		if !canonicalSHA256(digest) || index > 0 && evidence[index-1] == digest {
			return EngagementRecord{}, errors.New("obligation runtime evidence is invalid")
		}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found {
		return EngagementRecord{}, errors.New("obligation runtime has no Agreement")
	}
	record = detachedEngagementRecord(record)
	initializeObligationRuntime(&record)
	runtime, found := record.ObligationRuntime[obligationID]
	if !found || runtime.State != expected || executionID != "" && runtime.ExecutionID != "" && runtime.ExecutionID != executionID {
		return EngagementRecord{}, errors.New("obligation runtime transition has no exact predecessor")
	}
	if executionID != "" {
		runtime.ExecutionID = executionID
	}
	switch target {
	case ObligationExecutionPrepared, ObligationExecuting, ObligationExecutionSucceeded, ObligationFailed, ObligationAmbiguous:
		runtime.ExecutionEvidence = evidence
	case ObligationDelivered:
		runtime.DeliveryEvidence = evidence
		runtime.DeliveryEventID = eventID
	case ObligationSettled, ObligationOverdue:
		runtime.SettlementEvidence = evidence
	}
	runtime.State = target
	runtime.StateRevision++
	runtime.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	if target == ObligationExecutionSucceeded {
		runtime.ExecutionCompletedAtUnix = runtime.LastTransitionAtUnix
	}
	record.ObligationRuntime[obligationID] = runtime
	// Keep the legacy aggregate fields as a last-transition projection for CLI
	// compatibility. They are never used to decide which obligation may run.
	if executionID != "" {
		record.ExecutionID = executionID
	}
	switch target {
	case ObligationExecutionPrepared, ObligationExecuting, ObligationExecutionSucceeded, ObligationFailed, ObligationAmbiguous:
		record.ExecutionEvidence = append([]string(nil), evidence...)
	case ObligationDelivered:
		record.DeliveryEvidence = append([]string(nil), evidence...)
		record.DeliveryEventID = eventID
	case ObligationSettled, ObligationOverdue:
		record.SettlementEvidence = appendUniqueSorted(record.SettlementEvidence, evidence...)
	}
	record.StateRevision++
	record.LastTransitionAtUnix = runtime.LastTransitionAtUnix
	refreshEngagementProjection(&record)
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
}

func appendUniqueSorted(values []string, additions ...string) []string {
	result := append([]string(nil), values...)
	seen := make(map[string]bool, len(result)+len(additions))
	for _, value := range result {
		seen[value] = true
	}
	for _, value := range additions {
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	sort.Strings(result)
	return result
}

func allowedObligationTransition(from, to ObligationRuntimeState) bool {
	switch from {
	case ObligationPending:
		return to == ObligationReady || to == ObligationExecutionPrepared || to == ObligationDelivered ||
			to == ObligationSettling || to == ObligationCancelled
	case ObligationReady:
		return to == ObligationExecutionPrepared || to == ObligationCancelled
	case ObligationExecutionPrepared:
		return to == ObligationExecuting || to == ObligationAmbiguous || to == ObligationFailed
	case ObligationExecuting:
		return to == ObligationExecutionSucceeded || to == ObligationFailed || to == ObligationAmbiguous
	case ObligationExecutionSucceeded:
		return to == ObligationDelivered || to == ObligationFailed
	case ObligationDelivered:
		return to == ObligationSettling || to == ObligationSettled
	case ObligationSettling:
		return to == ObligationSettled || to == ObligationOverdue || to == ObligationAmbiguous || to == ObligationFailed
	case ObligationOverdue:
		return to == ObligationSettled
	default:
		return false
	}
}

func refreshEngagementProjection(record *EngagementRecord) {
	if record == nil || len(record.ObligationRuntime) == 0 {
		return
	}
	allTerminal, allDeliveredOrSettled := true, true
	var projected EngagementState
	for obligationID, runtime := range record.ObligationRuntime {
		obligation, _ := obligationByID(*record, obligationID)
		switch runtime.State {
		case ObligationAmbiguous:
			projected = EngagementAmbiguous
		case ObligationFailed:
			if projected != EngagementAmbiguous {
				projected = EngagementFailed
			}
		case ObligationExecuting:
			if projected == "" {
				projected = EngagementExecuting
			}
		case ObligationExecutionPrepared:
			if projected == "" {
				projected = EngagementExecutionPrepared
			}
		case ObligationExecutionSucceeded:
			if projected == "" {
				projected = EngagementExecutionSucceeded
			}
		case ObligationSettling:
			if projected == "" {
				projected = EngagementSettling
			}
		case ObligationOverdue:
			if projected == "" {
				projected = EngagementUnpaid
			}
		case ObligationPending, ObligationReady:
			allTerminal, allDeliveredOrSettled = false, false
		case ObligationDelivered:
			// A delivered non-value obligation is terminal. A value-bearing
			// obligation must instead reach an exact settlement state.
			if obligation.Amount != nil {
				allTerminal = false
			}
		case ObligationSettled, ObligationCancelled:
		}
		if runtime.State != ObligationDelivered && runtime.State != ObligationSettled && runtime.State != ObligationCancelled {
			allDeliveredOrSettled = false
		}
		if runtime.State != ObligationSettled && runtime.State != ObligationCancelled &&
			!(runtime.State == ObligationDelivered && obligation.Amount == nil) {
			allTerminal = false
		}
	}
	if projected != "" {
		record.State = projected
	} else if allTerminal {
		record.State = EngagementSettled
	} else if allDeliveredOrSettled {
		record.State = EngagementDelivered
	} else if allNonValueObligationsDelivered(*record) {
		record.State = EngagementDelivered
	} else if record.ReservationID != "" {
		record.State = EngagementReserved
	}
}

func (authority *PersonalAuthority) completeNoPaymentEngagement(agreementDigest, evidence string) (EngagementRecord, error) {
	if authority == nil || !canonicalSHA256(evidence) {
		return EngagementRecord{}, errors.New("completion evidence is invalid")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return EngagementRecord{}, err
	}
	record, found := authority.doc.Engagements[agreementDigest]
	if !found || hasValueObligation(record) || !allNonValueObligationsDelivered(record) {
		return EngagementRecord{}, errors.New("engagement is not complete")
	}
	record = detachedEngagementRecord(record)
	record.State = EngagementSettled
	record.StateRevision++
	record.SettlementEvidence = appendUniqueSorted(record.SettlementEvidence, evidence)
	record.LastTransitionAtUnix = uint64(authority.now().UTC().Unix())
	next := cloneAuthorityDocument(authority.doc)
	next.Engagements[agreementDigest] = detachedEngagementRecord(record)
	if err := authority.persist(next); err != nil {
		return EngagementRecord{}, err
	}
	authority.doc = next
	return detachedEngagementRecord(record), nil
}
