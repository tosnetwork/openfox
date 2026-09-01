package earning

import (
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// LocalOutcomeRiskPolicyRevision binds an advisory projection to the exact
// local Owner policy and evaluation time that requested it. It is not a
// portable protocol object and grants no authority.
type LocalOutcomeRiskPolicyRevision struct {
	OwnerID              string `json:"owner_id"`
	PolicyRevision       uint64 `json:"policy_revision"`
	PolicyDigest         string `json:"policy_digest"`
	EvaluationTimeUnix   uint64 `json:"evaluation_time_unix"`
	ProjectionVisibility string `json:"projection_visibility"`
}

type LocalOutcomeEvidenceState string

const (
	LocalOutcomeSucceeded     LocalOutcomeEvidenceState = "succeeded"
	LocalOutcomeAdverse       LocalOutcomeEvidenceState = "adverse"
	LocalOutcomeIndeterminate LocalOutcomeEvidenceState = "indeterminate"
	LocalOutcomeUnknown       LocalOutcomeEvidenceState = "unknown"

	localOutcomePrivateVisibility  = "local_owner_private"
	localOutcomeUnknownDenominator = "no_authority_closed_exact_attempt_denominator"
)

// ProviderDeliverySubjectBinding is an exact local, Agreement-derived lookup
// context. Outcome Event V1 does not itself bind a delivery subject to a
// provider or Agreement, so callers must obtain this mapping from already
// verified Agreement/obligation state. This type does not verify or authorize
// that state.
type ProviderDeliverySubjectBinding struct {
	AgreementBodyDigest       string `json:"agreement_body_digest"`
	AgreementObligationID     string `json:"agreement_obligation_id"`
	DeliverySubjectProfileURI string `json:"delivery_subject_profile_uri"`
	DeliverySubjectID         string `json:"delivery_subject_id"`
	OwningStateProfileURI     string `json:"owning_state_profile_uri"`
}

type ProviderDeliveryEvidence struct {
	Binding            ProviderDeliverySubjectBinding `json:"binding"`
	State              LocalOutcomeEvidenceState      `json:"state"`
	Disposition        string                         `json:"disposition,omitempty"`
	FailureStage       string                         `json:"failure_stage,omitempty"`
	FailureCode        string                         `json:"failure_code,omitempty"`
	ResolvedAtUnix     uint64                         `json:"resolved_at_unix,omitempty"`
	EvidenceConflict   bool                           `json:"evidence_conflict"`
	AssertingAgentIDs  []string                       `json:"asserting_agent_ids"`
	Assertions         []OutcomeAssertionKey          `json:"assertions"`
	AuthorityHighWater uint64                         `json:"authority_time_high_water"`
}

// ProviderDeliveryOutcomeRiskProjection is a descriptive, Owner-local view.
// Its denominator remains unknown without an authority-closed exact cohort,
// so it deliberately contains no score, probability, or recommendation.
type ProviderDeliveryOutcomeRiskProjection struct {
	Policy                  LocalOutcomeRiskPolicyRevision `json:"policy"`
	ProviderAgentID         string                         `json:"provider_agent_id"`
	Deliveries              []ProviderDeliveryEvidence     `json:"deliveries"`
	SucceededDeliveries     uint64                         `json:"succeeded_deliveries"`
	AdverseDeliveries       uint64                         `json:"adverse_deliveries"`
	IndeterminateDeliveries uint64                         `json:"indeterminate_deliveries"`
	UnknownDeliveries       uint64                         `json:"unknown_deliveries"`
	DenominatorState        string                         `json:"denominator_state"`
	Sufficient              bool                           `json:"sufficient"`
	InsufficiencyReason     string                         `json:"insufficiency_reason"`
}

// ProjectProviderDeliveryOutcomeRisk selects only authority-qualified,
// evidence-bound TerminalDispositionV1 assertions for the exact locally bound
// delivery subjects. Distinct publishing Actors may assert one exact
// disposition; they never create additional deliveries or prove independent
// corroboration. Conflicts remain indeterminate.
func ProjectProviderDeliveryOutcomeRisk(policy LocalOutcomeRiskPolicyRevision, providerAgentID string,
	bindings []ProviderDeliverySubjectBinding, assertions []VerifiedOutcomeAssertion) (ProviderDeliveryOutcomeRiskProjection, error) {
	projection := ProviderDeliveryOutcomeRiskProjection{Policy: policy, ProviderAgentID: providerAgentID,
		Deliveries: []ProviderDeliveryEvidence{}, DenominatorState: "unknown", Sufficient: false,
		InsufficiencyReason: localOutcomeUnknownDenominator}
	if err := validateLocalOutcomeRiskPolicy(policy); err != nil {
		return projection, err
	}
	if !validLocalOutcomeIdentifier(providerAgentID, 256) || len(bindings) == 0 {
		return projection, errors.New("provider delivery projection subject is incomplete")
	}
	ordered, err := validateAndSortDeliveryBindings(bindings)
	if err != nil {
		return projection, err
	}
	for _, binding := range ordered {
		accumulator := collectTerminalEvidence(binding.DeliverySubjectProfileURI, binding.DeliverySubjectID,
			"delivery", binding.OwningStateProfileURI, assertions)
		delivery := ProviderDeliveryEvidence{Binding: binding, State: accumulator.state(),
			EvidenceConflict: accumulator.conflict, AssertingAgentIDs: accumulator.sortedPublishers(),
			Assertions: accumulator.sortedAssertions(), AuthorityHighWater: accumulator.highWater}
		if accumulator.terminal != nil && !accumulator.conflict {
			delivery.Disposition = accumulator.terminal.Disposition
			delivery.FailureStage = accumulator.terminal.FailureStage
			delivery.FailureCode = accumulator.terminal.FailureCode
			delivery.ResolvedAtUnix = accumulator.terminal.ResolvedAtUnix
		}
		projection.Deliveries = append(projection.Deliveries, delivery)
		switch delivery.State {
		case LocalOutcomeSucceeded:
			projection.SucceededDeliveries++
		case LocalOutcomeAdverse:
			projection.AdverseDeliveries++
		case LocalOutcomeIndeterminate:
			projection.IndeterminateDeliveries++
		default:
			projection.UnknownDeliveries++
		}
	}
	return projection, nil
}

// ServiceCapabilityExecutionBinding is an exact local mapping from a
// market/service capability label to an Agreement execution. The label is not
// a Trusted Capability artifact identity and cannot admit executable bytes.
type ServiceCapabilityExecutionBinding struct {
	AgreementBodyDigest        string `json:"agreement_body_digest"`
	AgreementObligationID      string `json:"agreement_obligation_id"`
	ExecutionID                string `json:"execution_id"`
	ExecutionSubjectProfileURI string `json:"execution_subject_profile_uri"`
	OwningStateProfileURI      string `json:"owning_state_profile_uri"`
}

type ServiceCapabilityExecutionEvidence struct {
	Binding                  ServiceCapabilityExecutionBinding `json:"binding"`
	State                    LocalOutcomeEvidenceState         `json:"state"`
	Disposition              string                            `json:"disposition,omitempty"`
	FailureStage             string                            `json:"failure_stage,omitempty"`
	FailureCode              string                            `json:"failure_code,omitempty"`
	ResolvedAtUnix           uint64                            `json:"resolved_at_unix,omitempty"`
	EvidenceConflict         bool                              `json:"evidence_conflict"`
	BindingAssertingAgentIDs []string                          `json:"binding_asserting_agent_ids"`
	OutcomeAssertingAgentIDs []string                          `json:"outcome_asserting_agent_ids"`
	BindingAssertions        []OutcomeAssertionKey             `json:"binding_assertions"`
	OutcomeAssertions        []OutcomeAssertionKey             `json:"outcome_assertions"`
	AuthorityTimeHighWater   uint64                            `json:"authority_time_high_water"`
}

// ServiceCapabilityOutcomeRiskProjection is evidence about one Owner-local
// market/service capability label. It is neither Capability Admission nor
// Capability Use Binding and cannot enable an adapter, tool, or executable.
type ServiceCapabilityOutcomeRiskProjection struct {
	Policy                   LocalOutcomeRiskPolicyRevision       `json:"policy"`
	ProviderAgentID          string                               `json:"provider_agent_id"`
	LocalServiceCapabilityID string                               `json:"local_service_capability_id"`
	Executions               []ServiceCapabilityExecutionEvidence `json:"executions"`
	SucceededExecutions      uint64                               `json:"succeeded_executions"`
	AdverseExecutions        uint64                               `json:"adverse_executions"`
	IndeterminateExecutions  uint64                               `json:"indeterminate_executions"`
	UnknownExecutions        uint64                               `json:"unknown_executions"`
	DenominatorState         string                               `json:"denominator_state"`
	Sufficient               bool                                 `json:"sufficient"`
	InsufficiencyReason      string                               `json:"insufficiency_reason"`
}

// ProjectServiceCapabilityOutcomeRisk requires two independently verified
// existing profiles for each usable observation: GateExecutionObservationV1
// binds the execution to the exact Agreement/obligation, and a terminal
// disposition describes the scoped execution result. Neither event authorizes
// a future execution. Missing binding or terminal evidence stays unknown.
func ProjectServiceCapabilityOutcomeRisk(policy LocalOutcomeRiskPolicyRevision, providerAgentID,
	localServiceCapabilityID string, bindings []ServiceCapabilityExecutionBinding,
	assertions []VerifiedOutcomeAssertion) (ServiceCapabilityOutcomeRiskProjection, error) {
	projection := ServiceCapabilityOutcomeRiskProjection{Policy: policy, ProviderAgentID: providerAgentID,
		LocalServiceCapabilityID: localServiceCapabilityID, Executions: []ServiceCapabilityExecutionEvidence{},
		DenominatorState: "unknown", Sufficient: false, InsufficiencyReason: localOutcomeUnknownDenominator}
	if err := validateLocalOutcomeRiskPolicy(policy); err != nil {
		return projection, err
	}
	if !validLocalOutcomeIdentifier(providerAgentID, 256) ||
		!validLocalOutcomeIdentifier(localServiceCapabilityID, 256) || len(bindings) == 0 {
		return projection, errors.New("service capability projection subject is incomplete")
	}
	ordered, err := validateAndSortExecutionBindings(bindings)
	if err != nil {
		return projection, err
	}
	for _, binding := range ordered {
		gate := collectGateExecutionEvidence(binding, assertions)
		terminal := collectTerminalEvidence(binding.ExecutionSubjectProfileURI, binding.ExecutionID,
			"execution", binding.OwningStateProfileURI, assertions)
		state := LocalOutcomeUnknown
		conflict := gate.conflict || terminal.conflict
		if conflict {
			state = LocalOutcomeIndeterminate
		} else if gate.found && terminal.terminal != nil {
			state = localTerminalState(terminal.terminal.Disposition)
		}
		highWater := gate.highWater
		if terminal.highWater > highWater {
			highWater = terminal.highWater
		}
		execution := ServiceCapabilityExecutionEvidence{Binding: binding, State: state, EvidenceConflict: conflict,
			BindingAssertingAgentIDs: gate.sortedPublishers(), OutcomeAssertingAgentIDs: terminal.sortedPublishers(),
			BindingAssertions: gate.sortedAssertions(), OutcomeAssertions: terminal.sortedAssertions(),
			AuthorityTimeHighWater: highWater}
		if gate.found && terminal.terminal != nil && !conflict {
			execution.Disposition = terminal.terminal.Disposition
			execution.FailureStage = terminal.terminal.FailureStage
			execution.FailureCode = terminal.terminal.FailureCode
			execution.ResolvedAtUnix = terminal.terminal.ResolvedAtUnix
		}
		projection.Executions = append(projection.Executions, execution)
		switch state {
		case LocalOutcomeSucceeded:
			projection.SucceededExecutions++
		case LocalOutcomeAdverse:
			projection.AdverseExecutions++
		case LocalOutcomeIndeterminate:
			projection.IndeterminateExecutions++
		default:
			projection.UnknownExecutions++
		}
	}
	return projection, nil
}

type localTerminalAccumulator struct {
	terminal     *commerce.TerminalDispositionV1
	conflict     bool
	publishers   map[string]struct{}
	assertions   map[OutcomeAssertionKey]struct{}
	fingerprints map[OutcomeAssertionKey]string
	highWater    uint64
}

func collectTerminalEvidence(subjectProfileURI, subjectID, scope, owningStateProfileURI string,
	assertions []VerifiedOutcomeAssertion) localTerminalAccumulator {
	accumulator := localTerminalAccumulator{publishers: make(map[string]struct{}),
		assertions: make(map[OutcomeAssertionKey]struct{}), fingerprints: make(map[OutcomeAssertionKey]string)}
	for _, assertion := range assertions {
		if !assertion.Authority.AuthorityQualified || !assertion.payloadEvidenceBound ||
			assertion.Body.AssertionProfileURI != commerce.OutcomeProfileTerminal ||
			assertion.Body.PrimarySubjectRef.SubjectProfileURI != subjectProfileURI ||
			assertion.Body.PrimarySubjectRef.SubjectID != subjectID {
			continue
		}
		accumulator.record(assertion)
		var terminal commerce.TerminalDispositionV1
		if !validLocalOutcomeAssertionKey(assertion.Key) || assertion.Body.SchemaVersion != commerce.OperationOutcomeSchemaV1 ||
			assertion.Body.EventKind != commerce.OutcomeTerminalObservation ||
			codec.Unmarshal(assertion.AssertionPayload, &terminal) != nil || commerce.ValidateTerminalDispositionV1(terminal) != nil ||
			terminal.TerminalSubjectID != subjectID || terminal.TerminalScope != scope ||
			terminal.OwningStateProfileURI != owningStateProfileURI ||
			!containsEvidenceDigest(assertion.Authority.VerifiedEvidenceDigests, terminal.AuthoritativeResolutionDigest) {
			accumulator.conflict = true
			continue
		}
		if _, found := exactOutcomeEvidenceItem(assertion, "authoritative_resolution", terminal.AuthoritativeResolutionDigest); !found {
			accumulator.conflict = true
			continue
		}
		if accumulator.terminal == nil {
			copy := terminal
			accumulator.terminal = &copy
		} else if *accumulator.terminal != terminal {
			accumulator.conflict = true
		}
	}
	return accumulator
}

func (accumulator *localTerminalAccumulator) record(assertion VerifiedOutcomeAssertion) {
	accumulator.publishers[assertion.Key.ActorAgentID] = struct{}{}
	accumulator.assertions[assertion.Key] = struct{}{}
	if localOutcomeAssertionKeyConflicts(accumulator.fingerprints, assertion) {
		accumulator.conflict = true
	}
	if assertion.Authority.AuthorityTimeHighWater > accumulator.highWater {
		accumulator.highWater = assertion.Authority.AuthorityTimeHighWater
	}
}

func (accumulator localTerminalAccumulator) state() LocalOutcomeEvidenceState {
	if accumulator.conflict {
		return LocalOutcomeIndeterminate
	}
	if accumulator.terminal == nil {
		return LocalOutcomeUnknown
	}
	return localTerminalState(accumulator.terminal.Disposition)
}

func (accumulator localTerminalAccumulator) sortedPublishers() []string {
	return sortedLocalOutcomeStrings(accumulator.publishers)
}

func (accumulator localTerminalAccumulator) sortedAssertions() []OutcomeAssertionKey {
	return sortedLocalOutcomeAssertionKeys(accumulator.assertions)
}

type localGateExecutionAccumulator struct {
	found        bool
	conflict     bool
	immutable    *commerce.GateExecutionObservationV1
	revisions    map[uint64]commerce.GateExecutionObservationV1
	publishers   map[string]struct{}
	assertions   map[OutcomeAssertionKey]struct{}
	fingerprints map[OutcomeAssertionKey]string
	highWater    uint64
}

func collectGateExecutionEvidence(binding ServiceCapabilityExecutionBinding,
	assertions []VerifiedOutcomeAssertion) localGateExecutionAccumulator {
	accumulator := localGateExecutionAccumulator{revisions: make(map[uint64]commerce.GateExecutionObservationV1),
		publishers: make(map[string]struct{}), assertions: make(map[OutcomeAssertionKey]struct{}),
		fingerprints: make(map[OutcomeAssertionKey]string)}
	for _, assertion := range assertions {
		if !assertion.Authority.AuthorityQualified || !assertion.payloadEvidenceBound ||
			assertion.Body.AssertionProfileURI != commerce.OutcomeProfileGateExecution ||
			assertion.Body.PrimarySubjectRef.SubjectProfileURI != binding.ExecutionSubjectProfileURI ||
			assertion.Body.PrimarySubjectRef.SubjectID != binding.ExecutionID {
			continue
		}
		accumulator.record(assertion)
		var gate commerce.GateExecutionObservationV1
		if !validLocalOutcomeAssertionKey(assertion.Key) || assertion.Body.SchemaVersion != commerce.OperationOutcomeSchemaV1 ||
			assertion.Body.EventKind != commerce.OutcomeTransitionObservation ||
			codec.Unmarshal(assertion.AssertionPayload, &gate) != nil || commerce.ValidateGateExecutionObservationV1(gate) != nil ||
			gate.ExecutionID != binding.ExecutionID || gate.AgreementBodyDigest != binding.AgreementBodyDigest ||
			gate.ObligationID != binding.AgreementObligationID ||
			!containsEvidenceDigest(assertion.Authority.VerifiedEvidenceDigests, gate.AuthoritativeRecord) {
			accumulator.conflict = true
			continue
		}
		if _, found := exactOutcomeEvidenceItem(assertion, "authoritative_resolution", gate.AuthoritativeRecord); !found {
			accumulator.conflict = true
			continue
		}
		if accumulator.immutable == nil {
			copy := gate
			accumulator.immutable = &copy
		} else if !sameGateExecutionImmutableBinding(*accumulator.immutable, gate) {
			accumulator.conflict = true
		}
		if prior, found := accumulator.revisions[gate.StateRevision]; found &&
			(prior.State != gate.State || prior.AuthoritativeRecord != gate.AuthoritativeRecord) {
			accumulator.conflict = true
		} else {
			accumulator.revisions[gate.StateRevision] = gate
		}
		accumulator.found = true
	}
	return accumulator
}

func (accumulator *localGateExecutionAccumulator) record(assertion VerifiedOutcomeAssertion) {
	accumulator.publishers[assertion.Key.ActorAgentID] = struct{}{}
	accumulator.assertions[assertion.Key] = struct{}{}
	if localOutcomeAssertionKeyConflicts(accumulator.fingerprints, assertion) {
		accumulator.conflict = true
	}
	if assertion.Authority.AuthorityTimeHighWater > accumulator.highWater {
		accumulator.highWater = assertion.Authority.AuthorityTimeHighWater
	}
}

func (accumulator localGateExecutionAccumulator) sortedPublishers() []string {
	return sortedLocalOutcomeStrings(accumulator.publishers)
}

func (accumulator localGateExecutionAccumulator) sortedAssertions() []OutcomeAssertionKey {
	return sortedLocalOutcomeAssertionKeys(accumulator.assertions)
}

func sameGateExecutionImmutableBinding(left, right commerce.GateExecutionObservationV1) bool {
	return left.ExecutionID == right.ExecutionID && left.AgreementBodyDigest == right.AgreementBodyDigest &&
		left.ObligationID == right.ObligationID && left.PlanDigest == right.PlanDigest &&
		left.GatePolicyDigest == right.GatePolicyDigest && left.InputSetDigest == right.InputSetDigest &&
		left.ResourceSetDigest == right.ResourceSetDigest && left.CredentialSetDigest == right.CredentialSetDigest &&
		left.EffectSetDigest == right.EffectSetDigest && left.StartActionID == right.StartActionID &&
		left.StartRequestDigest == right.StartRequestDigest
}

func localTerminalState(disposition string) LocalOutcomeEvidenceState {
	switch disposition {
	case "succeeded":
		return LocalOutcomeSucceeded
	case "indeterminate", "conflict":
		return LocalOutcomeIndeterminate
	default:
		return LocalOutcomeAdverse
	}
}

func validateLocalOutcomeRiskPolicy(policy LocalOutcomeRiskPolicyRevision) error {
	if !validLocalOutcomeIdentifier(policy.OwnerID, 256) || policy.PolicyRevision == 0 ||
		!canonicalLocalOutcomeDigest(policy.PolicyDigest) || policy.EvaluationTimeUnix == 0 ||
		policy.ProjectionVisibility != localOutcomePrivateVisibility {
		return errors.New("local outcome-risk policy revision is invalid")
	}
	return nil
}

func validateAndSortDeliveryBindings(values []ProviderDeliverySubjectBinding) ([]ProviderDeliverySubjectBinding, error) {
	ordered := append([]ProviderDeliverySubjectBinding(nil), values...)
	for _, value := range ordered {
		if !canonicalLocalOutcomeDigest(value.AgreementBodyDigest) ||
			!validLocalOutcomeIdentifier(value.AgreementObligationID, 256) ||
			!validLocalOutcomeIdentifier(value.DeliverySubjectProfileURI, 1024) ||
			!validLocalOutcomeIdentifier(value.DeliverySubjectID, 4096) ||
			!validLocalOutcomeIdentifier(value.OwningStateProfileURI, 1024) {
			return nil, errors.New("provider delivery binding is invalid")
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].DeliverySubjectProfileURI != ordered[j].DeliverySubjectProfileURI {
			return ordered[i].DeliverySubjectProfileURI < ordered[j].DeliverySubjectProfileURI
		}
		return ordered[i].DeliverySubjectID < ordered[j].DeliverySubjectID
	})
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].DeliverySubjectProfileURI == ordered[index].DeliverySubjectProfileURI &&
			ordered[index-1].DeliverySubjectID == ordered[index].DeliverySubjectID {
			return nil, errors.New("provider delivery binding is duplicated or forked")
		}
	}
	return ordered, nil
}

func validateAndSortExecutionBindings(values []ServiceCapabilityExecutionBinding) ([]ServiceCapabilityExecutionBinding, error) {
	ordered := append([]ServiceCapabilityExecutionBinding(nil), values...)
	for _, value := range ordered {
		if !canonicalLocalOutcomeDigest(value.AgreementBodyDigest) ||
			!validLocalOutcomeIdentifier(value.AgreementObligationID, 256) ||
			!canonicalLocalOutcomeDigest(value.ExecutionID) ||
			!validLocalOutcomeIdentifier(value.ExecutionSubjectProfileURI, 1024) ||
			!validLocalOutcomeIdentifier(value.OwningStateProfileURI, 1024) {
			return nil, errors.New("service capability execution binding is invalid")
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].ExecutionSubjectProfileURI != ordered[j].ExecutionSubjectProfileURI {
			return ordered[i].ExecutionSubjectProfileURI < ordered[j].ExecutionSubjectProfileURI
		}
		return ordered[i].ExecutionID < ordered[j].ExecutionID
	})
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].ExecutionSubjectProfileURI == ordered[index].ExecutionSubjectProfileURI &&
			ordered[index-1].ExecutionID == ordered[index].ExecutionID {
			return nil, errors.New("service capability execution binding is duplicated or forked")
		}
	}
	return ordered, nil
}

func localOutcomeAssertionKeyConflicts(fingerprints map[OutcomeAssertionKey]string,
	assertion VerifiedOutcomeAssertion) bool {
	fingerprint, err := codec.Digest("tos.openfox.local-outcome-assertion.v1", assertion)
	if err != nil {
		return true
	}
	if prior, found := fingerprints[assertion.Key]; found {
		return prior != fingerprint
	}
	fingerprints[assertion.Key] = fingerprint
	return false
}

func sortedLocalOutcomeStrings(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedLocalOutcomeAssertionKeys(values map[OutcomeAssertionKey]struct{}) []OutcomeAssertionKey {
	result := make([]OutcomeAssertionKey, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].NetworkID != result[j].NetworkID {
			return result[i].NetworkID < result[j].NetworkID
		}
		if result[i].ActorAgentID != result[j].ActorAgentID {
			return result[i].ActorAgentID < result[j].ActorAgentID
		}
		if result[i].OperationID != result[j].OperationID {
			return result[i].OperationID < result[j].OperationID
		}
		return result[i].OperationEnvelopeDigest < result[j].OperationEnvelopeDigest
	})
	return result
}

func validLocalOutcomeIdentifier(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func canonicalLocalOutcomeDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

func validLocalOutcomeAssertionKey(value OutcomeAssertionKey) bool {
	return validLocalOutcomeIdentifier(value.NetworkID, 256) &&
		validLocalOutcomeIdentifier(value.ActorAgentID, 256) &&
		validLocalOutcomeIdentifier(value.OperationID, 256) &&
		canonicalLocalOutcomeDigest(value.OperationEnvelopeDigest)
}
