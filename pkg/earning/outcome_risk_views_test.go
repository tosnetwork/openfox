package earning

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	testDeliverySubjectProfile  = "tos.subject.delivery.v1"
	testDeliveryStateProfile    = "tos.delivery.objective.v1"
	testExecutionSubjectProfile = "tos.subject.execution.v1"
	testExecutionStateProfile   = "tos.execution.lifecycle.v1"
)

func TestProviderDeliveryOutcomeRiskIsSeparateDeduplicatedAndUnknownWithoutDenominator(t *testing.T) {
	bindings := []ProviderDeliverySubjectBinding{
		deliveryRiskBinding(t, "delivery:three", "work:three"),
		deliveryRiskBinding(t, "delivery:one", "work:one"),
		deliveryRiskBinding(t, "delivery:four", "work:four"),
		deliveryRiskBinding(t, "delivery:two", "work:two"),
	}
	oneResolution := outcomeRiskDigest(t, "delivery-one-resolution")
	oneA := terminalRiskAssertion(t, "issuer:a", testDeliverySubjectProfile, "delivery:one", "delivery",
		testDeliveryStateProfile, "succeeded", oneResolution, true, 4)
	oneA.Manifest.EvidenceItems[0].SubjectDescriptor = "private-customer-prompt"
	oneB := terminalRiskAssertion(t, "issuer:b", testDeliverySubjectProfile, "delivery:one", "delivery",
		testDeliveryStateProfile, "succeeded", oneResolution, true, 7)
	two := terminalRiskAssertion(t, "issuer:a", testDeliverySubjectProfile, "delivery:two", "delivery",
		testDeliveryStateProfile, "failed", outcomeRiskDigest(t, "delivery-two-resolution"), true, 6)
	unqualifiedThree := terminalRiskAssertion(t, "issuer:forged", testDeliverySubjectProfile, "delivery:three",
		"delivery", testDeliveryStateProfile, "succeeded", outcomeRiskDigest(t, "delivery-three-resolution"), false, 99)
	malformedFour := terminalRiskAssertion(t, "issuer:a", testDeliverySubjectProfile, "delivery:four", "delivery",
		testDeliveryStateProfile, "succeeded", outcomeRiskDigest(t, "delivery-four-resolution"), true, 8)
	malformedFour.Authority.VerifiedEvidenceDigests = []string{outcomeRiskDigest(t, "unrelated-evidence")}
	irrelevant := terminalRiskAssertion(t, "issuer:a", testDeliverySubjectProfile, "delivery:outside", "delivery",
		testDeliveryStateProfile, "succeeded", outcomeRiskDigest(t, "outside-resolution"), true, 8)
	assertions := []VerifiedOutcomeAssertion{two, oneB, unqualifiedThree, oneA, oneA, malformedFour, irrelevant}

	projection, err := ProjectProviderDeliveryOutcomeRisk(outcomeRiskPolicy(t), "provider.alice.tos", bindings, assertions)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Sufficient || projection.DenominatorState != "unknown" ||
		projection.InsufficiencyReason != localOutcomeUnknownDenominator {
		t.Fatalf("selected delivery evidence became a reliability denominator: %+v", projection)
	}
	if projection.SucceededDeliveries != 1 || projection.AdverseDeliveries != 1 ||
		projection.IndeterminateDeliveries != 1 || projection.UnknownDeliveries != 1 || len(projection.Deliveries) != 4 {
		t.Fatalf("provider delivery outcomes were not kept separate: %+v", projection)
	}
	one := providerDeliveryByID(t, projection, "delivery:one")
	if one.State != LocalOutcomeSucceeded || len(one.AssertingAgentIDs) != 2 || len(one.Assertions) != 2 ||
		one.AuthorityHighWater != 7 {
		t.Fatalf("Carrier replay or issuer corroboration inflated one delivery: %+v", one)
	}
	if providerDeliveryByID(t, projection, "delivery:three").State != LocalOutcomeUnknown {
		t.Fatal("an unqualified success was treated as provider evidence")
	}
	four := providerDeliveryByID(t, projection, "delivery:four")
	if four.State != LocalOutcomeIndeterminate || !four.EvidenceConflict {
		t.Fatalf("a terminal assertion without its exact resolution evidence did not fail closed: %+v", four)
	}

	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	if strings.Contains(lower, "private-customer-prompt") || strings.Contains(lower, "probability") ||
		strings.Contains(lower, `"score"`) || strings.Contains(lower, `"recommendation"`) {
		t.Fatalf("local evidence projection leaked private input or claimed an advisory result: %s", raw)
	}

	reversedBindings := append([]ProviderDeliverySubjectBinding(nil), bindings...)
	reverseDeliveryBindings(reversedBindings)
	reversedAssertions := append([]VerifiedOutcomeAssertion(nil), assertions...)
	reverseVerifiedOutcomeAssertions(reversedAssertions)
	reordered, err := ProjectProviderDeliveryOutcomeRisk(outcomeRiskPolicy(t), "provider.alice.tos",
		reversedBindings, reversedAssertions)
	if err != nil || !reflect.DeepEqual(projection, reordered) {
		t.Fatalf("projection changed with input arrival order: result=%+v err=%v", reordered, err)
	}
}

func TestProviderDeliveryOutcomeRiskRetainsConflictsAndNeverTrustsName(t *testing.T) {
	binding := deliveryRiskBinding(t, "delivery:conflict", "work:conflict")
	resolution := outcomeRiskDigest(t, "delivery-conflict-success")
	success := terminalRiskAssertion(t, "issuer:a", testDeliverySubjectProfile, binding.DeliverySubjectID,
		"delivery", testDeliveryStateProfile, "succeeded", resolution, true, 3)
	failure := terminalRiskAssertion(t, "issuer:b", testDeliverySubjectProfile, binding.DeliverySubjectID,
		"delivery", testDeliveryStateProfile, "failed", outcomeRiskDigest(t, "delivery-conflict-failure"), true, 4)
	projection, err := ProjectProviderDeliveryOutcomeRisk(outcomeRiskPolicy(t), "high-reputation-name.tos",
		[]ProviderDeliverySubjectBinding{binding}, []VerifiedOutcomeAssertion{success, failure})
	if err != nil {
		t.Fatal(err)
	}
	delivery := projection.Deliveries[0]
	if delivery.State != LocalOutcomeIndeterminate || !delivery.EvidenceConflict || projection.IndeterminateDeliveries != 1 ||
		projection.Sufficient {
		t.Fatalf("a .tos name or conflicting issuers became a positive provider result: %+v", projection)
	}

	empty, err := ProjectProviderDeliveryOutcomeRisk(outcomeRiskPolicy(t), "another-name.tos",
		[]ProviderDeliverySubjectBinding{deliveryRiskBinding(t, "delivery:none", "work:none")}, nil)
	if err != nil || empty.Deliveries[0].State != LocalOutcomeUnknown || empty.Sufficient {
		t.Fatalf("a .tos name became evidence without an Outcome assertion: result=%+v err=%v", empty, err)
	}
}

func TestServiceCapabilityOutcomeRiskRequiresExactGateBindingAndTerminal(t *testing.T) {
	bindings := []ServiceCapabilityExecutionBinding{
		executionRiskBinding(t, "execution:three", "service:review"),
		executionRiskBinding(t, "execution:one", "service:review"),
		executionRiskBinding(t, "execution:four", "service:review"),
		executionRiskBinding(t, "execution:two", "service:review"),
	}
	oneGate := gateRiskAssertion(t, "host:a", bindings[1], "complete", 2,
		outcomeRiskDigest(t, "gate-one-resolution"), true, 5)
	oneTerminal := terminalRiskAssertion(t, "runner:a", testExecutionSubjectProfile, bindings[1].ExecutionID,
		"execution", testExecutionStateProfile, "succeeded", outcomeRiskDigest(t, "execution-one-resolution"), true, 6)
	twoGate := gateRiskAssertion(t, "host:a", bindings[3], "complete", 3,
		outcomeRiskDigest(t, "gate-two-resolution"), true, 7)
	twoTerminal := terminalRiskAssertion(t, "runner:a", testExecutionSubjectProfile, bindings[3].ExecutionID,
		"execution", testExecutionStateProfile, "failed", outcomeRiskDigest(t, "execution-two-resolution"), true, 8)
	threeTerminalOnly := terminalRiskAssertion(t, "runner:a", testExecutionSubjectProfile, bindings[0].ExecutionID,
		"execution", testExecutionStateProfile, "succeeded", outcomeRiskDigest(t, "execution-three-resolution"), true, 9)
	fourGate := gateRiskAssertion(t, "host:a", bindings[2], "complete", 1,
		outcomeRiskDigest(t, "gate-four-resolution"), true, 10)
	fourWrongAgreement := gateRiskAssertion(t, "host:b", bindings[2], "complete", 1,
		outcomeRiskDigest(t, "gate-four-other-resolution"), true, 11)
	fourWrongAgreementPayload := decodeGateRiskAssertion(t, fourWrongAgreement)
	fourWrongAgreementPayload.AgreementBodyDigest = outcomeRiskDigest(t, "wrong-agreement")
	fourWrongAgreement.AssertionPayload = marshalOutcomeRiskPayload(t, fourWrongAgreementPayload)
	fourTerminal := terminalRiskAssertion(t, "runner:a", testExecutionSubjectProfile, bindings[2].ExecutionID,
		"execution", testExecutionStateProfile, "succeeded", outcomeRiskDigest(t, "execution-four-resolution"), true, 12)

	assertions := []VerifiedOutcomeAssertion{fourTerminal, oneGate, twoTerminal, threeTerminalOnly, oneTerminal,
		fourGate, oneGate, fourWrongAgreement, twoGate}
	projection, err := ProjectServiceCapabilityOutcomeRisk(outcomeRiskPolicy(t), "provider:security",
		"service:smart-contract-review", bindings, assertions)
	if err != nil {
		t.Fatal(err)
	}
	if projection.SucceededExecutions != 1 || projection.AdverseExecutions != 1 ||
		projection.UnknownExecutions != 1 || projection.IndeterminateExecutions != 1 || len(projection.Executions) != 4 {
		t.Fatalf("service-capability evidence was merged or overclaimed: %+v", projection)
	}
	one := capabilityExecutionByID(t, projection, bindings[1].ExecutionID)
	if one.State != LocalOutcomeSucceeded || len(one.BindingAssertions) != 1 || len(one.OutcomeAssertions) != 1 {
		t.Fatalf("exact assertion replay inflated an execution: %+v", one)
	}
	three := capabilityExecutionByID(t, projection, bindings[0].ExecutionID)
	if three.State != LocalOutcomeUnknown || len(three.OutcomeAssertions) != 1 || len(three.BindingAssertions) != 0 {
		t.Fatalf("a terminal result without Agreement-bound Gate evidence became capability history: %+v", three)
	}
	four := capabilityExecutionByID(t, projection, bindings[2].ExecutionID)
	if four.State != LocalOutcomeIndeterminate || !four.EvidenceConflict {
		t.Fatalf("a wrong-Agreement Gate assertion did not fail closed: %+v", four)
	}
	if projection.Sufficient || projection.DenominatorState != "unknown" ||
		projection.Policy.PolicyRevision != outcomeRiskPolicy(t).PolicyRevision {
		t.Fatalf("service capability evidence became an admission or global reliability claim: %+v", projection)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	if strings.Contains(lower, "probability") || strings.Contains(lower, `"score"`) ||
		strings.Contains(lower, `"admit"`) || strings.Contains(lower, `"enable"`) {
		t.Fatalf("service capability view exposed an authority-bearing result: %s", raw)
	}
}

func TestOutcomeRiskViewsRequireExplicitPrivateOwnerPolicyAndUnforkedBindings(t *testing.T) {
	policy := outcomeRiskPolicy(t)
	policy.PolicyRevision = 0
	if _, err := ProjectProviderDeliveryOutcomeRisk(policy, "provider:a",
		[]ProviderDeliverySubjectBinding{deliveryRiskBinding(t, "delivery:one", "work:one")}, nil); err == nil {
		t.Fatal("missing local Owner policy revision was accepted")
	}
	policy = outcomeRiskPolicy(t)
	policy.ProjectionVisibility = "public"
	if _, err := ProjectServiceCapabilityOutcomeRisk(policy, "provider:a", "service:a",
		[]ServiceCapabilityExecutionBinding{executionRiskBinding(t, "execution:one", "work:one")}, nil); err == nil {
		t.Fatal("a local-private projection was silently made public")
	}

	binding := deliveryRiskBinding(t, "delivery:fork", "work:one")
	fork := binding
	fork.AgreementBodyDigest = outcomeRiskDigest(t, "other-agreement")
	if _, err := ProjectProviderDeliveryOutcomeRisk(outcomeRiskPolicy(t), "provider:a",
		[]ProviderDeliverySubjectBinding{binding, fork}, nil); err == nil {
		t.Fatal("forked local delivery bindings were accepted")
	}
	execution := executionRiskBinding(t, "execution:fork", "work:one")
	executionFork := execution
	executionFork.AgreementObligationID = "work:other"
	if _, err := ProjectServiceCapabilityOutcomeRisk(outcomeRiskPolicy(t), "provider:a", "service:a",
		[]ServiceCapabilityExecutionBinding{execution, executionFork}, nil); err == nil {
		t.Fatal("forked local execution bindings were accepted")
	}
}

func outcomeRiskPolicy(t *testing.T) LocalOutcomeRiskPolicyRevision {
	t.Helper()
	return LocalOutcomeRiskPolicyRevision{OwnerID: "owner:risk", PolicyRevision: 17,
		PolicyDigest: outcomeRiskDigest(t, "owner-risk-policy-17"), EvaluationTimeUnix: 1_900_000_000,
		ProjectionVisibility: localOutcomePrivateVisibility}
}

func deliveryRiskBinding(t *testing.T, subjectID, obligationID string) ProviderDeliverySubjectBinding {
	t.Helper()
	return ProviderDeliverySubjectBinding{AgreementBodyDigest: outcomeRiskDigest(t, "agreement:"+subjectID),
		AgreementObligationID: obligationID, DeliverySubjectProfileURI: testDeliverySubjectProfile,
		DeliverySubjectID: subjectID, OwningStateProfileURI: testDeliveryStateProfile}
}

func executionRiskBinding(t *testing.T, label, obligationID string) ServiceCapabilityExecutionBinding {
	t.Helper()
	return ServiceCapabilityExecutionBinding{AgreementBodyDigest: outcomeRiskDigest(t, "agreement:"+label),
		AgreementObligationID: obligationID, ExecutionID: outcomeRiskDigest(t, label),
		ExecutionSubjectProfileURI: testExecutionSubjectProfile, OwningStateProfileURI: testExecutionStateProfile}
}

func terminalRiskAssertion(t *testing.T, actor, subjectProfile, subjectID, scope, owningStateProfile,
	disposition, resolutionDigest string, qualified bool, highWater uint64) VerifiedOutcomeAssertion {
	t.Helper()
	failureStage, failureCode := "delivery", "delivery.failed"
	if scope == "execution" {
		failureStage, failureCode = "execution", "execution.failed"
	}
	if disposition == "succeeded" {
		failureStage, failureCode = "not_applicable", "none"
	}
	terminal := commerce.TerminalDispositionV1{TerminalScope: scope, TerminalSubjectID: subjectID,
		OwningStateProfileURI: owningStateProfile, AuthoritativeResolutionDigest: resolutionDigest,
		TerminalStateRevision: 1, SuccessorPolicyDigest: outcomeRiskDigest(t, "successor:"+subjectID),
		Disposition: disposition, FailureStage: failureStage, FailureCode: failureCode, RetryDisposition: "none",
		ResolvedAtUnix: 1_899_999_900}
	payload := marshalOutcomeRiskPayload(t, terminal)
	operationID := outcomeRiskDigest(t, strings.Join([]string{actor, subjectID, disposition, resolutionDigest}, "|"))
	return VerifiedOutcomeAssertion{Key: OutcomeAssertionKey{NetworkID: "tos:test", ActorAgentID: actor,
		OperationID: operationID, OperationEnvelopeDigest: outcomeRiskDigest(t, "envelope:"+operationID)},
		Body: commerce.OperationOutcomeEventBodyV1{SchemaVersion: commerce.OperationOutcomeSchemaV1,
			EventKind:           commerce.OutcomeTerminalObservation,
			PrimarySubjectRef:   commerce.OutcomeSubjectRefV1{SubjectProfileURI: subjectProfile, SubjectID: subjectID},
			AssertionProfileURI: commerce.OutcomeProfileTerminal}, AssertionPayload: payload,
		Manifest: commerce.OutcomeEvidenceManifestV1{EvidenceItems: []commerce.OutcomeEvidenceItemV1{{
			EvidenceRole: "authoritative_resolution", ObjectDigest: resolutionDigest,
			IssuerDescriptor: "qualified-source:terminal"}}},
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: qualified,
			VerifiedEvidenceDigests: []string{resolutionDigest}, AuthorityTimeHighWater: highWater}, payloadEvidenceBound: true}
}

func gateRiskAssertion(t *testing.T, actor string, binding ServiceCapabilityExecutionBinding, state string,
	revision uint64, authoritativeRecord string, qualified bool, highWater uint64) VerifiedOutcomeAssertion {
	t.Helper()
	gate := commerce.GateExecutionObservationV1{ExecutionID: binding.ExecutionID,
		AgreementBodyDigest: binding.AgreementBodyDigest, ObligationID: binding.AgreementObligationID,
		PlanDigest: outcomeRiskDigest(t, "plan:"+binding.ExecutionID), GatePolicyDigest: outcomeRiskDigest(t, "gate-policy"),
		InputSetDigest: outcomeRiskDigest(t, "inputs:"+binding.ExecutionID), ResourceSetDigest: outcomeRiskDigest(t, "resources"),
		CredentialSetDigest: outcomeRiskDigest(t, "credentials"), EffectSetDigest: outcomeRiskDigest(t, "effects"),
		State: state, StateRevision: revision, AuthoritativeRecord: authoritativeRecord, ObservedAtUnix: 1_899_999_800}
	payload := marshalOutcomeRiskPayload(t, gate)
	operationID := outcomeRiskDigest(t, strings.Join([]string{actor, binding.ExecutionID, state,
		binding.AgreementBodyDigest, authoritativeRecord}, "|"))
	return VerifiedOutcomeAssertion{Key: OutcomeAssertionKey{NetworkID: "tos:test", ActorAgentID: actor,
		OperationID: operationID, OperationEnvelopeDigest: outcomeRiskDigest(t, "envelope:"+operationID)},
		Body: commerce.OperationOutcomeEventBodyV1{SchemaVersion: commerce.OperationOutcomeSchemaV1,
			EventKind: commerce.OutcomeTransitionObservation,
			PrimarySubjectRef: commerce.OutcomeSubjectRefV1{SubjectProfileURI: binding.ExecutionSubjectProfileURI,
				SubjectID: binding.ExecutionID}, AssertionProfileURI: commerce.OutcomeProfileGateExecution},
		AssertionPayload: payload, Manifest: commerce.OutcomeEvidenceManifestV1{EvidenceItems: []commerce.OutcomeEvidenceItemV1{{
			EvidenceRole: "authoritative_resolution", ObjectDigest: authoritativeRecord,
			IssuerDescriptor: "qualified-source:gate"}}},
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: qualified,
			VerifiedEvidenceDigests: []string{authoritativeRecord}, AuthorityTimeHighWater: highWater}, payloadEvidenceBound: true}
}

func decodeGateRiskAssertion(t *testing.T, assertion VerifiedOutcomeAssertion) commerce.GateExecutionObservationV1 {
	t.Helper()
	var value commerce.GateExecutionObservationV1
	if err := codec.Unmarshal(assertion.AssertionPayload, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func marshalOutcomeRiskPayload(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := codec.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func outcomeRiskDigest(t *testing.T, value string) string {
	t.Helper()
	digest, err := codec.Digest("tos.openfox.outcome-risk-test.v1", value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func providerDeliveryByID(t *testing.T, projection ProviderDeliveryOutcomeRiskProjection,
	subjectID string) ProviderDeliveryEvidence {
	t.Helper()
	for _, delivery := range projection.Deliveries {
		if delivery.Binding.DeliverySubjectID == subjectID {
			return delivery
		}
	}
	t.Fatalf("delivery %s is absent: %+v", subjectID, projection)
	return ProviderDeliveryEvidence{}
}

func capabilityExecutionByID(t *testing.T, projection ServiceCapabilityOutcomeRiskProjection,
	executionID string) ServiceCapabilityExecutionEvidence {
	t.Helper()
	for _, execution := range projection.Executions {
		if execution.Binding.ExecutionID == executionID {
			return execution
		}
	}
	t.Fatalf("execution %s is absent: %+v", executionID, projection)
	return ServiceCapabilityExecutionEvidence{}
}

func reverseDeliveryBindings(values []ProviderDeliverySubjectBinding) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseVerifiedOutcomeAssertions(values []VerifiedOutcomeAssertion) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
