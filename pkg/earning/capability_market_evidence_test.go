package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type capabilityMarketOutcomeFixture struct {
	now           time.Time
	outcome       CapabilityMarketTerminalOutcome
	operation     commerce.AgentOperationAuthorityResolver
	evidence      commerce.OutcomeEvidenceAuthorityVerifierV1
	resultBinding CapabilityMarketCampaignResultBindingV1
}

func TestCapabilityMarketTerminalOutcomeIsAuthorityQualifiedPayloadBoundAndIdempotent(t *testing.T) {
	fixture := newCapabilityMarketOutcomeFixture(t, "settled", "execution", 11)
	projection := NewOutcomeProjection()
	first, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, fixture.outcome,
		fixture.operation, fixture.evidence, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, fixture.outcome,
		fixture.operation, fixture.evidence, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Key != second.Key || !first.Authority.AuthorityQualified || !first.payloadEvidenceBound {
		t.Fatalf("verified campaign result lost authority or source binding: first=%+v second=%+v", first, second)
	}
	contentID, _, err := commerce.OperationOutcomeEventContentIDV1(fixture.outcome.EventBody)
	if err != nil || len(projection.ByContent(contentID)) != 1 {
		t.Fatalf("exact replay was not idempotent: content=%s err=%v assertions=%+v", contentID, err,
			projection.ByContent(contentID))
	}

	tampered := fixture.outcome
	tampered.Source = cloneCapabilityMarketSource(tampered.Source)
	tampered.Source.Object = []byte(strings.Replace(string(tampered.Source.Object), `"seller":"seller.security"`,
		`"seller":"seller.attacker"`, 1))
	if _, err := VerifyAndIngestCapabilityMarketTerminalOutcome(NewOutcomeProjection(), tampered,
		fixture.operation, fixture.evidence, fixture.now); err == nil {
		t.Fatal("rewritten campaign-result bytes retained authority over the original terminal payload")
	}
}

func TestCapabilityMarketOwnerRiskUsesExistingViewsAndConflictsStayIndeterminate(t *testing.T) {
	executionFixture := newCapabilityMarketOutcomeFixture(t, "settled", "execution", 21)
	deliveryFixture := newCapabilityMarketOutcomeFixture(t, "settled", "delivery", 22)
	projection := NewOutcomeProjection()
	execution, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, executionFixture.outcome,
		executionFixture.operation, executionFixture.evidence, executionFixture.now)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, deliveryFixture.outcome,
		deliveryFixture.operation, deliveryFixture.evidence, deliveryFixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCapabilityMarketCampaignResultPayloadBinder([]CapabilityMarketCampaignResultSource{
		executionFixture.outcome.Source, deliveryFixture.outcome.Source,
	}); err != nil {
		t.Fatalf("one exact result could not bind its distinct execution and delivery terminals: %v", err)
	}
	binding := executionFixture.resultBinding
	context := CapabilityMarketOwnerRiskContext{Policy: capabilityMarketRiskPolicy(t),
		ProviderAgentID: "agent:security-provider", LocalServiceCapabilityID: "service:smart-contract-review",
		Delivery: ProviderDeliverySubjectBinding{AgreementBodyDigest: binding.AgreementBodyDigest,
			AgreementObligationID: binding.AgreementObligationID, DeliverySubjectProfileURI: "tos.subject.delivery.v1",
			DeliverySubjectID: binding.DeliverySubjectID, OwningStateProfileURI: "tos.delivery.lifecycle.v1"},
		Execution: ServiceCapabilityExecutionBinding{AgreementBodyDigest: binding.AgreementBodyDigest,
			AgreementObligationID: binding.AgreementObligationID, ExecutionID: binding.ExecutionID,
			ExecutionSubjectProfileURI: "tos.subject.execution.v1", OwningStateProfileURI: "tos.execution.lifecycle.v1"}}
	gate := capabilityMarketGateAssertion(t, context.Execution, executionFixture.now)
	view, err := ProjectCapabilityMarketOwnerRisk(context,
		[]VerifiedOutcomeAssertion{delivery, execution, gate, delivery, execution, gate})
	if err != nil {
		t.Fatal(err)
	}
	if view.ProviderDelivery.SucceededDeliveries != 1 || view.ServiceCapability.SucceededExecutions != 1 ||
		view.ProviderDelivery.Sufficient || view.ServiceCapability.Sufficient {
		t.Fatalf("owner-local view counted replay or became a global score: %+v", view)
	}

	conflictFixture := newCapabilityMarketOutcomeFixture(t, "failed", "delivery", 23)
	conflict, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, conflictFixture.outcome,
		conflictFixture.operation, conflictFixture.evidence, conflictFixture.now)
	if err != nil {
		t.Fatal(err)
	}
	conflicted, err := ProjectCapabilityMarketOwnerRisk(context,
		[]VerifiedOutcomeAssertion{delivery, conflict, execution, gate})
	if err != nil {
		t.Fatal(err)
	}
	if conflicted.ProviderDelivery.IndeterminateDeliveries != 1 ||
		conflicted.ProviderDelivery.Deliveries[0].State != LocalOutcomeIndeterminate ||
		!conflicted.ProviderDelivery.Deliveries[0].EvidenceConflict {
		t.Fatalf("conflicting qualified results did not remain indeterminate: %+v", conflicted.ProviderDelivery)
	}
	encoded, err := json.Marshal(conflicted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), `"score"`) ||
		strings.Contains(strings.ToLower(string(encoded)), "probability") {
		t.Fatalf("local evidence helper invented a global score: %s", encoded)
	}
}

type capabilityMarketPaymentVerifier struct {
	reject bool
}

func (verifier capabilityMarketPaymentVerifier) VerifyPaymentEvidence(_ commerce.AgreementPaymentRequest,
	_ commerce.AgreementPaymentEvidence, _ time.Time) error {
	if verifier.reject {
		return errors.New("payment finality rejected")
	}
	return nil
}

type capabilityMarketFeeBinder struct {
	bound CapabilityMarketBoundTransactionFee
	err   error
}

func (binder capabilityMarketFeeBinder) BindCapabilityMarketTransactionFee(_ commerce.AgreementPaymentRequest,
	_ commerce.AgreementPaymentEvidence, _ time.Time) (CapabilityMarketBoundTransactionFee, error) {
	return binder.bound, binder.err
}

func TestCapabilityMarketCostsRequireExactPaymentAndChainFeeBinder(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	paymentRequest, paymentEvidence := capabilityMarketPayment(t, now)
	policyDigest := capabilityMarketDigest(t, "accounting-policy")
	base := CapabilityMarketCostEvidenceRequest{SubjectKind: "execution", SubjectID: capabilityMarketDigest(t, "execution"),
		AccountingPolicyDigest: policyDigest, PaymentRequest: &paymentRequest, PaymentEvidence: &paymentEvidence,
		PaymentVerifier: capabilityMarketPaymentVerifier{}}

	unknown, err := ObserveCapabilityMarketCosts(base, now)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.ChainFee.Status != CapabilityMarketCostUnknown || unknown.ChainFee.AmountAtomic != "" ||
		unknown.Model.Status != CapabilityMarketCostUnknown || unknown.Model.AmountAtomic != "" ||
		unknown.API.Status != CapabilityMarketCostUnknown || unknown.API.AmountAtomic != "" {
		t.Fatalf("missing cost evidence became numeric zero or observed cost: %+v", unknown)
	}

	requestDigest, err := commerce.AgreementPaymentRequestDigest(paymentRequest)
	if err != nil {
		t.Fatal(err)
	}
	bound := CapabilityMarketBoundTransactionFee{NetworkID: paymentRequest.NetworkID,
		PaymentRequestDigest: requestDigest, StableActionID: paymentRequest.StableActionID,
		TransactionDigest: paymentEvidence.ExactTransferReference, FinalityReference: paymentEvidence.FinalityReference,
		FeeAssetIdentityDigest: capabilityMarketDigest(t, "native-tos"), FeeAmountAtomic: "17",
		EvidenceProfileURI: "tos.chain.transaction-fee.v1", EvidenceIssuer: "validator-quorum:local",
		EvidenceDigest: capabilityMarketDigest(t, "transaction-fee-proof"), ObservedAtUnix: uint64(now.Add(-time.Minute).Unix())}
	base.FeeBinders = []CapabilityMarketTransactionFeeEvidenceBinder{capabilityMarketFeeBinder{bound: bound}}
	observed, err := ObserveCapabilityMarketCosts(base, now)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ChainFee.Status != CapabilityMarketCostObserved || observed.ChainFee.AmountAtomic != "17" ||
		observed.ChainFee.Observation == nil || observed.ChainFee.Observation.Category != "chain_fee" ||
		observed.Model.Status != CapabilityMarketCostUnknown || observed.API.Status != CapabilityMarketCostUnknown {
		t.Fatalf("verified transaction fee did not create the narrow cost observation: %+v", observed)
	}
	if err := validateCostObservationForCurrentDependency(*observed.ChainFee.Observation); err != nil {
		t.Fatalf("generated chain-fee Cost V1 payload is invalid: %v", err)
	}

	conflict := bound
	conflict.FeeAmountAtomic = "18"
	conflict.EvidenceDigest = capabilityMarketDigest(t, "conflicting-transaction-fee-proof")
	base.FeeBinders = []CapabilityMarketTransactionFeeEvidenceBinder{
		capabilityMarketFeeBinder{bound: bound}, capabilityMarketFeeBinder{bound: bound}, capabilityMarketFeeBinder{bound: conflict}}
	indeterminate, err := ObserveCapabilityMarketCosts(base, now)
	if err != nil {
		t.Fatal(err)
	}
	if indeterminate.ChainFee.Status != CapabilityMarketCostIndeterminate ||
		indeterminate.ChainFee.AmountAtomic != "" || indeterminate.ChainFee.Observation != nil {
		t.Fatalf("conflicting exact fee binders produced a numeric amount: %+v", indeterminate.ChainFee)
	}

	base.PaymentVerifier = capabilityMarketPaymentVerifier{reject: true}
	base.FeeBinders = []CapabilityMarketTransactionFeeEvidenceBinder{capabilityMarketFeeBinder{bound: bound}}
	rejected, err := ObserveCapabilityMarketCosts(base, now)
	if err != nil || rejected.ChainFee.Status != CapabilityMarketCostUnknown || rejected.ChainFee.AmountAtomic != "" {
		t.Fatalf("unverified payment produced a chain fee: view=%+v err=%v", rejected, err)
	}
}

func newCapabilityMarketOutcomeFixture(t *testing.T, resultDisposition, scope string,
	operationSequence uint64) capabilityMarketOutcomeFixture {
	t.Helper()
	now := time.Unix(1_900_000_000, 0).UTC()
	agreementDigest := capabilityMarketDigest(t, "agreement")
	executionID := capabilityMarketDigest(t, "execution")
	deliveryID := capabilityMarketDigest(t, "delivery")
	completed := now.Add(-2 * time.Minute)
	raw := []byte(fmt.Sprintf(`{"sequence":7,"disposition":%q,"round":1,"buyer":"buyer.audit","seller":"seller.security","capability":"smart-contract-review","demand_intent_digest":%q,"agreement_digest":%q,"execution_id":%q,"deliverable_digest":%q,"payment_transaction":%q,"finality_reference":"checkpoint:31","revenue_nanotos":50,"maximum_internal_cost_nanotos":9,"projected_net_nanotos":41,"skills_before":[],"skills_after":[],"execution_elapsed_millis":10,"settlement_elapsed_millis":20,"economic_evidence_digest":%q,"economic_analysis_mode":"bounded","expected_net_nanotos":"41","completed_at":%q,"carrier_ids":["carrier:one"]}`,
		resultDisposition, capabilityMarketDigest(t, "intent"), agreementDigest, executionID, deliveryID,
		capabilityMarketDigest(t, "payment-transaction"), capabilityMarketDigest(t, "economic-evidence"),
		completed.Format(time.RFC3339Nano)))
	terminalDisposition, failureStage, failureCode, retry := "succeeded", "not_applicable", "none", "none"
	if resultDisposition != "settled" {
		terminalDisposition, failureStage, failureCode, retry = "failed", scope, scope+".campaign_failed", "owner_review"
	}
	subjectProfile, stateProfile := "tos.subject.execution.v1", "tos.execution.lifecycle.v1"
	if scope == "delivery" {
		subjectProfile, stateProfile = "tos.subject.delivery.v1", "tos.delivery.lifecycle.v1"
	}
	binding := CapabilityMarketCampaignResultBindingV1{Sequence: 7, BuyerResultID: "buyer.audit",
		ProviderResultID: "seller.security", ResultCapabilityID: "smart-contract-review",
		ResultDisposition: resultDisposition, AgreementBodyDigest: agreementDigest, AgreementObligationID: "work",
		ExecutionID: executionID, DeliverySubjectID: deliveryID, TerminalScope: scope,
		SubjectProfileURI: subjectProfile, OwningStateProfileURI: stateProfile,
		SuccessorPolicyDigest: capabilityMarketDigest(t, "successor-policy"), TerminalStateRevision: 1,
		TerminalDisposition: terminalDisposition, FailureStage: failureStage, FailureCode: failureCode,
		RetryDisposition: retry}
	source := CapabilityMarketCampaignResultSource{Object: raw, Binding: binding}
	descriptor, err := CapabilityMarketCampaignResultSubjectDescriptor(source)
	if err != nil {
		t.Fatal(err)
	}
	timeProof := commerce.AuthorityTimeProofV1{ProfileURI: "tos.authority.clock.v1",
		AuthorityOrCheckpointID: "checkpoint:campaign", IntervalStartUnix: uint64(now.Add(-3 * time.Minute).Unix()),
		IntervalEndUnix: uint64(now.Add(-time.Minute).Unix()), FinalizedHighWater: operationSequence,
		FinalizedRootDigest: capabilityMarketDigest(t, fmt.Sprintf("authority-root-%d", operationSequence)),
		ProofDigest:         capabilityMarketDigest(t, fmt.Sprintf("authority-proof-%d", operationSequence))}
	timeBytes, err := codec.Marshal(timeProof)
	if err != nil {
		t.Fatal(err)
	}
	timeMaterial := commerce.OutcomeAuthorityProofMaterialV1{ProofProfileURI: commerce.OutcomeAuthorityTimeProofProfileV1,
		CanonicalObject: timeBytes}
	timeDigest, err := commerce.OutcomeAuthorityProofObjectDigestV1(timeMaterial)
	if err != nil {
		t.Fatal(err)
	}
	subjectScope, err := commerce.OutcomeSubjectScopeDigestV1(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "issuer:campaign-controller"
	evidenceProfile := "tos.openfox.campaign-result-authority.v1"
	qualification := commerce.IssuerQualificationProofV1{RootAuthorityID: "authority:campaign",
		IssuerAgentID: issuer, IssuerKeyDigest: capabilityMarketDigest(t, "issuer-key"),
		OrderedDelegationChainDigest: capabilityMarketDigest(t, "delegation-chain"), ScopeProfileURI: evidenceProfile,
		SubjectScopeDigest: subjectScope, ValidFromUnix: uint64(now.Add(-time.Hour).Unix()),
		ValidUntilUnix: uint64(now.Add(time.Hour).Unix()), RevocationHandleSetDigest: capabilityMarketDigest(t, "revocations"),
		AuthorityTimeProofDigest: timeDigest, RevocationHighWater: operationSequence,
		RevocationRootDigest: capabilityMarketDigest(t, "revocation-root")}
	qualificationBytes, err := codec.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualificationMaterial := commerce.OutcomeAuthorityProofMaterialV1{
		ProofProfileURI: commerce.OutcomeIssuerQualificationProofProfileV1, CanonicalObject: qualificationBytes}
	evidenceVerifier, err := commerce.NewPinnedOutcomeEvidenceAuthorityV1([]commerce.AuthorityTimeProofV1{timeProof},
		[]commerce.IssuerQualificationProofV1{qualification})
	if err != nil {
		t.Fatal(err)
	}
	_, operationKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := "agent:campaign-recorder"
	operationAuthority, err := commerce.NewPinnedAgentOperationAuthorityV1(actor,
		operationKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour),
		capabilityMarketDigest(t, "operation-trust"))
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := BuildCapabilityMarketTerminalOutcome(source, CapabilityMarketOutcomeSigningContext{
		NetworkID: "tos:local", ActorAgentID: actor, AuthorizationRef: operationAuthority.Profile,
		AudienceDescriptor: "local-owner-private", OrderingDomain: capabilityMarketDigest(t, "ordering-domain"),
		Sequence: operationSequence, Epoch: 1, CreatedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(30 * time.Minute),
		OperationKey: operationKey, HistoricalProof: operationAuthority.Proof}, CapabilityMarketOutcomeEvidenceAuthority{
		EvidenceProfileURI: evidenceProfile, IssuerDescriptor: issuer, Visibility: "local_private",
		AudienceDigest: capabilityMarketDigest(t, "audience"), RetentionDigest: capabilityMarketDigest(t, "retention"),
		RetrievalDigest: capabilityMarketDigest(t, "retrieval"),
		AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{timeMaterial, qualificationMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := commerce.PinnedAgentOperationAuthorityResolverV1{actor: []commerce.PinnedAgentOperationAuthorityRecordV1{operationAuthority}}
	return capabilityMarketOutcomeFixture{now: now, outcome: outcome, operation: resolver,
		evidence: evidenceVerifier, resultBinding: binding}
}

func capabilityMarketGateAssertion(t *testing.T, binding ServiceCapabilityExecutionBinding,
	now time.Time) VerifiedOutcomeAssertion {
	t.Helper()
	authoritative := capabilityMarketDigest(t, "gate-authoritative-record")
	gate := commerce.GateExecutionObservationV1{ExecutionID: binding.ExecutionID,
		AgreementBodyDigest: binding.AgreementBodyDigest, ObligationID: binding.AgreementObligationID,
		PlanDigest: capabilityMarketDigest(t, "plan"), GatePolicyDigest: capabilityMarketDigest(t, "gate-policy"),
		InputSetDigest: capabilityMarketDigest(t, "inputs"), ResourceSetDigest: capabilityMarketDigest(t, "resources"),
		CredentialSetDigest: capabilityMarketDigest(t, "credentials"), EffectSetDigest: capabilityMarketDigest(t, "effects"),
		State: "complete", StateRevision: 1, AuthoritativeRecord: authoritative,
		ObservedAtUnix: uint64(now.Add(-3 * time.Minute).Unix())}
	payload, err := codec.Marshal(gate)
	if err != nil {
		t.Fatal(err)
	}
	operationID := capabilityMarketDigest(t, "gate-operation")
	return VerifiedOutcomeAssertion{Key: OutcomeAssertionKey{NetworkID: "tos:local", ActorAgentID: "agent:gate",
		OperationID: operationID, OperationEnvelopeDigest: capabilityMarketDigest(t, "gate-envelope")},
		Body: commerce.OperationOutcomeEventBodyV1{SchemaVersion: commerce.OperationOutcomeSchemaV1,
			EventKind: commerce.OutcomeTransitionObservation,
			PrimarySubjectRef: commerce.OutcomeSubjectRefV1{SubjectProfileURI: binding.ExecutionSubjectProfileURI,
				SubjectID: binding.ExecutionID}, AssertionProfileURI: commerce.OutcomeProfileGateExecution},
		AssertionPayload: payload, Manifest: commerce.OutcomeEvidenceManifestV1{EvidenceItems: []commerce.OutcomeEvidenceItemV1{{
			EvidenceRole: "authoritative_resolution", ObjectDigest: authoritative, IssuerDescriptor: "issuer:gate"}}},
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: true,
			VerifiedEvidenceDigests: []string{authoritative}, AuthorityTimeHighWater: 8}, payloadEvidenceBound: true}
}

func capabilityMarketPayment(t *testing.T, now time.Time) (commerce.AgreementPaymentRequest,
	commerce.AgreementPaymentEvidence) {
	t.Helper()
	agreementDigest := capabilityMarketDigest(t, "payment-agreement")
	mandateDigest := capabilityMarketDigest(t, "payment-mandate")
	amount := commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native",
		AmountAtomic: "50", Unit: "nanotos"}
	obligation := commerce.AgreementObligation{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:buyer",
		BeneficiaryAgentID: "agent:provider", SubjectContentType: "text/plain", Subject: []byte("pay for result"),
		Amount: &amount, DueAtUnix: uint64(now.Add(20 * time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(40 * time.Minute).Unix()), ConfidentialityPolicy: "participants",
		CancellationPolicy: "before-due", DisputePolicy: "evidence", SettlementAdapterURI: "tos.payment.direct.v1",
		SettlementParameters: []byte("provider-wallet"), AuthorizationPredicateIDs: []string{"buyer-payment"}}
	instances, err := commerce.MaterializeSettlementObligations("owner:buyer", "agent:buyer", agreementDigest,
		"pay", mandateDigest, obligation)
	if err != nil || len(instances) != 1 {
		t.Fatalf("materialize payment: instances=%d err=%v", len(instances), err)
	}
	request, err := commerce.BuildAgreementPaymentRequest("owner:buyer", "agent:buyer", "tos:local",
		[]byte("provider-wallet"), instances[0])
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := commerce.AgreementPaymentRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := commerce.AgreementPaymentEvidence{PaymentRequestDigest: requestDigest,
		StableActionID: request.StableActionID, ExactTransferReference: capabilityMarketDigest(t, "chain-transaction"),
		AdapterEvidenceProfile: "tos.chain.finality.v1", ResolvedState: "finalized",
		ResolvedAtUnix: uint64(now.Add(-time.Minute).Unix()), FinalityReference: "checkpoint:payment",
		Evidence: []byte("real-finality-evidence-fixture")}
	return request, evidence
}

func capabilityMarketRiskPolicy(t *testing.T) LocalOutcomeRiskPolicyRevision {
	t.Helper()
	return LocalOutcomeRiskPolicyRevision{OwnerID: "owner:campaign", PolicyRevision: 3,
		PolicyDigest: capabilityMarketDigest(t, "risk-policy"), EvaluationTimeUnix: 1_900_000_000,
		ProjectionVisibility: localOutcomePrivateVisibility}
}

func capabilityMarketDigest(t *testing.T, value string) string {
	t.Helper()
	digest, err := codec.Digest("tos.openfox.capability-market-test.v1", value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
