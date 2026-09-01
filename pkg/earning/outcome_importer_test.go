package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type acceptingImportedOperationResolver struct{}

func (acceptingImportedOperationResolver) AuthorizeAgentOperationKey(string, commerce.ProfileRefV1,
	ed25519.PublicKey, time.Time, []byte) error {
	return nil
}

type rejectingImportedOperationResolver struct{}

func (rejectingImportedOperationResolver) AuthorizeAgentOperationKey(string, commerce.ProfileRefV1,
	ed25519.PublicKey, time.Time, []byte) error {
	return errors.New("operation authority is not pinned")
}

type pinnedImportedPayloadBindingVerifier map[string]string

func (verifier pinnedImportedPayloadBindingVerifier) VerifyOutcomePayloadEvidenceBinding(
	_ commerce.OperationOutcomeEventBodyV1, assertionPayload []byte, manifest commerce.OutcomeEvidenceManifestV1,
	_ commerce.OutcomeAuthorityAssessmentV1, _ time.Time) error {
	if len(manifest.EvidenceItems) != 1 {
		return errors.New("one pinned source object is required")
	}
	expected, found := verifier[manifest.EvidenceItems[0].ObjectDigest]
	if !found || expected != string(assertionPayload) {
		return errors.New("source object does not bind the exact assertion payload")
	}
	return nil
}

func importedPayloadBindingFor(request commerce.OperationCarrierRequestV1) pinnedImportedPayloadBindingVerifier {
	bindings := pinnedImportedPayloadBindingVerifier{}
	for _, item := range request.Artifacts.EvidenceManifest.EvidenceItems {
		bindings[item.ObjectDigest] = string(request.Artifacts.AssertionPayload)
	}
	return bindings
}

func TestImportOutcomeCarrierPageSeparatesRetentionFromEvidenceAuthority(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	carrierID := "carrier:import"
	qualifiedRequest, evidenceVerifier := qualifiedPaymentRequest(t, carrierID, "agent:publisher", "issuer:payments", now)
	unqualifiedRequest := testDirectoryOutcomeRequest(t, carrierID, "a", now)
	_, carrierKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	page := OutcomeCarrierPage{CarrierID: carrierID, Next: "seq:2", Results: []OutcomeCarrierResult{
		retainedOutcomeResult(t, qualifiedRequest, carrierKey, 1, now),
		retainedOutcomeResult(t, unqualifiedRequest, carrierKey, 2, now),
	}}
	projection := NewOutcomeProjection()
	result, err := ImportOutcomeCarrierPage(page, projection, OutcomeImportVerifier{
		CarrierReceiptKey: carrierKey.Public().(ed25519.PublicKey),
		Operation:         acceptingImportedOperationResolver{}, Evidence: evidenceVerifier,
		PayloadEvidence: importedPayloadBindingFor(qualifiedRequest)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Processed != 2 || result.Next != page.Next || len(result.Accepted) != 1 || len(result.Rejected) != 1 {
		t.Fatalf("whole-page audit result is incomplete: %+v", result)
	}
	if !result.Accepted[0].Authority.AuthorityQualified ||
		result.Accepted[0].Body.AssertionProfileURI != commerce.OutcomeProfileTransferAgreementPayment {
		t.Fatalf("qualified payment was not retained as qualified evidence: %+v", result.Accepted[0])
	}
	if result.Rejected[0].Index != 1 || result.Rejected[0].Stage != "evidence_authority" {
		t.Fatalf("unqualified assertion rejection is not auditable: %+v", result.Rejected[0])
	}
	// The rejected item had a valid Carrier signature. Its receipt therefore did
	// not accidentally promote the reference-only assertion into authority.
	key, err := decodeOutcomeCarrierKey(page.Results[1].CarrierPublicKey)
	if err != nil || commerce.VerifyOperationSubmissionReceiptV1(page.Results[1].Receipt, key) != nil {
		t.Fatal("test fixture did not carry a valid Carrier receipt")
	}
}

func TestImportOutcomeCarrierPageRejectsUnpinnedOperationPerItem(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	request, evidenceVerifier := qualifiedPaymentRequest(t, "carrier:import", "agent:publisher", "issuer:payments", now)
	_, carrierKey, _ := ed25519.GenerateKey(rand.Reader)
	page := OutcomeCarrierPage{CarrierID: "carrier:import", Results: []OutcomeCarrierResult{
		retainedOutcomeResult(t, request, carrierKey, 1, now),
	}}
	result, err := ImportOutcomeCarrierPage(page, NewOutcomeProjection(), OutcomeImportVerifier{
		CarrierReceiptKey: carrierKey.Public().(ed25519.PublicKey),
		Operation:         rejectingImportedOperationResolver{}, Evidence: evidenceVerifier,
		PayloadEvidence: importedPayloadBindingFor(request)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Accepted) != 0 || len(result.Rejected) != 1 || result.Rejected[0].Stage != "operation_authority" {
		t.Fatalf("unpinned operation did not fail at its authority boundary: %+v", result)
	}
}

func TestImportOutcomeCarrierPageRequiresPinnedCarrierReceiptKey(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	request, evidenceVerifier := qualifiedPaymentRequest(t, "carrier:import", "agent:publisher", "issuer:payments", now)
	_, carrierKey, _ := ed25519.GenerateKey(rand.Reader)
	_, unrelatedKey, _ := ed25519.GenerateKey(rand.Reader)
	page := OutcomeCarrierPage{CarrierID: "carrier:import", Results: []OutcomeCarrierResult{
		retainedOutcomeResult(t, request, carrierKey, 1, now),
	}}
	result, err := ImportOutcomeCarrierPage(page, NewOutcomeProjection(), OutcomeImportVerifier{
		CarrierReceiptKey: unrelatedKey.Public().(ed25519.PublicKey),
		Operation:         acceptingImportedOperationResolver{}, Evidence: evidenceVerifier,
		PayloadEvidence: importedPayloadBindingFor(request)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Accepted) != 0 || len(result.Rejected) != 1 || result.Rejected[0].Stage != "carrier_binding" {
		t.Fatalf("self-claimed Carrier receipt key was trusted: %+v", result)
	}
}

func TestImportOutcomeCarrierPageIsIdempotent(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	request, evidenceVerifier := qualifiedPaymentRequest(t, "carrier:import", "agent:publisher", "issuer:payments", now)
	_, carrierKey, _ := ed25519.GenerateKey(rand.Reader)
	page := OutcomeCarrierPage{CarrierID: "carrier:import", Results: []OutcomeCarrierResult{
		retainedOutcomeResult(t, request, carrierKey, 1, now),
	}}
	projection := NewOutcomeProjection()
	verifier := OutcomeImportVerifier{CarrierReceiptKey: carrierKey.Public().(ed25519.PublicKey),
		Operation: acceptingImportedOperationResolver{}, Evidence: evidenceVerifier,
		PayloadEvidence: importedPayloadBindingFor(request)}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := ImportOutcomeCarrierPage(page, projection, verifier, now)
		if err != nil || len(result.Accepted) != 1 || len(result.Rejected) != 0 {
			t.Fatalf("idempotent import attempt %d failed: result=%+v err=%v", attempt, result, err)
		}
	}
	contentID, _, err := commerce.OperationOutcomeEventContentIDV1(page.Results[0].EventBody)
	if err != nil {
		t.Fatal(err)
	}
	if got := projection.ByContent(contentID); len(got) != 1 {
		t.Fatalf("idempotent import duplicated or lost its event: %+v", got)
	}
}

func TestImportOutcomeCarrierPageRejectsQualifiedButPayloadUnboundEvidence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	request, evidenceVerifier := qualifiedPaymentRequest(t, "carrier:import", "agent:publisher", "issuer:payments", now)
	_, carrierKey, _ := ed25519.GenerateKey(rand.Reader)
	page := OutcomeCarrierPage{CarrierID: "carrier:import", Results: []OutcomeCarrierResult{
		retainedOutcomeResult(t, request, carrierKey, 1, now),
	}}
	binding := importedPayloadBindingFor(request)
	for digest := range binding {
		binding[digest] = "different qualified source payload"
	}
	result, err := ImportOutcomeCarrierPage(page, NewOutcomeProjection(), OutcomeImportVerifier{
		CarrierReceiptKey: carrierKey.Public().(ed25519.PublicKey), Operation: acceptingImportedOperationResolver{},
		Evidence: evidenceVerifier, PayloadEvidence: binding}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Accepted) != 0 || len(result.Rejected) != 1 || result.Rejected[0].Stage != "payload_evidence_binding" {
		t.Fatalf("unrelated qualified evidence authenticated a rewritten payload: %+v", result)
	}
}

func TestImportOutcomeCarrierPageImportsCostGenesisWithReleasedDependency(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	request, evidenceVerifier := qualifiedCostRequest(t, "carrier:import", "agent:publisher", "issuer:cost", now)
	_, carrierKey, _ := ed25519.GenerateKey(rand.Reader)
	page := OutcomeCarrierPage{CarrierID: "carrier:import", Results: []OutcomeCarrierResult{
		retainedOutcomeResult(t, request, carrierKey, 1, now),
	}}
	result, err := ImportOutcomeCarrierPage(page, NewOutcomeProjection(), OutcomeImportVerifier{
		CarrierReceiptKey: carrierKey.Public().(ed25519.PublicKey), Operation: acceptingImportedOperationResolver{},
		Evidence: evidenceVerifier, PayloadEvidence: importedPayloadBindingFor(request)}, now)
	if err != nil || len(result.Accepted) != 1 || len(result.Rejected) != 0 {
		t.Fatalf("non-contra cost genesis did not pass the end-to-end importer: result=%+v err=%v", result, err)
	}
	summary, err := SummarizeQualifiedCostEvidence(result.Accepted, nil)
	if err != nil || len(summary.Observed) != 1 || summary.Observed[0].AmountAtomic != "7" {
		t.Fatalf("imported cost genesis was not consumable: summary=%+v err=%v", summary, err)
	}
}

func qualifiedPaymentRequest(t *testing.T, carrierID, actor, issuer string,
	now time.Time) (commerce.OperationCarrierRequestV1, commerce.OutcomeEvidenceAuthorityVerifierV1) {
	t.Helper()
	transactionDigest, _ := codec.Digest("tos.test.transaction.v1", actor)
	transfer := commerce.TransferObservationV1{TransferClass: "agreement_bound", NetworkID: "tos:test",
		TransactionDigest: transactionDigest, FinalityEvidenceDigest: testDigest, PayerID: "agent:buyer", PayeeID: "agent:local",
		AssetIdentityDigest: zeroSHA256Digest(), AmountAtomic: "25", DestinationDigest: testDigest,
		AgreementBodyDigest: testDigest, ObligationInstanceID: zeroSHA256Digest(), PaymentRequestDigest: testDigest,
		StableActionID: zeroSHA256Digest(), ExactRequestDigest: testDigest, AdapterProfileURI: "tos.payment.direct.v1",
		ResolutionState: "validator_finalized", ObservedAtUnix: uint64(now.Add(-time.Minute).Unix())}
	assertion, err := codec.Marshal(transfer)
	if err != nil {
		t.Fatal(err)
	}
	timeProof := commerce.AuthorityTimeProofV1{ProfileURI: "tos.authority.clock.v1", AuthorityOrCheckpointID: "checkpoint:payments",
		IntervalStartUnix: uint64(now.Add(-2 * time.Minute).Unix()), IntervalEndUnix: uint64(now.Add(-time.Minute).Unix()),
		FinalizedHighWater: 9, FinalizedRootDigest: testDigest, ProofDigest: zeroSHA256Digest()}
	timeBytes, _ := codec.Marshal(timeProof)
	timeMaterial := commerce.OutcomeAuthorityProofMaterialV1{ProofProfileURI: commerce.OutcomeAuthorityTimeProofProfileV1,
		CanonicalObject: timeBytes}
	timeDigest, err := commerce.OutcomeAuthorityProofObjectDigestV1(timeMaterial)
	if err != nil {
		t.Fatal(err)
	}
	subjectDescriptor := "transaction:" + transactionDigest
	scopeDigest, err := commerce.OutcomeSubjectScopeDigestV1(subjectDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	qualification := commerce.IssuerQualificationProofV1{RootAuthorityID: "authority:payments", IssuerAgentID: issuer,
		IssuerKeyDigest: testDigest, OrderedDelegationChainDigest: zeroSHA256Digest(), ScopeProfileURI: "tos.transfer.finality.v1",
		SubjectScopeDigest: scopeDigest, ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ValidUntilUnix: uint64(now.Add(time.Hour).Unix()),
		RevocationHandleSetDigest: testDigest, AuthorityTimeProofDigest: timeDigest, RevocationHighWater: 3,
		RevocationRootDigest: zeroSHA256Digest()}
	qualificationBytes, _ := codec.Marshal(qualification)
	qualificationMaterial := commerce.OutcomeAuthorityProofMaterialV1{ProofProfileURI: commerce.OutcomeIssuerQualificationProofProfileV1,
		CanonicalObject: qualificationBytes}
	qualificationDigest, err := commerce.OutcomeAuthorityProofObjectDigestV1(qualificationMaterial)
	if err != nil {
		t.Fatal(err)
	}
	manifest := commerce.OutcomeEvidenceManifestV1{SchemaVersion: 1, ManifestPurpose: "qualified_payment",
		AuthorityProofRefs: []commerce.OutcomeAuthorityProofRefV1{
			{ProofProfileURI: timeMaterial.ProofProfileURI, ObjectDigest: timeDigest, CanonicalSize: uint64(len(timeBytes))},
			{ProofProfileURI: qualificationMaterial.ProofProfileURI, ObjectDigest: qualificationDigest, CanonicalSize: uint64(len(qualificationBytes))},
		}, EvidenceItems: []commerce.OutcomeEvidenceItemV1{{EvidenceRole: "finalized_transfer", EvidenceProfileURI: qualification.ScopeProfileURI,
			SourceObjectProfileURI: "tos.transfer.transaction.v1", SourceObjectDigest: transactionDigest, ObjectDigest: transfer.FinalityEvidenceDigest,
			CanonicalSize: 128, MediaType: "application/cbor", IssuerDescriptor: issuer, SubjectDescriptor: subjectDescriptor,
			ClaimedObservationTimeUnix: timeProof.IntervalEndUnix, AuthorityTimeProofDigest: timeDigest,
			IssuerQualificationProofDigest: qualificationDigest, Visibility: "local_private", AudienceDigest: testDigest,
			RetentionPolicyDigest: testDigest, RetrievalPolicyDigest: zeroSHA256Digest()}}}
	if err := commerce.SortOutcomeAuthorityProofRefsV1(manifest.AuthorityProofRefs); err != nil {
		t.Fatal(err)
	}
	if err := commerce.SortOutcomeEvidenceItemsV1(manifest.EvidenceItems); err != nil {
		t.Fatal(err)
	}
	materials := []commerce.OutcomeAuthorityProofMaterialV1{timeMaterial, qualificationMaterial}
	if err := commerce.SortOutcomeAuthorityProofMaterialsV1(materials); err != nil {
		t.Fatal(err)
	}
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: transfer.StableActionID}, nil,
		commerce.OutcomeProfileTransferAgreementPayment, assertion, manifest, commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}
	_, operationKey, _ := ed25519.GenerateKey(rand.Reader)
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: actor, AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.test.v1", ProfileVersion: 1, ProfileDigest: testDigest},
		AudienceDescriptor: "local-private", ObjectID: contentID, OrderingDomain: testDigest, Epoch: 1, Sequence: 1,
		CreatedAtUnix: uint64(now.Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commerce.SignAgentOperationV1(body, actor, operationKey, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := commerce.NewPinnedOutcomeEvidenceAuthorityV1([]commerce.AuthorityTimeProofV1{timeProof},
		[]commerce.IssuerQualificationProofV1{qualification})
	if err != nil {
		t.Fatal(err)
	}
	return commerce.OperationCarrierRequestV1{SchemaVersion: 1, CarrierID: carrierID,
		CarrierProfile:       commerce.ProfileRefV1{ProfileURI: "tos.carrier.test.v1", ProfileVersion: 1, ProfileDigest: testDigest},
		AudiencePolicyDigest: testDigest, OperationID: body.OperationID, OperationEnvelopeDigest: envelopeDigest,
		OperationEnvelope: envelopeBytes, EventPayload: eventPayload, Artifacts: commerce.OperationOutcomeArtifactBundleV1{
			AssertionPayload: assertion, EvidenceManifest: manifest, ExtensionSet: commerce.EmptyOutcomeExtensionSetV1(), AuthorityProofs: materials}}, pinned
}

func qualifiedCostRequest(t *testing.T, carrierID, actor, issuer string,
	now time.Time) (commerce.OperationCarrierRequestV1, commerce.OutcomeEvidenceAuthorityVerifierV1) {
	t.Helper()
	base, evidenceVerifier := qualifiedPaymentRequest(t, carrierID, actor, issuer, now)
	manifest := base.Artifacts.EvidenceManifest
	manifest.ManifestPurpose = "qualified_cost"
	manifest.EvidenceItems[0].EvidenceRole = "cost_source"
	if err := commerce.SortOutcomeEvidenceItemsV1(manifest.EvidenceItems); err != nil {
		t.Fatal(err)
	}
	cost := commerce.CostObservationPayloadV1{SubjectKind: "execution", SubjectID: "execution:imported",
		CostItemID: "cost:imported-genesis", CostClass: "usage_measured", Category: "model",
		AssetIdentityDigest: zeroSHA256Digest(), AmountAtomic: "7", EconomicDirection: "debit",
		QuantityDigest: digestTestValue(t, "imported-cost-quantity"), MeterIntervalDigest: digestTestValue(t, "imported-cost-interval"),
		MeterUnit: "tokens", InvoiceIdentityDigest: zeroSHA256Digest(), PaymentRequestDigest: zeroSHA256Digest(),
		MeterOrInvoiceEvidenceDigest: manifest.EvidenceItems[0].ObjectDigest, AccountingPolicyDigest: testDigest,
		IncurredAtUnix: uint64(now.Add(-time.Minute).Unix())}
	assertion, err := codec.Marshal(cost)
	if err != nil {
		t.Fatal(err)
	}
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.execution.v1", SubjectID: cost.SubjectID}, nil,
		commerce.OutcomeProfileCost, assertion, manifest, commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}
	_, operationKey, _ := ed25519.GenerateKey(rand.Reader)
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION",
		OpcodeName: "OUTCOME", OpcodeVersion: 1, ActorAgentID: actor,
		AuthorizationRef:   commerce.ProfileRefV1{ProfileURI: "tos.identity.test.v1", ProfileVersion: 1, ProfileDigest: testDigest},
		AudienceDescriptor: "local-private", ObjectID: contentID, OrderingDomain: testDigest, Epoch: 1, Sequence: 2,
		CreatedAtUnix: uint64(now.Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(),
		PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commerce.SignAgentOperationV1(body, actor, operationKey, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	base.OperationID, base.OperationEnvelopeDigest, base.OperationEnvelope = body.OperationID, envelopeDigest, envelopeBytes
	base.EventPayload = eventPayload
	base.Artifacts.AssertionPayload = assertion
	base.Artifacts.EvidenceManifest = manifest
	base.Artifacts.ExtensionSet = commerce.EmptyOutcomeExtensionSetV1()
	return base, evidenceVerifier
}

func retainedOutcomeResult(t *testing.T, request commerce.OperationCarrierRequestV1, carrierKey ed25519.PrivateKey,
	sequence uint64, now time.Time) OutcomeCarrierResult {
	t.Helper()
	var envelope commerce.AgentOperationEnvelopeV1
	var event commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil || codec.Unmarshal(request.EventPayload, &event) != nil {
		t.Fatal("invalid retained outcome fixture")
	}
	evidenceDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", request.Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := commerce.SignOperationSubmissionReceiptV1(commerce.OperationSubmissionReceiptV1{SchemaVersion: 1,
		StableActionID: testDigest, ExactRequestDigest: zeroSHA256Digest(), State: commerce.ActionTerminal,
		SinkID: request.CarrierID, SinkReference: request.OperationEnvelopeDigest, AuthorityTimeUnix: uint64(now.Unix()),
		StateRevision: 1, EvidenceDigest: evidenceDigest}, carrierKey)
	if err != nil {
		t.Fatal(err)
	}
	return OutcomeCarrierResult{Request: request, EventBody: event, ActorAgentID: envelope.Body.ActorAgentID,
		StoredAtUnix: uint64(now.Unix()), CarrierSequence: sequence, Provenance: "carrier-retained-unverified-assertion",
		Receipt: receipt, CarrierPublicKey: "ed25519:" + hex.EncodeToString(carrierKey.Public().(ed25519.PublicKey))}
}
