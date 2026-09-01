package earning

import (
	"encoding/json"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestQualifiedCostEvidenceAcceptsWindowGenesisAndMarksMissingExpectedUnknown(t *testing.T) {
	asset := digestTestValue(t, "asset-a")
	observed := testCostEvidenceDimension(asset, "model", "usage_measured", "debit")
	missing := testCostEvidenceDimension(asset, "api", "usage_measured", "debit")
	genesis := qualifiedCostAssertion(t, "issuer:a", "cost:first-in-window", observed, "5", true)
	unqualified := qualifiedCostAssertion(t, "issuer:b", "cost:unqualified", observed, "100", false)
	unbound := qualifiedCostAssertion(t, "issuer:c", "cost:unbound", observed, "100", true)
	unbound.Authority.VerifiedEvidenceDigests = []string{zeroSHA256Digest()}
	payloadUnbound := qualifiedCostAssertion(t, "issuer:d", "cost:payload-unbound", observed, "100", true)
	payloadUnbound.payloadEvidenceBound = false
	summary, err := SummarizeQualifiedCostEvidence([]VerifiedOutcomeAssertion{genesis, unqualified, unbound, payloadUnbound},
		[]CostEvidenceDimension{observed, missing})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Observed) != 1 || summary.Observed[0].AmountAtomic != "5" || summary.Observed[0].CostItemCount != 1 {
		t.Fatalf("qualified window genesis was lost or unqualified evidence was counted: %+v", summary)
	}
	if len(summary.Unknown) != 1 || summary.Unknown[0].CostEvidenceDimension != missing ||
		summary.Unknown[0].Status != "unknown" || summary.Unknown[0].AmountAtomic != "" {
		t.Fatalf("missing expected cost was converted to zero: %+v", summary.Unknown)
	}
	raw, err := json.Marshal(summary.Unknown[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "amount_atomic") {
		t.Fatalf("unknown cost serialized a numeric amount: %s", raw)
	}
}

func TestQualifiedCostEvidenceKeepsContraSeparate(t *testing.T) {
	asset := digestTestValue(t, "asset-a")
	gross := testCostEvidenceDimension(asset, "model", "usage_measured", "debit")
	contra := testCostEvidenceDimension(asset, "model", "contra", "credit")
	grossAssertion := qualifiedCostAssertion(t, "issuer:a", "cost:gross", gross, "9", true)
	contraAssertion := qualifiedCostAssertion(t, "issuer:a", "cost:contra", contra, "4", true)
	bindContraCostAssertion(t, &contraAssertion, grossAssertion)
	summary, err := SummarizeQualifiedCostEvidence([]VerifiedOutcomeAssertion{
		grossAssertion, contraAssertion,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Observed) != 1 || summary.Observed[0].AmountAtomic != "9" ||
		len(summary.Contra) != 1 || summary.Contra[0].AmountAtomic != "4" {
		t.Fatalf("contra was netted into observed cost: %+v", summary)
	}
}

func TestQualifiedCostEvidenceQuarantinesUnresolvedOrCrossPerimeterContra(t *testing.T) {
	asset := digestTestValue(t, "asset-a")
	grossDimension := testCostEvidenceDimension(asset, "model", "usage_measured", "debit")
	contraDimension := testCostEvidenceDimension(asset, "model", "contra", "credit")
	gross := qualifiedCostAssertion(t, "issuer:a", "cost:gross", grossDimension, "9", true)
	missing := qualifiedCostAssertion(t, "issuer:a", "cost:missing-original", contraDimension, "4", true)
	crossPerimeter := qualifiedCostAssertion(t, "issuer:a", "cost:cross-perimeter", contraDimension, "3", true)
	bindContraCostAssertion(t, &crossPerimeter, gross)
	var payload commerce.CostObservationPayloadV1
	if codec.Unmarshal(crossPerimeter.AssertionPayload, &payload) != nil {
		t.Fatal("decode cross-perimeter contra")
	}
	payload.AccountingPolicyDigest = digestTestValue(t, "other-accounting-policy")
	crossPerimeter.AssertionPayload, _ = codec.Marshal(payload)

	summary, err := SummarizeQualifiedCostEvidence([]VerifiedOutcomeAssertion{gross, missing, crossPerimeter}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Contra) != 0 || len(summary.UnresolvedContra) != 2 {
		t.Fatalf("unresolved contra was presented as verified: %+v", summary)
	}
	for _, bucket := range summary.UnresolvedContra {
		if bucket.Status != "unresolved_lineage" || bucket.AmountAtomic != "" {
			t.Fatalf("unresolved contra exposed an observed amount: %+v", bucket)
		}
	}
}

func TestQualifiedCostEvidenceKeepsSubjectsAndPoliciesSeparate(t *testing.T) {
	asset := digestTestValue(t, "asset-a")
	firstDimension := testCostEvidenceDimension(asset, "api", "payable_invoiced", "debit")
	secondDimension := firstDimension
	secondDimension.SubjectID = "execution:two"
	secondDimension.AccountingPolicyDigest = digestTestValue(t, "policy:two")
	first := qualifiedCostAssertion(t, "issuer:a", "cost:first", firstDimension, "5", true)
	second := qualifiedCostAssertion(t, "issuer:a", "cost:second", secondDimension, "7", true)
	summary, err := SummarizeQualifiedCostEvidence([]VerifiedOutcomeAssertion{second, first}, []CostEvidenceDimension{firstDimension, secondDimension})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Observed) != 2 || len(summary.Unknown) != 0 ||
		summary.Observed[0].SubjectID == summary.Observed[1].SubjectID {
		t.Fatalf("different subjects or accounting policies were merged: %+v", summary)
	}
}

func TestQualifiedCostEvidenceNeverSumsAcrossAssets(t *testing.T) {
	assetA := digestTestValue(t, "asset-a")
	assetB := digestTestValue(t, "asset-b")
	dimensionA := testCostEvidenceDimension(assetA, "tool", "cash_finalized", "debit")
	dimensionB := testCostEvidenceDimension(assetB, "tool", "cash_finalized", "debit")
	summary, err := SummarizeQualifiedCostEvidence([]VerifiedOutcomeAssertion{
		qualifiedCostAssertion(t, "issuer:a", "cost:a", dimensionA, "5", true),
		qualifiedCostAssertion(t, "issuer:a", "cost:b", dimensionB, "7", true),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Observed) != 2 || summary.Observed[0].AssetIdentityDigest == summary.Observed[1].AssetIdentityDigest {
		t.Fatalf("cross-asset costs were collapsed: %+v", summary.Observed)
	}
	amounts := map[string]string{}
	for _, bucket := range summary.Observed {
		amounts[bucket.AssetIdentityDigest] = bucket.AmountAtomic
	}
	if amounts[assetA] != "5" || amounts[assetB] != "7" {
		t.Fatalf("cross-asset evidence was summed: %+v", amounts)
	}
}

func TestQualifiedCostEvidenceQuarantinesConflictingCostItem(t *testing.T) {
	asset := digestTestValue(t, "asset-a")
	dimension := testCostEvidenceDimension(asset, "api", "payable_invoiced", "debit")
	left := qualifiedCostAssertion(t, "issuer:a", "cost:shared", dimension, "5", true)
	right := qualifiedCostAssertion(t, "issuer:b", "cost:shared", dimension, "6", true)
	summary, err := SummarizeQualifiedCostEvidence([]VerifiedOutcomeAssertion{left, right}, []CostEvidenceDimension{dimension})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Observed) != 0 || len(summary.Conflicts) != 1 || len(summary.Unknown) != 1 {
		t.Fatalf("conflicting cost item affected an observed amount: %+v", summary)
	}
}

func TestCostEvidenceCompatibilityRejectsLegacyLineageLoopholes(t *testing.T) {
	asset := digestTestValue(t, "asset-a")
	nonContra := testCostEvidenceDimension(asset, "model", "usage_measured", "debit")
	assertion := qualifiedCostAssertion(t, "issuer:a", "cost:legacy-non-contra-ref", nonContra, "5", true)
	var payload commerce.CostObservationPayloadV1
	if codec.Unmarshal(assertion.AssertionPayload, &payload) != nil {
		t.Fatal("cost fixture is not canonical")
	}
	payload.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: "tos:test", ActorAgentID: "issuer:origin",
		OperationID: testDigest, OperationEnvelopeDigest: zeroSHA256Digest()}
	if validateCostObservationForCurrentDependency(payload) == nil {
		t.Fatal("legacy validator allowed a non-contra cost to claim an original assertion")
	}

	contra := testCostEvidenceDimension(asset, "model", "contra", "credit")
	assertion = qualifiedCostAssertion(t, "issuer:a", "cost:legacy-contra-ref", contra, "5", true)
	if codec.Unmarshal(assertion.AssertionPayload, &payload) != nil {
		t.Fatal("contra fixture is not canonical")
	}
	payload.OriginalCostAssertionRef.OperationID = "opaque-operation-id"
	if validateCostObservationForCurrentDependency(payload) == nil {
		t.Fatal("legacy validator allowed a contra cost with a non-digest original operation")
	}
}

func qualifiedCostAssertion(t *testing.T, actor, itemID string, dimension CostEvidenceDimension,
	amount string, qualified bool) VerifiedOutcomeAssertion {
	t.Helper()
	evidenceDigest := digestTestValue(t, "evidence:"+itemID+":"+amount)
	payload := commerce.CostObservationPayloadV1{SubjectKind: dimension.SubjectKind, SubjectID: dimension.SubjectID, CostItemID: itemID,
		CostClass: dimension.CostClass, Category: dimension.Category, AssetIdentityDigest: dimension.AssetIdentityDigest,
		AmountAtomic: amount, EconomicDirection: dimension.EconomicDirection, QuantityDigest: digestTestValue(t, "quantity:"+itemID),
		MeterIntervalDigest: digestTestValue(t, "interval:"+itemID), MeterUnit: "tokens",
		InvoiceIdentityDigest: zeroSHA256Digest(), PaymentRequestDigest: zeroSHA256Digest(),
		MeterOrInvoiceEvidenceDigest: evidenceDigest, AccountingPolicyDigest: dimension.AccountingPolicyDigest, IncurredAtUnix: 1_900_000_000}
	if dimension.CostClass == "contra" {
		payload.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: "tos:test", ActorAgentID: "issuer:origin",
			OperationID:             digestTestValue(t, "original-operation:"+itemID),
			OperationEnvelopeDigest: digestTestValue(t, "original-envelope:"+itemID)}
	}
	raw, err := codec.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	operationID := digestTestValue(t, actor+itemID+amount)
	return VerifiedOutcomeAssertion{Key: OutcomeAssertionKey{NetworkID: "tos:test", ActorAgentID: actor,
		OperationID: operationID, OperationEnvelopeDigest: digestTestValue(t, "envelope:"+operationID)},
		Body: commerce.OperationOutcomeEventBodyV1{AssertionProfileURI: commerce.OutcomeProfileCost}, AssertionPayload: raw,
		Manifest: commerce.OutcomeEvidenceManifestV1{EvidenceItems: []commerce.OutcomeEvidenceItemV1{{EvidenceRole: "cost_source",
			EvidenceProfileURI: dimension.EvidenceProfileURI, ObjectDigest: evidenceDigest,
			IssuerDescriptor: dimension.EvidenceIssuerDescriptor}}},
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: qualified,
			VerifiedEvidenceDigests: []string{evidenceDigest}, AuthorityTimeHighWater: 1}, payloadEvidenceBound: true}
}

func testCostEvidenceDimension(asset, category, class, direction string) CostEvidenceDimension {
	return CostEvidenceDimension{SubjectKind: "execution", SubjectID: "execution:one", AccountingPolicyDigest: testDigest,
		EvidenceProfileURI: "tos.cost-source.test.v1", EvidenceIssuerDescriptor: "qualified-source:cost",
		AssetIdentityDigest: asset, Category: category, CostClass: class, EconomicDirection: direction}
}

func bindContraCostAssertion(t *testing.T, contra *VerifiedOutcomeAssertion, original VerifiedOutcomeAssertion) {
	t.Helper()
	var payload commerce.CostObservationPayloadV1
	if codec.Unmarshal(contra.AssertionPayload, &payload) != nil {
		t.Fatal("contra fixture is not canonical")
	}
	payload.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: original.Key.NetworkID,
		ActorAgentID: original.Key.ActorAgentID, OperationID: original.Key.OperationID,
		OperationEnvelopeDigest: original.Key.OperationEnvelopeDigest}
	var err error
	contra.AssertionPayload, err = codec.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
}
