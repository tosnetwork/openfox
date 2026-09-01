package earning

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// CostEvidenceDimension is the narrowest dimension on which amounts may be
// aggregated. In particular, the asset identity is never dropped.
type CostEvidenceDimension struct {
	SubjectKind              string `json:"subject_kind"`
	SubjectID                string `json:"subject_id"`
	AccountingPolicyDigest   string `json:"accounting_policy_digest"`
	EvidenceProfileURI       string `json:"evidence_profile_uri"`
	EvidenceIssuerDescriptor string `json:"evidence_issuer_descriptor"`
	AssetIdentityDigest      string `json:"asset_identity_digest"`
	Category                 string `json:"category"`
	CostClass                string `json:"cost_class"`
	EconomicDirection        string `json:"economic_direction"`
}

type CostEvidenceBucket struct {
	CostEvidenceDimension
	Status        string                `json:"status"`
	AmountAtomic  string                `json:"amount_atomic,omitempty"`
	CostItemCount uint64                `json:"cost_item_count"`
	AssertionKeys []OutcomeAssertionKey `json:"assertion_keys"`
}

type CostEvidenceConflict struct {
	SubjectKind   string                `json:"subject_kind"`
	SubjectID     string                `json:"subject_id"`
	CostItemID    string                `json:"cost_item_id"`
	Reason        string                `json:"reason"`
	AssertionKeys []OutcomeAssertionKey `json:"assertion_keys"`
}

// ObserveOnlyCostEvidenceSummary contains no cross-asset total and grants no
// admission, accounting, or economic-decision authority. Contra observations
// and missing expected dimensions remain separate from observed gross costs.
type ObserveOnlyCostEvidenceSummary struct {
	Observed         []CostEvidenceBucket   `json:"observed"`
	Contra           []CostEvidenceBucket   `json:"contra"`
	UnresolvedContra []CostEvidenceBucket   `json:"unresolved_contra"`
	Unknown          []CostEvidenceBucket   `json:"unknown"`
	Conflicts        []CostEvidenceConflict `json:"conflicts"`
}

type costEvidenceItem struct {
	payload    commerce.CostObservationPayloadV1
	source     commerce.OutcomeEvidenceItemV1
	raw        []byte
	assertions map[OutcomeAssertionKey]struct{}
	conflict   bool
}

type costEvidenceBucketAccumulator struct {
	dimension  CostEvidenceDimension
	amount     *big.Int
	items      uint64
	assertions map[OutcomeAssertionKey]struct{}
}

// SummarizeQualifiedCostEvidence observes already authority-qualified Cost V1
// assertions. The supplied slice may begin in the middle of a lineage; a valid
// external OriginalCostAssertionRef is not required to be present locally.
func SummarizeQualifiedCostEvidence(assertions []VerifiedOutcomeAssertion,
	expected []CostEvidenceDimension) (ObserveOnlyCostEvidenceSummary, error) {
	summary := ObserveOnlyCostEvidenceSummary{Observed: []CostEvidenceBucket{}, Contra: []CostEvidenceBucket{},
		UnresolvedContra: []CostEvidenceBucket{}, Unknown: []CostEvidenceBucket{}, Conflicts: []CostEvidenceConflict{}}
	expectedSet := make(map[CostEvidenceDimension]struct{}, len(expected))
	for _, dimension := range expected {
		if !validCostEvidenceDimension(dimension) {
			return summary, errors.New("expected cost evidence dimension is invalid")
		}
		expectedSet[dimension] = struct{}{}
	}
	items := make(map[string]*costEvidenceItem)
	itemsByAssertion := make(map[OutcomeAssertionKey]*costEvidenceItem)
	for _, assertion := range assertions {
		if !assertion.Authority.AuthorityQualified || !assertion.payloadEvidenceBound ||
			assertion.Body.AssertionProfileURI != commerce.OutcomeProfileCost {
			continue
		}
		var payload commerce.CostObservationPayloadV1
		if codec.Unmarshal(assertion.AssertionPayload, &payload) != nil ||
			validateCostObservationForCurrentDependency(payload) != nil ||
			!containsEvidenceDigest(assertion.Authority.VerifiedEvidenceDigests, payload.MeterOrInvoiceEvidenceDigest) {
			continue
		}
		source, sourceFound := exactOutcomeEvidenceItem(assertion, "cost_source", payload.MeterOrInvoiceEvidenceDigest)
		if !sourceFound {
			continue
		}
		identity := payload.SubjectKind + "\x00" + payload.SubjectID + "\x00" + payload.CostItemID
		item := items[identity]
		if item == nil {
			item = &costEvidenceItem{payload: payload, raw: append([]byte(nil), assertion.AssertionPayload...),
				source: source, assertions: make(map[OutcomeAssertionKey]struct{})}
			items[identity] = item
		} else if !bytes.Equal(item.raw, assertion.AssertionPayload) || item.source.EvidenceProfileURI != source.EvidenceProfileURI ||
			item.source.IssuerDescriptor != source.IssuerDescriptor || item.source.ObjectDigest != source.ObjectDigest {
			item.conflict = true
		}
		item.assertions[assertion.Key] = struct{}{}
		itemsByAssertion[assertion.Key] = item
	}

	buckets := make(map[CostEvidenceDimension]*costEvidenceBucketAccumulator)
	identities := make([]string, 0, len(items))
	for identity := range items {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	for _, identity := range identities {
		item := items[identity]
		if item.conflict {
			summary.Conflicts = append(summary.Conflicts, CostEvidenceConflict{SubjectKind: item.payload.SubjectKind,
				SubjectID: item.payload.SubjectID, CostItemID: item.payload.CostItemID,
				Reason:        "conflicting_cost_item_identity",
				AssertionKeys: sortedOutcomeAssertionKeys(item.assertions)})
			continue
		}
		dimension := costEvidenceDimensionFor(item.payload, item.source)
		if item.payload.CostClass == "contra" && !validContraCostLineage(item, itemsByAssertion) {
			summary.UnresolvedContra = append(summary.UnresolvedContra, CostEvidenceBucket{
				CostEvidenceDimension: dimension, Status: "unresolved_lineage",
				CostItemCount: 1, AssertionKeys: sortedOutcomeAssertionKeys(item.assertions)})
			continue
		}
		bucket := buckets[dimension]
		if bucket == nil {
			bucket = &costEvidenceBucketAccumulator{dimension: dimension, amount: new(big.Int),
				assertions: make(map[OutcomeAssertionKey]struct{})}
			buckets[dimension] = bucket
		}
		amount, ok := new(big.Int).SetString(item.payload.AmountAtomic, 10)
		if !ok {
			continue
		}
		bucket.amount.Add(bucket.amount, amount)
		bucket.items++
		for key := range item.assertions {
			bucket.assertions[key] = struct{}{}
		}
	}

	dimensions := make([]CostEvidenceDimension, 0, len(buckets))
	for dimension := range buckets {
		dimensions = append(dimensions, dimension)
	}
	sortCostEvidenceDimensions(dimensions)
	for _, dimension := range dimensions {
		bucket := buckets[dimension]
		value := CostEvidenceBucket{CostEvidenceDimension: dimension, Status: "observed", AmountAtomic: bucket.amount.String(),
			CostItemCount: bucket.items, AssertionKeys: sortedOutcomeAssertionKeys(bucket.assertions)}
		if dimension.CostClass == "contra" {
			value.Status = "verified_lineage"
			summary.Contra = append(summary.Contra, value)
		} else {
			summary.Observed = append(summary.Observed, value)
		}
		delete(expectedSet, dimension)
	}
	missing := make([]CostEvidenceDimension, 0, len(expectedSet))
	for dimension := range expectedSet {
		missing = append(missing, dimension)
	}
	sortCostEvidenceDimensions(missing)
	for _, dimension := range missing {
		// AmountAtomic intentionally remains absent: unknown is not zero.
		summary.Unknown = append(summary.Unknown, CostEvidenceBucket{CostEvidenceDimension: dimension,
			Status: "unknown", AssertionKeys: []OutcomeAssertionKey{}})
	}
	return summary, nil
}

func validCostEvidenceDimension(value CostEvidenceDimension) bool {
	if value.SubjectKind == "" || value.SubjectID == "" || !canonicalSHA256(value.AccountingPolicyDigest) ||
		value.EvidenceProfileURI == "" || value.EvidenceIssuerDescriptor == "" || !canonicalSHA256(value.AssetIdentityDigest) ||
		value.Category == "" || value.CostClass == "" || value.EconomicDirection == "" {
		return false
	}
	probe := commerce.CostObservationPayloadV1{SubjectKind: value.SubjectKind, SubjectID: value.SubjectID, CostItemID: "probe",
		CostClass: value.CostClass, Category: value.Category, AssetIdentityDigest: value.AssetIdentityDigest, AmountAtomic: "0",
		EconomicDirection: value.EconomicDirection, QuantityDigest: zeroSHA256Digest(), MeterIntervalDigest: zeroSHA256Digest(),
		MeterUnit: "unit", InvoiceIdentityDigest: zeroSHA256Digest(), PaymentRequestDigest: zeroSHA256Digest(),
		MeterOrInvoiceEvidenceDigest: zeroSHA256Digest(), AccountingPolicyDigest: value.AccountingPolicyDigest, IncurredAtUnix: 1}
	if value.CostClass == "contra" {
		probe.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: "probe", ActorAgentID: "probe",
			OperationID: zeroSHA256Digest(), OperationEnvelopeDigest: zeroSHA256Digest()}
	}
	return validateCostObservationForCurrentDependency(probe) == nil
}

func costEvidenceDimensionFor(payload commerce.CostObservationPayloadV1,
	source commerce.OutcomeEvidenceItemV1) CostEvidenceDimension {
	return CostEvidenceDimension{SubjectKind: payload.SubjectKind, SubjectID: payload.SubjectID,
		AccountingPolicyDigest: payload.AccountingPolicyDigest, EvidenceProfileURI: source.EvidenceProfileURI,
		EvidenceIssuerDescriptor: source.IssuerDescriptor, AssetIdentityDigest: payload.AssetIdentityDigest,
		Category: payload.Category, CostClass: payload.CostClass, EconomicDirection: payload.EconomicDirection}
}

func validContraCostLineage(contra *costEvidenceItem, assertions map[OutcomeAssertionKey]*costEvidenceItem) bool {
	if contra == nil || contra.payload.CostClass != "contra" {
		return false
	}
	ref := contra.payload.OriginalCostAssertionRef
	original := assertions[OutcomeAssertionKey{NetworkID: ref.NetworkID, ActorAgentID: ref.ActorAgentID,
		OperationID: ref.OperationID, OperationEnvelopeDigest: ref.OperationEnvelopeDigest}]
	if original == nil || original == contra || original.conflict || original.payload.CostClass == "contra" {
		return false
	}
	return original.payload.SubjectKind == contra.payload.SubjectKind && original.payload.SubjectID == contra.payload.SubjectID &&
		original.payload.AssetIdentityDigest == contra.payload.AssetIdentityDigest &&
		original.payload.AccountingPolicyDigest == contra.payload.AccountingPolicyDigest &&
		original.payload.Category == contra.payload.Category
}

// validateCostObservationForCurrentDependency bridges the released validator
// that required OriginalCostAssertionRef on every class and the newer V1 rule
// that permits an empty ref for genesis/non-contra observations. The retry only
// supplies the old validator's missing ref; all other fields and enums remain
// checked by that validator. Partial refs and contra observations never use the
// compatibility path.
func validateCostObservationForCurrentDependency(value commerce.CostObservationPayloadV1) error {
	ref := value.OriginalCostAssertionRef
	emptyRef := ref.NetworkID == "" && ref.ActorAgentID == "" && ref.OperationID == "" && ref.OperationEnvelopeDigest == ""
	if value.CostClass == "contra" {
		if emptyRef || !canonicalSHA256(ref.OperationID) || !canonicalSHA256(ref.OperationEnvelopeDigest) {
			return errors.New("contra cost lacks its exact original assertion")
		}
		return commerce.ValidateCostObservationPayloadV1(value)
	}
	if !emptyRef {
		return errors.New("non-contra cost claims an original assertion")
	}
	if err := commerce.ValidateCostObservationPayloadV1(value); err == nil {
		return nil
	} else {
		compatible := value
		compatible.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: "compatibility:genesis",
			ActorAgentID: "compatibility:genesis", OperationID: zeroSHA256Digest(), OperationEnvelopeDigest: zeroSHA256Digest()}
		if compatibilityErr := commerce.ValidateCostObservationPayloadV1(compatible); compatibilityErr != nil {
			return err
		}
		return nil
	}
}

// verifyOperationOutcomeArtifactsForCurrentDependency preserves the exact
// signed payload commitment while OpenFox is pinned to the previous released
// protocol module, whose Cost validator required a non-empty original ref on
// genesis observations. Only that obsolete structural requirement is adapted;
// the released verifier still checks every manifest, extension, role, enum and
// proof-reference rule against an equivalent compatibility payload.
func verifyOperationOutcomeArtifactsForCurrentDependency(body commerce.OperationOutcomeEventBodyV1,
	assertionPayload []byte, manifest commerce.OutcomeEvidenceManifestV1,
	extensions commerce.OutcomeExtensionSetV1) error {
	if body.AssertionProfileURI != commerce.OutcomeProfileCost {
		return commerce.VerifyOperationOutcomeArtifactsV1(body, assertionPayload, manifest, extensions)
	}
	var value commerce.CostObservationPayloadV1
	if codec.Unmarshal(assertionPayload, &value) != nil {
		return errors.New("cost observation payload is invalid")
	}
	if err := validateCostObservationForCurrentDependency(value); err != nil {
		return err
	}
	if err := commerce.VerifyOperationOutcomeArtifactsV1(body, assertionPayload, manifest, extensions); err == nil {
		return nil
	}
	originalDigest, err := commerce.OutcomeAssertionPayloadDigestV1(body.AssertionProfileURI, assertionPayload)
	if err != nil || originalDigest != body.AssertionPayloadDigest || uint64(len(assertionPayload)) != body.AssertionPayloadSize ||
		value.CostClass == "contra" {
		return errors.New("cost observation payload binding is invalid")
	}
	value.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: "compatibility:genesis",
		ActorAgentID: "compatibility:genesis", OperationID: zeroSHA256Digest(), OperationEnvelopeDigest: zeroSHA256Digest()}
	compatiblePayload, err := codec.Marshal(value)
	if err != nil {
		return err
	}
	compatibleBody := body
	compatibleBody.AssertionPayloadDigest, err = commerce.OutcomeAssertionPayloadDigestV1(body.AssertionProfileURI, compatiblePayload)
	if err != nil {
		return err
	}
	compatibleBody.AssertionPayloadSize = uint64(len(compatiblePayload))
	return commerce.VerifyOperationOutcomeArtifactsV1(compatibleBody, compatiblePayload, manifest, extensions)
}

func sortedOutcomeAssertionKeys(values map[OutcomeAssertionKey]struct{}) []OutcomeAssertionKey {
	keys := make([]OutcomeAssertionKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].NetworkID != keys[j].NetworkID {
			return keys[i].NetworkID < keys[j].NetworkID
		}
		if keys[i].ActorAgentID != keys[j].ActorAgentID {
			return keys[i].ActorAgentID < keys[j].ActorAgentID
		}
		if keys[i].OperationID != keys[j].OperationID {
			return keys[i].OperationID < keys[j].OperationID
		}
		return keys[i].OperationEnvelopeDigest < keys[j].OperationEnvelopeDigest
	})
	return keys
}

func sortCostEvidenceDimensions(values []CostEvidenceDimension) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].SubjectKind != values[j].SubjectKind {
			return values[i].SubjectKind < values[j].SubjectKind
		}
		if values[i].SubjectID != values[j].SubjectID {
			return values[i].SubjectID < values[j].SubjectID
		}
		if values[i].AccountingPolicyDigest != values[j].AccountingPolicyDigest {
			return values[i].AccountingPolicyDigest < values[j].AccountingPolicyDigest
		}
		if values[i].EvidenceProfileURI != values[j].EvidenceProfileURI {
			return values[i].EvidenceProfileURI < values[j].EvidenceProfileURI
		}
		if values[i].EvidenceIssuerDescriptor != values[j].EvidenceIssuerDescriptor {
			return values[i].EvidenceIssuerDescriptor < values[j].EvidenceIssuerDescriptor
		}
		if values[i].AssetIdentityDigest != values[j].AssetIdentityDigest {
			return values[i].AssetIdentityDigest < values[j].AssetIdentityDigest
		}
		if values[i].Category != values[j].Category {
			return values[i].Category < values[j].Category
		}
		if values[i].CostClass != values[j].CostClass {
			return values[i].CostClass < values[j].CostClass
		}
		return values[i].EconomicDirection < values[j].EconomicDirection
	})
}
