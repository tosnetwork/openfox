package earning

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	CapabilityMarketCampaignResultProfileV1 = "tos.openfox.capability-market.campaign-result.v1"
	capabilityMarketResultEvidenceRole      = "authoritative_resolution"
)

// CapabilityMarketCampaignResultBindingV1 is the Agreement-derived context
// used to interpret one retained campaign result. The mapping is local input;
// neither a campaign file nor this helper can create Agreement authority.
type CapabilityMarketCampaignResultBindingV1 struct {
	Sequence              uint64 `json:"sequence"`
	BuyerResultID         string `json:"buyer_result_id"`
	ProviderResultID      string `json:"provider_result_id"`
	ResultCapabilityID    string `json:"result_capability_id"`
	ResultDisposition     string `json:"result_disposition"`
	AgreementBodyDigest   string `json:"agreement_body_digest"`
	AgreementObligationID string `json:"agreement_obligation_id"`
	ExecutionID           string `json:"execution_id"`
	DeliverySubjectID     string `json:"delivery_subject_id"`
	TerminalScope         string `json:"terminal_scope"`
	SubjectProfileURI     string `json:"subject_profile_uri"`
	OwningStateProfileURI string `json:"owning_state_profile_uri"`
	SuccessorPolicyDigest string `json:"successor_policy_digest"`
	TerminalStateRevision uint64 `json:"terminal_state_revision"`
	TerminalDisposition   string `json:"terminal_disposition"`
	FailureStage          string `json:"failure_stage"`
	FailureCode           string `json:"failure_code"`
	RetryDisposition      string `json:"retry_disposition"`
}

// CapabilityMarketCampaignResultSource retains the exact campaign-result
// bytes. The object digest is over those bytes, so a rewritten result is a new
// source object even when its display fields look similar.
type CapabilityMarketCampaignResultSource struct {
	Object  []byte                                  `json:"object"`
	Binding CapabilityMarketCampaignResultBindingV1 `json:"binding"`
}

// CapabilityMarketOutcomeSigningContext supplies an existing operation key
// and ordering context. It does not mint or broaden that key's authority.
type CapabilityMarketOutcomeSigningContext struct {
	NetworkID          string
	ActorAgentID       string
	AuthorizationRef   commerce.ProfileRefV1
	AudienceDescriptor string
	OrderingDomain     string
	Sequence           uint64
	Epoch              uint64
	PredecessorDigests []string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	OperationKey       ed25519.PrivateKey
	HistoricalProof    []byte
}

// CapabilityMarketOutcomeEvidenceAuthority contains already issued historical
// authority material and privacy/retention metadata for the selected result
// source. BuildCapabilityMarketTerminalOutcome only binds it; verification is
// still performed by OutcomeEvidenceAuthorityVerifierV1.
type CapabilityMarketOutcomeEvidenceAuthority struct {
	EvidenceProfileURI string
	IssuerDescriptor   string
	Visibility         string
	AudienceDigest     string
	RetentionDigest    string
	RetrievalDigest    string
	AuthorityProofs    []commerce.OutcomeAuthorityProofMaterialV1
}

type CapabilityMarketTerminalOutcome struct {
	Source       CapabilityMarketCampaignResultSource
	SourceDigest string
	EventBody    commerce.OperationOutcomeEventBodyV1
	EventPayload []byte
	Envelope     commerce.AgentOperationEnvelopeV1
	Artifacts    commerce.OperationOutcomeArtifactBundleV1
}

type capabilityMarketCampaignResultJSON struct {
	Sequence          uint64 `json:"sequence"`
	Disposition       string `json:"disposition"`
	Buyer             string `json:"buyer"`
	Seller            string `json:"seller"`
	Capability        string `json:"capability"`
	AgreementDigest   string `json:"agreement_digest"`
	ExecutionID       string `json:"execution_id"`
	DeliverableDigest string `json:"deliverable_digest"`
	CompletedAt       string `json:"completed_at"`
}

// CapabilityMarketCampaignResultDigest returns the exact evidence-object
// identity used by the terminal payload and its manifest.
func CapabilityMarketCampaignResultDigest(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > commerce.MaxOutcomeEvidenceObjectBytes || !json.Valid(raw) {
		return "", errors.New("capability-market campaign result is invalid or oversized")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return "", errors.New("capability-market campaign result contains ambiguous JSON")
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// CapabilityMarketCampaignResultSubjectDescriptor is the exact qualification
// scope that an evidence issuer must be authorized to assert.
func CapabilityMarketCampaignResultSubjectDescriptor(source CapabilityMarketCampaignResultSource) (string, error) {
	result, terminal, _, err := bindCapabilityMarketCampaignResult(source)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("capability-market-result:%s:%s:%d:%s", terminal.TerminalScope,
		terminal.TerminalSubjectID, result.Sequence, source.Binding.AgreementBodyDigest), nil
}

// BuildCapabilityMarketTerminalOutcome creates an ordinary signed Outcome V1
// operation. Authority proofs remain caller-supplied historical material and
// are independently checked when the result is ingested.
func BuildCapabilityMarketTerminalOutcome(source CapabilityMarketCampaignResultSource,
	signing CapabilityMarketOutcomeSigningContext, authority CapabilityMarketOutcomeEvidenceAuthority) (CapabilityMarketTerminalOutcome, error) {
	result, terminal, sourceDigest, err := bindCapabilityMarketCampaignResult(source)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	if len(signing.OperationKey) != ed25519.PrivateKeySize || len(signing.HistoricalProof) == 0 || signing.CreatedAt.IsZero() ||
		signing.NetworkID == "" || signing.ActorAgentID == "" || signing.AudienceDescriptor == "" ||
		signing.OrderingDomain == "" || commerce.ValidateProfileRefV1(signing.AuthorizationRef) != nil {
		return CapabilityMarketTerminalOutcome{}, errors.New("capability-market outcome signing context is incomplete")
	}
	if authority.EvidenceProfileURI == "" || authority.IssuerDescriptor == "" || len(authority.AuthorityProofs) == 0 {
		return CapabilityMarketTerminalOutcome{}, errors.New("capability-market outcome evidence authority is incomplete")
	}
	subjectDescriptor, err := CapabilityMarketCampaignResultSubjectDescriptor(source)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	materials := append([]commerce.OutcomeAuthorityProofMaterialV1(nil), authority.AuthorityProofs...)
	if err := commerce.SortOutcomeAuthorityProofMaterialsV1(materials); err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	proofRefs, timeDigest, qualificationDigest, err := capabilityMarketAuthorityProofRefs(materials)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	item := commerce.OutcomeEvidenceItemV1{EvidenceRole: capabilityMarketResultEvidenceRole,
		EvidenceProfileURI: authority.EvidenceProfileURI, SourceObjectProfileURI: CapabilityMarketCampaignResultProfileV1,
		SourceObjectDigest: sourceDigest, ObjectDigest: sourceDigest, CanonicalSize: uint64(len(source.Object)),
		MediaType: "application/json", IssuerDescriptor: authority.IssuerDescriptor, SubjectDescriptor: subjectDescriptor,
		ClaimedObservationTimeUnix: terminal.ResolvedAtUnix, AuthorityTimeProofDigest: timeDigest,
		IssuerQualificationProofDigest: qualificationDigest, Visibility: authority.Visibility,
		AudienceDigest: authority.AudienceDigest, RetentionPolicyDigest: authority.RetentionDigest,
		RetrievalPolicyDigest: authority.RetrievalDigest}
	manifest := commerce.OutcomeEvidenceManifestV1{SchemaVersion: 1, ManifestPurpose: "qualified_campaign_result",
		AuthorityProofRefs: proofRefs, EvidenceItems: []commerce.OutcomeEvidenceItemV1{item}}
	if err := commerce.SortOutcomeEvidenceItemsV1(manifest.EvidenceItems); err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	assertionPayload, err := codec.Marshal(terminal)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeTerminalObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: source.Binding.SubjectProfileURI, SubjectID: terminal.TerminalSubjectID}, nil,
		commerce.OutcomeProfileTerminal, assertionPayload, manifest, commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	predecessors := append([]string(nil), signing.PredecessorDigests...)
	sort.Strings(predecessors)
	body := commerce.AgentOperationBodyV1{SchemaVersion: commerce.AgentOperationSchemaV1, NetworkID: signing.NetworkID,
		OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1, ActorAgentID: signing.ActorAgentID,
		AuthorizationRef: signing.AuthorizationRef, AudienceDescriptor: signing.AudienceDescriptor, ObjectID: contentID,
		OrderingDomain: signing.OrderingDomain, Sequence: signing.Sequence, Epoch: signing.Epoch,
		PredecessorDigests: predecessors, CreatedAtUnix: uint64(signing.CreatedAt.UTC().Unix()),
		PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	if !signing.ExpiresAt.IsZero() {
		body.ExpiresAtUnix = uint64(signing.ExpiresAt.UTC().Unix())
	}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	envelope, err := commerce.SignAgentOperationV1(body, signing.ActorAgentID, signing.OperationKey, signing.HistoricalProof)
	if err != nil {
		return CapabilityMarketTerminalOutcome{}, err
	}
	_ = result // result was fully bound above; retain only its immutable source.
	return CapabilityMarketTerminalOutcome{Source: cloneCapabilityMarketSource(source), SourceDigest: sourceDigest,
		EventBody: event, EventPayload: eventPayload, Envelope: envelope,
		Artifacts: commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertionPayload, EvidenceManifest: manifest,
			ExtensionSet: commerce.EmptyOutcomeExtensionSetV1(), AuthorityProofs: materials}}, nil
}

// CapabilityMarketCampaignResultPayloadBinder proves that the exact retained
// result object implies every authority-relevant terminal payload field.
type CapabilityMarketCampaignResultPayloadBinder struct {
	sources map[string][]CapabilityMarketCampaignResultSource
}

func NewCapabilityMarketCampaignResultPayloadBinder(sources []CapabilityMarketCampaignResultSource) (*CapabilityMarketCampaignResultPayloadBinder, error) {
	binder := &CapabilityMarketCampaignResultPayloadBinder{sources: make(map[string][]CapabilityMarketCampaignResultSource, len(sources))}
	for _, source := range sources {
		_, _, digest, err := bindCapabilityMarketCampaignResult(source)
		if err != nil {
			return nil, err
		}
		duplicate := false
		for _, prior := range binder.sources[digest] {
			if reflect.DeepEqual(prior, source) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			// One exact result may legitimately close both its execution and its
			// delivery. Selection remains payload-and-subject exact below.
			binder.sources[digest] = append(binder.sources[digest], cloneCapabilityMarketSource(source))
		}
	}
	if len(binder.sources) == 0 {
		return nil, errors.New("capability-market result binder has no source objects")
	}
	return binder, nil
}

func (binder *CapabilityMarketCampaignResultPayloadBinder) VerifyOutcomePayloadEvidenceBinding(body commerce.OperationOutcomeEventBodyV1,
	assertionPayload []byte, manifest commerce.OutcomeEvidenceManifestV1, assessment commerce.OutcomeAuthorityAssessmentV1, _ time.Time) error {
	if binder == nil || body.AssertionProfileURI != commerce.OutcomeProfileTerminal ||
		body.EventKind != commerce.OutcomeTerminalObservation || len(manifest.EvidenceItems) != 1 {
		return errors.New("capability-market terminal source binding is incomplete")
	}
	item := manifest.EvidenceItems[0]
	sources, found := binder.sources[item.ObjectDigest]
	if !found || item.EvidenceRole != capabilityMarketResultEvidenceRole ||
		item.SourceObjectProfileURI != CapabilityMarketCampaignResultProfileV1 || item.SourceObjectDigest != item.ObjectDigest ||
		item.MediaType != "application/json" ||
		!containsEvidenceDigest(assessment.VerifiedEvidenceDigests, item.ObjectDigest) {
		return errors.New("capability-market terminal source object is not exactly qualified")
	}
	var actual commerce.TerminalDispositionV1
	if codec.Unmarshal(assertionPayload, &actual) != nil {
		return errors.New("capability-market result does not bind the exact terminal payload")
	}
	matches := 0
	for _, source := range sources {
		_, expected, digest, err := bindCapabilityMarketCampaignResult(source)
		if err != nil || digest != item.ObjectDigest || item.CanonicalSize != uint64(len(source.Object)) {
			continue
		}
		descriptor, err := CapabilityMarketCampaignResultSubjectDescriptor(source)
		if err == nil && descriptor == item.SubjectDescriptor &&
			body.PrimarySubjectRef.SubjectProfileURI == source.Binding.SubjectProfileURI &&
			body.PrimarySubjectRef.SubjectID == expected.TerminalSubjectID && actual == expected &&
			actual.AuthoritativeResolutionDigest == item.ObjectDigest {
			matches++
		}
	}
	if matches != 1 {
		return errors.New("capability-market result does not uniquely bind the exact terminal payload")
	}
	return nil
}

// VerifyAndIngestCapabilityMarketTerminalOutcome performs the production
// operation, artifact, historical evidence-authority, and payload-source passes
// before setting payloadEvidenceBound. Replaying identical input is idempotent
// in OutcomeProjection; distinct qualified terminal claims remain distinct and
// are reduced to indeterminate by the existing Owner-local risk projections.
func VerifyAndIngestCapabilityMarketTerminalOutcome(projection *OutcomeProjection, outcome CapabilityMarketTerminalOutcome,
	operationResolver commerce.AgentOperationAuthorityResolver, evidenceVerifier commerce.OutcomeEvidenceAuthorityVerifierV1,
	now time.Time) (VerifiedOutcomeAssertion, error) {
	if projection == nil || operationResolver == nil || evidenceVerifier == nil || now.IsZero() {
		return VerifiedOutcomeAssertion{}, errors.New("capability-market outcome verifier is incomplete")
	}
	binder, err := NewCapabilityMarketCampaignResultPayloadBinder([]CapabilityMarketCampaignResultSource{outcome.Source})
	if err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	body, err := commerce.VerifyOperationOutcomeEnvelopeV1(outcome.Envelope, outcome.EventPayload, operationResolver, now.UTC())
	if err != nil || !reflect.DeepEqual(body, outcome.EventBody) {
		return VerifiedOutcomeAssertion{}, errors.New("capability-market operation envelope is invalid")
	}
	if err := verifyOperationOutcomeArtifactBundleForCurrentDependency(body, outcome.Artifacts); err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	assessment, err := commerce.VerifyOperationOutcomeAuthorityV1(body, outcome.Artifacts.EvidenceManifest,
		outcome.Artifacts.AuthorityProofs, evidenceVerifier, now.UTC())
	if err != nil || !assessment.AuthorityQualified {
		return VerifiedOutcomeAssertion{}, errors.New("capability-market terminal evidence is not authority-qualified")
	}
	if err := binder.VerifyOutcomePayloadEvidenceBinding(body, outcome.Artifacts.AssertionPayload,
		outcome.Artifacts.EvidenceManifest, assessment, now.UTC()); err != nil {
		return VerifiedOutcomeAssertion{}, err
	}
	return projection.ingestAuthorityQualified(outcome.Envelope, outcome.EventPayload, outcome.Artifacts.AssertionPayload,
		outcome.Artifacts.EvidenceManifest, outcome.Artifacts.ExtensionSet, operationResolver,
		outcome.Artifacts.AuthorityProofs, evidenceVerifier, now.UTC(), true)
}

type CapabilityMarketOwnerRiskContext struct {
	Policy                   LocalOutcomeRiskPolicyRevision
	ProviderAgentID          string
	LocalServiceCapabilityID string
	Delivery                 ProviderDeliverySubjectBinding
	Execution                ServiceCapabilityExecutionBinding
}

// CapabilityMarketOwnerRiskView intentionally contains the two existing local
// descriptive projections and no global score or authority-bearing verdict.
type CapabilityMarketOwnerRiskView struct {
	ProviderDelivery  ProviderDeliveryOutcomeRiskProjection  `json:"provider_delivery"`
	ServiceCapability ServiceCapabilityOutcomeRiskProjection `json:"service_capability"`
}

func ProjectCapabilityMarketOwnerRisk(context CapabilityMarketOwnerRiskContext,
	assertions []VerifiedOutcomeAssertion) (CapabilityMarketOwnerRiskView, error) {
	if context.Delivery.AgreementBodyDigest != context.Execution.AgreementBodyDigest ||
		context.Delivery.AgreementObligationID != context.Execution.AgreementObligationID {
		return CapabilityMarketOwnerRiskView{}, errors.New("capability-market local risk bindings select different Agreement state")
	}
	provider, err := ProjectProviderDeliveryOutcomeRisk(context.Policy, context.ProviderAgentID,
		[]ProviderDeliverySubjectBinding{context.Delivery}, assertions)
	if err != nil {
		return CapabilityMarketOwnerRiskView{}, err
	}
	service, err := ProjectServiceCapabilityOutcomeRisk(context.Policy, context.ProviderAgentID,
		context.LocalServiceCapabilityID, []ServiceCapabilityExecutionBinding{context.Execution}, assertions)
	if err != nil {
		return CapabilityMarketOwnerRiskView{}, err
	}
	return CapabilityMarketOwnerRiskView{ProviderDelivery: provider, ServiceCapability: service}, nil
}

type CapabilityMarketBoundTransactionFee struct {
	NetworkID              string `json:"network_id"`
	PaymentRequestDigest   string `json:"payment_request_digest"`
	StableActionID         string `json:"stable_action_id"`
	TransactionDigest      string `json:"transaction_digest"`
	FinalityReference      string `json:"finality_reference"`
	FeeAssetIdentityDigest string `json:"fee_asset_identity_digest"`
	FeeAmountAtomic        string `json:"fee_amount_atomic"`
	EvidenceProfileURI     string `json:"evidence_profile_uri"`
	EvidenceIssuer         string `json:"evidence_issuer"`
	EvidenceDigest         string `json:"evidence_digest"`
	ObservedAtUnix         uint64 `json:"observed_at_unix"`
}

// CapabilityMarketTransactionFeeEvidenceBinder must parse real payment/chain
// evidence and return the fee of the exact finalized transfer. A reservation,
// configured ceiling, or caller-supplied numeric estimate is not a binder.
type CapabilityMarketTransactionFeeEvidenceBinder interface {
	BindCapabilityMarketTransactionFee(commerce.AgreementPaymentRequest, commerce.AgreementPaymentEvidence,
		time.Time) (CapabilityMarketBoundTransactionFee, error)
}

type CapabilityMarketCostStatus string

const (
	CapabilityMarketCostObserved      CapabilityMarketCostStatus = "observed"
	CapabilityMarketCostUnknown       CapabilityMarketCostStatus = "unknown"
	CapabilityMarketCostIndeterminate CapabilityMarketCostStatus = "indeterminate"
)

type CapabilityMarketCostDimension struct {
	Category            string                             `json:"category"`
	Status              CapabilityMarketCostStatus         `json:"status"`
	AmountAtomic        string                             `json:"amount_atomic,omitempty"`
	AssetIdentityDigest string                             `json:"asset_identity_digest,omitempty"`
	EvidenceProfileURI  string                             `json:"evidence_profile_uri,omitempty"`
	EvidenceIssuer      string                             `json:"evidence_issuer,omitempty"`
	EvidenceDigest      string                             `json:"evidence_digest,omitempty"`
	Observation         *commerce.CostObservationPayloadV1 `json:"observation,omitempty"`
	UnknownReason       string                             `json:"unknown_reason,omitempty"`
}

type CapabilityMarketCostEvidenceView struct {
	SubjectKind string                        `json:"subject_kind"`
	SubjectID   string                        `json:"subject_id"`
	ChainFee    CapabilityMarketCostDimension `json:"chain_fee"`
	Model       CapabilityMarketCostDimension `json:"model"`
	API         CapabilityMarketCostDimension `json:"api"`
}

type CapabilityMarketCostEvidenceRequest struct {
	SubjectKind            string
	SubjectID              string
	AccountingPolicyDigest string
	PaymentRequest         *commerce.AgreementPaymentRequest
	PaymentEvidence        *commerce.AgreementPaymentEvidence
	PaymentVerifier        commerce.PaymentEvidenceVerifier
	FeeBinders             []CapabilityMarketTransactionFeeEvidenceBinder
}

// ObserveCapabilityMarketCosts emits a chain-fee observation only after both
// the production Agreement payment verifier and an exact transaction-fee
// binder succeed. Missing or conflicting evidence has no AmountAtomic. Model
// and API remain explicitly unknown until their own real meter/invoice binders
// are supplied; this helper never derives them from elapsed time or a ceiling.
func ObserveCapabilityMarketCosts(request CapabilityMarketCostEvidenceRequest,
	now time.Time) (CapabilityMarketCostEvidenceView, error) {
	view := CapabilityMarketCostEvidenceView{SubjectKind: request.SubjectKind, SubjectID: request.SubjectID,
		ChainFee: CapabilityMarketCostDimension{Category: "chain_fee", Status: CapabilityMarketCostUnknown,
			UnknownReason: "no_exact_payment_transaction_fee_binding"},
		Model: CapabilityMarketCostDimension{Category: "model", Status: CapabilityMarketCostUnknown,
			UnknownReason: "no_verified_model_meter_or_invoice"},
		API: CapabilityMarketCostDimension{Category: "api", Status: CapabilityMarketCostUnknown,
			UnknownReason: "no_verified_api_meter_or_invoice"}}
	if !validLocalOutcomeIdentifier(request.SubjectKind, 128) || !validLocalOutcomeIdentifier(request.SubjectID, 4096) ||
		!canonicalLocalOutcomeDigest(request.AccountingPolicyDigest) || now.IsZero() {
		return view, errors.New("capability-market cost evidence subject is invalid")
	}
	if request.PaymentRequest == nil || request.PaymentEvidence == nil || request.PaymentVerifier == nil || len(request.FeeBinders) == 0 {
		return view, nil
	}
	if err := commerce.VerifyAgreementPaymentEvidence(*request.PaymentRequest, *request.PaymentEvidence,
		request.PaymentVerifier, now.UTC()); err != nil {
		return view, nil
	}
	requestDigest, err := commerce.AgreementPaymentRequestDigest(*request.PaymentRequest)
	if err != nil {
		return view, nil
	}
	unique := make(map[string]CapabilityMarketBoundTransactionFee)
	for _, binder := range request.FeeBinders {
		if binder == nil {
			continue
		}
		bound, bindErr := binder.BindCapabilityMarketTransactionFee(*request.PaymentRequest, *request.PaymentEvidence, now.UTC())
		if bindErr != nil || validateCapabilityMarketBoundFee(bound, *request.PaymentRequest, *request.PaymentEvidence,
			requestDigest, now.UTC()) != nil {
			continue
		}
		fingerprint, digestErr := codec.Digest("tos.openfox.capability-market.bound-transaction-fee.v1", bound)
		if digestErr == nil {
			unique[fingerprint] = bound
		}
	}
	if len(unique) == 0 {
		return view, nil
	}
	if len(unique) != 1 {
		view.ChainFee.Status = CapabilityMarketCostIndeterminate
		view.ChainFee.UnknownReason = "conflicting_exact_transaction_fee_bindings"
		return view, nil
	}
	var bound CapabilityMarketBoundTransactionFee
	for _, candidate := range unique {
		bound = candidate
	}
	quantityDigest, _ := codec.Digest("tos.openfox.capability-market.chain-fee-quantity.v1", struct {
		TransactionDigest string `json:"transaction_digest"`
		AmountAtomic      string `json:"amount_atomic"`
	}{bound.TransactionDigest, bound.FeeAmountAtomic})
	intervalDigest, _ := codec.Digest("tos.openfox.capability-market.chain-fee-observation.v1", struct {
		EvidenceDigest string `json:"evidence_digest"`
		ObservedAtUnix uint64 `json:"observed_at_unix"`
	}{bound.EvidenceDigest, bound.ObservedAtUnix})
	costItemID, _ := codec.Digest("tos.openfox.capability-market.chain-fee-item.v1", struct {
		PaymentRequestDigest string `json:"payment_request_digest"`
		TransactionDigest    string `json:"transaction_digest"`
	}{bound.PaymentRequestDigest, bound.TransactionDigest})
	observation := commerce.CostObservationPayloadV1{SubjectKind: request.SubjectKind, SubjectID: request.SubjectID,
		CostItemID: costItemID, CostClass: "cash_finalized", Category: "chain_fee",
		AssetIdentityDigest: bound.FeeAssetIdentityDigest, AmountAtomic: bound.FeeAmountAtomic,
		EconomicDirection: "debit", QuantityDigest: quantityDigest, MeterIntervalDigest: intervalDigest,
		MeterUnit: "atomic", InvoiceIdentityDigest: zeroSHA256Digest(), PaymentRequestDigest: bound.PaymentRequestDigest,
		MeterOrInvoiceEvidenceDigest: bound.EvidenceDigest, AccountingPolicyDigest: request.AccountingPolicyDigest,
		IncurredAtUnix: bound.ObservedAtUnix}
	if validateCostObservationForCurrentDependency(observation) != nil {
		return view, nil
	}
	view.ChainFee = CapabilityMarketCostDimension{Category: "chain_fee", Status: CapabilityMarketCostObserved,
		AmountAtomic: bound.FeeAmountAtomic, AssetIdentityDigest: bound.FeeAssetIdentityDigest,
		EvidenceProfileURI: bound.EvidenceProfileURI, EvidenceIssuer: bound.EvidenceIssuer,
		EvidenceDigest: bound.EvidenceDigest, Observation: &observation}
	return view, nil
}

func bindCapabilityMarketCampaignResult(source CapabilityMarketCampaignResultSource) (capabilityMarketCampaignResultJSON,
	commerce.TerminalDispositionV1, string, error) {
	var result capabilityMarketCampaignResultJSON
	if rejectDuplicateJSONKeys(source.Object) != nil {
		return result, commerce.TerminalDispositionV1{}, "", errors.New("capability-market campaign result JSON is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(source.Object))
	if err := decoder.Decode(&result); err != nil || ensureJSONEOF(decoder) != nil {
		return result, commerce.TerminalDispositionV1{}, "", errors.New("capability-market campaign result JSON is invalid")
	}
	binding := source.Binding
	if binding.Sequence != result.Sequence || binding.BuyerResultID != result.Buyer ||
		binding.ProviderResultID != result.Seller || binding.ResultCapabilityID != result.Capability ||
		binding.ResultDisposition != result.Disposition || binding.AgreementBodyDigest != result.AgreementDigest ||
		binding.ExecutionID != result.ExecutionID || binding.DeliverySubjectID != result.DeliverableDigest ||
		!canonicalLocalOutcomeDigest(binding.AgreementBodyDigest) || !validLocalOutcomeIdentifier(binding.AgreementObligationID, 256) ||
		!canonicalLocalOutcomeDigest(binding.ExecutionID) || !canonicalLocalOutcomeDigest(binding.DeliverySubjectID) ||
		!validLocalOutcomeIdentifier(binding.SubjectProfileURI, 1024) || !validLocalOutcomeIdentifier(binding.OwningStateProfileURI, 1024) ||
		!canonicalLocalOutcomeDigest(binding.SuccessorPolicyDigest) || binding.TerminalStateRevision == 0 {
		return result, commerce.TerminalDispositionV1{}, "", errors.New("capability-market campaign result conflicts with its Agreement binding")
	}
	resolvedAt, err := time.Parse(time.RFC3339Nano, result.CompletedAt)
	if err != nil || resolvedAt.Unix() <= 0 {
		return result, commerce.TerminalDispositionV1{}, "", errors.New("capability-market campaign result has no exact completion time")
	}
	subjectID := binding.ExecutionID
	if binding.TerminalScope == "delivery" {
		subjectID = binding.DeliverySubjectID
	} else if binding.TerminalScope != "execution" {
		return result, commerce.TerminalDispositionV1{}, "", errors.New("capability-market campaign result terminal scope is unsupported")
	}
	digest, err := CapabilityMarketCampaignResultDigest(source.Object)
	if err != nil {
		return result, commerce.TerminalDispositionV1{}, "", err
	}
	terminal := commerce.TerminalDispositionV1{TerminalScope: binding.TerminalScope, TerminalSubjectID: subjectID,
		OwningStateProfileURI: binding.OwningStateProfileURI, AuthoritativeResolutionDigest: digest,
		TerminalStateRevision: binding.TerminalStateRevision, SuccessorPolicyDigest: binding.SuccessorPolicyDigest,
		Disposition: binding.TerminalDisposition, FailureStage: binding.FailureStage, FailureCode: binding.FailureCode,
		RetryDisposition: binding.RetryDisposition, ResolvedAtUnix: uint64(resolvedAt.UTC().Unix())}
	if err := commerce.ValidateTerminalDispositionV1(terminal); err != nil {
		return result, commerce.TerminalDispositionV1{}, "", err
	}
	return result, terminal, digest, nil
}

func capabilityMarketAuthorityProofRefs(materials []commerce.OutcomeAuthorityProofMaterialV1) (
	[]commerce.OutcomeAuthorityProofRefV1, string, string, error) {
	refs := make([]commerce.OutcomeAuthorityProofRefV1, 0, len(materials))
	timeDigest, qualificationDigest := "", ""
	for _, material := range materials {
		digest, err := commerce.OutcomeAuthorityProofObjectDigestV1(material)
		if err != nil {
			return nil, "", "", err
		}
		refs = append(refs, commerce.OutcomeAuthorityProofRefV1{ProofProfileURI: material.ProofProfileURI,
			ObjectDigest: digest, CanonicalSize: uint64(len(material.CanonicalObject))})
		switch material.ProofProfileURI {
		case commerce.OutcomeAuthorityTimeProofProfileV1:
			if timeDigest != "" {
				return nil, "", "", errors.New("capability-market outcome has multiple authority-time proofs")
			}
			timeDigest = digest
		case commerce.OutcomeIssuerQualificationProofProfileV1:
			if qualificationDigest != "" {
				return nil, "", "", errors.New("capability-market outcome has multiple issuer qualifications")
			}
			qualificationDigest = digest
		default:
			return nil, "", "", errors.New("capability-market outcome authority proof profile is unsupported")
		}
	}
	if timeDigest == "" || qualificationDigest == "" || len(refs) != 2 {
		return nil, "", "", errors.New("capability-market outcome requires one time proof and one issuer qualification")
	}
	if err := commerce.SortOutcomeAuthorityProofRefsV1(refs); err != nil {
		return nil, "", "", err
	}
	return refs, timeDigest, qualificationDigest, nil
}

func validateCapabilityMarketBoundFee(bound CapabilityMarketBoundTransactionFee, request commerce.AgreementPaymentRequest,
	evidence commerce.AgreementPaymentEvidence, requestDigest string, now time.Time) error {
	if bound.NetworkID != request.NetworkID || bound.PaymentRequestDigest != requestDigest ||
		bound.StableActionID != request.StableActionID || bound.TransactionDigest != evidence.ExactTransferReference ||
		bound.FinalityReference != evidence.FinalityReference || !canonicalLocalOutcomeDigest(bound.FeeAssetIdentityDigest) ||
		!canonicalUnsignedAtomic(bound.FeeAmountAtomic) || !validLocalOutcomeIdentifier(bound.EvidenceProfileURI, 1024) ||
		!validLocalOutcomeIdentifier(bound.EvidenceIssuer, 4096) || !canonicalLocalOutcomeDigest(bound.EvidenceDigest) ||
		bound.ObservedAtUnix == 0 || bound.ObservedAtUnix > uint64(now.UTC().Unix()) {
		return errors.New("capability-market transaction fee is not bound to the exact finalized payment")
	}
	return nil
}

func canonicalUnsignedAtomic(value string) bool {
	if value == "0" {
		return true
	}
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func cloneCapabilityMarketSource(source CapabilityMarketCampaignResultSource) CapabilityMarketCampaignResultSource {
	clone := source
	clone.Object = append([]byte(nil), source.Object...)
	return clone
}

var _ OutcomePayloadEvidenceBindingVerifier = (*CapabilityMarketCampaignResultPayloadBinder)(nil)
