package earning

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	capabilityMarketEvidenceIndexSchema    = "tos.openfox.capability-market.result-evidence-index.v1"
	capabilityMarketTerminalArtifactSchema = "tos.openfox.capability-market.terminal-outcome-artifact.v1"
	capabilityMarketEvidenceVerifiedState  = "authority_qualified_payload_bound"
	capabilityMarketEvidenceNotApplicable  = "not_applicable:no_agreement_terminal"
	capabilityMarketUnknownDenominator     = "unknown"
)

type campaignCapabilityMarketEvidenceIndex struct {
	Schema                  string `json:"schema"`
	Sequence                int    `json:"sequence"`
	ResultSourceDigest      string `json:"result_source_digest"`
	TerminalEvidenceState   string `json:"terminal_evidence_state"`
	ExecutionEventContentID string `json:"execution_event_content_id,omitempty"`
	DeliveryEventContentID  string `json:"delivery_event_content_id,omitempty"`
	ExecutionArtifactDigest string `json:"execution_artifact_digest,omitempty"`
	DeliveryArtifactDigest  string `json:"delivery_artifact_digest,omitempty"`
	RiskEvidenceDigest      string `json:"risk_evidence_digest,omitempty"`
	CostEvidenceDigest      string `json:"cost_evidence_digest,omitempty"`
	ProviderDeliveryState   string `json:"provider_delivery_state,omitempty"`
	ServiceExecutionState   string `json:"service_execution_state,omitempty"`
	DenominatorState        string `json:"denominator_state"`
	ChainFeeCostState       string `json:"chain_fee_cost_state"`
	ModelCostState          string `json:"model_cost_state"`
	APICostState            string `json:"api_cost_state"`
	PolicyEffect            string `json:"policy_effect"`
}

type campaignCapabilityMarketTerminalArtifact struct {
	Schema              string                                         `json:"schema"`
	Scope               string                                         `json:"scope"`
	Outcome             CapabilityMarketTerminalOutcome                `json:"outcome"`
	OperationAuthority  commerce.PinnedAgentOperationAuthorityRecordV1 `json:"operation_authority"`
	AuthorityTimeProof  commerce.AuthorityTimeProofV1                  `json:"authority_time_proof"`
	IssuerQualification commerce.IssuerQualificationProofV1            `json:"issuer_qualification"`
}

func persistCapabilityMarketResultEvidence(root string, result *eightAgentJobResult, buyer,
	seller *campaignRuntime) (*campaignMarketHistory, error) {
	if root == "" || result == nil || buyer == nil || result.Sequence < 0 ||
		result.Buyer != buyer.definition.Name {
		return nil, errors.New("capability-market result evidence context is incomplete")
	}
	if result.CampaignRunID != "" {
		if err := validateCampaignRunID(result.CampaignRunID); err != nil {
			return nil, fmt.Errorf("capability-market result run scope: %w", err)
		}
	}
	if err := validateCampaignResultNegotiationRepairEvidence(*result); err != nil {
		return nil, err
	}
	if result.CampaignResultSourceDigest != "" || result.OutcomeEvidenceDigest != "" ||
		result.OutcomeEvidenceState != "" || result.CostEvidenceDigest != "" || result.CostEvidenceState != "" {
		return nil, errors.New("capability-market result was enriched before its exact source bytes were retained")
	}
	raw, err := json.Marshal(*result)
	if err != nil {
		return nil, err
	}
	sourceDigest, err := CapabilityMarketCampaignResultDigest(raw)
	if err != nil {
		return nil, err
	}
	directory := capabilityMarketResultEvidenceDirectory(root, result.Sequence)
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err = writeCapabilityMarketEvidenceOnce(filepath.Join(directory, "result-source.json"), raw); err != nil {
		return nil, err
	}
	result.CampaignResultSourceDigest = sourceDigest
	if result.Seller == "" {
		if seller != nil || result.Capability != "" {
			return nil, errors.New("capability-market result without a provider has inconsistent provider context")
		}
	} else if seller == nil || result.Seller != seller.definition.Name ||
		result.Capability != seller.definition.Capability {
		return nil, errors.New("capability-market result conflicts with the selected provider")
	}

	if !campaignResultSettled(*result) {
		result.OutcomeEvidenceState = capabilityMarketEvidenceNotApplicable
		result.CostEvidenceState = "chain_fee=unknown;model=unknown;api=unknown:no_execution_subject"
		index := campaignCapabilityMarketEvidenceIndex{
			Schema: capabilityMarketEvidenceIndexSchema, Sequence: result.Sequence,
			ResultSourceDigest: sourceDigest, TerminalEvidenceState: capabilityMarketEvidenceNotApplicable,
			DenominatorState: capabilityMarketUnknownDenominator, ChainFeeCostState: "unknown",
			ModelCostState: "unknown", APICostState: "unknown", PolicyEffect: "no_terminal_outcome",
		}
		indexRaw, marshalErr := json.Marshal(index)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if err = writeCapabilityMarketEvidenceOnce(filepath.Join(directory, "evidence-index.json"), indexRaw); err != nil {
			return nil, err
		}
		result.OutcomeEvidenceDigest = capabilityMarketRawDigest(indexRaw)
		if seller == nil {
			return nil, nil
		}
		return &campaignMarketHistory{Sequence: result.Sequence, Round: result.Round,
			Counterparty: result.Seller, Capability: result.Capability, Disposition: result.Disposition,
			EvidenceState: "unknown:no_authority_bound_terminal", OutcomeDigest: result.OutcomeEvidenceDigest,
			Denominator: capabilityMarketUnknownDenominator, PolicyEffect: "no_terminal_outcome"}, nil
	}
	if seller == nil || len(buyer.identity) != ed25519.PrivateKeySize {
		return nil, errors.New("capability-market settled result conflicts with its buyer or provider runtime")
	}
	completedAt, err := time.Parse(time.RFC3339Nano, result.CompletedAt)
	if err != nil || completedAt.Unix() <= 1 {
		return nil, errors.New("capability-market settled result has no exact completion time")
	}
	verificationTime := time.Now().UTC()
	if verificationTime.Before(completedAt) {
		return nil, errors.New("capability-market result completion time is in the future")
	}
	projection := NewOutcomeProjection()
	executionArtifact, executionAssertion, err := buildAndVerifyCapabilityMarketTerminalArtifact(
		*result, raw, buyer, seller, "execution", uint64(result.Sequence*2+1), completedAt, verificationTime, projection,
	)
	if err != nil {
		return nil, fmt.Errorf("execution terminal outcome: %w", err)
	}
	deliveryArtifact, deliveryAssertion, err := buildAndVerifyCapabilityMarketTerminalArtifact(
		*result, raw, buyer, seller, "delivery", uint64(result.Sequence*2+2), completedAt, verificationTime, projection,
	)
	if err != nil {
		return nil, fmt.Errorf("delivery terminal outcome: %w", err)
	}
	risk, err := projectCampaignCapabilityMarketRisk(*result, buyer, seller,
		[]VerifiedOutcomeAssertion{executionAssertion, deliveryAssertion}, completedAt)
	if err != nil {
		return nil, err
	}
	// No exact transaction-fee binder and no verified model/API meter or invoice
	// is available in this harness. ObserveCapabilityMarketCosts therefore
	// records unknown dimensions with empty amounts; ceilings and elapsed time
	// are deliberately not converted into fabricated zero or estimated costs.
	cost, err := ObserveCapabilityMarketCosts(CapabilityMarketCostEvidenceRequest{
		SubjectKind: "execution", SubjectID: result.ExecutionID,
		AccountingPolicyDigest: campaignDigest("capability-market-accounting-policy:v1:" + buyer.definition.OwnerID),
	}, completedAt)
	if err != nil {
		return nil, err
	}
	if cost.ChainFee.Status != CapabilityMarketCostUnknown || cost.ChainFee.AmountAtomic != "" ||
		cost.Model.Status != CapabilityMarketCostUnknown || cost.Model.AmountAtomic != "" ||
		cost.API.Status != CapabilityMarketCostUnknown || cost.API.AmountAtomic != "" {
		return nil, errors.New("capability-market unmetered cost evidence became numeric")
	}

	executionRaw, err := json.Marshal(executionArtifact)
	if err != nil {
		return nil, err
	}
	deliveryRaw, err := json.Marshal(deliveryArtifact)
	if err != nil {
		return nil, err
	}
	riskRaw, err := json.Marshal(risk)
	if err != nil {
		return nil, err
	}
	costRaw, err := json.Marshal(cost)
	if err != nil {
		return nil, err
	}
	for path, object := range map[string][]byte{
		"execution-terminal-outcome.json": executionRaw,
		"delivery-terminal-outcome.json":  deliveryRaw,
		"owner-local-risk.json":           riskRaw,
		"cost-evidence.json":              costRaw,
	} {
		if err = writeCapabilityMarketEvidenceOnce(filepath.Join(directory, path), object); err != nil {
			return nil, err
		}
	}
	executionContentID, _, err := commerce.OperationOutcomeEventContentIDV1(executionArtifact.Outcome.EventBody)
	if err != nil {
		return nil, err
	}
	deliveryContentID, _, err := commerce.OperationOutcomeEventContentIDV1(deliveryArtifact.Outcome.EventBody)
	if err != nil {
		return nil, err
	}
	providerState, serviceState := capabilityMarketRiskStates(risk)
	index := campaignCapabilityMarketEvidenceIndex{
		Schema: capabilityMarketEvidenceIndexSchema, Sequence: result.Sequence, ResultSourceDigest: sourceDigest,
		TerminalEvidenceState: capabilityMarketEvidenceVerifiedState, ExecutionEventContentID: executionContentID,
		DeliveryEventContentID: deliveryContentID, ExecutionArtifactDigest: capabilityMarketRawDigest(executionRaw),
		DeliveryArtifactDigest: capabilityMarketRawDigest(deliveryRaw), RiskEvidenceDigest: capabilityMarketRawDigest(riskRaw),
		CostEvidenceDigest: capabilityMarketRawDigest(costRaw), ProviderDeliveryState: providerState,
		ServiceExecutionState: serviceState, DenominatorState: risk.ProviderDelivery.DenominatorState,
		ChainFeeCostState: string(cost.ChainFee.Status), ModelCostState: string(cost.Model.Status),
		APICostState: string(cost.API.Status), PolicyEffect: "owner_local_advisory_only:no_global_score",
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	if err = writeCapabilityMarketEvidenceOnce(filepath.Join(directory, "evidence-index.json"), indexRaw); err != nil {
		return nil, err
	}
	result.OutcomeEvidenceDigest = capabilityMarketRawDigest(indexRaw)
	result.OutcomeEvidenceState = capabilityMarketEvidenceVerifiedState + ";provider_delivery=" + providerState +
		";service_execution=" + serviceState
	result.CostEvidenceDigest = index.CostEvidenceDigest
	result.CostEvidenceState = "chain_fee=" + index.ChainFeeCostState + ";model=" + index.ModelCostState +
		";api=" + index.APICostState
	return &campaignMarketHistory{Sequence: result.Sequence, Round: result.Round, Counterparty: result.Seller,
		Capability: result.Capability, Disposition: result.Disposition, EvidenceState: result.OutcomeEvidenceState,
		OutcomeDigest: result.OutcomeEvidenceDigest, Denominator: index.DenominatorState,
		PolicyEffect: index.PolicyEffect}, nil
}

func validateCampaignResultNegotiationRepairEvidence(result eightAgentJobResult) error {
	if result.NegotiationRepairProfile == "" {
		if len(result.NegotiationRepairDispositions) != 0 {
			return errors.New("capability-market result repair dispositions have no profile")
		}
		return nil
	}
	if result.NegotiationRepairProfile != campaignNegotiationRound5RepairProfile ||
		validateCampaignRunID(result.CampaignRunID) != nil || len(result.NegotiationRepairDispositions) > 2 {
		return errors.New("capability-market result negotiation repair evidence is invalid")
	}
	previousRank := -1
	seen := map[string]bool{}
	for _, disposition := range result.NegotiationRepairDispositions {
		rank := -1
		switch disposition {
		case campaignNegotiationBuyerAmountRepair, campaignNegotiationBuyerChoiceDeclineRepair:
			rank = 0
		case campaignNegotiationSellerAmountRepair:
			rank = 1
		default:
			return errors.New("capability-market result has an unknown negotiation repair disposition")
		}
		if seen[disposition] || rank < previousRank {
			return errors.New("capability-market result negotiation repairs are duplicated or out of order")
		}
		seen[disposition], previousRank = true, rank
	}
	return nil
}

func buildAndVerifyCapabilityMarketTerminalArtifact(result eightAgentJobResult, raw []byte, buyer,
	seller *campaignRuntime, scope string, operationSequence uint64, completedAt, verificationTime time.Time,
	projection *OutcomeProjection) (campaignCapabilityMarketTerminalArtifact, VerifiedOutcomeAssertion, error) {
	binding := CapabilityMarketCampaignResultBindingV1{
		Sequence: uint64(result.Sequence), BuyerResultID: result.Buyer, ProviderResultID: result.Seller,
		ResultCapabilityID: result.Capability, ResultDisposition: result.Disposition,
		AgreementBodyDigest: result.AgreementDigest, AgreementObligationID: "work",
		ExecutionID: result.ExecutionID, DeliverySubjectID: result.DeliverableDigest, TerminalScope: scope,
		SuccessorPolicyDigest: campaignDigest("capability-market-terminal-successor-policy:v1"),
		TerminalStateRevision: 1, TerminalDisposition: "succeeded", FailureStage: "not_applicable",
		FailureCode: "none", RetryDisposition: "none",
	}
	switch scope {
	case "execution":
		binding.SubjectProfileURI = "tos.subject.execution.v1"
		binding.OwningStateProfileURI = "tos.execution.lifecycle.v1"
	case "delivery":
		binding.SubjectProfileURI = "tos.subject.delivery.v1"
		binding.OwningStateProfileURI = "tos.delivery.lifecycle.v1"
	default:
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{},
			errors.New("capability-market terminal scope is unsupported")
	}
	source := CapabilityMarketCampaignResultSource{Object: append([]byte(nil), raw...), Binding: binding}
	subjectDescriptor, err := CapabilityMarketCampaignResultSubjectDescriptor(source)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	completedUnix := completedAt.UTC().Unix()
	timeProof := commerce.AuthorityTimeProofV1{
		ProfileURI:              "tos.openfox.campaign-result-clock.v1",
		AuthorityOrCheckpointID: fmt.Sprintf("checkpoint:capability-market:%03d:%s", result.Sequence, scope),
		IntervalStartUnix:       uint64(completedUnix - 1), IntervalEndUnix: uint64(completedUnix),
		FinalizedHighWater:  operationSequence,
		FinalizedRootDigest: campaignDigest(fmt.Sprintf("capability-market-authority-root:%d:%s", result.Sequence, scope)),
		ProofDigest:         campaignDigest(fmt.Sprintf("capability-market-authority-proof:%d:%s", result.Sequence, scope)),
	}
	timeBytes, err := codec.Marshal(timeProof)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	timeMaterial := commerce.OutcomeAuthorityProofMaterialV1{
		ProofProfileURI: commerce.OutcomeAuthorityTimeProofProfileV1, CanonicalObject: timeBytes,
	}
	timeDigest, err := commerce.OutcomeAuthorityProofObjectDigestV1(timeMaterial)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	subjectScope, err := commerce.OutcomeSubjectScopeDigestV1(subjectDescriptor)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	evidenceProfile := "tos.openfox.campaign-result-authority.v1"
	qualification := commerce.IssuerQualificationProofV1{
		RootAuthorityID: buyer.definition.AuthorityID, IssuerAgentID: buyer.definition.AgentID,
		IssuerKeyDigest: campaignDigest("capability-market-issuer-key:" +
			hex.EncodeToString(buyer.identity.Public().(ed25519.PublicKey))),
		OrderedDelegationChainDigest: campaignDigest("capability-market-delegation:v1:" + buyer.definition.OwnerID),
		ScopeProfileURI:              evidenceProfile, SubjectScopeDigest: subjectScope,
		ValidFromUnix: uint64(completedUnix - 86_400), ValidUntilUnix: uint64(completedUnix + 10*365*24*60*60),
		RevocationHandleSetDigest: campaignDigest("capability-market-revocations:v1:" + buyer.definition.OwnerID),
		AuthorityTimeProofDigest:  timeDigest, RevocationHighWater: operationSequence,
		RevocationRootDigest: campaignDigest(fmt.Sprintf("capability-market-revocation-root:%d:%s", result.Sequence, scope)),
	}
	if qualification.RootAuthorityID == "" {
		qualification.RootAuthorityID = "authority:capability-market:" + buyer.definition.Name
	}
	qualificationBytes, err := codec.Marshal(qualification)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	qualificationMaterial := commerce.OutcomeAuthorityProofMaterialV1{
		ProofProfileURI: commerce.OutcomeIssuerQualificationProofProfileV1, CanonicalObject: qualificationBytes,
	}
	evidenceVerifier, err := commerce.NewPinnedOutcomeEvidenceAuthorityV1(
		[]commerce.AuthorityTimeProofV1{timeProof}, []commerce.IssuerQualificationProofV1{qualification},
	)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	operationAuthority, err := commerce.NewPinnedAgentOperationAuthorityV1(
		buyer.definition.AgentID, buyer.identity.Public().(ed25519.PublicKey),
		time.Unix(completedUnix-86_400, 0).UTC(), time.Unix(completedUnix+10*365*24*60*60, 0).UTC(),
		campaignDigest("capability-market-operation-trust:v1:"+buyer.definition.OwnerID),
	)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	outcome, err := BuildCapabilityMarketTerminalOutcome(source, CapabilityMarketOutcomeSigningContext{
		NetworkID: "tos:local-three-node", ActorAgentID: buyer.definition.AgentID,
		AuthorizationRef: operationAuthority.Profile, AudienceDescriptor: "local-owner-private",
		OrderingDomain: campaignDigest("capability-market-outcome-ordering:" + buyer.definition.AgentID),
		Sequence:       operationSequence, Epoch: 1, CreatedAt: time.Unix(completedUnix, 0).UTC(),
		OperationKey: buyer.identity, HistoricalProof: operationAuthority.Proof,
	}, CapabilityMarketOutcomeEvidenceAuthority{
		EvidenceProfileURI: evidenceProfile, IssuerDescriptor: buyer.definition.AgentID, Visibility: "local_private",
		AudienceDigest:  campaignDigest("capability-market-audience:" + buyer.definition.OwnerID),
		RetentionDigest: campaignDigest("capability-market-retention:v1"),
		RetrievalDigest: campaignDigest("capability-market-retrieval:v1:" + buyer.definition.OwnerID),
		AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{timeMaterial, qualificationMaterial},
	})
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	resolver := commerce.PinnedAgentOperationAuthorityResolverV1{
		buyer.definition.AgentID: []commerce.PinnedAgentOperationAuthorityRecordV1{operationAuthority},
	}
	assertion, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, outcome, resolver,
		evidenceVerifier, verificationTime)
	if err != nil {
		return campaignCapabilityMarketTerminalArtifact{}, VerifiedOutcomeAssertion{}, err
	}
	return campaignCapabilityMarketTerminalArtifact{Schema: capabilityMarketTerminalArtifactSchema, Scope: scope,
		Outcome: outcome, OperationAuthority: operationAuthority, AuthorityTimeProof: timeProof,
		IssuerQualification: qualification}, assertion, nil
}

func projectCampaignCapabilityMarketRisk(result eightAgentJobResult, buyer, seller *campaignRuntime,
	assertions []VerifiedOutcomeAssertion, evaluatedAt time.Time) (CapabilityMarketOwnerRiskView, error) {
	return ProjectCapabilityMarketOwnerRisk(CapabilityMarketOwnerRiskContext{
		Policy: LocalOutcomeRiskPolicyRevision{OwnerID: buyer.definition.OwnerID, PolicyRevision: 1,
			PolicyDigest:       campaignDigest("capability-market-outcome-risk-policy:v1:" + buyer.definition.OwnerID),
			EvaluationTimeUnix: uint64(evaluatedAt.UTC().Unix()), ProjectionVisibility: localOutcomePrivateVisibility},
		ProviderAgentID: seller.definition.AgentID, LocalServiceCapabilityID: result.Capability,
		Delivery: ProviderDeliverySubjectBinding{AgreementBodyDigest: result.AgreementDigest,
			AgreementObligationID: "work", DeliverySubjectProfileURI: "tos.subject.delivery.v1",
			DeliverySubjectID: result.DeliverableDigest, OwningStateProfileURI: "tos.delivery.lifecycle.v1"},
		Execution: ServiceCapabilityExecutionBinding{AgreementBodyDigest: result.AgreementDigest,
			AgreementObligationID: "work", ExecutionID: result.ExecutionID,
			ExecutionSubjectProfileURI: "tos.subject.execution.v1", OwningStateProfileURI: "tos.execution.lifecycle.v1"},
	}, assertions)
}

// adoptCapabilityMarketResultJournals closes the crash window between the
// per-sequence evidence commit and the aggregate campaign checkpoint. The
// exact pre-enrichment result is the prepare record and evidence-index.json is
// the commit record. A prepare record without a commit record is completed
// deterministically; a sequence directory without the exact prepare record is
// ambiguous and must never trigger replanning or execution.
func adoptCapabilityMarketResultJournals(root string, report *eightAgentCampaignReport,
	runtimes []*campaignRuntime, maximumSequences int) (bool, error) {
	if root == "" || report == nil || !isCapabilityMarketCampaignSchema(report.Schema) ||
		maximumSequences < 1 {
		return false, errors.New("capability-market result-journal recovery context is invalid")
	}
	expectedRunID := report.CampaignRunID
	if expectedRunID != "" {
		if err := validateCampaignRunID(expectedRunID); err != nil {
			return false, fmt.Errorf("capability-market checkpoint run scope: %w", err)
		}
	}
	byName := make(map[string]*campaignRuntime, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil || runtime.definition.Name == "" || byName[runtime.definition.Name] != nil {
			return false, errors.New("capability-market result-journal runtime identity is invalid or duplicated")
		}
		byName[runtime.definition.Name] = runtime
	}
	outcomesDirectory := filepath.Join(root, "campaign", "outcomes")
	entries, err := os.ReadDir(outcomesDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	type journal struct {
		sequence  int
		directory string
	}
	journals := make([]journal, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "sequence-") {
			continue
		}
		value := strings.TrimPrefix(entry.Name(), "sequence-")
		sequence, parseErr := strconv.Atoi(value)
		if parseErr != nil || sequence < 0 || sequence >= maximumSequences ||
			entry.Name() != fmt.Sprintf("sequence-%03d", sequence) || !entry.IsDir() {
			return false, fmt.Errorf("capability-market result journal %q is outside the campaign sequence domain", entry.Name())
		}
		journals = append(journals, journal{sequence: sequence,
			directory: filepath.Join(outcomesDirectory, entry.Name())})
	}
	sort.Slice(journals, func(i, j int) bool { return journals[i].sequence < journals[j].sequence })
	reported := make(map[int]eightAgentJobResult, len(report.Results))
	for _, result := range report.Results {
		if result.CampaignRunID != expectedRunID {
			return false, fmt.Errorf("capability-market checkpoint sequence %d belongs to a different run", result.Sequence)
		}
		if result.Sequence < 0 || result.Sequence >= maximumSequences {
			return false, fmt.Errorf("capability-market checkpoint sequence %d is outside the campaign domain", result.Sequence)
		}
		if _, duplicate := reported[result.Sequence]; duplicate {
			return false, fmt.Errorf("capability-market checkpoint repeats sequence %d", result.Sequence)
		}
		reported[result.Sequence] = result
	}
	adopted := false
	for _, retained := range journals {
		sourcePath := filepath.Join(retained.directory, "result-source.json")
		sourceRaw, readErr := os.ReadFile(sourcePath)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				return false, fmt.Errorf("capability-market sequence %d has an ambiguous journal without an exact result source", retained.sequence)
			}
			return false, readErr
		}
		result, decodeErr := decodeCapabilityMarketSourceResult(sourceRaw)
		if decodeErr != nil {
			return false, fmt.Errorf("capability-market sequence %d has an invalid exact result source: %w",
				retained.sequence, decodeErr)
		}
		if result.Sequence != retained.sequence {
			return false, fmt.Errorf("capability-market sequence %d source claims sequence %d",
				retained.sequence, result.Sequence)
		}
		if result.CampaignRunID != expectedRunID {
			return false, fmt.Errorf("capability-market sequence %d source belongs to a different run", retained.sequence)
		}
		buyer := byName[result.Buyer]
		if buyer == nil {
			return false, fmt.Errorf("capability-market orphan sequence %d has unknown buyer %q",
				retained.sequence, result.Buyer)
		}
		var seller *campaignRuntime
		if result.Seller != "" {
			seller = byName[result.Seller]
			if seller == nil {
				return false, fmt.Errorf("capability-market orphan sequence %d has unknown seller %q",
					retained.sequence, result.Seller)
			}
		}
		indexPath := filepath.Join(retained.directory, "evidence-index.json")
		if _, statErr := os.Stat(indexPath); errors.Is(statErr, os.ErrNotExist) {
			// The exact result already exists, so repeating the business job is
			// forbidden. Finish only the deterministic evidence phase.
			if _, persistErr := persistCapabilityMarketResultEvidence(root, &result, buyer, seller); persistErr != nil {
				return false, fmt.Errorf("complete capability-market sequence %d evidence journal: %w",
					retained.sequence, persistErr)
			}
		} else if statErr != nil {
			return false, statErr
		} else if enrichErr := enrichCapabilityMarketResultFromIndex(retained.directory, &result); enrichErr != nil {
			return false, fmt.Errorf("recover capability-market sequence %d evidence index: %w",
				retained.sequence, enrichErr)
		}
		if _, verifyErr := loadCapabilityMarketResultEvidence(root, result, buyer, seller, time.Now().UTC()); verifyErr != nil {
			return false, fmt.Errorf("verify capability-market sequence %d recovery: %w",
				retained.sequence, verifyErr)
		}
		if checkpointResult, found := reported[retained.sequence]; found {
			if !sameJSON(checkpointResult, result) {
				return false, fmt.Errorf("capability-market sequence %d journal conflicts with the aggregate checkpoint",
					retained.sequence)
			}
			continue
		}
		report.Results = append(report.Results, result)
		reported[result.Sequence] = result
		adopted = true
	}
	if adopted {
		sort.Slice(report.Results, func(i, j int) bool { return report.Results[i].Sequence < report.Results[j].Sequence })
	}
	return adopted, nil
}

func decodeCapabilityMarketSourceResult(raw []byte) (eightAgentJobResult, error) {
	var result eightAgentJobResult
	if len(raw) == 0 || rejectDuplicateJSONKeys(raw) != nil {
		return result, errors.New("capability-market source result is empty or ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || requireCampaignJSONEOF(decoder) != nil {
		return result, errors.New("capability-market source result JSON is invalid")
	}
	if result.CampaignResultSourceDigest != "" || result.OutcomeEvidenceDigest != "" ||
		result.OutcomeEvidenceState != "" || result.CostEvidenceDigest != "" || result.CostEvidenceState != "" {
		return result, errors.New("capability-market source result already contains derived evidence fields")
	}
	if err := validateCampaignResultNegotiationRepairEvidence(result); err != nil {
		return result, err
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, raw) {
		return result, errors.New("capability-market source result is not the exact canonical campaign object")
	}
	return result, nil
}

func enrichCapabilityMarketResultFromIndex(directory string, result *eightAgentJobResult) error {
	if result == nil {
		return errors.New("capability-market result is nil")
	}
	indexRaw, err := os.ReadFile(filepath.Join(directory, "evidence-index.json"))
	if err != nil {
		return err
	}
	var index campaignCapabilityMarketEvidenceIndex
	if rejectDuplicateJSONKeys(indexRaw) != nil || json.Unmarshal(indexRaw, &index) != nil ||
		index.Schema != capabilityMarketEvidenceIndexSchema || index.Sequence != result.Sequence {
		return errors.New("capability-market evidence commit record is invalid")
	}
	sourceRaw, err := os.ReadFile(filepath.Join(directory, "result-source.json"))
	if err != nil {
		return err
	}
	sourceDigest, err := CapabilityMarketCampaignResultDigest(sourceRaw)
	if err != nil || sourceDigest != index.ResultSourceDigest {
		return errors.New("capability-market evidence commit has the wrong result source")
	}
	result.CampaignResultSourceDigest = sourceDigest
	result.OutcomeEvidenceDigest = capabilityMarketRawDigest(indexRaw)
	if campaignResultSettled(*result) {
		if index.TerminalEvidenceState != capabilityMarketEvidenceVerifiedState ||
			index.ProviderDeliveryState == "" || index.ServiceExecutionState == "" ||
			index.CostEvidenceDigest == "" {
			return errors.New("settled capability-market evidence commit is incomplete")
		}
		result.OutcomeEvidenceState = index.TerminalEvidenceState + ";provider_delivery=" +
			index.ProviderDeliveryState + ";service_execution=" + index.ServiceExecutionState
		result.CostEvidenceDigest = index.CostEvidenceDigest
		result.CostEvidenceState = "chain_fee=" + index.ChainFeeCostState + ";model=" + index.ModelCostState +
			";api=" + index.APICostState
		return nil
	}
	if index.TerminalEvidenceState != capabilityMarketEvidenceNotApplicable || index.CostEvidenceDigest != "" {
		return errors.New("non-settled capability-market evidence commit acquired terminal or cost evidence")
	}
	result.OutcomeEvidenceState = index.TerminalEvidenceState
	result.CostEvidenceState = "chain_fee=unknown;model=unknown;api=unknown:no_execution_subject"
	return nil
}

func restoreCapabilityMarketHistories(root string, report eightAgentCampaignReport,
	runtimes []*campaignRuntime) error {
	if report.CampaignRunID != "" {
		if err := validateCampaignRunID(report.CampaignRunID); err != nil {
			return fmt.Errorf("capability-market history run scope: %w", err)
		}
	}
	byName := make(map[string]*campaignRuntime, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil || runtime.definition.Name == "" {
			return errors.New("capability-market runtime identity is incomplete")
		}
		runtime.marketHistory = nil
		byName[runtime.definition.Name] = runtime
	}
	results := append([]eightAgentJobResult(nil), report.Results...)
	sort.Slice(results, func(i, j int) bool { return results[i].Sequence < results[j].Sequence })
	seen := make(map[int]bool, len(results))
	for _, result := range results {
		if result.CampaignRunID != report.CampaignRunID {
			return fmt.Errorf("capability-market checkpoint sequence %d belongs to a different run", result.Sequence)
		}
		if seen[result.Sequence] {
			return fmt.Errorf("capability-market checkpoint repeats sequence %d", result.Sequence)
		}
		seen[result.Sequence] = true
		buyer := byName[result.Buyer]
		if buyer == nil {
			return fmt.Errorf("capability-market checkpoint buyer %q is unknown", result.Buyer)
		}
		var seller *campaignRuntime
		if result.Seller != "" {
			seller = byName[result.Seller]
			if seller == nil {
				return fmt.Errorf("capability-market checkpoint seller %q is unknown", result.Seller)
			}
		}
		history, err := loadCapabilityMarketResultEvidence(root, result, buyer, seller, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("restore capability-market sequence %d: %w", result.Sequence, err)
		}
		if history != nil {
			buyer.marketHistory = append(buyer.marketHistory, *history)
		}
	}
	return nil
}

func loadCapabilityMarketResultEvidence(root string, result eightAgentJobResult, buyer,
	seller *campaignRuntime, verificationTime time.Time) (*campaignMarketHistory, error) {
	if result.CampaignResultSourceDigest == "" || result.OutcomeEvidenceDigest == "" ||
		result.OutcomeEvidenceState == "" || result.Sequence < 0 || buyer == nil || verificationTime.IsZero() {
		return nil, errors.New("capability-market checkpoint has no retained evidence identity")
	}
	directory := capabilityMarketResultEvidenceDirectory(root, result.Sequence)
	sourceRaw, err := os.ReadFile(filepath.Join(directory, "result-source.json"))
	if err != nil {
		return nil, err
	}
	expected := result
	expected.CampaignResultSourceDigest = ""
	expected.OutcomeEvidenceDigest = ""
	expected.OutcomeEvidenceState = ""
	expected.CostEvidenceDigest = ""
	expected.CostEvidenceState = ""
	expectedRaw, err := json.Marshal(expected)
	if err != nil || !bytes.Equal(sourceRaw, expectedRaw) {
		return nil, errors.New("retained capability-market result is not the exact pre-enrichment checkpoint object")
	}
	sourceDigest, err := CapabilityMarketCampaignResultDigest(sourceRaw)
	if err != nil || sourceDigest != result.CampaignResultSourceDigest {
		return nil, errors.New("retained capability-market result digest mismatch")
	}
	indexRaw, err := os.ReadFile(filepath.Join(directory, "evidence-index.json"))
	if err != nil {
		return nil, err
	}
	if capabilityMarketRawDigest(indexRaw) != result.OutcomeEvidenceDigest {
		return nil, errors.New("capability-market evidence index digest mismatch")
	}
	var index campaignCapabilityMarketEvidenceIndex
	if err = json.Unmarshal(indexRaw, &index); err != nil || index.Schema != capabilityMarketEvidenceIndexSchema ||
		index.Sequence != result.Sequence || index.ResultSourceDigest != sourceDigest ||
		index.TerminalEvidenceState != result.OutcomeEvidenceState &&
			!strings.HasPrefix(result.OutcomeEvidenceState, index.TerminalEvidenceState+";") {
		return nil, errors.New("capability-market evidence index conflicts with the checkpoint")
	}
	if !campaignResultSettled(result) {
		if index.TerminalEvidenceState != capabilityMarketEvidenceNotApplicable || result.CostEvidenceDigest != "" ||
			result.CostEvidenceState != "chain_fee=unknown;model=unknown;api=unknown:no_execution_subject" {
			return nil, errors.New("declined capability-market result acquired terminal or numeric cost evidence")
		}
		if result.Seller == "" {
			if seller != nil || result.Capability != "" {
				return nil, errors.New("capability-market result without a provider has inconsistent provider context")
			}
			return nil, nil
		}
		if seller == nil || result.Seller != seller.definition.Name ||
			result.Capability != seller.definition.Capability {
			return nil, errors.New("declined capability-market checkpoint conflicts with its provider runtime")
		}
		return &campaignMarketHistory{Sequence: result.Sequence, Round: result.Round,
			Counterparty: result.Seller, Capability: result.Capability, Disposition: result.Disposition,
			EvidenceState: "unknown:no_authority_bound_terminal", OutcomeDigest: result.OutcomeEvidenceDigest,
			Denominator: index.DenominatorState, PolicyEffect: index.PolicyEffect}, nil
	}
	if seller == nil || result.Seller != seller.definition.Name || result.Capability != seller.definition.Capability {
		return nil, errors.New("settled capability-market checkpoint conflicts with its provider runtime")
	}
	completedAt, err := time.Parse(time.RFC3339Nano, result.CompletedAt)
	if err != nil {
		return nil, err
	}
	projection := NewOutcomeProjection()
	executionArtifact, executionAssertion, err := loadAndVerifyCapabilityMarketTerminalArtifact(
		filepath.Join(directory, "execution-terminal-outcome.json"), index.ExecutionArtifactDigest,
		"execution", sourceRaw, buyer,
		verificationTime, projection,
	)
	if err != nil {
		return nil, err
	}
	deliveryArtifact, deliveryAssertion, err := loadAndVerifyCapabilityMarketTerminalArtifact(
		filepath.Join(directory, "delivery-terminal-outcome.json"), index.DeliveryArtifactDigest,
		"delivery", sourceRaw, buyer,
		verificationTime, projection,
	)
	if err != nil {
		return nil, err
	}
	executionContentID, _, _ := commerce.OperationOutcomeEventContentIDV1(executionArtifact.Outcome.EventBody)
	deliveryContentID, _, _ := commerce.OperationOutcomeEventContentIDV1(deliveryArtifact.Outcome.EventBody)
	if executionContentID != index.ExecutionEventContentID || deliveryContentID != index.DeliveryEventContentID {
		return nil, errors.New("capability-market terminal content identity mismatch")
	}
	risk, err := projectCampaignCapabilityMarketRisk(result, buyer, seller,
		[]VerifiedOutcomeAssertion{executionAssertion, deliveryAssertion}, completedAt)
	if err != nil {
		return nil, err
	}
	riskRaw, err := json.Marshal(risk)
	if err != nil || capabilityMarketRawDigest(riskRaw) != index.RiskEvidenceDigest {
		return nil, errors.New("capability-market owner-local risk evidence mismatch")
	}
	retainedRisk, readErr := os.ReadFile(filepath.Join(directory, "owner-local-risk.json"))
	if readErr != nil || !bytes.Equal(retainedRisk, riskRaw) {
		return nil, errors.New("capability-market retained owner-local risk object mismatch")
	}
	cost, err := ObserveCapabilityMarketCosts(CapabilityMarketCostEvidenceRequest{
		SubjectKind: "execution", SubjectID: result.ExecutionID,
		AccountingPolicyDigest: campaignDigest("capability-market-accounting-policy:v1:" + buyer.definition.OwnerID),
	}, completedAt)
	if err != nil {
		return nil, err
	}
	costRaw, err := json.Marshal(cost)
	if err != nil || capabilityMarketRawDigest(costRaw) != index.CostEvidenceDigest ||
		index.CostEvidenceDigest != result.CostEvidenceDigest {
		return nil, errors.New("capability-market cost evidence mismatch")
	}
	retainedCost, readErr := os.ReadFile(filepath.Join(directory, "cost-evidence.json"))
	if readErr != nil || !bytes.Equal(retainedCost, costRaw) {
		return nil, errors.New("capability-market retained cost evidence object mismatch")
	}
	providerState, serviceState := capabilityMarketRiskStates(risk)
	expectedOutcomeState := capabilityMarketEvidenceVerifiedState + ";provider_delivery=" + providerState +
		";service_execution=" + serviceState
	expectedCostState := "chain_fee=" + string(cost.ChainFee.Status) + ";model=" + string(cost.Model.Status) +
		";api=" + string(cost.API.Status)
	if result.OutcomeEvidenceState != expectedOutcomeState || result.CostEvidenceState != expectedCostState ||
		index.ProviderDeliveryState != providerState || index.ServiceExecutionState != serviceState ||
		index.ChainFeeCostState != string(cost.ChainFee.Status) || index.ModelCostState != string(cost.Model.Status) ||
		index.APICostState != string(cost.API.Status) {
		return nil, errors.New("capability-market evidence states conflict with retained objects")
	}
	return &campaignMarketHistory{Sequence: result.Sequence, Round: result.Round, Counterparty: result.Seller,
		Capability: result.Capability, Disposition: result.Disposition, EvidenceState: result.OutcomeEvidenceState,
		OutcomeDigest: result.OutcomeEvidenceDigest, Denominator: index.DenominatorState,
		PolicyEffect: index.PolicyEffect}, nil
}

func loadAndVerifyCapabilityMarketTerminalArtifact(path, expectedDigest, scope string, sourceRaw []byte,
	buyer *campaignRuntime, verificationTime time.Time, projection *OutcomeProjection) (
	campaignCapabilityMarketTerminalArtifact, VerifiedOutcomeAssertion, error) {
	var artifact campaignCapabilityMarketTerminalArtifact
	raw, err := os.ReadFile(path)
	if err != nil {
		return artifact, VerifiedOutcomeAssertion{}, err
	}
	if expectedDigest == "" || capabilityMarketRawDigest(raw) != expectedDigest {
		return artifact, VerifiedOutcomeAssertion{}, errors.New("capability-market terminal artifact digest mismatch")
	}
	if err = json.Unmarshal(raw, &artifact); err != nil || artifact.Schema != capabilityMarketTerminalArtifactSchema ||
		artifact.Scope != scope || !bytes.Equal(artifact.Outcome.Source.Object, sourceRaw) {
		return artifact, VerifiedOutcomeAssertion{}, errors.New("capability-market terminal artifact is invalid")
	}
	rebuiltAuthority, err := commerce.NewPinnedAgentOperationAuthorityV1(
		artifact.OperationAuthority.Body.ActorAgentID, artifact.OperationAuthority.Key,
		time.Unix(int64(artifact.OperationAuthority.Body.ValidFromUnix), 0).UTC(),
		time.Unix(int64(artifact.OperationAuthority.Body.ValidUntilUnix), 0).UTC(),
		artifact.OperationAuthority.Body.TrustConfigurationHash,
	)
	if err != nil || !sameJSON(rebuiltAuthority, artifact.OperationAuthority) ||
		artifact.OperationAuthority.Body.ActorAgentID != buyer.definition.AgentID ||
		!artifact.OperationAuthority.Key.Equal(buyer.identity.Public().(ed25519.PublicKey)) {
		return artifact, VerifiedOutcomeAssertion{}, errors.New("capability-market operation authority pin mismatch")
	}
	verifier, err := commerce.NewPinnedOutcomeEvidenceAuthorityV1(
		[]commerce.AuthorityTimeProofV1{artifact.AuthorityTimeProof},
		[]commerce.IssuerQualificationProofV1{artifact.IssuerQualification},
	)
	if err != nil {
		return artifact, VerifiedOutcomeAssertion{}, err
	}
	resolver := commerce.PinnedAgentOperationAuthorityResolverV1{
		buyer.definition.AgentID: []commerce.PinnedAgentOperationAuthorityRecordV1{artifact.OperationAuthority},
	}
	assertion, err := VerifyAndIngestCapabilityMarketTerminalOutcome(projection, artifact.Outcome, resolver,
		verifier, verificationTime)
	return artifact, assertion, err
}

func capabilityMarketRiskStates(view CapabilityMarketOwnerRiskView) (string, string) {
	providerState, serviceState := "unknown", "unknown"
	if len(view.ProviderDelivery.Deliveries) == 1 {
		providerState = string(view.ProviderDelivery.Deliveries[0].State)
	}
	if len(view.ServiceCapability.Executions) == 1 {
		serviceState = string(view.ServiceCapability.Executions[0].State)
	}
	return providerState, serviceState
}

func capabilityMarketResultEvidenceDirectory(root string, sequence int) string {
	return filepath.Join(root, "campaign", "outcomes", fmt.Sprintf("sequence-%03d", sequence))
}

func writeCapabilityMarketEvidenceOnce(path string, object []byte) error {
	retained, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(retained, object) {
			return nil
		}
		return fmt.Errorf("retained capability-market evidence conflicts at %s", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fileutil.WriteFileAtomic(path, object, 0o600)
}

func capabilityMarketRawDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestCapabilityMarketCampaignPersistsAndRestoresQualifiedOutcomeEvidence(t *testing.T) {
	_, buyerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "buyer", OwnerID: "owner:buyer",
		AgentID: "agent:buyer", AuthorityID: "authority:buyer"}, identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "seller", OwnerID: "owner:seller",
		AgentID: "agent:seller", Capability: "bounded-review"}}
	result := eightAgentJobResult{Sequence: 3, Round: 1, Disposition: "settled", Buyer: "buyer", Seller: "seller",
		Capability: "bounded-review", DemandIntentDigest: campaignDigest("demand"),
		AgreementDigest: campaignDigest("agreement"), ExecutionID: campaignDigest("execution"),
		DeliverableDigest: campaignDigest("delivery"), PaymentTransaction: campaignDigest("payment"),
		FinalityReference: "checkpoint:payment", RevenueNanoTOS: 50, MaximumInternalCostNanoTOS: 9,
		ProjectedNetNanoTOS: 41, SkillsBefore: []string{}, SkillsAfter: []string{},
		EconomicEvidenceDigest: campaignDigest("economics"), EconomicAnalysisMode: "bounded",
		ExpectedNetNanoTOS: "41", CompletedAt: time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339Nano),
		CarrierIDs: []string{"carrier:a", "carrier:b"}}
	root := t.TempDir()
	history, err := persistCapabilityMarketResultEvidence(root, &result, buyer, seller)
	if err != nil {
		t.Fatal(err)
	}
	if history == nil || result.CampaignResultSourceDigest == "" || result.OutcomeEvidenceDigest == "" ||
		result.CostEvidenceDigest == "" || !strings.Contains(result.OutcomeEvidenceState, "provider_delivery=succeeded") ||
		!strings.Contains(result.OutcomeEvidenceState, "service_execution=unknown") ||
		result.CostEvidenceState != "chain_fee=unknown;model=unknown;api=unknown" ||
		history.Denominator != capabilityMarketUnknownDenominator {
		t.Fatalf("capability-market evidence/history is incomplete: result=%+v history=%+v", result, history)
	}
	report := eightAgentCampaignReport{Results: []eightAgentJobResult{result}}
	if err = restoreCapabilityMarketHistories(root, report, []*campaignRuntime{buyer, seller}); err != nil {
		t.Fatal(err)
	}
	if len(buyer.marketHistory) != 1 || buyer.marketHistory[0] != *history {
		t.Fatalf("checkpoint did not reconstruct exact owner-local history: %+v", buyer.marketHistory)
	}
	if err = restoreCapabilityMarketHistories(root, report, []*campaignRuntime{buyer, seller}); err != nil ||
		len(buyer.marketHistory) != 1 {
		t.Fatalf("checkpoint replay duplicated history: history=%+v err=%v", buyer.marketHistory, err)
	}
	costRaw, err := os.ReadFile(filepath.Join(capabilityMarketResultEvidenceDirectory(root, result.Sequence),
		"cost-evidence.json"))
	if err != nil || bytes.Contains(costRaw, []byte(`"amount_atomic":"0"`)) {
		t.Fatalf("unknown costs became a fabricated zero: %s err=%v", costRaw, err)
	}
	terminalPath := filepath.Join(capabilityMarketResultEvidenceDirectory(root, result.Sequence),
		"execution-terminal-outcome.json")
	terminalRaw, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatal(err)
	}
	var terminalObject map[string]any
	if err = json.Unmarshal(terminalRaw, &terminalObject); err != nil {
		t.Fatal(err)
	}
	terminalObject["scope"] = "delivery"
	tamperedTerminal, err := json.Marshal(terminalObject)
	if err != nil {
		t.Fatal(err)
	}
	if err = fileutil.WriteFileAtomic(terminalPath, tamperedTerminal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = restoreCapabilityMarketHistories(root, report, []*campaignRuntime{buyer, seller}); err == nil {
		t.Fatal("rewritten terminal artifact kept the checkpoint evidence identity")
	}
}

func TestCapabilityMarketCampaignRejectsRewrittenRetainedResult(t *testing.T) {
	_, buyerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "buyer", OwnerID: "owner:buyer",
		AgentID: "agent:buyer", AuthorityID: "authority:buyer"}, identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "seller", OwnerID: "owner:seller",
		AgentID: "agent:seller", Capability: "bounded-review"}}
	result := eightAgentJobResult{Sequence: 4, Round: 1, Disposition: "declined:negotiation", Buyer: "buyer",
		Seller: "seller", Capability: "bounded-review", DemandIntentDigest: campaignDigest("declined-demand"),
		EconomicAnalysisMode: "bounded", ExpectedNetNanoTOS: "unknown",
		CompletedAt: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), CarrierIDs: []string{"carrier:a"}}
	root := t.TempDir()
	if _, err = persistCapabilityMarketResultEvidence(root, &result, buyer, seller); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(capabilityMarketResultEvidenceDirectory(root, result.Sequence), "result-source.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"seller":"seller"`), []byte(`"seller":"otherx"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test did not rewrite retained result")
	}
	if err = fileutil.WriteFileAtomic(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadCapabilityMarketResultEvidence(root, result, buyer, seller, time.Now().UTC()); err == nil {
		t.Fatal("rewritten retained result kept its checkpoint evidence identity")
	}
}

func TestRound5NegotiationRepairEvidenceIsSourceDigestBoundAndStrict(t *testing.T) {
	_, buyerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{
		Name: "buyer", OwnerID: "owner:buyer", AgentID: "agent:buyer", AuthorityID: "authority:buyer",
	}, identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{
		Name: "seller", OwnerID: "owner:seller", AgentID: "agent:seller", Capability: "bounded-review",
	}}
	result := eightAgentJobResult{
		CampaignRunID: "round5-result-repair-binding", Sequence: 44, Round: 1,
		Disposition: "declined:negotiation", Buyer: "buyer", Seller: "seller", Capability: "bounded-review",
		DemandIntentDigest: campaignDigest("declined-demand"), EconomicAnalysisMode: "bounded",
		ExpectedNetNanoTOS: "unknown", CompletedAt: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano),
		CarrierIDs: []string{"carrier:a"}, NegotiationRepairProfile: campaignNegotiationRound5RepairProfile,
		NegotiationRepairDispositions: []string{campaignNegotiationBuyerAmountRepair},
	}
	root := t.TempDir()
	if _, err = persistCapabilityMarketResultEvidence(root, &result, buyer, seller); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(capabilityMarketResultEvidenceDirectory(root, result.Sequence), "result-source.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := CapabilityMarketCampaignResultDigest(raw)
	if err != nil || digest != result.CampaignResultSourceDigest {
		t.Fatalf("repair fields are not source-digest bound: digest=%q result=%q err=%v",
			digest, result.CampaignResultSourceDigest, err)
	}
	decoded, err := decodeCapabilityMarketSourceResult(raw)
	if err != nil || decoded.NegotiationRepairProfile != campaignNegotiationRound5RepairProfile ||
		!reflect.DeepEqual(decoded.NegotiationRepairDispositions,
			[]string{campaignNegotiationBuyerAmountRepair}) {
		t.Fatalf("strict source decode lost repair evidence: %+v err=%v", decoded, err)
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["negotiation_repair_dispositions"] = []string{"forged_repair"}
	tampered, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	tamperedDigest, digestErr := CapabilityMarketCampaignResultDigest(tampered)
	if digestErr != nil || tamperedDigest == digest {
		t.Fatalf("rewritten repair evidence retained its digest: %q err=%v", tamperedDigest, digestErr)
	}
	if _, err = decodeCapabilityMarketSourceResult(tampered); err == nil {
		t.Fatal("strict source decoder accepted a forged repair disposition")
	}
}

func TestCapabilityMarketCampaignAdoptsCommittedOrphanWithoutReexecution(t *testing.T) {
	buyer, seller, result := capabilityMarketCrashGapFixture(t, 5)
	root := t.TempDir()
	if _, err := persistCapabilityMarketResultEvidence(root, &result, buyer, seller); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(capabilityMarketResultEvidenceDirectory(root, result.Sequence), "result-source.json")
	sourceBefore, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	report := eightAgentCampaignReport{Schema: capabilityMarketCampaignSchema, Results: []eightAgentJobResult{}}
	adopted, err := adoptCapabilityMarketResultJournals(root, &report,
		[]*campaignRuntime{buyer, seller}, 16)
	if err != nil || !adopted || len(report.Results) != 1 || !sameJSON(report.Results[0], result) {
		t.Fatalf("committed orphan was not adopted exactly: adopted=%t results=%+v err=%v",
			adopted, report.Results, err)
	}
	sourceAfter, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatalf("orphan adoption rewrote the exact source: err=%v", err)
	}
	adopted, err = adoptCapabilityMarketResultJournals(root, &report,
		[]*campaignRuntime{buyer, seller}, 16)
	if err != nil || adopted || len(report.Results) != 1 {
		t.Fatalf("orphan replay duplicated the checkpoint: adopted=%t results=%d err=%v",
			adopted, len(report.Results), err)
	}
	if err = restoreCapabilityMarketHistories(root, report, []*campaignRuntime{buyer, seller}); err != nil ||
		len(buyer.marketHistory) != 1 || buyer.marketHistory[0].Sequence != result.Sequence {
		t.Fatalf("adopted orphan did not restore owner-local history: history=%+v err=%v",
			buyer.marketHistory, err)
	}
}

func TestCapabilityMarketCampaignRecoveryAcceptsRoundScopedSchemas(t *testing.T) {
	runtimes := []*campaignRuntime{{definition: eightAgentManifestEntry{Name: "buyer"}}}
	for _, schema := range []string{capabilityMarketRound4CampaignSchema, capabilityMarketRound5CampaignSchema} {
		report := eightAgentCampaignReport{Schema: schema}
		adopted, err := adoptCapabilityMarketResultJournals(privateTempDir(t), &report, runtimes, 16)
		if err != nil || adopted {
			t.Fatalf("empty round-scoped recovery schema=%s adopted=%t err=%v", schema, adopted, err)
		}
	}
	report := eightAgentCampaignReport{Schema: "tos.openfox.not-a-capability-market.v1"}
	if _, err := adoptCapabilityMarketResultJournals(privateTempDir(t), &report, runtimes, 16); err == nil {
		t.Fatal("capability-market recovery accepted an unrelated report schema")
	}
}

func TestCapabilityMarketCampaignRejectsResultJournalFromDifferentRun(t *testing.T) {
	buyer, seller, result := capabilityMarketCrashGapFixture(t, 8)
	result.CampaignRunID = "round4:stale-result-journal"
	root := t.TempDir()
	if _, err := persistCapabilityMarketResultEvidence(root, &result, buyer, seller); err != nil {
		t.Fatal(err)
	}
	report := eightAgentCampaignReport{
		Schema: capabilityMarketRound4CampaignSchema, CampaignRunID: "round4:current-result-journal",
	}
	if adopted, err := adoptCapabilityMarketResultJournals(root, &report,
		[]*campaignRuntime{buyer, seller}, 16); err == nil || adopted || len(report.Results) != 0 {
		t.Fatalf("stale result journal was accepted: adopted=%t results=%+v err=%v", adopted, report.Results, err)
	}
}

func TestCapabilityMarketCampaignCompletesPreparedOrphanWithoutBusinessReplay(t *testing.T) {
	buyer, seller, sourceResult := capabilityMarketCrashGapFixture(t, 6)
	root := t.TempDir()
	directory := capabilityMarketResultEvidenceDirectory(root, sourceResult.Sequence)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	sourceRaw, err := json.Marshal(sourceResult)
	if err != nil {
		t.Fatal(err)
	}
	if err = fileutil.WriteFileAtomic(filepath.Join(directory, "result-source.json"), sourceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	report := eightAgentCampaignReport{Schema: capabilityMarketCampaignSchema, Results: []eightAgentJobResult{}}
	adopted, err := adoptCapabilityMarketResultJournals(root, &report,
		[]*campaignRuntime{buyer, seller}, 16)
	if err != nil || !adopted || len(report.Results) != 1 {
		t.Fatalf("prepared orphan did not finish its evidence phase: adopted=%t results=%+v err=%v",
			adopted, report.Results, err)
	}
	if _, err = os.Stat(filepath.Join(directory, "evidence-index.json")); err != nil {
		t.Fatalf("prepared orphan has no evidence commit record: %v", err)
	}
	retainedSource, err := os.ReadFile(filepath.Join(directory, "result-source.json"))
	if err != nil || !bytes.Equal(retainedSource, sourceRaw) {
		t.Fatalf("evidence completion changed the prepared business result: err=%v", err)
	}
}

func TestCapabilityMarketCampaignCrashGapFailsClosedOnAmbiguityOrConflict(t *testing.T) {
	buyer, seller, result := capabilityMarketCrashGapFixture(t, 7)
	t.Run("missing-exact-source", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(capabilityMarketResultEvidenceDirectory(root, result.Sequence), 0o700); err != nil {
			t.Fatal(err)
		}
		report := eightAgentCampaignReport{Schema: capabilityMarketCampaignSchema, Results: []eightAgentJobResult{}}
		if adopted, err := adoptCapabilityMarketResultJournals(root, &report,
			[]*campaignRuntime{buyer, seller}, 16); err == nil || adopted || len(report.Results) != 0 {
			t.Fatalf("ambiguous journal permitted replay or adoption: adopted=%t results=%+v err=%v",
				adopted, report.Results, err)
		}
	})
	t.Run("checkpoint-conflict", func(t *testing.T) {
		root := t.TempDir()
		committed := result
		if _, err := persistCapabilityMarketResultEvidence(root, &committed, buyer, seller); err != nil {
			t.Fatal(err)
		}
		conflicting := committed
		conflicting.DemandRationale = "different checkpoint claim"
		report := eightAgentCampaignReport{Schema: capabilityMarketCampaignSchema,
			Results: []eightAgentJobResult{conflicting}}
		if adopted, err := adoptCapabilityMarketResultJournals(root, &report,
			[]*campaignRuntime{buyer, seller}, 16); err == nil || adopted {
			t.Fatalf("conflicting aggregate checkpoint was silently replaced: adopted=%t err=%v", adopted, err)
		}
	})
}

func capabilityMarketCrashGapFixture(t *testing.T, sequence int) (*campaignRuntime, *campaignRuntime,
	eightAgentJobResult) {
	t.Helper()
	_, buyerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	buyer := &campaignRuntime{definition: eightAgentManifestEntry{Name: "buyer", OwnerID: "owner:buyer",
		AgentID: "agent:buyer", AuthorityID: "authority:buyer"}, identity: buyerKey}
	seller := &campaignRuntime{definition: eightAgentManifestEntry{Name: "seller", OwnerID: "owner:seller",
		AgentID: "agent:seller", Capability: "bounded-review"}}
	result := eightAgentJobResult{Sequence: sequence, Round: 1, Disposition: "settled", Buyer: "buyer",
		Seller: "seller", Capability: "bounded-review", DemandIntentDigest: campaignDigest("crash-gap-demand"),
		AgreementDigest: campaignDigest("crash-gap-agreement"), ExecutionID: campaignDigest("crash-gap-execution"),
		DeliverableDigest:  campaignDigest("crash-gap-delivery"),
		PaymentTransaction: campaignDigest("crash-gap-payment"), FinalityReference: "checkpoint:payment",
		RevenueNanoTOS: 50, MaximumInternalCostNanoTOS: 9, ProjectedNetNanoTOS: 41,
		SkillsBefore: []string{}, SkillsAfter: []string{}, EconomicEvidenceDigest: campaignDigest("crash-gap-economics"),
		EconomicAnalysisMode: "bounded", ExpectedNetNanoTOS: "41",
		CompletedAt: time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339Nano),
		CarrierIDs:  []string{"carrier:a", "carrier:b"}}
	return buyer, seller, result
}
