package earning

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"github.com/tosnetwork/tosutils-go/tvm/cell"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

type PredictionOracleSubmissionConfig struct {
	MarketDefinitionJSON  []byte
	OracleProfile         prediction.OracleProfile
	VoteMessageValue      uint64
	PolicyRevision        uint64
	ApprovalDigest        string
	SourceCursor          prediction.AccountCursor
	MasterchainCheckpoint prediction.BlockIdentity
}

type predictionReportOperation struct {
	Operation                string `json:"operation"`
	QueryID                  uint64 `json:"query_id"`
	Round                    uint8  `json:"round"`
	ExpectedRoundContextHash string `json:"expected_round_context_hash"`
	Outcome                  uint8  `json:"outcome"`
	EvidenceRoot             string `json:"evidence_root"`
	StatementCreatedAt       uint64 `json:"statement_created_at"`
	StatementExpiry          uint64 `json:"statement_expiry"`
}

type predictionChallengeOperation struct {
	Operation                     string `json:"operation"`
	QueryID                       uint64 `json:"query_id"`
	ExpectedProposedStatementHash string `json:"expected_proposed_statement_hash"`
	CounterOutcome                uint8  `json:"counter_outcome"`
	CounterEvidenceRoot           string `json:"counter_evidence_root"`
}

// PrepareOracleVoteEffect converts one evidence-committed Oracle plan into the
// closed semantic action and exact tosctl operation consumed by Agent Account
// custody. It independently decodes the statement instead of trusting the
// plan's duplicate display fields.
func (engine *Engine) PrepareOracleVoteEffect(ctx context.Context, sink *TOSCTLPaymentSink,
	plan prediction.OracleVotePlan, config PredictionOracleSubmissionConfig,
	fence commerce.WriterFence,
) (PreparedPredictionEffect, error) {
	if engine == nil {
		return PreparedPredictionEffect{}, errors.New("prediction Oracle vote engine is unavailable")
	}
	request, err := oracleVoteEffectRequest(engine, sink, plan, config)
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	return engine.PreparePredictionEffect(ctx, sink, request, fence)
}

func oracleVoteEffectRequest(engine *Engine, sink *TOSCTLPaymentSink,
	plan prediction.OracleVotePlan, config PredictionOracleSubmissionConfig,
) (PredictionEffectRequest, error) {
	if engine == nil {
		return PredictionEffectRequest{}, errors.New("prediction Oracle vote engine is unavailable")
	}
	profile, statementHash, contextHash, evidenceRoot, err := validateOracleVoteSubmission(sink, plan, config)
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	operation, err := json.Marshal(predictionReportOperation{
		Operation: "report_result", QueryID: queryID(statementHash), Round: uint8(plan.Round),
		ExpectedRoundContextHash: contextHash.CellHashString(), Outcome: uint8(plan.Outcome),
		EvidenceRoot: evidenceRoot.CellHashString(), StatementCreatedAt: plan.StatementCreatedAt,
		StatementExpiry: plan.StatementExpiry,
	})
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	reporterDigest, err := protocol.PredictionAccountBindingDigestV1(profile.ReporterAddress)
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	round, err := predictionRoundKind(plan.Round)
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	networkDigest, _ := sinkPredictionNetworkDigest(sink)
	fields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"network_domain_digest":   commerce.Digest32(networkDigest),
		"market_id":               commerce.Digest32(statementMarketID(profile)),
		"reporter_account_digest": commerce.Digest32(reporterDigest.SHA256String()),
		"round":                   commerce.Kind(round),
		"round_context_hash":      commerce.Digest32(contextHash.SHA256String()),
		"vote_statement_hash":     commerce.Digest32(statementHash.SHA256String()),
	}
	return PredictionEffectRequest{
		ActionKind: "prediction.resolution.report", SemanticFields: fields,
		MarketDefinitionJSON: append([]byte(nil), config.MarketDefinitionJSON...),
		OperationJSON:        operation, AmountNanoTOS: config.VoteMessageValue,
		ValidUntil: uint32(plan.StatementExpiry), PolicyRevision: config.PolicyRevision,
		ApprovalDigest: config.ApprovalDigest, SourceCursor: config.SourceCursor,
		MasterchainCheckpoint: config.MasterchainCheckpoint,
	}, nil
}

// PrepareOracleChallengeEffect applies the same custody boundary to a durable
// disagreement plan. The exact required bond/fee/budget value comes from the
// watcher profile and cannot be weakened by a caller-provided amount.
func (engine *Engine) PrepareOracleChallengeEffect(ctx context.Context, sink *TOSCTLPaymentSink,
	plan prediction.ChallengePlan, config PredictionOracleSubmissionConfig,
	fence commerce.WriterFence,
) (PreparedPredictionEffect, error) {
	if engine == nil {
		return PreparedPredictionEffect{}, errors.New("prediction Oracle challenge engine is unavailable")
	}
	request, err := oracleChallengeEffectRequest(engine, sink, plan, config)
	if err != nil {
		return PreparedPredictionEffect{}, err
	}
	return engine.PreparePredictionEffect(ctx, sink, request, fence)
}

func oracleChallengeEffectRequest(engine *Engine, sink *TOSCTLPaymentSink,
	plan prediction.ChallengePlan, config PredictionOracleSubmissionConfig,
) (PredictionEffectRequest, error) {
	if engine == nil {
		return PredictionEffectRequest{}, errors.New("prediction Oracle challenge engine is unavailable")
	}
	profile, proposalHash, counterRoot, err := validateOracleChallengeSubmission(sink, plan, config)
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	operation, err := json.Marshal(predictionChallengeOperation{
		Operation: "challenge_result", QueryID: queryID(proposalHash),
		ExpectedProposedStatementHash: proposalHash.CellHashString(),
		CounterOutcome:                uint8(plan.CounterOutcome), CounterEvidenceRoot: counterRoot.CellHashString(),
	})
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	challengerDigest, err := protocol.PredictionAccountBindingDigestV1(sink.SourceAccount)
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	outcome, err := predictionOutcomeKind(plan.CounterOutcome)
	if err != nil {
		return PredictionEffectRequest{}, err
	}
	networkDigest, _ := sinkPredictionNetworkDigest(sink)
	fields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"network_domain_digest":     commerce.Digest32(networkDigest),
		"market_id":                 commerce.Digest32(statementMarketID(profile)),
		"challenger_account_digest": commerce.Digest32(challengerDigest.SHA256String()),
		"proposed_statement_hash":   commerce.Digest32(proposalHash.SHA256String()),
		"counter_outcome":           commerce.Kind(outcome),
		"counter_evidence_root":     commerce.Digest32(counterRoot.SHA256String()),
	}
	return PredictionEffectRequest{
		ActionKind: "prediction.resolution.challenge", SemanticFields: fields,
		MarketDefinitionJSON: append([]byte(nil), config.MarketDefinitionJSON...),
		OperationJSON:        operation, AmountNanoTOS: plan.RequiredMessageValue,
		ValidUntil: uint32(plan.ChallengeDeadline), PolicyRevision: config.PolicyRevision,
		ApprovalDigest: config.ApprovalDigest, SourceCursor: config.SourceCursor,
		MasterchainCheckpoint: config.MasterchainCheckpoint,
	}, nil
}

func validateOracleVoteSubmission(sink *TOSCTLPaymentSink, plan prediction.OracleVotePlan,
	config PredictionOracleSubmissionConfig,
) (prediction.OracleProfile, protocol.Hash32, protocol.Hash32, protocol.Hash32, error) {
	profile, err := validateOracleSubmissionProfile(sink, config)
	if err != nil || config.VoteMessageValue == 0 || plan.StatementCreatedAt == 0 ||
		plan.StatementCreatedAt >= plan.StatementExpiry || plan.StatementExpiry > math.MaxUint32 ||
		!validOracleReceiptDigests(plan.ArchiveReceiptDigests) {
		return prediction.OracleProfile{}, protocol.Hash32{}, protocol.Hash32{}, protocol.Hash32{},
			errors.New("prediction Oracle vote submission is invalid")
	}
	statementCell, err := canonicalOracleCell(plan.StatementBOC)
	if err != nil {
		return prediction.OracleProfile{}, protocol.Hash32{}, protocol.Hash32{}, protocol.Hash32{}, err
	}
	statement, err := protocol.DecodePredictionResolutionStatementV1(statementCell)
	manifestCell, manifestCellErr := canonicalOracleCell(plan.EvidenceManifestBOC)
	var manifest *protocol.PredictionEvidenceManifestV1
	if manifestCellErr == nil {
		manifest, manifestCellErr = protocol.DecodePredictionEvidenceManifestV1(manifestCell)
	}
	statementHash := oracleCellHash(statementCell)
	contextHash, contextErr := protocol.ParseHash32(plan.RoundContextHash)
	evidenceRoot, evidenceErr := protocol.ParseHash32(plan.EvidenceRoot)
	planStatementHash, hashErr := protocol.ParseHash32(plan.StatementHash)
	marketID, marketErr := protocol.ParseHash32(profile.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(profile.RulesHash)
	policyHash, policyErr := protocol.ParseHash32(profile.RoundPolicyHash)
	if err != nil || manifestCellErr != nil || contextErr != nil || evidenceErr != nil || hashErr != nil || marketErr != nil ||
		rulesErr != nil || policyErr != nil || statementHash != planStatementHash ||
		statement.GlobalID != profile.GlobalID || statement.MarketAddress != profile.MarketAddress ||
		statement.MarketID != marketID || statement.RulesHash != rulesHash ||
		statement.RoundPolicyHash != policyHash || statement.RoundContextHash != contextHash ||
		statement.Round != profile.Round || statement.Round != plan.Round || statement.Outcome != plan.Outcome ||
		statement.EvidenceRoot != evidenceRoot || statement.StatementCreatedAt != plan.StatementCreatedAt ||
		statement.StatementExpiry != plan.StatementExpiry || oracleCellHash(manifestCell) != evidenceRoot ||
		manifest.MarketID != marketID || manifest.RulesHash != rulesHash ||
		manifest.RoundContextHash != contextHash || manifest.Outcome != plan.Outcome {
		return prediction.OracleProfile{}, protocol.Hash32{}, protocol.Hash32{}, protocol.Hash32{},
			errors.New("prediction Oracle statement conflicts with its durable plan")
	}
	return profile, statementHash, contextHash, evidenceRoot, nil
}

func validateOracleChallengeSubmission(sink *TOSCTLPaymentSink, plan prediction.ChallengePlan,
	config PredictionOracleSubmissionConfig,
) (prediction.OracleProfile, protocol.Hash32, protocol.Hash32, error) {
	profile, err := validateOracleSubmissionProfile(sink, config)
	if err != nil || plan.RequiredMessageValue == 0 || plan.ChallengeDeadline == 0 ||
		plan.ChallengeDeadline > math.MaxUint32 || plan.CounterOutcome > protocol.OutcomeInvalid ||
		plan.CounterOutcome == plan.ProposedOutcome || !validOracleReceiptDigests(plan.ArchiveReceiptDigests) {
		return prediction.OracleProfile{}, protocol.Hash32{}, protocol.Hash32{},
			errors.New("prediction Oracle challenge submission is invalid")
	}
	manifestCell, err := canonicalOracleCell(plan.EvidenceManifestBOC)
	if err != nil {
		return prediction.OracleProfile{}, protocol.Hash32{}, protocol.Hash32{}, err
	}
	manifest, err := protocol.DecodePredictionChallengeEvidenceManifestV1(manifestCell)
	proposalHash, proposalErr := protocol.ParseHash32(plan.ProposedStatementHash)
	counterRoot, rootErr := protocol.ParseHash32(plan.CounterEvidenceRoot)
	marketID, marketErr := protocol.ParseHash32(profile.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(profile.RulesHash)
	if err != nil || proposalErr != nil || rootErr != nil || marketErr != nil || rulesErr != nil ||
		counterRoot != oracleCellHash(manifestCell) || manifest.MarketID != marketID ||
		manifest.RulesHash != rulesHash || manifest.ProposedStatementHash != proposalHash ||
		manifest.CounterOutcome != plan.CounterOutcome {
		return prediction.OracleProfile{}, protocol.Hash32{}, protocol.Hash32{},
			errors.New("prediction challenge manifest conflicts with its durable plan")
	}
	return profile, proposalHash, counterRoot, nil
}

func validateOracleSubmissionProfile(sink *TOSCTLPaymentSink,
	config PredictionOracleSubmissionConfig,
) (prediction.OracleProfile, error) {
	if sink == nil || sink.PredictionRelayJournal == nil || len(config.MarketDefinitionJSON) == 0 ||
		config.PolicyRevision == 0 {
		return prediction.OracleProfile{}, errors.New("prediction Oracle submission is not configured")
	}
	relay, ok := sink.PredictionRelayJournal.Profile()
	networkDigest, err := sinkPredictionNetworkDigest(sink)
	profile := config.OracleProfile
	profileMarketID, profileMarketErr := protocol.ParseHash32(profile.MarketID)
	relayMarketID, relayMarketErr := protocol.ParseHash32(relay.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(profile.RulesHash)
	policyHash, policyErr := protocol.ParseHash32(profile.RoundPolicyHash)
	_, reporterErr := protocol.PredictionAccountBindingDigestV1(profile.ReporterAddress)
	if !ok || err != nil || relay.NetworkDomainHash != networkDigest ||
		profile.GlobalID != sink.RelayNetworkDomain.GlobalID || profile.MarketAddress != relay.MarketAddress ||
		profileMarketErr != nil || relayMarketErr != nil || profileMarketID != relayMarketID ||
		rulesErr != nil || rulesHash.IsZero() || policyErr != nil || policyHash.IsZero() || reporterErr != nil ||
		!validTVMCellSHA256(profile.MarketID) || !canonicalSHA256(profile.RulesHash) ||
		!validTVMCellSHA256(profile.RoundPolicyHash) || profile.ReporterAddress != sink.SourceAccount ||
		(profile.Round != protocol.RoundNormal && profile.Round != protocol.RoundAppeal) {
		return prediction.OracleProfile{}, errors.New("prediction Oracle profile conflicts with relay custody")
	}
	return profile, nil
}

func validOracleReceiptDigests(values []string) bool {
	if len(values) < 2 || len(values) > 2*protocol.MaxEvidenceEntries {
		return false
	}
	previous := ""
	for _, value := range values {
		if !canonicalSHA256(value) || (previous != "" && value <= previous) {
			return false
		}
		previous = value
	}
	return true
}

func sinkPredictionNetworkDigest(sink *TOSCTLPaymentSink) (string, error) {
	if sink == nil || sink.RelayNetworkDomain == nil {
		return "", errors.New("prediction network domain is unavailable")
	}
	return agentrelay.NetworkDomainDigest(*sink.RelayNetworkDomain)
}

func canonicalOracleCell(raw []byte) (*cell.Cell, error) {
	if len(raw) == 0 || len(raw) > 256<<10 {
		return nil, errors.New("prediction Oracle canonical cell is invalid")
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) {
		return nil, errors.New("prediction Oracle object is not one canonical cell")
	}
	return root, nil
}

func oracleCellHash(root *cell.Cell) protocol.Hash32 {
	var result protocol.Hash32
	copy(result[:], root.Hash())
	return result
}

func queryID(value protocol.Hash32) uint64 { return binary.BigEndian.Uint64(value[:8]) }

func statementMarketID(profile prediction.OracleProfile) string {
	value, _ := protocol.ParseHash32(profile.MarketID)
	return value.SHA256String()
}

func predictionRoundKind(value protocol.Round) (string, error) {
	switch value {
	case protocol.RoundNormal:
		return "normal", nil
	case protocol.RoundAppeal:
		return "appeal", nil
	default:
		return "", errors.New("prediction Oracle round is invalid")
	}
}

func predictionOutcomeKind(value protocol.Outcome) (string, error) {
	switch value {
	case protocol.OutcomeYes:
		return "yes", nil
	case protocol.OutcomeNo:
		return "no", nil
	case protocol.OutcomeInvalid:
		return "invalid", nil
	default:
		return "", errors.New("prediction Oracle outcome is invalid")
	}
}
