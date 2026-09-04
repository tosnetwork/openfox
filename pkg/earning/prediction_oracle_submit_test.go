package earning

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

func oracleSubmitHash(value byte) protocol.Hash32 {
	var result protocol.Hash32
	for index := range result {
		result[index] = value
	}
	return result
}

func oracleSubmitFixture(t *testing.T) (*TOSCTLPaymentSink, PredictionOracleSubmissionConfig,
	prediction.OracleVotePlan, func(),
) {
	t.Helper()
	digest := func(prefix string, value byte) string {
		return prefix + strings.Repeat(hex.EncodeToString([]byte{value}), 32)
	}
	source := "0:" + strings.Repeat("1", 64)
	market := "0:" + strings.Repeat("2", 64)
	network := agentrelay.NetworkDomain{
		NetworkID: "tos:test", GlobalID: 42,
		ZeroStateRootHash: digest("sha256:", 0x31),
		ZeroStateFileHash: digest("sha256:", 0x32), WorkchainID: 0,
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	marketID, rulesHash, policyHash := oracleSubmitHash(0x41), oracleSubmitHash(0x42), oracleSubmitHash(0x43)
	contextHash, content := oracleSubmitHash(0x44), oracleSubmitHash(0x45)
	manifest, err := protocol.BuildPredictionEvidenceManifestCell(protocol.PredictionEvidenceManifestV1{
		MarketID: marketID, RulesHash: rulesHash, RoundContextHash: contextHash,
		Outcome: protocol.OutcomeYes,
		Entries: []protocol.EvidenceEntryV1{{
			SourceKind: protocol.SourceHTTPS, CanonicalSourceID: "https://results.example/final",
			ContentDigest: content, ArchiveLocator: "tos-cas-sha256:" + hex.EncodeToString(content[:]),
			PublicationTimeSeconds: 200, EventTimeSeconds: 190,
			ParserProfileVersion: "election-result/v1",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceRoot := oracleCellHash(manifest)
	statement, err := protocol.BuildPredictionResolutionStatementCell(
		protocol.PredictionResolutionStatementV1{
			GlobalID: 42, MarketAddress: market, MarketID: marketID, RulesHash: rulesHash,
			RoundPolicyHash: policyHash, RoundContextHash: contextHash,
			Round: protocol.RoundNormal, Outcome: protocol.OutcomeYes, EvidenceRoot: evidenceRoot,
			StatementCreatedAt: 1_800_000_100, StatementExpiry: 1_800_000_300,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	statementHash := oracleCellHash(statement)
	profile := prediction.OracleProfile{
		GlobalID: 42, MarketAddress: market, MarketID: marketID.CellHashString(),
		RulesHash: rulesHash.SHA256String(), RoundPolicyHash: policyHash.CellHashString(),
		ReporterAddress: source, Round: protocol.RoundNormal, ClaimDeadline: 1_800_001_000,
		AuditRetention: 86_400,
	}
	relay, err := prediction.OpenPredictionRelayJournal(
		filepath.Join(privateTempDir(t), "oracle-submit-relay"),
		prediction.PredictionRelayProfile{
			NetworkDomainHash: networkDigest, SourceAgentAccount: source,
			SourceAgentAccountCodeHash: digest("tvm-cell-sha256:", 0x51),
			MarketAddress:              market, MarketID: marketID.SHA256String(),
			MarketCodeHash:   digest("tvm-cell-sha256:", 0x52),
			MarketConfigHash: digest("tvm-cell-sha256:", 0x53),
			ObserverIDs:      []string{digest("sha256:", 0x61), digest("sha256:", 0x62), digest("sha256:", 0x63)},
			QuorumThreshold:  2, MaximumOutstanding: 8, MaximumSignedBOCBytes: 64 << 10,
			MinimumNoBounceMCBlocks: 8,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	sink := &TOSCTLPaymentSink{
		SourceAccount: source, NetworkGlobalID: 42, RelayNetworkDomain: &network,
		PredictionRelayJournal: relay,
	}
	config := PredictionOracleSubmissionConfig{
		MarketDefinitionJSON: []byte(`{"global_id":42}`), OracleProfile: profile,
		VoteMessageValue: 1_000_000_000, PolicyRevision: 1,
	}
	plan := prediction.OracleVotePlan{
		Round: protocol.RoundNormal, Outcome: protocol.OutcomeYes,
		RoundContextHash: contextHash.CellHashString(), EvidenceRoot: evidenceRoot.CellHashString(),
		StatementHash: statementHash.CellHashString(), EvidenceManifestBOC: manifest.ToBOCWithFlags(false),
		StatementBOC:       statement.ToBOCWithFlags(false),
		StatementCreatedAt: 1_800_000_100, StatementExpiry: 1_800_000_300,
		ArchiveReceiptDigests: []string{digest("sha256:", 0x81), digest("sha256:", 0x82)},
	}
	return sink, config, plan, func() { _ = relay.Close() }
}

func TestOracleVoteSubmissionRevalidatesCanonicalStatementAndAccountBinding(t *testing.T) {
	sink, config, plan, closeFixture := oracleSubmitFixture(t)
	defer closeFixture()
	profile, statementHash, contextHash, evidenceRoot, err := validateOracleVoteSubmission(sink, plan, config)
	if err != nil || profile.MarketID != config.OracleProfile.MarketID || statementHash.SHA256String() == "" ||
		contextHash.SHA256String() == "" || evidenceRoot.SHA256String() == "" {
		t.Fatalf("valid durable Oracle vote was rejected: %v", err)
	}
	mutated := plan
	mutated.RoundContextHash = oracleSubmitHash(0x99).CellHashString()
	if _, _, _, _, err := validateOracleVoteSubmission(sink, mutated, config); err == nil {
		t.Fatal("vote submission accepted a context that differs from the statement")
	}
	wrongReporter := config
	wrongReporter.OracleProfile.ReporterAddress = "0:" + strings.Repeat("3", 64)
	if _, _, _, _, err := validateOracleVoteSubmission(sink, plan, wrongReporter); err == nil {
		t.Fatal("vote submission accepted another reporter account")
	}
	request, err := oracleVoteEffectRequest(
		&Engine{OwnerID: "owner:oracle", AgentID: "agent:oracle"}, sink, plan, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	var operation predictionReportOperation
	if json.Unmarshal(request.OperationJSON, &operation) != nil ||
		request.ActionKind != "prediction.resolution.report" ||
		request.ValidUntil != uint32(plan.StatementExpiry) ||
		operation.QueryID != queryID(statementHash) || operation.Round != uint8(protocol.RoundNormal) ||
		operation.ExpectedRoundContextHash != plan.RoundContextHash ||
		operation.EvidenceRoot != plan.EvidenceRoot {
		t.Fatalf("vote plan mapped to a conflicting custody request: %+v %+v", request, operation)
	}
	wire, err := commerce.ExportSemanticFields(request.ActionKind, request.SemanticFields)
	if err != nil {
		t.Fatal(err)
	}
	reporter, _ := protocol.PredictionAccountBindingDigestV1(sink.SourceAccount)
	if semanticTextField(wire, "reporter_account_digest") != reporter.SHA256String() ||
		semanticTextField(wire, "round_context_hash") != contextHash.SHA256String() ||
		semanticTextField(wire, "vote_statement_hash") != statementHash.SHA256String() {
		t.Fatalf("vote semantic binding is incomplete: %+v", wire)
	}
}

func TestOracleChallengeSubmissionRevalidatesManifestBindings(t *testing.T) {
	sink, config, _, closeFixture := oracleSubmitFixture(t)
	defer closeFixture()
	marketID, _ := protocol.ParseHash32(config.OracleProfile.MarketID)
	rulesHash, _ := protocol.ParseHash32(config.OracleProfile.RulesHash)
	proposal := oracleSubmitHash(0x71)
	content := oracleSubmitHash(0x72)
	manifest, err := protocol.BuildPredictionChallengeEvidenceManifestCell(
		protocol.PredictionChallengeEvidenceManifestV1{
			MarketID: marketID, RulesHash: rulesHash, ProposedStatementHash: proposal,
			CounterOutcome: protocol.OutcomeNo,
			Entries: []protocol.EvidenceEntryV1{{
				SourceKind: protocol.SourceHTTPS, CanonicalSourceID: "https://results.example/final",
				ContentDigest: content, ArchiveLocator: "tos-cas-sha256:" + hex.EncodeToString(content[:]),
				PublicationTimeSeconds: 200, EventTimeSeconds: 190,
				ParserProfileVersion: "election-result/v1",
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	root := oracleCellHash(manifest)
	plan := prediction.ChallengePlan{
		ProposedStatementHash: proposal.CellHashString(), ProposedOutcome: protocol.OutcomeYes,
		CounterOutcome: protocol.OutcomeNo, CounterEvidenceRoot: root.CellHashString(),
		EvidenceManifestBOC: manifest.ToBOCWithFlags(false), RequiredMessageValue: 2_000_000_000,
		ChallengeDeadline: 1_800_000_500,
		ArchiveReceiptDigests: []string{
			"sha256:" + strings.Repeat("81", 32), "sha256:" + strings.Repeat("82", 32),
		},
	}
	if _, _, _, err := validateOracleChallengeSubmission(sink, plan, config); err != nil {
		t.Fatalf("valid durable challenge was rejected: %v", err)
	}
	plan.CounterEvidenceRoot = oracleSubmitHash(0x73).CellHashString()
	if _, _, _, err := validateOracleChallengeSubmission(sink, plan, config); err == nil {
		t.Fatal("challenge submission accepted a different evidence root")
	}
	plan.CounterEvidenceRoot = root.CellHashString()
	request, err := oracleChallengeEffectRequest(
		&Engine{OwnerID: "owner:oracle", AgentID: "agent:oracle"}, sink, plan, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	var operation predictionChallengeOperation
	if json.Unmarshal(request.OperationJSON, &operation) != nil ||
		request.ActionKind != "prediction.resolution.challenge" ||
		request.AmountNanoTOS != plan.RequiredMessageValue ||
		operation.QueryID != queryID(proposal) ||
		operation.ExpectedProposedStatementHash != proposal.CellHashString() ||
		operation.CounterEvidenceRoot != root.CellHashString() {
		t.Fatalf("challenge plan mapped to a conflicting custody request: %+v %+v", request, operation)
	}
	wire, err := commerce.ExportSemanticFields(request.ActionKind, request.SemanticFields)
	if err != nil || semanticTextField(wire, "counter_outcome") != "no" ||
		semanticTextField(wire, "counter_evidence_root") != root.SHA256String() {
		t.Fatalf("challenge semantic binding is incomplete: %+v err=%v", wire, err)
	}
}

func semanticTextField(fields []commerce.SemanticFieldValue, name string) string {
	for _, field := range fields {
		if field.Name == name {
			return field.Text
		}
	}
	return ""
}
