package prediction

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

type fixedResolutionEvaluator struct {
	outcome protocol.Outcome
	calls   int
}

func (evaluator *fixedResolutionEvaluator) EvaluatePredictionResolution(
	_ context.Context,
	_ string,
	_ string,
	evidence []ArchivedEvidence,
) (protocol.Outcome, error) {
	evaluator.calls++
	if len(evidence) == 0 {
		return 0, context.Canceled
	}
	evidence[0].Content[0] ^= 1
	return evaluator.outcome, nil
}

func watcherProfile() ChallengeWatcherProfile {
	return ChallengeWatcherProfile{
		NetworkDomainHash:      testHash(0x20).SHA256String(),
		MarketConfigHash:       testHash(0x23).CellHashString(),
		ContractCodeHash:       testHash(0x24).CellHashString(),
		ChallengeBond:          10 * testTOS,
		ChallengeProcessingFee: testTOS,
		OperationBudget:        testTOS,
		MaximumSnapshotAge:     30,
	}
}

func proposedObservation(profile OracleProfile) ProposedMarketObservation {
	return ProposedMarketObservation{
		Status:                proposedMarketStatus,
		NetworkDomainHash:     watcherProfile().NetworkDomainHash,
		MarketID:              profile.MarketID,
		MarketAddress:         profile.MarketAddress,
		RulesHash:             profile.RulesHash,
		MarketConfigHash:      watcherProfile().MarketConfigHash,
		ContractCodeHash:      watcherProfile().ContractCodeHash,
		ProposedStatementHash: testHash(0x91).CellHashString(),
		ProposedOutcome:       protocol.OutcomeYes,
		ChallengeDeadline:     12_000,
		ObservedAt:            10_999,
		FinalityViewID:        testHash(0x92).SHA256String(),
		QuorumFinalized:       true,
	}
}

func TestChallengeWatcherPersistsExactCounterManifestBeforeReturning(t *testing.T) {
	profile, keys := oracleFixture(t, protocol.RoundNormal)
	directory := filepath.Join(t.TempDir(), "oracle")
	journal, err := OpenOracleJournal(directory, profile)
	if err != nil {
		t.Fatal(err)
	}
	evidence := archivedEvidence(t, keys)
	originalContent := append([]byte(nil), evidence[0].Content...)
	evaluator := &fixedResolutionEvaluator{outcome: protocol.OutcomeNo}
	watcher := ChallengeWatcher{Journal: journal, Profile: watcherProfile(), Evaluator: evaluator}
	plan, err := watcher.PrepareChallenge(t.Context(), proposedObservation(profile), evidence, 11_000)
	if err != nil || plan == nil || plan.CounterOutcome != protocol.OutcomeNo ||
		plan.RequiredMessageValue != 12*testTOS || len(plan.EvidenceManifestBOC) == 0 ||
		!bytes.Equal(evidence[0].Content, originalContent) {
		t.Fatalf("unexpected durable challenge plan: %+v err=%v", plan, err)
	}
	retry, err := watcher.PrepareChallenge(t.Context(), proposedObservation(profile), evidence, 11_000)
	if err != nil || retry == nil || !bytes.Equal(retry.EvidenceManifestBOC, plan.EvidenceManifestBOC) {
		t.Fatalf("exact challenge retry failed: %v", err)
	}
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	journal, err = OpenOracleJournal(directory, profile)
	if err != nil {
		t.Fatalf("durable challenge did not recover: %v", err)
	}
	defer func() { _ = journal.Close() }()
	recoveredWatcher := ChallengeWatcher{Journal: journal, Profile: watcherProfile(), Evaluator: evaluator}
	recovered, err := recoveredWatcher.PrepareChallenge(t.Context(), proposedObservation(profile), evidence, 11_000)
	if err != nil || recovered == nil || !bytes.Equal(recovered.EvidenceManifestBOC, plan.EvidenceManifestBOC) {
		t.Fatalf("recovered challenge bytes changed: %v", err)
	}
}

func TestChallengeWatcherRequiresFinalizedFreshDisagreementAndRejectsDrift(t *testing.T) {
	profile, keys := oracleFixture(t, protocol.RoundNormal)
	journal, err := OpenOracleJournal(filepath.Join(t.TempDir(), "oracle"), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	evidence := archivedEvidence(t, keys)
	evaluator := &fixedResolutionEvaluator{outcome: protocol.OutcomeYes}
	watcher := ChallengeWatcher{Journal: journal, Profile: watcherProfile(), Evaluator: evaluator}
	observation := proposedObservation(profile)
	plan, err := watcher.PrepareChallenge(t.Context(), observation, evidence, 11_000)
	if err != nil || plan != nil {
		t.Fatal("watcher challenged a proposal matching deterministic evidence")
	}
	observation.QuorumFinalized = false
	_, unfinalizedErr := watcher.PrepareChallenge(t.Context(), observation, evidence, 11_000)
	if unfinalizedErr == nil {
		t.Fatal("unfinalized proposal observation reached the evaluator")
	}
	observation = proposedObservation(profile)
	evaluator.outcome = protocol.OutcomeNo
	first, err := watcher.PrepareChallenge(t.Context(), observation, evidence, 11_000)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	drifted := archivedEvidence(t, keys)
	drifted[0].Entry.ParserProfileVersion = "election-json/v2"
	if _, err := watcher.PrepareChallenge(t.Context(), observation, drifted, 11_000); err == nil {
		t.Fatal("same proposal was rebound to a different counter evidence root")
	}
}
