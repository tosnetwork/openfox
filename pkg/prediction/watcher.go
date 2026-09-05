package prediction

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"reflect"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

const proposedMarketStatus uint8 = 2

type ChallengeWatcherProfile struct {
	NetworkDomainHash      string `json:"network_domain_hash"`
	MarketConfigHash       string `json:"market_config_hash"`
	ContractCodeHash       string `json:"contract_code_hash"`
	ChallengeBond          uint64 `json:"challenge_bond"`
	ChallengeProcessingFee uint64 `json:"challenge_processing_fee"`
	OperationBudget        uint64 `json:"operation_budget"`
	MaximumSnapshotAge     uint64 `json:"maximum_snapshot_age"`
}

type ProposedMarketObservation struct {
	Status                uint8
	NetworkDomainHash     string
	MarketID              string
	MarketAddress         string
	RulesHash             string
	MarketConfigHash      string
	ContractCodeHash      string
	ProposedStatementHash string
	ProposedOutcome       protocol.Outcome
	ChallengeDeadline     uint64
	ObservedAt            uint64
	FinalityViewID        string
	QuorumFinalized       bool
}

type DeterministicResolutionEvaluator interface {
	EvaluatePredictionResolution(
		ctx context.Context,
		marketID string,
		rulesHash string,
		evidence []ArchivedEvidence,
	) (protocol.Outcome, error)
}

type ChallengePlan struct {
	ProposedStatementHash string
	ProposedOutcome       protocol.Outcome
	CounterOutcome        protocol.Outcome
	CounterEvidenceRoot   string
	EvidenceManifestBOC   []byte
	RequiredMessageValue  uint64
	ChallengeDeadline     uint64
	FinalityViewID        string
	ArchiveReceiptDigests []string
}

type ChallengeWatcher struct {
	Journal   *OracleJournal
	Profile   ChallengeWatcherProfile
	Evaluator DeterministicResolutionEvaluator
}

// PrepareChallenge returns nil when the deterministic outcome agrees with the
// proposal. A disagreement is persisted before the plan is returned, so a
// restart can only recover the exact same counter manifest.
func (watcher ChallengeWatcher) PrepareChallenge(
	ctx context.Context,
	observation ProposedMarketObservation,
	evidence []ArchivedEvidence,
	now uint64,
) (*ChallengePlan, error) {
	if ctx == nil || watcher.Journal == nil || watcher.Evaluator == nil || len(evidence) == 0 ||
		now == 0 || now > math.MaxInt64 ||
		validateChallengeWatcherProfile(watcher.Profile) != nil {
		return nil, errors.New("prediction challenge watcher is unavailable")
	}
	watcher.Journal.mu.Lock()
	if watcher.Journal.lock == nil {
		watcher.Journal.mu.Unlock()
		return nil, errors.New("prediction oracle journal is closed")
	}
	oracleProfile := watcher.Journal.doc.Profile
	watcher.Journal.mu.Unlock()
	if err := validateProposedObservation(observation, watcher.Profile, oracleProfile, now); err != nil {
		return nil, err
	}
	watcher.Journal.mu.Lock()
	_, receiptDigests, archiveErr := watcher.Journal.verifyArchivedEvidence(evidence, now)
	watcher.Journal.mu.Unlock()
	if archiveErr != nil {
		return nil, archiveErr
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	counterOutcome, err := watcher.Evaluator.EvaluatePredictionResolution(
		ctx,
		observation.MarketID,
		observation.RulesHash,
		cloneArchivedEvidenceSet(evidence),
	)
	if err != nil {
		return nil, err
	}
	if counterOutcome > protocol.OutcomeInvalid {
		return nil, errors.New("prediction resolution evaluator returned an invalid outcome")
	}
	if counterOutcome == observation.ProposedOutcome {
		return nil, nil
	}
	marketID, marketErr := protocol.ParseHash32(observation.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(observation.RulesHash)
	proposalHash, proposalErr := protocol.ParseHash32(observation.ProposedStatementHash)
	if marketErr != nil || rulesErr != nil || proposalErr != nil {
		return nil, errors.New("prediction challenge binding hash is invalid")
	}
	entries := make([]protocol.EvidenceEntryV1, len(evidence))
	for index := range evidence {
		entries[index] = evidence[index].Entry
	}
	manifest, err := protocol.BuildPredictionChallengeEvidenceManifestCell(
		protocol.PredictionChallengeEvidenceManifestV1{
			MarketID:              marketID,
			RulesHash:             rulesHash,
			ProposedStatementHash: proposalHash,
			CounterOutcome:        counterOutcome,
			Entries:               entries,
		},
	)
	if err != nil {
		return nil, err
	}
	required, ok := add64(watcher.Profile.ChallengeBond, watcher.Profile.ChallengeProcessingFee)
	if !ok {
		return nil, errors.New("prediction challenge value overflows")
	}
	required, ok = add64(required, watcher.Profile.OperationBudget)
	if !ok {
		return nil, errors.New("prediction challenge value overflows")
	}
	profileDigest, err := codec.Digest("tos.prediction.challenge-watcher-profile.v1", watcher.Profile)
	if err != nil {
		return nil, err
	}
	record := oracleChallengeRecord{
		ProposedStatementHash: observation.ProposedStatementHash,
		ProposedOutcome:       observation.ProposedOutcome,
		CounterOutcome:        counterOutcome,
		CounterEvidenceRoot:   hash32(manifest.Hash()).CellHashString(),
		EvidenceManifestBOC:   base64.StdEncoding.EncodeToString(manifest.ToBOC()),
		ChallengeDeadline:     observation.ChallengeDeadline,
		FinalityViewID:        observation.FinalityViewID,
		WatcherProfileDigest:  profileDigest,
		RequiredMessageValue:  required,
		ArchiveReceiptDigests: receiptDigests,
	}
	watcher.Journal.mu.Lock()
	defer watcher.Journal.mu.Unlock()
	if watcher.Journal.lock == nil {
		return nil, errors.New("prediction oracle journal closed while preparing challenge")
	}
	if prior, ok := watcher.Journal.doc.Challenges[observation.ProposedStatementHash]; ok {
		if !reflect.DeepEqual(prior, record) {
			return nil, errors.New("prediction challenge conflicts with the durable counter statement")
		}
		return challengePlan(prior), nil
	}
	if len(watcher.Journal.doc.Challenges) != 0 {
		return nil, errors.New("prediction oracle journal already tracks another challenge")
	}
	next := cloneOracleDocument(watcher.Journal.doc)
	next.Revision++
	next.Challenges[record.ProposedStatementHash] = record
	if err := watcher.Journal.persist(next); err != nil {
		return nil, err
	}
	watcher.Journal.doc = next
	return challengePlan(record), nil
}

func validateChallengeWatcherProfile(profile ChallengeWatcherProfile) error {
	if !canonicalDigest(profile.NetworkDomainHash, "sha256:") ||
		!canonicalDigest(profile.MarketConfigHash, "tvm-cell-sha256:") ||
		!canonicalDigest(profile.ContractCodeHash, "tvm-cell-sha256:") ||
		profile.ChallengeBond == 0 || profile.ChallengeProcessingFee == 0 || profile.OperationBudget == 0 ||
		profile.MaximumSnapshotAge == 0 || profile.MaximumSnapshotAge > 300 {
		return errors.New("invalid prediction challenge watcher profile")
	}
	return nil
}

func validateProposedObservation(
	observation ProposedMarketObservation,
	profile ChallengeWatcherProfile,
	oracle OracleProfile,
	now uint64,
) error {
	if !observation.QuorumFinalized || observation.Status != proposedMarketStatus ||
		observation.NetworkDomainHash != profile.NetworkDomainHash ||
		observation.MarketID != oracle.MarketID || observation.MarketAddress != oracle.MarketAddress ||
		observation.RulesHash != oracle.RulesHash || observation.MarketConfigHash != profile.MarketConfigHash ||
		observation.ContractCodeHash != profile.ContractCodeHash || observation.ProposedOutcome > protocol.OutcomeInvalid ||
		!canonicalDigest(observation.ProposedStatementHash, "tvm-cell-sha256:") ||
		!canonicalDigest(observation.FinalityViewID, "sha256:") || observation.ChallengeDeadline <= now ||
		observation.ObservedAt == 0 || observation.ObservedAt > now ||
		now-observation.ObservedAt > profile.MaximumSnapshotAge {
		return errors.New("prediction proposal observation is stale or outside the admitted market")
	}
	return nil
}

func challengePlan(record oracleChallengeRecord) *ChallengePlan {
	manifest, _ := base64.StdEncoding.DecodeString(record.EvidenceManifestBOC)
	return &ChallengePlan{
		ProposedStatementHash: record.ProposedStatementHash,
		ProposedOutcome:       record.ProposedOutcome,
		CounterOutcome:        record.CounterOutcome,
		CounterEvidenceRoot:   record.CounterEvidenceRoot,
		EvidenceManifestBOC:   manifest,
		RequiredMessageValue:  record.RequiredMessageValue,
		ChallengeDeadline:     record.ChallengeDeadline,
		FinalityViewID:        record.FinalityViewID,
		ArchiveReceiptDigests: append([]string(nil), record.ArchiveReceiptDigests...),
	}
}

func cloneArchivedEvidenceSet(values []ArchivedEvidence) []ArchivedEvidence {
	result := make([]ArchivedEvidence, len(values))
	for index := range values {
		result[index] = cloneArchivedEvidence(values[index])
	}
	return result
}
