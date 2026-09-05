package earning

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

const predictionMarketChainViewSchema = "tos.prediction-market-chain-view.v1"

// PredictionOracleContextObservation is a quorum-reproduced, read-only input
// to OracleJournal.PrepareVote. The BOCs are exact contract-built cells, not a
// local reconstruction from display fields.
type PredictionOracleContextObservation struct {
	RoundContextBOC       []byte
	ReviewBaseContextBOC  []byte
	RoundContextHash      string
	ReviewBaseContextHash string
	Status                string
	ReviewReason          uint8
	NextDeadline          uint64
	AgreeingObserverIDs   []string
	Checkpoints           []PredictionOracleCheckpoint
}

type PredictionOracleCheckpoint struct {
	ObserverID string
	Seqno      uint32
	RootHash   string
	FileHash   string
}

type tosctlPredictionMarketChainView struct {
	Schema        string `json:"schema"`
	Address       string `json:"address"`
	GlobalVersion uint32 `json:"global_version"`
	Checkpoint    struct {
		Seqno    uint32 `json:"seqno"`
		RootHash string `json:"root_hash"`
		FileHash string `json:"file_hash"`
	} `json:"checkpoint"`
	CodeHashVerified           bool    `json:"code_hash_verified"`
	ConfigHashVerified         bool    `json:"config_hash_verified"`
	Activated                  bool    `json:"activated"`
	ActivatedAt                uint64  `json:"activated_at"`
	Status                     string  `json:"status"`
	ReviewReason               uint8   `json:"review_reason"`
	FinalOutcome               *string `json:"final_outcome"`
	MarketID                   string  `json:"market_id"`
	MarketConfigHash           string  `json:"market_config_hash"`
	Participants               uint32  `json:"participants"`
	LiveOrders                 uint32  `json:"live_orders"`
	FillCount                  uint64  `json:"fill_count"`
	CompleteSets               uint64  `json:"complete_sets"`
	TotalFree                  uint64  `json:"total_free"`
	Locked                     uint64  `json:"locked"`
	FinalBacking               uint64  `json:"final_backing"`
	RemainingPayout            uint64  `json:"remaining_payout"`
	Claimed                    uint64  `json:"claimed"`
	ChallengeBond              uint64  `json:"challenge_bond"`
	CleanupLiability           uint64  `json:"cleanup_liability"`
	CurrentContextHash         string  `json:"current_context_hash"`
	CurrentContextBOCBase64    *string `json:"current_context_boc_base64"`
	ReviewBaseContextHash      string  `json:"review_base_context_hash"`
	ReviewBaseContextBOCBase64 *string `json:"review_base_context_boc_base64"`
	ProposedStatementHash      string  `json:"proposed_statement_hash"`
	NextDeadline               uint64  `json:"next_deadline"`
}

type verifiedPredictionOracleView struct {
	roundContext []byte
	reviewBase   []byte
	contextHash  protocol.Hash32
	baseHash     protocol.Hash32
	status       string
	reviewReason uint8
	deadline     uint64
	checkpoint   PredictionOracleCheckpoint
}

// ObservePredictionOracleContext reads the exact current vote context from
// every owner-pinned RPC configuration and returns only a threshold-identical
// view. Each endpoint is network-domain checked before it may vote.
func (sink *TOSCTLPaymentSink) ObservePredictionOracleContext(ctx context.Context,
	marketDefinitionJSON []byte, profile prediction.OracleProfile,
) (PredictionOracleContextObservation, error) {
	if len(marketDefinitionJSON) == 0 || len(marketDefinitionJSON) > maximumPredictionBuilderInputBytes {
		return PredictionOracleContextObservation{}, errors.New("prediction Oracle market definition is invalid")
	}
	if err := sink.validatePredictionSourceResolver(ctx); err != nil {
		return PredictionOracleContextObservation{}, err
	}
	relay, ok := sink.PredictionRelayJournal.Profile()
	configs := append([]string{sink.ConfigPath}, sink.QuorumConfigPaths...)
	profileMarketID, profileMarketErr := protocol.ParseHash32(profile.MarketID)
	relayMarketID, relayMarketErr := protocol.ParseHash32(relay.MarketID)
	if !ok || profile.GlobalID != sink.NetworkGlobalID || relay.MarketAddress != profile.MarketAddress ||
		profileMarketErr != nil || relayMarketErr != nil || profileMarketID != relayMarketID ||
		len(relay.ObserverIDs) != len(configs) ||
		relay.QuorumThreshold < 2 || relay.QuorumThreshold > uint32(len(configs)) {
		return PredictionOracleContextObservation{}, errors.New("prediction Oracle observer trust domain is invalid")
	}
	definitionPath, cleanup, err := sink.writePrivateBytes(
		".prediction-oracle-market-*.json", marketDefinitionJSON,
	)
	if err != nil {
		return PredictionOracleContextObservation{}, err
	}
	defer cleanup()

	groups := make(map[[sha256.Size]byte][]verifiedPredictionOracleView)
	for index, configPath := range configs {
		if err := sink.verifyRelayNetworkDomainAt(ctx, *sink.RelayNetworkDomain, configPath); err != nil {
			continue
		}
		raw, runErr := sink.run(ctx, []string{
			"agent", "prediction", "show", "--definition", definitionPath, "-c", configPath,
		})
		if runErr != nil {
			continue
		}
		view, verifyErr := verifyPredictionOracleChainView(raw, profile, relay)
		if verifyErr != nil {
			continue
		}
		view.checkpoint.ObserverID = relay.ObserverIDs[index]
		groups[predictionOracleViewDigest(view)] = append(
			groups[predictionOracleViewDigest(view)], view,
		)
	}
	var selected []verifiedPredictionOracleView
	for _, group := range groups {
		if len(group) >= int(relay.QuorumThreshold) && len(group) > len(selected) {
			selected = group
		}
	}
	if len(selected) < int(relay.QuorumThreshold) {
		return PredictionOracleContextObservation{}, errors.New(
			"prediction Oracle context did not reach the pinned RPC quorum",
		)
	}
	first := selected[0]
	observation := PredictionOracleContextObservation{
		RoundContextBOC:       append([]byte(nil), first.roundContext...),
		ReviewBaseContextBOC:  append([]byte(nil), first.reviewBase...),
		RoundContextHash:      first.contextHash.CellHashString(),
		ReviewBaseContextHash: optionalCellHash(first.baseHash, len(first.reviewBase) != 0),
		Status:                first.status, ReviewReason: first.reviewReason, NextDeadline: first.deadline,
	}
	for _, view := range selected {
		observation.AgreeingObserverIDs = append(
			observation.AgreeingObserverIDs, view.checkpoint.ObserverID,
		)
		observation.Checkpoints = append(observation.Checkpoints, view.checkpoint)
	}
	sort.Strings(observation.AgreeingObserverIDs)
	sort.Slice(observation.Checkpoints, func(i, j int) bool {
		return observation.Checkpoints[i].ObserverID < observation.Checkpoints[j].ObserverID
	})
	return observation, nil
}

func verifyPredictionOracleChainView(raw []byte, profile prediction.OracleProfile,
	relay prediction.PredictionRelayProfile,
) (verifiedPredictionOracleView, error) {
	var wire tosctlPredictionMarketChainView
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return verifiedPredictionOracleView{}, errors.New("decode strict Prediction market chain view")
	}
	marketID, marketErr := protocol.ParseHash32(profile.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(profile.RulesHash)
	if marketErr != nil || rulesErr != nil || marketID.IsZero() || rulesHash.IsZero() ||
		wire.Schema != predictionMarketChainViewSchema || wire.Address != profile.MarketAddress ||
		wire.Address != relay.MarketAddress || !wire.Activated || !wire.CodeHashVerified ||
		!wire.ConfigHashVerified || wire.GlobalVersion < 14 || wire.MarketID != hex.EncodeToString(marketID[:]) ||
		wire.MarketConfigHash != trimCellHash(relay.MarketConfigHash) || wire.Checkpoint.Seqno == 0 ||
		!canonicalRawHash(wire.Checkpoint.RootHash) || !canonicalRawHash(wire.Checkpoint.FileHash) {
		return verifiedPredictionOracleView{}, errors.New("Prediction market chain view conflicts with its immutable profile")
	}
	roundBOC, contextHash, err := decodeChainViewCell(wire.CurrentContextBOCBase64, wire.CurrentContextHash, true)
	if err != nil {
		return verifiedPredictionOracleView{}, err
	}
	baseRequired := profile.Round == protocol.RoundAppeal
	baseBOC, baseHash, err := decodeChainViewCell(
		wire.ReviewBaseContextBOCBase64, wire.ReviewBaseContextHash, baseRequired,
	)
	if err != nil {
		return verifiedPredictionOracleView{}, err
	}
	roundCell, err := canonicalOracleCell(roundBOC)
	if err != nil {
		return verifiedPredictionOracleView{}, err
	}
	switch profile.Round {
	case protocol.RoundNormal:
		decoded, decodeErr := protocol.DecodePredictionNormalContextV1(roundCell)
		if decodeErr != nil || wire.Status != "reporting" || wire.ReviewReason != 0 ||
			len(baseBOC) != 0 || wire.ProposedStatementHash != zeroRawHash() ||
			decoded.MarketID != marketID || decoded.RulesHash != rulesHash ||
			decoded.OracleVoteDeadline != wire.NextDeadline {
			return verifiedPredictionOracleView{}, errors.New("normal Oracle context conflicts with the market view")
		}
	case protocol.RoundAppeal:
		baseCell, canonicalBaseErr := canonicalOracleCell(baseBOC)
		if canonicalBaseErr != nil {
			return verifiedPredictionOracleView{}, canonicalBaseErr
		}
		vote, voteErr := protocol.DecodePredictionReviewVoteContextV1(roundCell)
		base, baseErr := protocol.DecodePredictionReviewBaseContextV1(baseCell)
		if voteErr != nil || baseErr != nil || wire.Status != "reviewing" ||
			uint8(base.Reason) != wire.ReviewReason || wire.ReviewReason > 1 ||
			(wire.ReviewReason == 0 && wire.ProposedStatementHash != zeroRawHash()) ||
			(wire.ReviewReason == 1 && !canonicalRawHash(wire.ProposedStatementHash)) ||
			base.MarketID != marketID || base.RulesHash != rulesHash ||
			vote.ReviewBaseContextHash != baseHash || base.AppealDeadline != wire.NextDeadline {
			return verifiedPredictionOracleView{}, errors.New("appellate Oracle context conflicts with the market view")
		}
	default:
		return verifiedPredictionOracleView{}, errors.New("unsupported prediction Oracle round")
	}
	return verifiedPredictionOracleView{
		roundContext: roundBOC, reviewBase: baseBOC, contextHash: contextHash, baseHash: baseHash,
		status: wire.Status, reviewReason: wire.ReviewReason, deadline: wire.NextDeadline,
		checkpoint: PredictionOracleCheckpoint{
			Seqno: wire.Checkpoint.Seqno, RootHash: wire.Checkpoint.RootHash,
			FileHash: wire.Checkpoint.FileHash,
		},
	}, nil
}

func decodeChainViewCell(encoded *string, claimed string, required bool) ([]byte, protocol.Hash32, error) {
	if encoded == nil {
		if required || claimed != zeroRawHash() {
			return nil, protocol.Hash32{}, errors.New("required Prediction context cell is absent")
		}
		return nil, protocol.Hash32{}, nil
	}
	if !required && claimed == zeroRawHash() {
		return nil, protocol.Hash32{}, errors.New("unexpected Prediction context cell is present")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(*encoded)
	if err != nil {
		return nil, protocol.Hash32{}, errors.New("Prediction context cell base64 is invalid")
	}
	root, err := canonicalOracleCell(raw)
	if err != nil {
		return nil, protocol.Hash32{}, err
	}
	hash := oracleCellHash(root)
	if claimed != hex.EncodeToString(hash[:]) {
		return nil, protocol.Hash32{}, errors.New("Prediction context cell hash mismatch")
	}
	return append([]byte(nil), raw...), hash, nil
}

func predictionOracleViewDigest(view verifiedPredictionOracleView) [sha256.Size]byte {
	wire := struct {
		RoundContext []byte `json:"round_context"`
		ReviewBase   []byte `json:"review_base"`
		Status       string `json:"status"`
		ReviewReason uint8  `json:"review_reason"`
		Deadline     uint64 `json:"deadline"`
	}{view.roundContext, view.reviewBase, view.status, view.reviewReason, view.deadline}
	raw, _ := json.Marshal(wire)
	return sha256.Sum256(raw)
}

func canonicalRawHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(raw) != value {
		return false
	}
	for _, item := range raw {
		if item != 0 {
			return true
		}
	}
	return false
}

func trimCellHash(value string) string {
	const prefix = "tvm-cell-sha256:"
	if len(value) == len(prefix)+64 && value[:len(prefix)] == prefix {
		return value[len(prefix):]
	}
	return ""
}

func optionalCellHash(value protocol.Hash32, present bool) string {
	if !present {
		return ""
	}
	return value.CellHashString()
}

func zeroRawHash() string { return strings.Repeat("0", 64) }
