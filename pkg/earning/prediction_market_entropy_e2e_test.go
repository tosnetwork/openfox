package earning

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/chain"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	predictionEntropyDistributionGate = "OPENFOX_PREDICTION_ENTROPY_DISTRIBUTION_THREE_NODE_E2E"
	predictionMasterchainShard        = "-9223372036854775808"
	predictionEntropyMinimumSamples   = 32
	predictionEntropyMaximumSamples   = 256
	maxPredictionEntropyRPCBody       = int64(1 << 20)
)

type predictionEntropyRPC interface {
	Call(context.Context, string, interface{}, interface{}) error
}

type predictionEntropyNode struct {
	operatorID string
	client     predictionEntropyRPC
}

type predictionEntropyBlockID struct {
	Type      string `json:"@type"`
	Workchain int32  `json:"workchain"`
	Shard     string `json:"shard"`
	Seqno     uint64 `json:"seqno"`
	RootHash  string `json:"root_hash"`
	FileHash  string `json:"file_hash"`
}

type predictionEntropyMasterchainInfo struct {
	Type          string                   `json:"@type"`
	Last          predictionEntropyBlockID `json:"last"`
	Init          predictionEntropyBlockID `json:"init"`
	StateRootHash string                   `json:"state_root_hash"`
}

type predictionEntropyConsensus struct {
	Type           string `json:"@type"`
	ConsensusBlock uint64 `json:"consensus_block"`
	Timestamp      int64  `json:"timestamp"`
	LastBlockUtime int64  `json:"last_block_utime"`
}

type predictionEntropyValidatorJSON struct {
	PublicKey        string `json:"public_key"`
	ADNLAddress      string `json:"adnl_address"`
	Weight           string `json:"weight"`
	CumulativeWeight string `json:"cumulative_weight"`
}

type predictionEntropyValidatorSetJSON struct {
	UTimeSince  uint64                           `json:"utime_since"`
	UTimeUntil  uint64                           `json:"utime_until"`
	Total       uint16                           `json:"total"`
	Main        uint16                           `json:"main"`
	TotalWeight string                           `json:"total_weight"`
	Validators  []predictionEntropyValidatorJSON `json:"validators"`
}

type predictionEntropyConfigInfo struct {
	Type   string `json:"@type"`
	Config struct {
		Type  string `json:"@type"`
		Bytes string `json:"bytes"`
	} `json:"config"`
	ValidatorSet predictionEntropyValidatorSetJSON `json:"validator_set"`
}

type predictionEntropyValidator struct {
	PublicKey        string `json:"public_key"`
	ADNLAddress      string `json:"adnl_address"`
	Weight           uint64 `json:"weight"`
	CumulativeWeight uint64 `json:"cumulative_weight"`
}

type predictionEntropyValidatorSet struct {
	ConfigCellHash string                       `json:"config_cell_hash"`
	UTimeSince     uint64                       `json:"utime_since"`
	UTimeUntil     uint64                       `json:"utime_until"`
	Total          uint16                       `json:"total"`
	Main           uint16                       `json:"main"`
	TotalWeight    uint64                       `json:"total_weight"`
	Validators     []predictionEntropyValidator `json:"validators"`
}

type predictionEntropyObserverSnapshot struct {
	ObserverID       string `json:"observer_id"`
	ConsensusSeqno   uint64 `json:"consensus_seqno"`
	LastSeqno        uint64 `json:"last_seqno"`
	LastBlockUtime   int64  `json:"last_block_utime"`
	ValidatorSetHash string `json:"validator_set_hash"`
}

type predictionEntropyBlock struct {
	Seqno    uint64 `json:"seqno"`
	RootHash string `json:"root_hash"`
	FileHash string `json:"file_hash"`
	Parity   string `json:"parity"`
}

type predictionEntropyDistributionReport struct {
	Schema            string                              `json:"schema"`
	Verdict           string                              `json:"verdict"`
	ObservedAt        string                              `json:"observed_at"`
	SelectionRule     string                              `json:"selection_rule"`
	NetworkDomain     agentrelay.NetworkDomain            `json:"network_domain"`
	NetworkDomainHash string                              `json:"network_domain_hash"`
	SampleStartSeqno  uint64                              `json:"sample_start_seqno"`
	SampleEndSeqno    uint64                              `json:"sample_end_seqno"`
	SampleCount       uint32                              `json:"sample_count"`
	EvenCount         uint32                              `json:"even_count"`
	OddCount          uint32                              `json:"odd_count"`
	ObserverSnapshots []predictionEntropyObserverSnapshot `json:"observer_snapshots"`
	ValidatorSet      predictionEntropyValidatorSet       `json:"validator_set"`
	Blocks            []predictionEntropyBlock            `json:"blocks"`
}

type predictionEntropyNodeState struct {
	snapshot   predictionEntropyObserverSnapshot
	validators predictionEntropyValidatorSet
}

type fixedPredictionEntropyBlockRPC struct {
	rootByte byte
	fileByte byte
}

func (rpc fixedPredictionEntropyBlockRPC) Call(_ context.Context, method string, params, result interface{}) error {
	if method != "lookupBlock" {
		return errors.New("unexpected entropy test RPC method")
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	var request struct {
		Workchain int32  `json:"workchain"`
		Shard     string `json:"shard"`
		Seqno     uint64 `json:"seqno"`
	}
	if decodeStrictJSON(raw, &request) != nil || request.Workchain != -1 ||
		request.Shard != predictionMasterchainShard || request.Seqno != 91 {
		return errors.New("entropy test RPC received the wrong exact block request")
	}
	wire, ok := result.(*predictionEntropyBlockID)
	if !ok {
		return errors.New("entropy test RPC received the wrong result type")
	}
	wire.Type, wire.Workchain, wire.Shard, wire.Seqno = "tos.blockIdExt", -1, predictionMasterchainShard, request.Seqno
	wire.RootHash = base64.StdEncoding.EncodeToString(bytesOf(rpc.rootByte, sha256.Size))
	wire.FileHash = base64.StdEncoding.EncodeToString(bytesOf(rpc.fileByte, sha256.Size))
	return nil
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

// TestPredictionFutureBlockEntropyDistributionThreeNodeReleaseGate samples a
// contiguous window chosen from finalized height before any block hash is read.
// It is intentionally separate from the future-height wager gate: historical
// distribution evidence can qualify a subject, but can never settle a wager.
func TestPredictionFutureBlockEntropyDistributionThreeNodeReleaseGate(t *testing.T) {
	if os.Getenv(predictionEntropyDistributionGate) != "1" {
		t.Skip("set " + predictionEntropyDistributionGate + "=1 for the live release gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	network := predictionAcceptanceNetworkDomain(t)
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	configs := acceptancePinRPCConfigs(t, []string{
		mustEnv(t, "OPENFOX_PREDICTION_TOSCTL_CONFIG_1"),
		mustEnv(t, "OPENFOX_PREDICTION_TOSCTL_CONFIG_2"),
		mustEnv(t, "OPENFOX_PREDICTION_TOSCTL_CONFIG_3"),
	})
	nodes := predictionEntropyNodes(t, configs)
	count := predictionEntropySampleCount(t)
	states := make([]predictionEntropyNodeState, len(nodes))
	minimumFinalized := ^uint64(0)
	for index, node := range nodes {
		state, readErr := readPredictionEntropyNodeState(ctx, node, network)
		if readErr != nil {
			t.Fatalf("read Prediction entropy observer %d: %v", index+1, readErr)
		}
		states[index] = state
		if state.snapshot.ConsensusSeqno < minimumFinalized {
			minimumFinalized = state.snapshot.ConsensusSeqno
		}
	}
	if minimumFinalized < uint64(count) {
		t.Fatal("Prediction chain does not have enough finalized blocks for the distribution gate")
	}
	validatorSet := states[0].validators
	for _, state := range states[1:] {
		if state.validators.ConfigCellHash != validatorSet.ConfigCellHash {
			t.Fatal("Prediction entropy observers disagree on ConfigParam 34")
		}
	}
	start := minimumFinalized - uint64(count) + 1
	blocks := make([]predictionEntropyBlock, 0, count)
	var even, odd uint32
	for seqno := start; seqno <= minimumFinalized; seqno++ {
		block, readErr := readPredictionEntropyBlockQuorum(ctx, nodes, seqno)
		if readErr != nil {
			t.Fatalf("read Prediction entropy block %d: %v", seqno, readErr)
		}
		blocks = append(blocks, block)
		if block.Parity == "EVEN" {
			even++
		} else {
			odd++
		}
	}
	if !predictionEntropyDistributionWithinBound(even, odd) {
		t.Fatalf("Prediction block-root parity distribution is outside the frozen three-sigma bound: even=%d odd=%d", even, odd)
	}
	report := predictionEntropyDistributionReport{
		Schema: "tos.openfox.prediction-entropy-distribution-three-node.v1", Verdict: "PASS",
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
		SelectionRule: "contiguous-window-ending-at-minimum-finalized-checkpoint-before-sampled-lookup-reads",
		NetworkDomain: network, NetworkDomainHash: networkDigest,
		SampleStartSeqno: start, SampleEndSeqno: minimumFinalized, SampleCount: uint32(count),
		EvenCount: even, OddCount: odd, ValidatorSet: validatorSet, Blocks: blocks,
	}
	for _, state := range states {
		report.ObserverSnapshots = append(report.ObserverSnapshots, state.snapshot)
	}
	writePredictionEntropyReport(t, report)
	t.Logf("Prediction future-block subject distribution passed: EVEN=%d ODD=%d over [%d,%d]",
		even, odd, start, minimumFinalized)
}

func TestPredictionFutureBlockEntropyDistributionEvidenceIsSelfConsistent(t *testing.T) {
	raw := acceptanceReadBounded(t,
		"../../tests/integration/predictionmarket/evidence/future-block-entropy-distribution-three-node.json", 2<<20)
	var report predictionEntropyDistributionReport
	if decodeStrictJSON(raw, &report) != nil {
		t.Fatal("decode committed Prediction entropy distribution evidence")
	}
	if err := validatePredictionEntropyDistributionReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestPredictionFutureBlockEntropyRequiresThreeExactBlockIDs(t *testing.T) {
	nodes := []predictionEntropyNode{
		{operatorID: "one", client: fixedPredictionEntropyBlockRPC{rootByte: 2, fileByte: 3}},
		{operatorID: "two", client: fixedPredictionEntropyBlockRPC{rootByte: 2, fileByte: 3}},
		{operatorID: "three", client: fixedPredictionEntropyBlockRPC{rootByte: 2, fileByte: 3}},
	}
	block, err := readPredictionEntropyBlockQuorum(t.Context(), nodes, 91)
	if err != nil || block.Parity != "EVEN" || block.Seqno != 91 {
		t.Fatalf("valid exact three-node block failed: block=%+v err=%v", block, err)
	}
	nodes[2].client = fixedPredictionEntropyBlockRPC{rootByte: 4, fileByte: 3}
	if _, err := readPredictionEntropyBlockQuorum(t.Context(), nodes, 91); err == nil {
		t.Fatal("conflicting third Prediction block identity reached entropy selection")
	}
	nodes[2].client = fixedPredictionEntropyBlockRPC{rootByte: 2, fileByte: 4}
	if _, err := readPredictionEntropyBlockQuorum(t.Context(), nodes, 91); err == nil {
		t.Fatal("conflicting third Prediction block file hash reached entropy selection")
	}
}

func predictionAcceptanceNetworkDomain(t *testing.T) agentrelay.NetworkDomain {
	t.Helper()
	globalID, err := strconv.ParseInt(mustEnv(t, "OPENFOX_PREDICTION_GLOBAL_ID"), 10, 32)
	if err != nil || globalID == 0 {
		t.Fatal("OPENFOX_PREDICTION_GLOBAL_ID must be a nonzero int32")
	}
	workchainID, err := strconv.ParseInt(mustEnv(t, "OPENFOX_PREDICTION_WORKCHAIN_ID"), 10, 32)
	if err != nil {
		t.Fatal("OPENFOX_PREDICTION_WORKCHAIN_ID must be an int32")
	}
	rootHash, err := canonicalTOSZeroStateHash(mustEnv(t, "OPENFOX_PREDICTION_ZERO_STATE_ROOT_HASH"))
	if err != nil {
		t.Fatal(err)
	}
	fileHash, err := canonicalTOSZeroStateHash(mustEnv(t, "OPENFOX_PREDICTION_ZERO_STATE_FILE_HASH"))
	if err != nil {
		t.Fatal(err)
	}
	return agentrelay.NetworkDomain{
		NetworkID: mustEnv(t, "OPENFOX_PREDICTION_NETWORK_ID"), GlobalID: int32(globalID),
		ZeroStateRootHash: rootHash, ZeroStateFileHash: fileHash, WorkchainID: int32(workchainID),
	}
}

func predictionEntropyNodes(t *testing.T, configs []predictionAcceptanceConfig) []predictionEntropyNode {
	t.Helper()
	if len(configs) != 3 {
		t.Fatal("Prediction entropy gate requires exactly three observer configs")
	}
	nodes := make([]predictionEntropyNode, 0, len(configs))
	for _, config := range configs {
		client, err := chain.NewClient(config.endpoint, 8*time.Second, maxPredictionEntropyRPCBody)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, predictionEntropyNode{operatorID: config.operatorID, client: client})
	}
	return nodes
}

func predictionEntropySampleCount(t *testing.T) int {
	t.Helper()
	raw := os.Getenv("OPENFOX_PREDICTION_ENTROPY_SAMPLE_COUNT")
	value := strings.TrimSpace(raw)
	if value == "" {
		return 48
	}
	if value != raw {
		t.Fatal("OPENFOX_PREDICTION_ENTROPY_SAMPLE_COUNT must use canonical decimal encoding")
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < predictionEntropyMinimumSamples || count > predictionEntropyMaximumSamples {
		t.Fatalf("OPENFOX_PREDICTION_ENTROPY_SAMPLE_COUNT must be in [%d,%d]",
			predictionEntropyMinimumSamples, predictionEntropyMaximumSamples)
	}
	return count
}

func readPredictionEntropyNodeState(ctx context.Context, node predictionEntropyNode,
	network agentrelay.NetworkDomain,
) (predictionEntropyNodeState, error) {
	var result predictionEntropyNodeState
	var master predictionEntropyMasterchainInfo
	if err := node.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
		return result, err
	}
	if master.Type != "blocks.masterchainInfo" || !validPredictionMasterchainBlockID(master.Last, false) ||
		!validPredictionMasterchainBlockID(master.Init, true) {
		return result, errors.New("malformed Prediction masterchain response")
	}
	if _, err := predictionRPCDigest(master.Last.RootHash); err != nil {
		return result, errors.New("Prediction masterchain tip root is malformed")
	}
	if _, err := predictionRPCDigest(master.Last.FileHash); err != nil {
		return result, errors.New("Prediction masterchain tip file hash is malformed")
	}
	if _, err := predictionRPCDigest(master.StateRootHash); err != nil {
		return result, errors.New("Prediction masterchain state root is malformed")
	}
	root, err := predictionRPCDigest(master.Init.RootHash)
	if err != nil || root != network.ZeroStateRootHash {
		return result, errors.New("Prediction entropy observer has the wrong zero-state root")
	}
	file, err := predictionRPCDigest(master.Init.FileHash)
	if err != nil || file != network.ZeroStateFileHash {
		return result, errors.New("Prediction entropy observer has the wrong zero-state file")
	}
	var consensus predictionEntropyConsensus
	if err := node.client.Call(ctx, "getConsensusBlock", struct{}{}, &consensus); err != nil {
		return result, err
	}
	now := time.Now().UTC().Unix()
	if consensus.Type != "ext.blocks.consensusBlock" || consensus.ConsensusBlock == 0 ||
		consensus.ConsensusBlock > master.Last.Seqno || consensus.LastBlockUtime <= 0 ||
		consensus.Timestamp <= 0 || consensus.LastBlockUtime > consensus.Timestamp+120 ||
		consensus.LastBlockUtime < now-120 || consensus.LastBlockUtime > now+120 {
		return result, errors.New("stale or malformed Prediction consensus response")
	}
	validators, err := readPredictionEntropyValidatorSet(ctx, node.client)
	if err != nil {
		return result, err
	}
	if validators.UTimeSince > uint64(consensus.LastBlockUtime) ||
		validators.UTimeUntil <= uint64(consensus.LastBlockUtime) {
		return result, errors.New("Prediction ConfigParam 34 is not active at the finalized observation")
	}
	result.snapshot = predictionEntropyObserverSnapshot{
		ObserverID: node.operatorID, ConsensusSeqno: consensus.ConsensusBlock,
		LastSeqno: master.Last.Seqno, LastBlockUtime: consensus.LastBlockUtime,
		ValidatorSetHash: validators.ConfigCellHash,
	}
	result.validators = validators
	return result, nil
}

func readPredictionEntropyValidatorSet(ctx context.Context, client predictionEntropyRPC) (predictionEntropyValidatorSet, error) {
	var response predictionEntropyConfigInfo
	if err := client.Call(ctx, "getConfigParam", struct {
		Param int `json:"param"`
	}{34}, &response); err != nil {
		return predictionEntropyValidatorSet{}, err
	}
	if response.Type != "configInfo" || response.Config.Type != "tvm.cell" || response.Config.Bytes == "" {
		return predictionEntropyValidatorSet{}, errors.New("invalid Prediction ConfigParam 34 response")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(response.Config.Bytes)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != response.Config.Bytes {
		return predictionEntropyValidatorSet{}, errors.New("non-canonical Prediction ConfigParam 34 BOC")
	}
	root, err := cell.FromBOC(raw)
	if err != nil {
		return predictionEntropyValidatorSet{}, errors.New("invalid Prediction ConfigParam 34 BOC")
	}
	rootSlice, err := root.BeginParse()
	if err != nil {
		return predictionEntropyValidatorSet{}, errors.New("invalid Prediction ConfigParam 34 root cell")
	}
	var parsed tlb.ValidatorSetAny
	if err := tlb.LoadFromCell(&parsed, rootSlice); err != nil {
		return predictionEntropyValidatorSet{}, errors.New("cannot decode Prediction ConfigParam 34")
	}
	result := predictionEntropyValidatorSet{
		ConfigCellHash: "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()),
		UTimeSince:     response.ValidatorSet.UTimeSince, UTimeUntil: response.ValidatorSet.UTimeUntil,
		Total: response.ValidatorSet.Total, Main: response.ValidatorSet.Main,
	}
	var dictionary *cell.Dictionary
	var encodedTotalWeight uint64
	switch value := parsed.Validators.(type) {
	case tlb.ValidatorSet:
		return predictionEntropyValidatorSet{}, errors.New("Prediction entropy gate requires validator ADNL identities")
	case tlb.ValidatorSetExt:
		if uint64(value.UTimeSince) != result.UTimeSince || uint64(value.UTimeUntil) != result.UTimeUntil ||
			value.Total != result.Total || value.Main != result.Main {
			return predictionEntropyValidatorSet{}, errors.New("Prediction validator JSON conflicts with its BOC")
		}
		dictionary, encodedTotalWeight = value.List, value.TotalWeight
	default:
		return predictionEntropyValidatorSet{}, errors.New("unsupported Prediction validator-set encoding")
	}
	if dictionary == nil || result.Total == 0 || result.Main == 0 || result.Main > result.Total ||
		len(response.ValidatorSet.Validators) != int(result.Total) {
		return predictionEntropyValidatorSet{}, errors.New("invalid Prediction validator-set bounds")
	}
	items, err := dictionary.LoadAll()
	if err != nil || len(items) != int(result.Total) {
		return predictionEntropyValidatorSet{}, errors.New("invalid Prediction validator dictionary")
	}
	seen := make(map[string]struct{}, len(items))
	var cumulative uint64
	for index, item := range items {
		key, loadErr := item.Key.LoadUInt(16)
		if loadErr != nil || key != uint64(index) || item.Key.BitsLeft() != 0 || item.Key.RefsNum() != 0 {
			return predictionEntropyValidatorSet{}, errors.New("non-canonical Prediction validator dictionary key")
		}
		validator, parseErr := parsePredictionEntropyValidator(item.Value.Copy())
		if parseErr != nil || validator.Weight == 0 || !canonicalRawHash(validator.PublicKey) ||
			!canonicalRawHash(validator.ADNLAddress) {
			return predictionEntropyValidatorSet{}, errors.New("invalid Prediction validator descriptor")
		}
		if _, duplicate := seen[validator.PublicKey]; duplicate {
			return predictionEntropyValidatorSet{}, errors.New("duplicate Prediction validator public key")
		}
		seen[validator.PublicKey] = struct{}{}
		validator.CumulativeWeight = cumulative
		if ^uint64(0)-cumulative < validator.Weight {
			return predictionEntropyValidatorSet{}, errors.New("Prediction validator weight overflow")
		}
		cumulative += validator.Weight
		wire := response.ValidatorSet.Validators[index]
		wireKey, keyErr := predictionRPCDigest(wire.PublicKey)
		wireADNL, adnlErr := predictionRPCDigest(wire.ADNLAddress)
		wireWeight, weightErr := canonicalPredictionUint64(wire.Weight)
		wireCumulative, cumulativeErr := canonicalPredictionUint64(wire.CumulativeWeight)
		if keyErr != nil || adnlErr != nil || weightErr != nil || cumulativeErr != nil ||
			strings.TrimPrefix(wireKey, "sha256:") != validator.PublicKey ||
			strings.TrimPrefix(wireADNL, "sha256:") != validator.ADNLAddress ||
			wireWeight != validator.Weight || wireCumulative != validator.CumulativeWeight {
			return predictionEntropyValidatorSet{}, errors.New("Prediction validator JSON conflicts with descriptor bytes")
		}
		result.Validators = append(result.Validators, validator)
	}
	wireTotal, err := canonicalPredictionUint64(response.ValidatorSet.TotalWeight)
	if err != nil || wireTotal != cumulative || encodedTotalWeight != cumulative {
		return predictionEntropyValidatorSet{}, errors.New("Prediction validator total weight is inconsistent")
	}
	result.TotalWeight = cumulative
	return result, nil
}

func parsePredictionEntropyValidator(value *cell.Slice) (predictionEntropyValidator, error) {
	if value == nil {
		return predictionEntropyValidator{}, errors.New("missing validator descriptor")
	}
	peek := value.Copy()
	tag, err := peek.LoadUInt(8)
	if err != nil {
		return predictionEntropyValidator{}, err
	}
	var key, adnl []byte
	var weight uint64
	switch tag {
	case 0x53:
		var parsed tlb.Validator
		if err := tlb.LoadFromCell(&parsed, value); err != nil {
			return predictionEntropyValidator{}, err
		}
		key, weight, adnl = parsed.PublicKey.Key, parsed.Weight, make([]byte, sha256.Size)
	case 0x73:
		var parsed tlb.ValidatorAddr
		if err := tlb.LoadFromCell(&parsed, value); err != nil {
			return predictionEntropyValidator{}, err
		}
		key, weight, adnl = parsed.PublicKey.Key, parsed.Weight, parsed.ADNLAddr
	default:
		return predictionEntropyValidator{}, errors.New("unknown validator descriptor tag")
	}
	if len(key) != sha256.Size || len(adnl) != sha256.Size {
		return predictionEntropyValidator{}, errors.New("invalid validator identity width")
	}
	return predictionEntropyValidator{
		PublicKey: hex.EncodeToString(key), ADNLAddress: hex.EncodeToString(adnl), Weight: weight,
	}, nil
}

func readPredictionEntropyBlockQuorum(ctx context.Context, nodes []predictionEntropyNode,
	seqno uint64,
) (predictionEntropyBlock, error) {
	if len(nodes) != 3 || seqno == 0 {
		return predictionEntropyBlock{}, errors.New("invalid Prediction entropy block request")
	}
	var selected predictionEntropyBlock
	for index, node := range nodes {
		var wire predictionEntropyBlockID
		if err := node.client.Call(ctx, "lookupBlock", struct {
			Workchain int32  `json:"workchain"`
			Shard     string `json:"shard"`
			Seqno     uint64 `json:"seqno"`
		}{-1, predictionMasterchainShard, seqno}, &wire); err != nil {
			return predictionEntropyBlock{}, err
		}
		if !validPredictionMasterchainBlockID(wire, false) || wire.Seqno != seqno {
			return predictionEntropyBlock{}, errors.New("Prediction lookupBlock returned the wrong block")
		}
		root, err := predictionRPCDigest(wire.RootHash)
		if err != nil {
			return predictionEntropyBlock{}, err
		}
		file, err := predictionRPCDigest(wire.FileHash)
		if err != nil {
			return predictionEntropyBlock{}, err
		}
		rootRaw, _ := hex.DecodeString(strings.TrimPrefix(root, "sha256:"))
		block := predictionEntropyBlock{
			Seqno: seqno, RootHash: strings.TrimPrefix(root, "sha256:"),
			FileHash: strings.TrimPrefix(file, "sha256:"), Parity: "ODD",
		}
		if rootRaw[0]&1 == 0 {
			block.Parity = "EVEN"
		}
		if index == 0 {
			selected = block
		} else if block != selected {
			return predictionEntropyBlock{}, errors.New("Prediction entropy observers disagree on lookupBlock")
		}
	}
	return selected, nil
}

func validPredictionMasterchainBlockID(value predictionEntropyBlockID, genesis bool) bool {
	if value.Type != "tos.blockIdExt" || value.Workchain != -1 || value.Shard != predictionMasterchainShard ||
		value.RootHash == "" || value.FileHash == "" {
		return false
	}
	if genesis {
		return value.Seqno == 0
	}
	return value.Seqno > 0
}

func predictionRPCDigest(value string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != sha256.Size || base64.StdEncoding.EncodeToString(raw) != value {
		return "", errors.New("TOS RPC hash is not canonical 32-byte Base64")
	}
	nonzero := false
	for _, item := range raw {
		nonzero = nonzero || item != 0
	}
	if !nonzero {
		return "", errors.New("TOS RPC hash is zero")
	}
	return "sha256:" + hex.EncodeToString(raw), nil
}

func canonicalPredictionUint64(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("non-canonical uint64")
	}
	return parsed, nil
}

func predictionEntropyDistributionWithinBound(even, odd uint32) bool {
	total := uint64(even) + uint64(odd)
	if total < predictionEntropyMinimumSamples || total > predictionEntropyMaximumSamples || even == 0 || odd == 0 {
		return false
	}
	difference := int64(even) - int64(odd)
	if difference < 0 {
		difference = -difference
	}
	// For a fair bit, Var(EVEN-ODD)=n. The fixed three-sigma gate rejects a
	// grossly biased subject while retaining a bounded, documented false-reject
	// probability. Integer arithmetic avoids platform-dependent float edges.
	return uint64(difference*difference) <= 9*total
}

func validatePredictionEntropyDistributionReport(report predictionEntropyDistributionReport) error {
	if report.Schema != "tos.openfox.prediction-entropy-distribution-three-node.v1" || report.Verdict != "PASS" ||
		report.SelectionRule != "contiguous-window-ending-at-minimum-finalized-checkpoint-before-sampled-lookup-reads" ||
		report.SampleCount < predictionEntropyMinimumSamples || report.SampleCount > predictionEntropyMaximumSamples ||
		len(report.Blocks) != int(report.SampleCount) || len(report.ObserverSnapshots) != 3 ||
		report.SampleEndSeqno < report.SampleStartSeqno ||
		report.SampleEndSeqno-report.SampleStartSeqno+1 != uint64(report.SampleCount) {
		return errors.New("committed Prediction entropy evidence has invalid bounds")
	}
	observedAt, err := time.Parse(time.RFC3339, report.ObservedAt)
	digest, digestErr := agentrelay.NetworkDomainDigest(report.NetworkDomain)
	if err != nil || observedAt.IsZero() || digestErr != nil || digest != report.NetworkDomainHash {
		return errors.New("committed Prediction entropy evidence has an invalid network or time")
	}
	if err := validatePredictionEntropyValidatorSet(report.ValidatorSet); err != nil {
		return err
	}
	var even, odd uint32
	previousObserver := ""
	var latestBlockTime int64
	for _, observer := range report.ObserverSnapshots {
		if !validCanonicalSHA256(observer.ObserverID) || observer.ObserverID <= previousObserver ||
			observer.ConsensusSeqno < report.SampleEndSeqno || observer.LastSeqno < observer.ConsensusSeqno ||
			observer.LastBlockUtime <= 0 || observer.ValidatorSetHash != report.ValidatorSet.ConfigCellHash {
			return errors.New("committed Prediction entropy observer snapshot is invalid")
		}
		previousObserver = observer.ObserverID
		if observer.LastBlockUtime > latestBlockTime {
			latestBlockTime = observer.LastBlockUtime
		}
	}
	if observedAt.Unix() < latestBlockTime || observedAt.Unix() > latestBlockTime+120 ||
		report.ValidatorSet.UTimeSince > uint64(latestBlockTime) ||
		report.ValidatorSet.UTimeUntil <= uint64(latestBlockTime) {
		return errors.New("committed Prediction entropy evidence time is inconsistent")
	}
	for index, block := range report.Blocks {
		if block.Seqno != report.SampleStartSeqno+uint64(index) || !canonicalRawHash(block.RootHash) ||
			!canonicalRawHash(block.FileHash) {
			return errors.New("committed Prediction entropy block is invalid")
		}
		raw, _ := hex.DecodeString(block.RootHash)
		expected := "ODD"
		if raw[0]&1 == 0 {
			expected, even = "EVEN", even+1
		} else {
			odd++
		}
		if block.Parity != expected {
			return errors.New("committed Prediction entropy parity conflicts with its root hash")
		}
	}
	if even != report.EvenCount || odd != report.OddCount ||
		!predictionEntropyDistributionWithinBound(even, odd) {
		return errors.New("committed Prediction entropy distribution is inconsistent")
	}
	return nil
}

func validatePredictionEntropyValidatorSet(value predictionEntropyValidatorSet) error {
	if !validTVMCellSHA256(value.ConfigCellHash) || value.UTimeSince == 0 || value.UTimeUntil <= value.UTimeSince ||
		value.Total == 0 || value.Main == 0 || value.Main > value.Total || len(value.Validators) != int(value.Total) {
		return errors.New("committed Prediction validator set is invalid")
	}
	seenKeys := make(map[string]struct{}, len(value.Validators))
	seenADNL := make(map[string]struct{}, len(value.Validators))
	var cumulative uint64
	for _, validator := range value.Validators {
		if !canonicalRawHash(validator.PublicKey) || !canonicalRawHash(validator.ADNLAddress) ||
			validator.Weight == 0 || validator.CumulativeWeight != cumulative {
			return errors.New("committed Prediction validator descriptor is invalid")
		}
		if _, duplicate := seenKeys[validator.PublicKey]; duplicate {
			return errors.New("committed Prediction validator public key is duplicated")
		}
		if _, duplicate := seenADNL[validator.ADNLAddress]; duplicate {
			return errors.New("committed Prediction validator ADNL identity is duplicated")
		}
		seenKeys[validator.PublicKey], seenADNL[validator.ADNLAddress] = struct{}{}, struct{}{}
		if ^uint64(0)-cumulative < validator.Weight {
			return errors.New("committed Prediction validator weight overflows")
		}
		cumulative += validator.Weight
	}
	if cumulative != value.TotalWeight {
		return errors.New("committed Prediction validator total weight is inconsistent")
	}
	return nil
}

func validCanonicalSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == "sha256:"+hex.EncodeToString(raw)
}

func writePredictionEntropyReport(t *testing.T, report predictionEntropyDistributionReport) {
	t.Helper()
	directory := mustEnv(t, "OPENFOX_PREDICTION_EVIDENCE_DIRECTORY")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("OPENFOX_PREDICTION_EVIDENCE_DIRECTORY must be absolute and clean")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatal("Prediction evidence directory must be owner-private")
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil || len(raw) > 2<<20 {
		t.Fatal("Prediction entropy report is not bounded")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	name := "future-block-entropy-distribution-three-node.json"
	if err := fileutil.WriteFileAtomicRoot(root, name, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote machine-readable Prediction entropy evidence to %s", filepath.Join(directory, name))
}

// Keep math imported in the test build as an explicit assertion that the
// integer three-sigma boundary matches its statistical definition.
func TestPredictionEntropyIntegerBoundMatchesDefinition(t *testing.T) {
	for total := predictionEntropyMinimumSamples; total <= predictionEntropyMaximumSamples; total++ {
		for even := 0; even <= total; even++ {
			odd := total - even
			integer := predictionEntropyDistributionWithinBound(uint32(even), uint32(odd))
			difference := math.Abs(float64(even - odd))
			defined := even > 0 && odd > 0 && difference <= 3*math.Sqrt(float64(total))
			if integer != defined {
				t.Fatalf("integer entropy bound diverged at even=%d odd=%d", even, odd)
			}
		}
	}
}
