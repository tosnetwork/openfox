package earning

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/prediction"
)

const predictionContextThreeNodeGate = "OPENFOX_PREDICTION_CONTEXT_THREE_NODE_E2E"

type predictionAcceptanceAuthority struct{ EconomicAuthority }

type predictionAcceptanceDefinition struct {
	GlobalID           int32  `json:"global_id"`
	WorkchainID        int32  `json:"workchain_id"`
	RulesHash          string `json:"rules_hash"`
	ClaimDeadline      uint64 `json:"claim_deadline"`
	NormalOraclePolicy struct {
		Reporters []string `json:"reporters"`
	} `json:"normal_oracle_policy"`
	AppellateOraclePolicy struct {
		Reporters []string `json:"reporters"`
	} `json:"appellate_oracle_policy"`
}

type predictionAcceptanceBuildState struct {
	Schema             string  `json:"schema"`
	Address            string  `json:"address"`
	MarketID           string  `json:"market_id"`
	MarketConfigHash   string  `json:"market_config_hash"`
	CodeHash           string  `json:"code_hash"`
	RulesHash          string  `json:"rules_hash"`
	StateInitBOCBase64 string  `json:"state_init_boc_base64"`
	OutputBOC          *string `json:"output_boc"`
}

type predictionAcceptanceConfig struct {
	path       string
	operatorID string
	endpoint   string
}

type predictionContextAcceptanceReport struct {
	Schema                string                           `json:"schema"`
	Verdict               string                           `json:"verdict"`
	ObservedAt            string                           `json:"observed_at"`
	DefinitionSHA256      string                           `json:"definition_sha256"`
	NetworkDomain         agentrelay.NetworkDomain         `json:"network_domain"`
	NetworkDomainHash     string                           `json:"network_domain_hash"`
	MarketAddress         string                           `json:"market_address"`
	MarketID              string                           `json:"market_id"`
	MarketConfigHash      string                           `json:"market_config_hash"`
	MarketCodeHash        string                           `json:"market_code_hash"`
	RulesHash             string                           `json:"rules_hash"`
	Round                 protocol.Round                   `json:"round"`
	RoundPolicyHash       string                           `json:"round_policy_hash"`
	Status                string                           `json:"status"`
	ReviewReason          uint8                            `json:"review_reason"`
	NextDeadline          uint64                           `json:"next_deadline"`
	RoundContextHash      string                           `json:"round_context_hash"`
	RoundContextBOCBase64 string                           `json:"round_context_boc_base64"`
	ReviewBaseContextHash string                           `json:"review_base_context_hash,omitempty"`
	ReviewBaseBOCBase64   string                           `json:"review_base_context_boc_base64,omitempty"`
	AgreeingObserverIDs   []string                         `json:"agreeing_observer_ids"`
	ObserverCheckpoints   []predictionAcceptanceCheckpoint `json:"observer_checkpoints"`
}

type predictionAcceptanceCheckpoint struct {
	ObserverID string `json:"observer_id"`
	Seqno      uint32 `json:"seqno"`
	RootHash   string `json:"root_hash"`
	FileHash   string `json:"file_hash"`
}

// TestPredictionOracleContextThreeNodeReleaseGate runs only when explicitly
// selected because it reads a live three-node chain. Once selected, every
// fixture is mandatory and every observation goes through the production
// executable pin, network preflight, strict chain-view decoder, and quorum.
func TestPredictionOracleContextThreeNodeReleaseGate(t *testing.T) {
	if os.Getenv(predictionContextThreeNodeGate) != "1" {
		t.Skip("set " + predictionContextThreeNodeGate + "=1 for the live release gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	executable := acceptanceRequiredAbsoluteFile(t, "OPENFOX_PREDICTION_TOSCTL")
	definitionPath := acceptanceRequiredAbsoluteFile(t, "OPENFOX_PREDICTION_MARKET_DEFINITION")
	definitionRaw := acceptanceReadBounded(t, definitionPath, 1<<20)
	var definition predictionAcceptanceDefinition
	if err := json.Unmarshal(definitionRaw, &definition); err != nil || definition.GlobalID == 0 ||
		definition.ClaimDeadline == 0 || definition.RulesHash == "" {
		t.Fatal("Prediction market definition is incomplete")
	}
	globalID, err := strconv.ParseInt(mustEnv(t, "OPENFOX_PREDICTION_GLOBAL_ID"), 10, 32)
	if err != nil || int32(globalID) != definition.GlobalID {
		t.Fatal("OPENFOX_PREDICTION_GLOBAL_ID conflicts with the market definition")
	}
	workchainID, err := strconv.ParseInt(mustEnv(t, "OPENFOX_PREDICTION_WORKCHAIN_ID"), 10, 32)
	if err != nil || int32(workchainID) != definition.WorkchainID {
		t.Fatal("OPENFOX_PREDICTION_WORKCHAIN_ID conflicts with the market definition")
	}
	rootHash, err := canonicalTOSZeroStateHash(mustEnv(t, "OPENFOX_PREDICTION_ZERO_STATE_ROOT_HASH"))
	if err != nil {
		t.Fatal(err)
	}
	fileHash, err := canonicalTOSZeroStateHash(mustEnv(t, "OPENFOX_PREDICTION_ZERO_STATE_FILE_HASH"))
	if err != nil {
		t.Fatal(err)
	}
	network := agentrelay.NetworkDomain{
		NetworkID: mustEnv(t, "OPENFOX_PREDICTION_NETWORK_ID"), GlobalID: int32(globalID),
		ZeroStateRootHash: rootHash, ZeroStateFileHash: fileHash, WorkchainID: int32(workchainID),
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		t.Fatal(err)
	}
	configs := acceptancePinRPCConfigs(t, []string{
		mustEnv(t, "OPENFOX_PREDICTION_TOSCTL_CONFIG_1"),
		mustEnv(t, "OPENFOX_PREDICTION_TOSCTL_CONFIG_2"),
		mustEnv(t, "OPENFOX_PREDICTION_TOSCTL_CONFIG_3"),
	})
	stateDirectory := privateTempDir(t)
	sink := &TOSCTLPaymentSink{
		Authority: &predictionAcceptanceAuthority{}, Executable: executable,
		ConfigPath: configs[0].path, Wallet: "prediction-context-release-gate",
		SourceAccount: "0:" + strings.Repeat("1", 64), NetworkGlobalID: int32(globalID),
		RelayNetworkDomain: &network, FeeReserveNanoTOS: 1,
		QuorumConfigPaths:             []string{configs[1].path, configs[2].path},
		PredictionMaximumTransactions: 100_000, EvidenceDirectory: stateDirectory,
		VaultURL: strings.TrimSpace(os.Getenv("OPENFOX_PREDICTION_VAULT_URL")),
	}
	sink.RelayNetworkPreflight = predictionAcceptanceNetworkPreflight(t, sink, configs, stateDirectory)
	buildRaw, err := sink.run(ctx, []string{
		"agent", "prediction", "build-state", "--definition", definitionPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	var build predictionAcceptanceBuildState
	if decodeStrictJSON(buildRaw, &build) != nil || build.Schema != "tos.prediction-market-state-init.v1" ||
		build.Address == "" || !validTVMCellSHA256(build.MarketConfigHash) ||
		!validTVMCellSHA256(build.CodeHash) || !validSHA256Digest(build.MarketID) ||
		build.RulesHash != definition.RulesHash || build.OutputBOC != nil ||
		len(build.StateInitBOCBase64) == 0 {
		t.Fatal("tosctl returned an invalid Prediction market StateInit profile")
	}
	round, reporter := acceptanceRoundAndReporter(t, definition)
	roundPolicyHash := mustEnv(t, "OPENFOX_PREDICTION_ROUND_POLICY_HASH")
	if !validTVMCellSHA256(roundPolicyHash) {
		t.Fatal("OPENFOX_PREDICTION_ROUND_POLICY_HASH is not canonical")
	}
	sink.SourceAccount = reporter
	relayProfile := prediction.PredictionRelayProfile{
		NetworkDomainHash: networkDigest, SourceAgentAccount: reporter,
		SourceAgentAccountCodeHash: mustEnv(t, "OPENFOX_PREDICTION_SOURCE_AGENT_CODE_HASH"),
		MarketAddress:              build.Address, MarketID: build.MarketID, MarketCodeHash: build.CodeHash,
		MarketConfigHash: build.MarketConfigHash,
		ObserverIDs:      []string{configs[0].operatorID, configs[1].operatorID, configs[2].operatorID},
		QuorumThreshold:  2, MaximumOutstanding: 8, MaximumSignedBOCBytes: 64 << 10,
		MinimumNoBounceMCBlocks: 8,
	}
	relayJournal, err := prediction.OpenPredictionRelayJournal(
		filepath.Join(stateDirectory, "prediction-relay"), relayProfile,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := relayJournal.Close(); closeErr != nil {
			t.Errorf("close Prediction relay journal: %v", closeErr)
		}
	}()
	sink.PredictionRelayJournal = relayJournal
	profile := prediction.OracleProfile{
		GlobalID: int32(globalID), MarketAddress: build.Address,
		MarketID:  "tvm-cell-sha256:" + strings.TrimPrefix(build.MarketID, "sha256:"),
		RulesHash: definition.RulesHash, RoundPolicyHash: roundPolicyHash,
		ReporterAddress: reporter, Round: round, ClaimDeadline: definition.ClaimDeadline,
		AuditRetention: 1,
	}
	for index, config := range configs {
		raw, runErr := sink.run(ctx, []string{
			"agent", "prediction", "show", "--definition", definitionPath, "-c", config.path,
		})
		if runErr != nil {
			t.Fatalf("read Prediction market from observer %d: %v", index+1, runErr)
		}
		if _, verifyErr := verifyPredictionOracleChainView(raw, profile, relayProfile); verifyErr != nil {
			t.Fatalf("verify Prediction market observer %d: %v", index+1, verifyErr)
		}
	}
	observation, err := sink.ObservePredictionOracleContext(ctx, definitionRaw, profile)
	if err != nil {
		t.Fatal(err)
	}
	expectedStatus := "reporting"
	if round == protocol.RoundAppeal {
		expectedStatus = "reviewing"
	}
	if observation.Status != expectedStatus || len(observation.RoundContextBOC) == 0 ||
		len(observation.AgreeingObserverIDs) != 3 || len(observation.Checkpoints) != 3 ||
		observation.RoundContextHash == "" || observation.NextDeadline == 0 {
		t.Fatalf("three-node Prediction Oracle observation is incomplete: %+v", observation)
	}
	definitionDigest := sha256.Sum256(definitionRaw)
	report := predictionContextAcceptanceReport{
		Schema: "tos.openfox.prediction-oracle-context-three-node.v1", Verdict: "PASS",
		ObservedAt:       time.Now().UTC().Format(time.RFC3339),
		DefinitionSHA256: "sha256:" + hex.EncodeToString(definitionDigest[:]),
		NetworkDomain:    network, NetworkDomainHash: networkDigest,
		MarketAddress: build.Address, MarketID: build.MarketID,
		MarketConfigHash: build.MarketConfigHash, MarketCodeHash: build.CodeHash,
		RulesHash: definition.RulesHash, Round: round, RoundPolicyHash: roundPolicyHash,
		Status: observation.Status, ReviewReason: observation.ReviewReason,
		NextDeadline: observation.NextDeadline, RoundContextHash: observation.RoundContextHash,
		RoundContextBOCBase64: base64.StdEncoding.EncodeToString(observation.RoundContextBOC),
		ReviewBaseContextHash: observation.ReviewBaseContextHash,
		ReviewBaseBOCBase64:   base64.StdEncoding.EncodeToString(observation.ReviewBaseContextBOC),
		AgreeingObserverIDs:   append([]string(nil), observation.AgreeingObserverIDs...),
		ObserverCheckpoints:   acceptanceCheckpoints(observation.Checkpoints),
	}
	acceptanceWritePredictionReport(t, report)
	t.Logf("Prediction Oracle context reached 3-of-3 agreement for %s at checkpoints %+v",
		build.Address, observation.Checkpoints)
}

func TestPredictionOracleContextThreeNodeEvidenceIsSelfConsistent(t *testing.T) {
	definitionRaw := acceptanceReadBounded(
		t, "../../tests/integration/predictionmarket/fixtures/oracle-context-market.json", 1<<20,
	)
	reportRaw := acceptanceReadBounded(
		t, "../../tests/integration/predictionmarket/evidence/oracle-context-three-node.json", 1<<20,
	)
	var report predictionContextAcceptanceReport
	if decodeStrictJSON(reportRaw, &report) != nil ||
		report.Schema != "tos.openfox.prediction-oracle-context-three-node.v1" || report.Verdict != "PASS" ||
		report.Round != protocol.RoundNormal || report.Status != "reporting" || report.ReviewReason != 0 ||
		report.ReviewBaseContextHash != "" || report.ReviewBaseBOCBase64 != "" ||
		!validSHA256Digest(report.DefinitionSHA256) || !validSHA256Digest(report.NetworkDomainHash) ||
		!validSHA256Digest(report.MarketID) || !validTVMCellSHA256(report.MarketConfigHash) ||
		!validTVMCellSHA256(report.MarketCodeHash) || !validSHA256Digest(report.RulesHash) ||
		!validTVMCellSHA256(report.RoundPolicyHash) || !validTVMCellSHA256(report.RoundContextHash) {
		t.Fatal("committed Prediction context evidence has an invalid schema or identity")
	}
	observedAt, err := time.Parse(time.RFC3339, report.ObservedAt)
	definitionDigest := sha256.Sum256(definitionRaw)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(report.NetworkDomain)
	if err != nil || observedAt.IsZero() ||
		report.DefinitionSHA256 != "sha256:"+hex.EncodeToString(definitionDigest[:]) ||
		networkErr != nil || report.NetworkDomainHash != networkDigest {
		t.Fatal("committed Prediction context evidence does not bind its definition or network")
	}
	roundBOC, err := base64.StdEncoding.Strict().DecodeString(report.RoundContextBOCBase64)
	if err != nil {
		t.Fatal(err)
	}
	roundCell, err := canonicalOracleCell(roundBOC)
	if err != nil || oracleCellHash(roundCell).CellHashString() != report.RoundContextHash {
		t.Fatal("committed Prediction context BOC does not match its hash")
	}
	contextValue, err := protocol.DecodePredictionNormalContextV1(roundCell)
	marketID, marketErr := protocol.ParseHash32(report.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(report.RulesHash)
	if err != nil || marketErr != nil || rulesErr != nil || contextValue.MarketID != marketID ||
		contextValue.RulesHash != rulesHash || contextValue.OracleVoteDeadline != report.NextDeadline {
		t.Fatal("committed Prediction context BOC conflicts with its market report")
	}
	if len(report.AgreeingObserverIDs) != 3 || len(report.ObserverCheckpoints) != 3 ||
		!sort.StringsAreSorted(report.AgreeingObserverIDs) {
		t.Fatal("committed Prediction context evidence lacks three sorted observers")
	}
	for index, observerID := range report.AgreeingObserverIDs {
		checkpoint := report.ObserverCheckpoints[index]
		if !validSHA256Digest(observerID) || checkpoint.ObserverID != observerID || checkpoint.Seqno == 0 ||
			!canonicalRawHash(checkpoint.RootHash) || !canonicalRawHash(checkpoint.FileHash) {
			t.Fatal("committed Prediction observer checkpoint is malformed")
		}
	}
}

func acceptancePinRPCConfigs(t *testing.T, sourcePaths []string) []predictionAcceptanceConfig {
	t.Helper()
	directory := privateTempDir(t)
	configs := make([]predictionAcceptanceConfig, 0, len(sourcePaths))
	seenEndpoints := make(map[string]struct{}, len(sourcePaths))
	for index, sourcePath := range sourcePaths {
		sourcePath = acceptanceAbsoluteFile(t, "Prediction tosctl config", sourcePath)
		raw := acceptanceReadBounded(t, sourcePath, 1<<20)
		var document map[string]json.RawMessage
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		var chainRPC map[string]json.RawMessage
		if err := json.Unmarshal(document["chain_rpc"], &chainRPC); err != nil {
			t.Fatal("each Prediction acceptance config must contain chain_rpc")
		}
		var urls []string
		if err := json.Unmarshal(chainRPC["urls"], &urls); err != nil || len(urls) != 1 || urls[0] == "" {
			t.Fatal("each Prediction acceptance config must pin exactly one RPC endpoint")
		}
		endpoint := urls[0]
		if _, duplicate := seenEndpoints[endpoint]; duplicate {
			t.Fatal("Prediction acceptance RPC endpoints are not distinct")
		}
		seenEndpoints[endpoint] = struct{}{}
		digest := sha256.Sum256([]byte(fmt.Sprintf(
			"tos.prediction.acceptance.rpc-operator.v1\x00%d\x00%s", index, endpoint,
		)))
		operatorID := "sha256:" + hex.EncodeToString(digest[:])
		encoded, err := json.Marshal(document)
		if err != nil || len(encoded) > 1<<20 {
			t.Fatal("Prediction acceptance config cannot be bounded and encoded")
		}
		target := filepath.Join(directory, fmt.Sprintf("node-%d.json", index+1))
		if err := os.WriteFile(target, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		configs = append(configs, predictionAcceptanceConfig{
			path: target, operatorID: operatorID, endpoint: endpoint,
		})
	}
	sort.Slice(configs, func(left, right int) bool {
		return configs[left].operatorID < configs[right].operatorID
	})
	return configs
}

func predictionAcceptanceNetworkPreflight(t *testing.T, sink *TOSCTLPaymentSink,
	configs []predictionAcceptanceConfig, stateDirectory string,
) func(context.Context, string, agentrelay.NetworkDomain) error {
	t.Helper()
	verified := make(map[string]bool, len(configs))
	var mu sync.Mutex
	return func(ctx context.Context, configPath string, expected agentrelay.NetworkDomain) error {
		mu.Lock()
		defer mu.Unlock()
		if verified[configPath] {
			return nil
		}
		var quorum []string
		found := false
		for _, config := range configs {
			if config.path == configPath {
				found = true
				continue
			}
			quorum = append(quorum, config.path)
		}
		if !found || len(quorum) != 2 || sink.RelayNetworkDomain == nil ||
			*sink.RelayNetworkDomain != expected {
			return errors.New("Prediction acceptance preflight escaped its pinned RPC set")
		}
		digest := sha256.Sum256([]byte(configPath))
		snapshotDirectory := filepath.Join(stateDirectory, "network-preflight-"+hex.EncodeToString(digest[:8]))
		if err := os.Mkdir(snapshotDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		args := []string{
			"agent", "account", "economic-payment-corroboration-profile",
			"--network-id", expected.NetworkID, "--global-id", strconv.FormatInt(int64(expected.GlobalID), 10),
			"--zero-state-root-hash", expected.ZeroStateRootHash,
			"--zero-state-file-hash", expected.ZeroStateFileHash,
			"--workchain-id", strconv.FormatInt(int64(expected.WorkchainID), 10),
			"--quorum-config", quorum[0], quorum[1], "--max-transactions", "10000",
			"--snapshot-directory", snapshotDirectory, "-c", configPath,
		}
		raw, err := sink.run(ctx, args)
		if err != nil {
			return err
		}
		var capability tosctlRelaySponsorshipCapability
		if decodeStrictJSON(raw, &capability) != nil ||
			capability.Schema != "tosctl.agent-account.agreement-payment-rpc-corroboration-capability.v1" ||
			capability.NetworkDomain != expected || capability.EvidenceProfile.NetworkDomain != expected ||
			capability.MemberCount != 3 || len(capability.EvidenceProfile.Members) != 3 ||
			capability.EvidenceProfile.Threshold != 2 || !capability.EvidenceProfile.StrictMajority ||
			!capability.EvidenceProfile.ExactSubmittedMessage ||
			!capability.EvidenceProfile.ExactDestinationCredit || capability.SideEffect {
			return errors.New("Prediction acceptance network capability conflicts with its owner pin")
		}
		verified[configPath] = true
		return nil
	}
}

func acceptanceRoundAndReporter(t *testing.T, definition predictionAcceptanceDefinition) (protocol.Round, string) {
	t.Helper()
	round := strings.ToLower(mustEnv(t, "OPENFOX_PREDICTION_ROUND"))
	var value protocol.Round
	var reporters []string
	switch round {
	case "normal":
		value, reporters = protocol.RoundNormal, definition.NormalOraclePolicy.Reporters
	case "appeal":
		value, reporters = protocol.RoundAppeal, definition.AppellateOraclePolicy.Reporters
	default:
		t.Fatal("OPENFOX_PREDICTION_ROUND must be normal or appeal")
	}
	if len(reporters) == 0 {
		t.Fatal("selected Prediction Oracle round has no reporter")
	}
	reporter := mustEnv(t, "OPENFOX_PREDICTION_REPORTER_ADDRESS")
	for _, admitted := range reporters {
		if reporter == admitted {
			return value, reporter
		}
	}
	t.Fatal("OPENFOX_PREDICTION_REPORTER_ADDRESS is not admitted in the selected round")
	return 0, ""
}

func acceptanceRequiredAbsoluteFile(t *testing.T, environment string) string {
	t.Helper()
	return acceptanceAbsoluteFile(t, environment, mustEnv(t, environment))
}

func acceptanceAbsoluteFile(t *testing.T, label, path string) string {
	t.Helper()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatalf("%s must be an absolute clean path", label)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("%s must be a regular non-symlink file", label)
	}
	return path
}

func acceptanceCheckpoints(values []PredictionOracleCheckpoint) []predictionAcceptanceCheckpoint {
	result := make([]predictionAcceptanceCheckpoint, len(values))
	for index, value := range values {
		result[index] = predictionAcceptanceCheckpoint{
			ObserverID: value.ObserverID, Seqno: value.Seqno,
			RootHash: value.RootHash, FileHash: value.FileHash,
		}
	}
	return result
}

func acceptanceReadBounded(t *testing.T, path string, maximum int64) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		t.Fatalf("bounded Prediction acceptance input is invalid: %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil || int64(len(raw)) != info.Size() {
		t.Fatalf("read bounded Prediction acceptance input: %v", err)
	}
	return raw
}

func acceptanceWritePredictionReport(t *testing.T, report predictionContextAcceptanceReport) {
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
	if err != nil || len(raw) > 1<<20 {
		t.Fatal("Prediction acceptance report is not bounded")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			t.Errorf("close Prediction context evidence root: %v", closeErr)
		}
	}()
	name := "prediction-oracle-context-" + strings.TrimPrefix(report.MarketID, "sha256:") + ".json"
	if err := fileutil.WriteFileAtomicRoot(root, name, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote machine-readable Prediction evidence to %s", filepath.Join(directory, name))
}
