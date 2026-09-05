package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	predictionAcceptedWagerGate         = "OPENFOX_PREDICTION_ACCEPTED_WAGER_CONTRACT_THREE_NODE_E2E"
	predictionMatchPairOpcode           = uint64(0x504d0009)
	predictionAcceptanceOperationBudget = uint64(1_000_000_000)
	predictionAcceptanceHistoryLimit    = 128
	maxPredictionAcceptanceBOCBytes     = int64(2 << 20)
)

type predictionAcceptedDefinition struct {
	GlobalID             int32  `json:"global_id"`
	WorkchainID          int32  `json:"workchain_id"`
	RulesHash            string `json:"rules_hash"`
	TradeClose           uint64 `json:"trade_close"`
	LotValue             uint64 `json:"lot_value"`
	OrderEntryFee        uint64 `json:"order_entry_fee"`
	OrderCleanupBounty   uint64 `json:"order_cleanup_bounty"`
	AccountCleanupBounty uint64 `json:"account_cleanup_bounty"`
}

type predictionAcceptedTransactionID struct {
	LT   string `json:"lt"`
	Hash string `json:"hash"`
}

type predictionAcceptedAccountInfo struct {
	State             string                          `json:"state"`
	LastTransactionID predictionAcceptedTransactionID `json:"last_transaction_id"`
}

type predictionAcceptedTransactionWire struct {
	Data          string                          `json:"data"`
	UTime         uint32                          `json:"utime"`
	TransactionID predictionAcceptedTransactionID `json:"transaction_id"`
	BlockID       predictionEntropyBlockID        `json:"block_id"`
}

type predictionAcceptedBlock struct {
	Workchain int32  `json:"workchain"`
	Shard     string `json:"shard"`
	Seqno     uint64 `json:"seqno"`
	RootHash  string `json:"root_hash"`
	FileHash  string `json:"file_hash"`
}

type predictionAcceptedTransaction struct {
	Hash             string                  `json:"hash"`
	BOCBase64        string                  `json:"boc_base64"`
	LT               uint64                  `json:"lt"`
	UTime            uint32                  `json:"utime"`
	Block            predictionAcceptedBlock `json:"block"`
	MasterchainSeqno uint64                  `json:"masterchain_seqno"`
}

type predictionAcceptedMessage struct {
	Hash               string `json:"hash"`
	BOCBase64          string `json:"boc_base64"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	ValueNanoTOS       uint64 `json:"value_nanotos"`
	BodyHash           string `json:"body_hash"`
	BodyBOCBase64      string `json:"body_boc_base64"`
	ExtraFlags         uint64 `json:"extra_flags"`
}

type predictionAcceptedOrder struct {
	OwnerAddress     string `json:"owner_address"`
	TradingPublicKey string `json:"trading_public_key"`
	OrderDigest      string `json:"order_digest"`
	OrderCellHash    string `json:"order_cell_hash"`
	Outcome          string `json:"outcome"`
	Role             string `json:"role"`
	QuantityLots     uint64 `json:"quantity_lots"`
	PriceTick        uint16 `json:"price_tick"`
}

type predictionAcceptedAccounting struct {
	Status           string `json:"status"`
	Participants     uint32 `json:"participants"`
	LiveOrders       uint32 `json:"live_orders"`
	FillCount        uint64 `json:"fill_count"`
	CompleteSets     uint64 `json:"complete_sets"`
	TotalFree        uint64 `json:"total_free"`
	Locked           uint64 `json:"locked"`
	FinalBacking     uint64 `json:"final_backing"`
	RemainingPayout  uint64 `json:"remaining_payout"`
	Claimed          uint64 `json:"claimed"`
	ChallengeBond    uint64 `json:"challenge_bond"`
	CleanupLiability uint64 `json:"cleanup_liability"`
}

type predictionAcceptedObserverReceipt struct {
	ObserverID                 string `json:"observer_id"`
	ConsensusSeqno             uint64 `json:"consensus_seqno"`
	LatestSeqno                uint64 `json:"latest_seqno"`
	LatestBlockUTime           int64  `json:"latest_block_utime"`
	StateCheckpointSeqno       uint32 `json:"state_checkpoint_seqno"`
	StateCheckpointRootHash    string `json:"state_checkpoint_root_hash"`
	StateCheckpointFileHash    string `json:"state_checkpoint_file_hash"`
	SourceTransactionHash      string `json:"source_transaction_hash"`
	DestinationTransactionHash string `json:"destination_transaction_hash"`
}

type predictionAcceptedWagerReport struct {
	Schema                       string                              `json:"schema"`
	Verdict                      string                              `json:"verdict"`
	ObservedAt                   string                              `json:"observed_at"`
	SelectionRule                string                              `json:"selection_rule"`
	SubmissionProfile            string                              `json:"submission_profile"`
	DefinitionSHA256             string                              `json:"definition_sha256"`
	NetworkDomain                agentrelay.NetworkDomain            `json:"network_domain"`
	NetworkDomainHash            string                              `json:"network_domain_hash"`
	MarketAddress                string                              `json:"market_address"`
	MarketID                     string                              `json:"market_id"`
	MarketConfigHash             string                              `json:"market_config_hash"`
	MarketCodeHash               string                              `json:"market_code_hash"`
	RulesHash                    string                              `json:"rules_hash"`
	SourceAddress                string                              `json:"source_address"`
	SubmittedExternalMessageHash string                              `json:"submitted_external_message_hash"`
	ExactExternalBOCSHA256       string                              `json:"exact_external_boc_sha256"`
	ExactExternalBOCBase64       string                              `json:"exact_external_boc_base64"`
	OperationBodyHash            string                              `json:"operation_body_hash"`
	OperationBodyBOCBase64       string                              `json:"operation_body_boc_base64"`
	ScanStartMasterchainBlock    predictionEntropyBlock              `json:"scan_start_masterchain_block"`
	MatchQuantityLots            uint64                              `json:"match_quantity_lots"`
	ParticipantTradingPublicKeys []string                            `json:"participant_trading_public_keys"`
	Orders                       []predictionAcceptedOrder           `json:"orders"`
	SourceTransaction            predictionAcceptedTransaction       `json:"source_transaction"`
	OutboundMessage              predictionAcceptedMessage           `json:"outbound_message"`
	DestinationTransaction       predictionAcceptedTransaction       `json:"destination_transaction"`
	Accounting                   predictionAcceptedAccounting        `json:"accounting"`
	ObserverReceipts             []predictionAcceptedObserverReceipt `json:"observer_receipts"`
}

type predictionEntropyRevealReport struct {
	Schema                      string                              `json:"schema"`
	Verdict                     string                              `json:"verdict"`
	RevealedAt                  string                              `json:"revealed_at"`
	AcceptedWagerEvidenceSHA256 string                              `json:"accepted_wager_evidence_sha256"`
	FutureLockSHA256            string                              `json:"future_lock_sha256"`
	NetworkDomain               agentrelay.NetworkDomain            `json:"network_domain"`
	NetworkDomainHash           string                              `json:"network_domain_hash"`
	MarketID                    string                              `json:"market_id"`
	TargetSeqno                 uint64                              `json:"target_seqno"`
	Block                       predictionEntropyBlock              `json:"block"`
	Outcome                     string                              `json:"outcome"`
	ObserverSnapshots           []predictionEntropyObserverSnapshot `json:"observer_snapshots"`
}

type predictionDecodedTransaction struct {
	report predictionAcceptedTransaction
	tx     *tlb.Transaction
	root   *cell.Cell
}

// TestPredictionAcceptedWagerAndFutureRevealThreeNodeContractGate proves one
// fresh complete-set match from exact submitted bytes through a successful
// destination transaction, then makes the subject unpredictable by durably
// fixing a future block before any lookup of that height.
func TestPredictionAcceptedWagerAndFutureRevealThreeNodeContractGate(t *testing.T) {
	if os.Getenv(predictionAcceptedWagerGate) != "1" {
		t.Skip("set " + predictionAcceptedWagerGate + "=1 for the live release gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	executable := acceptanceRequiredAbsoluteFile(t, "OPENFOX_PREDICTION_TOSCTL")
	definitionPath := acceptanceRequiredAbsoluteFile(t, "OPENFOX_PREDICTION_MARKET_DEFINITION")
	externalPath := acceptanceRequiredAbsoluteFile(t, "OPENFOX_PREDICTION_MATCH_EXTERNAL_BOC")
	bodyPath := acceptanceRequiredAbsoluteFile(t, "OPENFOX_PREDICTION_MATCH_BODY_BOC")
	definitionRaw := acceptanceReadBounded(t, definitionPath, 1<<20)
	var definition predictionAcceptedDefinition
	if json.Unmarshal(definitionRaw, &definition) != nil || definition.GlobalID == 0 ||
		definition.TradeClose == 0 || definition.LotValue == 0 ||
		definition.OrderCleanupBounty == 0 || definition.AccountCleanupBounty == 0 ||
		!validCanonicalSHA256(definition.RulesHash) {
		t.Fatal("Prediction accepted-wager definition is incomplete")
	}
	network := predictionAcceptanceNetworkDomain(t)
	if network.GlobalID != definition.GlobalID || network.WorkchainID != definition.WorkchainID {
		t.Fatal("Prediction accepted-wager network conflicts with the definition")
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
	nodes := predictionEntropyNodes(t, configs)
	externalRaw := acceptanceReadBounded(t, externalPath, 64<<10)
	bodyRaw := acceptanceReadBounded(t, bodyPath, 64<<10)
	externalCell := canonicalPredictionAcceptanceCell(t, "match external message", externalRaw)
	bodyCell := canonicalPredictionAcceptanceCell(t, "match operation body", bodyRaw)
	submittedHash := predictionAcceptanceCellHash(externalCell)
	bodyHash := predictionAcceptanceCellHash(bodyCell)
	quantity, orders, participantKeys, signedOrders, err := decodePredictionAcceptedMatch(bodyCell)
	if err != nil {
		t.Fatal(err)
	}
	sourceAddress := mustEnv(t, "OPENFOX_PREDICTION_MATCH_SOURCE_ADDRESS")
	if parsed, parseErr := address.ParseRawAddr(sourceAddress); parseErr != nil || parsed == nil ||
		parsed.StringRaw() != sourceAddress {
		t.Fatal("OPENFOX_PREDICTION_MATCH_SOURCE_ADDRESS is not canonical")
	}
	sink := &TOSCTLPaymentSink{
		Executable: executable,
		VaultURL:   strings.TrimSpace(os.Getenv("OPENFOX_PREDICTION_VAULT_URL")),
	}
	buildRaw, err := sink.run(ctx, []string{"agent", "prediction", "build-state", "--definition", definitionPath})
	if err != nil {
		t.Fatal(err)
	}
	var build predictionAcceptanceBuildState
	if decodeStrictJSON(buildRaw, &build) != nil || build.Schema != "tos.prediction-market-state-init.v1" ||
		!validCanonicalSHA256(build.MarketID) || !validTVMCellSHA256(build.MarketConfigHash) ||
		!validTVMCellSHA256(build.CodeHash) || build.RulesHash != definition.RulesHash {
		t.Fatal("Prediction accepted-wager StateInit identity is invalid")
	}
	if validateErr := validatePredictionAcceptedOrders(
		definition, build, quantity, orders, signedOrders, 0,
	); validateErr != nil {
		t.Fatal(validateErr)
	}
	scanStart, err := strconv.ParseUint(mustEnv(t, "OPENFOX_PREDICTION_MATCH_SCAN_START_MC_SEQNO"), 10, 64)
	if err != nil || scanStart == 0 || strconv.FormatUint(scanStart, 10) !=
		mustEnv(t, "OPENFOX_PREDICTION_MATCH_SCAN_START_MC_SEQNO") {
		t.Fatal("OPENFOX_PREDICTION_MATCH_SCAN_START_MC_SEQNO must be a nonzero canonical uint64")
	}
	scanStartBlock, err := readPredictionEntropyBlockQuorum(ctx, nodes, scanStart)
	if err != nil {
		t.Fatal(err)
	}
	definitionDigest := sha256.Sum256(definitionRaw)
	report := predictionAcceptedWagerReport{
		Schema:                       "tos.openfox.prediction-accepted-wager-three-node.v1",
		Verdict:                      "PASS",
		ObservedAt:                   time.Now().UTC().Format(time.RFC3339),
		SelectionRule:                "direct-wallet-exact-external-to-source-transaction-to-single-outbound-to-successful-market-transaction",
		SubmissionProfile:            "direct-wallet-contract-probe",
		DefinitionSHA256:             "sha256:" + hex.EncodeToString(definitionDigest[:]),
		NetworkDomain:                network,
		NetworkDomainHash:            networkDigest,
		MarketAddress:                build.Address,
		MarketID:                     build.MarketID,
		MarketConfigHash:             build.MarketConfigHash,
		MarketCodeHash:               build.CodeHash,
		RulesHash:                    definition.RulesHash,
		SourceAddress:                sourceAddress,
		SubmittedExternalMessageHash: submittedHash,
		ExactExternalBOCSHA256:       sha256Digest(externalRaw),
		ExactExternalBOCBase64:       base64.StdEncoding.EncodeToString(externalRaw),
		OperationBodyHash:            bodyHash,
		OperationBodyBOCBase64:       base64.StdEncoding.EncodeToString(bodyRaw),
		ScanStartMasterchainBlock:    scanStartBlock,
		MatchQuantityLots:            quantity,
		ParticipantTradingPublicKeys: participantKeys,
		Orders:                       orders,
	}
	states := make([]predictionEntropyNodeState, 0, len(nodes))
	var canonicalSource, canonicalDestination predictionDecodedTransaction
	var canonicalOutbound predictionAcceptedMessage
	var canonicalAccounting predictionAcceptedAccounting
	for index, node := range nodes {
		state, stateErr := readPredictionEntropyNodeState(ctx, node, network)
		if stateErr != nil {
			t.Fatalf("read accepted-wager observer %d state: %v", index+1, stateErr)
		}
		source, sourceErr := findPredictionAcceptanceTransaction(
			ctx, node.client, sourceAddress, submittedHash, predictionAcceptanceHistoryLimit,
		)
		if sourceErr != nil {
			t.Fatalf("find accepted-wager source transaction at observer %d: %v", index+1, sourceErr)
		}
		outbound, outboundErr := predictionAcceptanceSourceOutbound(
			source.tx, sourceAddress, build.Address, bodyRaw, bodyHash,
		)
		if outboundErr != nil {
			t.Fatalf("verify accepted-wager source output at observer %d: %v", index+1, outboundErr)
		}
		destination, destinationErr := findPredictionAcceptanceTransaction(
			ctx, node.client, build.Address, outbound.Hash, predictionAcceptanceHistoryLimit,
		)
		if destinationErr != nil {
			t.Fatalf("find accepted-wager destination transaction at observer %d: %v", index+1, destinationErr)
		}
		if destination.report.UTime < source.report.UTime ||
			uint64(destination.report.UTime) >= definition.TradeClose ||
			predictionAcceptanceSuccessfulOrdinary(destination.tx) != nil {
			t.Fatalf("accepted-wager destination execution is invalid at observer %d", index+1)
		}
		if validateErr := validatePredictionAcceptedOrders(
			definition, build, quantity, orders, signedOrders, uint64(destination.report.UTime),
		); validateErr != nil {
			t.Fatalf("verify accepted-wager order execution time at observer %d: %v", index+1, validateErr)
		}
		sourceInclusion, inclusionErr := findPredictionAcceptanceMasterchainInclusion(
			ctx, node.client, source.report.Block, scanStart, state.snapshot.ConsensusSeqno,
		)
		if inclusionErr != nil {
			t.Fatalf("find accepted-wager source masterchain inclusion at observer %d: %v", index+1, inclusionErr)
		}
		destinationInclusion := sourceInclusion
		if destination.report.Block != source.report.Block {
			destinationInclusion, inclusionErr = findPredictionAcceptanceMasterchainInclusion(
				ctx, node.client, destination.report.Block, scanStart, state.snapshot.ConsensusSeqno,
			)
			if inclusionErr != nil {
				t.Fatalf(
					"find accepted-wager destination masterchain inclusion at observer %d: %v",
					index+1,
					inclusionErr,
				)
			}
		}
		source.report.MasterchainSeqno = sourceInclusion
		destination.report.MasterchainSeqno = destinationInclusion
		viewRaw, viewErr := sink.run(ctx, []string{
			"agent", "prediction", "show", "--definition", definitionPath, "-c", configs[index].path,
		})
		if viewErr != nil {
			t.Fatalf("read accepted-wager market view at observer %d: %v", index+1, viewErr)
		}
		var view tosctlPredictionMarketChainView
		if decodeStrictJSON(viewRaw, &view) != nil {
			t.Fatalf("decode accepted-wager market view at observer %d", index+1)
		}
		accounting, accountingErr := validatePredictionAcceptedAccounting(definition, build, quantity, view)
		if accountingErr != nil {
			t.Fatalf("verify accepted-wager accounting at observer %d: %v", index+1, accountingErr)
		}
		if state.snapshot.ConsensusSeqno < sourceInclusion ||
			state.snapshot.ConsensusSeqno < destinationInclusion ||
			uint64(view.Checkpoint.Seqno) < destinationInclusion {
			t.Fatalf("accepted-wager transaction is not finalized at observer %d", index+1)
		}
		if index == 0 {
			canonicalSource, canonicalDestination = source, destination
			canonicalOutbound, canonicalAccounting = outbound, accounting
		} else if !reflect.DeepEqual(source.report, canonicalSource.report) ||
			!reflect.DeepEqual(destination.report, canonicalDestination.report) ||
			outbound != canonicalOutbound || accounting != canonicalAccounting {
			t.Fatalf("accepted-wager observers disagree at observer %d", index+1)
		}
		states = append(states, state)
		report.ObserverReceipts = append(report.ObserverReceipts, predictionAcceptedObserverReceipt{
			ObserverID: state.snapshot.ObserverID, ConsensusSeqno: state.snapshot.ConsensusSeqno,
			LatestSeqno: state.snapshot.LastSeqno, LatestBlockUTime: state.snapshot.LastBlockUtime,
			StateCheckpointSeqno:       view.Checkpoint.Seqno,
			StateCheckpointRootHash:    view.Checkpoint.RootHash,
			StateCheckpointFileHash:    view.Checkpoint.FileHash,
			SourceTransactionHash:      source.report.Hash,
			DestinationTransactionHash: destination.report.Hash,
		})
	}
	report.SourceTransaction, report.OutboundMessage = canonicalSource.report, canonicalOutbound
	report.DestinationTransaction, report.Accounting = canonicalDestination.report, canonicalAccounting
	report.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	if validateErr := validatePredictionAcceptedWagerReport(
		report, definition, sha256Digest(definitionRaw),
	); validateErr != nil {
		t.Fatal(validateErr)
	}
	evidenceDirectory := predictionAcceptanceEvidenceDirectory(t)
	acceptedRaw, err := persistPredictionAcceptedWagerReport(
		evidenceDirectory, report, definition, sha256Digest(definitionRaw),
	)
	if err != nil {
		t.Fatal(err)
	}
	lockedAt := time.Now().UTC()
	lock, lockDigest, err := persistPredictionEntropyFutureLock(
		evidenceDirectory, acceptedRaw, network, build.MarketID, participantKeys, states, lockedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	revealStates := waitPredictionEntropyTarget(t, ctx, nodes, network, lock)
	block, err := readPredictionEntropyBlockQuorum(ctx, nodes, lock.TargetSeqno)
	if err != nil {
		t.Fatal(err)
	}
	outcome := "NO"
	if block.Parity == "EVEN" {
		outcome = "YES"
	}
	reveal := predictionEntropyRevealReport{
		Schema: "tos.openfox.prediction-future-block-reveal-three-node.v1", Verdict: "PASS",
		RevealedAt:                  time.Now().UTC().Format(time.RFC3339),
		AcceptedWagerEvidenceSHA256: sha256Digest(acceptedRaw), FutureLockSHA256: lockDigest,
		NetworkDomain: network, NetworkDomainHash: networkDigest,
		MarketID: build.MarketID, TargetSeqno: lock.TargetSeqno, Block: block, Outcome: outcome,
	}
	for _, state := range revealStates {
		reveal.ObserverSnapshots = append(reveal.ObserverSnapshots, state.snapshot)
	}
	if err := validatePredictionEntropyRevealReport(reveal, lock, lockDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := persistPredictionEntropyRevealReport(evidenceDirectory, reveal, lock, lockDigest); err != nil {
		t.Fatal(err)
	}
	t.Logf("Prediction wager accepted and future block %d revealed %s", lock.TargetSeqno, outcome)
}

func canonicalPredictionAcceptanceCell(t *testing.T, label string, raw []byte) *cell.Cell {
	t.Helper()
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) {
		t.Fatalf("%s is not one canonical BOC", label)
	}
	return root
}

func predictionAcceptanceCellHash(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}

func decodePredictionAcceptedMatch(body *cell.Cell) (
	uint64, []predictionAcceptedOrder, []string, []*protocol.SignedPredictionOrderV1, error,
) {
	if body == nil {
		return 0, nil, nil, nil, errors.New("Prediction accepted-wager match body is absent")
	}
	slice, err := body.BeginParse()
	if err != nil {
		return 0, nil, nil, nil, err
	}
	opcode, err := slice.LoadUInt(32)
	if err != nil || opcode != predictionMatchPairOpcode {
		return 0, nil, nil, nil, errors.New("Prediction accepted-wager body is not match_pair")
	}
	if _, err = slice.LoadUInt(64); err != nil {
		return 0, nil, nil, nil, errors.New("Prediction accepted-wager query id is truncated")
	}
	quantity, err := slice.LoadUInt(64)
	if err != nil || quantity == 0 {
		return 0, nil, nil, nil, errors.New("Prediction accepted-wager quantity is invalid")
	}
	left, leftErr := slice.LoadRefCell()
	right, rightErr := slice.LoadRefCell()
	if leftErr != nil || rightErr != nil || slice.BitsLeft() != 0 || slice.RefsNum() != 0 {
		return 0, nil, nil, nil, errors.New("Prediction accepted-wager body has a noncanonical shape")
	}
	decoded := make([]*protocol.SignedPredictionOrderV1, 2)
	decoded[0], leftErr = protocol.DecodeAndVerifySignedPredictionOrder(left)
	decoded[1], rightErr = protocol.DecodeAndVerifySignedPredictionOrder(right)
	if leftErr != nil || rightErr != nil {
		return 0, nil, nil, nil, errors.New("Prediction accepted-wager order signature is invalid")
	}
	orders := make([]predictionAcceptedOrder, 0, 2)
	keys := make([]string, 0, 2)
	for _, signed := range decoded {
		outcome, role := "NO", "taker"
		if signed.Order.Outcome == protocol.OutcomeYes {
			outcome = "YES"
		}
		if signed.Order.LiquidityRole == protocol.RoleMaker {
			role = "maker"
		}
		key := hex.EncodeToString(signed.PublicKey[:])
		keys = append(keys, key)
		orders = append(orders, predictionAcceptedOrder{
			OwnerAddress: signed.Order.OwnerAddress, TradingPublicKey: key,
			OrderDigest:   signed.OrderDigest.CellHashString(),
			OrderCellHash: signed.OrderCellHash.CellHashString(), Outcome: outcome, Role: role,
			QuantityLots: signed.Order.QuantityLots, PriceTick: signed.Order.LimitPriceTick,
		})
	}
	sort.Strings(keys)
	return quantity, orders, keys, decoded, nil
}

func validatePredictionAcceptedOrders(definition predictionAcceptedDefinition,
	build predictionAcceptanceBuildState, quantity uint64, evidence []predictionAcceptedOrder,
	signed []*protocol.SignedPredictionOrderV1, transactionTime uint64,
) error {
	if quantity != 1 || len(evidence) != 2 || len(signed) != 2 || len(evidence[0].TradingPublicKey) != 64 ||
		len(evidence[1].TradingPublicKey) != 64 || evidence[0].TradingPublicKey == evidence[1].TradingPublicKey ||
		evidence[0].OwnerAddress == evidence[1].OwnerAddress || evidence[0].QuantityLots != quantity ||
		evidence[1].QuantityLots != quantity || uint32(evidence[0].PriceTick)+uint32(evidence[1].PriceTick) != uint32(protocol.PriceScale) {
		return errors.New("Prediction accepted-wager orders do not mint one fresh complete set")
	}
	if !((evidence[0].Outcome == "YES" && evidence[1].Outcome == "NO") ||
		(evidence[0].Outcome == "NO" && evidence[1].Outcome == "YES")) ||
		!((evidence[0].Role == "maker" && evidence[1].Role == "taker") ||
			(evidence[0].Role == "taker" && evidence[1].Role == "maker")) {
		return errors.New("Prediction accepted-wager orders are not complementary maker/taker orders")
	}
	if !validCanonicalSHA256(build.MarketID) || !validTVMCellSHA256(build.MarketConfigHash) ||
		definition.LotValue > ^uint64(0)/quantity {
		return errors.New("Prediction accepted-wager market arithmetic is invalid")
	}
	for _, value := range signed {
		order := value.Order
		if order.GlobalID != definition.GlobalID || int32(order.WorkchainID) != definition.WorkchainID ||
			order.MarketAddress != build.Address || order.MarketConfigHash.CellHashString() != build.MarketConfigHash ||
			order.Action != protocol.ActionBuy || order.QuantityLots != quantity || order.MinFillLots > quantity ||
			order.AllowPartial || order.OptionalCounterparty != nil || order.ValidUntil > definition.TradeClose {
			return errors.New("Prediction accepted-wager signed order conflicts with the fresh market")
		}
		if transactionTime != 0 && (transactionTime < order.ValidAfter || transactionTime >= order.ValidUntil) {
			return errors.New("Prediction accepted-wager order was executed outside its signed validity interval")
		}
	}
	return nil
}

func findPredictionAcceptanceTransaction(ctx context.Context, rpc predictionEntropyRPC,
	accountAddress, wantedInboundHash string, maximum int,
) (predictionDecodedTransaction, error) {
	var zero predictionDecodedTransaction
	if ctx == nil || rpc == nil || maximum <= 0 || maximum > 10_000 || !validTVMCellSHA256(wantedInboundHash) {
		return zero, errors.New("invalid Prediction accepted-wager transaction search")
	}
	parsed, err := address.ParseRawAddr(accountAddress)
	if err != nil || parsed == nil || parsed.StringRaw() != accountAddress {
		return zero, errors.New("invalid Prediction accepted-wager account")
	}
	var infoDocument map[string]json.RawMessage
	if callErr := rpc.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
	}{accountAddress}, &infoDocument); callErr != nil {
		return zero, callErr
	}
	var info predictionAcceptedAccountInfo
	stateErr := json.Unmarshal(infoDocument["state"], &info.State)
	headErr := json.Unmarshal(infoDocument["last_transaction_id"], &info.LastTransactionID)
	expectedLT, err := canonicalPredictionUint64(info.LastTransactionID.LT)
	expectedHash, errHash := predictionRPCDigest(info.LastTransactionID.Hash)
	if stateErr != nil || headErr != nil || info.State != "active" || err != nil || errHash != nil || expectedLT == 0 {
		return zero, errors.New("Prediction accepted-wager account head is invalid")
	}
	inspected := 0
	for expectedLT != 0 && inspected < maximum {
		limit := maximum - inspected
		if limit > 8 {
			limit = 8
		}
		var page []json.RawMessage
		if err := rpc.Call(ctx, "getTransactions", struct {
			Address string `json:"address"`
			LT      string `json:"lt"`
			Hash    string `json:"hash"`
			Limit   int    `json:"limit"`
		}{accountAddress, strconv.FormatUint(expectedLT, 10), info.LastTransactionID.Hash, limit}, &page); err != nil {
			return zero, err
		}
		if len(page) == 0 || len(page) > limit {
			return zero, errors.New("Prediction accepted-wager transaction history is incomplete")
		}
		for _, wireRaw := range page {
			var wire predictionAcceptedTransactionWire
			if json.Unmarshal(wireRaw, &wire) != nil {
				return zero, errors.New("Prediction accepted-wager transaction response is malformed")
			}
			decoded, decodeErr := decodePredictionAcceptanceTransaction(wire, accountAddress)
			if decodeErr != nil || decoded.report.LT != expectedLT || decoded.report.Hash != expectedHash {
				return zero, errors.New("Prediction accepted-wager transaction chain is invalid")
			}
			inspected++
			inCell, cellErr := decoded.tx.IO.In.ToCell()
			if cellErr == nil && predictionAcceptanceCellHash(inCell) == wantedInboundHash {
				return decoded, nil
			}
			expectedLT = decoded.tx.PrevTxLT
			if expectedLT == 0 {
				expectedHash = "sha256:" + strings.Repeat("0", 64)
				break
			}
			if len(decoded.tx.PrevTxHash) != sha256.Size {
				return zero, errors.New("Prediction accepted-wager previous transaction hash is invalid")
			}
			expectedHash = "sha256:" + hex.EncodeToString(decoded.tx.PrevTxHash)
			info.LastTransactionID.Hash = base64.StdEncoding.EncodeToString(decoded.tx.PrevTxHash)
			if inspected >= maximum {
				break
			}
		}
	}
	return zero, errors.New("exact Prediction accepted-wager transaction was not found within the bound")
}

func findPredictionAcceptanceMasterchainInclusion(ctx context.Context, rpc predictionEntropyRPC,
	wanted predictionAcceptedBlock, start, finalized uint64,
) (uint64, error) {
	if ctx == nil || rpc == nil || start == 0 || finalized < start ||
		wanted.Workchain == -1 || wanted.Seqno == 0 || !validCanonicalSHA256(wanted.RootHash) ||
		!validCanonicalSHA256(wanted.FileHash) {
		return 0, errors.New("invalid Prediction accepted-wager masterchain inclusion search")
	}
	wantedShard, err := canonicalPredictionShard(wanted.Shard)
	if err != nil {
		return 0, err
	}
	end := finalized
	if finalized-start > 4096 {
		end = start + 4096
	}
	for seqno := start; ; seqno++ {
		var document map[string]json.RawMessage
		if err := rpc.Call(ctx, "getShards", struct {
			Seqno uint64 `json:"seqno"`
		}{seqno}, &document); err != nil {
			return 0, err
		}
		var shards []predictionEntropyBlockID
		if json.Unmarshal(document["shards"], &shards) != nil || len(shards) == 0 || len(shards) > 256 {
			return 0, errors.New("Prediction accepted-wager masterchain shard list is invalid")
		}
		for _, shard := range shards {
			shardID, shardErr := canonicalPredictionShard(shard.Shard)
			rootHash, rootErr := predictionRPCDigest(shard.RootHash)
			fileHash, fileErr := predictionRPCDigest(shard.FileHash)
			if shardErr != nil || rootErr != nil || fileErr != nil || shard.Type != "tos.blockIdExt" ||
				shard.Seqno == 0 {
				return 0, errors.New("Prediction accepted-wager shard identity is malformed")
			}
			if shard.Workchain == wanted.Workchain && shardID == wantedShard && shard.Seqno == wanted.Seqno &&
				rootHash == wanted.RootHash && fileHash == wanted.FileHash {
				return seqno, nil
			}
		}
		if seqno == end {
			break
		}
	}
	return 0, errors.New("Prediction accepted-wager transaction block is absent from the finalized masterchain range")
}

func canonicalPredictionShard(value string) (uint64, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, errors.New("Prediction shard identifier is not canonical")
	}
	if strings.HasPrefix(value, "-") {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || strconv.FormatInt(parsed, 10) != value {
			return 0, errors.New("Prediction shard identifier is not canonical")
		}
		return uint64(parsed), nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("Prediction shard identifier is not canonical")
	}
	return parsed, nil
}

func decodePredictionAcceptanceTransaction(wire predictionAcceptedTransactionWire,
	accountAddress string,
) (predictionDecodedTransaction, error) {
	var zero predictionDecodedTransaction
	raw, err := base64.StdEncoding.Strict().DecodeString(wire.Data)
	if err != nil || len(raw) == 0 || int64(len(raw)) > maxPredictionAcceptanceBOCBytes ||
		base64.StdEncoding.EncodeToString(raw) != wire.Data {
		return zero, errors.New("Prediction accepted-wager transaction BOC is invalid")
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) {
		return zero, errors.New("Prediction accepted-wager transaction BOC is noncanonical")
	}
	hash, err := predictionRPCDigest(wire.TransactionID.Hash)
	lt, ltErr := canonicalPredictionUint64(wire.TransactionID.LT)
	if err != nil || ltErr != nil || hash != "sha256:"+hex.EncodeToString(root.Hash()) || wire.UTime == 0 ||
		wire.BlockID.Type != "tos.blockIdExt" || wire.BlockID.Seqno == 0 || wire.BlockID.Shard == "" {
		return zero, errors.New("Prediction accepted-wager transaction identity is invalid")
	}
	rootHash, rootErr := predictionRPCDigest(wire.BlockID.RootHash)
	fileHash, fileErr := predictionRPCDigest(wire.BlockID.FileHash)
	if rootErr != nil || fileErr != nil {
		return zero, errors.New("Prediction accepted-wager transaction block is invalid")
	}
	var tx tlb.Transaction
	if decodeErr := tlb.LoadFromCell(
		&tx,
		root.MustBeginParse(),
	); decodeErr != nil || tx.LT != lt ||
		tx.Now != wire.UTime {
		return zero, errors.New("Prediction accepted-wager transaction TL-B is invalid")
	}
	rebuilt, err := tx.ToCell()
	parsed, addressErr := address.ParseRawAddr(accountAddress)
	if err != nil || parsed == nil || addressErr != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) ||
		!bytes.Equal(tx.AccountAddr, parsed.Data()) || tx.IO.In == nil {
		return zero, errors.New("Prediction accepted-wager transaction is not bound to its account")
	}
	return predictionDecodedTransaction{
		tx: &tx, root: root,
		report: predictionAcceptedTransaction{
			Hash: hash, BOCBase64: wire.Data, LT: lt, UTime: wire.UTime,
			Block: predictionAcceptedBlock{
				Workchain: wire.BlockID.Workchain, Shard: wire.BlockID.Shard, Seqno: wire.BlockID.Seqno,
				RootHash: rootHash, FileHash: fileHash,
			},
		},
	}, nil
}

func predictionAcceptanceSourceOutbound(tx *tlb.Transaction, source, destination string,
	bodyRaw []byte, bodyHash string,
) (predictionAcceptedMessage, error) {
	var zero predictionAcceptedMessage
	if tx == nil || tx.IO.In == nil || tx.IO.In.MsgType != tlb.MsgTypeExternalIn ||
		predictionAcceptanceSuccessfulOrdinary(tx) != nil || tx.IO.Out == nil || tx.OutMsgCount != 1 {
		return zero, errors.New("Prediction accepted-wager source transaction did not execute exactly one output")
	}
	values, err := tx.IO.Out.ToSlice()
	if err != nil || len(values) != 1 {
		return zero, errors.New("Prediction accepted-wager source output dictionary is invalid")
	}
	message := &values[0]
	if message.MsgType != tlb.MsgTypeInternal {
		return zero, errors.New("Prediction accepted-wager source output is not internal")
	}
	internal := message.AsInternal()
	messageCell, err := message.ToCell()
	if err != nil || internal == nil || internal.SrcAddr == nil || internal.DstAddr == nil {
		return zero, errors.New("Prediction accepted-wager source output has no canonical message header")
	}
	if internal.SrcAddr.StringRaw() != source || internal.DstAddr.StringRaw() != destination {
		return zero, errors.New("Prediction accepted-wager source output has the wrong endpoints")
	}
	if !internal.IHRDisabled || !internal.Bounce || internal.Bounced || internal.StateInit != nil {
		return zero, errors.New("Prediction accepted-wager source output has unsafe delivery flags")
	}
	if internal.Body == nil || !internal.Amount.Nano().IsUint64() ||
		(internal.ExtraCurrencies != nil && !internal.ExtraCurrencies.IsEmpty()) {
		return zero, errors.New("Prediction accepted-wager source output has invalid value or body")
	}
	if !internal.IHRFee.Nano().IsUint64() || internal.IHRFee.Nano().Uint64() != 0 {
		return zero, errors.New("Prediction direct-wallet accepted-wager output has unexpected extra flags")
	}
	if predictionAcceptanceCellHash(internal.Body) != bodyHash ||
		!bytes.Equal(internal.Body.ToBOCWithFlags(false), bodyRaw) {
		return zero, errors.New("Prediction accepted-wager source output body differs from the frozen call")
	}
	return predictionAcceptedMessage{
		Hash:          predictionAcceptanceCellHash(messageCell),
		BOCBase64:     base64.StdEncoding.EncodeToString(messageCell.ToBOCWithFlags(false)),
		SourceAddress: source, DestinationAddress: destination,
		ValueNanoTOS: internal.Amount.Nano().Uint64(), BodyHash: bodyHash,
		BodyBOCBase64: base64.StdEncoding.EncodeToString(bodyRaw), ExtraFlags: 0,
	}, nil
}

func predictionAcceptanceSuccessfulOrdinary(tx *tlb.Transaction) error {
	if tx == nil {
		return errors.New("Prediction accepted-wager transaction is absent")
	}
	var ordinary tlb.TransactionDescriptionOrdinary
	switch value := tx.Description.(type) {
	case tlb.TransactionDescriptionOrdinary:
		ordinary = value
	case *tlb.TransactionDescriptionOrdinary:
		if value == nil {
			return errors.New("Prediction accepted-wager ordinary transaction is absent")
		}
		ordinary = *value
	default:
		return errors.New("Prediction accepted-wager transaction is not ordinary")
	}
	var computeSuccess bool
	switch phase := ordinary.ComputePhase.Phase.(type) {
	case tlb.ComputePhaseVM:
		computeSuccess = phase.Success && phase.Details.ExitCode == 0
	case *tlb.ComputePhaseVM:
		computeSuccess = phase != nil && phase.Success && phase.Details.ExitCode == 0
	}
	if ordinary.Aborted || !computeSuccess || ordinary.ActionPhase == nil ||
		!ordinary.ActionPhase.Success || !ordinary.ActionPhase.Valid || ordinary.ActionPhase.NoFunds ||
		ordinary.ActionPhase.ResultCode != 0 {
		return errors.New("Prediction accepted-wager transaction execution failed")
	}
	return nil
}

func validatePredictionAcceptedAccounting(definition predictionAcceptedDefinition,
	build predictionAcceptanceBuildState, quantity uint64, view tosctlPredictionMarketChainView,
) (predictionAcceptedAccounting, error) {
	var zero predictionAcceptedAccounting
	locked, overflow := checkedPredictionProduct(definition.LotValue, quantity)
	cleanupAccounts, accountOverflow := checkedPredictionProduct(definition.AccountCleanupBounty, 2)
	cleanupOrders, orderOverflow := checkedPredictionProduct(definition.OrderCleanupBounty, 2)
	cleanup, cleanupOverflow := checkedPredictionSum(cleanupAccounts, cleanupOrders)
	if overflow || accountOverflow || orderOverflow || cleanupOverflow ||
		view.Schema != predictionMarketChainViewSchema || !view.Activated || !view.CodeHashVerified ||
		!view.ConfigHashVerified || view.Address != build.Address ||
		view.MarketID != strings.TrimPrefix(build.MarketID, "sha256:") ||
		view.MarketConfigHash != strings.TrimPrefix(build.MarketConfigHash, "tvm-cell-sha256:") ||
		view.Status != "trading" ||
		view.Participants != 2 || view.LiveOrders != 2 || view.FillCount != 1 ||
		view.CompleteSets != quantity || view.Locked != locked || view.TotalFree != locked ||
		view.FinalBacking != 0 || view.RemainingPayout != 0 || view.Claimed != 0 ||
		view.ChallengeBond != 0 || view.CleanupLiability != cleanup || view.Checkpoint.Seqno == 0 ||
		!canonicalRawHash(view.Checkpoint.RootHash) || !canonicalRawHash(view.Checkpoint.FileHash) {
		return zero, errors.New("Prediction accepted-wager accounting does not describe one fresh complete set")
	}
	return predictionAcceptedAccounting{
		Status: view.Status, Participants: view.Participants, LiveOrders: view.LiveOrders,
		FillCount: view.FillCount, CompleteSets: view.CompleteSets, TotalFree: view.TotalFree,
		Locked: view.Locked, FinalBacking: view.FinalBacking, RemainingPayout: view.RemainingPayout,
		Claimed: view.Claimed, ChallengeBond: view.ChallengeBond,
		CleanupLiability: view.CleanupLiability,
	}, nil
}

func checkedPredictionProduct(left, right uint64) (uint64, bool) {
	if right != 0 && left > ^uint64(0)/right {
		return 0, true
	}
	return left * right, false
}

func checkedPredictionSum(left, right uint64) (uint64, bool) {
	if ^uint64(0)-left < right {
		return 0, true
	}
	return left + right, false
}

func validatePredictionAcceptedWagerReport(report predictionAcceptedWagerReport,
	definition predictionAcceptedDefinition, expectedDefinitionDigest string,
) error {
	if report.Schema != "tos.openfox.prediction-accepted-wager-three-node.v1" || report.Verdict != "PASS" ||
		report.SelectionRule != "direct-wallet-exact-external-to-source-transaction-to-single-outbound-to-successful-market-transaction" ||
		report.SubmissionProfile != "direct-wallet-contract-probe" ||
		!validCanonicalSHA256(expectedDefinitionDigest) || report.DefinitionSHA256 != expectedDefinitionDigest ||
		!validCanonicalSHA256(report.NetworkDomainHash) ||
		!validCanonicalSHA256(report.MarketID) || !validTVMCellSHA256(report.MarketConfigHash) ||
		!validTVMCellSHA256(report.MarketCodeHash) || !validCanonicalSHA256(report.RulesHash) ||
		!validTVMCellSHA256(report.SubmittedExternalMessageHash) ||
		!validCanonicalSHA256(report.ExactExternalBOCSHA256) || !validTVMCellSHA256(report.OperationBodyHash) ||
		len(report.Orders) != 2 || len(report.ParticipantTradingPublicKeys) != 2 ||
		len(report.ObserverReceipts) != 3 || report.MatchQuantityLots != 1 ||
		report.ScanStartMasterchainBlock.Seqno == 0 ||
		!canonicalRawHash(report.ScanStartMasterchainBlock.RootHash) ||
		!canonicalRawHash(report.ScanStartMasterchainBlock.FileHash) ||
		!predictionAcceptanceBlockParityValid(report.ScanStartMasterchainBlock) {
		return errors.New("Prediction accepted-wager evidence has invalid bounds")
	}
	observedAt, err := time.Parse(time.RFC3339, report.ObservedAt)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(report.NetworkDomain)
	if err != nil || observedAt.IsZero() || networkErr != nil || networkDigest != report.NetworkDomainHash ||
		report.NetworkDomain.GlobalID != definition.GlobalID ||
		report.NetworkDomain.WorkchainID != definition.WorkchainID || report.RulesHash != definition.RulesHash {
		return errors.New("Prediction accepted-wager evidence has an invalid network or time")
	}
	externalRaw, externalErr := base64.StdEncoding.Strict().DecodeString(report.ExactExternalBOCBase64)
	bodyRaw, bodyErr := base64.StdEncoding.Strict().DecodeString(report.OperationBodyBOCBase64)
	if externalErr != nil || bodyErr != nil || sha256Digest(externalRaw) != report.ExactExternalBOCSHA256 {
		return errors.New("Prediction accepted-wager exact inputs are invalid")
	}
	externalCell, externalErr := cell.FromBOC(externalRaw)
	bodyCell, bodyErr := cell.FromBOC(bodyRaw)
	if externalErr != nil || bodyErr != nil || externalCell == nil || bodyCell == nil ||
		!bytes.Equal(externalRaw, externalCell.ToBOCWithFlags(false)) ||
		!bytes.Equal(bodyRaw, bodyCell.ToBOCWithFlags(false)) ||
		predictionAcceptanceCellHash(externalCell) != report.SubmittedExternalMessageHash ||
		predictionAcceptanceCellHash(bodyCell) != report.OperationBodyHash {
		return errors.New("Prediction accepted-wager exact cells are not canonical or hash-bound")
	}
	quantity, orders, keys, signedOrders, err := decodePredictionAcceptedMatch(bodyCell)
	if err != nil || quantity != report.MatchQuantityLots || !reflect.DeepEqual(orders, report.Orders) ||
		!reflect.DeepEqual(keys, report.ParticipantTradingPublicKeys) ||
		validatePredictionAcceptedOrders(definition, predictionAcceptanceBuildState{
			Address: report.MarketAddress, MarketID: report.MarketID,
			MarketConfigHash: report.MarketConfigHash, CodeHash: report.MarketCodeHash,
		}, quantity, orders, signedOrders, uint64(report.DestinationTransaction.UTime)) != nil {
		return errors.New("Prediction accepted-wager exact orders are inconsistent")
	}
	if report.SourceTransaction.UTime > report.DestinationTransaction.UTime ||
		uint64(report.DestinationTransaction.UTime) >= definition.TradeClose ||
		report.SourceTransaction.MasterchainSeqno == 0 || report.DestinationTransaction.MasterchainSeqno == 0 ||
		report.ScanStartMasterchainBlock.Seqno > report.SourceTransaction.MasterchainSeqno ||
		report.ScanStartMasterchainBlock.Seqno > report.DestinationTransaction.MasterchainSeqno ||
		report.OutboundMessage.SourceAddress != report.SourceAddress ||
		report.OutboundMessage.DestinationAddress != report.MarketAddress ||
		report.OutboundMessage.BodyHash != report.OperationBodyHash ||
		report.OutboundMessage.BodyBOCBase64 != report.OperationBodyBOCBase64 ||
		report.OutboundMessage.ExtraFlags != 0 || report.OutboundMessage.ValueNanoTOS == 0 {
		return errors.New("Prediction accepted-wager exact transaction path is inconsistent")
	}
	sourceTx, err := decodePredictionAcceptanceReportTransaction(report.SourceTransaction, report.SourceAddress)
	if err != nil || sourceTx.IO.In == nil || sourceTx.IO.In.MsgType != tlb.MsgTypeExternalIn ||
		predictionAcceptanceSuccessfulOrdinary(sourceTx) != nil {
		return errors.New("Prediction accepted-wager source transaction BOC is inconsistent")
	}
	sourceInput, err := sourceTx.IO.In.ToCell()
	if err != nil || predictionAcceptanceCellHash(sourceInput) != report.SubmittedExternalMessageHash ||
		!bytes.Equal(sourceInput.ToBOCWithFlags(false), externalRaw) {
		return errors.New("Prediction accepted-wager source transaction did not consume the exact external BOC")
	}
	outbound, err := predictionAcceptanceSourceOutbound(
		sourceTx, report.SourceAddress, report.MarketAddress, bodyRaw, report.OperationBodyHash,
	)
	if err != nil || outbound != report.OutboundMessage {
		return errors.New("Prediction accepted-wager source transaction did not create the declared outbound")
	}
	destinationTx, err := decodePredictionAcceptanceReportTransaction(
		report.DestinationTransaction, report.MarketAddress,
	)
	if err != nil || predictionAcceptanceSuccessfulOrdinary(destinationTx) != nil ||
		destinationTx.IO.In == nil || destinationTx.IO.In.MsgType != tlb.MsgTypeInternal ||
		destinationTx.OutMsgCount != 0 {
		return errors.New("Prediction accepted-wager destination transaction BOC is inconsistent")
	}
	destinationInput, err := destinationTx.IO.In.ToCell()
	declaredOutbound, decodeErr := base64.StdEncoding.Strict().DecodeString(report.OutboundMessage.BOCBase64)
	if err != nil || decodeErr != nil ||
		predictionAcceptanceCellHash(destinationInput) != report.OutboundMessage.Hash ||
		!bytes.Equal(destinationInput.ToBOCWithFlags(false), declaredOutbound) {
		return errors.New("Prediction accepted-wager destination did not consume the exact source outbound")
	}
	stateContribution, overflow := checkedPredictionSum(definition.OrderEntryFee, definition.OrderCleanupBounty)
	stateContribution, overflow2 := checkedPredictionProduct(stateContribution, 2)
	minimum, overflow3 := checkedPredictionSum(predictionAcceptanceOperationBudget, stateContribution)
	if overflow || overflow2 || overflow3 || report.OutboundMessage.ValueNanoTOS != minimum {
		return errors.New("Prediction accepted-wager message value does not cover its exact state contribution")
	}
	locked, overflow := checkedPredictionProduct(definition.LotValue, quantity)
	accountCleanup, accountOverflow := checkedPredictionProduct(definition.AccountCleanupBounty, 2)
	orderCleanup, orderOverflow := checkedPredictionProduct(definition.OrderCleanupBounty, 2)
	cleanup, cleanupOverflow := checkedPredictionSum(accountCleanup, orderCleanup)
	if overflow || accountOverflow || orderOverflow || cleanupOverflow || report.Accounting.Status != "trading" ||
		report.Accounting.Participants != 2 || report.Accounting.LiveOrders != 2 ||
		report.Accounting.FillCount != 1 || report.Accounting.CompleteSets != quantity ||
		report.Accounting.Locked != locked || report.Accounting.TotalFree != locked ||
		report.Accounting.FinalBacking != 0 || report.Accounting.RemainingPayout != 0 ||
		report.Accounting.Claimed != 0 || report.Accounting.ChallengeBond != 0 ||
		report.Accounting.CleanupLiability != cleanup {
		return errors.New("Prediction accepted-wager accounting is inconsistent")
	}
	previous := ""
	latestObserverTime := int64(0)
	for _, receipt := range report.ObserverReceipts {
		if !validCanonicalSHA256(receipt.ObserverID) || receipt.ObserverID <= previous ||
			receipt.ConsensusSeqno < report.SourceTransaction.MasterchainSeqno ||
			receipt.ConsensusSeqno < report.DestinationTransaction.MasterchainSeqno ||
			receipt.LatestSeqno < receipt.ConsensusSeqno || receipt.StateCheckpointSeqno == 0 ||
			uint64(receipt.StateCheckpointSeqno) < report.DestinationTransaction.MasterchainSeqno ||
			receipt.LatestBlockUTime < int64(report.DestinationTransaction.UTime) ||
			!canonicalRawHash(receipt.StateCheckpointRootHash) ||
			!canonicalRawHash(receipt.StateCheckpointFileHash) ||
			receipt.SourceTransactionHash != report.SourceTransaction.Hash ||
			receipt.DestinationTransactionHash != report.DestinationTransaction.Hash {
			return errors.New("Prediction accepted-wager observer receipt is invalid")
		}
		if receipt.LatestBlockUTime > latestObserverTime {
			latestObserverTime = receipt.LatestBlockUTime
		}
		previous = receipt.ObserverID
	}
	observerSkew := int64(predictionEntropyPrelockMaxAge / time.Second)
	if observedAt.Unix() < int64(report.DestinationTransaction.UTime) ||
		observedAt.Unix() < latestObserverTime-observerSkew ||
		observedAt.Unix() > latestObserverTime+observerSkew {
		return errors.New("Prediction accepted-wager observation time is inconsistent")
	}
	return nil
}

func predictionAcceptanceBlockParityValid(block predictionEntropyBlock) bool {
	if !canonicalRawHash(block.RootHash) {
		return false
	}
	raw, err := hex.DecodeString(block.RootHash)
	if err != nil || len(raw) != sha256.Size {
		return false
	}
	wanted := "ODD"
	if raw[0]&1 == 0 {
		wanted = "EVEN"
	}
	return block.Parity == wanted
}

func decodePredictionAcceptanceReportTransaction(report predictionAcceptedTransaction,
	accountAddress string,
) (*tlb.Transaction, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(report.BOCBase64)
	if err != nil || len(raw) == 0 || int64(len(raw)) > maxPredictionAcceptanceBOCBytes ||
		base64.StdEncoding.EncodeToString(raw) != report.BOCBase64 {
		return nil, errors.New("Prediction accepted-wager report transaction BOC is invalid")
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) ||
		report.Hash != "sha256:"+hex.EncodeToString(root.Hash()) {
		return nil, errors.New("Prediction accepted-wager report transaction is not hash-bound")
	}
	var tx tlb.Transaction
	if decodeErr := tlb.LoadFromCell(&tx, root.MustBeginParse()); decodeErr != nil || tx.LT != report.LT ||
		tx.Now != report.UTime {
		return nil, errors.New("Prediction accepted-wager report transaction TL-B is invalid")
	}
	rebuilt, err := tx.ToCell()
	parsed, addressErr := address.ParseRawAddr(accountAddress)
	if err != nil || addressErr != nil || parsed == nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) ||
		!bytes.Equal(tx.AccountAddr, parsed.Data()) || report.Block.Workchain == -1 || report.Block.Seqno == 0 ||
		!validCanonicalSHA256(report.Block.RootHash) || !validCanonicalSHA256(report.Block.FileHash) {
		return nil, errors.New("Prediction accepted-wager report transaction identity is invalid")
	}
	return &tx, nil
}

func predictionAcceptanceEvidenceDirectory(t *testing.T) string {
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
	return directory
}

func persistPredictionAcceptedWagerReport(directory string, report predictionAcceptedWagerReport,
	definition predictionAcceptedDefinition, expectedDefinitionDigest string,
) (result []byte, resultErr error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		validateRelayJournalDirectorySecurity(directory) != nil {
		return nil, errors.New("Prediction accepted-wager evidence directory is not owner-private")
	}
	if err := validatePredictionAcceptedWagerReport(report, definition, expectedDefinitionDigest); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil || int64(len(raw)) >= maxPredictionEntropyEvidenceBytes {
		return nil, errors.New("Prediction accepted-wager evidence exceeds its bound")
	}
	raw = append(raw, '\n')
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	lock, err := acquireRelayJournalLockRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, releaseRelayJournalLock(lock)) }()
	name := "accepted-wager-" + strings.TrimPrefix(report.MarketID, "sha256:") + ".json"
	prior, readErr := readPredictionEntropyRootFile(root, name, maxPredictionEntropyEvidenceBytes)
	if readErr == nil {
		var existing predictionAcceptedWagerReport
		if decodeStrictJSON(prior, &existing) != nil ||
			validatePredictionAcceptedWagerReport(existing, definition, expectedDefinitionDigest) != nil ||
			existing.MarketID != report.MarketID ||
			existing.SubmittedExternalMessageHash != report.SubmittedExternalMessageHash ||
			existing.DestinationTransaction.Hash != report.DestinationTransaction.Hash {
			return nil, errors.New("durable Prediction accepted-wager evidence conflicts with this run")
		}
		return prior, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	if writeErr := fileutil.WriteFileAtomicRoot(root, name, raw, 0o600); writeErr != nil {
		return nil, writeErr
	}
	durable, err := readPredictionEntropyRootFile(root, name, maxPredictionEntropyEvidenceBytes)
	if err != nil || !bytes.Equal(durable, raw) {
		return nil, errors.New("Prediction accepted-wager evidence did not become durable exactly")
	}
	return durable, nil
}

func waitPredictionEntropyTarget(t *testing.T, ctx context.Context, nodes []predictionEntropyNode,
	network agentrelay.NetworkDomain, lock predictionEntropyFutureLock,
) []predictionEntropyNodeState {
	t.Helper()
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	for {
		states := make([]predictionEntropyNodeState, len(nodes))
		ready := true
		for index, node := range nodes {
			state, err := readPredictionEntropyNodeState(ctx, node, network)
			if err != nil {
				t.Fatal(err)
			}
			states[index] = state
			if !reflect.DeepEqual(state.validators, lock.ValidatorSet) {
				t.Fatal("Prediction validator set changed before the frozen future reveal")
			}
			if state.snapshot.ConsensusSeqno < lock.TargetSeqno {
				ready = false
			}
		}
		if ready {
			return states
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("Prediction future block did not finalize before the bounded reveal deadline")
		case <-time.After(time.Second):
		}
	}
}

func validatePredictionEntropyRevealReport(report predictionEntropyRevealReport,
	lock predictionEntropyFutureLock, lockDigest string,
) error {
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(report.NetworkDomain)
	lockRaw, lockEncodeErr := json.MarshalIndent(lock, "", "  ")
	lockRaw = append(lockRaw, '\n')
	if report.Schema != "tos.openfox.prediction-future-block-reveal-three-node.v1" ||
		report.Verdict != "PASS" || report.AcceptedWagerEvidenceSHA256 != lock.AcceptedWagerEvidenceSHA256 ||
		lockEncodeErr != nil || validatePredictionEntropyFutureLock(lock) != nil ||
		!validCanonicalSHA256(lockDigest) || sha256Digest(lockRaw) != lockDigest ||
		report.FutureLockSHA256 != lockDigest ||
		networkErr != nil || networkDigest != report.NetworkDomainHash || report.NetworkDomain != lock.NetworkDomain ||
		report.NetworkDomainHash != lock.NetworkDomainHash || report.MarketID != lock.MarketID ||
		report.TargetSeqno != lock.TargetSeqno || report.Block.Seqno != lock.TargetSeqno ||
		len(report.ObserverSnapshots) != 3 || !canonicalRawHash(report.Block.RootHash) ||
		!canonicalRawHash(report.Block.FileHash) {
		return errors.New("Prediction future reveal has invalid identity or bounds")
	}
	revealedAt, err := time.Parse(time.RFC3339, report.RevealedAt)
	lockedAt, lockErr := time.Parse(time.RFC3339, lock.LockedAt)
	if err != nil || revealedAt.IsZero() || lockErr != nil || lockedAt.IsZero() || revealedAt.Before(lockedAt) {
		return errors.New("Prediction future reveal time is invalid")
	}
	raw, _ := hex.DecodeString(report.Block.RootHash)
	wantedParity, wantedOutcome := "ODD", "NO"
	if raw[0]&1 == 0 {
		wantedParity, wantedOutcome = "EVEN", "YES"
	}
	if report.Block.Parity != wantedParity || report.Outcome != wantedOutcome {
		return errors.New("Prediction future reveal outcome conflicts with the exact root hash")
	}
	previous := ""
	for _, snapshot := range report.ObserverSnapshots {
		if !validCanonicalSHA256(snapshot.ObserverID) || snapshot.ObserverID <= previous ||
			snapshot.ConsensusSeqno < report.TargetSeqno || snapshot.LastSeqno < snapshot.ConsensusSeqno ||
			snapshot.ValidatorSetHash != lock.ValidatorSet.ConfigCellHash ||
			snapshot.LastBlockUtime < lockedAt.Unix() || snapshot.LastBlockUtime > revealedAt.Unix()+1 {
			return errors.New("Prediction future reveal observer snapshot is invalid")
		}
		previous = snapshot.ObserverID
	}
	return nil
}

func persistPredictionEntropyRevealReport(directory string, report predictionEntropyRevealReport,
	lock predictionEntropyFutureLock, lockDigest string,
) (result []byte, resultErr error) {
	if err := validatePredictionEntropyRevealReport(report, lock, lockDigest); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil || int64(len(raw)) >= maxPredictionEntropyEvidenceBytes {
		return nil, errors.New("Prediction future reveal exceeds its bound")
	}
	raw = append(raw, '\n')
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	lockFile, err := acquireRelayJournalLockRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, releaseRelayJournalLock(lockFile)) }()
	name := "future-block-reveal-" + strings.TrimPrefix(report.MarketID, "sha256:") + ".json"
	prior, readErr := readPredictionEntropyRootFile(root, name, maxPredictionEntropyEvidenceBytes)
	if readErr == nil {
		var existing predictionEntropyRevealReport
		if decodeStrictJSON(prior, &existing) != nil ||
			validatePredictionEntropyRevealReport(existing, lock, lockDigest) != nil ||
			existing.MarketID != report.MarketID || existing.TargetSeqno != report.TargetSeqno ||
			existing.Block != report.Block || existing.Outcome != report.Outcome {
			return nil, errors.New("durable Prediction future reveal conflicts with this run")
		}
		return prior, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	if writeErr := fileutil.WriteFileAtomicRoot(root, name, raw, 0o600); writeErr != nil {
		return nil, writeErr
	}
	durable, err := readPredictionEntropyRootFile(root, name, maxPredictionEntropyEvidenceBytes)
	if err != nil || !bytes.Equal(durable, raw) {
		return nil, errors.New("Prediction future reveal did not become durable exactly")
	}
	return durable, nil
}

func TestPredictionFutureRevealRejectsChangedParity(t *testing.T) {
	network := agentrelay.NetworkDomain{
		NetworkID: "tos:test-reveal", GlobalID: 3, WorkchainID: 0,
		ZeroStateRootHash: "sha256:" + strings.Repeat("21", 32),
		ZeroStateFileHash: "sha256:" + strings.Repeat("22", 32),
	}
	validators := predictionEntropyValidatorSet{
		ConfigCellHash: "tvm-cell-sha256:" + strings.Repeat("31", 32),
		UTimeSince:     1_700_000_000, UTimeUntil: 1_700_100_000, Total: 2, Main: 2, TotalWeight: 20,
		Validators: []predictionEntropyValidator{
			{PublicKey: strings.Repeat("11", 32), ADNLAddress: strings.Repeat("12", 32), Weight: 10},
			{
				PublicKey:        strings.Repeat("13", 32),
				ADNLAddress:      strings.Repeat("14", 32),
				Weight:           10,
				CumulativeWeight: 10,
			},
		},
	}
	now := time.Unix(1_700_000_200, 0).UTC()
	states := []predictionEntropyNodeState{
		{
			snapshot: predictionEntropyObserverSnapshot{
				ObserverID:       "sha256:" + strings.Repeat("41", 32),
				ConsensusSeqno:   29,
				LastSeqno:        30,
				LastBlockUtime:   now.Unix(),
				ValidatorSetHash: validators.ConfigCellHash,
			},
			validators: validators,
		},
		{
			snapshot: predictionEntropyObserverSnapshot{
				ObserverID:       "sha256:" + strings.Repeat("42", 32),
				ConsensusSeqno:   30,
				LastSeqno:        31,
				LastBlockUtime:   now.Unix(),
				ValidatorSetHash: validators.ConfigCellHash,
			},
			validators: validators,
		},
		{
			snapshot: predictionEntropyObserverSnapshot{
				ObserverID:       "sha256:" + strings.Repeat("43", 32),
				ConsensusSeqno:   30,
				LastSeqno:        31,
				LastBlockUtime:   now.Unix(),
				ValidatorSetHash: validators.ConfigCellHash,
			},
			validators: validators,
		},
	}
	lock, err := buildPredictionEntropyFutureLock(
		[]byte(`{"schema":"accepted","verdict":"PASS"}`), network,
		"sha256:"+strings.Repeat("51", 32),
		[]string{strings.Repeat("61", 32), strings.Repeat("62", 32)}, states, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	lockRaw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	lockDigest := sha256Digest(append(lockRaw, '\n'))
	revealedAt := now.Add(90 * time.Second)
	report := predictionEntropyRevealReport{
		Schema: "tos.openfox.prediction-future-block-reveal-three-node.v1", Verdict: "PASS",
		RevealedAt:                  revealedAt.Format(time.RFC3339),
		AcceptedWagerEvidenceSHA256: lock.AcceptedWagerEvidenceSHA256,
		FutureLockSHA256:            lockDigest,
		NetworkDomain:               lock.NetworkDomain, NetworkDomainHash: lock.NetworkDomainHash,
		MarketID: lock.MarketID, TargetSeqno: lock.TargetSeqno,
		Block: predictionEntropyBlock{
			Seqno: lock.TargetSeqno, RootHash: "02" + strings.Repeat("00", 31),
			FileHash: strings.Repeat("71", 32), Parity: "EVEN",
		},
		Outcome: "YES",
	}
	for index := 0; index < 3; index++ {
		report.ObserverSnapshots = append(report.ObserverSnapshots, predictionEntropyObserverSnapshot{
			ObserverID: fmt.Sprintf("sha256:%064x", index+1), ConsensusSeqno: lock.TargetSeqno,
			LastSeqno: lock.TargetSeqno + 1, LastBlockUtime: revealedAt.Unix(),
			ValidatorSetHash: lock.ValidatorSet.ConfigCellHash,
		})
	}
	if err := validatePredictionEntropyRevealReport(report, lock, lockDigest); err != nil {
		t.Fatal(err)
	}
	report.Outcome = "NO"
	if err := validatePredictionEntropyRevealReport(report, lock, lockDigest); err == nil {
		t.Fatal("Prediction future reveal accepted an outcome that conflicts with root parity")
	}
}
