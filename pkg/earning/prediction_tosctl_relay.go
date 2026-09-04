package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

const (
	tosctlPredictionSourceRequestSchema        = "tosctl.prediction-relay-source-request.v1"
	tosctlPredictionSourceEvidenceSchema       = "tosctl.prediction-relay-source-evidence.v1"
	tosctlPredictionDestinationRequestSchema   = "tosctl.prediction-relay-destination-request.v1"
	tosctlPredictionDestinationEvidenceSchema  = "tosctl.prediction-relay-destination-evidence.v1"
	tosctlPredictionBounceCreditRequestSchema  = "tosctl.prediction-relay-bounce-credit-request.v1"
	tosctlPredictionBounceCreditEvidenceSchema = "tosctl.prediction-relay-bounce-credit-evidence.v1"
	maximumPredictionSourceTransactions        = 1_000_000
	maximumPredictionMasterchainBlocks         = 1_000_000
)

var (
	predictionSourceReceiptDigestDomain       = []byte("tosctl.prediction-source-observer.v1\x00")
	predictionSourceViewDigestDomain          = []byte("tosctl.prediction-source-finality-view.v1\x00")
	predictionDestinationReceiptDigestDomain  = []byte("tosctl.prediction-destination-observer.v1\x00")
	predictionDestinationViewDigestDomain     = []byte("tosctl.prediction-destination-finality-view.v1\x00")
	predictionNoBounceObservationDigestDomain = []byte("tosctl.prediction-no-bounce-observation.v1\x00")
	predictionNoBounceSetDigestDomain         = []byte("tosctl.prediction-no-bounce-set.v1\x00")
	predictionBounceCreditReceiptDigestDomain = []byte("tosctl.prediction-bounce-credit-observer.v1\x00")
	predictionBounceCreditViewDigestDomain    = []byte("tosctl.prediction-bounce-credit-finality-view.v1\x00")
)

type tosctlPredictionSourceRequest struct {
	Schema                            string                            `json:"schema"`
	ActionID                          string                            `json:"action_id"`
	Profile                           prediction.PredictionRelayProfile `json:"profile"`
	SubmittedExternalMessageHash      string                            `json:"submitted_external_message_hash"`
	PreBroadcastSourceCursor          prediction.AccountCursor          `json:"pre_broadcast_source_cursor"`
	PreBroadcastMasterchainCheckpoint prediction.BlockIdentity          `json:"pre_broadcast_masterchain_checkpoint"`
}

type tosctlPredictionSourceObserverReceipt struct {
	ObserverID               string                   `json:"observer_id"`
	OperatorProvenance       string                   `json:"operator_provenance"`
	ObservedMasterchain      prediction.BlockIdentity `json:"observed_masterchain"`
	FinalizedDeploymentID    string                   `json:"finalized_deployment_id"`
	FinalizedControllerEpoch uint64                   `json:"finalized_controller_epoch"`
	FinalizedSeqno           uint32                   `json:"finalized_seqno"`
	CandidateDigest          string                   `json:"candidate_digest"`
}

type tosctlPredictionSourceEnvelope struct {
	Schema           string                                  `json:"schema"`
	StableActionID   string                                  `json:"stable_action_id"`
	SourceEvidence   prediction.SourceTransactionEvidence    `json:"source_evidence"`
	ObserverReceipts []tosctlPredictionSourceObserverReceipt `json:"observer_receipts"`
	Failures         []string                                `json:"failures"`
	State            string                                  `json:"state"`
}

type tosctlPredictionSourceCandidate struct {
	TransactionHash  string                            `json:"transaction_hash"`
	TransactionBOC   string                            `json:"transaction_boc_base64"`
	BlockWorkchain   int32                             `json:"block_workchain"`
	BlockShard       int64                             `json:"block_shard"`
	BlockSeqno       uint32                            `json:"block_seqno"`
	BlockRootHash    string                            `json:"block_root_hash"`
	BlockFileHash    string                            `json:"block_file_hash"`
	NextSourceCursor prediction.AccountCursor          `json:"next_source_cursor"`
	OutboundMessages []prediction.ChainObservedMessage `json:"outbound_messages"`
}

type tosctlPredictionDestinationRequest struct {
	Schema                            string                               `json:"schema"`
	ActionID                          string                               `json:"action_id"`
	Profile                           prediction.PredictionRelayProfile    `json:"profile"`
	Expected                          prediction.ExpectedContractCall      `json:"expected"`
	PreBroadcastSourceCursor          prediction.AccountCursor             `json:"pre_broadcast_source_cursor"`
	PreBroadcastMasterchainCheckpoint prediction.BlockIdentity             `json:"pre_broadcast_masterchain_checkpoint"`
	SourceEvidence                    prediction.SourceTransactionEvidence `json:"source_evidence"`
	ActualOutbound                    prediction.ChainObservedMessage      `json:"actual_outbound"`
}

type tosctlPredictionDestinationCandidate struct {
	InboundMessageHash       string                           `json:"inbound_message_hash"`
	TransactionHash          string                           `json:"transaction_hash"`
	TransactionBOCBase64     string                           `json:"transaction_boc_base64"`
	BlockWorkchain           int32                            `json:"block_workchain"`
	BlockShard               int64                            `json:"block_shard"`
	BlockSeqno               uint32                           `json:"block_seqno"`
	BlockRootHash            string                           `json:"block_root_hash"`
	BlockFileHash            string                           `json:"block_file_hash"`
	ObservedMasterchainSeqno uint32                           `json:"observed_masterchain_seqno"`
	NextDestinationCursor    prediction.AccountCursor         `json:"next_destination_cursor"`
	Ordinary                 bool                             `json:"ordinary"`
	Aborted                  bool                             `json:"aborted"`
	ComputeSuccess           bool                             `json:"compute_success"`
	ActionSuccess            bool                             `json:"action_success"`
	OpcodeSuccess            bool                             `json:"opcode_success"`
	BounceMessage            *prediction.ChainObservedMessage `json:"bounce_message,omitempty"`
}

type tosctlPredictionDestinationObserverReceipt struct {
	ObserverID                string                   `json:"observer_id"`
	OperatorProvenance        string                   `json:"operator_provenance"`
	ObservedMasterchain       prediction.BlockIdentity `json:"observed_masterchain"`
	MarketCodeHash            string                   `json:"market_code_hash"`
	MarketConfigHash          string                   `json:"market_config_hash"`
	CandidateDigest           string                   `json:"candidate_digest"`
	NoBounceObservationDigest string                   `json:"no_bounce_observation_digest,omitempty"`
}

type tosctlPredictionDestinationEnvelope struct {
	Schema              string                                       `json:"schema"`
	StableActionID      string                                       `json:"stable_action_id"`
	DestinationEvidence prediction.DestinationTransactionEvidence    `json:"destination_evidence"`
	Candidate           tosctlPredictionDestinationCandidate         `json:"candidate"`
	ObserverReceipts    []tosctlPredictionDestinationObserverReceipt `json:"observer_receipts"`
	Failures            []string                                     `json:"failures"`
	State               string                                       `json:"state"`
}

type tosctlPredictionBounceCreditRequest struct {
	Schema                            string                                    `json:"schema"`
	ActionID                          string                                    `json:"action_id"`
	Profile                           prediction.PredictionRelayProfile         `json:"profile"`
	Expected                          prediction.ExpectedContractCall           `json:"expected"`
	PreBroadcastSourceCursor          prediction.AccountCursor                  `json:"pre_broadcast_source_cursor"`
	PreBroadcastMasterchainCheckpoint prediction.BlockIdentity                  `json:"pre_broadcast_masterchain_checkpoint"`
	SourceEvidence                    prediction.SourceTransactionEvidence      `json:"source_evidence"`
	DestinationEvidence               prediction.DestinationTransactionEvidence `json:"destination_evidence"`
}

type tosctlPredictionBounceCreditCandidate struct {
	InboundBounceMessageHash string                   `json:"inbound_bounce_message_hash"`
	TransactionHash          string                   `json:"transaction_hash"`
	TransactionBOCBase64     string                   `json:"transaction_boc_base64"`
	BlockWorkchain           int32                    `json:"block_workchain"`
	BlockShard               int64                    `json:"block_shard"`
	BlockSeqno               uint32                   `json:"block_seqno"`
	BlockRootHash            string                   `json:"block_root_hash"`
	BlockFileHash            string                   `json:"block_file_hash"`
	ObservedMasterchainSeqno uint32                   `json:"observed_masterchain_seqno"`
	NextSourceCursor         prediction.AccountCursor `json:"next_source_cursor"`
	CreditedValueNanoTOS     uint64                   `json:"credited_value_nanotos"`
}

type tosctlPredictionBounceCreditObserverReceipt struct {
	ObserverID                 string                   `json:"observer_id"`
	OperatorProvenance         string                   `json:"operator_provenance"`
	ObservedMasterchain        prediction.BlockIdentity `json:"observed_masterchain"`
	SourceAgentAccountCodeHash string                   `json:"source_agent_account_code_hash"`
	CandidateDigest            string                   `json:"candidate_digest"`
}

type tosctlPredictionBounceCreditEnvelope struct {
	Schema               string                                        `json:"schema"`
	StableActionID       string                                        `json:"stable_action_id"`
	BounceCreditEvidence prediction.BounceCreditEvidence               `json:"bounce_credit_evidence"`
	Candidate            tosctlPredictionBounceCreditCandidate         `json:"candidate"`
	ObserverReceipts     []tosctlPredictionBounceCreditObserverReceipt `json:"observer_receipts"`
	Failures             []string                                      `json:"failures"`
	State                string                                        `json:"state"`
}

// ResolvePredictionEffect advances one durable relay record to the strongest
// terminal state currently provable. Each transition persists before the next
// RPC phase, so a process crash simply resumes from the recorded state.
func (engine *Engine) ResolvePredictionEffect(ctx context.Context, sink *TOSCTLPaymentSink,
	actionID string,
) (prediction.PredictionRelayRecord, error) {
	if sink == nil || sink.PredictionRelayJournal == nil {
		return prediction.PredictionRelayRecord{}, errors.New("prediction relay journal is unavailable")
	}
	for transitions := 0; transitions < 3; transitions++ {
		record, found := sink.PredictionRelayJournal.Get(actionID)
		if !found {
			return prediction.PredictionRelayRecord{}, errors.New("prediction relay action was not found")
		}
		switch record.State {
		case prediction.RelayBroadcasting:
			resolved, err := engine.ResolvePredictionEffectSource(ctx, sink, actionID)
			if err != nil {
				return prediction.PredictionRelayRecord{}, err
			}
			if resolved.State == prediction.RelaySourceActionSkipped {
				return resolved, nil
			}
		case prediction.RelaySourceFinalized:
			resolved, err := engine.ResolvePredictionEffectDestination(ctx, sink, actionID)
			if err != nil {
				return prediction.PredictionRelayRecord{}, err
			}
			if resolved.State != prediction.RelayDestinationFailedBounceCreated {
				return resolved, nil
			}
		case prediction.RelayDestinationFailedBounceCreated:
			return engine.ResolvePredictionEffectBounceCredit(ctx, sink, actionID)
		case prediction.RelaySourceActionSkipped, prediction.RelayDestinationCommitted,
			prediction.RelayBounceCreditedAtAgent, prediction.RelayDestinationFailedNoBounce:
			return record, nil
		default:
			return prediction.PredictionRelayRecord{}, errors.New("prediction action is not ready for resolution")
		}
	}
	return prediction.PredictionRelayRecord{}, errors.New("prediction relay exceeded its finite transition bound")
}

// ResolvePredictionEffectSource crosses the second durable boundary of a
// Prediction effect. tosctl first proves and terminalizes the exact Agent
// Account source transaction; OpenFox then independently parses the returned
// transaction/message BOCs before advancing its own relay journal.
func (engine *Engine) ResolvePredictionEffectSource(ctx context.Context, sink *TOSCTLPaymentSink,
	actionID string,
) (prediction.PredictionRelayRecord, error) {
	if engine == nil || sink == nil || ctx == nil ||
		!engine.permits("prediction", engine.Gates.Prediction, true) {
		return prediction.PredictionRelayRecord{}, errors.New("prediction source resolution is disabled")
	}
	if err := sink.validatePredictionSourceResolver(ctx); err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	record, found := sink.PredictionRelayJournal.Get(actionID)
	if !found {
		return prediction.PredictionRelayRecord{}, errors.New("prediction relay action was not found")
	}
	if record.State != prediction.RelayBroadcasting {
		if record.SourceEvidence != nil {
			return record, nil
		}
		return prediction.PredictionRelayRecord{}, errors.New("prediction action is not awaiting source finality")
	}
	request := tosctlPredictionSourceRequest{
		Schema: tosctlPredictionSourceRequestSchema, ActionID: record.ActionID,
		Profile: record.Profile, SubmittedExternalMessageHash: record.SubmittedExternalMessageHash,
		PreBroadcastSourceCursor:          record.PreBroadcastSourceCursor,
		PreBroadcastMasterchainCheckpoint: record.PreBroadcastMasterchainCheckpoint,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	requestPath, cleanup, err := sink.writePrivateBytes(".prediction-source-request-*.json", requestJSON)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer cleanup()
	args := []string{
		"agent", "account", "prediction-relay-source-resolve", "--wallet", sink.Wallet,
		"--stable-action-id", actionID, "--relay-request", requestPath,
		"--max-transactions", strconv.FormatUint(uint64(sink.maximumPredictionTransactions()), 10),
		"--quorum-config",
	}
	args = append(args, sink.QuorumConfigPaths...)
	args = append(args, "-c", sink.ConfigPath)

	attempts := sink.ResolveAttempts
	if attempts == 0 {
		attempts = 30
	}
	interval := sink.ResolveInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	var lastErr error
	for attempt := uint32(0); attempt < attempts; attempt++ {
		raw, runErr := sink.run(ctx, args)
		if runErr == nil {
			var envelope tosctlPredictionSourceEnvelope
			if decodeErr := decodeStrictJSON(raw, &envelope); decodeErr != nil {
				return prediction.PredictionRelayRecord{}, fmt.Errorf(
					"decode Prediction source evidence: %w", decodeErr,
				)
			}
			if verifyErr := verifyTOSCTLPredictionSourceEnvelope(record, envelope); verifyErr != nil {
				return prediction.PredictionRelayRecord{}, verifyErr
			}
			attestor := tosctlPredictionSourceAttestor{
				Profile: record.Profile, Block: envelope.SourceEvidence.Block,
				Finality: envelope.SourceEvidence.Finality,
			}
			verifier := prediction.CanonicalPredictionRelayEvidenceVerifier{Attestor: attestor}
			return sink.PredictionRelayJournal.ResolveSource(
				ctx, actionID, envelope.SourceEvidence, verifier,
			)
		}
		lastErr = runErr
		if attempt+1 == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return prediction.PredictionRelayRecord{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return prediction.PredictionRelayRecord{}, fmt.Errorf(
		"resolve Prediction source from TOS quorum: %w", lastErr,
	)
}

// ResolvePredictionEffectDestination proves the exact market-side execution
// (or its exact rich-bounce/no-bounce terminal failure) from the same durable
// pre-broadcast checkpoint. OpenFox re-hashes the independent observer view
// and then re-parses the transaction BOC before committing journal state.
func (engine *Engine) ResolvePredictionEffectDestination(ctx context.Context, sink *TOSCTLPaymentSink,
	actionID string,
) (prediction.PredictionRelayRecord, error) {
	if engine == nil || sink == nil || ctx == nil ||
		!engine.permits("prediction", engine.Gates.Prediction, true) {
		return prediction.PredictionRelayRecord{}, errors.New("prediction destination resolution is disabled")
	}
	if err := sink.validatePredictionDestinationResolver(ctx); err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	record, found := sink.PredictionRelayJournal.Get(actionID)
	if !found {
		return prediction.PredictionRelayRecord{}, errors.New("prediction relay action was not found")
	}
	if record.State != prediction.RelaySourceFinalized || record.SourceEvidence == nil ||
		record.ActualOutbound == nil {
		if record.DestinationEvidence != nil {
			return record, nil
		}
		return prediction.PredictionRelayRecord{}, errors.New("prediction action is not awaiting destination finality")
	}
	request := tosctlPredictionDestinationRequest{
		Schema: tosctlPredictionDestinationRequestSchema, ActionID: record.ActionID,
		Profile: record.Profile, Expected: record.Expected,
		PreBroadcastSourceCursor:          record.PreBroadcastSourceCursor,
		PreBroadcastMasterchainCheckpoint: record.PreBroadcastMasterchainCheckpoint,
		SourceEvidence:                    *record.SourceEvidence, ActualOutbound: *record.ActualOutbound,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	requestPath, cleanup, err := sink.writePrivateBytes(".prediction-destination-request-*.json", requestJSON)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer cleanup()
	args := []string{
		"agent", "account", "prediction-relay-destination-resolve", "--wallet", sink.Wallet,
		"--stable-action-id", actionID, "--relay-request", requestPath,
		"--max-masterchain-blocks", strconv.FormatUint(uint64(sink.maximumPredictionMasterchainBlocks()), 10),
		"--max-transactions", strconv.FormatUint(uint64(sink.maximumPredictionTransactions()), 10),
		"--quorum-config",
	}
	args = append(args, sink.QuorumConfigPaths...)
	args = append(args, "-c", sink.ConfigPath)

	attempts := sink.ResolveAttempts
	if attempts == 0 {
		attempts = 30
	}
	interval := sink.ResolveInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	var lastErr error
	for attempt := uint32(0); attempt < attempts; attempt++ {
		raw, runErr := sink.run(ctx, args)
		if runErr == nil {
			var envelope tosctlPredictionDestinationEnvelope
			if decodeErr := decodeStrictJSON(raw, &envelope); decodeErr != nil {
				return prediction.PredictionRelayRecord{}, fmt.Errorf(
					"decode Prediction destination evidence: %w", decodeErr,
				)
			}
			if verifyErr := verifyTOSCTLPredictionDestinationEnvelope(record, envelope); verifyErr != nil {
				return prediction.PredictionRelayRecord{}, verifyErr
			}
			attestor := tosctlPredictionDestinationAttestor{
				Profile: record.Profile, Evidence: envelope.DestinationEvidence,
			}
			verifier := prediction.CanonicalPredictionRelayEvidenceVerifier{Attestor: attestor}
			return sink.PredictionRelayJournal.ResolveDestination(
				ctx, actionID, envelope.DestinationEvidence, verifier,
			)
		}
		lastErr = runErr
		if attempt+1 == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return prediction.PredictionRelayRecord{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return prediction.PredictionRelayRecord{}, fmt.Errorf(
		"resolve Prediction destination from TOS quorum: %w", lastErr,
	)
}

// ResolvePredictionEffectBounceCredit proves that the exact rich bounce from
// a finalized market failure was physically credited back to the source Agent
// Account. This is the only failure transition that releases source liquidity.
func (engine *Engine) ResolvePredictionEffectBounceCredit(ctx context.Context, sink *TOSCTLPaymentSink,
	actionID string,
) (prediction.PredictionRelayRecord, error) {
	if engine == nil || sink == nil || ctx == nil ||
		!engine.permits("prediction", engine.Gates.Prediction, true) {
		return prediction.PredictionRelayRecord{}, errors.New("prediction bounce-credit resolution is disabled")
	}
	if err := sink.validatePredictionDestinationResolver(ctx); err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	record, found := sink.PredictionRelayJournal.Get(actionID)
	if !found {
		return prediction.PredictionRelayRecord{}, errors.New("prediction relay action was not found")
	}
	if record.State != prediction.RelayDestinationFailedBounceCreated || record.SourceEvidence == nil ||
		record.DestinationEvidence == nil || record.DestinationEvidence.BounceMessage == nil {
		if record.BounceCreditEvidence != nil {
			return record, nil
		}
		return prediction.PredictionRelayRecord{}, errors.New("prediction action is not awaiting bounce credit")
	}
	request := tosctlPredictionBounceCreditRequest{
		Schema: tosctlPredictionBounceCreditRequestSchema, ActionID: record.ActionID,
		Profile: record.Profile, Expected: record.Expected,
		PreBroadcastSourceCursor:          record.PreBroadcastSourceCursor,
		PreBroadcastMasterchainCheckpoint: record.PreBroadcastMasterchainCheckpoint,
		SourceEvidence:                    *record.SourceEvidence, DestinationEvidence: *record.DestinationEvidence,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	requestPath, cleanup, err := sink.writePrivateBytes(".prediction-bounce-credit-request-*.json", requestJSON)
	if err != nil {
		return prediction.PredictionRelayRecord{}, err
	}
	defer cleanup()
	args := []string{
		"agent", "account", "prediction-relay-bounce-credit-resolve", "--wallet", sink.Wallet,
		"--stable-action-id", actionID, "--relay-request", requestPath,
		"--max-masterchain-blocks", strconv.FormatUint(uint64(sink.maximumPredictionMasterchainBlocks()), 10),
		"--max-transactions", strconv.FormatUint(uint64(sink.maximumPredictionTransactions()), 10),
		"--quorum-config",
	}
	args = append(args, sink.QuorumConfigPaths...)
	args = append(args, "-c", sink.ConfigPath)
	attempts := sink.ResolveAttempts
	if attempts == 0 {
		attempts = 30
	}
	interval := sink.ResolveInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	var lastErr error
	for attempt := uint32(0); attempt < attempts; attempt++ {
		raw, runErr := sink.run(ctx, args)
		if runErr == nil {
			var envelope tosctlPredictionBounceCreditEnvelope
			if decodeErr := decodeStrictJSON(raw, &envelope); decodeErr != nil {
				return prediction.PredictionRelayRecord{}, fmt.Errorf(
					"decode Prediction bounce-credit evidence: %w", decodeErr,
				)
			}
			if verifyErr := verifyTOSCTLPredictionBounceCreditEnvelope(record, envelope); verifyErr != nil {
				return prediction.PredictionRelayRecord{}, verifyErr
			}
			attestor := tosctlPredictionBounceCreditAttestor{
				Profile: record.Profile, Evidence: envelope.BounceCreditEvidence,
			}
			verifier := prediction.CanonicalPredictionRelayEvidenceVerifier{Attestor: attestor}
			return sink.PredictionRelayJournal.ResolveBounceCredit(
				ctx, actionID, envelope.BounceCreditEvidence, verifier,
			)
		}
		lastErr = runErr
		if attempt+1 == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return prediction.PredictionRelayRecord{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return prediction.PredictionRelayRecord{}, fmt.Errorf(
		"resolve Prediction bounce credit from TOS quorum: %w", lastErr,
	)
}

func (sink *TOSCTLPaymentSink) validatePredictionSourceResolver(ctx context.Context) error {
	if err := sink.validatePredictionAdapter(ctx); err != nil {
		return err
	}
	if len(sink.QuorumConfigPaths) < 2 || sink.maximumPredictionTransactions() == 0 ||
		sink.maximumPredictionTransactions() > maximumPredictionSourceTransactions {
		return errors.New("TOS Prediction source resolver quorum or history capacity is invalid")
	}
	seen := map[string]bool{filepath.Clean(sink.ConfigPath): true}
	for _, path := range sink.QuorumConfigPaths {
		clean := filepath.Clean(path)
		if !filepath.IsAbs(path) || seen[clean] {
			return errors.New("TOS Prediction quorum configs must be distinct absolute paths")
		}
		seen[clean] = true
	}
	return nil
}

func (sink *TOSCTLPaymentSink) validatePredictionDestinationResolver(ctx context.Context) error {
	if err := sink.validatePredictionSourceResolver(ctx); err != nil {
		return err
	}
	if sink.maximumPredictionMasterchainBlocks() == 0 ||
		sink.maximumPredictionMasterchainBlocks() > maximumPredictionMasterchainBlocks {
		return errors.New("TOS Prediction destination checkpoint capacity is invalid")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) maximumPredictionTransactions() uint32 {
	if sink.PredictionMaximumTransactions == 0 {
		return 100_000
	}
	return sink.PredictionMaximumTransactions
}

func (sink *TOSCTLPaymentSink) maximumPredictionMasterchainBlocks() uint32 {
	if sink.PredictionMaximumMasterchainBlocks == 0 {
		return 100_000
	}
	return sink.PredictionMaximumMasterchainBlocks
}

func verifyTOSCTLPredictionSourceEnvelope(record prediction.PredictionRelayRecord,
	envelope tosctlPredictionSourceEnvelope,
) error {
	evidence := envelope.SourceEvidence
	expectedState := "source_finalized"
	if len(evidence.OutboundMessages) == 0 {
		expectedState = "source_action_skipped"
	}
	if envelope.Schema != tosctlPredictionSourceEvidenceSchema ||
		envelope.StableActionID != record.ActionID || envelope.State != expectedState ||
		evidence.SubmittedExternalMessageHash != record.SubmittedExternalMessageHash ||
		!reflect.DeepEqual(evidence.Finality.ObserverIDs, record.Profile.ObserverIDs) ||
		evidence.Finality.Threshold != record.Profile.QuorumThreshold ||
		len(envelope.ObserverReceipts) != len(evidence.Finality.AgreeingIDs) ||
		len(envelope.ObserverReceipts) < int(record.Profile.QuorumThreshold) {
		return errors.New("tosctl returned unrelated Prediction source evidence")
	}
	candidate := tosctlPredictionSourceCandidate{
		TransactionHash: evidence.TransactionHash, TransactionBOC: evidence.TransactionBOCBase64,
		BlockWorkchain: evidence.Block.WorkchainID, BlockShard: evidence.Block.Shard,
		BlockSeqno: evidence.Block.SequenceNumber, BlockRootHash: evidence.Block.RootHash,
		BlockFileHash: evidence.Block.FileHash, NextSourceCursor: evidence.NextSourceCursor,
		OutboundMessages: evidence.OutboundMessages,
	}
	agreeing := append([]string(nil), evidence.Finality.AgreeingIDs...)
	sort.Strings(agreeing)
	if !reflect.DeepEqual(agreeing, evidence.Finality.AgreeingIDs) {
		return errors.New("Prediction source agreeing observer identities are not canonical")
	}
	allowed := make(map[string]bool, len(agreeing))
	profileObservers := make(map[string]bool, len(record.Profile.ObserverIDs))
	for _, observerID := range record.Profile.ObserverIDs {
		profileObservers[observerID] = true
	}
	for _, observerID := range agreeing {
		if !canonicalSHA256(observerID) || !profileObservers[observerID] || allowed[observerID] {
			return errors.New("Prediction source observer quorum is invalid")
		}
		allowed[observerID] = true
	}
	receipts := append([]tosctlPredictionSourceObserverReceipt(nil), envelope.ObserverReceipts...)
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].ObserverID < receipts[j].ObserverID })
	operators := make(map[string]bool, len(receipts))
	minimumMasterchainSeqno := ^uint32(0)
	deploymentID := ""
	for index, receipt := range receipts {
		if index >= len(agreeing) || receipt.ObserverID != agreeing[index] ||
			!canonicalSHA256(receipt.OperatorProvenance) || !canonicalSHA256(receipt.CandidateDigest) ||
			operators[receipt.OperatorProvenance] ||
			receipt.ObservedMasterchain.WorkchainID != -1 ||
			receipt.ObservedMasterchain.SequenceNumber != receipt.ObservedMasterchain.MasterchainSequence ||
			receipt.ObservedMasterchain.SequenceNumber < evidence.Finality.MasterchainSeqno ||
			!canonicalBlockIdentity(receipt.ObservedMasterchain) ||
			len(receipt.FinalizedDeploymentID) != 64 || !lowerHex(receipt.FinalizedDeploymentID) ||
			(receipt.FinalizedControllerEpoch == 0 && receipt.FinalizedSeqno == 0) {
			return errors.New("Prediction source observer receipt is invalid")
		}
		operators[receipt.OperatorProvenance] = true
		if deploymentID == "" {
			deploymentID = receipt.FinalizedDeploymentID
		} else if receipt.FinalizedDeploymentID != deploymentID {
			return errors.New("Prediction source observers disagree on Agent Account deployment")
		}
		if receipt.ObservedMasterchain.SequenceNumber < minimumMasterchainSeqno {
			minimumMasterchainSeqno = receipt.ObservedMasterchain.SequenceNumber
		}
		projection := map[string]any{
			"observer_id":                receipt.ObserverID,
			"operator_provenance":        receipt.OperatorProvenance,
			"observed_masterchain":       receipt.ObservedMasterchain,
			"finalized_deployment_id":    receipt.FinalizedDeploymentID,
			"finalized_controller_epoch": receipt.FinalizedControllerEpoch,
			"finalized_seqno":            receipt.FinalizedSeqno,
			"candidate":                  candidate,
		}
		digest, err := predictionTOSCTLJSONDigest(predictionSourceReceiptDigestDomain, projection)
		if err != nil || digest != receipt.CandidateDigest {
			return errors.New("Prediction source observer receipt digest is invalid")
		}
	}
	if minimumMasterchainSeqno != evidence.Finality.MasterchainSeqno ||
		evidence.Block.MasterchainSequence != evidence.Finality.MasterchainSeqno {
		return errors.New("Prediction source finality checkpoint is not the conservative quorum head")
	}
	view := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs,
		"agreeing_ids":        agreeing,
		"threshold":           record.Profile.QuorumThreshold,
		"masterchain_seqno":   evidence.Finality.MasterchainSeqno,
		"candidate":           candidate,
		"receipts":            receipts,
	}
	viewDigest, err := predictionTOSCTLJSONDigest(predictionSourceViewDigestDomain, view)
	if err != nil || viewDigest != evidence.Finality.FinalityViewID {
		return errors.New("Prediction source finality view digest is invalid")
	}
	return nil
}

func verifyTOSCTLPredictionDestinationEnvelope(record prediction.PredictionRelayRecord,
	envelope tosctlPredictionDestinationEnvelope,
) error {
	evidence := envelope.DestinationEvidence
	candidate := envelope.Candidate
	successful := candidate.Ordinary && !candidate.Aborted && candidate.ComputeSuccess &&
		candidate.ActionSuccess && candidate.OpcodeSuccess
	expectedState := "destination_failed_no_bounce"
	if successful {
		expectedState = "destination_committed"
	} else if candidate.BounceMessage != nil {
		expectedState = "destination_failed_bounce_created"
	}
	if envelope.Schema != tosctlPredictionDestinationEvidenceSchema ||
		envelope.StableActionID != record.ActionID || envelope.State != expectedState ||
		record.ActualOutbound == nil || candidate.InboundMessageHash != record.ActualOutbound.MessageHash ||
		evidence.InboundMessageHash != candidate.InboundMessageHash ||
		evidence.TransactionHash != candidate.TransactionHash ||
		evidence.TransactionBOCBase64 != candidate.TransactionBOCBase64 ||
		evidence.Block.WorkchainID != candidate.BlockWorkchain ||
		evidence.Block.Shard != candidate.BlockShard ||
		evidence.Block.SequenceNumber != candidate.BlockSeqno ||
		evidence.Block.RootHash != candidate.BlockRootHash ||
		evidence.Block.FileHash != candidate.BlockFileHash ||
		!reflect.DeepEqual(evidence.NextDestinationCursor, candidate.NextDestinationCursor) ||
		evidence.Ordinary != candidate.Ordinary || evidence.Aborted != candidate.Aborted ||
		evidence.ComputeSuccess != candidate.ComputeSuccess ||
		evidence.ActionSuccess != candidate.ActionSuccess ||
		evidence.OpcodeSuccess != candidate.OpcodeSuccess ||
		!reflect.DeepEqual(evidence.BounceMessage, candidate.BounceMessage) ||
		evidence.MarketCodeHash != record.Profile.MarketCodeHash ||
		evidence.MarketConfigHash != record.Profile.MarketConfigHash ||
		!reflect.DeepEqual(evidence.Finality.ObserverIDs, record.Profile.ObserverIDs) ||
		evidence.Finality.Threshold != record.Profile.QuorumThreshold ||
		len(envelope.ObserverReceipts) != len(evidence.Finality.AgreeingIDs) ||
		len(envelope.ObserverReceipts) < int(record.Profile.QuorumThreshold) {
		return errors.New("tosctl returned unrelated Prediction destination evidence")
	}
	if successful {
		if evidence.SuccessPredicateDigest != record.Expected.SuccessPredicateDigest ||
			evidence.NoBounceProof != nil || evidence.RichBounceEnvelopeHash != "" ||
			evidence.RichBounceOriginalBodyHash != "" {
			return errors.New("Prediction destination success predicate is inconsistent")
		}
	} else if candidate.BounceMessage != nil {
		if evidence.SuccessPredicateDigest != "" || evidence.NoBounceProof != nil ||
			evidence.RichBounceEnvelopeHash != candidate.BounceMessage.BodyHash ||
			evidence.RichBounceOriginalBodyHash != record.Expected.BodyHash {
			return errors.New("Prediction destination rich-bounce declaration is inconsistent")
		}
	} else if evidence.SuccessPredicateDigest != "" || evidence.NoBounceProof == nil ||
		evidence.RichBounceEnvelopeHash != "" || evidence.RichBounceOriginalBodyHash != "" {
		return errors.New("Prediction destination no-bounce declaration is inconsistent")
	}

	agreeing := append([]string(nil), evidence.Finality.AgreeingIDs...)
	sort.Strings(agreeing)
	if !reflect.DeepEqual(agreeing, evidence.Finality.AgreeingIDs) {
		return errors.New("Prediction destination agreeing observer identities are not canonical")
	}
	profileObservers := make(map[string]bool, len(record.Profile.ObserverIDs))
	for _, observerID := range record.Profile.ObserverIDs {
		profileObservers[observerID] = true
	}
	allowed := make(map[string]bool, len(agreeing))
	for _, observerID := range agreeing {
		if !canonicalSHA256(observerID) || !profileObservers[observerID] || allowed[observerID] {
			return errors.New("Prediction destination observer quorum is invalid")
		}
		allowed[observerID] = true
	}
	receipts := append([]tosctlPredictionDestinationObserverReceipt(nil), envelope.ObserverReceipts...)
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].ObserverID < receipts[j].ObserverID })
	operators := make(map[string]bool, len(receipts))
	minimumMasterchainSeqno := ^uint32(0)
	noBounceDigests := make([]string, 0, len(receipts))
	for index, receipt := range receipts {
		if index >= len(agreeing) || receipt.ObserverID != agreeing[index] ||
			!canonicalSHA256(receipt.OperatorProvenance) || operators[receipt.OperatorProvenance] ||
			!canonicalSHA256(receipt.CandidateDigest) ||
			receipt.ObservedMasterchain.WorkchainID != -1 ||
			receipt.ObservedMasterchain.SequenceNumber != receipt.ObservedMasterchain.MasterchainSequence ||
			receipt.ObservedMasterchain.SequenceNumber < candidate.ObservedMasterchainSeqno ||
			!canonicalBlockIdentity(receipt.ObservedMasterchain) ||
			receipt.MarketCodeHash != record.Profile.MarketCodeHash ||
			receipt.MarketConfigHash != record.Profile.MarketConfigHash {
			return errors.New("Prediction destination observer receipt is invalid")
		}
		operators[receipt.OperatorProvenance] = true
		if receipt.ObservedMasterchain.SequenceNumber < minimumMasterchainSeqno {
			minimumMasterchainSeqno = receipt.ObservedMasterchain.SequenceNumber
		}
		if !successful && candidate.BounceMessage == nil {
			projection := map[string]any{
				"observer_id":                  receipt.ObserverID,
				"operator_provenance":          receipt.OperatorProvenance,
				"action_id":                    record.ActionID,
				"inbound_message_hash":         record.ActualOutbound.MessageHash,
				"destination_transaction_hash": candidate.TransactionHash,
				"scan_start_masterchain_seqno": candidate.ObservedMasterchainSeqno,
				"scan_end_masterchain_seqno":   receipt.ObservedMasterchain.SequenceNumber,
				"outbound_count":               0,
			}
			digest, err := predictionTOSCTLJSONDigest(predictionNoBounceObservationDigestDomain, projection)
			if err != nil || digest != receipt.NoBounceObservationDigest {
				return errors.New("Prediction no-bounce observer digest is invalid")
			}
			noBounceDigests = append(noBounceDigests, digest)
		} else if receipt.NoBounceObservationDigest != "" {
			return errors.New("Prediction terminal receipt invents a no-bounce observation")
		}
		projection := map[string]any{
			"observer_id":                  receipt.ObserverID,
			"operator_provenance":          receipt.OperatorProvenance,
			"observed_masterchain":         receipt.ObservedMasterchain,
			"market_code_hash":             receipt.MarketCodeHash,
			"market_config_hash":           receipt.MarketConfigHash,
			"candidate":                    candidate,
			"no_bounce_observation_digest": receipt.NoBounceObservationDigest,
		}
		digest, err := predictionTOSCTLJSONDigest(predictionDestinationReceiptDigestDomain, projection)
		if err != nil || digest != receipt.CandidateDigest {
			return errors.New("Prediction destination observer receipt digest is invalid")
		}
	}
	if minimumMasterchainSeqno != evidence.Finality.MasterchainSeqno ||
		evidence.Block.MasterchainSequence != candidate.ObservedMasterchainSeqno ||
		evidence.Finality.MasterchainSeqno < evidence.Block.MasterchainSequence {
		return errors.New("Prediction destination finality checkpoint is not the conservative quorum head")
	}
	if evidence.Finality.NetworkDomainHash != record.Profile.NetworkDomainHash {
		return errors.New("Prediction destination finality is on another network")
	}
	if evidence.NoBounceProof != nil {
		sort.Strings(noBounceDigests)
		proof := evidence.NoBounceProof
		if proof.ScanStartMasterchainSeqno != candidate.ObservedMasterchainSeqno ||
			proof.ScanEndMasterchainSeqno != minimumMasterchainSeqno ||
			uint64(proof.ScanEndMasterchainSeqno) < uint64(proof.ScanStartMasterchainSeqno)+
				uint64(record.Profile.MinimumNoBounceMCBlocks) ||
			!reflect.DeepEqual(proof.ObservationDigests, noBounceDigests) {
			return errors.New("Prediction no-bounce evidence does not cover the frozen interval")
		}
		setProjection := map[string]any{
			"action_id":                    record.ActionID,
			"inbound_message_hash":         record.ActualOutbound.MessageHash,
			"destination_transaction_hash": candidate.TransactionHash,
			"scan_start_masterchain_seqno": candidate.ObservedMasterchainSeqno,
			"scan_end_masterchain_seqno":   minimumMasterchainSeqno,
			"observation_digests":          noBounceDigests,
		}
		digest, err := predictionTOSCTLJSONDigest(predictionNoBounceSetDigestDomain, setProjection)
		if err != nil || digest != proof.EvidenceSetDigest {
			return errors.New("Prediction no-bounce evidence-set digest is invalid")
		}
	}
	view := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs,
		"agreeing_ids":        agreeing,
		"threshold":           record.Profile.QuorumThreshold,
		"masterchain_seqno":   evidence.Finality.MasterchainSeqno,
		"candidate":           candidate,
		"receipts":            receipts,
		"no_bounce_proof":     evidence.NoBounceProof,
	}
	viewDigest, err := predictionTOSCTLJSONDigest(predictionDestinationViewDigestDomain, view)
	if err != nil || viewDigest != evidence.Finality.FinalityViewID {
		return errors.New("Prediction destination finality view digest is invalid")
	}
	return nil
}

func verifyTOSCTLPredictionBounceCreditEnvelope(record prediction.PredictionRelayRecord,
	envelope tosctlPredictionBounceCreditEnvelope,
) error {
	evidence := envelope.BounceCreditEvidence
	candidate := envelope.Candidate
	if envelope.Schema != tosctlPredictionBounceCreditEvidenceSchema ||
		envelope.StableActionID != record.ActionID || envelope.State != "bounce_credited_at_agent" ||
		record.DestinationEvidence == nil || record.DestinationEvidence.BounceMessage == nil ||
		candidate.InboundBounceMessageHash != record.DestinationEvidence.BounceMessage.MessageHash ||
		candidate.CreditedValueNanoTOS != record.DestinationEvidence.BounceMessage.ValueNanoTOS ||
		evidence.InboundBounceMessageHash != candidate.InboundBounceMessageHash ||
		evidence.TransactionHash != candidate.TransactionHash ||
		evidence.TransactionBOCBase64 != candidate.TransactionBOCBase64 ||
		evidence.Block.WorkchainID != candidate.BlockWorkchain ||
		evidence.Block.Shard != candidate.BlockShard ||
		evidence.Block.SequenceNumber != candidate.BlockSeqno ||
		evidence.Block.RootHash != candidate.BlockRootHash ||
		evidence.Block.FileHash != candidate.BlockFileHash ||
		evidence.Block.MasterchainSequence != candidate.ObservedMasterchainSeqno ||
		!reflect.DeepEqual(evidence.NextSourceCursor, candidate.NextSourceCursor) ||
		evidence.CreditedValueNanoTOS != candidate.CreditedValueNanoTOS ||
		!reflect.DeepEqual(evidence.Finality.ObserverIDs, record.Profile.ObserverIDs) ||
		evidence.Finality.Threshold != record.Profile.QuorumThreshold ||
		evidence.Finality.NetworkDomainHash != record.Profile.NetworkDomainHash ||
		len(envelope.ObserverReceipts) != len(evidence.Finality.AgreeingIDs) ||
		len(envelope.ObserverReceipts) < int(record.Profile.QuorumThreshold) {
		return errors.New("tosctl returned unrelated Prediction bounce-credit evidence")
	}
	agreeing := append([]string(nil), evidence.Finality.AgreeingIDs...)
	sort.Strings(agreeing)
	if !reflect.DeepEqual(agreeing, evidence.Finality.AgreeingIDs) {
		return errors.New("Prediction bounce-credit agreeing observer identities are not canonical")
	}
	profileObservers := make(map[string]bool, len(record.Profile.ObserverIDs))
	for _, observerID := range record.Profile.ObserverIDs {
		profileObservers[observerID] = true
	}
	allowed := make(map[string]bool, len(agreeing))
	for _, observerID := range agreeing {
		if !canonicalSHA256(observerID) || !profileObservers[observerID] || allowed[observerID] {
			return errors.New("Prediction bounce-credit observer quorum is invalid")
		}
		allowed[observerID] = true
	}
	receipts := append([]tosctlPredictionBounceCreditObserverReceipt(nil), envelope.ObserverReceipts...)
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].ObserverID < receipts[j].ObserverID })
	operators := make(map[string]bool, len(receipts))
	minimumMasterchainSeqno := ^uint32(0)
	for index, receipt := range receipts {
		if index >= len(agreeing) || receipt.ObserverID != agreeing[index] ||
			!canonicalSHA256(receipt.OperatorProvenance) || operators[receipt.OperatorProvenance] ||
			!canonicalSHA256(receipt.CandidateDigest) ||
			receipt.ObservedMasterchain.WorkchainID != -1 ||
			receipt.ObservedMasterchain.SequenceNumber != receipt.ObservedMasterchain.MasterchainSequence ||
			receipt.ObservedMasterchain.SequenceNumber < candidate.ObservedMasterchainSeqno ||
			!canonicalBlockIdentity(receipt.ObservedMasterchain) ||
			receipt.SourceAgentAccountCodeHash != record.Profile.SourceAgentAccountCodeHash {
			return errors.New("Prediction bounce-credit observer receipt is invalid")
		}
		operators[receipt.OperatorProvenance] = true
		if receipt.ObservedMasterchain.SequenceNumber < minimumMasterchainSeqno {
			minimumMasterchainSeqno = receipt.ObservedMasterchain.SequenceNumber
		}
		projection := map[string]any{
			"observer_id":                    receipt.ObserverID,
			"operator_provenance":            receipt.OperatorProvenance,
			"observed_masterchain":           receipt.ObservedMasterchain,
			"source_agent_account_code_hash": receipt.SourceAgentAccountCodeHash,
			"candidate":                      candidate,
		}
		digest, err := predictionTOSCTLJSONDigest(predictionBounceCreditReceiptDigestDomain, projection)
		if err != nil || digest != receipt.CandidateDigest {
			return errors.New("Prediction bounce-credit observer receipt digest is invalid")
		}
	}
	if minimumMasterchainSeqno != evidence.Finality.MasterchainSeqno ||
		evidence.Finality.MasterchainSeqno < evidence.Block.MasterchainSequence {
		return errors.New("Prediction bounce-credit finality is not the conservative quorum head")
	}
	view := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs,
		"agreeing_ids":        agreeing,
		"threshold":           record.Profile.QuorumThreshold,
		"masterchain_seqno":   evidence.Finality.MasterchainSeqno,
		"candidate":           candidate,
		"receipts":            receipts,
	}
	viewDigest, err := predictionTOSCTLJSONDigest(predictionBounceCreditViewDigestDomain, view)
	if err != nil || viewDigest != evidence.Finality.FinalityViewID {
		return errors.New("Prediction bounce-credit finality view digest is invalid")
	}
	return nil
}

func predictionTOSCTLJSONDigest(domain []byte, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var canonical any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&canonical); err != nil {
		return "", err
	}
	canonicalRaw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	hasher.Write(domain)
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(canonicalRaw)))
	hasher.Write(size[:])
	hasher.Write(canonicalRaw)
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func canonicalBlockIdentity(block prediction.BlockIdentity) bool {
	return block.SequenceNumber != 0 && block.MasterchainSequence != 0 &&
		canonicalSHA256(block.RootHash) && canonicalSHA256(block.FileHash)
}

type tosctlPredictionSourceAttestor struct {
	Profile  prediction.PredictionRelayProfile
	Block    prediction.BlockIdentity
	Finality prediction.QuorumFinality
}

func (attestor tosctlPredictionSourceAttestor) VerifyPredictionBlockFinality(_ context.Context,
	profile prediction.PredictionRelayProfile, block prediction.BlockIdentity,
	finality prediction.QuorumFinality,
) error {
	if !reflect.DeepEqual(profile, attestor.Profile) || block != attestor.Block ||
		!reflect.DeepEqual(finality, attestor.Finality) {
		return errors.New("Prediction source finality differs from the verified tosctl quorum view")
	}
	return nil
}

func (tosctlPredictionSourceAttestor) VerifyPredictionMarketIdentity(context.Context,
	prediction.PredictionRelayProfile, prediction.BlockIdentity,
) error {
	return errors.New("source-only Prediction attestor cannot verify market identity")
}

func (tosctlPredictionSourceAttestor) VerifyPredictionSuccessPredicate(context.Context,
	prediction.PredictionRelayRecord, prediction.DestinationTransactionEvidence,
) error {
	return errors.New("source-only Prediction attestor cannot verify destination success")
}

func (tosctlPredictionSourceAttestor) VerifyPredictionNoBounce(context.Context,
	prediction.PredictionRelayRecord, prediction.DestinationTransactionEvidence,
) error {
	return errors.New("source-only Prediction attestor cannot verify no-bounce evidence")
}

var _ prediction.PredictionRelayChainAttestor = tosctlPredictionSourceAttestor{}

type tosctlPredictionDestinationAttestor struct {
	Profile  prediction.PredictionRelayProfile
	Evidence prediction.DestinationTransactionEvidence
}

func (attestor tosctlPredictionDestinationAttestor) VerifyPredictionBlockFinality(_ context.Context,
	profile prediction.PredictionRelayProfile, block prediction.BlockIdentity,
	finality prediction.QuorumFinality,
) error {
	if !reflect.DeepEqual(profile, attestor.Profile) || block != attestor.Evidence.Block ||
		!reflect.DeepEqual(finality, attestor.Evidence.Finality) {
		return errors.New("Prediction destination finality differs from the verified tosctl quorum view")
	}
	return nil
}

func (attestor tosctlPredictionDestinationAttestor) VerifyPredictionMarketIdentity(_ context.Context,
	profile prediction.PredictionRelayProfile, block prediction.BlockIdentity,
) error {
	if !reflect.DeepEqual(profile, attestor.Profile) || block != attestor.Evidence.Block ||
		attestor.Evidence.MarketCodeHash != profile.MarketCodeHash ||
		attestor.Evidence.MarketConfigHash != profile.MarketConfigHash {
		return errors.New("Prediction market identity differs from the verified tosctl checkpoint")
	}
	return nil
}

func (attestor tosctlPredictionDestinationAttestor) VerifyPredictionSuccessPredicate(_ context.Context,
	record prediction.PredictionRelayRecord, evidence prediction.DestinationTransactionEvidence,
) error {
	if !reflect.DeepEqual(evidence, attestor.Evidence) ||
		evidence.SuccessPredicateDigest != record.Expected.SuccessPredicateDigest {
		return errors.New("Prediction success predicate differs from the verified exact-call semantics")
	}
	return nil
}

func (attestor tosctlPredictionDestinationAttestor) VerifyPredictionNoBounce(_ context.Context,
	_ prediction.PredictionRelayRecord, evidence prediction.DestinationTransactionEvidence,
) error {
	if !reflect.DeepEqual(evidence, attestor.Evidence) || evidence.NoBounceProof == nil {
		return errors.New("Prediction no-bounce proof differs from the verified bounded scan")
	}
	return nil
}

var _ prediction.PredictionRelayChainAttestor = tosctlPredictionDestinationAttestor{}

type tosctlPredictionBounceCreditAttestor struct {
	Profile  prediction.PredictionRelayProfile
	Evidence prediction.BounceCreditEvidence
}

func (attestor tosctlPredictionBounceCreditAttestor) VerifyPredictionBlockFinality(_ context.Context,
	profile prediction.PredictionRelayProfile, block prediction.BlockIdentity,
	finality prediction.QuorumFinality,
) error {
	if !reflect.DeepEqual(profile, attestor.Profile) || block != attestor.Evidence.Block ||
		!reflect.DeepEqual(finality, attestor.Evidence.Finality) {
		return errors.New("Prediction bounce-credit finality differs from the verified tosctl quorum view")
	}
	return nil
}

func (tosctlPredictionBounceCreditAttestor) VerifyPredictionMarketIdentity(context.Context,
	prediction.PredictionRelayProfile, prediction.BlockIdentity,
) error {
	return errors.New("bounce-only Prediction attestor cannot verify market identity")
}

func (tosctlPredictionBounceCreditAttestor) VerifyPredictionSuccessPredicate(context.Context,
	prediction.PredictionRelayRecord, prediction.DestinationTransactionEvidence,
) error {
	return errors.New("bounce-only Prediction attestor cannot verify destination success")
}

func (tosctlPredictionBounceCreditAttestor) VerifyPredictionNoBounce(context.Context,
	prediction.PredictionRelayRecord, prediction.DestinationTransactionEvidence,
) error {
	return errors.New("bounce-only Prediction attestor cannot verify no-bounce evidence")
}

var _ prediction.PredictionRelayChainAttestor = tosctlPredictionBounceCreditAttestor{}
