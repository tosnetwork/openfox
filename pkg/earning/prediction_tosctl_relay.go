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
	tosctlPredictionSourceRequestSchema  = "tosctl.prediction-relay-source-request.v1"
	tosctlPredictionSourceEvidenceSchema = "tosctl.prediction-relay-source-evidence.v1"
	maximumPredictionSourceTransactions  = 1_000_000
)

var (
	predictionSourceReceiptDigestDomain = []byte("tosctl.prediction-source-observer.v1\x00")
	predictionSourceViewDigestDomain    = []byte("tosctl.prediction-source-finality-view.v1\x00")
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

func (sink *TOSCTLPaymentSink) maximumPredictionTransactions() uint32 {
	if sink.PredictionMaximumTransactions == 0 {
		return 100_000
	}
	return sink.PredictionMaximumTransactions
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
	for _, observerID := range agreeing {
		if !canonicalSHA256(observerID) || allowed[observerID] {
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
