package earning

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/tosnetwork/openfox/pkg/prediction"
)

func TestVerifyTOSCTLPredictionSourceEnvelopeBindsReceiptsAndView(t *testing.T) {
	digest := func(label string) string {
		value := sha256.Sum256([]byte(label))
		return "sha256:" + hex.EncodeToString(value[:])
	}
	cellDigest := func(label string) string {
		value := sha256.Sum256([]byte(label))
		return "tvm-cell-sha256:" + hex.EncodeToString(value[:])
	}
	observers := []string{digest("observer-a"), digest("observer-b"), digest("observer-c")}
	// The production profile requires canonical lexical ordering.
	if observers[0] > observers[1] {
		observers[0], observers[1] = observers[1], observers[0]
	}
	if observers[1] > observers[2] {
		observers[1], observers[2] = observers[2], observers[1]
	}
	if observers[0] > observers[1] {
		observers[0], observers[1] = observers[1], observers[0]
	}
	block := prediction.BlockIdentity{
		WorkchainID: 0, Shard: 1, SequenceNumber: 7,
		RootHash: digest("block-root"), FileHash: digest("block-file"), MasterchainSequence: 11,
	}
	record := prediction.PredictionRelayRecord{
		ActionID: digest("action"), SubmittedExternalMessageHash: cellDigest("external"),
		Profile: prediction.PredictionRelayProfile{
			NetworkDomainHash: digest("network"), ObserverIDs: observers, QuorumThreshold: 2,
		},
	}
	evidence := prediction.SourceTransactionEvidence{
		SubmittedExternalMessageHash: record.SubmittedExternalMessageHash,
		TransactionHash:              digest("transaction"), TransactionBOCBase64: "dHJhbnNhY3Rpb24=",
		Block: block,
		NextSourceCursor: prediction.AccountCursor{
			AccountAddress: "0:source", LastLogicalTime: 8, LastTransactionHash: digest("transaction"),
		},
	}
	evidence.Finality = prediction.QuorumFinality{
		NetworkDomainHash: record.Profile.NetworkDomainHash,
		ObserverIDs:       append([]string(nil), observers...), AgreeingIDs: append([]string(nil), observers[:2]...),
		Threshold: 2, MasterchainSeqno: 11,
	}
	candidate := tosctlPredictionSourceCandidate{
		TransactionHash: evidence.TransactionHash, TransactionBOC: evidence.TransactionBOCBase64,
		BlockWorkchain: block.WorkchainID, BlockShard: block.Shard, BlockSeqno: block.SequenceNumber,
		BlockRootHash: block.RootHash, BlockFileHash: block.FileHash,
		NextSourceCursor: evidence.NextSourceCursor, OutboundMessages: evidence.OutboundMessages,
	}
	receipts := make([]tosctlPredictionSourceObserverReceipt, 0, 2)
	for index, observer := range evidence.Finality.AgreeingIDs {
		receipt := tosctlPredictionSourceObserverReceipt{
			ObserverID: observer, OperatorProvenance: digest("operator-" + string(rune('a'+index))),
			ObservedMasterchain: prediction.BlockIdentity{
				WorkchainID: -1, Shard: -1 << 63, SequenceNumber: 11,
				RootHash: digest("master-root"), FileHash: digest("master-file"), MasterchainSequence: 11,
			},
			FinalizedDeploymentID:    hex.EncodeToString(make([]byte, 32)),
			FinalizedControllerEpoch: 1, FinalizedSeqno: 2,
		}
		projection := map[string]any{
			"observer_id": receipt.ObserverID, "operator_provenance": receipt.OperatorProvenance,
			"observed_masterchain":       receipt.ObservedMasterchain,
			"finalized_deployment_id":    receipt.FinalizedDeploymentID,
			"finalized_controller_epoch": receipt.FinalizedControllerEpoch,
			"finalized_seqno":            receipt.FinalizedSeqno, "candidate": candidate,
		}
		receipt.CandidateDigest, _ = predictionTOSCTLJSONDigest(
			predictionSourceReceiptDigestDomain, projection,
		)
		receipts = append(receipts, receipt)
	}
	view := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs, "agreeing_ids": evidence.Finality.AgreeingIDs,
		"threshold":         record.Profile.QuorumThreshold,
		"masterchain_seqno": evidence.Finality.MasterchainSeqno,
		"candidate":         candidate, "receipts": receipts,
	}
	evidence.Finality.FinalityViewID, _ = predictionTOSCTLJSONDigest(
		predictionSourceViewDigestDomain, view,
	)
	envelope := tosctlPredictionSourceEnvelope{
		Schema: tosctlPredictionSourceEvidenceSchema, StableActionID: record.ActionID,
		SourceEvidence: evidence, ObserverReceipts: receipts, State: "source_action_skipped",
	}
	if err := verifyTOSCTLPredictionSourceEnvelope(record, envelope); err != nil {
		t.Fatalf("valid source envelope rejected: %v", err)
	}
	envelope.ObserverReceipts[0].FinalizedSeqno++
	if err := verifyTOSCTLPredictionSourceEnvelope(record, envelope); err == nil {
		t.Fatal("source envelope accepted a receipt mutation without a new receipt/view digest")
	}
}

func TestPredictionTOSCTLJSONDigestGolden(t *testing.T) {
	digest, err := predictionTOSCTLJSONDigest(
		predictionSourceReceiptDigestDomain,
		map[string]any{"z": "last", "a": uint64(7), "nested": map[string]any{"b": true, "a": "x"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:82c45f946d85935641b722a83c69932efecd7c28e797157011e5aee8f6fc9a13" {
		t.Fatalf("cross-language source receipt digest drifted: %s", digest)
	}
}
