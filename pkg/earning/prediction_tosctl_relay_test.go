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

func TestVerifyTOSCTLPredictionDestinationEnvelopeBindsReceiptsAndPredicate(t *testing.T) {
	digest := func(label string) string {
		value := sha256.Sum256([]byte(label))
		return "sha256:" + hex.EncodeToString(value[:])
	}
	cellDigest := func(label string) string {
		value := sha256.Sum256([]byte(label))
		return "tvm-cell-sha256:" + hex.EncodeToString(value[:])
	}
	observers := []string{digest("destination-observer-a"), digest("destination-observer-b"), digest("destination-observer-c")}
	for i := 0; i < len(observers); i++ {
		for j := i + 1; j < len(observers); j++ {
			if observers[j] < observers[i] {
				observers[i], observers[j] = observers[j], observers[i]
			}
		}
	}
	actual := prediction.ChainObservedMessage{MessageHash: cellDigest("actual-outbound")}
	record := prediction.PredictionRelayRecord{
		ActionID: digest("destination-action"), ActualOutbound: &actual,
		Profile: prediction.PredictionRelayProfile{
			NetworkDomainHash: digest("destination-network"), ObserverIDs: observers,
			QuorumThreshold: 2, MarketCodeHash: cellDigest("market-code"),
			MarketConfigHash: cellDigest("market-config"), MinimumNoBounceMCBlocks: 5,
		},
		Expected: prediction.ExpectedContractCall{SuccessPredicateDigest: digest("predicate")},
	}
	candidate := tosctlPredictionDestinationCandidate{
		InboundMessageHash: actual.MessageHash, TransactionHash: digest("destination-tx"),
		TransactionBOCBase64: "dHJhbnNhY3Rpb24=", BlockWorkchain: 0, BlockShard: 1,
		BlockSeqno: 9, BlockRootHash: digest("destination-block-root"),
		BlockFileHash: digest("destination-block-file"), ObservedMasterchainSeqno: 15,
		NextDestinationCursor: prediction.AccountCursor{
			AccountAddress: "0:market", LastLogicalTime: 12,
			LastTransactionHash: digest("destination-tx"),
		},
		Ordinary: true, ComputeSuccess: true, ActionSuccess: true, OpcodeSuccess: true,
	}
	evidence := prediction.DestinationTransactionEvidence{
		InboundMessageHash: candidate.InboundMessageHash, TransactionHash: candidate.TransactionHash,
		TransactionBOCBase64: candidate.TransactionBOCBase64,
		Block: prediction.BlockIdentity{
			WorkchainID: candidate.BlockWorkchain, Shard: candidate.BlockShard,
			SequenceNumber: candidate.BlockSeqno, RootHash: candidate.BlockRootHash,
			FileHash: candidate.BlockFileHash, MasterchainSequence: 15,
		},
		NextDestinationCursor: candidate.NextDestinationCursor, Ordinary: true,
		ComputeSuccess: true, ActionSuccess: true, OpcodeSuccess: true,
		MarketCodeHash:         record.Profile.MarketCodeHash,
		MarketConfigHash:       record.Profile.MarketConfigHash,
		SuccessPredicateDigest: record.Expected.SuccessPredicateDigest,
	}
	evidence.Finality = prediction.QuorumFinality{
		NetworkDomainHash: record.Profile.NetworkDomainHash,
		ObserverIDs:       append([]string(nil), observers...), AgreeingIDs: append([]string(nil), observers[:2]...),
		Threshold: 2, MasterchainSeqno: 20,
	}
	receipts := make([]tosctlPredictionDestinationObserverReceipt, 0, 2)
	for index, observer := range evidence.Finality.AgreeingIDs {
		receipt := tosctlPredictionDestinationObserverReceipt{
			ObserverID: observer, OperatorProvenance: digest("destination-operator-" + string(rune('a'+index))),
			ObservedMasterchain: prediction.BlockIdentity{
				WorkchainID: -1, Shard: -1 << 63, SequenceNumber: uint32(20 + index),
				RootHash:            digest("destination-master-root-" + string(rune('a'+index))),
				FileHash:            digest("destination-master-file-" + string(rune('a'+index))),
				MasterchainSequence: uint32(20 + index),
			},
			MarketCodeHash:   record.Profile.MarketCodeHash,
			MarketConfigHash: record.Profile.MarketConfigHash,
		}
		projection := map[string]any{
			"observer_id": receipt.ObserverID, "operator_provenance": receipt.OperatorProvenance,
			"observed_masterchain": receipt.ObservedMasterchain,
			"market_code_hash":     receipt.MarketCodeHash, "market_config_hash": receipt.MarketConfigHash,
			"candidate": candidate, "no_bounce_observation_digest": "",
		}
		receipt.CandidateDigest, _ = predictionTOSCTLJSONDigest(predictionDestinationReceiptDigestDomain, projection)
		receipts = append(receipts, receipt)
	}
	view := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs, "agreeing_ids": evidence.Finality.AgreeingIDs,
		"threshold": record.Profile.QuorumThreshold, "masterchain_seqno": uint32(20),
		"candidate": candidate, "receipts": receipts, "no_bounce_proof": nil,
	}
	evidence.Finality.FinalityViewID, _ = predictionTOSCTLJSONDigest(predictionDestinationViewDigestDomain, view)
	envelope := tosctlPredictionDestinationEnvelope{
		Schema: tosctlPredictionDestinationEvidenceSchema, StableActionID: record.ActionID,
		DestinationEvidence: evidence, Candidate: candidate, ObserverReceipts: receipts,
		State: "destination_committed",
	}
	if err := verifyTOSCTLPredictionDestinationEnvelope(record, envelope); err != nil {
		t.Fatalf("valid destination envelope rejected: %v", err)
	}
	noBounceCandidate := candidate
	noBounceCandidate.Aborted = true
	noBounceCandidate.ComputeSuccess = false
	noBounceCandidate.ActionSuccess = false
	noBounceCandidate.OpcodeSuccess = false
	noBounceEvidence := evidence
	noBounceEvidence.Aborted = true
	noBounceEvidence.ComputeSuccess = false
	noBounceEvidence.ActionSuccess = false
	noBounceEvidence.OpcodeSuccess = false
	noBounceEvidence.SuccessPredicateDigest = ""
	noBounceReceipts := append([]tosctlPredictionDestinationObserverReceipt(nil), receipts...)
	noBounceDigests := make([]string, 0, len(noBounceReceipts))
	for index := range noBounceReceipts {
		receipt := &noBounceReceipts[index]
		absenceProjection := map[string]any{
			"observer_id": receipt.ObserverID, "operator_provenance": receipt.OperatorProvenance,
			"action_id": record.ActionID, "inbound_message_hash": actual.MessageHash,
			"destination_transaction_hash": noBounceCandidate.TransactionHash,
			"scan_start_masterchain_seqno": noBounceCandidate.ObservedMasterchainSeqno,
			"scan_end_masterchain_seqno":   receipt.ObservedMasterchain.SequenceNumber,
			"outbound_count":               0,
		}
		receipt.NoBounceObservationDigest, _ = predictionTOSCTLJSONDigest(
			predictionNoBounceObservationDigestDomain, absenceProjection,
		)
		noBounceDigests = append(noBounceDigests, receipt.NoBounceObservationDigest)
		projection := map[string]any{
			"observer_id": receipt.ObserverID, "operator_provenance": receipt.OperatorProvenance,
			"observed_masterchain": receipt.ObservedMasterchain,
			"market_code_hash":     receipt.MarketCodeHash, "market_config_hash": receipt.MarketConfigHash,
			"candidate":                    noBounceCandidate,
			"no_bounce_observation_digest": receipt.NoBounceObservationDigest,
		}
		receipt.CandidateDigest, _ = predictionTOSCTLJSONDigest(predictionDestinationReceiptDigestDomain, projection)
	}
	for i := 0; i < len(noBounceDigests); i++ {
		for j := i + 1; j < len(noBounceDigests); j++ {
			if noBounceDigests[j] < noBounceDigests[i] {
				noBounceDigests[i], noBounceDigests[j] = noBounceDigests[j], noBounceDigests[i]
			}
		}
	}
	noBounceProof := &prediction.BoundedAbsenceEvidence{
		ScanStartMasterchainSeqno: noBounceCandidate.ObservedMasterchainSeqno,
		ScanEndMasterchainSeqno:   evidence.Finality.MasterchainSeqno,
		ObservationDigests:        noBounceDigests,
	}
	setProjection := map[string]any{
		"action_id": record.ActionID, "inbound_message_hash": actual.MessageHash,
		"destination_transaction_hash": noBounceCandidate.TransactionHash,
		"scan_start_masterchain_seqno": noBounceProof.ScanStartMasterchainSeqno,
		"scan_end_masterchain_seqno":   noBounceProof.ScanEndMasterchainSeqno,
		"observation_digests":          noBounceDigests,
	}
	noBounceProof.EvidenceSetDigest, _ = predictionTOSCTLJSONDigest(predictionNoBounceSetDigestDomain, setProjection)
	noBounceEvidence.NoBounceProof = noBounceProof
	noBounceView := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs, "agreeing_ids": noBounceEvidence.Finality.AgreeingIDs,
		"threshold": record.Profile.QuorumThreshold, "masterchain_seqno": noBounceEvidence.Finality.MasterchainSeqno,
		"candidate": noBounceCandidate, "receipts": noBounceReceipts,
		"no_bounce_proof": noBounceProof,
	}
	noBounceEvidence.Finality.FinalityViewID, _ = predictionTOSCTLJSONDigest(
		predictionDestinationViewDigestDomain, noBounceView,
	)
	noBounceEnvelope := tosctlPredictionDestinationEnvelope{
		Schema: tosctlPredictionDestinationEvidenceSchema, StableActionID: record.ActionID,
		DestinationEvidence: noBounceEvidence, Candidate: noBounceCandidate,
		ObserverReceipts: noBounceReceipts, State: "destination_failed_no_bounce",
	}
	if err := verifyTOSCTLPredictionDestinationEnvelope(record, noBounceEnvelope); err != nil {
		t.Fatalf("valid bounded no-bounce envelope rejected: %v", err)
	}
	noBounceEnvelope.DestinationEvidence.NoBounceProof.ScanEndMasterchainSeqno--
	if err := verifyTOSCTLPredictionDestinationEnvelope(record, noBounceEnvelope); err == nil {
		t.Fatal("destination envelope accepted a shortened no-bounce interval")
	}
	envelope.ObserverReceipts[0].MarketConfigHash = cellDigest("attacker-config")
	if err := verifyTOSCTLPredictionDestinationEnvelope(record, envelope); err == nil {
		t.Fatal("destination envelope accepted a market identity mutation")
	}
}

func TestVerifyTOSCTLPredictionBounceCreditEnvelopeBindsExactCredit(t *testing.T) {
	digest := func(label string) string {
		value := sha256.Sum256([]byte(label))
		return "sha256:" + hex.EncodeToString(value[:])
	}
	cellDigest := func(label string) string {
		value := sha256.Sum256([]byte(label))
		return "tvm-cell-sha256:" + hex.EncodeToString(value[:])
	}
	observers := []string{digest("bounce-observer-a"), digest("bounce-observer-b"), digest("bounce-observer-c")}
	for i := 0; i < len(observers); i++ {
		for j := i + 1; j < len(observers); j++ {
			if observers[j] < observers[i] {
				observers[i], observers[j] = observers[j], observers[i]
			}
		}
	}
	bounce := prediction.ChainObservedMessage{MessageHash: cellDigest("rich-bounce"), ValueNanoTOS: 77}
	record := prediction.PredictionRelayRecord{
		ActionID: digest("bounce-action"),
		Profile: prediction.PredictionRelayProfile{
			NetworkDomainHash: digest("bounce-network"), ObserverIDs: observers, QuorumThreshold: 2,
			SourceAgentAccountCodeHash: cellDigest("agent-v2-code"),
		},
		DestinationEvidence: &prediction.DestinationTransactionEvidence{BounceMessage: &bounce},
	}
	candidate := tosctlPredictionBounceCreditCandidate{
		InboundBounceMessageHash: bounce.MessageHash, TransactionHash: digest("bounce-credit-tx"),
		TransactionBOCBase64: "dHJhbnNhY3Rpb24=", BlockWorkchain: -1, BlockShard: -1 << 63,
		BlockSeqno: 30, BlockRootHash: digest("bounce-block-root"),
		BlockFileHash: digest("bounce-block-file"), ObservedMasterchainSeqno: 30,
		NextSourceCursor: prediction.AccountCursor{
			AccountAddress: "-1:agent", LastLogicalTime: 31,
			LastTransactionHash: digest("bounce-credit-tx"),
		},
		CreditedValueNanoTOS: bounce.ValueNanoTOS,
	}
	evidence := prediction.BounceCreditEvidence{
		InboundBounceMessageHash: candidate.InboundBounceMessageHash,
		TransactionHash:          candidate.TransactionHash, TransactionBOCBase64: candidate.TransactionBOCBase64,
		Block: prediction.BlockIdentity{
			WorkchainID: candidate.BlockWorkchain, Shard: candidate.BlockShard,
			SequenceNumber: candidate.BlockSeqno, RootHash: candidate.BlockRootHash,
			FileHash: candidate.BlockFileHash, MasterchainSequence: candidate.ObservedMasterchainSeqno,
		},
		NextSourceCursor: candidate.NextSourceCursor, CreditedValueNanoTOS: candidate.CreditedValueNanoTOS,
	}
	evidence.Finality = prediction.QuorumFinality{
		NetworkDomainHash: record.Profile.NetworkDomainHash,
		ObserverIDs:       append([]string(nil), observers...), AgreeingIDs: append([]string(nil), observers[:2]...),
		Threshold: 2, MasterchainSeqno: 32,
	}
	receipts := make([]tosctlPredictionBounceCreditObserverReceipt, 0, 2)
	for index, observer := range evidence.Finality.AgreeingIDs {
		receipt := tosctlPredictionBounceCreditObserverReceipt{
			ObserverID: observer, OperatorProvenance: digest("bounce-operator-" + string(rune('a'+index))),
			ObservedMasterchain: prediction.BlockIdentity{
				WorkchainID: -1, Shard: -1 << 63, SequenceNumber: uint32(32 + index),
				RootHash:            digest("bounce-master-root-" + string(rune('a'+index))),
				FileHash:            digest("bounce-master-file-" + string(rune('a'+index))),
				MasterchainSequence: uint32(32 + index),
			},
			SourceAgentAccountCodeHash: record.Profile.SourceAgentAccountCodeHash,
		}
		projection := map[string]any{
			"observer_id": receipt.ObserverID, "operator_provenance": receipt.OperatorProvenance,
			"observed_masterchain":           receipt.ObservedMasterchain,
			"source_agent_account_code_hash": receipt.SourceAgentAccountCodeHash,
			"candidate":                      candidate,
		}
		receipt.CandidateDigest, _ = predictionTOSCTLJSONDigest(predictionBounceCreditReceiptDigestDomain, projection)
		receipts = append(receipts, receipt)
	}
	view := map[string]any{
		"network_domain_hash": record.Profile.NetworkDomainHash,
		"observer_ids":        record.Profile.ObserverIDs, "agreeing_ids": evidence.Finality.AgreeingIDs,
		"threshold": record.Profile.QuorumThreshold, "masterchain_seqno": evidence.Finality.MasterchainSeqno,
		"candidate": candidate, "receipts": receipts,
	}
	evidence.Finality.FinalityViewID, _ = predictionTOSCTLJSONDigest(predictionBounceCreditViewDigestDomain, view)
	envelope := tosctlPredictionBounceCreditEnvelope{
		Schema: tosctlPredictionBounceCreditEvidenceSchema, StableActionID: record.ActionID,
		BounceCreditEvidence: evidence, Candidate: candidate, ObserverReceipts: receipts,
		State: "bounce_credited_at_agent",
	}
	if err := verifyTOSCTLPredictionBounceCreditEnvelope(record, envelope); err != nil {
		t.Fatalf("valid bounce-credit envelope rejected: %v", err)
	}
	envelope.BounceCreditEvidence.CreditedValueNanoTOS++
	if err := verifyTOSCTLPredictionBounceCreditEnvelope(record, envelope); err == nil {
		t.Fatal("bounce-credit envelope accepted a changed credited amount")
	}
}
