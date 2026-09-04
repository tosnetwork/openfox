package prediction

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type relayVerifierAttestor struct {
	finalityCalls int
	marketCalls   int
	successCalls  int
	absenceCalls  int
}

func (attestor *relayVerifierAttestor) VerifyPredictionBlockFinality(
	context.Context, PredictionRelayProfile, BlockIdentity, QuorumFinality,
) error {
	attestor.finalityCalls++
	return nil
}

func (attestor *relayVerifierAttestor) VerifyPredictionMarketIdentity(
	context.Context, PredictionRelayProfile, BlockIdentity,
) error {
	attestor.marketCalls++
	return nil
}

func (attestor *relayVerifierAttestor) VerifyPredictionSuccessPredicate(
	context.Context, PredictionRelayRecord, DestinationTransactionEvidence,
) error {
	attestor.successCalls++
	return nil
}

func (attestor *relayVerifierAttestor) VerifyPredictionNoBounce(
	context.Context, PredictionRelayRecord, DestinationTransactionEvidence,
) error {
	attestor.absenceCalls++
	return nil
}

func TestCanonicalRelayVerifierParsesSourceAndDestinationTransactions(t *testing.T) {
	fixture := newRelayFixture(t)
	source, _ := address.ParseRawAddr(fixture.profile.SourceAgentAccount)
	market, _ := address.ParseRawAddr(fixture.profile.MarketAddress)

	externalBody := cell.BeginCell().MustStoreUInt(0x5151, 16).EndCell()
	external := &tlb.Message{MsgType: tlb.MsgTypeExternalIn, Msg: &tlb.ExternalMessage{
		SrcAddr: address.NewAddressNone(), DstAddr: source, ImportFee: tlb.ZeroCoins, Body: externalBody,
	}}
	externalCell, err := external.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	callBody, err := decodeCanonicalCell(fixture.expected.BodyBOCBase64, maximumChainBOCBytes)
	if err != nil {
		t.Fatal(err)
	}
	outbound := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{
		IHRDisabled: true, Bounce: true, SrcAddr: source, DstAddr: market,
		Amount: tlb.FromNanoTONU(fixture.expected.ValueNanoTOS), IHRFee: tlb.FromNanoTONU(3),
		FwdFee: tlb.FromNanoTONU(1), CreatedLT: 101, CreatedAt: 1_800_000_000, Body: callBody,
	}}
	declaredOutbound := declaredVerifierMessage(t, outbound, 3)
	record := PredictionRelayRecord{
		Profile: fixture.profile, Expected: fixture.expected,
		SubmittedExternalMessageHash: cellDigest(externalCell), ActualOutbound: &declaredOutbound,
	}
	block, finality := verifierBlockAndFinality(fixture.profile)

	sourceTx := verifierTransaction(t, source, 110, external, []*tlb.Message{outbound}, true, 0)
	sourceEvidence := SourceTransactionEvidence{
		SubmittedExternalMessageHash: record.SubmittedExternalMessageHash,
		TransactionHash:              "sha256:" + hex.EncodeToString(sourceTx.Hash()),
		TransactionBOCBase64:         base64.StdEncoding.EncodeToString(sourceTx.ToBOCWithFlags(false)),
		Block:                        block, Finality: finality,
		NextSourceCursor: AccountCursor{AccountAddress: fixture.profile.SourceAgentAccount,
			LastLogicalTime: 110, LastTransactionHash: "sha256:" + hex.EncodeToString(sourceTx.Hash())},
		OutboundMessages: []ChainObservedMessage{declaredOutbound},
	}
	attestor := &relayVerifierAttestor{}
	verifier := CanonicalPredictionRelayEvidenceVerifier{Attestor: attestor}
	if err := verifier.VerifyPredictionSource(t.Context(), record, sourceEvidence); err != nil {
		t.Fatalf("valid source transaction rejected: %v", err)
	}
	if attestor.finalityCalls != 1 {
		t.Fatal("source transaction did not cross the finality attestor")
	}
	mutatedSource := sourceEvidence
	mutatedSource.OutboundMessages = append([]ChainObservedMessage(nil), sourceEvidence.OutboundMessages...)
	mutatedSource.OutboundMessages[0].ValueNanoTOS++
	if err := verifier.VerifyPredictionSource(t.Context(), record, mutatedSource); err == nil {
		t.Fatal("source verifier accepted JSON fields that contradict the message BOC")
	}
	wrongFlagsOutbound := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{
		IHRDisabled: true, Bounce: true, SrcAddr: source, DstAddr: market,
		Amount: tlb.FromNanoTONU(fixture.expected.ValueNanoTOS), IHRFee: tlb.FromNanoTONU(2),
		FwdFee: tlb.FromNanoTONU(1), CreatedLT: 102, CreatedAt: 1_800_000_000, Body: callBody,
	}}
	wrongFlagsDeclared := declaredVerifierMessage(t, wrongFlagsOutbound, 3)
	wrongFlagsTx := verifierTransaction(t, source, 111, external, []*tlb.Message{wrongFlagsOutbound}, true, 0)
	wrongFlagsEvidence := sourceEvidence
	wrongFlagsEvidence.TransactionHash = "sha256:" + hex.EncodeToString(wrongFlagsTx.Hash())
	wrongFlagsEvidence.TransactionBOCBase64 = base64.StdEncoding.EncodeToString(
		wrongFlagsTx.ToBOCWithFlags(false),
	)
	wrongFlagsEvidence.NextSourceCursor.LastLogicalTime = 111
	wrongFlagsEvidence.NextSourceCursor.LastTransactionHash = wrongFlagsEvidence.TransactionHash
	wrongFlagsEvidence.OutboundMessages = []ChainObservedMessage{wrongFlagsDeclared}
	if err := verifier.VerifyPredictionSource(t.Context(), record, wrongFlagsEvidence); err == nil {
		t.Fatal("source verifier accepted JSON extra_flags=3 for a message carrying extra_flags=2")
	}

	destinationTx := verifierTransaction(t, market, 120, outbound, nil, true, 0)
	destinationEvidence := DestinationTransactionEvidence{
		InboundMessageHash: declaredOutbound.MessageHash,
		TransactionHash:    "sha256:" + hex.EncodeToString(destinationTx.Hash()),
		TransactionBOCBase64: base64.StdEncoding.EncodeToString(
			destinationTx.ToBOCWithFlags(false),
		),
		Block: block, Finality: finality,
		NextDestinationCursor: AccountCursor{AccountAddress: fixture.profile.MarketAddress,
			LastLogicalTime: 120, LastTransactionHash: "sha256:" + hex.EncodeToString(destinationTx.Hash())},
		Ordinary: true, ComputeSuccess: true, ActionSuccess: true, OpcodeSuccess: true,
		MarketCodeHash: fixture.profile.MarketCodeHash, MarketConfigHash: fixture.profile.MarketConfigHash,
		SuccessPredicateDigest: fixture.expected.SuccessPredicateDigest,
	}
	if err := verifier.VerifyPredictionDestination(t.Context(), record, destinationEvidence); err != nil {
		t.Fatalf("valid destination transaction rejected: %v", err)
	}
	if attestor.finalityCalls != 2 || attestor.marketCalls != 1 || attestor.successCalls != 1 {
		t.Fatalf("destination omitted a trust boundary: %+v", attestor)
	}
	mutatedDestination := destinationEvidence
	mutatedDestination.ComputeSuccess = false
	if err := verifier.VerifyPredictionDestination(t.Context(), record, mutatedDestination); err == nil {
		t.Fatal("destination verifier accepted self-reported execution flags")
	}
}

func TestCanonicalRelayVerifierParsesBounceAndCredit(t *testing.T) {
	fixture := newRelayFixture(t)
	source, _ := address.ParseRawAddr(fixture.profile.SourceAgentAccount)
	market, _ := address.ParseRawAddr(fixture.profile.MarketAddress)
	callBody, _ := decodeCanonicalCell(fixture.expected.BodyBOCBase64, maximumChainBOCBytes)
	outbound := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{
		IHRDisabled: true, Bounce: true, SrcAddr: source, DstAddr: market,
		Amount: tlb.FromNanoTONU(fixture.expected.ValueNanoTOS), IHRFee: tlb.FromNanoTONU(3),
		FwdFee: tlb.FromNanoTONU(1), CreatedLT: 201, CreatedAt: 1_800_000_000, Body: callBody,
	}}
	declaredOutbound := declaredVerifierMessage(t, outbound, 3)
	bounceBody := verifierRichBounceBody(t, outbound.AsInternal(), 1, 0, true, 1, 1)
	bounce := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{
		IHRDisabled: true, Bounced: true, SrcAddr: market, DstAddr: source,
		Amount: tlb.FromNanoTONU(fixture.expected.ValueNanoTOS - 100), IHRFee: tlb.FromNanoTONU(3),
		FwdFee: tlb.FromNanoTONU(1), CreatedLT: 202, CreatedAt: 1_800_000_001, Body: bounceBody,
	}}
	declaredBounce := declaredVerifierMessage(t, bounce, 3)
	record := PredictionRelayRecord{Profile: fixture.profile, Expected: fixture.expected,
		ActualOutbound: &declaredOutbound}
	block, finality := verifierBlockAndFinality(fixture.profile)
	destinationTx := verifierTransaction(t, market, 210, outbound, []*tlb.Message{bounce}, false, 0)
	destinationEvidence := DestinationTransactionEvidence{
		InboundMessageHash: declaredOutbound.MessageHash,
		TransactionHash:    "sha256:" + hex.EncodeToString(destinationTx.Hash()),
		TransactionBOCBase64: base64.StdEncoding.EncodeToString(
			destinationTx.ToBOCWithFlags(false),
		),
		Block: block, Finality: finality,
		NextDestinationCursor: AccountCursor{AccountAddress: fixture.profile.MarketAddress,
			LastLogicalTime: 210, LastTransactionHash: "sha256:" + hex.EncodeToString(destinationTx.Hash())},
		Ordinary: true, Aborted: true, BounceMessage: &declaredBounce,
		MarketCodeHash: fixture.profile.MarketCodeHash, MarketConfigHash: fixture.profile.MarketConfigHash,
		RichBounceEnvelopeHash: declaredBounce.BodyHash, RichBounceOriginalBodyHash: fixture.expected.BodyHash,
	}
	attestor := &relayVerifierAttestor{}
	verifier := CanonicalPredictionRelayEvidenceVerifier{Attestor: attestor}
	if err := verifier.VerifyPredictionDestination(t.Context(), record, destinationEvidence); err != nil {
		t.Fatalf("valid failed destination/bounce rejected: %v", err)
	}
	legacyBounce := *bounce
	legacyBounce.Msg = &tlb.InternalMessage{
		IHRDisabled: true, Bounced: true, SrcAddr: market, DstAddr: source,
		Amount: tlb.FromNanoTONU(fixture.expected.ValueNanoTOS - 100), IHRFee: tlb.FromNanoTONU(3),
		FwdFee: tlb.FromNanoTONU(1), CreatedLT: 202, CreatedAt: 1_800_000_001,
		Body: cell.BeginCell().MustStoreUInt(0xffffffff, 32).MustStoreUInt(0x504d000f, 32).EndCell(),
	}
	legacyDeclared := declaredVerifierMessage(t, &legacyBounce, 3)
	legacyTx := verifierTransaction(t, market, 211, outbound, []*tlb.Message{&legacyBounce}, false, 0)
	legacyEvidence := destinationEvidence
	legacyEvidence.TransactionHash = "sha256:" + hex.EncodeToString(legacyTx.Hash())
	legacyEvidence.TransactionBOCBase64 = base64.StdEncoding.EncodeToString(legacyTx.ToBOCWithFlags(false))
	legacyEvidence.NextDestinationCursor.LastLogicalTime = 211
	legacyEvidence.NextDestinationCursor.LastTransactionHash = legacyEvidence.TransactionHash
	legacyEvidence.BounceMessage = &legacyDeclared
	legacyEvidence.RichBounceEnvelopeHash = legacyDeclared.BodyHash
	if err := verifier.VerifyPredictionDestination(t.Context(), record, legacyEvidence); err == nil {
		t.Fatal("destination verifier accepted a legacy/truncated bounce as a full rich bounce")
	}
	noBounceTx := verifierTransaction(t, market, 215, outbound, nil, false, 0)
	noBounce := destinationEvidence
	noBounce.TransactionHash = "sha256:" + hex.EncodeToString(noBounceTx.Hash())
	noBounce.TransactionBOCBase64 = base64.StdEncoding.EncodeToString(noBounceTx.ToBOCWithFlags(false))
	noBounce.NextDestinationCursor.LastLogicalTime = 215
	noBounce.NextDestinationCursor.LastTransactionHash = noBounce.TransactionHash
	noBounce.BounceMessage = nil
	noBounce.NoBounceProof = &BoundedAbsenceEvidence{
		ScanStartMasterchainSeqno: 11, ScanEndMasterchainSeqno: 20,
	}
	if err := verifier.VerifyPredictionDestination(t.Context(), record, noBounce); err != nil ||
		attestor.absenceCalls != 1 {
		t.Fatalf("bounded no-bounce path did not cross its attestor: calls=%d err=%v", attestor.absenceCalls, err)
	}
	noBounce.NoBounceProof = nil
	if err := verifier.VerifyPredictionDestination(t.Context(), record, noBounce); err == nil {
		t.Fatal("no-bounce verifier accepted an absent bounded proof")
	}
	record.DestinationEvidence = &destinationEvidence
	creditTx := verifierTransaction(
		t, source, 220, bounce, nil, true, declaredBounce.ValueNanoTOS,
	)
	creditEvidence := BounceCreditEvidence{
		InboundBounceMessageHash: declaredBounce.MessageHash,
		TransactionHash:          "sha256:" + hex.EncodeToString(creditTx.Hash()),
		TransactionBOCBase64: base64.StdEncoding.EncodeToString(
			creditTx.ToBOCWithFlags(false),
		),
		Block: block, Finality: finality,
		NextSourceCursor: AccountCursor{AccountAddress: fixture.profile.SourceAgentAccount,
			LastLogicalTime: 220, LastTransactionHash: "sha256:" + hex.EncodeToString(creditTx.Hash())},
		CreditedValueNanoTOS: declaredBounce.ValueNanoTOS,
	}
	if err := verifier.VerifyPredictionBounceCredit(t.Context(), record, creditEvidence); err != nil {
		t.Fatalf("valid bounce credit rejected: %v", err)
	}
	creditEvidence.CreditedValueNanoTOS--
	if err := verifier.VerifyPredictionBounceCredit(t.Context(), record, creditEvidence); err == nil {
		t.Fatal("bounce verifier accepted a self-reported credit amount")
	}
}

func verifierTransaction(t *testing.T, account *address.Address, logicalTime uint64,
	in *tlb.Message, outputs []*tlb.Message, success bool, creditAmount uint64,
) *cell.Cell {
	t.Helper()
	var out *tlb.MessagesList
	if len(outputs) != 0 {
		dict := cell.NewDict(15)
		for index, message := range outputs {
			messageCell, err := message.ToCell()
			if err != nil || dict.SetIntKey(big.NewInt(int64(index)), cell.BeginCell().MustStoreRef(messageCell).EndCell()) != nil {
				t.Fatal("build transaction output dictionary")
			}
		}
		out = &tlb.MessagesList{List: dict}
	}
	hash := func(value byte) []byte { return relayVerifierBytes(value, 32) }
	actionFees := tlb.FromNanoTONU(1)
	action := &tlb.ActionPhase{
		Success: success, Valid: success, StatusChange: tlb.AccStatusChange{Type: tlb.AccStatusChangeUnchanged},
		TotalFwdFees: &actionFees, TotalActionFees: &actionFees, ResultCode: 0,
		TotalActions: uint16(len(outputs)), MessagesCreated: uint16(len(outputs)),
		ActionListHash: hash(0x71), TotalMsgSize: tlb.StorageUsedShort{Cells: big.NewInt(1), Bits: big.NewInt(1)},
	}
	ordinary := tlb.TransactionDescriptionOrdinary{
		ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{
			Success: success, GasFees: tlb.FromNanoTONU(1), Details: tlb.ComputePhaseVMDetails{
				GasUsed: big.NewInt(1), GasLimit: big.NewInt(2), ExitCode: 0, VMSteps: 1,
				VMInitStateHash: hash(0x51), VMFinalStateHash: hash(0x61),
			},
		}}, ActionPhase: action,
	}
	ordinary.Aborted = !success
	if !success && len(outputs) != 0 {
		fees := tlb.FromNanoTONU(1)
		ordinary.BouncePhase = &tlb.BouncePhase{Phase: tlb.BouncePhaseOk{
			MsgSize: tlb.StorageUsedShort{Cells: big.NewInt(1), Bits: big.NewInt(1)},
			MsgFees: fees, FwdFees: fees,
		}}
	}
	if creditAmount != 0 {
		ordinary.CreditFirst = true
		ordinary.CreditPhase = &tlb.CreditPhase{
			Credit: tlb.CurrencyCollection{Coins: tlb.FromNanoTONU(creditAmount)},
		}
	}
	tx := &tlb.Transaction{
		AccountAddr: account.Data(), LT: logicalTime, PrevTxHash: hash(0x21), PrevTxLT: logicalTime - 1,
		Now: 1_800_000_001, OutMsgCount: uint16(len(outputs)), OrigStatus: tlb.AccountStatusActive,
		EndStatus: tlb.AccountStatusActive, TotalFees: tlb.CurrencyCollection{Coins: tlb.FromNanoTONU(1)},
		StateUpdate: tlb.HashUpdate{OldHash: hash(0x31), NewHash: hash(0x41)},
		Description: ordinary,
	}
	tx.IO.In, tx.IO.Out = in, out
	root, err := tx.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func declaredVerifierMessage(t *testing.T, message *tlb.Message, extraFlags uint64) ChainObservedMessage {
	t.Helper()
	root, err := message.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	internal := message.AsInternal()
	return ChainObservedMessage{
		MessageHash: cellDigest(root), ExactMessageBOC: base64.StdEncoding.EncodeToString(root.ToBOCWithFlags(false)),
		SourceAddress: internal.SrcAddr.StringRaw(), DestinationAddress: internal.DstAddr.StringRaw(),
		ValueNanoTOS:  internal.Amount.Nano().Uint64(),
		BodyBOCBase64: base64.StdEncoding.EncodeToString(internal.Body.ToBOCWithFlags(false)),
		BodyHash:      cellDigest(internal.Body), Bounce: internal.Bounce, Bounced: internal.Bounced,
		ExtraFlags: extraFlags,
	}
}

func verifierRichBounceBody(t *testing.T, original *tlb.InternalMessage, bouncedBy uint8,
	exitCode int32, hasCompute bool, gasUsed, vmSteps uint32,
) *cell.Cell {
	t.Helper()
	value, err := tlb.ToCell(&tlb.CurrencyCollection{
		Coins: original.Amount, ExtraCurrencies: original.ExtraCurrencies,
	})
	if err != nil {
		t.Fatal(err)
	}
	info := cell.BeginCell().MustStoreBuilder(value.ToBuilder()).
		MustStoreUInt(original.CreatedLT, 64).MustStoreUInt(uint64(original.CreatedAt), 32).EndCell()
	builder := cell.BeginCell().MustStoreUInt(0xfffffffe, 32).MustStoreRef(original.Body).
		MustStoreRef(info).MustStoreUInt(uint64(bouncedBy), 8).MustStoreInt(int64(exitCode), 32).
		MustStoreBoolBit(hasCompute)
	if hasCompute {
		builder.MustStoreUInt(uint64(gasUsed), 32).MustStoreUInt(uint64(vmSteps), 32)
	}
	return builder.EndCell()
}

func verifierBlockAndFinality(profile PredictionRelayProfile) (BlockIdentity, QuorumFinality) {
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	block := BlockIdentity{WorkchainID: 0, Shard: 1, SequenceNumber: 10,
		RootHash: digest("a"), FileHash: digest("b"), MasterchainSequence: 11}
	return block, QuorumFinality{NetworkDomainHash: profile.NetworkDomainHash,
		FinalityViewID: digest("c"), ObserverIDs: append([]string(nil), profile.ObserverIDs...),
		AgreeingIDs: append([]string(nil), profile.ObserverIDs[:profile.QuorumThreshold]...),
		Threshold:   profile.QuorumThreshold, MasterchainSeqno: 12}
}

func relayVerifierBytes(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
