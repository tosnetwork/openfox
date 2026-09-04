package prediction

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// PredictionRelayChainAttestor supplies the chain-trust part that raw
// transaction BOCs cannot prove by themselves. Implementations must verify the
// frozen observer quorum, checkpoint-pinned market identity, opcode-specific
// postcondition, and (when needed) the bounded no-bounce scan.
type PredictionRelayChainAttestor interface {
	VerifyPredictionBlockFinality(
		context.Context, PredictionRelayProfile, BlockIdentity, QuorumFinality,
	) error
	VerifyPredictionMarketIdentity(
		context.Context, PredictionRelayProfile, BlockIdentity,
	) error
	VerifyPredictionSuccessPredicate(
		context.Context, PredictionRelayRecord, DestinationTransactionEvidence,
	) error
	VerifyPredictionNoBounce(
		context.Context, PredictionRelayRecord, DestinationTransactionEvidence,
	) error
}

// CanonicalPredictionRelayEvidenceVerifier independently parses every supplied
// transaction and message BOC. The attestor is deliberately narrower than this
// parser: it cannot override byte-level contradictions with a boolean result.
type CanonicalPredictionRelayEvidenceVerifier struct {
	Attestor PredictionRelayChainAttestor
}

func (CanonicalPredictionRelayEvidenceVerifier) predictionRelayEvidenceVerifier() {}

func (verifier CanonicalPredictionRelayEvidenceVerifier) VerifyPredictionSource(
	ctx context.Context, record PredictionRelayRecord, evidence SourceTransactionEvidence,
) error {
	if ctx == nil || verifier.Attestor == nil {
		return errors.New("prediction source verifier is unavailable")
	}
	tx, root, err := decodePredictionTransaction(evidence.TransactionBOCBase64, evidence.TransactionHash)
	if err != nil || !transactionAccountMatches(tx, record.Profile.SourceAgentAccount) ||
		evidence.NextSourceCursor.LastLogicalTime != tx.LT ||
		evidence.NextSourceCursor.LastTransactionHash != evidence.TransactionHash {
		return errors.New("prediction source transaction identity is invalid")
	}
	inCell, err := predictionMessageCell(tx.IO.In)
	if err != nil || tx.IO.In.MsgType != tlb.MsgTypeExternalIn ||
		cellDigest(inCell) != record.SubmittedExternalMessageHash {
		return errors.New("prediction source transaction did not consume the submitted external message")
	}
	ordinary, ok := predictionOrdinary(tx)
	if !ok || ordinary.Aborted || !predictionComputeSucceeded(ordinary) ||
		!predictionActionSucceeded(ordinary) {
		return errors.New("prediction source Agent Account transaction did not execute successfully")
	}
	outputs, err := predictionOutMessages(tx)
	if err != nil || len(outputs) != int(tx.OutMsgCount) || len(outputs) != len(evidence.OutboundMessages) {
		return errors.New("prediction source outbound message count is inconsistent")
	}
	for index := range outputs {
		if err := verifyDeclaredPredictionMessage(outputs[index], evidence.OutboundMessages[index]); err != nil {
			return fmt.Errorf("verify prediction source outbound: %w", err)
		}
	}
	if "sha256:"+hex.EncodeToString(root.Hash()) != evidence.TransactionHash {
		return errors.New("prediction source transaction hash changed during parsing")
	}
	return verifier.Attestor.VerifyPredictionBlockFinality(
		ctx, record.Profile, evidence.Block, evidence.Finality,
	)
}

func (verifier CanonicalPredictionRelayEvidenceVerifier) VerifyPredictionDestination(
	ctx context.Context, record PredictionRelayRecord, evidence DestinationTransactionEvidence,
) error {
	if ctx == nil || verifier.Attestor == nil || record.ActualOutbound == nil {
		return errors.New("prediction destination verifier is unavailable")
	}
	tx, _, err := decodePredictionTransaction(evidence.TransactionBOCBase64, evidence.TransactionHash)
	if err != nil || !transactionAccountMatches(tx, record.Profile.MarketAddress) ||
		evidence.NextDestinationCursor.LastLogicalTime != tx.LT ||
		evidence.NextDestinationCursor.LastTransactionHash != evidence.TransactionHash {
		return errors.New("prediction destination transaction identity is invalid")
	}
	if err := verifyDeclaredPredictionMessage(tx.IO.In, *record.ActualOutbound); err != nil {
		return fmt.Errorf("verify prediction destination inbound: %w", err)
	}
	ordinary, ok := predictionOrdinary(tx)
	computeSuccess := ok && predictionComputeSucceeded(ordinary)
	actionSuccess := ok && predictionActionSucceeded(ordinary)
	aborted := !ok || ordinary.Aborted
	opcodeSuccess := !aborted && computeSuccess && actionSuccess
	if !evidence.Ordinary || evidence.Aborted != aborted ||
		evidence.ComputeSuccess != computeSuccess || evidence.ActionSuccess != actionSuccess ||
		evidence.OpcodeSuccess != opcodeSuccess {
		return errors.New("prediction destination execution flags contradict the transaction BOC")
	}
	if err := verifier.Attestor.VerifyPredictionBlockFinality(
		ctx, record.Profile, evidence.Block, evidence.Finality,
	); err != nil {
		return err
	}
	if err := verifier.Attestor.VerifyPredictionMarketIdentity(ctx, record.Profile, evidence.Block); err != nil {
		return err
	}
	if opcodeSuccess {
		return verifier.Attestor.VerifyPredictionSuccessPredicate(ctx, record, evidence)
	}
	outputs, err := predictionOutMessages(tx)
	if err != nil || len(outputs) != int(tx.OutMsgCount) {
		return errors.New("prediction destination outbound messages are malformed")
	}
	if evidence.BounceMessage != nil {
		if len(outputs) != 1 || evidence.RichBounceEnvelopeHash != evidence.BounceMessage.BodyHash ||
			evidence.RichBounceOriginalBodyHash != record.Expected.BodyHash {
			return errors.New("prediction rich-bounce evidence is not hash-bound")
		}
		matches := 0
		for index := range outputs {
			if verifyDeclaredPredictionMessage(outputs[index], *evidence.BounceMessage) == nil &&
				verifyPredictionRichBounce(ordinary, tx.IO.In.AsInternal(), outputs[index].AsInternal()) == nil {
				matches++
			}
		}
		if matches != 1 {
			return errors.New("prediction destination transaction does not contain the declared bounce")
		}
		return nil
	}
	if len(outputs) != 0 {
		return errors.New("prediction no-bounce failure unexpectedly created outbound messages")
	}
	if evidence.NoBounceProof == nil {
		return errors.New("prediction no-bounce claim has no bounded absence proof")
	}
	return verifier.Attestor.VerifyPredictionNoBounce(ctx, record, evidence)
}

func (verifier CanonicalPredictionRelayEvidenceVerifier) VerifyPredictionBounceCredit(
	ctx context.Context, record PredictionRelayRecord, evidence BounceCreditEvidence,
) error {
	if ctx == nil || verifier.Attestor == nil || record.DestinationEvidence == nil ||
		record.DestinationEvidence.BounceMessage == nil {
		return errors.New("prediction bounce-credit verifier is unavailable")
	}
	tx, _, err := decodePredictionTransaction(evidence.TransactionBOCBase64, evidence.TransactionHash)
	if err != nil || !transactionAccountMatches(tx, record.Profile.SourceAgentAccount) ||
		evidence.NextSourceCursor.LastLogicalTime != tx.LT ||
		evidence.NextSourceCursor.LastTransactionHash != evidence.TransactionHash {
		return errors.New("prediction bounce-credit transaction identity is invalid")
	}
	if err := verifyDeclaredPredictionMessage(
		tx.IO.In, *record.DestinationEvidence.BounceMessage,
	); err != nil {
		return fmt.Errorf("verify prediction inbound bounce: %w", err)
	}
	ordinary, ok := predictionOrdinary(tx)
	if !ok || ordinary.Aborted || ordinary.CreditPhase == nil ||
		(ordinary.CreditPhase.Credit.ExtraCurrencies != nil &&
			!ordinary.CreditPhase.Credit.ExtraCurrencies.IsEmpty()) ||
		!ordinary.CreditPhase.Credit.Coins.Nano().IsUint64() ||
		ordinary.CreditPhase.Credit.Coins.Nano().Uint64() != evidence.CreditedValueNanoTOS {
		return errors.New("prediction bounce credit contradicts the transaction credit phase")
	}
	return verifier.Attestor.VerifyPredictionBlockFinality(
		ctx, record.Profile, evidence.Block, evidence.Finality,
	)
}

func decodePredictionTransaction(encoded, digest string) (*tlb.Transaction, *cell.Cell, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximumChainBOCBytes {
		return nil, nil, errors.New("prediction transaction BOC is invalid")
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOCWithFlags(false)) ||
		digest != "sha256:"+hex.EncodeToString(root.Hash()) {
		return nil, nil, errors.New("prediction transaction BOC is not canonical or hash-bound")
	}
	var tx tlb.Transaction
	if err := tlb.LoadFromCell(&tx, root.MustBeginParse()); err != nil {
		return nil, nil, errors.New("prediction transaction TL-B is invalid")
	}
	rebuilt, err := tx.ToCell()
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, nil, errors.New("prediction transaction has trailing or noncanonical TL-B")
	}
	return &tx, root, nil
}

func transactionAccountMatches(tx *tlb.Transaction, rawAddress string) bool {
	parsed, err := address.ParseRawAddr(rawAddress)
	return err == nil && parsed != nil && tx != nil && bytes.Equal(tx.AccountAddr, parsed.Data())
}

func predictionMessageCell(message *tlb.Message) (*cell.Cell, error) {
	if message == nil {
		return nil, errors.New("prediction transaction message is absent")
	}
	return message.ToCell()
}

func predictionOutMessages(tx *tlb.Transaction) ([]*tlb.Message, error) {
	if tx == nil || tx.IO.Out == nil {
		return nil, nil
	}
	values, err := tx.IO.Out.ToSlice()
	if err != nil {
		return nil, err
	}
	result := make([]*tlb.Message, len(values))
	for index := range values {
		result[index] = &values[index]
	}
	return result, nil
}

func predictionOrdinary(tx *tlb.Transaction) (tlb.TransactionDescriptionOrdinary, bool) {
	if tx == nil {
		return tlb.TransactionDescriptionOrdinary{}, false
	}
	switch value := tx.Description.(type) {
	case tlb.TransactionDescriptionOrdinary:
		return value, true
	case *tlb.TransactionDescriptionOrdinary:
		if value != nil {
			return *value, true
		}
	}
	return tlb.TransactionDescriptionOrdinary{}, false
}

func predictionComputeSucceeded(value tlb.TransactionDescriptionOrdinary) bool {
	switch phase := value.ComputePhase.Phase.(type) {
	case tlb.ComputePhaseVM:
		return phase.Success && phase.Details.ExitCode == 0
	case *tlb.ComputePhaseVM:
		return phase != nil && phase.Success && phase.Details.ExitCode == 0
	default:
		return false
	}
}

func predictionActionSucceeded(value tlb.TransactionDescriptionOrdinary) bool {
	return value.ActionPhase != nil && value.ActionPhase.Success && value.ActionPhase.Valid &&
		!value.ActionPhase.NoFunds && value.ActionPhase.ResultCode == 0
}

func verifyDeclaredPredictionMessage(actual *tlb.Message, declared ChainObservedMessage) error {
	if actual == nil || actual.MsgType != tlb.MsgTypeInternal {
		return errors.New("declared prediction message is not internal")
	}
	actualCell, err := actual.ToCell()
	if err != nil {
		return err
	}
	declaredRaw, err := base64.StdEncoding.Strict().DecodeString(declared.ExactMessageBOC)
	if err != nil || !bytes.Equal(declaredRaw, actualCell.ToBOCWithFlags(false)) ||
		declared.MessageHash != cellDigest(actualCell) {
		return errors.New("declared prediction message bytes differ from the transaction")
	}
	internal := actual.AsInternal()
	extraFlags, err := predictionInternalExtraFlags(internal)
	if internal.SrcAddr == nil || internal.DstAddr == nil ||
		!internal.IHRDisabled ||
		internal.SrcAddr.StringRaw() != declared.SourceAddress ||
		internal.DstAddr.StringRaw() != declared.DestinationAddress ||
		!internal.Amount.Nano().IsUint64() || internal.Amount.Nano().Uint64() != declared.ValueNanoTOS ||
		err != nil || extraFlags != declared.ExtraFlags ||
		(internal.ExtraCurrencies != nil && !internal.ExtraCurrencies.IsEmpty()) ||
		internal.Bounce != declared.Bounce || internal.Bounced != declared.Bounced || internal.Body == nil ||
		declared.BodyHash != cellDigest(internal.Body) ||
		declared.BodyBOCBase64 != base64.StdEncoding.EncodeToString(internal.Body.ToBOCWithFlags(false)) {
		return errors.New("declared prediction message fields differ from the transaction")
	}
	if internal.StateInit == nil {
		if declared.StateInitBOCBase64 != "" || declared.StateInitHash != "" {
			return errors.New("declared prediction message invents StateInit")
		}
		return nil
	}
	state, err := internal.StateInit.ToCell()
	if err != nil || declared.StateInitHash != cellDigest(state) ||
		declared.StateInitBOCBase64 != base64.StdEncoding.EncodeToString(state.ToBOCWithFlags(false)) {
		return errors.New("declared prediction StateInit differs from the transaction")
	}
	return nil
}

// TOS global version 12 repurposed the CommonMsgInfo field immediately after
// CurrencyCollection from legacy ihr_fee to extra_flags. tosutils-go keeps the
// historical InternalMessage.IHRFee field name for wire compatibility, so the
// value must be interpreted as extra_flags when verifying PredictionMarket's
// v14+ checked-call transport.
func predictionInternalExtraFlags(message *tlb.InternalMessage) (uint64, error) {
	if message == nil || !message.IHRFee.Nano().IsUint64() {
		return 0, errors.New("prediction internal message has invalid extra_flags")
	}
	return message.IHRFee.Nano().Uint64(), nil
}

// verifyPredictionRichBounce parses NewBounceBody directly from the exact
// destination transaction. In particular, it proves that the body contains a
// full ref-DAG copy of the rejected call; a legacy 0xffffffff prefix or a
// caller-supplied original-body hash is not recovery evidence.
func verifyPredictionRichBounce(ordinary tlb.TransactionDescriptionOrdinary, original,
	bounce *tlb.InternalMessage,
) error {
	if original == nil || bounce == nil || original.Body == nil || bounce.Body == nil ||
		!original.Bounce || original.Bounced || bounce.Bounce || !bounce.Bounced ||
		bounce.StateInit != nil || !ordinary.Aborted || !predictionBouncePhaseSucceeded(ordinary.BouncePhase) ||
		(bounce.ExtraCurrencies != nil && !bounce.ExtraCurrencies.IsEmpty()) {
		return errors.New("prediction bounce message flags are invalid")
	}
	originalFlags, err := predictionInternalExtraFlags(original)
	if err != nil || originalFlags != 3 {
		return errors.New("prediction rejected call did not request a full rich bounce")
	}
	bounceFlags, err := predictionInternalExtraFlags(bounce)
	if err != nil || bounceFlags != originalFlags {
		return errors.New("prediction bounce did not preserve the rich-bounce flags")
	}
	body := bounce.Body.MustBeginParse()
	tag, err := body.LoadUInt(32)
	if err != nil || tag != 0xfffffffe {
		return errors.New("prediction bounce is not a NewBounceBody")
	}
	originalBody, err := body.LoadRefCell()
	if err != nil || !bytes.Equal(originalBody.Hash(), original.Body.Hash()) ||
		!bytes.Equal(originalBody.ToBOCWithFlags(false), original.Body.ToBOCWithFlags(false)) {
		return errors.New("prediction rich bounce does not contain the full original body")
	}
	originalInfo, err := body.LoadRefCell()
	if err != nil {
		return errors.New("prediction rich bounce omitted original message information")
	}
	info := originalInfo.MustBeginParse()
	var originalValue tlb.CurrencyCollection
	if err := tlb.LoadFromCell(&originalValue, info); err != nil ||
		!originalValue.Coins.Nano().IsUint64() || !original.Amount.Nano().IsUint64() ||
		originalValue.Coins.Nano().Uint64() != original.Amount.Nano().Uint64() ||
		(originalValue.ExtraCurrencies != nil && !originalValue.ExtraCurrencies.IsEmpty()) ||
		(original.ExtraCurrencies != nil && !original.ExtraCurrencies.IsEmpty()) {
		return errors.New("prediction rich bounce original value is invalid")
	}
	createdLT, err := info.LoadUInt(64)
	if err != nil || createdLT != original.CreatedLT {
		return errors.New("prediction rich bounce original logical time is invalid")
	}
	createdAt, err := info.LoadUInt(32)
	if err != nil || uint32(createdAt) != original.CreatedAt || info.BitsLeft() != 0 || info.RefsNum() != 0 {
		return errors.New("prediction rich bounce original creation metadata is invalid")
	}
	bouncedBy, err := body.LoadUInt(8)
	if err != nil {
		return errors.New("prediction rich bounce omitted the failure phase")
	}
	exitCode, err := body.LoadInt(32)
	if err != nil {
		return errors.New("prediction rich bounce omitted the failure code")
	}
	hasCompute, err := body.LoadBoolBit()
	if err != nil {
		return errors.New("prediction rich bounce omitted compute provenance")
	}
	var gasUsed, vmSteps uint64
	if hasCompute {
		gasUsed, err = body.LoadUInt(32)
		if err == nil {
			vmSteps, err = body.LoadUInt(32)
		}
		if err != nil {
			return errors.New("prediction rich bounce compute provenance is truncated")
		}
	}
	if body.BitsLeft() != 0 || body.RefsNum() != 0 ||
		!predictionBounceFailureMatches(ordinary, uint8(bouncedBy), int32(exitCode), hasCompute,
			uint32(gasUsed), uint32(vmSteps)) {
		return errors.New("prediction rich bounce failure provenance contradicts the transaction")
	}
	return nil
}

func predictionBouncePhaseSucceeded(phase *tlb.BouncePhase) bool {
	if phase == nil {
		return false
	}
	switch value := phase.Phase.(type) {
	case tlb.BouncePhaseOk:
		return true
	case *tlb.BouncePhaseOk:
		return value != nil
	default:
		return false
	}
}

func predictionBounceFailureMatches(ordinary tlb.TransactionDescriptionOrdinary, bouncedBy uint8,
	exitCode int32, hasCompute bool, gasUsed, vmSteps uint32,
) bool {
	switch phase := ordinary.ComputePhase.Phase.(type) {
	case tlb.ComputePhaseSkipped:
		return bouncedBy == 0 && !hasCompute && exitCode == predictionComputeSkipExitCode(phase.Reason.Type)
	case *tlb.ComputePhaseSkipped:
		return phase != nil && bouncedBy == 0 && !hasCompute &&
			exitCode == predictionComputeSkipExitCode(phase.Reason.Type)
	case tlb.ComputePhaseVM:
		if !hasCompute || phase.Details.GasUsed == nil || !phase.Details.GasUsed.IsUint64() ||
			phase.Details.GasUsed.Uint64() != uint64(gasUsed) || phase.Details.VMSteps != vmSteps {
			return false
		}
		if !phase.Success {
			return bouncedBy == 1 && exitCode == phase.Details.ExitCode
		}
		return bouncedBy == 2 && ordinary.ActionPhase != nil && !ordinary.ActionPhase.Success &&
			exitCode == ordinary.ActionPhase.ResultCode
	case *tlb.ComputePhaseVM:
		return phase != nil && predictionBounceFailureMatches(
			tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: *phase},
				ActionPhase: ordinary.ActionPhase},
			bouncedBy, exitCode, hasCompute, gasUsed, vmSteps,
		)
	default:
		return false
	}
}

func predictionComputeSkipExitCode(reason tlb.ComputeSkipReasonType) int32 {
	switch reason {
	case tlb.ComputeSkipReasonNoState:
		return -1
	case tlb.ComputeSkipReasonBadState:
		return -2
	case tlb.ComputeSkipReasonNoGas:
		return -3
	case tlb.ComputeSkipReasonSuspended:
		return -4
	default:
		return 0
	}
}

var _ PredictionRelayEvidenceVerifier = CanonicalPredictionRelayEvidenceVerifier{}
