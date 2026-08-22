package nativeimpl

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-service-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ExecutionSigner signs the settlement-intent hash with the execution signer key
// held in the custody boundary; it never returns raw key material.
type ExecutionSigner interface {
	SignSettlementIntent(ctx context.Context, intentHash []byte) ([]byte, error)
}

// ReleaseSubmitter broadcasts the escrow release message body.
type ReleaseSubmitter interface {
	SubmitRelease(ctx context.Context, escrowAddress string, releaseBody *cell.Cell) error
}

// EscrowReleaseSettler closes the provider loop the receiver adapters leave
// open. It implements the adapters' post-execution Settler hook: given the
// finalized Gate Evidence and the validated Outcome, it reads the finalized
// escrow for the authoritative Accepted Quote cell and funded amount, builds the
// canonical Receipt, signs the settlement intent, and submits the escrow
// release. Every value that determines the charge comes from finalized state or
// the Gate's evidence — never from the transport — so the same execution always
// settles to the same release, and a re-submit is idempotent by query ID.
type EscrowReleaseSettler struct {
	escrow finalizedEscrowReader
	signer ExecutionSigner
	submit ReleaseSubmitter
}

// NewEscrowReleaseSettler validates its collaborators and returns a settler.
func NewEscrowReleaseSettler(
	escrow finalizedEscrowReader,
	signer ExecutionSigner,
	submit ReleaseSubmitter,
) (*EscrowReleaseSettler, error) {
	if escrow == nil || signer == nil || submit == nil {
		return nil, errors.New("nativeimpl: escrow release settler needs an escrow reader, a signer, and a submitter")
	}
	return &EscrowReleaseSettler{escrow: escrow, signer: signer, submit: submit}, nil
}

// Settle releases escrow for one completed execution. It fails closed on any
// mismatch between the outcome, the Gate evidence, and the finalized escrow, so
// a release is only ever built for a funded escrow bound to exactly this quote.
func (s *EscrowReleaseSettler) Settle(
	ctx context.Context,
	evidence executiongate.Evidence,
	outcome softwarework.Outcome,
) error {
	if evidence.EscrowAddress == "" || evidence.ProviderAgentID == "" {
		return errors.New("nativeimpl: settlement evidence is missing escrow or provider identity")
	}
	if outcome.QuoteCommitment == "" || outcome.QuoteCommitment != evidence.QuoteCommitment {
		return errors.New("nativeimpl: outcome does not match the authorized quote")
	}
	resolved, found, err := s.escrow.ResolveFinalized(ctx, evidence.EscrowAddress)
	if err != nil {
		return err
	}
	if !found || resolved == nil || resolved.State == nil {
		return errors.New("nativeimpl: escrow is not finalized; cannot release")
	}
	state := resolved.State
	if state.Status != nativecore.EscrowStatusFunded {
		return errors.New("nativeimpl: escrow is not in the funded state; refusing to release")
	}
	if state.QuoteCommitment != outcome.QuoteCommitment {
		return errors.New("nativeimpl: finalized escrow is bound to a different quote")
	}
	if state.AcceptedQuote == nil {
		return errors.New("nativeimpl: finalized escrow has no accepted quote cell")
	}
	charged, ok := new(big.Int).SetString(state.FundedAtomicAmount, 10)
	if !ok || charged.Sign() <= 0 || charged.BitLen() > 120 {
		return errors.New("nativeimpl: escrow funded amount is not a releasable charge")
	}
	queryID := deterministicQueryID(outcome.ExecutionID)

	receipt, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment:     outcome.QuoteCommitment,
		ExecutionID:         outcome.ExecutionID,
		InputDigest:         outcome.InputDigest,
		ResultDigest:        outcome.ResultDigest,
		ArtifactDigest:      outcome.Artifact.Digest,
		ReportDigest:        outcome.Report.Digest,
		SourceDigest:        outcome.SourceDigest,
		ToolchainDigest:     outcome.ToolchainDigest,
		SandboxDigest:       outcome.SandboxDigest,
		ChargedAtomicAmount: charged.String(),
		ProviderAgentID:     evidence.ProviderAgentID,
		CompletedAt:         outcome.CompletedAtUnix,
		ExitCode:            int32(outcome.ExitCode),
	})
	if err != nil {
		return err
	}
	intent, err := nativecore.BuildEscrowSettlementIntentV1(
		evidence.EscrowAddress,
		state.AcceptedQuote,
		receipt,
		charged,
		queryID,
	)
	if err != nil {
		return err
	}
	signature, err := s.signer.SignSettlementIntent(ctx, intent.Hash())
	if err != nil {
		return err
	}
	body, err := nativecore.BuildEscrowReleaseBodyV1(queryID, receipt, signature)
	if err != nil {
		return err
	}
	return s.submit.SubmitRelease(ctx, evidence.EscrowAddress, body)
}

// deterministicQueryID derives a stable, non-zero release query ID from the
// execution ID, so re-submitting the release for the same execution produces the
// identical message the escrow already saw.
func deterministicQueryID(executionID string) uint64 {
	sum := sha256.Sum256([]byte(executionID))
	q := binary.BigEndian.Uint64(sum[:8])
	if q == 0 {
		q = 1
	}
	return q
}
