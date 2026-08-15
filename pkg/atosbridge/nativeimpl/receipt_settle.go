package nativeimpl

import (
	"context"
	"errors"
	"math/big"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// SettlementContext is the provider-held canonical context needed to settle one
// admitted purchase: the exact Accepted Quote cell, escrow account, provider
// Agent, charged amount, and the settlement query ID.
type SettlementContext struct {
	QuoteCell         *cell.Cell
	EscrowAddress     string
	ProviderAgentID   string
	ChargedAtomic     *big.Int
	SettlementQueryID uint64
}

// ExecutionSigner signs the settlement-intent hash with the execution signer key
// held in the custody boundary; it never returns raw key material.
type ExecutionSigner interface {
	SignSettlementIntent(ctx context.Context, intentHash []byte) ([]byte, error)
}

// ReleaseSubmitter broadcasts the escrow release message body.
type ReleaseSubmitter interface {
	SubmitRelease(ctx context.Context, escrowAddress string, releaseBody *cell.Cell) error
}

// ReceiptSettler closes the provider loop that the A2A/MCP/Agent Packet receiver
// adapters leave open: given a software-work Outcome it builds the canonical
// Receipt, builds and signs the settlement intent, and submits the escrow
// release. It uses only the frozen nativecore encoders and never invents a
// second Receipt or settlement path.
type ReceiptSettler struct {
	ctx    SettlementContext
	signer ExecutionSigner
	submit ReleaseSubmitter
}

// NewReceiptSettler validates the settlement context and returns a settler.
func NewReceiptSettler(sc SettlementContext, signer ExecutionSigner, submit ReleaseSubmitter) (*ReceiptSettler, error) {
	if sc.QuoteCell == nil || sc.EscrowAddress == "" || sc.ProviderAgentID == "" ||
		sc.ChargedAtomic == nil || sc.ChargedAtomic.Sign() <= 0 || sc.SettlementQueryID == 0 ||
		signer == nil || submit == nil {
		return nil, errors.New("nativeimpl: incomplete receipt settler configuration")
	}
	return &ReceiptSettler{ctx: sc, signer: signer, submit: submit}, nil
}

// Settle builds the Receipt, signs the settlement intent, and submits the
// release. It returns the canonical Receipt for the caller to persist. A failed
// build/sign/submit returns an error and no successful Receipt.
func (s *ReceiptSettler) Settle(ctx context.Context, out softwarework.Outcome) (atosbridge.Receipt, error) {
	if out.QuoteCommitment == "" || out.ExecutionID == "" {
		return atosbridge.Receipt{}, errors.New("nativeimpl: outcome is missing its quote/execution binding")
	}
	receipt, commitment, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: out.QuoteCommitment, ExecutionID: out.ExecutionID, InputDigest: out.InputDigest,
		ResultDigest: out.ResultDigest, ArtifactDigest: out.Artifact.Digest, ReportDigest: out.Report.Digest,
		SourceDigest: out.SourceDigest, ToolchainDigest: out.ToolchainDigest, SandboxDigest: out.SandboxDigest,
		ChargedAtomicAmount: s.ctx.ChargedAtomic.String(), ProviderAgentID: s.ctx.ProviderAgentID,
		CompletedAt: out.CompletedAtUnix, ExitCode: int32(out.ExitCode),
	})
	if err != nil {
		return atosbridge.Receipt{}, err
	}
	intent, err := nativecore.BuildEscrowSettlementIntentV1(s.ctx.EscrowAddress, s.ctx.QuoteCell, receipt, s.ctx.ChargedAtomic, s.ctx.SettlementQueryID)
	if err != nil {
		return atosbridge.Receipt{}, err
	}
	signature, err := s.signer.SignSettlementIntent(ctx, intent.Hash())
	if err != nil {
		return atosbridge.Receipt{}, err
	}
	body, err := nativecore.BuildEscrowReleaseBodyV1(s.ctx.SettlementQueryID, receipt, signature)
	if err != nil {
		return atosbridge.Receipt{}, err
	}
	if err := s.submit.SubmitRelease(ctx, s.ctx.EscrowAddress, body); err != nil {
		return atosbridge.Receipt{}, err
	}
	return atosbridge.Receipt{
		Commitment:      commitment,
		QuoteCommitment: out.QuoteCommitment,
		ExecutionID:     out.ExecutionID,
		ChargedAtomic:   s.ctx.ChargedAtomic.Uint64(),
		ReleaseQueryID:  s.ctx.SettlementQueryID,
	}, nil
}

// SettlingRunner wraps a bound software-work runner so that, after a successful
// execution, the provider loop is closed: outcome -> Receipt -> release. It
// satisfies the tos-ai adapter Runner interface, so it drops directly into the
// A2A, MCP, and Agent Packet receiver adapters behind the shared execution Gate.
type SettlingRunner struct {
	inner   softwareRunner
	settler *ReceiptSettler
}

// NewSettlingRunner composes an inner runner with a receipt settler.
func NewSettlingRunner(inner softwareRunner, settler *ReceiptSettler) (*SettlingRunner, error) {
	if inner == nil || settler == nil {
		return nil, errors.New("nativeimpl: settling runner needs an inner runner and a settler")
	}
	return &SettlingRunner{inner: inner, settler: settler}, nil
}

// Execute runs the bounded execution and then settles it. A settlement failure
// after a successful execution is surfaced as an error so the caller does not
// treat an unsettled outcome as complete.
func (r *SettlingRunner) Execute(ctx context.Context, req softwarework.Request) (softwarework.Outcome, error) {
	out, err := r.inner.Execute(ctx, req)
	if err != nil {
		return softwarework.Outcome{}, err
	}
	if _, err := r.settler.Settle(ctx, out); err != nil {
		return softwarework.Outcome{}, err
	}
	return out, nil
}
