package nativeimpl

import (
	"context"
	"testing"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func sampleOutcome() softwarework.Outcome {
	return softwarework.Outcome{
		QuoteCommitment: "tvm-cell-sha256:" + hex64,
		ExecutionID:     "sha256:" + hex64,
		InputDigest:     "sha256:" + hex64,
		ResultDigest:    "sha256:" + hex64,
		SourceDigest:    "sha256:" + hex64,
		ToolchainDigest: "sha256:" + hex64,
		SandboxDigest:   "sha256:" + hex64,
		Artifact:        artifactstore.Descriptor{Digest: "sha256:" + hex64},
		Report:          artifactstore.Descriptor{Digest: "sha256:" + hex64},
		ExitCode:        0,
		CompletedAtUnix: 1786765456,
	}
}

func sampleEvidence() executiongate.Evidence {
	return executiongate.Evidence{
		EscrowAddress:   "0:" + hex64,
		ProviderAgentID: "agent_" + hex64,
		QuoteCommitment: "tvm-cell-sha256:" + hex64,
	}
}

// fundedEscrow returns a fake finalized reader holding a funded escrow bound to
// the sample quote, with an accepted-quote cell.
func fundedEscrow(status uint8, quoteCommitment, funded string, withQuote bool) fakeFinalized {
	state := &nativecore.EscrowStateV1{
		Status: status, QuoteCommitment: quoteCommitment, FundedAtomicAmount: funded, SettledAtomicAmount: "0",
	}
	if withQuote {
		state.AcceptedQuote = cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	}
	return fakeFinalized{found: true, cp: 100, state: state}
}

type fakeExecSigner struct {
	gotHash []byte
	sig     []byte
	err     error
}

func (f *fakeExecSigner) SignSettlementIntent(_ context.Context, h []byte) ([]byte, error) {
	f.gotHash = append([]byte(nil), h...)
	if f.err != nil {
		return nil, f.err
	}
	if f.sig != nil {
		return f.sig, nil
	}
	return make([]byte, 64), nil // ed25519 signature size
}

type fakeSubmitter struct {
	calls int
	body  *cell.Cell
	err   error
}

func (f *fakeSubmitter) SubmitRelease(_ context.Context, _ string, body *cell.Cell) error {
	f.calls++
	f.body = body
	return f.err
}

func newSettler(t *testing.T, reader fakeFinalized) (*EscrowReleaseSettler, *fakeExecSigner, *fakeSubmitter) {
	t.Helper()
	signer, sub := &fakeExecSigner{}, &fakeSubmitter{}
	s, err := NewEscrowReleaseSettler(reader, signer, sub)
	if err != nil {
		t.Fatalf("new settler: %v", err)
	}
	return s, signer, sub
}

func TestSettlerReleasesFromFinalizedEscrow(t *testing.T) {
	s, signer, sub := newSettler(t, fundedEscrow(nativecore.EscrowStatusFunded, "tvm-cell-sha256:"+hex64, "25000000", true))
	if err := s.Settle(context.Background(), sampleEvidence(), sampleOutcome()); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if len(signer.gotHash) != 32 {
		t.Fatalf("execution signer must sign the 32-byte settlement-intent hash, got %d", len(signer.gotHash))
	}
	if sub.calls != 1 || sub.body == nil {
		t.Fatalf("release must be submitted exactly once with a non-nil body, calls=%d", sub.calls)
	}
}

func TestSettlerRejectsQuoteMismatch(t *testing.T) {
	s, _, sub := newSettler(t, fundedEscrow(nativecore.EscrowStatusFunded, "tvm-cell-sha256:"+hex64, "25000000", true))
	evidence := sampleEvidence()
	evidence.QuoteCommitment = "tvm-cell-sha256:" + "b" + hex64[1:]
	if err := s.Settle(context.Background(), evidence, sampleOutcome()); err == nil {
		t.Fatalf("evidence bound to a different quote must not release")
	}
	if sub.calls != 0 {
		t.Fatalf("no release on a mismatched quote")
	}
}

func TestSettlerRefusesUnfundedEscrow(t *testing.T) {
	s, _, sub := newSettler(t, fundedEscrow(nativecore.EscrowStatusReleasePending, "tvm-cell-sha256:"+hex64, "25000000", true))
	if err := s.Settle(context.Background(), sampleEvidence(), sampleOutcome()); err == nil {
		t.Fatalf("an already-released escrow must not be released again")
	}
	if sub.calls != 0 {
		t.Fatalf("no release when the escrow is not funded")
	}
}

func TestSettlerRefusesEscrowBoundToAnotherQuote(t *testing.T) {
	s, _, sub := newSettler(t, fundedEscrow(nativecore.EscrowStatusFunded, "tvm-cell-sha256:"+"c"+hex64[1:], "25000000", true))
	if err := s.Settle(context.Background(), sampleEvidence(), sampleOutcome()); err == nil {
		t.Fatalf("finalized escrow bound to a different quote must not release")
	}
	if sub.calls != 0 {
		t.Fatalf("no release when the finalized escrow quote differs")
	}
}

func TestSettlerRequiresAcceptedQuoteCell(t *testing.T) {
	s, _, _ := newSettler(t, fundedEscrow(nativecore.EscrowStatusFunded, "tvm-cell-sha256:"+hex64, "25000000", false))
	if err := s.Settle(context.Background(), sampleEvidence(), sampleOutcome()); err == nil {
		t.Fatalf("a funded escrow without an accepted quote cell cannot be settled")
	}
}

func TestSettlerRejectsNonReleasableCharge(t *testing.T) {
	s, _, _ := newSettler(t, fundedEscrow(nativecore.EscrowStatusFunded, "tvm-cell-sha256:"+hex64, "0", true))
	if err := s.Settle(context.Background(), sampleEvidence(), sampleOutcome()); err == nil {
		t.Fatalf("a zero funded amount is not a releasable charge")
	}
}

func TestSettlerRejectsMissingEvidence(t *testing.T) {
	s, _, _ := newSettler(t, fundedEscrow(nativecore.EscrowStatusFunded, "tvm-cell-sha256:"+hex64, "25000000", true))
	if err := s.Settle(context.Background(), executiongate.Evidence{}, sampleOutcome()); err == nil {
		t.Fatalf("settlement without escrow/provider evidence must fail closed")
	}
}
