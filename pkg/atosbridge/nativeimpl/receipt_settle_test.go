package nativeimpl

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
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

func sampleContext() SettlementContext {
	return SettlementContext{
		QuoteCell:         cell.BeginCell().MustStoreUInt(1, 8).EndCell(),
		EscrowAddress:     "0:" + hex64,
		ProviderAgentID:   "agent_" + hex64,
		ChargedAtomic:     big.NewInt(25_000_000),
		SettlementQueryID: 1786740001,
	}
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

func TestReceiptSettlerBuildsSignsAndSubmits(t *testing.T) {
	signer := &fakeExecSigner{}
	sub := &fakeSubmitter{}
	settler, err := NewReceiptSettler(sampleContext(), signer, sub)
	if err != nil {
		t.Fatalf("new settler: %v", err)
	}
	rec, err := settler.Settle(context.Background(), sampleOutcome())
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if !strings.HasPrefix(rec.Commitment, "tvm-cell-sha256:") {
		t.Fatalf("receipt commitment not canonical: %q", rec.Commitment)
	}
	if rec.ReleaseQueryID != 1786740001 || rec.ChargedAtomic != 25_000_000 {
		t.Fatalf("receipt not bound to settlement context: %+v", rec)
	}
	if len(signer.gotHash) != 32 {
		t.Fatalf("execution signer must sign the 32-byte settlement-intent hash, got %d", len(signer.gotHash))
	}
	if sub.calls != 1 || sub.body == nil {
		t.Fatalf("release must be submitted exactly once with a non-nil body, calls=%d", sub.calls)
	}
}

func TestReceiptSettlerRejectsBadConfig(t *testing.T) {
	sc := sampleContext()
	sc.ChargedAtomic = big.NewInt(0)
	if _, err := NewReceiptSettler(sc, &fakeExecSigner{}, &fakeSubmitter{}); err == nil {
		t.Fatalf("must reject non-positive charged amount")
	}
}

func TestSettlingRunnerClosesLoop(t *testing.T) {
	sub := &fakeSubmitter{}
	settler, err := NewReceiptSettler(sampleContext(), &fakeExecSigner{}, sub)
	if err != nil {
		t.Fatalf("settler: %v", err)
	}
	inner := &fakeRunner{outcome: sampleOutcome()}
	runner, err := NewSettlingRunner(inner, settler)
	if err != nil {
		t.Fatalf("settling runner: %v", err)
	}
	out, err := runner.Execute(context.Background(), softwarework.Request{QuoteCommitment: "tvm-cell-sha256:" + hex64})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out.ExecutionID == "" || sub.calls != 1 {
		t.Fatalf("settling runner must execute then settle once, calls=%d", sub.calls)
	}
}

func TestSettlingRunnerDoesNotSettleFailedExecution(t *testing.T) {
	sub := &fakeSubmitter{}
	settler, _ := NewReceiptSettler(sampleContext(), &fakeExecSigner{}, sub)
	inner := &fakeRunner{err: errors.New("bounded execution failed")}
	runner, _ := NewSettlingRunner(inner, settler)
	if _, err := runner.Execute(context.Background(), softwarework.Request{}); err == nil {
		t.Fatalf("failed execution must propagate")
	}
	if sub.calls != 0 {
		t.Fatalf("no release on failed execution, got %d submits", sub.calls)
	}
}
