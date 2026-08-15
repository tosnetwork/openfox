package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

type fakeRunner struct {
	gotRequest softwarework.Request
	outcome    softwarework.Outcome
	err        error
}

func (f *fakeRunner) Execute(_ context.Context, req softwarework.Request) (softwarework.Outcome, error) {
	f.gotRequest = req
	return f.outcome, f.err
}

func TestRunnerExecutionAdapterMapsClaimAndOutcome(t *testing.T) {
	fr := &fakeRunner{outcome: softwarework.Outcome{
		QuoteCommitment: "tvm-cell-sha256:qc",
		ExecutionID:     "sha256:x",
		Artifact:        artifactstore.Descriptor{Digest: "sha256:a", MediaType: "application/vnd.tos.service.software-artifact.v1+tar", SizeBytes: 3072},
		Report:          artifactstore.Descriptor{Digest: "sha256:r", MediaType: "application/vnd.tos.service.test-report.v1+json", SizeBytes: 355},
		ExitCode:        0,
		CompletedAtUnix: 1786765456,
	}}
	adapter := NewRunnerExecutionAdapter(fr)

	task := servicebridge.Task{
		EscrowAddress:   "EQescrow",
		QuoteCommitment: "tvm-cell-sha256:qc",
		ExecutionID:     "sha256:x",
		InputDigest:     "sha256:i",
		SourceDigest:    "sha256:s",
		SourceArchive:   []byte("src"),
	}
	out, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Claim mapped into the runner request exactly.
	if fr.gotRequest.QuoteCommitment != task.QuoteCommitment ||
		fr.gotRequest.ExecutionID != task.ExecutionID ||
		fr.gotRequest.InputDigest != task.InputDigest ||
		fr.gotRequest.SourceDigest != task.SourceDigest ||
		string(fr.gotRequest.SourceArchive) != "src" {
		t.Fatalf("request not mapped 1:1 from task: %+v", fr.gotRequest)
	}
	// Outcome mapped back with content-addressed artifact/report digests.
	if out.QuoteCommitment != "tvm-cell-sha256:qc" || out.ExecutionID != "sha256:x" ||
		out.ArtifactDigest != "sha256:a" || out.ReportDigest != "sha256:r" ||
		out.ExitCode != 0 || out.CompletedUnix != 1786765456 {
		t.Fatalf("outcome not mapped: %+v", out)
	}
}

func TestRunnerExecutionAdapterPropagatesError(t *testing.T) {
	adapter := NewRunnerExecutionAdapter(&fakeRunner{err: errors.New("bounded execution failed")})
	if _, err := adapter.Execute(context.Background(), servicebridge.Task{}); err == nil {
		t.Fatalf("runner error must propagate (no successful outcome on failed execution)")
	}
}
