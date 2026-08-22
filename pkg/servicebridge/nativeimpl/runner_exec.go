// Package nativeimpl provides the SDK-backed concrete implementations of the
// servicebridge component interfaces. It is a separate module so the lightweight
// OpenFox core does not carry the heavy tos-ai / tos-service-protocol dependency graph
// unless the economic bridge is actually built.
package nativeimpl

import (
	"context"

	"github.com/tosnetwork/tos-ai/pkg/softwarework"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// softwareRunner is the narrow behaviour of *softwarework.Runner the execution
// adapter depends on. Depending on the interface keeps the mapping unit-testable
// without a real bounded executor.
type softwareRunner interface {
	Execute(context.Context, softwarework.Request) (softwarework.Outcome, error)
}

// RunnerExecutionAdapter maps the bridge's transport-agnostic Task onto the
// tos-ai software-work runner and maps the runner's Outcome back. It is the
// provider execution surface behind the shared Native execution Gate: the Gate
// has already admitted the task at most once, and this adapter runs it inside
// the bounded executor the runner was constructed with.
type RunnerExecutionAdapter struct {
	runner softwareRunner
}

// NewRunnerExecutionAdapter wraps a constructed *softwarework.Runner (or any
// value with the same Execute behaviour) as an servicebridge.ExecutionAdapter.
func NewRunnerExecutionAdapter(runner softwareRunner) *RunnerExecutionAdapter {
	return &RunnerExecutionAdapter{runner: runner}
}

var _ servicebridge.ExecutionAdapter = (*RunnerExecutionAdapter)(nil)

// Execute runs the admitted task on the bound software-work runner. The runner
// owns bounded execution, the content-addressed artifact store, and the
// at-most-once execution journal; this adapter only translates the claim and
// the result and never re-derives authority.
func (a *RunnerExecutionAdapter) Execute(ctx context.Context, task servicebridge.Task) (servicebridge.Outcome, error) {
	out, err := a.runner.Execute(ctx, softwarework.Request{
		QuoteCommitment: task.QuoteCommitment,
		ExecutionID:     task.ExecutionID,
		InputDigest:     task.InputDigest,
		SourceDigest:    task.SourceDigest,
		SourceArchive:   task.SourceArchive,
	})
	if err != nil {
		return servicebridge.Outcome{}, err
	}
	return servicebridge.Outcome{
		ExecutionID:     out.ExecutionID,
		QuoteCommitment: out.QuoteCommitment,
		ArtifactDigest:  out.Artifact.Digest,
		ReportDigest:    out.Report.Digest,
		ExitCode:        out.ExitCode,
		CompletedUnix:   int64(out.CompletedAtUnix),
	}, nil
}
