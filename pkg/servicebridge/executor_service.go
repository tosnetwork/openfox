package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/executorservice"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// DefaultExecutorSocket is where the root-run executor service listens.
const DefaultExecutorSocket = "/run/tos-service-executor/executor.sock"

// What an answer of the executor service means for the request it was sent
// for. Every error of ServiceRunner.Execute that is neither failed nor
// unknown is pending.
var (
	// ErrExecutionPending: there is no verified outcome yet. Nothing may be
	// attested, and the same request is sent again later: the service runs
	// an execution id at most once and answers a repeated request from its
	// journal, so asking again never starts a second run.
	ErrExecutionPending = errors.New("servicebridge: the executor service gave no verified outcome yet")
	// ErrExecutionUnknown: the service holds the execution id without an
	// outcome for this request. It is never run again and never attested.
	ErrExecutionUnknown = errors.New("servicebridge: the executor service cannot say what the execution did")
	// ErrExecutionFailed: the run started and did not succeed. It is never
	// attested.
	ErrExecutionFailed = errors.New("servicebridge: the execution ran and did not succeed")
)

// ExecutorService is the part of the executor service client a node uses.
type ExecutorService interface {
	Describe(ctx context.Context) (executorservice.Description, error)
	Execute(ctx context.Context, request executorservice.ExecuteRequest) (executorservice.ExecuteResult, error)
}

// OpenExecutorService returns a client of the service at socket. Every
// connection is refused unless root serves the socket.
func OpenExecutorService(socket string) (ExecutorService, error) {
	client, err := executorservice.NewClient(executorservice.ClientConfig{SocketPath: socket})
	if err != nil {
		return nil, errors.New("servicebridge: executor_socket must be an absolute clean path")
	}
	return client, nil
}

// describeTimeout bounds one readiness question to the service. The client
// bounds a call without a deadline only by the length of a whole job.
var describeTimeout = 15 * time.Second

// ServiceExecution is one request for the executor service.
type ServiceExecution struct {
	Request softwarework.Request
	// ManifestDigest, ToolchainDigest and Limits are the manifest the
	// request was admitted under. They are fixed when it is admitted and
	// sent unchanged every time: the service binds an execution id to its
	// limits and answers the same id under other limits with a conflict.
	ManifestDigest  string
	ToolchainDigest string
	Limits          nativecore.SoftwareWorkLimitsV1
	// ServiceRetainUntilUnix is how long the service keeps its copy of the
	// objects, which the node needs only until it holds its own.
	ServiceRetainUntilUnix int64
	// RetainUntilUnix is how long the node keeps its own copy for delivery.
	RetainUntilUnix int64
}

// ServiceRunner executes through a service that owns the execution: the run
// survives this process, and the same request sent again returns the one
// recorded outcome.
type ServiceRunner interface {
	// Ready reports whether the service can run this node's manifest now.
	Ready(ctx context.Context) error
	// Execute returns the verified outcome once the node holds its objects.
	Execute(ctx context.Context, execution ServiceExecution) (softwarework.Outcome, error)
}

// classifyServiceError maps a failed service call onto what it means for the
// request. Only an explicit answer of the service ends an execution; a
// refusal that claimed nothing, a dropped connection, an ended context, a
// server of another identity and a response that violates the protocol all
// leave it pending.
func classifyServiceError(err error) error {
	switch {
	case errors.Is(err, executorservice.ErrExecutionFailed):
		return fmt.Errorf("%w: %w", ErrExecutionFailed, err)
	case errors.Is(err, executorservice.ErrAmbiguous), errors.Is(err, executorservice.ErrConflict):
		return fmt.Errorf("%w: %w", ErrExecutionUnknown, err)
	default:
		return fmt.Errorf("%w: %w", ErrExecutionPending, err)
	}
}

func serviceLimits(limits nativecore.SoftwareWorkLimitsV1) executorservice.Limits {
	return executorservice.Limits{
		CPUMillis: limits.CPUMillis, MemoryBytes: limits.MemoryBytes, ScratchBytes: limits.ScratchBytes,
		OutputBytes: limits.OutputBytes, WallClockMillis: limits.WallClockMillis,
	}
}

// notReadyReason is what a service that describes itself as not ready can
// mean; its description does not say which.
const notReadyReason = "the private container runtime is down, or the pinned image is not imported and unpacked " +
	"in it; a job sent now is refused with nothing claimed"

// describedImageProblem compares the image the service runs jobs in with
// the manifest's toolchain.
func describedImageProblem(description executorservice.Description, toolchainDigest string) string {
	if description.ImageDigest != toolchainDigest {
		return fmt.Sprintf("the service runs jobs in image %s, not the manifest toolchain %s",
			description.ImageDigest, toolchainDigest)
	}
	return ""
}

// describedLimitsProblem names the first manifest limit the service would
// refuse: one that is zero or looser than the limit the service enforces.
func describedLimitsProblem(description executorservice.Description, limits nativecore.SoftwareWorkLimitsV1) string {
	for _, limit := range []struct {
		name            string
		manifest, upper uint64
	}{
		{"cpu_millis", limits.CPUMillis, description.Limits.CPUMillis},
		{"memory_bytes", limits.MemoryBytes, description.Limits.MemoryBytes},
		{"scratch_bytes", limits.ScratchBytes, description.Limits.ScratchBytes},
		{"output_bytes", limits.OutputBytes, description.Limits.OutputBytes},
		{"wall_clock_millis", limits.WallClockMillis, description.Limits.WallClockMillis},
	} {
		if limit.manifest == 0 || limit.manifest > limit.upper {
			return fmt.Sprintf("the manifest limit %s is %d; the service enforces 1 to %d", limit.name,
				limit.manifest, limit.upper)
		}
	}
	if description.MaxSourceBytes < MaxInlineInputBytes {
		return fmt.Sprintf("the service takes %d source bytes, less than the %d a task may carry",
			description.MaxSourceBytes, MaxInlineInputBytes)
	}
	return ""
}

// SocketRunner executes through the root-run executor service, so the node
// needs no container runtime privilege and reads no path of another user.
// It verifies every answer itself and keeps the artifact and report in the
// node's own state directory.
type SocketRunner struct {
	client          ExecutorService
	toolchainDigest string
	limits          nativecore.SoftwareWorkLimitsV1
	store           *artifactstore.Store
}

// SocketRunnerConfig binds a runner to one published manifest.
type SocketRunnerConfig struct {
	SocketPath string
	// StateDir is a directory of the node; the objects live below it.
	StateDir        string
	ManifestDigest  string
	ToolchainDigest string
	Limits          nativecore.SoftwareWorkLimitsV1
	// Client replaces the client of SocketPath.
	Client ExecutorService
}

// NewSocketRunner refuses an incomplete configuration. It does not contact
// the service.
func NewSocketRunner(config SocketRunnerConfig) (*SocketRunner, error) {
	if !cleanAbsolute(config.StateDir) {
		return nil, errors.New("servicebridge: executor paths must be absolute and clean")
	}
	if !sha256Pattern.MatchString(config.ManifestDigest) || !sha256Pattern.MatchString(config.ToolchainDigest) ||
		config.Limits.CPUMillis == 0 || config.Limits.MemoryBytes == 0 || config.Limits.ScratchBytes == 0 ||
		config.Limits.OutputBytes == 0 || config.Limits.WallClockMillis == 0 {
		return nil, errors.New("servicebridge: invalid executor configuration")
	}
	client := config.Client
	if client == nil {
		opened, err := OpenExecutorService(config.SocketPath)
		if err != nil {
			return nil, err
		}
		client = opened
	}
	if err := ensurePrivateDirectory(config.StateDir); err != nil {
		return nil, err
	}
	store, err := artifactstore.Open(filepath.Join(config.StateDir, "artifacts"), artifactstore.MaxObjectBytesHard)
	if err != nil {
		return nil, err
	}
	return &SocketRunner{
		client: client, toolchainDigest: config.ToolchainDigest,
		limits: config.Limits, store: store,
	}, nil
}

// Ready implements ServiceRunner: the service answers as root, its backend
// is ready, and it would run this manifest's image under its limits.
func (r *SocketRunner) Ready(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("servicebridge: invalid executor service probe")
	}
	probe, cancel := context.WithTimeout(ctx, describeTimeout)
	defer cancel()
	description, err := r.client.Describe(probe)
	if err != nil {
		return fmt.Errorf("servicebridge: the executor service does not answer: %w", err)
	}
	if !description.Ready {
		return errors.New("servicebridge: the executor service is not ready: " + notReadyReason)
	}
	if problem := describedImageProblem(description, r.toolchainDigest); problem != "" {
		return errors.New("servicebridge: " + problem)
	}
	if problem := describedLimitsProblem(description, r.limits); problem != "" {
		return errors.New("servicebridge: " + problem)
	}
	return nil
}

// Execute implements ServiceRunner.
func (r *SocketRunner) Execute(ctx context.Context, execution ServiceExecution) (softwarework.Outcome, error) {
	request := execution.Request
	limits := execution.Limits
	if r == nil || ctx == nil || len(request.SourceArchive) == 0 || len(request.SourceArchive) > MaxInlineInputBytes ||
		execution.ServiceRetainUntilUnix <= 0 || execution.RetainUntilUnix <= 0 ||
		!sha256Pattern.MatchString(execution.ManifestDigest) || !sha256Pattern.MatchString(execution.ToolchainDigest) ||
		limits.CPUMillis == 0 || limits.MemoryBytes == 0 || limits.ScratchBytes == 0 || limits.OutputBytes == 0 ||
		limits.WallClockMillis == 0 {
		return softwarework.Outcome{}, errors.New("servicebridge: invalid execution")
	}
	// The service is told the digest of the bytes it is sent, so a request
	// that names another source must not be sent at all.
	if sha256Text(sha256.Sum256(request.SourceArchive)) != request.SourceDigest {
		return softwarework.Outcome{}, errors.New("servicebridge: the source archive is not the one the request names")
	}
	result, err := r.client.Execute(ctx, executorservice.ExecuteRequest{
		ExecutionID: request.ExecutionID, QuoteCommitment: request.QuoteCommitment, InputDigest: request.InputDigest,
		ManifestDigest: execution.ManifestDigest, Limits: serviceLimits(limits),
		RetainUntilUnix: execution.ServiceRetainUntilUnix, SourceArchive: request.SourceArchive,
	})
	if err != nil {
		return softwarework.Outcome{}, classifyServiceError(err)
	}
	if err = verifyServiceResult(execution, result); err != nil {
		// Nothing in an answer that fails a check is trusted, including
		// that the execution ended.
		return softwarework.Outcome{}, fmt.Errorf("%w: %w", ErrExecutionPending, err)
	}
	if err = r.keep(ctx, result, execution.RetainUntilUnix); err != nil {
		return softwarework.Outcome{}, fmt.Errorf("%w: %w", ErrExecutionPending, err)
	}
	return result.Outcome, nil
}

// verifyServiceResult requires the answer to be a completed success of
// exactly this request in its manifest's sandbox and image, with the bytes
// its descriptors name. It repeats what the client checks, so the node does
// not depend on a check it cannot see. How long the service says it keeps
// its own copy is not looked at: the node serves only the copy it stores.
func verifyServiceResult(execution ServiceExecution, result executorservice.ExecuteResult) error {
	request, outcome := execution.Request, result.Outcome
	switch {
	case outcome.QuoteCommitment != request.QuoteCommitment || outcome.ExecutionID != request.ExecutionID ||
		outcome.InputDigest != request.InputDigest || outcome.SourceDigest != request.SourceDigest ||
		outcome.SandboxDigest != execution.ManifestDigest:
		return errors.New("servicebridge: the executor outcome is for another request or sandbox")
	case outcome.ToolchainDigest != execution.ToolchainDigest:
		return errors.New("servicebridge: the executor outcome names another image than the manifest toolchain")
	case outcome.ExitCode != 0 || outcome.CompletedAtUnix == 0:
		return errors.New("servicebridge: the executor outcome is not a completed success")
	case outcome.Artifact.MediaType != softwarework.ArtifactMediaType ||
		outcome.Report.MediaType != softwarework.ReportMediaType:
		return errors.New("servicebridge: the executor outcome names objects of another media type")
	case outcome.Artifact.SizeBytes != uint64(len(result.Artifact)) ||
		outcome.Artifact.Digest != sha256Text(sha256.Sum256(result.Artifact)):
		return errors.New("servicebridge: the artifact bytes are not the ones the outcome names")
	case outcome.Report.SizeBytes != uint64(len(result.Report)) ||
		outcome.Report.Digest != sha256Text(sha256.Sum256(result.Report)):
		return errors.New("servicebridge: the report bytes are not the ones the outcome names")
	}
	return nil
}

// keep stores both objects for the execution and gives them their deadline.
func (r *SocketRunner) keep(ctx context.Context, result executorservice.ExecuteResult, retainUntilUnix int64) error {
	outcome := result.Outcome
	for _, object := range []struct {
		descriptor artifactstore.Descriptor
		value      []byte
	}{{outcome.Artifact, result.Artifact}, {outcome.Report, result.Report}} {
		stored, err := r.store.PutFor(ctx, outcome.ExecutionID, object.descriptor.MediaType,
			bytes.NewReader(object.value))
		if err != nil {
			return fmt.Errorf("servicebridge: store an executor object: %w", err)
		}
		if stored.Digest != object.descriptor.Digest {
			return errors.New("servicebridge: a stored executor object has another digest than the outcome names")
		}
	}
	if err := r.store.Retain(ctx, outcome.ExecutionID, time.Unix(retainUntilUnix, 0),
		[]string{outcome.Artifact.Digest, outcome.Report.Digest}); err != nil {
		return fmt.Errorf("servicebridge: retain the executor objects: %w", err)
	}
	return nil
}

// Get returns an object the node stored.
func (r *SocketRunner) Get(ctx context.Context, digest string) ([]byte, error) {
	return r.store.Get(ctx, digest)
}

// Sweep deletes the objects of executions whose retention ended before now.
func (r *SocketRunner) Sweep(ctx context.Context, now time.Time) error {
	if _, err := r.store.Sweep(ctx, now, artifactstore.MaxSweepJobs); err != nil {
		return fmt.Errorf("servicebridge: sweep the executor objects: %w", err)
	}
	return nil
}
