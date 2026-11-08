package servicebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

// SubprocessRunner runs the tos-ai software-work executor as a separate,
// pinned binary, so the container runtime client and its privileges stay
// outside OpenFox. The executor keeps its own at-most-once journal and
// artifact store under StateDir; OpenFox reads artifacts from that store.
type SubprocessRunner struct {
	binary           []byte
	containerdSocket string
	fifoDir          string
	stateDir         string
	manifestDigest   string
	outputBytes      uint64
	timeout          time.Duration
	store            *artifactstore.Store
}

// SubprocessRunnerConfig pins the executor binary by SHA-256.
type SubprocessRunnerConfig struct {
	BinaryPath       string
	BinarySHA256     string
	ContainerdSocket string
	FIFODir          string
	StateDir         string
	ManifestDigest   string
	OutputBytes      uint64
}

// NewSubprocessRunner reads the executor once and refuses other bytes.
func NewSubprocessRunner(config SubprocessRunnerConfig) (*SubprocessRunner, error) {
	for _, path := range []string{config.BinaryPath, config.ContainerdSocket, config.FIFODir, config.StateDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("servicebridge: executor paths must be absolute and clean")
		}
	}
	if !hex64Pattern.MatchString(config.BinarySHA256) || !sha256Pattern.MatchString(config.ManifestDigest) ||
		config.OutputBytes == 0 {
		return nil, errors.New("servicebridge: invalid executor configuration")
	}
	binary, err := os.ReadFile(config.BinaryPath)
	if err != nil || len(binary) == 0 || len(binary) > maxTOSCTLBytes {
		return nil, errors.New("servicebridge: read the executor binary")
	}
	digest := sha256.Sum256(binary)
	if hex.EncodeToString(digest[:]) != config.BinarySHA256 {
		return nil, errors.New("servicebridge: the executor binary does not have the pinned SHA-256")
	}
	if err = ensurePrivateDirectory(config.StateDir); err != nil {
		return nil, err
	}
	store, err := artifactstore.Open(filepath.Join(config.StateDir, "artifacts"), 64<<20)
	if err != nil {
		return nil, err
	}
	return &SubprocessRunner{
		binary: binary, containerdSocket: config.ContainerdSocket, fifoDir: config.FIFODir,
		stateDir: config.StateDir, manifestDigest: config.ManifestDigest, outputBytes: config.OutputBytes,
		timeout: 10 * time.Minute, store: store,
	}, nil
}

// Execute stages the source archive privately and runs the executor.
func (r *SubprocessRunner) Execute(ctx context.Context, request softwarework.Request) (softwarework.Outcome, error) {
	if r == nil || ctx == nil || len(request.SourceArchive) == 0 || len(request.SourceArchive) > MaxInlineInputBytes {
		return softwarework.Outcome{}, errors.New("servicebridge: invalid execution")
	}
	staging := filepath.Join(r.stateDir, "staging")
	if err := ensurePrivateDirectory(staging); err != nil {
		return softwarework.Outcome{}, err
	}
	source := filepath.Join(staging, request.ExecutionID[len("sha256:"):]+".tar")
	if err := writeSynced(source, request.SourceArchive); err != nil && !errors.Is(err, os.ErrExist) {
		return softwarework.Outcome{}, err
	}
	executable, err := sealedExecutable(r.binary)
	if err != nil {
		return softwarework.Outcome{}, err
	}
	defer executable.Close()
	call, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	command := exec.CommandContext(call, fmt.Sprintf("/proc/self/fd/%d", executable.Fd()),
		"-containerd-socket", r.containerdSocket, "-fifo-dir", r.fifoDir, "-state-dir", r.stateDir, "-source", source,
		"-quote", request.QuoteCommitment, "-execution-id", request.ExecutionID, "-input-digest", request.InputDigest,
		"-manifest-digest", r.manifestDigest, "-output-bytes", strconv.FormatUint(r.outputBytes, 10))
	command.Env = []string{}
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxLifecycleOutput, maxLifecycleOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return softwarework.Outcome{}, fmt.Errorf("servicebridge: the executor failed: %s", exitStatus(err))
	}
	var outcome softwarework.Outcome
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&outcome); err != nil {
		return softwarework.Outcome{}, errors.New("servicebridge: the executor outcome does not decode")
	}
	if outcome.QuoteCommitment != request.QuoteCommitment || outcome.ExecutionID != request.ExecutionID ||
		outcome.InputDigest != request.InputDigest || outcome.SourceDigest != request.SourceDigest || outcome.SandboxDigest != r.manifestDigest {
		return softwarework.Outcome{}, errors.New(
			"servicebridge: the executor outcome is for another request or sandbox",
		)
	}
	return outcome, nil
}

// Get returns an artifact the executor stored.
func (r *SubprocessRunner) Get(ctx context.Context, digest string) ([]byte, error) {
	return r.store.Get(ctx, digest)
}
