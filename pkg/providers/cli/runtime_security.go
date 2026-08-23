package cliprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/isolation"
)

const defaultMaxOutputBytes = 4 * 1024 * 1024

var ErrOutputLimit = errors.New("agent backend output exceeded configured limit")

var isolationStart = isolation.Start

// RuntimeOptions is the fail-closed execution policy shared by local full-agent
// providers. Native tools are disabled by default so OpenFox remains the only
// tool authorization and execution loop.
type RuntimeOptions struct {
	Workspace          string
	Sandbox            string
	ApprovalPolicy     string
	AllowNativeTools   bool
	SubscriptionUse    string
	MaxConcurrentCalls int
	MaxOutputBytes     int
	Timeout            time.Duration
}

func (o RuntimeOptions) normalized() RuntimeOptions {
	if o.Sandbox == "" {
		o.Sandbox = "read-only"
	}
	if o.ApprovalPolicy == "" {
		o.ApprovalPolicy = "never"
	}
	if o.MaxConcurrentCalls == 0 {
		o.MaxConcurrentCalls = 1
	}
	if o.MaxOutputBytes == 0 {
		o.MaxOutputBytes = defaultMaxOutputBytes
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Minute
	}
	return o
}

func (o RuntimeOptions) validate() error {
	o = o.normalized()
	if o.Sandbox != "read-only" && o.Sandbox != "workspace-write" {
		return fmt.Errorf("unsafe agent backend sandbox %q", o.Sandbox)
	}
	if o.ApprovalPolicy != "never" {
		return fmt.Errorf("agent backend approval policy %q requires an interactive approval broker", o.ApprovalPolicy)
	}
	if o.AllowNativeTools {
		return fmt.Errorf("agent backend native tools require an OpenFox approval broker and are not available yet")
	}
	if o.SubscriptionUse != "" && o.SubscriptionUse != "local-personal" {
		return fmt.Errorf("unsupported subscription use %q", o.SubscriptionUse)
	}
	if o.MaxConcurrentCalls < 1 || o.MaxConcurrentCalls > 16 {
		return fmt.Errorf("max concurrent calls must be between 1 and 16")
	}
	if o.MaxOutputBytes < 4096 || o.MaxOutputBytes > 16*1024*1024 {
		return fmt.Errorf("max output bytes must be between 4096 and 16777216")
	}
	if o.Timeout < time.Second || o.Timeout > time.Hour {
		return fmt.Errorf("agent backend timeout must be between 1 second and 1 hour")
	}
	return nil
}

func (o RuntimeOptions) boundedContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, o.normalized().Timeout)
}

func (o RuntimeOptions) canonicalWorkspace() (string, error) {
	workspace := o.Workspace
	if workspace == "" {
		return "", fmt.Errorf("agent backend workspace is required")
	}
	if !filepath.IsAbs(workspace) {
		return "", fmt.Errorf("agent backend workspace must be an absolute path")
	}
	abs, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolve agent backend workspace: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve agent backend workspace symlinks: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat agent backend workspace: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("agent backend workspace is not a directory")
	}
	return canonical, nil
}

type boundedCollector struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func newBoundedCollector(limit int) *boundedCollector {
	return &boundedCollector{remaining: limit}
}

func (w *boundedCollector) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
		w.truncated = true
	}
	if len(p) > 0 {
		_, _ = w.buf.Write(p)
		w.remaining -= len(p)
	}
	return original, nil
}

func (w *boundedCollector) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *boundedCollector) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

// runCommandBounded drains stdout and stderr even after the retention limit is
// reached. This prevents an untrusted provider process from blocking on a full
// pipe while keeping OpenFox memory use bounded.
func runCommandBounded(ctx context.Context, cmd *exec.Cmd, input []byte, maxOutputBytes int) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}
	cmd.Stdin = bytes.NewReader(input)

	if err := isolationStart(cmd); err != nil {
		return "", "", err
	}

	stdout := newBoundedCollector(maxOutputBytes)
	stderr := newBoundedCollector(maxOutputBytes)
	done := make(chan struct{}, 2)
	copyPipe := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyPipe(stdout, stdoutPipe)
	go copyPipe(stderr, stderrPipe)

	waitErr := cmd.Wait()
	<-done
	<-done
	if stdout.Truncated() || stderr.Truncated() {
		return stdout.String(), stderr.String(), ErrOutputLimit
	}
	return stdout.String(), stderr.String(), waitErr
}
