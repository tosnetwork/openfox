package cliprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	OwnerChannel       string
	OwnerSenderID      string
	AllowInternal      bool
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
	if o.SubscriptionUse == "local-personal" && (o.OwnerChannel == "" || o.OwnerSenderID == "") {
		return fmt.Errorf("local-personal agent backend requires an owner principal")
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

func removeEnvironmentPrefixes(environment []string, prefixes ...string) []string {
	result := make([]string, 0, len(environment))
	for _, item := range environment {
		key, _, _ := strings.Cut(item, "=")
		remove := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(strings.ToUpper(key), strings.ToUpper(prefix)) {
				remove = true
				break
			}
		}
		if !remove {
			result = append(result, item)
		}
	}
	return result
}

type boundedCollector struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	budget    *byteBudget
	truncated bool
}

func newBoundedCollector(limit int) *boundedCollector {
	return newBoundedCollectorWithBudget(newByteBudget(limit))
}

func newBoundedCollectorWithBudget(budget *byteBudget) *boundedCollector {
	return &boundedCollector{budget: budget}
}

type byteBudget struct {
	mu        sync.Mutex
	remaining int
	truncated bool
}

func newByteBudget(limit int) *byteBudget {
	return &byteBudget{remaining: limit}
}

func (b *byteBudget) take(size int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size > b.remaining {
		size = b.remaining
		b.truncated = true
	}
	b.remaining -= size
	return size
}

func (b *byteBudget) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (w *boundedCollector) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(p)
	retained := w.budget.take(len(p))
	if retained < len(p) {
		p = p[:retained]
		w.truncated = true
	}
	if len(p) > 0 {
		_, _ = w.buf.Write(p)
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
	return w.truncated || w.budget.Truncated()
}

func (w *boundedCollector) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

// runCommandBounded drains stdout and stderr even after the retention limit is
// reached. This prevents an untrusted provider process from blocking on a full
// pipe while keeping OpenFox memory use bounded.
func runCommandBounded(ctx context.Context, cmd *exec.Cmd, input []byte, maxOutputBytes int) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	budget := newByteBudget(maxOutputBytes)
	stdout := newBoundedCollectorWithBudget(budget)
	stderr := newBoundedCollectorWithBudget(budget)
	if cmd.Stdout != nil || cmd.Stderr != nil || cmd.Stdin != nil {
		return "", "", fmt.Errorf("agent backend command standard streams are already configured")
	}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := isolationStart(cmd); err != nil {
		return "", "", err
	}
	if err := attachProcessTree(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return stdout.String(), stderr.String(), fmt.Errorf("attach agent backend process tree: %w", err)
	}

	// exec.Cmd owns the copy goroutines for non-file stdout/stderr writers and
	// waits for them before Wait returns. Calling Wait while independently
	// reading StdoutPipe/StderrPipe is explicitly unsafe: Wait may close a pipe
	// after the process exits before the reader has retained its final bytes.
	waitErr := cmd.Wait()
	if stdout.Truncated() || stderr.Truncated() {
		return stdout.String(), stderr.String(), ErrOutputLimit
	}
	return stdout.String(), stderr.String(), waitErr
}
