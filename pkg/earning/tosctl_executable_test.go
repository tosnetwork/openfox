//go:build linux

package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

type campaignPaymentPreflightProvider struct {
	calls  int
	closes int
}

func (provider *campaignPaymentPreflightProvider) Chat(context.Context, []providers.Message,
	[]providers.ToolDefinition, string, map[string]any,
) (*providers.LLMResponse, error) {
	provider.calls++
	return &providers.LLMResponse{Content: "unexpected"}, nil
}

func (*campaignPaymentPreflightProvider) GetDefaultModel() string { return "preflight-test" }

func (provider *campaignPaymentPreflightProvider) Close() { provider.closes++ }

func TestTOSCTLExecutableHelper(t *testing.T) {
	arguments := []string(nil)
	for index, argument := range os.Args {
		if argument == "--" && index+1 < len(os.Args) {
			arguments = os.Args[index+1:]
			break
		}
	}
	if len(arguments) == 0 {
		return
	}
	mode := arguments[0]
	switch mode {
	case "normal":
		_, _ = fmt.Fprint(os.Stdout, `{"state":"safe"}`)
		os.Exit(0)
	case "overflow":
		chunk := bytes.Repeat([]byte("x"), 600<<10)
		_, _ = os.Stdout.Write(chunk)
		_, _ = os.Stderr.Write(chunk)
		os.Exit(0)
	case "secret-error":
		_, _ = fmt.Fprint(os.Stderr, "TOP-SECRET-CUSTODY-DIAGNOSTIC")
		os.Exit(2)
	case "spawn-grandchild":
		if len(arguments) != 2 {
			os.Exit(3)
		}
		child := exec.Command("/proc/self/exe", "-test.run=^TestTOSCTLExecutableHelper$", "--",
			"delayed-marker", arguments[1])
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(4)
		}
		_, _ = fmt.Fprint(os.Stdout, `{"state":"parent-exited"}`)
		os.Exit(0)
	case "spawn-detached-grandchild":
		if len(arguments) != 2 || os.Getpid() != 1 {
			os.Exit(7)
		}
		child := exec.Command("/proc/self/exe", "-test.run=^TestTOSCTLExecutableHelper$", "--",
			"delayed-marker", arguments[1])
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(8)
		}
		_, _ = fmt.Fprint(os.Stdout, `{"state":"detached-parent-exited"}`)
		os.Exit(0)
	case "spawn-detached-and-wait":
		if len(arguments) != 2 || os.Getpid() != 1 {
			os.Exit(9)
		}
		child := exec.Command("/proc/self/exe", "-test.run=^TestTOSCTLExecutableHelper$", "--",
			"delayed-marker", arguments[1])
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(10)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "delayed-marker":
		if len(arguments) != 2 {
			os.Exit(5)
		}
		time.Sleep(3 * time.Second)
		if os.WriteFile(arguments[1], []byte("escaped"), 0o600) != nil {
			os.Exit(6)
		}
		os.Exit(0)
	}
}

func requireTOSCTLProcessContainment(t *testing.T, sink *TOSCTLPaymentSink) {
	t.Helper()
	output, err := sink.run(t.Context(), []string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "normal"})
	if errors.Is(err, errTOSCTLProcessContainmentUnavailable) {
		if output != nil || len(sink.executableLaunches) != 0 {
			t.Fatalf("unavailable containment did not fail closed: output=%q slots=%d", output,
				len(sink.executableLaunches))
		}
		t.Skip("kernel does not permit the user/PID namespace required for secure tosctl containment")
	}
	if err != nil || string(output) != `{"state":"safe"}` {
		t.Fatalf("probe secure tosctl containment: output=%q err=%v", output, err)
	}
}

func TestTOSCTLRunnerContainsOrdinaryDescendant(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := privateTempDir(t)
	executable := filepath.Join(root, "tosctl")
	copyExecutableFixture(t, current, executable)
	marker := filepath.Join(root, "escaped-marker")
	sink := &TOSCTLPaymentSink{Executable: executable}
	requireTOSCTLProcessContainment(t, sink)
	output, err := sink.run(t.Context(), []string{"-test.run=^TestTOSCTLExecutableHelper$", "--",
		"spawn-grandchild", marker})
	if err != nil || string(output) != `{"state":"parent-exited"}` {
		t.Fatalf("run descendant fixture: output=%q err=%v", output, err)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tosctl descendant survived leader cleanup and wrote marker: %v", err)
	}
	if len(sink.executableLaunches) != 0 {
		t.Fatal("descendant cleanup leaked a bounded tosctl launch slot")
	}
}

func TestTOSCTLRunnerContainsDetachedDescendantsOnLeaderExit(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := privateTempDir(t)
	executable := filepath.Join(root, "tosctl")
	copyExecutableFixture(t, current, executable)
	marker := filepath.Join(root, "detached-marker")
	sink := &TOSCTLPaymentSink{Executable: executable}
	requireTOSCTLProcessContainment(t, sink)
	output, err := sink.run(t.Context(), []string{"-test.run=^TestTOSCTLExecutableHelper$", "--",
		"spawn-detached-grandchild", marker})
	if err != nil || string(output) != `{"state":"detached-parent-exited"}` {
		t.Fatalf("run detached descendant fixture: output=%q err=%v", output, err)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setsid descendant survived PID namespace teardown and wrote marker: %v", err)
	}
}

func TestTOSCTLRunnerContainsDetachedDescendantsOnCancellation(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := privateTempDir(t)
	executable := filepath.Join(root, "tosctl")
	copyExecutableFixture(t, current, executable)
	marker := filepath.Join(root, "cancelled-detached-marker")
	sink := &TOSCTLPaymentSink{Executable: executable}
	requireTOSCTLProcessContainment(t, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if output, err := sink.run(ctx, []string{"-test.run=^TestTOSCTLExecutableHelper$", "--",
		"spawn-detached-and-wait", marker}); err == nil || output != nil ||
		!strings.Contains(err.Error(), "deadline") {
		t.Fatalf("cancelled detached fixture did not fail closed: output=%q err=%v", output, err)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setsid descendant survived cancellation and wrote marker: %v", err)
	}
	if len(sink.executableLaunches) != 0 {
		t.Fatal("cancelled containment leaked a bounded tosctl launch slot")
	}
}

func TestTOSCTLRunnerUsesSharedOutputBudgetAndRedactedErrors(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(privateTempDir(t), "tosctl")
	copyExecutableFixture(t, current, executable)
	sink := &TOSCTLPaymentSink{Executable: executable}
	requireTOSCTLProcessContainment(t, sink)
	enrolled := sink.executableSnapshot
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 24)
	for index := 0; index < cap(errorsSeen); index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			output, runErr := sink.run(t.Context(),
				[]string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "normal"})
			if runErr == nil && string(output) != `{"state":"safe"}` {
				runErr = errors.New("concurrent launch returned unrelated output")
			}
			errorsSeen <- runErr
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for runErr := range errorsSeen {
		if runErr != nil {
			t.Fatalf("concurrent sealed tosctl launch: %v", runErr)
		}
	}
	if enrolled == nil || sink.executableSnapshot != enrolled || len(sink.executableLaunches) != 0 {
		t.Fatal("concurrent launches did not reuse and release one sealed executable snapshot")
	}
	if output, err := sink.run(t.Context(),
		[]string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "overflow"}); err == nil || output != nil ||
		!strings.Contains(err.Error(), "shared byte budget") || len(err.Error()) > 128 {
		t.Fatalf("shared stdout/stderr budget was not enforced: bytes=%d err=%v", len(output), err)
	}
	if output, err := sink.run(t.Context(),
		[]string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "secret-error"}); err == nil || output != nil ||
		strings.Contains(err.Error(), "TOP-SECRET") || len(err.Error()) > 128 {
		t.Fatalf("tosctl diagnostic escaped the redacted error boundary: output=%q err=%v", output, err)
	}
}

func TestTOSCTLInjectedRunnerResultIsBoundedCopiedAndRedacted(t *testing.T) {
	backing := make([]byte, 32, 2<<20)
	copy(backing, []byte("bounded"))
	sink := &TOSCTLPaymentSink{VaultURL: "file:///owner/vault", Run: func(_ context.Context, _ []string,
		environment []string) ([]byte, error) {
		if len(environment) != 1 || environment[0] != "VAULT_URL=file:///owner/vault" {
			return nil, errors.New("environment was not capability-scoped")
		}
		return backing, nil
	}}
	output, err := sink.run(t.Context(), []string{"agent", "account", "query"})
	if err != nil || len(output) != len(backing) || cap(output) > len(backing)+16 {
		t.Fatalf("bounded callback result was retained unsafely: len=%d cap=%d err=%v", len(output), cap(output), err)
	}
	backing[0] = 'X'
	if output[0] == 'X' {
		t.Fatal("callback retained mutable ownership of an accepted tosctl result")
	}
	sink.Run = func(context.Context, []string, []string) ([]byte, error) {
		return bytes.Repeat([]byte("x"), maximumTOSCTLCommandOutputBytes+1), nil
	}
	if output, err := sink.run(t.Context(), nil); err == nil || output != nil {
		t.Fatal("oversized injected tosctl result crossed the shared byte budget")
	}
	sink.Run = func(context.Context, []string, []string) ([]byte, error) {
		return nil, errors.New("TOP-SECRET callback failure")
	}
	if _, err := sink.run(t.Context(), nil); err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
		t.Fatalf("injected tosctl error was not redacted: %v", err)
	}
	for _, capability := range []string{"unix:///run/tos-vault.sock", "http://127.0.0.1:8200", "https://vault.example"} {
		candidate := &TOSCTLPaymentSink{VaultURL: capability,
			Run: func(context.Context, []string, []string) ([]byte, error) { return []byte("{}"), nil }}
		if _, err := candidate.run(t.Context(), nil); err != nil {
			t.Fatalf("opaque bounded vault capability %q was rejected: %v", capability, err)
		}
		candidate.VaultURL += "/changed"
		if _, err := candidate.run(t.Context(), nil); err == nil {
			t.Fatalf("enrolled vault capability %q was mutable", capability)
		}
	}
}

func TestTOSCTLExecutableReplacementCannotChangeEnrolledOrOpenedLaunch(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTempDir(t)
	executable := filepath.Join(directory, "tosctl")
	copyExecutableFixture(t, current, executable)

	sink := &TOSCTLPaymentSink{Executable: executable}
	if err := sink.pinTOSCTLExecutable(); err != nil {
		t.Fatal(err)
	}
	opened, _, err := snapshotTOSCTLExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nprintf attacker\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, executable); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.run(t.Context(), []string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "normal"}); err == nil {
		t.Fatal("path replacement retained the enrolled tosctl authority")
	}

	t.Run("production command wiring launches the sealed descriptor", func(t *testing.T) {
		// The descriptor opened before replacement is a sealed byte snapshot, so
		// even an immediate pathname swap cannot redirect the production command
		// wiring to the attacker script.
		command := newSealedTOSCTLCommand(t.Context(),
			[]string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "normal"}, nil, opened)
		if command.Path != "/proc/self/fd/3" || len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != opened {
			t.Fatalf("production launch is not wired to descriptor 3: path=%q extra=%v",
				command.Path, command.ExtraFiles)
		}
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if err := command.Run(); errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
			errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
			t.Skip("kernel does not permit the production user/PID namespace wiring")
		} else if err != nil || output.String() != `{"state":"safe"}` {
			t.Fatalf("production sealed launch followed its replaced path: output=%q err=%v", output.String(), err)
		}
	})
}

func TestTOSCTLExecutableRejectsWritableOrIndirectAncestry(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unsafeDirectory, err := os.MkdirTemp(os.TempDir(), "openfox-unsafe-tosctl-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(unsafeDirectory) })
	executable := filepath.Join(unsafeDirectory, "tosctl")
	copyExecutableFixture(t, current, executable)
	if err := os.Chmod(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if snapshot, _, err := snapshotTOSCTLExecutable(executable); err == nil {
		_ = snapshot.Close()
		t.Fatal("executable beneath writable ancestry was trusted")
	}
	if err := os.Chmod(unsafeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(unsafeDirectory, "tosctl-link")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	if snapshot, _, err := snapshotTOSCTLExecutable(link); err == nil {
		_ = snapshot.Close()
		t.Fatal("symlinked tosctl executable was trusted")
	}
}

func TestRound5CampaignBootstrapPinsBeforeBinderAndProvider(t *testing.T) {
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENFOX_TOSCTL_PRIMARY_CONFIG", filepath.Join(privateTempDir(t), "primary.json"))
	t.Setenv("OPENFOX_TOS_VAULT_URL", "file:///owner/round5-bootstrap-test-vault")
	entry := func(index int) eightAgentManifestEntry {
		return eightAgentManifestEntry{
			Name:        fmt.Sprintf("bootstrap-agent-%d", index),
			Wallet:      fmt.Sprintf("bootstrap-wallet-%d", index),
			AuthorityID: fmt.Sprintf("authority:bootstrap-agent-%d", index),
		}
	}
	journal := privateTempDir(t)

	t.Run("unsafe bootstrap stops bind and Provider factory", func(t *testing.T) {
		unsafeParent, err := os.MkdirTemp(os.TempDir(), "openfox-round5-bootstrap-unsafe-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(unsafeParent) })
		if err = os.Chmod(unsafeParent, 0o770); err != nil {
			t.Fatal(err)
		}
		unsafePrivateChild := filepath.Join(unsafeParent, "owner-private-after-writable-parent")
		if err = os.Mkdir(unsafePrivateChild, 0o700); err != nil {
			t.Fatal(err)
		}
		unsafeMarker := filepath.Join(unsafePrivateChild, "unsafe-bind-ran")
		unsafeExecutable := filepath.Join(unsafePrivateChild, "tosctl")
		writeCampaignBindingExecutable(t, unsafeExecutable, unsafeMarker, "unsafe")
		binderCallbacks, providerCreations := 0, 0
		wiring := &campaignRuntimeProviderWiring{
			round5: true, expectedBindings: 8,
			providerFactory: func(*config.Config) (providers.LLMProvider, string, error) {
				providerCreations++
				return &campaignPaymentPreflightProvider{}, "bootstrap-test", nil
			},
		}
		err = withCampaignTOSCTLBootstrap(true, unsafeExecutable, os.Getenv("OPENFOX_TOS_VAULT_URL"),
			func(bootstrap *TOSCTLPaymentSink) error {
				for index := 0; index < 8; index++ {
					manifestEntry := entry(index)
					if bindErr := wiring.bind(bootstrap, func() error {
						binderCallbacks++
						return bindCampaignPayer(t, manifestEntry, authorityKey, journal, bootstrap)
					}); bindErr != nil {
						return bindErr
					}
				}
				_, _, providerErr := wiring.createProvider(nil)
				return providerErr
			})
		if err == nil || !strings.Contains(err.Error(), "executable is untrusted") ||
			binderCallbacks != 0 || providerCreations != 0 {
			t.Fatalf("unsafe bootstrap crossed startup trust gate: binders=%d providers=%d err=%v",
				binderCallbacks, providerCreations, err)
		}
		if _, statErr := os.Lstat(unsafeMarker); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("unsafe bootstrap executable ran before rejection: %v", statErr)
		}
	})

	t.Run("Provider factory requires all eight bindings", func(t *testing.T) {
		safeRoot := privateTempDir(t)
		safeExecutable := filepath.Join(safeRoot, "tosctl")
		writeCampaignBindingExecutable(t, safeExecutable, filepath.Join(safeRoot, "unused"), "unused")
		providerCreations := 0
		wiring := &campaignRuntimeProviderWiring{
			round5: true, expectedBindings: 8,
			providerFactory: func(*config.Config) (providers.LLMProvider, string, error) {
				providerCreations++
				return &campaignPaymentPreflightProvider{}, "bootstrap-test", nil
			},
		}
		sealedFD := -1
		err = withCampaignTOSCTLBootstrap(true, safeExecutable, os.Getenv("OPENFOX_TOS_VAULT_URL"),
			func(bootstrap *TOSCTLPaymentSink) error {
				sealedFD = int(bootstrap.executableSnapshot.Fd())
				for index := 0; index < 7; index++ {
					if bindErr := wiring.bind(bootstrap, func() error { return nil }); bindErr != nil {
						return bindErr
					}
				}
				_, _, providerErr := wiring.createProvider(nil)
				return providerErr
			})
		if err == nil || !strings.Contains(err.Error(), "exactly eight bindings") || providerCreations != 0 {
			t.Fatalf("Provider factory ran before all bindings: providers=%d err=%v", providerCreations, err)
		}
		requireClosedFileDescriptor(t, sealedFD)
	})

	t.Run("eight sealed bindings share one snapshot before Provider factory", func(t *testing.T) {
		safeRoot := privateTempDir(t)
		safeMarker := filepath.Join(safeRoot, "safe-bind-ran")
		safeExecutable := filepath.Join(safeRoot, "tosctl")
		writeCampaignAppendingBindingExecutable(t, safeExecutable, safeMarker, "safe")
		var bootstraps []*TOSCTLPaymentSink
		var snapshots []*os.File
		providerCreations := 0
		wiring := &campaignRuntimeProviderWiring{
			round5: true, expectedBindings: 8,
			providerFactory: func(*config.Config) (providers.LLMProvider, string, error) {
				if len(bootstraps) != 8 || len(snapshots) != 8 {
					return nil, "", errors.New("Provider factory observed incomplete payer binding")
				}
				providerCreations++
				return &campaignPaymentPreflightProvider{}, "bootstrap-test", nil
			},
		}
		sealedFD := -1
		err = withCampaignTOSCTLBootstrap(true, safeExecutable, os.Getenv("OPENFOX_TOS_VAULT_URL"),
			func(bootstrap *TOSCTLPaymentSink) error {
				for index := 0; index < 8; index++ {
					manifestEntry := entry(index)
					if bindErr := wiring.bind(bootstrap, func() error {
						bootstrap.executableMu.Lock()
						snapshot := bootstrap.executableSnapshot
						bootstrap.executableMu.Unlock()
						if snapshot == nil {
							return errors.New("sealed snapshot disappeared before payer binding")
						}
						if sealedFD < 0 {
							sealedFD = int(snapshot.Fd())
						}
						bootstraps = append(bootstraps, bootstrap)
						snapshots = append(snapshots, snapshot)
						return bindCampaignPayer(t, manifestEntry, authorityKey, journal, bootstrap)
					}); bindErr != nil {
						return bindErr
					}
				}
				for index := 0; index < 8; index++ {
					if _, _, providerErr := wiring.createProvider(nil); providerErr != nil {
						return providerErr
					}
				}
				return nil
			})
		if errors.Is(err, errTOSCTLProcessContainmentUnavailable) {
			if sealedFD >= 0 {
				requireClosedFileDescriptor(t, sealedFD)
			}
			t.Skip("kernel does not permit the user/PID namespace required for sealed Round 5 binding")
		}
		if err != nil || len(bootstraps) != 8 || providerCreations != 8 {
			t.Fatalf("safe bootstrap wiring: bindings=%d providers=%d err=%v",
				len(bootstraps), providerCreations, err)
		}
		for index := range bootstraps {
			if bootstraps[index] != wiring.bootstrap || snapshots[index] != wiring.snapshot {
				t.Fatalf("binding %d did not share the production bootstrap snapshot", index)
			}
		}
		if wiring.bootstrap.executableSnapshot != nil {
			t.Fatal("bootstrap retained its snapshot after Provider construction")
		}
		requireClosedFileDescriptor(t, sealedFD)
		raw, readErr := os.ReadFile(safeMarker)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if readErr != nil || len(lines) != 8 {
			t.Fatalf("sealed bootstrap did not execute exactly eight bindings: marker=%q err=%v", raw, readErr)
		}
		for index, line := range lines {
			if line != "safe" {
				t.Fatalf("sealed binding %d executed unexpected bytes: %q", index, line)
			}
		}
	})

	t.Run("pathname swap fails closed independently of containment", func(t *testing.T) {
		swapRoot := privateTempDir(t)
		originalMarker := filepath.Join(swapRoot, "original-bind-ran")
		attackerMarker := filepath.Join(swapRoot, "attacker-bind-ran")
		swapExecutable := filepath.Join(swapRoot, "tosctl")
		writeCampaignBindingExecutable(t, swapExecutable, originalMarker, "original")
		binderCallbacks, providerCreations := 0, 0
		wiring := &campaignRuntimeProviderWiring{
			round5: true, expectedBindings: 8,
			providerFactory: func(*config.Config) (providers.LLMProvider, string, error) {
				providerCreations++
				return &campaignPaymentPreflightProvider{}, "bootstrap-test", nil
			},
		}
		sealedFD := -1
		var retainedBootstrap *TOSCTLPaymentSink
		err = withCampaignTOSCTLBootstrap(true, swapExecutable, os.Getenv("OPENFOX_TOS_VAULT_URL"),
			func(bootstrap *TOSCTLPaymentSink) error {
				retainedBootstrap = bootstrap
				sealedFD = int(bootstrap.executableSnapshot.Fd())
				replacement := filepath.Join(swapRoot, "replacement")
				writeCampaignBindingExecutable(t, replacement, attackerMarker, "attacker")
				if renameErr := os.Rename(replacement, swapExecutable); renameErr != nil {
					return renameErr
				}
				return wiring.bind(bootstrap, func() error {
					binderCallbacks++
					return bindCampaignPayer(t, entry(0), authorityKey, journal, bootstrap)
				})
			})
		if err == nil || !strings.Contains(err.Error(), "executable is untrusted") ||
			binderCallbacks != 1 || providerCreations != 0 || retainedBootstrap == nil {
			t.Fatalf("pathname swap escaped sealed bootstrap: binders=%d providers=%d bootstrap=%v err=%v",
				binderCallbacks, providerCreations, retainedBootstrap, err)
		}
		if retainedBootstrap.executableSnapshot != nil {
			t.Fatal("pathname-swap failure retained the bootstrap snapshot")
		}
		requireClosedFileDescriptor(t, sealedFD)
		for _, marker := range []string{originalMarker, attackerMarker} {
			if _, statErr := os.Lstat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("swapped bootstrap executed %s: %v", marker, statErr)
			}
		}
	})

	t.Run("legacy and Round 4 keep direct pathname binding", func(t *testing.T) {
		legacyRoot := privateTempDir(t)
		legacyMarker := filepath.Join(legacyRoot, "legacy-bind-ran")
		legacyExecutable := filepath.Join(legacyRoot, "tosctl")
		writeCampaignBindingExecutable(t, legacyExecutable, legacyMarker, "legacy")
		t.Setenv("OPENFOX_TOSCTL", legacyExecutable)
		binderCallbacks := 0
		err = withCampaignTOSCTLBootstrap(false, "", "", func(bootstrap *TOSCTLPaymentSink) error {
			if bootstrap != nil {
				return errors.New("legacy campaign unexpectedly received a sealed bootstrap")
			}
			binderCallbacks++
			return bindCampaignPayer(t, entry(0), authorityKey, journal, nil)
		})
		if err != nil || binderCallbacks != 1 {
			t.Fatalf("legacy direct binder behavior changed: binders=%d err=%v", binderCallbacks, err)
		}
		if raw, readErr := os.ReadFile(legacyMarker); readErr != nil || string(raw) != "legacy" {
			t.Fatalf("legacy direct binder no longer executes its configured path: marker=%q err=%v", raw, readErr)
		}
	})
}

func writeCampaignBindingExecutable(t *testing.T, path, marker, value string) {
	t.Helper()
	quotedMarker := "'" + strings.ReplaceAll(marker, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nprintf '" + value + "' > " + quotedMarker + "\nprintf '{}'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeCampaignAppendingBindingExecutable(t *testing.T, path, marker, value string) {
	t.Helper()
	quotedMarker := "'" + strings.ReplaceAll(marker, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nprintf '" + value + "\\n' >> " + quotedMarker + "\nprintf '{}'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func requireClosedFileDescriptor(t *testing.T, descriptor int) {
	t.Helper()
	if descriptor < 0 {
		t.Fatal("sealed executable descriptor was not captured")
	}
	var status syscall.Stat_t
	if err := syscall.Fstat(descriptor, &status); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("sealed executable descriptor %d remains usable after close: %v", descriptor, err)
	}
}

func TestRound5CampaignPaymentPreflightRejectsWritableAncestryBeforeProviderTurn(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	safeRoot := privateTempDir(t)
	safeExecutable := filepath.Join(safeRoot, "tosctl")
	copyExecutableFixture(t, current, safeExecutable)
	safeProvider := &campaignPaymentPreflightProvider{}
	safeRuntime := &campaignRuntime{
		definition: eightAgentManifestEntry{Name: "safe-payment-agent"},
		provider:   safeProvider,
		payment:    campaignPaymentPreflightSink(safeExecutable, safeRoot),
	}
	if err = preflightCampaignPaymentAdapters(true, []*campaignRuntime{safeRuntime}); err != nil {
		t.Fatalf("owner-private Round 5 payment Adapter failed preflight: %v", err)
	}
	if safeProvider.calls != 0 || safeProvider.closes != 0 || safeRuntime.payment.executableSnapshot == nil {
		t.Fatalf("safe preflight called or closed Provider, or omitted enrollment: calls=%d closes=%d snapshot=%v",
			safeProvider.calls, safeProvider.closes, safeRuntime.payment.executableSnapshot)
	}
	safeSnapshotFD := int(safeRuntime.payment.executableSnapshot.Fd())
	closeCampaignRuntimes([]*campaignRuntime{safeRuntime})
	if safeProvider.closes != 1 || safeRuntime.payment.executableSnapshot != nil {
		t.Fatalf("safe runtime cleanup closes=%d snapshot=%v",
			safeProvider.closes, safeRuntime.payment.executableSnapshot)
	}
	requireClosedFileDescriptor(t, safeSnapshotFD)

	unsafeParent, err := os.MkdirTemp(os.TempDir(), "openfox-round5-writable-parent-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(unsafeParent) })
	if err = os.Chmod(unsafeParent, 0o770); err != nil {
		t.Fatal(err)
	}
	unsafePrivateChild := filepath.Join(unsafeParent, "owner-private-after-writable-parent")
	if err = os.Mkdir(unsafePrivateChild, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeExecutable := filepath.Join(unsafePrivateChild, "tosctl")
	copyExecutableFixture(t, current, unsafeExecutable)

	firstProvider := &campaignPaymentPreflightProvider{}
	failingProvider := &campaignPaymentPreflightProvider{}
	first := &campaignRuntime{
		definition: eightAgentManifestEntry{Name: "enrolled-before-failure"},
		provider:   firstProvider,
		payment:    campaignPaymentPreflightSink(safeExecutable, safeRoot),
	}
	failing := &campaignRuntime{
		definition: eightAgentManifestEntry{Name: "untrusted-payment-agent"},
		provider:   failingProvider,
		payment:    campaignPaymentPreflightSink(unsafeExecutable, unsafePrivateChild),
	}
	runtimes := []*campaignRuntime{first, failing}
	if err = preflightCampaignPaymentAdapters(false, runtimes); err != nil ||
		first.payment.executableSnapshot != nil || failing.payment.executableSnapshot != nil ||
		firstProvider.closes != 0 || failingProvider.closes != 0 {
		t.Fatalf("legacy/Round 4 behavior changed: err=%v first_snapshot=%v failing_snapshot=%v closes=%d/%d",
			err, first.payment.executableSnapshot, failing.payment.executableSnapshot,
			firstProvider.closes, failingProvider.closes)
	}
	err = preflightCampaignPaymentAdapters(true, runtimes)
	if err == nil || !strings.Contains(err.Error(), "executable is untrusted") {
		t.Fatalf("Round 5 trusted unsafe executable ancestry: %v", err)
	}
	if firstProvider.calls != 0 || failingProvider.calls != 0 ||
		firstProvider.closes != 1 || failingProvider.closes != 1 ||
		first.payment.executableSnapshot != nil || failing.payment.executableSnapshot != nil {
		t.Fatalf("failed preflight did not precede Provider calls and clean partial enrollment: calls=%d/%d closes=%d/%d snapshots=%v/%v",
			firstProvider.calls, failingProvider.calls, firstProvider.closes, failingProvider.closes,
			first.payment.executableSnapshot, failing.payment.executableSnapshot)
	}
}

func campaignPaymentPreflightSink(executable, directory string) *TOSCTLPaymentSink {
	domain := agentrelay.NetworkDomain{
		NetworkID:         "tos:local-three-node",
		GlobalID:          76_543_219,
		ZeroStateRootHash: campaignDigest("round5-payment-preflight-root"),
		ZeroStateFileHash: campaignDigest("round5-payment-preflight-file"),
		WorkchainID:       0,
	}
	return &TOSCTLPaymentSink{
		Authority:          &PersonalAuthority{},
		Executable:         executable,
		ConfigPath:         filepath.Join(directory, "primary.json"),
		Wallet:             "round5-payment-wallet",
		SourceAccount:      "0:" + strings.Repeat("12", 32),
		NetworkGlobalID:    domain.GlobalID,
		RelayNetworkDomain: &domain,
		FeeReserveNanoTOS:  50_000_000,
		QuorumConfigPaths: []string{
			filepath.Join(directory, "quorum-2.json"),
			filepath.Join(directory, "quorum-3.json"),
		},
		MaximumTransactions: 1000,
		VaultURL:            "file:///owner/round5-test-vault",
		EvidenceDirectory:   filepath.Join(directory, "payment-evidence"),
	}
}

func copyExecutableFixture(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestTOSCTLDiagnosticRedactsVaultMaterial(t *testing.T) {
	const key = "0000000000000000000000000000000000000000000000000000000000000010"
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "query parameter",
			value: "failed to open file:///v.json?master_key=" + key + " for reading",
			want:  "failed to open file:///v.json?master_key=[redacted] for reading",
		},
		{
			name:  "followed by another parameter",
			value: "url=file:///v.json?master_key=" + key + "&mode=ro",
			want:  "url=file:///v.json?master_key=[redacted]&mode=ro",
		},
		{
			name:  "two occurrences",
			value: "a master_key=" + key + " b master_key=" + key,
			want:  "a master_key=[redacted] b master_key=[redacted]",
		},
		{
			name:  "empty value is left alone",
			value: "master_key= missing",
			want:  "master_key= missing",
		},
		{
			name:  "unrelated output is unchanged",
			value: "Error: command failed: Task record 'x' not found",
			want:  "Error: command failed: Task record 'x' not found",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := redactTOSCTLDiagnostic(testCase.value)
			if got != testCase.want {
				t.Fatalf("redactTOSCTLDiagnostic(%q) = %q, want %q", testCase.value, got, testCase.want)
			}
			if strings.Contains(got, key) {
				t.Fatalf("redactTOSCTLDiagnostic leaked the master key: %q", got)
			}
		})
	}
}
