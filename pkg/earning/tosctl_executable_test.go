//go:build linux

package earning

import (
	"bytes"
	"context"
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
)

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
	normal, err := sink.run(t.Context(), []string{"-test.run=^TestTOSCTLExecutableHelper$", "--", "normal"})
	if err != nil || string(normal) != `{"state":"safe"}` {
		t.Fatalf("run sealed tosctl fixture: output=%q err=%v", normal, err)
	}
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

	// The descriptor opened before replacement is a sealed byte snapshot, so
	// even an immediate pathname swap cannot redirect the already-authorized
	// launch to the attacker script.
	command := exec.Command("/proc/self/fd/3", "-test.run=^TestTOSCTLExecutableHelper$", "--", "normal")
	command.ExtraFiles = []*os.File{opened}
	command.Env = []string{}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil || output.String() != `{"state":"safe"}` {
		t.Fatalf("opened launch image followed its replaced path: output=%q err=%v", output.String(), err)
	}
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
