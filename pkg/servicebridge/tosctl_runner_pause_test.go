package servicebridge

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// slowCallSignalEnv names a file the sealed runner test creates just
// before its slow call, so a parent process can pause it there.
const slowCallSignalEnv = "OPENFOX_SLOW_CALL_SIGNAL"

func signalSlowCall(t *testing.T) {
	t.Helper()
	if path := os.Getenv(slowCallSignalEnv); path != "" {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// runnerPauseLength is longer than a wall-clock allowance a timing
// assertion would reasonably make for a one-second call (an upper bound of
// 10 seconds fails under it), as a thermal guard's SIGSTOP of the whole
// test process group can be.
const runnerPauseLength = 12 * time.Second

// A pause of the whole process group (the test and its tosctl stand-in)
// in the middle of the timed-out call must not fail the bounds test: the
// runner still cuts the call off at its timeout, and the test pins that
// without measuring the pause.
func TestTheSealedRunnerBoundsHoldWhenTheWholeProcessGroupIsPaused(t *testing.T) {
	signal := filepath.Join(t.TempDir(), "slow-call-started")
	command := exec.Command(os.Args[0], "-test.run=^TestTheSealedRunnerBoundsOutputAndTimeAndRedactsFailures$",
		"-test.count=1", "-test.v")
	command.Env = append(os.Environ(), slowCallSignalEnv+"="+signal)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	logPath := filepath.Join(t.TempDir(), "child.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	childOutput := func() string {
		data, _ := os.ReadFile(logPath)
		return string(data)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	group := command.Process.Pid
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := os.Stat(signal); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-group, syscall.SIGKILL)
			_ = command.Wait()
			t.Fatalf("the child never reached its slow call:\n%s", childOutput())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(-group, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(runnerPauseLength)
	if err := syscall.Kill(-group, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("a %s pause failed the bounds test: %v\n%s", runnerPauseLength, err, childOutput())
	}
	passed := []byte("--- PASS: TestTheSealedRunnerBoundsOutputAndTimeAndRedactsFailures")
	if !bytes.Contains([]byte(childOutput()), passed) {
		t.Fatalf("the bounds test did not run in the child:\n%s", childOutput())
	}
}
