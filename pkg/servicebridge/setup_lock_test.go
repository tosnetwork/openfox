package servicebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// startHanging runs a command in a helper process that stops, alive, in the
// middle of the scripted step, and returns once it is there.
func (f *setupFixture) startHanging(t *testing.T, command string, input any) *exec.Cmd {
	t.Helper()
	return f.startHangingAt(t, command, input, "")
}

// startHangingAt stops the helper at a report line instead of a tosctl
// call, for a command that makes none.
func (f *setupFixture) startHangingAt(t *testing.T, command string, input any, report string) *exec.Cmd {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(f.root, "input.json"), raw, 0o600)
	_ = os.Remove(hangMarker(f.worldPath))
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperProcessForSetupCrashTests$")
	helper.Env = append(os.Environ(), crashHelperDir+"="+f.root, crashHelperCommand+"="+command,
		crashHelperHangOn+"="+report)
	var output bytes.Buffer
	helper.Stdout, helper.Stderr = &output, &output
	if err = helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, statErr := os.Stat(hangMarker(f.worldPath)); statErr == nil {
			return helper
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper never reached its step:\n%s", output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// kill ends the helper with SIGKILL and requires that it died of it.
func killHelper(t *testing.T, helper *exec.Cmd) {
	t.Helper()
	if err := helper.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	err := helper.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the helper was not killed: %v", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("the helper ended otherwise than by SIGKILL: %v", err)
	}
}

// stateOf is everything a refused run must leave untouched: the tosctl
// calls made, the journal bytes and the withdrawal records.
func (f *setupFixture) stateOf(t *testing.T) (calls int, journal string, records int) {
	t.Helper()
	raw, err := os.ReadFile(setupJournalPath(f.init.StateDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	listed, err := ReadWithdrawals(f.init.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return len(f.world().Calls), string(raw), len(listed)
}

// init, offer, withdraw and withdraw --acknowledge each read, decide and
// then send. Two at once in one state directory would both read "nothing
// sent" and both send, so a second run is refused at once, before it reads
// or sends anything, by a lock a killed run cannot leave behind.
func TestOneSetupOrWithdrawRunAtATimePerStateDirectory(t *testing.T) {
	ctx := context.Background()
	refused := func(t *testing.T, f *setupFixture, attempts map[string]func() error) {
		t.Helper()
		calls, journal, records := f.stateOf(t)
		for name, attempt := range attempts {
			err := attempt()
			if !errors.Is(err, ErrSetupBusy) {
				t.Errorf("%s beside a run in progress: %v", name, err)
			}
			nowCalls, nowJournal, nowRecords := f.stateOf(t)
			if nowCalls != calls || nowJournal != journal || nowRecords != records {
				t.Errorf("%s was refused but ran tosctl (%d calls, was %d), changed the journal (%v) or recorded a "+
					"withdrawal (%d, was %d)", name, nowCalls, calls, nowJournal != journal, nowRecords, records)
			}
		}
	}
	withdrawOne := func(f *setupFixture) WithdrawInput {
		return WithdrawInput{RailConfigPath: f.init.RailConfigPath, AmountNano: 1_000_000_000, Yes: true}
	}
	acknowledge := func(f *setupFixture) error {
		_, err := RunWithdrawAcknowledge(ctx, AcknowledgeInput{
			RailConfigPath: f.init.RailConfigPath, QueryID: 7, Note: "checked", Yes: true,
		}, f.env())
		return err
	}

	t.Run("init", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeHang)
		helper := f.startHanging(t, "init", f.init)
		refused(t, f, map[string]func() error{
			"a second init": func() error { _, err := RunInit(ctx, f.init, f.env()); return err },
		})
		if _, err := os.Stat(f.init.RailConfigPath); err == nil {
			t.Fatal("a refused init wrote a configuration")
		}
		killHelper(t, helper)
		// The killed run's lock is gone; what it left is its journal, which
		// says a message may be in flight.
		_, err := RunInit(ctx, f.init, f.env())
		if errors.Is(err, ErrSetupBusy) || !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("after the first run was killed: %v", err)
		}
		if f.world().count("agent native-registry register-agent") != 1 {
			t.Fatal("a second registration was built")
		}
	})
	t.Run("offer", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.script("agent service deploy", fakeHang)
		helper := f.startHanging(t, "offer", f.offer)
		refused(t, f, map[string]func() error{
			"a second offer": func() error { _, err := RunOffer(ctx, f.offer, f.env()); return err },
			"an init":        func() error { _, err := RunInit(ctx, f.init, f.env()); return err },
			"a withdraw":     func() error { _, err := RunWithdraw(ctx, withdrawOne(f), f.env()); return err },
			"an acknowledge": func() error { return acknowledge(f) },
		})
		killHelper(t, helper)
		_, err := RunOffer(ctx, f.offer, f.env())
		if errors.Is(err, ErrSetupBusy) || !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("after the first run was killed: %v", err)
		}
	})
	t.Run("withdraw", func(t *testing.T) {
		f, _ := newWithdrawFixture(t, 5_000_000_000)
		f.script(withdrawLabel, fakeHang)
		helper := f.startHanging(t, "withdraw", withdrawOne(f))
		refused(t, f, map[string]func() error{
			"a second withdraw": func() error { _, err := RunWithdraw(ctx, withdrawOne(f), f.env()); return err },
			"an acknowledge":    func() error { return acknowledge(f) },
			"an offer":          func() error { _, err := RunOffer(ctx, f.offer, f.env()); return err },
			"an init":           func() error { _, err := RunInit(ctx, f.init, f.env()); return err },
		})
		if f.world().count(withdrawLabel) != 1 {
			t.Fatal("a second withdrawal was sent")
		}
		killHelper(t, helper)
		_, err := RunWithdraw(ctx, withdrawOne(f), f.env())
		if errors.Is(err, ErrSetupBusy) || !errors.Is(err, ErrWithdrawalPending) {
			t.Fatalf("after the first run was killed: %v", err)
		}
	})
	t.Run("acknowledge", func(t *testing.T) {
		// A withdrawal finalized state cannot decide, past its window.
		f, _ := newWithdrawFixture(t, 5_000_000_000)
		f.script(withdrawLabel, fakeLost)
		if _, err := RunWithdraw(ctx, withdrawOne(f), f.env()); err == nil {
			t.Fatal("the scripted failure did not happen")
		}
		record := withdrawals(t, f)[0]
		f.change(func(w *fakeWorld) {
			w.History = append(w.History, f.withdrawTx(w, record.QueryID, fakeWalletAddress, "999999999"))
			w.Clock += int64(sendResolutionWindow.Seconds()) + 1
		})
		in := AcknowledgeInput{
			RailConfigPath: f.init.RailConfigPath, QueryID: record.QueryID, Note: "checked the wallet", Yes: true,
		}
		helper := f.startHangingAt(t, "acknowledge", in, "acknowledging closes this record")
		refused(t, f, map[string]func() error{
			"a withdraw": func() error { _, err := RunWithdraw(ctx, withdrawOne(f), f.env()); return err },
			"a second acknowledge": func() error {
				_, err := RunWithdrawAcknowledge(ctx, in, f.env())
				return err
			},
		})
		if now := withdrawals(t, f)[0]; now.terminal() {
			t.Fatalf("the record was closed by a refused run: %+v", now)
		}
		killHelper(t, helper)
		if _, err := RunWithdrawAcknowledge(ctx, in, f.env()); err != nil {
			t.Fatalf("after the first run was killed: %v", err)
		}
	})
	// A lock file that is not an owner-only regular file is not trusted.
	t.Run("the lock file", func(t *testing.T) {
		f := newSetupFixture(t)
		release, err := lockSetup(f.init.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = lockSetup(f.init.StateDir); !errors.Is(err, ErrSetupBusy) {
			t.Fatalf("the lock was taken twice: %v", err)
		}
		release()
		path := filepath.Join(f.init.StateDir, setupDirectory, setupLockFile)
		if err = os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err = lockSetup(f.init.StateDir); err == nil || errors.Is(err, ErrSetupBusy) {
			t.Fatalf("a lock file other users can read was accepted: %v", err)
		}
	})
}
