package servicebridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privateStateDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestPauseAndResumeAreDurableOwnerOnlyAndIdempotent(t *testing.T) {
	state := privateStateDir(t)
	if pause, err := ReadAdmissionPause(state); err != nil || pause != nil {
		t.Fatalf("a fresh node reads as paused: %v %v", pause, err)
	}
	first := time.Unix(1_800_000_000, 0)
	pause, already, err := PauseAdmission(state, "maintenance", first)
	if err != nil || already || pause.PausedUnix != first.Unix() {
		t.Fatalf("pause: %+v %v %v", pause, already, err)
	}
	info, err := os.Lstat(filepath.Join(state, AdmissionPauseFile))
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("the marker is not an owner-only regular file: %v %v", info, err)
	}
	again, already, err := PauseAdmission(state, "other", first.Add(time.Hour))
	if err != nil || !already || again.PausedUnix != first.Unix() || again.Reason != "maintenance" {
		t.Fatalf("a second pause replaced the first: %+v %v %v", again, already, err)
	}
	if _, _, lineErr := PauseAdmission(state, "two\nlines", first); lineErr == nil {
		t.Fatal("a multi-line reason was accepted")
	}
	if _, _, sizeErr := PauseAdmission(state, strings.Repeat("x", maxPauseReason+1), first); sizeErr == nil {
		t.Fatal("an oversized reason was accepted")
	}
	was, err := ResumeAdmission(state)
	if err != nil || !was {
		t.Fatalf("resume: %v %v", was, err)
	}
	if pause, err := ReadAdmissionPause(state); err != nil || pause != nil {
		t.Fatalf("still paused after resume: %v %v", pause, err)
	}
	if was, err := ResumeAdmission(state); err != nil || was {
		t.Fatalf("resuming an open node: %v %v", was, err)
	}
}

func TestAnUnreadablePauseMarkerHoldsAdmission(t *testing.T) {
	state := privateStateDir(t)
	if _, _, err := PauseAdmission(state, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(state, AdmissionPauseFile), 0o644); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{config: ProviderConfig{StateDir: state}}
	if err := provider.admissionOpen(); !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("an unreadable marker opened admission: %v", err)
	}
	if err := os.WriteFile(filepath.Join(state, AdmissionPauseFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.admissionOpen(); !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("an invalid marker opened admission: %v", err)
	}
}

func TestAPausedProviderRefusesAdmissionBeforeTheGate(t *testing.T) {
	state := privateStateDir(t)
	// No gate is configured: if the pause did not stop the task first, the
	// admission would fail with the gate's own error instead.
	provider := &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork, StateDir: state}}
	message, _ := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	if _, _, err := PauseAdmission(state, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := provider.HandleTask(context.Background(), message); !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("a paused provider went on to admit: %v", err)
	}
	if _, err := ResumeAdmission(state); err != nil {
		t.Fatal(err)
	}
	if err := provider.HandleTask(context.Background(), message); err == nil ||
		errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("a resumed provider did not reach admission: %v", err)
	}
}

func TestDispatchHoldsATaskWhilePausedWithoutSpendingItsAttempts(t *testing.T) {
	state := privateStateDir(t)
	inbox, _ := openTestInbox(t, 2, 4)
	message, _ := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	frames, err := SplitMessage(FrameTask, testActor, 0, testRequest, message.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if _, _, err = inbox.Put(testBuyer, frame); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := PauseAdmission(state, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	var reports []string
	service := &Service{
		Inbox:    inbox,
		Provider: &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork, StateDir: state}},
		Report:   func(stage string, _ error) { reports = append(reports, stage) },
	}
	for round := 0; round < 2*maxHandlingAttempts; round++ {
		if err := service.Dispatch(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if pending, err := inbox.Pending(); err != nil || len(pending) != 1 {
		t.Fatalf("a held task was retired while paused: %d %v", len(pending), err)
	}
	if len(reports) != 0 {
		t.Fatalf("a held task was counted as failed: %v", reports)
	}
}

func TestPauseDoesNotStopAdmittedWorkFromResponding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	provider, checker, lifecycle, path := executedProvider(t, now, uint64(now.Unix())+600)
	state := privateStateDir(t)
	provider.config.StateDir = state
	if _, _, err := PauseAdmission(state, "", now); err != nil {
		t.Fatal(err)
	}
	checker.err = nil
	if err := provider.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := providerState(t, path); state != ProviderResponding || lifecycle.responds != 1 {
		t.Fatalf("paused admission stopped admitted work: state %s, %d responds", state, lifecycle.responds)
	}
}
