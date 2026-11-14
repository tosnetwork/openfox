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
	// One pause line per round, and never a failed-handling report.
	if len(reports) != 2*maxHandlingAttempts {
		t.Fatalf("%d reports over %d rounds: %v", len(reports), 2*maxHandlingAttempts, reports)
	}
	for _, stage := range reports {
		if stage != "admission paused" {
			t.Fatalf("a held task was reported as %q", stage)
		}
	}
}

// putTask stores a complete task message whose frames name requestHash, so
// each call makes a distinct assembly from the same buyer.
func putTask(t *testing.T, inbox *Inbox, requestHash [32]byte) error {
	t.Helper()
	message, _ := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	frames, err := SplitMessage(FrameTask, testActor, 0, requestHash, message.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if _, _, err := inbox.Put(testBuyer, frame); err != nil {
			return err
		}
	}
	return nil
}

func TestHeldTasksCannotKeepOutAcknowledgementsOfAdmittedWork(t *testing.T) {
	state := privateStateDir(t)
	const bound = 4
	inbox, _ := openTestInbox(t, bound, bound)
	for index := range bound {
		if err := putTask(t, inbox, [32]byte{byte(index + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := putTask(t, inbox, [32]byte{0xf0}); err == nil {
		t.Fatal("the fixture did not fill the inbox")
	}
	if _, _, err := PauseAdmission(state, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	var reported []error
	service := &Service{
		Inbox:    inbox,
		Provider: &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork, StateDir: state}},
		Report:   func(_ string, err error) { reported = append(reported, err) },
	}
	if err := service.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The buyer of admitted work acknowledges its result while the inbox
	// holds a full bound of paused tasks.
	body, err := EncodeAck([32]byte{0x42})
	if err != nil {
		t.Fatal(err)
	}
	frames, err := SplitMessage(FrameResultAck, testActor, 3, testRequest, body)
	if err != nil {
		t.Fatal(err)
	}
	ackSender := "agent_" + strings.Repeat("c3", 32)
	for _, frame := range frames {
		if _, _, putErr := inbox.Put(ackSender, frame); putErr != nil {
			t.Fatalf("held tasks kept out an acknowledgement of admitted work: %v", putErr)
		}
	}
	// Held tasks have a bound of their own: one more is retired, not held.
	if putErr := putTask(t, inbox, [32]byte{0xf1}); putErr != nil {
		t.Fatal(putErr)
	}
	reported = nil
	if dispatchErr := service.Dispatch(context.Background()); dispatchErr != nil {
		t.Fatal(dispatchErr)
	}
	pending, err := inbox.Pending()
	if err != nil {
		t.Fatal(err)
	}
	tasks := 0
	for _, message := range pending {
		if message.Kind == FrameTask {
			tasks++
		}
	}
	if tasks != bound {
		t.Fatalf("%d tasks held, want the hold bound %d", tasks, bound)
	}
	if len(reported) == 0 || !strings.Contains(reported[len(reported)-1].Error(), "1 retired") {
		t.Fatalf("the retired task was not reported: %v", reported)
	}
}

func TestServeReportsAnUnreadablePauseMarker(t *testing.T) {
	state := privateStateDir(t)
	inbox, _ := openTestInbox(t, 2, 4)
	if err := putTask(t, inbox, testRequest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, AdmissionPauseFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var reported []error
	service := &Service{
		Inbox:    inbox,
		Provider: &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork, StateDir: state}},
		Report:   func(_ string, err error) { reported = append(reported, err) },
	}
	if err := service.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "pause marker is invalid") {
		t.Fatalf("an unreadable pause marker was not reported: %v", reported)
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
