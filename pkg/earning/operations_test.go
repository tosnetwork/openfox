package earning

import (
	"os"
	"testing"
)

func TestOperationalControllerPersistsPauseDrainAndAudit(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	controller, err := OpenOperationalController(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !controller.Permits("contact", true) {
		t.Fatal("fresh controller unexpectedly blocks contact")
	}
	record, err := controller.SetMode("local-owner", "*", OperationalDraining, "planned maintenance")
	if err != nil || record.Sequence != 1 || controller.Permits("contact", true) || !controller.Permits("payment", false) {
		t.Fatalf("drain mismatch: %+v %v", record, err)
	}
	if _, err := controller.SetMode("local-owner", "payment", OperationalPaused, "custody incident"); err != nil {
		t.Fatal(err)
	}
	if controller.Permits("payment", false) {
		t.Fatal("scope pause did not override global drain")
	}
	reopened, err := OpenOperationalController(directory)
	if err != nil {
		t.Fatal(err)
	}
	revision, states, audit := reopened.Snapshot()
	if revision != 3 || len(states) != 2 || len(audit) != 2 || audit[1].Sequence != 2 {
		t.Fatalf("unexpected persisted operations state: revision=%d states=%+v audit=%+v", revision, states, audit)
	}
	if _, err := reopened.SetMode("local-owner", "*", OperationalRunning, "maintenance complete"); err != nil {
		t.Fatal(err)
	}
	if !reopened.Permits("contact", true) || reopened.Permits("payment", false) {
		t.Fatal("global resume should preserve the explicit payment pause")
	}
}

func TestOperationalControllerRejectsUnsafeStorage(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOperationalController(directory); err == nil {
		t.Fatal("world-readable operations directory accepted")
	}
}
