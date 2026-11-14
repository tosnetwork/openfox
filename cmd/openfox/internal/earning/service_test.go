package earning

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

func TestStatusStillReportsWhenTheFinalizedReaderCannotOpen(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "provider"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, _, _, err := servicebridge.BuildManifest(servicebridge.ManifestInput{
		ProviderAgentID: "agent_" + strings.Repeat("ab", 32), Actor: "0:" + strings.Repeat("77", 32),
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), Attestor: "mldsa44:" + strings.Repeat("99", 32),
		Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(root, "manifest.cbor")
	if writeErr := os.WriteFile(manifestFile, manifest, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	// No endpoints and no registry code: the reader cannot be opened.
	raw, err := json.Marshal(servicebridge.NodeConfig{
		StateDir: state, RegistryCodeBOC: filepath.Join(root, "absent.boc"),
		Provider: &servicebridge.ProviderNode{ManifestFile: manifestFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "rail.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	command := serviceCommand()
	var out bytes.Buffer
	command.SetOut(&out)
	command.SetArgs([]string{"status", "--rail-config", path})
	if err := command.Execute(); err != nil {
		t.Fatalf("status failed instead of reporting offline: %v", err)
	}
	var status servicebridge.ProviderStatus
	if err := json.Unmarshal(out.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Actor == nil || status.Actor.Read || !strings.Contains(status.Actor.Error, "open the finalized reader") {
		t.Fatalf("the reader failure is not in actor.error: %+v", status.Actor)
	}
}

func TestPreflightPrintsItsReportAndExitsNonZeroOnFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	command := serviceCommand()
	var out bytes.Buffer
	command.SetOut(&out)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"preflight", "--config", missing})
	err := command.Execute()
	if !errors.Is(err, errPreflightFailed) {
		t.Fatalf("a failed preflight returned %v", err)
	}
	var report servicebridge.PreflightReport
	if decodeErr := json.Unmarshal(out.Bytes(), &report); decodeErr != nil {
		t.Fatalf("the report is not JSON: %v: %s", decodeErr, out.String())
	}
	if report.OK || report.Schema != servicebridge.PreflightSchema || len(report.Checks) == 0 ||
		report.Checks[0].Status != servicebridge.CheckFail {
		t.Fatalf("report: %+v", report)
	}
}

func TestPauseAndResumeCommandsDriveTheAdmissionMarker(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(servicebridge.NodeConfig{StateDir: state, Provider: &servicebridge.ProviderNode{}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "rail.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	execute := func(args ...string) map[string]any {
		command := serviceCommand()
		var out bytes.Buffer
		command.SetOut(&out)
		command.SetArgs(args)
		if err := command.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var answer map[string]any
		if err := json.Unmarshal(out.Bytes(), &answer); err != nil {
			t.Fatal(err)
		}
		return answer
	}
	if answer := execute("pause", "--rail-config", path, "--reason", "drain"); answer["paused"] != true ||
		answer["already_paused"] != false {
		t.Fatalf("pause: %v", answer)
	}
	if pause, err := servicebridge.ReadAdmissionPause(state); err != nil || pause == nil || pause.Reason != "drain" {
		t.Fatalf("the marker was not written: %+v %v", pause, err)
	}
	if answer := execute("resume", "--rail-config", path); answer["was_paused"] != true {
		t.Fatalf("resume: %v", answer)
	}
	if pause, err := servicebridge.ReadAdmissionPause(state); err != nil || pause != nil {
		t.Fatalf("the marker survived resume: %+v %v", pause, err)
	}
}
