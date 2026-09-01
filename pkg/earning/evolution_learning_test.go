package earning

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/evolution"
)

type recordingLearningAcquisitionFence struct {
	mu       sync.Mutex
	requests []capabilitycontrol.CapabilityAcquisitionRequest
}

func (fence *recordingLearningAcquisitionFence) AdmitCapabilityAcquisition(
	_ context.Context, request capabilitycontrol.CapabilityAcquisitionRequest,
) error {
	fence.mu.Lock()
	defer fence.mu.Unlock()
	fence.requests = append(fence.requests, request)
	return nil
}

func TestEvolutionExecutionLearningRecorderRejectsIndirectWorkspace(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	indirect := filepath.Join(root, "indirect")
	if err := os.Symlink(workspace, indirect); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEvolutionExecutionLearningRecorder(config.EvolutionConfig{Enabled: true, Mode: "observe"},
		indirect, "agent:test", estimatorProvider{}, "test"); err == nil {
		t.Fatal("earning evolution accepted an indirect workspace")
	}
}

func TestEvolutionExecutionLearningRecorderUsesAcquisitionFenceAndQuarantinesDraft(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	fence := &recordingLearningAcquisitionFence{}
	recorder, err := NewEvolutionExecutionLearningRecorderWithAcquisition(config.EvolutionConfig{
		Enabled: true, Mode: "apply", MinTaskCount: 1,
	}, workspace, "owner:test", "agent:test", nil, "", fence, "bounded-review")
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordExecution(context.Background(), ExecutionLearningEvent{
		ExecutionID: "sha256:execution", AgreementBodyDigest: "sha256:agreement", AgentID: "agent:test",
		ObligationID: "public-reusable-learning", Task: "Review a bounded contract change",
		ReusableProcedureSummary: "Check the stated scope, cite concrete findings, and label evidence gaps.",
	}); err != nil {
		t.Fatal(err)
	}

	fence.mu.Lock()
	requests := append([]capabilitycontrol.CapabilityAcquisitionRequest(nil), fence.requests...)
	fence.mu.Unlock()
	if len(requests) != 2 || requests[0].Phase != "reserve" || requests[1].Phase != "commit" {
		t.Fatalf("acquisition phases = %v, want reserve then commit", requests)
	}
	for _, request := range requests {
		if request.SchemaVersion != 1 || string(request.OwnerID) != "owner:test" ||
			string(request.AgentID) != "agent:test" {
			t.Fatalf("acquisition request escaped owner/agent scope: %+v", request)
		}
	}
	if matches, err := filepath.Glob(filepath.Join(workspace, "state", "trusted-capabilities", "quarantine",
		"*", "reusable-earning-capability-bounded-review", "SKILL.md")); err != nil || len(matches) != 1 {
		t.Fatalf("quarantined drafts = %v, err = %v", matches, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "skills", "reusable-earning-capability-bounded-review",
		"SKILL.md")); !os.IsNotExist(err) {
		t.Fatal("model-authored earning skill became loader-visible")
	}
}

func TestEvolutionExecutionLearningRecorderWithAcquisitionFailsClosedWithoutFence(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEvolutionExecutionLearningRecorderWithAcquisition(config.EvolutionConfig{
		Enabled: true, Mode: "apply",
	}, workspace, "owner:test", "agent:test", nil, "", nil); err == nil {
		t.Fatal("apply-mode earning evolution accepted a missing acquisition fence")
	}
}

func TestEvolutionExecutionLearningRecorderLegacyConstructorRejectsApplyMode(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEvolutionExecutionLearningRecorder(config.EvolutionConfig{
		Enabled: true, Mode: "apply",
	}, workspace, "agent:test", nil, ""); err == nil {
		t.Fatal("legacy earning evolution constructor accepted apply mode without an acquisition fence")
	}
}

func TestCapabilityLearningClustererGroupsDistinctTasksUnderOwnerCapability(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	delegate := evolution.NewLLMPatternClusterer(nil, "", evolution.NewHeuristicPatternClusterer(2,
		func() time.Time { return now }), 2, func() time.Time { return now })
	clusterer := capabilityLearningClusterer{capability: "data-normalization", delegate: delegate}
	tasks := []evolution.LearningRecord{
		{ID: "task-1", Kind: evolution.RecordKindTask, WorkspaceID: "workspace", Summary: "Normalize catalog fields"},
		{ID: "task-2", Kind: evolution.RecordKindTask, WorkspaceID: "workspace", Summary: "Deduplicate revision lineage"},
	}
	patterns, ids, err := clusterer.BuildPatterns(context.Background(), "workspace", tasks, nil)
	if err != nil || len(patterns) != 1 || len(ids) != 2 {
		t.Fatalf("patterns=%d ids=%v err=%v", len(patterns), ids, err)
	}
}
