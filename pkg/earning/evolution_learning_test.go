package earning

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/evolution"
)

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
