package evolution

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
)

type allowEvolutionAcquisitionFence struct{}

func (allowEvolutionAcquisitionFence) AdmitCapabilityAcquisition(context.Context, capabilitycontrol.CapabilityAcquisitionRequest) error {
	return nil
}

func TestTrustedApplierQuarantinesInsteadOfActivating(t *testing.T) {
	workspace := t.TempDir()
	applier := NewTrustedApplierWithAcquisition(NewPaths(workspace, ""), nil, allowEvolutionAcquisitionFence{}, []byte("owner"), []byte("agent"))
	draft := SkillDraft{ID: "draft-1", TargetSkillName: "bounded-review", ChangeKind: ChangeKindCreate,
		BodyOrPatch: "---\nname: bounded-review\ndescription: bounded\n---\n# bounded-review\nOnly bounded work."}
	rollback, err := applier.applyDraftWithRollback(context.Background(), workspace, draft)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback()
	if _, err := os.Stat(filepath.Join(workspace, "skills", "bounded-review", "SKILL.md")); !os.IsNotExist(err) {
		t.Fatal("draft became loader-visible")
	}
	root := filepath.Join(workspace, "state", "trusted-capabilities", "quarantine")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) == 64 {
			if _, err := os.Stat(filepath.Join(root, entry.Name(), draft.TargetSkillName, "SKILL.md")); err == nil {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("draft was not retained in the common content-addressed quarantine")
	}
}
