package nativeimpl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// The purchase-phase vectors are the shared iOS/Android ground truth for
// crash-safe resume: they encode which transitions are legal, when the single
// funding lease may be taken, and — the at-most-once payment invariant — what a
// purchase recovered in each phase may safely do. This test proves they match
// the extracted servicebridge phase functions.

type phaseResumeCase struct {
	Phase           string `json:"phase"`
	CanAcquireLease bool   `json:"can_acquire_lease"`
	ResumeAction    string `json:"resume_action"`
}

type phaseTransitionCase struct {
	From       string `json:"from"`
	To         string `json:"to"`
	CanAdvance bool   `json:"can_advance"`
}

type phaseVectors struct {
	Schema      string                `json:"schema"`
	Resume      []phaseResumeCase     `json:"resume"`
	Transitions []phaseTransitionCase `json:"transitions"`
}

func TestMobilePurchasePhaseVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "mobile_buyer_purchase_phase_v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors phaseVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if vectors.Schema != "tos.service.mobile-buyer-purchase-phase.v1" ||
		len(vectors.Resume) == 0 || len(vectors.Transitions) == 0 {
		t.Fatalf("unexpected vector schema/shape: %q", vectors.Schema)
	}

	for _, c := range vectors.Resume {
		phase := servicebridge.Phase(c.Phase)
		if got := servicebridge.CanAcquireFundingLease(phase); got != c.CanAcquireLease {
			t.Fatalf("phase %s: CanAcquireFundingLease got %v, want %v", c.Phase, got, c.CanAcquireLease)
		}
		if got := string(servicebridge.ResumeActionFor(phase)); got != c.ResumeAction {
			t.Fatalf("phase %s: ResumeActionFor got %q, want %q", c.Phase, got, c.ResumeAction)
		}
	}

	for _, c := range vectors.Transitions {
		if got := servicebridge.CanAdvance(servicebridge.Phase(c.From), servicebridge.Phase(c.To)); got != c.CanAdvance {
			t.Fatalf("%s->%s: CanAdvance got %v, want %v", c.From, c.To, got, c.CanAdvance)
		}
	}
}
