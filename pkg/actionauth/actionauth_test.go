package actionauth

import (
	"context"
	"strings"
	"testing"
)

func TestToolInvocationKeyIsStableAndCommitsArguments(t *testing.T) {
	first, err := ToolInvocationKey("agent", "session", "message", "call-1", "scan", map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ToolInvocationKey("agent", "session", "message", "call-1", "scan", map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ToolInvocationKey("agent", "session", "message", "call-1", "scan", map[string]any{"a": 2, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if first != retry || first == other || len(first) != len("idem_")+64 {
		t.Fatalf("keys first=%q retry=%q other=%q", first, retry, other)
	}
}

func TestInvocationContextCopiesProvenance(t *testing.T) {
	origins := []Origin{{EventID: "evt"}}
	ctx := WithInvocation(context.Background(), Invocation{IdempotencyKey: "idem", DerivedFrom: origins})
	origins[0].EventID = "changed"
	got, ok := InvocationFrom(ctx)
	if !ok || got.DerivedFrom[0].EventID != "evt" {
		t.Fatalf("invocation = %+v, %v", got, ok)
	}
}

func TestPhysicalOperationRequiresReviewableCanonicalArguments(t *testing.T) {
	valid := PhysicalOperation{
		CapabilityID: "cap_" + strings.Repeat("a", 64), Tool: "i2c", Operation: "read",
		ArgumentsDigest: "sha256:16384135fc236bb03583cf3024b9fb573cc1ae45f908a98d0601d2ab45f8cfbe",
		ArgumentsJSON:   `{"action":"read"}`,
	}
	if !valid.Valid() {
		t.Fatal("valid physical operation was refused")
	}
	cases := []PhysicalOperation{valid, valid, valid, valid}
	cases[0].ArgumentsDigest = "sha256:" + strings.Repeat("b", 64)
	cases[1].ArgumentsJSON = `{ "action": "read" }`
	cases[2].ArgumentsJSON = `{"action":"write"}`
	cases[3].ArgumentsJSON = strings.Repeat("x", MaxPhysicalArgumentsBytes+1)
	for _, candidate := range cases {
		if candidate.Valid() {
			t.Fatalf("accepted malformed physical operation: %+v", candidate)
		}
	}
}
