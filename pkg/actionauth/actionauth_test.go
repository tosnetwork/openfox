package actionauth

import (
	"context"
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
