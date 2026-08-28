package earning

import (
	"strings"
	"testing"
)

func TestContextualAgentSystemPromptReadsCurrentOwnerContext(t *testing.T) {
	current := "# USER.md\n\nDo not accept work below 2 TOS."
	source := func() string { return current }

	first, err := contextualAgentSystemPrompt(source, "Assess one untrusted Intent.")
	if err != nil || !strings.Contains(first, "below 2 TOS") || !strings.Contains(first, "Assess one untrusted Intent") {
		t.Fatalf("first contextual prompt = %q, err=%v", first, err)
	}
	current = "# USER.md\n\nDo not accept work below 5 TOS."
	second, err := contextualAgentSystemPrompt(source, "Assess one untrusted Intent.")
	if err != nil || !strings.Contains(second, "below 5 TOS") || strings.Contains(second, "below 2 TOS") {
		t.Fatalf("hot-reloaded contextual prompt = %q, err=%v", second, err)
	}
}

func TestContextualAgentSystemPromptRejectsInvalidConfiguredContext(t *testing.T) {
	if _, err := contextualAgentSystemPrompt(func() string { return "" }, "bounded role"); err == nil {
		t.Fatal("empty configured context was accepted")
	}
	if _, err := contextualAgentSystemPrompt(func() string { return string([]byte{0xff}) }, "bounded role"); err == nil {
		t.Fatal("invalid UTF-8 configured context was accepted")
	}
}
