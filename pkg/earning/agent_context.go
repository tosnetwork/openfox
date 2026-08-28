package earning

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const maximumAgentContextBytes = 512 << 10

// AgentContextSource returns the current owner-controlled OpenFox system
// context. Callers use a function instead of a captured string so edits to
// AGENT.md, SOUL.md, USER.md, memory, and workspace skills are visible on the
// next autonomous decision without restarting the earning worker.
type AgentContextSource func() string

func contextualAgentSystemPrompt(source AgentContextSource, boundedRole string) (string, error) {
	boundedRole = strings.TrimSpace(boundedRole)
	if boundedRole == "" {
		return "", errors.New("bounded Agent role prompt is empty")
	}
	if source == nil {
		return boundedRole, nil
	}
	context := strings.TrimSpace(source())
	if context == "" {
		return "", errors.New("configured Agent context is empty")
	}
	if len(context) > maximumAgentContextBytes || !utf8.ValidString(context) || strings.IndexByte(context, 0) >= 0 {
		return "", errors.New("configured Agent context is invalid or oversized")
	}
	return context + "\n\n# Current bounded autonomous role\n\n" + boundedRole, nil
}
