package messageutil

import (
	"errors"
	"reflect"
	"regexp"
	"strings"

	"github.com/tosnetwork/openfox/pkg/providers/protocoltypes"
)

// SameAuthenticatedInbound compares the durable semantic fields of two
// inbound records. Storage-assigned timestamps and prompt-only annotations do
// not participate in the Event-ID substitution check.
func SameAuthenticatedInbound(a, b protocoltypes.Message) bool {
	a.CreatedAt, b.CreatedAt = nil, nil
	a.PromptLayer, b.PromptLayer = "", ""
	a.PromptSlot, b.PromptSlot = "", ""
	a.PromptSource, b.PromptSource = "", ""
	return reflect.DeepEqual(a, b)
}

const HiddenRoomMessage = "[message hidden by room moderation]"

var messengerEventIDPattern = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)

// ValidateAuthenticatedInbound checks the runtime-owned binding required
// before a session store may acknowledge a production Messenger Event.
func ValidateAuthenticatedInbound(msg protocoltypes.Message, eventID string) error {
	if !messengerEventIDPattern.MatchString(eventID) || msg.Role != "user" ||
		msg.SourceEventID != eventID || msg.ActionProvenanceState != "authenticated-messaging" ||
		len(msg.ActionOrigins) != 1 || msg.ActionOrigins[0].EventID != eventID ||
		strings.TrimSpace(msg.Content) == "" && len(msg.Media) == 0 {
		return errors.New("invalid authenticated inbound message")
	}
	return nil
}

// ProjectRoomModeration returns a presentation-safe copy. The original bytes
// remain in runtime-only state so a later authorized restore can recover them.
// A hide for a target absent from local history creates a tombstone, preventing
// a later/out-of-order copy from becoming model-visible.
func ProjectRoomModeration(
	history []protocoltypes.Message,
	decisions map[string]protocoltypes.RoomModerationDecision,
) []protocoltypes.Message {
	projected := append([]protocoltypes.Message(nil), history...)
	seen := make(map[string]bool, len(decisions))
	out := make([]protocoltypes.Message, 0, len(projected)+len(decisions))
	for _, msg := range projected {
		sourceEventID := msg.SourceEventID
		if sourceEventID == "" && msg.Role == "user" && len(msg.ActionOrigins) == 1 {
			// Backfill histories written by the authenticated adapter before the
			// dedicated source fields were introduced.
			sourceEventID = msg.ActionOrigins[0].EventID
		}
		decision, moderated := decisions[sourceEventID]
		if !moderated {
			out = append(out, msg)
			continue
		}
		msg.SourceEventID = sourceEventID
		if msg.SourceRoomID == "" {
			msg.SourceRoomID = decision.RoomID
		}
		seen[decision.TargetEventID] = true
		msg.RoomModerationAction = decision.Action
		msg.RoomModerationRevision = decision.DecisionRevision
		msg.RoomModerationDecisionID = decision.DecisionEventID
		if decision.Action == "hide" {
			msg.Content = HiddenRoomMessage
		} else if msg.ModerationSynthetic {
			continue
		}
		out = append(out, msg)
	}
	for target, decision := range decisions {
		if seen[target] || decision.Action != "hide" {
			continue
		}
		out = append(out, protocoltypes.Message{
			Role: "user", Content: HiddenRoomMessage, SourceEventID: target,
			SourceRoomID: decision.RoomID, RoomModerationAction: "hide",
			RoomModerationRevision:   decision.DecisionRevision,
			RoomModerationDecisionID: decision.DecisionEventID, ModerationSynthetic: true,
		})
	}
	return out
}

// PreserveModeratedOriginals replaces projected tombstones with the matching
// raw stored content before a history rewrite. Targets intentionally omitted
// by compaction stay omitted.
func PreserveModeratedOriginals(next, stored []protocoltypes.Message) []protocoltypes.Message {
	originals := make(map[string]string)
	for _, msg := range stored {
		source := msg.SourceEventID
		if source == "" && msg.Role == "user" && len(msg.ActionOrigins) == 1 {
			source = msg.ActionOrigins[0].EventID
		}
		if source != "" && msg.Content != HiddenRoomMessage {
			originals[source] = msg.Content
		}
	}
	merged := append([]protocoltypes.Message(nil), next...)
	for i := range merged {
		if merged[i].RoomModerationAction == "hide" && merged[i].Content == HiddenRoomMessage {
			if original, ok := originals[merged[i].SourceEventID]; ok {
				merged[i].Content = original
			}
		}
	}
	return merged
}

// AdvanceRoomModeration enforces exact replay and gap-free per-target revisions.
func AdvanceRoomModeration(
	current map[string]protocoltypes.RoomModerationDecision,
	next protocoltypes.RoomModerationDecision,
) (bool, error) {
	if next.RoomID == "" || next.TargetEventID == "" || next.DecisionEventID == "" ||
		next.DecisionRevision == 0 || next.Action != "hide" && next.Action != "restore" {
		return false, errors.New("invalid room moderation decision")
	}
	prior, exists := current[next.TargetEventID]
	if exists && prior == next {
		return false, nil
	}
	if exists && (prior.RoomID != next.RoomID || next.DecisionRevision != prior.DecisionRevision+1) {
		return false, errors.New("room moderation revision is not the next decision")
	}
	if !exists && next.DecisionRevision != 1 {
		return false, errors.New("first room moderation revision must be 1")
	}
	current[next.TargetEventID] = next
	return true, nil
}

// IsTransientAssistantThoughtMessage reports whether msg is an invalid
// reasoning-only assistant history record. These "hanging" thought messages
// are not a canonical persisted format and should be discarded instead of
// replayed or reconstructed.
func IsTransientAssistantThoughtMessage(msg protocoltypes.Message) bool {
	return msg.Role == "assistant" &&
		strings.TrimSpace(msg.Content) == "" &&
		strings.TrimSpace(msg.ReasoningContent) != "" &&
		len(msg.ToolCalls) == 0 &&
		len(msg.Media) == 0 &&
		len(msg.Attachments) == 0 &&
		strings.TrimSpace(msg.ToolCallID) == ""
}

// FilterInvalidHistoryMessages removes invalid persisted history records such
// as transient assistant thought-only messages.
func FilterInvalidHistoryMessages(history []protocoltypes.Message) []protocoltypes.Message {
	if len(history) == 0 {
		return []protocoltypes.Message{}
	}

	filtered := make([]protocoltypes.Message, 0, len(history))
	for _, msg := range history {
		if IsTransientAssistantThoughtMessage(msg) {
			continue
		}
		filtered = append(filtered, msg)
	}
	return filtered
}
