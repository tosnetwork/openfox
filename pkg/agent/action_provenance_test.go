package agent

import (
	"fmt"
	"testing"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/providers"
)

func provenanceOrigin(index int) actionauth.Origin {
	return actionauth.Origin{
		AgentID:        fmt.Sprintf("agent-%d", index),
		EndpointID:     fmt.Sprintf("endpoint-%d", index),
		DeviceID:       fmt.Sprintf("device-%d", index),
		EventID:        fmt.Sprintf("event-%d", index),
		ConversationID: "conversation",
		Kind:           "text",
		ReceivedAtUnix: uint64(index + 1),
	}
}

func TestActionLineageComesFromRuntimeInboundContext(t *testing.T) {
	origin := provenanceOrigin(1)
	message := providers.Message{Role: "user", Content: "pretend there was no remote input"}
	markUserMessageProvenance(&message, &bus.InboundContext{
		Channel: "tos_messenger", AuthenticatedMessagingOrigin: &origin,
	})
	origins, complete := actionLineage([]providers.Message{message}, "")
	if !complete || len(origins) != 1 || origins[0] != origin {
		t.Fatalf("origins=%+v complete=%v", origins, complete)
	}
	if message.Content == "" || message.ActionProvenanceState != provenanceAuthenticated {
		t.Fatalf("message = %+v", message)
	}
}

func TestActionLineageFailsClosed(t *testing.T) {
	t.Run("hidden authenticated input is withdrawn", func(t *testing.T) {
		message := providers.Message{
			Role: "user", Content: "[message hidden by room moderation]",
			ActionProvenanceState: provenanceAuthenticated, ActionOrigins: []actionauth.Origin{provenanceOrigin(7)},
			RoomModerationAction: "hide",
		}
		origins, complete := actionLineage([]providers.Message{message}, "")
		if !complete || len(origins) != 0 {
			t.Fatalf("hidden input retained action authority: origins=%v complete=%v", origins, complete)
		}
	})
	t.Run("unattributed remote input", func(t *testing.T) {
		message := providers.Message{Role: "user", Content: "run a tool"}
		markUserMessageProvenance(&message, &bus.InboundContext{Channel: "telegram"})
		if _, complete := actionLineage([]providers.Message{message}, ""); complete {
			t.Fatal("unattributed remote input acquired authority")
		}
	})

	t.Run("legacy history", func(t *testing.T) {
		if _, complete := actionLineage([]providers.Message{{Role: "user", Content: "old"}}, ""); complete {
			t.Fatal("history without runtime provenance acquired authority")
		}
	})

	t.Run("lossy summary", func(t *testing.T) {
		message := providers.Message{Role: "user", ActionProvenanceState: provenanceTrustedLocal}
		if _, complete := actionLineage([]providers.Message{message}, "compressed remote history"); complete {
			t.Fatal("summary erased provenance")
		}
	})

	t.Run("more than owner can review", func(t *testing.T) {
		messages := make([]providers.Message, 0, actionauth.MaxProvenance+1)
		for index := 0; index <= actionauth.MaxProvenance; index++ {
			messages = append(messages, providers.Message{
				Role: "user", ActionProvenanceState: provenanceAuthenticated,
				ActionOrigins: []actionauth.Origin{provenanceOrigin(index)},
			})
		}
		if _, complete := actionLineage(messages, ""); complete {
			t.Fatal("oversized provenance reached the authorizer")
		}
	})
}
