package agent

import (
	"strings"
	"testing"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/providers"
)

func TestRoomModerationIsDurableAndCancelsActiveRoomTurn(t *testing.T) {
	al, messageBus, provider, cfg, cleanup := newTestAgentLoop(t)
	_ = messageBus
	_ = provider
	_ = cfg
	defer cleanup()
	roomID := "room_" + strings.Repeat("1", 64)
	target := "evt_" + strings.Repeat("2", 64)
	decisionID := "evt_" + strings.Repeat("3", 64)
	msg := bus.InboundMessage{Context: bus.InboundContext{
		Channel: "tos_messenger", ChatID: roomID, ChatType: "group", SpaceID: roomID, SpaceType: "room",
		SenderID: "tos_messenger:moderator", MessageID: decisionID,
		AuthenticatedMessagingOrigin: &actionauth.Origin{EventID: decisionID, Kind: "room.moderation"},
	}, RoomModeration: &bus.RoomModerationControl{
		RoomID: roomID, TargetEventID: target,
		DecisionEventID: decisionID, DecisionRevision: 1, Action: "hide", Reason: "policy",
	}}
	route, agent, err := al.resolveMessageRoute(msg)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := resolveScopeKey(al.allocateRouteSession(route, msg).SessionKey, msg.SessionKey)
	agent.Sessions.AddFullMessage(sessionKey, providers.Message{
		Role: "user", Content: "withdraw me",
		SourceEventID: target, SourceRoomID: roomID, ActionProvenanceState: provenanceAuthenticated,
	})
	canceled := false
	al.activeTurnStates.Store(sessionKey, &turnState{
		turnID: "turn-room", session: agent.Sessions,
		initialHistoryLength: 1, turnCancel: func() { canceled = true },
	})
	if err := al.processRoomModeration(msg); err != nil {
		t.Fatal(err)
	}
	if !canceled {
		t.Fatal("hide did not cancel active room turn")
	}
	history := agent.Sessions.GetHistory(sessionKey)
	if len(history) != 1 || history[0].Content == "withdraw me" || history[0].RoomModerationAction != "hide" {
		t.Fatalf("history=%+v", history)
	}
	if _, complete := actionLineage(history, ""); !complete {
		t.Fatal("hidden-only history should have an empty, complete authority lineage")
	}
}

func TestRoomModerationControlRejectsUntrustedInput(t *testing.T) {
	al, messageBus, provider, cfg, cleanup := newTestAgentLoop(t)
	_ = messageBus
	_ = provider
	_ = cfg
	defer cleanup()
	if err := al.processRoomModeration(bus.InboundMessage{RoomModeration: &bus.RoomModerationControl{
		RoomID: "room", TargetEventID: "event", DecisionEventID: "decision", DecisionRevision: 1, Action: "hide",
	}}); err == nil {
		t.Fatal("untrusted moderation control was accepted")
	}
}
