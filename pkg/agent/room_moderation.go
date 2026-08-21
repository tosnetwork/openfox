package agent

import (
	"errors"
	"fmt"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/openfox/pkg/session"
)

func (al *AgentLoop) processRoomModeration(msg bus.InboundMessage) error {
	control := msg.RoomModeration
	origin := msg.Context.AuthenticatedMessagingOrigin
	if control == nil || origin == nil || msg.Context.Channel != "tos_messenger" ||
		msg.Context.ChatType != "group" || msg.Context.SpaceType != "room" ||
		msg.Context.ChatID != control.RoomID || msg.Context.SpaceID != control.RoomID ||
		msg.Context.MessageID != control.DecisionEventID || origin.EventID != control.DecisionEventID ||
		origin.Kind != "room.moderation" || control.TargetEventID == "" {
		return errors.New("invalid authenticated room moderation control")
	}
	route, agent, err := al.resolveMessageRoute(msg)
	if err != nil {
		return err
	}
	sessionKey := resolveScopeKey(al.allocateRouteSession(route, msg).SessionKey, msg.SessionKey)
	if control.Action == "hide" {
		if _, active := al.activeTurnStates.Load(sessionKey); active {
			if err := al.HardAbort(sessionKey); err != nil {
				return fmt.Errorf("cancel active turn before room hide: %w", err)
			}
		}
	}
	store, ok := agent.Sessions.(session.RoomModerationSessionStore)
	if !ok {
		return errors.New("session store cannot persist room moderation")
	}
	_, err = store.ApplyRoomModeration(sessionKey, providers.RoomModerationDecision{
		RoomID: control.RoomID, TargetEventID: control.TargetEventID,
		DecisionEventID: control.DecisionEventID, DecisionRevision: control.DecisionRevision,
		Action: control.Action, Reason: control.Reason,
	})
	if err != nil {
		return err
	}
	return agent.Sessions.Save(sessionKey)
}
