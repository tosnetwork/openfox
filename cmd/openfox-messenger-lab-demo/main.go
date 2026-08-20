// Command openfox-messenger-lab-demo runs three OpenFox channel instances
// through the local TOS Messenger acceptance carrier and prints the resulting
// group transcript. It uses no LLM and makes no production transport claim.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels/tosmessengerlab"
	"github.com/tosnetwork/openfox/pkg/config"
)

type credentialFlags []string

func (f *credentialFlags) String() string         { return strings.Join(*f, ",") }
func (f *credentialFlags) Set(value string) error { *f = append(*f, value); return nil }

type (
	credential     struct{ id, token string }
	transcriptLine struct{ AgentID, Content string }
)

func main() {
	var raw credentialFlags
	socket := flag.String("socket", "", "Messenger lab Unix socket")
	stateDir := flag.String("state-dir", "", "directory for OpenFox durable cursors")
	label := flag.String("label", "openfox-builders", "deterministic room label")
	message := flag.String("message", "hello from OpenFox A", "opening group message")
	flag.Var(&raw, "agent", "agent_id=token (repeat exactly three times)")
	flag.Parse()
	if err := run(*socket, *stateDir, *label, *message, raw); err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-lab-demo:", err)
		os.Exit(1)
	}
}

func run(socket, stateDir, label, opening string, raw []string) error {
	if socket == "" || stateDir == "" || strings.TrimSpace(label) == "" || strings.TrimSpace(opening) == "" {
		return errors.New("socket, state-dir, label, and message are required")
	}
	if len(raw) != 3 {
		return errors.New("exactly three -agent credentials are required")
	}
	credentials := make([]credential, 0, 3)
	memberIDs := make([]string, 0, 3)
	for _, value := range raw {
		id, token, ok := strings.Cut(value, "=")
		if !ok {
			return errors.New("each -agent must be agent_id=token")
		}
		credentials = append(credentials, credential{id: id, token: token})
		memberIDs = append(memberIDs, id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	type running struct {
		id      string
		bus     *bus.MessageBus
		channel *tosmessengerlab.Channel
	}
	agents := make([]running, 0, 3)
	for index, identity := range credentials {
		settings := &config.TOSMessengerLabSettings{
			SocketPath:     socket,
			AgentID:        identity.id,
			Token:          *config.NewSecureString(identity.token),
			CursorPath:     filepath.Join(stateDir, identity.id+".json"),
			PollIntervalMS: 50,
		}
		if index == 0 {
			settings.Rooms = []config.TOSMessengerLabRoom{{Label: label, Members: memberIDs}}
		}
		messageBus := bus.NewMessageBus()
		channel, err := tosmessengerlab.New(&config.Channel{AllowFrom: []string{"*"}}, settings, messageBus)
		if err != nil {
			return err
		}
		if err := channel.Start(ctx); err != nil {
			return err
		}
		defer channel.Stop(context.Background())
		agents = append(agents, running{id: identity.id, bus: messageBus, channel: channel})
	}
	roomID, ok := agents[0].channel.RoomID(label, memberIDs)
	if !ok {
		return errors.New("creator did not join the configured room")
	}
	if _, err := agents[0].channel.Send(ctx, bus.OutboundMessage{ChatID: roomID, Content: opening}); err != nil {
		return err
	}
	transcript := []transcriptLine{{AgentID: agents[0].id, Content: opening}}
	for index := 1; index < len(agents); index++ {
		for {
			select {
			case inbound := <-agents[index].bus.InboundChan():
				if inbound.Content != opening {
					continue
				}
				answer := "ack from " + agents[index].id
				if _, err := agents[index].channel.Send(
					ctx,
					bus.OutboundMessage{ChatID: roomID, Content: answer},
				); err != nil {
					return err
				}
				transcript = append(transcript, transcriptLine{AgentID: agents[index].id, Content: answer})
				goto nextAgent
			case <-ctx.Done():
				return errors.New("timed out waiting for group delivery")
			}
		}
	nextAgent:
	}
	expected := map[string]bool{}
	for index := 1; index < len(agents); index++ {
		expected["ack from "+agents[index].id] = true
	}
	received := map[string]bool{}
	for len(received) < 2 {
		select {
		case inbound := <-agents[0].bus.InboundChan():
			if expected[inbound.Content] {
				received[inbound.Content] = true
			}
		case <-ctx.Done():
			return errors.New("creator did not receive both group replies")
		}
	}
	result := map[string]any{
		"ok":         true,
		"mode":       "local-unix-plaintext-lab",
		"room_id":    roomID,
		"members":    memberIDs,
		"transcript": transcript,
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
