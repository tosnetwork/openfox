package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/localapi"
)

// The Messenger packet transport is the fallback transport of an OpenFox
// rail node: it serves the socket messenger_socket names.
func init() {
	RegisterFallbackTransport(openMessengerTransport)
}

// MessengerTransport sends packets through the local Messenger daemon as
// direct applications of kind agent.packet.
type MessengerTransport struct {
	Client *localapi.Client
}

// Send queues the packet in the daemon's durable outbox. A nil error means
// the daemon accepted it; delivery is the daemon's.
func (t MessengerTransport) Send(ctx context.Context, packet OutboundPacket) error {
	if t.Client == nil || ctx == nil || !agentIDPattern.MatchString(packet.RecipientAgentID) || len(packet.JSON) == 0 ||
		packet.ExpiresAtUnix == 0 || !idempotencyKeyPattern.MatchString(packet.IdempotencyKey) {
		return errors.New("servicebridge: invalid Messenger packet send")
	}
	response, err := t.Client.Call(ctx, localapi.Request{
		Op: localapi.OpSendDirectApplication, Recipient: packet.RecipientAgentID,
		ApplicationKind: "agent.packet", ApplicationBody: packet.JSON, IdempotencyKey: packet.IdempotencyKey,
		ExpiresAtUnix: packet.ExpiresAtUnix,
	})
	if err != nil {
		return fmt.Errorf("servicebridge: Messenger send: %w", err)
	}
	if !response.OK || response.EventID == "" {
		return fmt.Errorf("servicebridge: Messenger refused the packet: %s", response.Code)
	}
	return nil
}

func newMessengerClient(socket string) (*localapi.Client, error) {
	return localapi.NewClient(socket, 30*time.Second)
}

// openMessengerTransport opens the Messenger transport on the daemon's
// socket.
func openMessengerTransport(socket string) (PacketTransport, error) {
	client, err := newMessengerClient(socket)
	if err != nil {
		return nil, err
	}
	return MessengerTransport{Client: client}, nil
}
