// Package tosmessenger adapts the authenticated production daemon boundary to
// OpenFox. Outbound calls submit semantics under an operator-bound route; the
// daemon alone constructs canonical events and the transport remains separate.
package tosmessenger

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels"
	"github.com/tosnetwork/openfox/pkg/config"
)

const defaultPollInterval = 250 * time.Millisecond

var ErrOutboundUnavailable = errors.New(
	"production Messenger outbound needs an authenticated origin and configured route",
)

var sessionPattern = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)

type Channel struct {
	*channels.BaseChannel
	settings *config.TOSMessengerSettings
	interval time.Duration
	lease    uint64
	timeout  time.Duration
	routes   map[string]config.TOSMessengerRoute
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func New(bc *config.Channel, settings *config.TOSMessengerSettings, messageBus *bus.MessageBus) (*Channel, error) {
	if settings == nil ||
		!filepath.IsAbs(settings.SocketPath) ||
		filepath.Clean(settings.SocketPath) != settings.SocketPath {
		return nil, errors.New("tos_messenger needs a clean absolute socket_path")
	}
	interval := time.Duration(settings.PollIntervalMS) * time.Millisecond
	if interval == 0 {
		interval = defaultPollInterval
	}
	if interval < 50*time.Millisecond || interval > time.Minute {
		return nil, errors.New("tos_messenger poll interval is outside 50ms..1m")
	}
	lease := settings.LeaseSeconds
	if lease == 0 {
		lease = 30
	}
	if lease < 5 || lease > 300 {
		return nil, errors.New("tos_messenger lease is outside 5..300 seconds")
	}
	routes := make(map[string]config.TOSMessengerRoute, len(settings.Routes))
	for _, route := range settings.Routes {
		if route.ChatID == "" || !conversationPattern.MatchString(route.ConversationID) ||
			!sessionPattern.MatchString(route.SessionID) || !endpointPattern.MatchString(route.RecipientEndpointID) {
			return nil, errors.New("tos_messenger route has invalid chat, conversation, session, or recipient")
		}
		if route.RoomID == "" {
			if route.ChatID != route.ConversationID || route.MembershipEpoch != 0 {
				return nil, errors.New("tos_messenger direct route must use its conversation as chat_id")
			}
		} else if !roomPattern.MatchString(route.RoomID) || route.ChatID != route.RoomID || route.MembershipEpoch == 0 {
			return nil, errors.New("tos_messenger room route must bind chat_id, room_id, and membership_epoch")
		}
		if route.LifetimeSeconds == 0 {
			route.LifetimeSeconds = 24 * 60 * 60
		}
		if route.LifetimeSeconds < 60 || route.LifetimeSeconds > 7*24*60*60 {
			return nil, errors.New("tos_messenger route lifetime is outside 1m..7d")
		}
		if _, duplicate := routes[route.ChatID]; duplicate {
			return nil, errors.New("tos_messenger has duplicate chat route")
		}
		routes[route.ChatID] = route
	}
	return &Channel{
		BaseChannel: channels.NewBaseChannel(config.ChannelTOSMessenger, settings, messageBus, bc.AllowFrom),
		settings:    settings, interval: interval, lease: uint64(lease), timeout: 10 * time.Second,
		routes: routes,
	}, nil
}

func (c *Channel) Start(ctx context.Context) error {
	if c.IsRunning() {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.SetRunning(true)
	c.wg.Add(1)
	go c.poll(runCtx)
	return nil
}

func (c *Channel) Stop(context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	c.SetRunning(false)
	return nil
}

func (c *Channel) Send(ctx context.Context, message bus.OutboundMessage) ([]string, error) {
	if !c.IsRunning() {
		return nil, channels.ErrNotRunning
	}
	route, known := c.routes[message.ChatID]
	origin := message.Context.AuthenticatedMessagingOrigin
	if !known || origin == nil || origin.EventID != message.Context.MessageID ||
		!eventPattern.MatchString(origin.EventID) || origin.ReceivedAtUnix == 0 || message.Content == "" {
		return nil, ErrOutboundUnavailable
	}
	// One model result for one authenticated input has one retry identity. The
	// hash contains the exact output and fixed route, so substitution conflicts
	// at the daemon even if a caller reuses it incorrectly.
	preimage := route.ChatID + "\x00" + route.ConversationID + "\x00" + route.RoomID + "\x00" +
		route.SessionID + "\x00" + route.RecipientEndpointID + "\x00" + origin.EventID + "\x00" +
		message.ReplyToMessageID + "\x00" + message.Content
	digest := sha256.Sum256([]byte(preimage))
	response, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
		Op: "outbox.compose", ConversationID: route.ConversationID, RoomID: route.RoomID,
		MembershipEpoch: route.MembershipEpoch, ReplyToEventID: message.ReplyToMessageID,
		MediaType: "text/plain; charset=utf-8", Body: message.Content,
		IdempotencyKey: "idem_" + hex.EncodeToString(digest[:]), SessionID: route.SessionID,
		RecipientEndpointID: route.RecipientEndpointID,
		ExpiresAtUnix:       origin.ReceivedAtUnix + route.LifetimeSeconds,
	})
	if err != nil {
		return nil, err
	}
	if !eventPattern.MatchString(response.EventID) {
		return nil, errors.New("Messenger compose returned no canonical Event ID")
	}
	return []string{response.EventID}, nil
}

func (c *Channel) poll(ctx context.Context) {
	defer c.wg.Done()
	defer c.SetRunning(false)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		_ = c.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Channel) pollOnce(ctx context.Context) error {
	response, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{Op: "inbox.pending", Limit: 64})
	if err != nil {
		return err
	}
	for _, offered := range response.Events {
		leaseID, err := newLeaseID()
		if err != nil {
			return err
		}
		claimed, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op: "inbox.claim", EventID: offered.EventID, LeaseID: leaseID, LeaseSeconds: c.lease,
		})
		if err != nil {
			continue
		}
		if claimed.Event == nil || claimed.Event.EventID != offered.EventID {
			return errors.New("Messenger claim returned another event")
		}
		event, content, decodeErr := decodeAdmittedText(*claimed.Event)
		if decodeErr != nil {
			_, rejectErr := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
				Op: "inbox.reject", EventID: offered.EventID, LeaseID: leaseID, Code: "unknown-event-kind",
			})
			if rejectErr != nil {
				return rejectErr
			}
			continue
		}
		if err := c.publish(ctx, *claimed.Event, event, content); err != nil {
			// Bus delivery is not a protocol rejection. Leave the lease to expire
			// so another attempt can publish the same stable Event ID.
			return err
		}
		if _, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op: "inbox.complete", EventID: offered.EventID, LeaseID: leaseID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Channel) publish(ctx context.Context, pending pendingEvent, event wireEvent, content string) error {
	chatID, chatType, spaceType := event.ConversationID, "direct", ""
	if event.RoomID != "" {
		chatID, chatType, spaceType = event.RoomID, "group", "room"
	}
	senderID := config.ChannelTOSMessenger + ":" + event.SenderAgentID
	sender := bus.SenderInfo{
		Platform: config.ChannelTOSMessenger, PlatformID: event.SenderAgentID, CanonicalID: senderID,
	}
	origin := actionauth.Origin{
		AgentID: event.SenderAgentID, EndpointID: event.SenderEndpointID, DeviceID: event.SenderDeviceID,
		EventID: event.EventID, ConversationID: event.ConversationID, Kind: event.Kind,
		ReceivedAtUnix: pending.ReceivedAtUnix,
	}
	inbound := bus.InboundContext{
		Channel: c.Name(), ChatID: chatID, ChatType: chatType, SpaceID: event.RoomID, SpaceType: spaceType,
		SenderID: senderID, MessageID: event.EventID, ReplyToMessageID: event.ReplyToEventID,
		Raw: map[string]string{"transport": "tos-messengerd-authenticated"}, AuthenticatedMessagingOrigin: &origin,
	}
	return c.HandleInboundContext(ctx, chatID, content, nil, inbound, sender)
}

func newLeaseID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate Messenger application lease")
	}
	return "lease_" + hex.EncodeToString(raw[:]), nil
}

var _ channels.Channel = (*Channel)(nil)
