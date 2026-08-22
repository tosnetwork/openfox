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
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels"
	"github.com/tosnetwork/openfox/pkg/config"
)

const (
	defaultPollInterval        = 250 * time.Millisecond
	maxOutboundAttachmentBytes = 512 << 20
	outboundAttachmentChunk    = 1 << 20
)

var ErrOutboundUnavailable = errors.New(
	"production Messenger outbound needs an authenticated origin and configured route",
)

var (
	sessionPattern        = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)
	uploadPattern         = regexp.MustCompile(`^attup_[0-9a-f]{64}$`)
	deliveryIntentPattern = regexp.MustCompile(`^intent_[0-9a-f]{64}$`)
)

type Channel struct {
	*channels.BaseChannel
	settings          *config.TOSMessengerSettings
	interval          time.Duration
	lease             uint64
	timeout           time.Duration
	routes            map[string]config.TOSMessengerRoute
	agentRoutes       map[string]config.TOSMessengerRoute
	proactiveLifetime uint64
	attachments       bool
	cancel            context.CancelFunc
	wg                sync.WaitGroup
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
	proactiveLifetime := settings.ProactiveLifetimeSeconds
	if proactiveLifetime == 0 {
		proactiveLifetime = 24 * 60 * 60
	}
	if proactiveLifetime < 60 || proactiveLifetime > 7*24*60*60 {
		return nil, errors.New("tos_messenger proactive lifetime is outside 1m..7d")
	}
	routes := make(map[string]config.TOSMessengerRoute, len(settings.Routes))
	agentRoutes := make(map[string]config.TOSMessengerRoute, len(settings.Routes))
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
		if route.RecipientAgentID != "" {
			if route.RoomID != "" || !agentPattern.MatchString(route.RecipientAgentID) {
				return nil, errors.New("tos_messenger proactive route needs a canonical AgentID and must be direct")
			}
			if _, duplicate := agentRoutes[route.RecipientAgentID]; duplicate {
				return nil, errors.New("tos_messenger has duplicate recipient Agent route")
			}
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
		if route.RecipientAgentID != "" {
			agentRoutes[route.RecipientAgentID] = route
		}
	}
	return &Channel{
		BaseChannel: channels.NewBaseChannel(config.ChannelTOSMessenger, settings, messageBus, bc.AllowFrom),
		settings:    settings, interval: interval, lease: uint64(lease), timeout: 10 * time.Second,
		routes: routes, agentRoutes: agentRoutes, proactiveLifetime: proactiveLifetime,
		attachments: settings.EnableAttachments,
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
	origin := message.Context.AuthenticatedMessagingOrigin
	if message.Recipient != "" {
		if origin != nil || message.ChatID != "" || message.ReplyToMessageID != "" || message.Content == "" ||
			!deliveryIntentPattern.MatchString(message.DeliveryIntentID) {
			return nil, ErrOutboundUnavailable
		}
		idempotencyDigest := sha256.Sum256([]byte(
			"openfox.tos-messenger.proactive-idempotency.v1\x00" + message.DeliveryIntentID + "\x00" +
				message.Recipient + "\x00" + message.Content,
		))
		response, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op: "messages.send-direct", Recipient: message.Recipient,
			MediaType: "text/plain; charset=utf-8", Body: message.Content,
			IdempotencyKey: "idem_" + hex.EncodeToString(idempotencyDigest[:]),
			ExpiresAtUnix:  uint64(time.Now().Add(time.Duration(c.proactiveLifetime) * time.Second).Unix()),
		})
		if err != nil {
			return nil, err
		}
		if !eventPattern.MatchString(response.EventID) {
			return nil, errors.New("Messenger compose returned no canonical Event ID")
		}
		return []string{response.EventID}, nil
	}
	if origin != nil && conversationPattern.MatchString(message.ChatID) &&
		origin.EventID == message.Context.MessageID && origin.ConversationID == message.ChatID &&
		eventPattern.MatchString(origin.EventID) && origin.ReceivedAtUnix != 0 && message.Content != "" {
		preimage := "openfox.tos-messenger.reply-idempotency.v1\x00" + origin.EventID + "\x00" +
			message.ReplyToMessageID + "\x00" + message.Content
		digest := sha256.Sum256([]byte(preimage))
		response, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op: "messages.reply-direct", ReplyToEventID: origin.EventID,
			MediaType: "text/plain; charset=utf-8", Body: message.Content,
			IdempotencyKey: "idem_" + hex.EncodeToString(digest[:]),
			ExpiresAtUnix:  uint64(time.Now().Add(time.Duration(c.proactiveLifetime) * time.Second).Unix()),
		})
		if err != nil {
			return nil, err
		}
		if !eventPattern.MatchString(response.EventID) {
			return nil, errors.New("Messenger direct reply returned no canonical Event ID")
		}
		return []string{response.EventID}, nil
	}
	route, known := c.routes[message.ChatID]
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

// SendMedia streams OpenFox MediaStore files through the daemon-owned
// attachment transaction. OpenFox chooses bounded presentation semantics and
// supplies exact plaintext evidence; it never receives or chooses encryption
// keys, capability grants, storage authority, retention, locator, sender
// identity, network, clock, or Event ID.
func (c *Channel) SendMedia(ctx context.Context, message bus.OutboundMediaMessage) ([]string, error) {
	if !c.IsRunning() {
		return nil, channels.ErrNotRunning
	}
	if !c.attachments || len(message.Parts) == 0 || len(message.Parts) > 16 {
		return nil, ErrOutboundUnavailable
	}
	route, known := c.routes[message.ChatID]
	origin := message.Context.AuthenticatedMessagingOrigin
	if !known || origin == nil || origin.EventID != message.Context.MessageID ||
		!eventPattern.MatchString(origin.EventID) || origin.ReceivedAtUnix == 0 {
		return nil, ErrOutboundUnavailable
	}
	store := c.GetMediaStore()
	if store == nil {
		return nil, errors.New("tos_messenger outbound attachments need a MediaStore")
	}

	// The v3 attachment payload has no unauthenticated caption field. Preserve
	// one shared caption as an ordinary canonical text Event and make every
	// attachment reply to it. Divergent per-part captions are refused rather
	// than silently discarded or ambiguously reordered.
	caption := ""
	for _, part := range message.Parts {
		if part.Caption == "" {
			continue
		}
		if caption != "" && part.Caption != caption {
			return nil, errors.New("tos_messenger media parts need one shared caption")
		}
		caption = part.Caption
	}
	replyTo := origin.EventID
	var eventIDs []string
	if caption != "" {
		captionIDs, err := c.Send(ctx, bus.OutboundMessage{
			Channel: message.Channel, ChatID: message.ChatID,
			Context: message.Context, AgentID: message.AgentID, SessionKey: message.SessionKey,
			Scope: message.Scope, Content: caption, ReplyToMessageID: origin.EventID,
		})
		if err != nil {
			return nil, err
		}
		replyTo = captionIDs[0]
		eventIDs = append(eventIDs, replyTo)
	}

	for index, part := range message.Parts {
		if part.Type != "image" && part.Type != "audio" && part.Type != "video" && part.Type != "file" {
			return eventIDs, errors.New("tos_messenger media part has an unsupported type")
		}
		path, metadata, err := store.ResolveWithMeta(part.Ref)
		if err != nil {
			return eventIDs, err
		}
		filename := part.Filename
		if filename == "" {
			filename = metadata.Filename
		}
		if filename == "" {
			filename = filepath.Base(path)
		}
		mediaType := part.ContentType
		if mediaType == "" {
			mediaType = metadata.ContentType
		}
		parsedType, params, parseErr := mime.ParseMediaType(mediaType)
		if parseErr != nil || parsedType != mediaType || len(params) != 0 || filename == "" || len(filename) > 255 ||
			strings.TrimSpace(filename) != filename || strings.ContainsAny(filename, "/\\\x00\r\n") {
			return eventIDs, errors.New("tos_messenger media metadata is not canonical")
		}
		file, size, digest, err := openAndDigestMedia(path)
		if err != nil {
			return eventIDs, err
		}
		partIDs, err := c.streamAttachment(ctx, route, origin.EventID, replyTo, index, part.Type,
			filename, mediaType, size, digest, file)
		_ = file.Close()
		if err != nil {
			return eventIDs, err
		}
		eventIDs = append(eventIDs, partIDs...)
	}
	return eventIDs, nil
}

func (c *Channel) streamAttachment(ctx context.Context, route config.TOSMessengerRoute, originEventID,
	replyTo string, partIndex int, partType, filename, mediaType string, size uint64, digest string, file *os.File,
) ([]string, error) {
	preimage := route.ChatID + "\x00" + route.ConversationID + "\x00" + route.RoomID + "\x00" +
		route.SessionID + "\x00" + route.RecipientEndpointID + "\x00" + originEventID + "\x00" + replyTo + "\x00" +
		partType + "\x00" + filename + "\x00" + mediaType + "\x00" + digest + "\x00" + strconv.Itoa(partIndex)
	idempotency := sha256.Sum256([]byte(preimage))
	response, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
		Op:             "attachments.outbound.begin",
		ConversationID: route.ConversationID, RoomID: route.RoomID, ReplyToEventID: replyTo,
		MembershipEpoch: route.MembershipEpoch, IdempotencyKey: "idem_" + hex.EncodeToString(idempotency[:]),
		SessionID: route.SessionID, RecipientEndpointID: route.RecipientEndpointID,
		Filename: filename, MediaType: mediaType, PlaintextDigest: digest, PlaintextBytes: size,
	})
	if err != nil {
		return nil, err
	}
	if response.Complete {
		if !eventPattern.MatchString(response.EventID) || response.UploadID != "" {
			return nil, errors.New("Messenger returned an invalid completed attachment retry")
		}
		return []string{response.EventID}, nil
	}
	if !uploadPattern.MatchString(response.UploadID) {
		return nil, errors.New("Messenger returned no canonical attachment upload")
	}
	count := uint32((size + outboundAttachmentChunk - 1) / outboundAttachmentChunk)
	if response.NextChunk > count {
		return nil, errors.New("Messenger attachment progress exceeds the source")
	}
	offset := int64(response.NextChunk) * outboundAttachmentChunk
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, errors.New("seek Messenger attachment retry source")
	}
	for chunkIndex := response.NextChunk; chunkIndex < count; chunkIndex++ {
		remaining := int64(size) - int64(chunkIndex)*outboundAttachmentChunk
		length := int64(outboundAttachmentChunk)
		if remaining < length {
			length = remaining
		}
		chunk := make([]byte, int(length))
		if _, err := io.ReadFull(file, chunk); err != nil {
			clear(chunk)
			return nil, errors.New("read exact Messenger attachment source chunk")
		}
		appended, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op:       "attachments.outbound.chunk",
			UploadID: response.UploadID, ChunkIndex: chunkIndex, Chunk: chunk,
		})
		clear(chunk)
		if err != nil {
			return nil, err
		}
		if appended.UploadID != response.UploadID || appended.NextChunk != chunkIndex+1 {
			return nil, errors.New("Messenger attachment progress did not advance exactly once")
		}
	}
	uploaded := uint32(0)
	for {
		committed, err := callLocal(
			ctx,
			c.settings.SocketPath,
			c.timeout,
			localRequest{Op: "attachments.outbound.commit", UploadID: response.UploadID},
		)
		if err != nil {
			return nil, err
		}
		if committed.Complete {
			if !eventPattern.MatchString(committed.EventID) || committed.UploadID != "" {
				return nil, errors.New("Messenger attachment commit returned no canonical Event ID")
			}
			return []string{committed.EventID}, nil
		}
		if committed.UploadID != response.UploadID || committed.EventID != "" || committed.NextChunk <= uploaded ||
			committed.NextChunk >= count {
			return nil, errors.New("Messenger attachment storage progress did not advance")
		}
		uploaded = committed.NextChunk
	}
}

func openAndDigestMedia(path string) (*os.File, uint64, string, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() <= 0 ||
		pathInfo.Size() > maxOutboundAttachmentBytes {
		return nil, 0, "", errors.New("tos_messenger media source must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, "", errors.New("open tos_messenger media source")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(pathInfo, opened) {
		_ = file.Close()
		return nil, 0, "", errors.New("tos_messenger media source changed while opened")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, maxOutboundAttachmentBytes+1))
	if err != nil || written != pathInfo.Size() || written > maxOutboundAttachmentBytes {
		_ = file.Close()
		return nil, 0, "", errors.New("hash bounded tos_messenger media source")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, 0, "", errors.New("rewind tos_messenger media source")
	}
	return file, uint64(written), "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
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
		event, content, moderation, decodeErr := decodeAdmitted(*claimed.Event)
		if decodeErr != nil {
			_, rejectErr := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
				Op: "inbox.reject", EventID: offered.EventID, LeaseID: leaseID, Code: "unknown-event-kind",
			})
			if rejectErr != nil {
				return rejectErr
			}
			continue
		}
		var publishErr error
		if moderation != nil {
			publishErr = c.publishModeration(ctx, *claimed.Event, event, *moderation)
		} else {
			publishErr = c.publish(ctx, *claimed.Event, event, content)
		}
		if publishErr != nil {
			// Bus delivery is not a protocol rejection. Leave the lease to expire
			// so another attempt can publish the same stable Event ID.
			return publishErr
		}
		if _, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op: "inbox.complete", EventID: offered.EventID, LeaseID: leaseID,
		}); err != nil {
			return err
		}
	}
	if c.attachments {
		return c.pollAttachments(ctx)
	}
	return nil
}

func (c *Channel) pollAttachments(ctx context.Context) error {
	response, err := callLocal(
		ctx,
		c.settings.SocketPath,
		c.timeout,
		localRequest{Op: "attachments.pending", Limit: 64},
	)
	if err != nil {
		return err
	}
	for _, offered := range response.Attachments {
		if !validPendingAttachment(offered) {
			return errors.New("Messenger returned invalid attachment inbox metadata")
		}
		leaseID, err := newLeaseID()
		if err != nil {
			return err
		}
		claimed, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op:      "attachments.claim",
			EventID: offered.EventID, LeaseID: leaseID, LeaseSeconds: c.lease,
		})
		if err != nil {
			continue
		}
		if claimed.Attachment == nil || claimed.Attachment.EventID != offered.EventID ||
			claimed.Attachment.SenderEndpointID != offered.SenderEndpointID ||
			claimed.Attachment.ConversationID != offered.ConversationID ||
			claimed.Attachment.ReceivedAtUnix != offered.ReceivedAtUnix || !validAdmittedAttachment(*claimed.Attachment) {
			if _, rejectErr := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
				Op:      "inbox.reject",
				EventID: offered.EventID, LeaseID: leaseID, Code: "not-authentic",
			}); rejectErr != nil {
				return rejectErr
			}
			continue
		}
		if err := c.publishAttachment(ctx, *claimed.Attachment); err != nil {
			return err
		}
		if _, err := callLocal(ctx, c.settings.SocketPath, c.timeout, localRequest{
			Op:      "inbox.complete",
			EventID: offered.EventID, LeaseID: leaseID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Channel) publishAttachment(ctx context.Context, attachment admittedAttachment) error {
	chatID, chatType, spaceType := attachment.ConversationID, "direct", ""
	if attachment.RoomID != "" {
		chatID, chatType, spaceType = attachment.RoomID, "group", "room"
	}
	senderID := config.ChannelTOSMessenger + ":" + attachment.SenderAgentID
	origin := actionauth.Origin{
		AgentID: attachment.SenderAgentID, EndpointID: attachment.SenderEndpointID,
		DeviceID: attachment.SenderDeviceID, EventID: attachment.EventID, ConversationID: attachment.ConversationID,
		Kind: "artifact.encrypted", ReceivedAtUnix: attachment.ReceivedAtUnix,
	}
	inbound := bus.InboundContext{
		Channel: c.Name(), ChatID: chatID, ChatType: chatType,
		SpaceID: attachment.RoomID, SpaceType: spaceType, SenderID: senderID, MessageID: attachment.EventID,
		ReplyToMessageID: attachment.ReplyToEventID,
		Raw: map[string]string{
			"transport": "tos-messengerd-authenticated-admission", "attachment_filename": attachment.Filename,
			"attachment_media_type": attachment.MediaType, "attachment_plaintext_digest": attachment.PlaintextDigest,
		},
		AuthenticatedMessagingOrigin: &origin,
	}
	result := make(chan error, 1)
	sender := bus.SenderInfo{
		Platform: config.ChannelTOSMessenger, PlatformID: attachment.SenderAgentID,
		CanonicalID: senderID,
	}
	if err := c.HandleInboundContextWithApplicationResult(
		ctx,
		chatID,
		attachment.Body,
		nil,
		inbound,
		result,
		sender,
	); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.timeout):
		return errors.New("OpenFox attachment application persistence timed out")
	}
}

func (c *Channel) publishModeration(
	ctx context.Context,
	pending pendingEvent,
	event wireEvent,
	control bus.RoomModerationControl,
) error {
	senderID := config.ChannelTOSMessenger + ":" + event.SenderAgentID
	origin := actionauth.Origin{
		AgentID: event.SenderAgentID, EndpointID: event.SenderEndpointID, DeviceID: event.SenderDeviceID,
		EventID: event.EventID, ConversationID: event.ConversationID, Kind: event.Kind,
		ReceivedAtUnix: pending.ReceivedAtUnix,
	}
	result := make(chan error, 1)
	message := bus.InboundMessage{
		Context: bus.InboundContext{
			Channel: c.Name(), ChatID: event.RoomID, ChatType: "group", SpaceID: event.RoomID, SpaceType: "room",
			SenderID: senderID, MessageID: event.EventID,
			Raw: map[string]string{"transport": "tos-messengerd-authenticated"}, AuthenticatedMessagingOrigin: &origin,
		},
		Sender: bus.SenderInfo{
			Platform:    config.ChannelTOSMessenger,
			PlatformID:  event.SenderAgentID,
			CanonicalID: senderID,
		},
		RoomModeration: &control,
		ControlResult:  result,
	}
	if err := c.PublishInboundControl(ctx, message); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.timeout):
		return errors.New("OpenFox room moderation persistence timed out")
	}
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
	result := make(chan error, 1)
	if err := c.HandleInboundContextWithApplicationResult(
		ctx, chatID, content, nil, inbound, result, sender,
	); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.timeout):
		return errors.New("OpenFox message application persistence timed out")
	}
}

func newLeaseID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate Messenger application lease")
	}
	return "lease_" + hex.EncodeToString(raw[:]), nil
}

var _ channels.Channel = (*Channel)(nil)
