package servicebridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Layout of the relay state below a node's state directory.
const (
	relayStateDir   = "relay"
	relayKeysDir    = "keys"
	relayPeersDir   = "peers"
	relayOutboxDir  = "outbox"
	relayStatusFile = "status.json"
	// relayMaintainEvery paces key rotation and destruction.
	relayMaintainEvery = time.Minute
)

const relayStatusSchema = "tos.openfox.relay-status.v1"

// RelayCarrier is a node's Agent Packet Relay carrier: its own encryption
// keys and cards, the verified cards of its peers, the sending transport
// and the inbound poller.
type RelayCarrier struct {
	Keys      *RelayKeys
	Cards     *PeerCards
	Transport *RelayTransport
	Inbound   *RelayInbound
	// Chat is the Messenger chat lane, nil without a chat section. It has
	// its own keys, cards and journal and shares the pool and poll loop.
	Chat     *ChatCarrier
	stateDir string
	now      func() time.Time
	report   func(string, error)
	// onRotate is given the current own card at every maintenance pass, so
	// the provider's offer file always carries it.
	onRotate func(context.Context, OwnRelayKey) error
}

// RelayCarrierConfig assembles a carrier.
type RelayCarrierConfig struct {
	StateDir string
	AgentID  string
	Relays   []string
	Signer   cardSigner
	Cards    *PeerCards
	Receiver *Receiver
	Dial     relayDialer
	Now      func() time.Time
	Report   func(string, error)
	// Chat, when set, opens the chat lane.
	Chat *chatLaneConfig
}

// OpenRelayCarrier opens the carrier's owner-private state.
func OpenRelayCarrier(config RelayCarrierConfig) (*RelayCarrier, error) {
	if !cleanAbsolute(config.StateDir) || config.Cards == nil || config.Receiver == nil {
		return nil, errors.New("servicebridge: invalid relay carrier configuration")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(string, error) {}
	}
	root := filepath.Join(config.StateDir, relayStateDir)
	if err := ensurePrivateDirectory(root); err != nil {
		return nil, err
	}
	keys, err := OpenRelayKeys(filepath.Join(root, relayKeysDir), config.AgentID, config.Relays, config.Signer,
		config.Now)
	if err != nil {
		return nil, err
	}
	pool := newRelayPool(config.Dial)
	transport, err := OpenRelayTransport(filepath.Join(root, relayOutboxDir), config.Cards, pool, config.Now)
	if err != nil {
		return nil, err
	}
	inbound, err := NewRelayInbound(config.AgentID, keys, config.Receiver, pool, config.Now, config.Report)
	if err != nil {
		return nil, err
	}
	carrier := &RelayCarrier{
		Keys: keys, Cards: config.Cards, Transport: transport, Inbound: inbound, stateDir: config.StateDir,
		now: config.Now, report: config.Report,
	}
	if config.Chat != nil {
		chat, err := openChatCarrier(root, config.AgentID, *config.Chat, config.Receiver.Verifier,
			config.Receiver.Resolver, pool, config.Now, config.Report)
		if err != nil {
			return nil, err
		}
		if err := separateKeySets(keys, chat.Keys); err != nil {
			return nil, err
		}
		carrier.Chat = chat
		inbound.chat = chat
	}
	return carrier, nil
}

// separateKeySets refuses a rail and a chat key set that hold one key id:
// no key serves two purposes.
func separateKeySets(rail, chat *RelayKeys) error {
	for _, key := range chat.Held() {
		if _, held := rail.private(key.KeyID); held {
			return errors.New("servicebridge: a chat key is also held as a rail key; no key serves both purposes")
		}
	}
	return nil
}

// SetRotationHook registers what every maintenance pass hands the current
// own card to.
func (c *RelayCarrier) SetRotationHook(hook func(context.Context, OwnRelayKey) error) {
	c.onRotate = hook
}

// Maintain rotates and destroys keys and runs the rotation hook.
func (c *RelayCarrier) Maintain(ctx context.Context) error {
	if c.Chat != nil {
		if err := c.Chat.Maintain(ctx); err != nil {
			c.report("relay.chat.keys", err)
		}
	}
	if _, err := c.Keys.Maintain(ctx); err != nil {
		return err
	}
	if c.onRotate == nil {
		return nil
	}
	// Every pass, not only the one that issued a card: a republish that
	// failed, or a crash after the successor was stored, is caught up here.
	// The hook writes only when what it publishes differs.
	now := c.now().Unix()
	if now <= 0 {
		return errors.New("servicebridge: the clock is not set")
	}
	key, err := c.Keys.Current(ctx, offerCardCover(uint64(now)))
	if err != nil {
		return err
	}
	return c.onRotate(ctx, key)
}

// Run polls the relays, keeps redundant deposits going and maintains keys
// until ctx ends.
func (c *RelayCarrier) Run(ctx context.Context) error {
	if c == nil || ctx == nil {
		return errors.New("servicebridge: invalid relay carrier")
	}
	var lastMaintain time.Time
	for {
		now := c.now()
		if now.Sub(lastMaintain) >= relayMaintainEvery || now.Before(lastMaintain) {
			lastMaintain = now
			if err := c.Maintain(ctx); err != nil {
				c.report("relay.keys", err)
			}
		}
		next := c.Inbound.Due(ctx)
		if err := c.Transport.Redeposit(ctx); err != nil {
			c.report("relay.redeposit", err)
		}
		var chatWake chan struct{}
		if c.Chat != nil {
			chatWake = c.Chat.Transport.wake
			if err := c.Chat.Transport.Redeposit(ctx); err != nil {
				c.report("relay.chat.redeposit", err)
			}
		}
		if err := c.WriteStatus(); err != nil {
			c.report("relay.status", err)
		}
		wait := time.Until(next)
		if wait < time.Second {
			wait = time.Second
		}
		if wait > RelayPollInterval {
			wait = RelayPollInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.Transport.wake:
			timer.Stop()
		case <-chatWake:
			// A nil channel (no chat lane) never fires.
			timer.Stop()
		case <-timer.C:
		}
	}
}

// RelayKeyView is a held own key as status shows it; it never carries the
// private key.
type RelayKeyView struct {
	KeyID         string   `json:"key_id"`
	NotBeforeUnix uint64   `json:"not_before_unix"`
	NotAfterUnix  uint64   `json:"not_after_unix"`
	DestroyAtUnix uint64   `json:"destroy_at_unix"`
	Relays        []string `json:"relays"`
}

// RelayStatus is the relay carrier's state file, written by `serve`.
type RelayStatus struct {
	Schema      string           `json:"schema"`
	UpdatedUnix int64            `json:"updated_unix"`
	Relays      []RelayPollState `json:"relays"`
	Keys        []RelayKeyView   `json:"keys"`
	PeerCards   []PeerCardView   `json:"peer_cards"`
	// Chat is the chat lane's keys and peer cards, absent without one.
	Chat *ChatStatus `json:"chat,omitempty"`
}

// WriteStatus records the poll state, the held keys and the peer cards.
func (c *RelayCarrier) WriteStatus() error {
	status := RelayStatus{
		Schema: relayStatusSchema, UpdatedUnix: c.now().Unix(), Relays: c.Inbound.States(),
		Keys: relayKeyViews(c.Keys.Held()), PeerCards: c.Cards.List(), Chat: c.Chat.status(),
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		return errors.New("servicebridge: encode the relay status")
	}
	return replaceSynced(filepath.Join(c.stateDir, relayStateDir, relayStatusFile), encoded)
}

func relayKeyViews(keys []OwnRelayKey) []RelayKeyView {
	out := make([]RelayKeyView, 0, len(keys))
	for _, key := range keys {
		out = append(out, RelayKeyView{
			KeyID: agentpacketseal.KeyIDText(key.KeyID), NotBeforeUnix: key.NotBeforeUnix,
			NotAfterUnix: key.NotAfterUnix, DestroyAtUnix: key.DestroyAtUnix(), Relays: key.Relays,
		})
	}
	return out
}

// RelayDeliveryReport is what `status` shows of the relay carrier.
type RelayDeliveryReport struct {
	Configured []string          `json:"configured_relays"`
	Status     *RelayStatus      `json:"poller,omitempty"`
	Outbox     []RelayOutboxView `json:"outbox"`
	// ChatOutbox is the chat lane's envelope journal.
	ChatOutbox []RelayOutboxView `json:"chat_outbox,omitempty"`
}

// ReadRelayDelivery reads the relay state of a node without taking it
// over, so it runs beside `serve`.
func ReadRelayDelivery(stateDir string, configured []string) (*RelayDeliveryReport, error) {
	if !cleanAbsolute(stateDir) {
		return nil, errors.New("servicebridge: state_dir must be clean and absolute")
	}
	report := &RelayDeliveryReport{Configured: append([]string{}, configured...), Outbox: []RelayOutboxView{}}
	root := filepath.Join(stateDir, relayStateDir)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err := checkPrivateDirectory(root); err != nil {
		return nil, err
	}
	var status RelayStatus
	if err := readJSON(filepath.Join(root, relayStatusFile), 1<<20, &status); err == nil {
		if status.Schema == relayStatusSchema {
			report.Status = &status
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	outbox, err := ReadRelayOutbox(filepath.Join(root, relayOutboxDir))
	if err != nil {
		return nil, err
	}
	if outbox != nil {
		report.Outbox = outbox
	}
	chatOutbox, err := ReadRelayOutbox(filepath.Join(root, relayChatOutboxDir))
	if err != nil {
		return nil, err
	}
	report.ChatOutbox = chatOutbox
	return report, nil
}
