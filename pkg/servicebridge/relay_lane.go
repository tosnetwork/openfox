package servicebridge

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// A rail node carries rail packets over direct sockets and relays. Two
// further carriers are optional and are supplied by the program that embeds
// this package, never built here: a fallback packet transport for the socket
// named by messenger_socket, and a second relay lane for the configuration's
// chat section. A configuration that names either one while the program
// registered none is refused at node open, in setup and in preflight.

// ErrNoFallbackTransport refuses a configuration that names
// messenger_socket in a program that registered no fallback transport.
var ErrNoFallbackTransport = errors.New("servicebridge: messenger_socket is configured, but this program has " +
	"no packet transport for it; remove messenger_socket and use direct_peers or relay_urls")

// ErrNoRelayLane refuses a configuration that has a chat section in a
// program that registered no relay lane.
var ErrNoRelayLane = errors.New("servicebridge: the configuration has a chat section, but this program " +
	"carries no relay lane for it; remove the chat section")

// FallbackTransportOpener opens the packet transport that takes every
// packet no direct socket and no relay reaches. It is given the configured
// messenger_socket.
type FallbackTransportOpener func(socket string) (PacketTransport, error)

// RelayLane is a second purpose carried over a node's relays beside the
// rail. It has its own keys, peer cards and envelope journal, and shares the
// carrier's relay client pool, poll loop and maintenance pass. An envelope
// sealed to one of its keys is handed to it and never to the rail receiver.
type RelayLane interface {
	// LaneKeys is the lane's own key set. No key id is held by both the
	// rail and the lane.
	LaneKeys() *RelayKeys
	// LaneTransport is the lane's sending transport, whose journal the
	// carrier keeps redeposited.
	LaneTransport() *RelayTransport
	// Maintain rotates and destroys the lane's keys.
	Maintain(ctx context.Context) error
	// Receive takes a packet opened under one of the lane's keys. It
	// reports whether the envelope may be acknowledged; false leaves it at
	// the relay for a later poll.
	Receive(ctx context.Context, packetJSON []byte) bool
	// LaneStatus is what the carrier's status file shows of the lane, as a
	// value that encodes to a JSON object.
	LaneStatus() any
}

// RelayLaneEnv is what a carrier gives the lane it opens.
type RelayLaneEnv struct {
	// Root is the carrier's state directory, state_dir/relay.
	Root     string
	AgentID  string
	Verifier mldsa44.Verifier
	Agents   agentpacket.AgentResolver
	Now      func() time.Time
	Report   func(stage string, err error)
	// pool is the carrier's relay client pool, which the lane shares.
	pool *relayPool
}

// RelayLaneOpener opens the lane on a carrier.
type RelayLaneOpener func(env RelayLaneEnv) (RelayLane, error)

// RelayLaneHandler is everything the node, setup, preflight and status need
// from the lane the configuration's chat section configures. The section
// itself is opaque here: the handler decodes, completes and validates it.
type RelayLaneHandler interface {
	// DecodeSection strictly decodes the section's JSON.
	DecodeSection(raw []byte) (any, error)
	// Validate checks the section against the rest of the configuration.
	Validate(config NodeConfig) error
	// OwnRelays lists the relays the section names beside the rail's.
	OwnRelays(config NodeConfig) []string
	// InitSection returns the section `init` writes: the given one with its
	// defaults below the state directory filled in.
	InitSection(section *LaneSection, stateDir string) *LaneSection
	// InitNextStep is the next step `init` prints for the section.
	InitNextStep(railConfigPath string) string
	// Opener returns what opens the lane on the node's relay carrier.
	// options is NodeOptions.Lane.
	Opener(config NodeConfig, signer *PacketSigner, options any) (RelayLaneOpener, error)
	// Preflight adds the lane's checks to a preflight run.
	Preflight(p *preflight)
	// ReadOutbox lists the lane's envelope journal below the carrier's
	// state directory without taking ownership of it.
	ReadOutbox(relayRoot string) ([]RelayOutboxView, error)
	// CheckStatus strictly decodes what LaneStatus wrote.
	CheckStatus(raw []byte) error
}

var (
	extensionMutex   sync.RWMutex
	fallbackOpener   FallbackTransportOpener
	relayLaneHandler RelayLaneHandler
)

// RegisterFallbackTransport sets the opener of the fallback packet
// transport; nil removes it. A program registers it once, before it loads a
// configuration.
func RegisterFallbackTransport(open FallbackTransportOpener) {
	extensionMutex.Lock()
	defer extensionMutex.Unlock()
	fallbackOpener = open
}

// RegisterRelayLane sets the handler of the configuration's chat section;
// nil removes it. A program registers it once, before it loads a
// configuration.
func RegisterRelayLane(handler RelayLaneHandler) {
	extensionMutex.Lock()
	defer extensionMutex.Unlock()
	relayLaneHandler = handler
}

func registeredFallbackTransport() FallbackTransportOpener {
	extensionMutex.RLock()
	defer extensionMutex.RUnlock()
	return fallbackOpener
}

func registeredRelayLane() RelayLaneHandler {
	extensionMutex.RLock()
	defer extensionMutex.RUnlock()
	return relayLaneHandler
}

// checkFallbackSocket refuses a messenger_socket no registered transport
// can serve.
func checkFallbackSocket(socket string) error {
	if socket != "" && registeredFallbackTransport() == nil {
		return ErrNoFallbackTransport
	}
	return nil
}

// LaneSection is the chat section of a node configuration. It encodes
// exactly as the value the registered lane decoded it to.
type LaneSection struct {
	// Value is the section as the registered lane decoded it.
	Value any
	// raw is the section as it was read while no lane was registered. It is
	// kept so that the configuration still encodes; nothing interprets it.
	raw json.RawMessage
}

// MarshalJSON implements json.Marshaler.
func (s LaneSection) MarshalJSON() ([]byte, error) {
	if s.Value != nil {
		return json.Marshal(s.Value)
	}
	if len(s.raw) > 0 {
		return s.raw, nil
	}
	return nil, errors.New("servicebridge: empty chat section")
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *LaneSection) UnmarshalJSON(raw []byte) error {
	handler := registeredRelayLane()
	if handler == nil {
		s.Value, s.raw = nil, append(json.RawMessage(nil), raw...)
		return nil
	}
	value, err := handler.DecodeSection(raw)
	if err != nil {
		return err
	}
	s.Value, s.raw = value, nil
	return nil
}

// normalized returns the section as it reads back from its own encoding, so
// that empty and absent collections inside it compare equal.
func (s *LaneSection) normalized() *LaneSection {
	if s == nil {
		return nil
	}
	encoded, err := json.Marshal(*s)
	if err != nil {
		return s
	}
	var decoded LaneSection
	if err := decoded.UnmarshalJSON(encoded); err != nil {
		return s
	}
	return &decoded
}

// validateLaneSection checks the chat section against the rest of the
// configuration; a configuration without one passes.
func validateLaneSection(config NodeConfig) error {
	if config.Chat == nil {
		return nil
	}
	handler := registeredRelayLane()
	if handler == nil {
		return ErrNoRelayLane
	}
	return handler.Validate(config)
}
