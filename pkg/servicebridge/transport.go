package servicebridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// PacketLifetime is how long a sent packet stays deliverable; it stays
// inside the Messenger bridge's 24 hour staleness bound.
const PacketLifetime = 24*time.Hour - 5*time.Minute

// OutboundPacket is one signed packet with the exact identity a retry of an
// ambiguous send must reuse.
type OutboundPacket struct {
	RecipientAgentID string
	JSON             []byte
	IdempotencyKey   string
	ExpiresAtUnix    uint64
}

// PacketTransport hands one signed Agent Packet to a carrier that delivers
// it to the recipient Agent. The carrier is trusted for nothing: the
// recipient verifies every packet against finalized state.
type PacketTransport interface {
	Send(ctx context.Context, packet OutboundPacket) error
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

var idempotencyKeyPattern = regexp.MustCompile(`^idem_[0-9a-f]{64}$`)

// PacketSigner signs packets as the local Agent with one of its finalized
// ML-DSA-44 controllers, held in tosctl custody.
type PacketSigner struct {
	Signer     mldsa44.Signer
	Controller string
	KeyID      [mldsa44.KeyIDSize]byte
	AgentID    string
	mutex      sync.Mutex
	sequence   uint64
	now        func() time.Time
}

// NewPacketSigner binds a controller to the local Agent.
func NewPacketSigner(signer mldsa44.Signer, controller, keyIDText, agentID string) (*PacketSigner, error) {
	keyID, err := mldsa44.ParseKeyIDText(keyIDText)
	if signer == nil || controller == "" || err != nil || !agentIDPattern.MatchString(agentID) {
		return nil, errors.New("servicebridge: invalid packet signer")
	}
	return &PacketSigner{Signer: signer, Controller: controller, KeyID: keyID, AgentID: agentID, now: time.Now}, nil
}

func (s *PacketSigner) sign(
	ctx context.Context,
	recipient, capabilityID, quoteCommitment string,
	payload []byte,
) (agentpacket.Packet, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return agentpacket.Packet{}, errors.New("servicebridge: draw packet nonce")
	}
	s.mutex.Lock()
	now := uint64(s.now().Unix())
	// A strictly increasing sequence seeded from the clock keeps packets of
	// one process ordered without a durable counter; the receiver does not
	// rely on it.
	if s.sequence < now<<16 {
		s.sequence = now << 16
	}
	s.sequence++
	sequence := s.sequence
	s.mutex.Unlock()
	return agentpacket.Sign(ctx, s.Signer, s.Controller, agentpacket.Packet{
		SenderAgentID:    s.AgentID,
		RecipientAgentID: recipient,
		CapabilityID:     capabilityID,
		QuoteCommitment:  quoteCommitment,
		Sequence:         sequence,
		Nonce:            nonce,
		Payload:          payload,
		CreatedAtUnix:    now,
		SenderKeyID:      s.KeyID,
	})
}

// courierPacket is one journaled packet of one send generation.
type courierPacket struct {
	Schema         string `json:"schema"`
	Recipient      string `json:"recipient"`
	PacketBase64   string `json:"packet_base64"`
	IdempotencyKey string `json:"idempotency_key"`
	ExpiresAtUnix  uint64 `json:"expires_at_unix"`
	Sent           bool   `json:"sent"`
}

const courierSchema = "tos.openfox.rail-courier-packet.v1"

// Courier sends rail messages as signed packets with a durable record of
// each attempt. Every packet's bytes, idempotency key and expiry are on disk
// before its first send, so an ambiguous send is retried identically after a
// restart. A new delivery of the same message is a new generation with fresh
// packets, so the Messenger's per-nonce completion and staleness bounds never
// suppress it.
type Courier struct {
	root      string
	signer    *PacketSigner
	transport PacketTransport
	mutex     sync.Mutex
	now       func() time.Time
}

// OpenCourier opens an owner-private outbox directory.
func OpenCourier(directory string, signer *PacketSigner, transport PacketTransport) (*Courier, error) {
	if signer == nil || transport == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("servicebridge: invalid courier configuration")
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &Courier{root: directory, signer: signer, transport: transport, now: time.Now}, nil
}

// Envelope addresses one rail message.
type Envelope struct {
	RecipientAgentID string
	CapabilityID     string
	QuoteCommitment  string
	Kind             byte
	ActorAccount     [32]byte
	RequestID        uint64
	RequestHash      [32]byte
	// NotAfterUnix caps every packet's expiry (for example the request's
	// refund claim deadline).
	NotAfterUnix uint64
}

// MessageKey names a message's outbox directory.
func (e Envelope) MessageKey() string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("tos.openfox.rail-outbox.v1\x00%s\x00%d\x00%x\x00%d\x00%x",
		e.RecipientAgentID, e.Kind, e.ActorAccount, e.RequestID, e.RequestHash)))
	return hex.EncodeToString(digest[:])
}

// Deliver starts a new send generation of body and sends every packet. It
// returns nil when the transport accepted all of them; on error the
// generation stays journaled and Resume retries the unsent packets.
func (c *Courier) Deliver(ctx context.Context, envelope Envelope, body []byte) (int, error) {
	if c == nil || ctx == nil || !agentIDPattern.MatchString(envelope.RecipientAgentID) ||
		!capabilityPattern.MatchString(envelope.CapabilityID) {
		return 0, errors.New("servicebridge: invalid delivery")
	}
	frames, err := SplitMessage(envelope.Kind, envelope.ActorAccount, envelope.RequestID, envelope.RequestHash, body)
	if err != nil {
		return 0, err
	}
	now := uint64(c.now().Unix())
	expires := now + uint64(PacketLifetime/time.Second)
	if envelope.NotAfterUnix != 0 && envelope.NotAfterUnix < expires {
		expires = envelope.NotAfterUnix
	}
	if expires <= now {
		return 0, errors.New("servicebridge: the message can no longer be delivered")
	}
	c.mutex.Lock()
	directory := filepath.Join(c.root, envelope.MessageKey())
	if err = ensurePrivateDirectory(directory); err != nil {
		c.mutex.Unlock()
		return 0, err
	}
	generation, err := nextGeneration(directory)
	if err != nil {
		c.mutex.Unlock()
		return 0, err
	}
	genDir := filepath.Join(directory, strconv.Itoa(generation))
	if err := os.Mkdir(genDir, 0o700); err != nil {
		c.mutex.Unlock()
		return 0, errors.New("servicebridge: create send generation")
	}
	c.mutex.Unlock()
	for _, frame := range frames {
		payload, err := EncodeFrame(frame)
		if err != nil {
			return generation, err
		}
		packet, err := c.signer.sign(
			ctx,
			envelope.RecipientAgentID,
			envelope.CapabilityID,
			envelope.QuoteCommitment,
			payload,
		)
		if err != nil {
			return generation, err
		}
		encoded, err := agentpacket.EncodeJSON(packet)
		if err != nil {
			return generation, err
		}
		key := sha256.Sum256(encoded)
		record := courierPacket{
			Schema:    courierSchema,
			Recipient: envelope.RecipientAgentID,
			PacketBase64: base64.StdEncoding.EncodeToString(
				encoded,
			),
			IdempotencyKey: "idem_" + hex.EncodeToString(key[:]),
			ExpiresAtUnix:  expires,
		}
		if err := writeJSON(filepath.Join(genDir, strconv.Itoa(int(frame.Index))+".json"), record, true); err != nil {
			return generation, err
		}
	}
	if err := syncDirectory(genDir); err != nil {
		return generation, err
	}
	return generation, c.flush(ctx, genDir)
}

// Resume retries every journaled packet not yet accepted, with its exact
// bytes, key and expiry. A packet past its expiry is never retried; its
// generation is retired and the caller decides on a fresh one.
func (c *Courier) Resume(ctx context.Context) error {
	if c == nil {
		return errors.New("servicebridge: invalid courier")
	}
	messages, err := os.ReadDir(c.root)
	if err != nil {
		return errors.New("servicebridge: read outbox")
	}
	var failures []error
	for _, message := range messages {
		if !assemblyNamePattern.MatchString(message.Name()) {
			continue
		}
		generations, err := os.ReadDir(filepath.Join(c.root, message.Name()))
		if err != nil {
			return errors.New("servicebridge: read outbox message")
		}
		for _, generation := range generations {
			if _, err := strconv.Atoi(generation.Name()); err != nil {
				continue
			}
			if err := c.flush(ctx, filepath.Join(c.root, message.Name(), generation.Name())); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

// ErrGenerationExpired reports a generation whose packets can no longer be
// sent; it is retired, never retried.
var ErrGenerationExpired = errors.New("servicebridge: the send generation expired before it was accepted")

func (c *Courier) flush(ctx context.Context, genDir string) error {
	if _, err := os.Lstat(filepath.Join(genDir, "retired")); err == nil {
		return nil
	}
	entries, err := os.ReadDir(genDir)
	if err != nil {
		return errors.New("servicebridge: read send generation")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	now := uint64(c.now().Unix())
	for _, name := range names {
		path := filepath.Join(genDir, name)
		var record courierPacket
		if err := readJSON(path, 256<<10, &record); err != nil || record.Schema != courierSchema {
			return errors.New("servicebridge: invalid outbox record")
		}
		if record.Sent {
			continue
		}
		if record.ExpiresAtUnix <= now {
			if err := writeSynced(
				filepath.Join(genDir, "retired"),
				[]byte("expired"),
			); err != nil &&
				!errors.Is(err, os.ErrExist) {
				return err
			}
			return ErrGenerationExpired
		}
		encoded, err := base64.StdEncoding.Strict().DecodeString(record.PacketBase64)
		if err != nil {
			return errors.New("servicebridge: invalid outbox packet")
		}
		if err := c.transport.Send(ctx, OutboundPacket{
			RecipientAgentID: record.Recipient, JSON: encoded,
			IdempotencyKey: record.IdempotencyKey, ExpiresAtUnix: record.ExpiresAtUnix,
		}); err != nil {
			return err
		}
		record.Sent = true
		if err := writeJSON(path, record, false); err != nil {
			return err
		}
	}
	return nil
}

// Generations reports how many send generations a message has.
func (c *Courier) Generations(envelope Envelope) (int, error) {
	directory := filepath.Join(c.root, envelope.MessageKey())
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	next, err := nextGeneration(directory)
	return next - 1, err
}

func nextGeneration(directory string) (int, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, errors.New("servicebridge: read outbox message")
	}
	highest := 0
	for _, entry := range entries {
		value, err := strconv.Atoi(entry.Name())
		if err == nil && value > highest {
			highest = value
		}
	}
	return highest + 1, nil
}

func writeJSON(path string, value any, create bool) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.New("servicebridge: encode record")
	}
	if create {
		return writeSynced(path, encoded)
	}
	return replaceSynced(path, encoded)
}
