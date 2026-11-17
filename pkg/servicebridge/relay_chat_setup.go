package servicebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// ChatContactSchema names the contact file two operators exchange out of
// band: the Messenger daemon's relay contact (relay identity evidence and
// the chat card, no locator) wrapped unchanged. It is rendezvous, not
// authority: everything in it is verified on import.
const ChatContactSchema = "tos.openfox.chat-contact.v1"

// maxChatContactBytes bounds one wrapped contact file.
const maxChatContactBytes = relayframe.MaxContactBytes + 1024

type chatContactFile struct {
	Schema       string          `json:"schema"`
	RelayContact json.RawMessage `json:"relay_contact"`
}

// ChatCardResult reports the chat card a node hands out.
type ChatCardResult struct {
	AgentID       string   `json:"agent_id"`
	KeyID         string   `json:"key_id"`
	NotBeforeUnix uint64   `json:"not_before_unix"`
	NotAfterUnix  uint64   `json:"not_after_unix"`
	Relays        []string `json:"relays"`
	CardPath      string   `json:"card_path"`
	NextSteps     []string `json:"next_steps,omitempty"`
}

// loadChatConfig reads a node configuration that has a valid chat section.
func loadChatConfig(path string) (NodeConfig, error) {
	config, err := LoadNodeConfig(path)
	if err != nil {
		return NodeConfig{}, err
	}
	if config.Chat == nil {
		return NodeConfig{}, errors.New("servicebridge: the configuration has no chat section; run init with " +
			"--messenger-carrier-socket")
	}
	if !agentIDPattern.MatchString(config.AgentID) || !cleanAbsolute(config.StateDir) {
		return NodeConfig{}, errors.New("servicebridge: the configuration names no established Agent")
	}
	if err := validateChatConfig(config); err != nil {
		return NodeConfig{}, err
	}
	return config, nil
}

// ChatRepublish rotates the chat keys, issues a chat card signed by the
// packet controller when none qualifies, and writes the current card to the
// daemon's card path. `chat init` and `chat republish` both run it; `serve`
// does the same at every maintenance pass.
func ChatRepublish(ctx context.Context, configPath string, env SetupEnv) (*ChatCardResult, error) {
	env.fill()
	if ctx == nil {
		return nil, errors.New("servicebridge: no context")
	}
	config, err := loadChatConfig(configPath)
	if err != nil {
		return nil, err
	}
	relays, err := chatRelays(config)
	if err != nil {
		return nil, err
	}
	helper, err := env.PacketSigner(config.TOSCTL, env.vaultURL(config.TOSCTL))
	if err != nil {
		return nil, err
	}
	signer, err := NewPacketSigner(helper, config.PacketController, config.PacketKeyID, config.AgentID)
	if err != nil {
		return nil, err
	}
	signer.now = env.Now
	root := filepath.Join(config.StateDir, relayStateDir)
	if err = ensurePrivateDirectory(root); err != nil {
		return nil, err
	}
	keys, err := OpenChatRelayKeys(filepath.Join(root, relayChatKeysDir), config.AgentID, relays, signer, env.Now)
	if err != nil {
		return nil, err
	}
	if _, err = keys.Maintain(ctx); err != nil {
		return nil, err
	}
	now := env.Now().Unix()
	if now <= 0 {
		return nil, errors.New("servicebridge: the clock is not set")
	}
	key, err := keys.Current(ctx, offerCardCover(uint64(now)))
	if err != nil {
		return nil, err
	}
	if err = publishChatCard(config.Chat.CardPath, key.CardJSON); err != nil {
		return nil, err
	}
	return &ChatCardResult{
		AgentID: config.AgentID, KeyID: agentpacketseal.KeyIDText(key.KeyID), NotBeforeUnix: key.NotBeforeUnix,
		NotAfterUnix: key.NotAfterUnix, Relays: key.Relays, CardPath: config.Chat.CardPath,
		NextSteps: []string{
			"set the Messenger daemon's relay_carriage.card_path to " + config.Chat.CardPath + ", carry_socket_path " +
				"to " + config.Chat.CarrierSocket + " and listen_socket_path to " + config.Chat.MessengerCarrierSocket,
			"openfox earning chat contact export --rail-config " + configPath + " --out <file>, once the daemon " +
				"published its relay evidence",
		},
	}, nil
}

// heldChatCard returns the chat card a node hands out now, read from its
// key directory without changing it, and whether the card path publishes it.
// The card is the one republication published: the held key, valid now for
// the configured relays, whose card is exactly the file at the card path.
// Several keys may be valid at once (a fresh init holds a seven-day and a
// thirty-day key with one issue time), so the key is chosen by the published
// file, never by key order. Without a matching file it is the valid key that
// runs longest, the one republication would hand out.
func heldChatCard(config NodeConfig, now time.Time) (OwnRelayKey, bool, error) {
	relays, err := chatRelays(config)
	if err != nil {
		return OwnRelayKey{}, false, err
	}
	keyDir := filepath.Join(config.StateDir, relayStateDir, relayChatKeysDir)
	if err = checkPrivateDirectory(keyDir); err != nil {
		return OwnRelayKey{}, false, errors.New("servicebridge: no chat key directory; run `openfox earning chat " +
			"init`")
	}
	keys := &RelayKeys{directory: keyDir, agentID: config.AgentID, relays: relays, schema: relayChatKeySchema}
	if err = keys.load(); err != nil {
		return OwnRelayKey{}, false, err
	}
	published, readErr := readPrivateFile(config.Chat.CardPath, relayframe.MaxCardBytes)
	unix := uint64(now.Unix())
	var longest *OwnRelayKey
	for index := range keys.keys {
		key := &keys.keys[index]
		if key.NotBeforeUnix > unix || unix >= key.NotAfterUnix || !slices.Equal(key.Relays, relays) {
			continue
		}
		if readErr == nil && bytes.Equal(key.CardJSON, published) {
			return *key, true, nil
		}
		if longest == nil || key.NotAfterUnix > longest.NotAfterUnix {
			longest = key
		}
	}
	if longest == nil {
		return OwnRelayKey{}, false, errors.New("servicebridge: no held chat card is valid now; run `openfox " +
			"earning chat republish`")
	}
	return *longest, false, nil
}

// ChatContactExport writes this node's contact file: the daemon's exported
// relay contact, with its chat card replaced by the card this node hands out
// now when they differ (the daemon exports at its own publication times).
func ChatContactExport(configPath, out string, now time.Time) ([]byte, error) {
	if !cleanAbsolute(out) {
		return nil, errors.New("servicebridge: --out must be an absolute clean path")
	}
	config, err := loadChatConfig(configPath)
	if err != nil {
		return nil, err
	}
	if config.Chat.EvidenceExportDir == "" {
		return nil, errors.New("servicebridge: chat.evidence_export_dir is not configured")
	}
	key, published, err := heldChatCard(config, now)
	if err != nil {
		return nil, err
	}
	if !published {
		return nil, errors.New("servicebridge: the card path does not hold the current chat card; run `openfox " +
			"earning chat republish`")
	}
	raw, err := readPrivateFile(filepath.Join(config.Chat.EvidenceExportDir, directory.RelayContactFile),
		relayframe.MaxContactBytes)
	if err != nil {
		return nil, errors.New("servicebridge: the daemon has not exported its relay contact yet (relay-contact.json " +
			"in evidence_export_dir)")
	}
	exported, err := relayframe.DecodeContactJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: the exported relay contact is invalid: %w", err)
	}
	if exported.AgentID != config.AgentID {
		return nil, errors.New("servicebridge: the exported relay contact belongs to another Agent")
	}
	contact, err := relayframe.EncodeContactJSON(relayframe.Contact{
		AgentID: config.AgentID, Evidence: exported.Evidence, Card: key.CardJSON,
	})
	if err != nil {
		return nil, err
	}
	wrapped, err := json.Marshal(chatContactFile{Schema: ChatContactSchema, RelayContact: contact})
	if err != nil || len(wrapped) > maxChatContactBytes {
		return nil, errors.New("servicebridge: encode the chat contact file")
	}
	if err := replaceSynced(out, append(wrapped, '\n')); err != nil {
		return nil, err
	}
	return wrapped, nil
}

// decodeChatContact strictly parses a wrapped contact file and the relay
// contact inside it. It checks shapes only; nothing is verified against
// finalized state.
func decodeChatContact(raw []byte) (relayframe.Contact, []byte, error) {
	if len(raw) == 0 || len(raw) > maxChatContactBytes {
		return relayframe.Contact{}, nil, errors.New("servicebridge: the chat contact file size is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file chatContactFile
	if err := decoder.Decode(&file); err != nil {
		return relayframe.Contact{}, nil, errors.New("servicebridge: the chat contact file is not strict JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return relayframe.Contact{}, nil, errors.New("servicebridge: the chat contact file has trailing content")
	}
	if file.Schema != ChatContactSchema {
		return relayframe.Contact{}, nil, errors.New("servicebridge: unsupported chat contact schema")
	}
	contact, err := relayframe.DecodeContactJSON(file.RelayContact)
	if err != nil {
		return relayframe.Contact{}, nil, fmt.Errorf("servicebridge: the relay contact is invalid: %w", err)
	}
	return contact, append([]byte(nil), file.RelayContact...), nil
}

// ChatContactImported reports an imported contact.
type ChatContactImported struct {
	AgentID     string `json:"agent_id"`
	KeyID       string `json:"key_id"`
	ContactFile string `json:"contact_file"`
	// InviteDecision is the prepared invites.present decision of an import
	// with an invite.
	InviteDecision *ChatPrepared `json:"invite_decision,omitempty"`
}

// importChatContact verifies a contact file's chat card against finalized
// state and stores it in the chat card store, then hands the relay contact
// to the daemon's contact directory, where the daemon verifies the evidence
// (CheckPeer) and commits it. Importing is the owner's admission decision,
// so the card goes into the admitted store; a card that fails verification
// leaves nothing written.
func importChatContact(ctx context.Context, cards *PeerCards, contactDir, ownAgent string,
	raw []byte,
) (ChatContactImported, error) {
	if cards == nil || ctx == nil || !cleanAbsolute(contactDir) || !agentIDPattern.MatchString(ownAgent) {
		return ChatContactImported{}, errChatInvalidLane
	}
	contact, relayContact, err := decodeChatContact(raw)
	if err != nil {
		return ChatContactImported{}, err
	}
	if contact.AgentID == ownAgent {
		return ChatContactImported{}, errors.New("servicebridge: the contact file is this node's own")
	}
	packet, err := agentpacket.DecodeJSON(contact.Card)
	if err != nil || packet.SenderAgentID != contact.AgentID {
		return ChatContactImported{}, errors.New("servicebridge: the contact's card is not a card of its Agent")
	}
	card, err := decodeOwnCard(contact.AgentID, contact.Card)
	if err != nil {
		return ChatContactImported{}, fmt.Errorf("%w: %v", ErrCardRefused, err)
	}
	verified, err := cards.verified(ctx, contact.Card, contact.AgentID, "")
	if err != nil {
		return ChatContactImported{}, err
	}
	// A contact is a direct admission: recorded before the card is stored,
	// so forgetting a room that also admitted the Agent never removes it. The
	// admission lock keeps a running `serve` from changing the record between.
	unlock, err := lockRoomAdmissions(cards.directory)
	if err != nil {
		return ChatContactImported{}, err
	}
	_, err = setDirectAdmission(chatRoomAdmissionsDir(cards.directory), contact.AgentID, true)
	if err == nil {
		err = cards.keep(verified)
	}
	unlock()
	if err != nil {
		return ChatContactImported{}, err
	}
	if err := os.MkdirAll(contactDir, 0o700); err != nil {
		return ChatContactImported{}, errors.New("servicebridge: create the Messenger contact directory")
	}
	path := filepath.Join(contactDir, strings.TrimPrefix(contact.AgentID, "agent_")+".json")
	if err := replaceSynced(path, relayContact); err != nil {
		return ChatContactImported{}, err
	}
	return ChatContactImported{
		AgentID: contact.AgentID, KeyID: agentpacketseal.KeyIDText(card.KeyID), ContactFile: path,
	}, nil
}

// ChatContactRemoved reports a removed contact.
type ChatContactRemoved struct {
	AgentID      string   `json:"agent_id"`
	RemovedCards []string `json:"removed_card_key_ids"`
	ContactFile  string   `json:"removed_contact_file,omitempty"`
	// KeptForRooms names the rooms that still admit the Agent: its cards
	// stay for them, and go when the last of them forgets the Agent.
	KeptForRooms []string `json:"cards_kept_for_rooms,omitempty"`
}

// removeChatContact ends the contact's direct admission and deletes the
// contact file import wrote for it in the daemon's contact directory. Its
// stored chat cards are deleted too, so a contact whose evidence the daemon
// refused stops occupying a card slot, unless a room still admits the
// Agent: those cards stay for the room, which forgets them later. A running
// `serve` forgets deleted cards at its next use of the store. An Agent with
// neither a card, a contact file nor a direct admission is unknown and
// refused.
func removeChatContact(cardsDir, contactDir, ownAgent, agent string) (ChatContactRemoved, error) {
	if !cleanAbsolute(cardsDir) || (contactDir != "" && !cleanAbsolute(contactDir)) ||
		!agentIDPattern.MatchString(ownAgent) {
		return ChatContactRemoved{}, errChatInvalidLane
	}
	if !agentIDPattern.MatchString(agent) {
		return ChatContactRemoved{}, errors.New("servicebridge: the contact to remove must be an Agent id " +
			"(agent_<64 hex>)")
	}
	if agent == ownAgent {
		return ChatContactRemoved{}, errors.New("servicebridge: this node's own Agent is not a contact")
	}
	unlock, err := lockRoomAdmissions(cardsDir)
	if err != nil {
		return ChatContactRemoved{}, err
	}
	defer unlock()
	held, err := readPeerCards(cardsDir)
	if err != nil {
		return ChatContactRemoved{}, err
	}
	// The direct admission ends before any card goes: a crash in between
	// leaves the cards held only by the rooms that admitted the Agent, if
	// any, and a later forget of the last of them removes them.
	rooms, err := setDirectAdmission(chatRoomAdmissionsDir(cardsDir), agent, false)
	if err != nil {
		return ChatContactRemoved{}, err
	}
	removed := ChatContactRemoved{AgentID: agent, RemovedCards: []string{}, KeptForRooms: rooms}
	for _, card := range held {
		if card.AgentID != agent || len(rooms) > 0 {
			continue
		}
		path := filepath.Join(cardsDir, peerCardFile(card))
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, errors.New("servicebridge: remove a chat card")
		}
		removed.RemovedCards = append(removed.RemovedCards, agentpacketseal.KeyIDText(card.Key.KeyID))
	}
	if len(removed.RemovedCards) > 0 {
		if err := syncDirectory(cardsDir); err != nil {
			return removed, err
		}
	}
	if contactDir != "" {
		path := filepath.Join(contactDir, strings.TrimPrefix(agent, "agent_")+".json")
		switch info, statErr := os.Lstat(path); {
		case errors.Is(statErr, os.ErrNotExist):
		case statErr != nil || !info.Mode().IsRegular():
			return removed, errors.New("servicebridge: the contact file path is not a regular file")
		default:
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return removed, errors.New("servicebridge: remove the contact file")
			}
			if err := syncDirectory(contactDir); err != nil {
				return removed, err
			}
			removed.ContactFile = path
		}
	}
	if len(removed.RemovedCards) == 0 && removed.ContactFile == "" && len(rooms) == 0 {
		return removed, errors.New("servicebridge: no chat card or contact file of that Agent is held")
	}
	return removed, nil
}

// ChatContactRemove removes a contact from the chat card store and the
// daemon's contact directory.
func ChatContactRemove(configPath, agent string) (*ChatContactRemoved, error) {
	config, err := loadChatConfig(configPath)
	if err != nil {
		return nil, err
	}
	removed, err := removeChatContact(filepath.Join(config.StateDir, relayStateDir, relayChatPeersDir),
		config.Chat.ContactDir, config.AgentID, agent)
	if err != nil {
		return nil, err
	}
	return &removed, nil
}

// ChatContactImport imports a peer's contact file into this node's chat card
// store and the daemon's contact directory.
func ChatContactImport(ctx context.Context, configPath, file string, now func() time.Time,
) (*ChatContactImported, error) {
	if ctx == nil || !cleanAbsolute(file) {
		return nil, errors.New("servicebridge: --file must be an absolute clean path")
	}
	if now == nil {
		now = time.Now
	}
	config, err := loadChatConfig(configPath)
	if err != nil {
		return nil, err
	}
	if config.Chat.ContactDir == "" {
		return nil, errors.New("servicebridge: chat.contact_dir is not configured")
	}
	raw, err := readBoundedFile(file, maxChatContactBytes)
	if err != nil {
		return nil, err
	}
	verifier, agents, err := openChatVerification(config)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(config.StateDir, relayStateDir)
	if err = ensurePrivateDirectory(root); err != nil {
		return nil, err
	}
	cards, err := OpenPeerCards(filepath.Join(root, relayChatPeersDir), verifier, agents, chatNoOwners{}, now)
	if err != nil {
		return nil, err
	}
	relays, err := chatRelays(config)
	if err != nil {
		return nil, err
	}
	cards.AllowLoopbackRelays(ownRelaysOnLoopback(relays))
	imported, err := importChatContact(ctx, cards, config.Chat.ContactDir, config.AgentID, raw)
	if err != nil {
		return nil, err
	}
	return &imported, nil
}

// ChatContactImportWithInvite imports a peer's contact file and prepares
// the invites.present decision of the invite the peer's owner issued to this
// one, into out, so every delivery to the peer carries it once the owner
// signed and submitted it.
func ChatContactImportWithInvite(ctx context.Context, configPath, file string, invite ChatInvite, out string,
	now func() time.Time,
) (*ChatContactImported, error) {
	if ctx == nil || !cleanAbsolute(file) {
		return nil, errors.New("servicebridge: --file must be an absolute clean path")
	}
	if now == nil {
		now = time.Now
	}
	owner, err := ownerFromConfig(configPath)
	if err != nil {
		return nil, err
	}
	raw, err := readBoundedFile(file, maxChatContactBytes)
	if err != nil {
		return nil, err
	}
	return importWithInvite(ctx, owner, raw, invite, out, now(), func() (*ChatContactImported, error) {
		return ChatContactImport(ctx, configPath, file, now)
	})
}

// importWithInvite checks the invite and the decision file before anything
// is imported, imports, then prepares the decision. A preparation that fails
// after the import says so: the contact stays, and `chat invite present`
// prepares the decision again.
func importWithInvite(ctx context.Context, owner chatOwnerCaller, raw []byte, invite ChatInvite, out string,
	now time.Time, doImport func() (*ChatContactImported, error),
) (*ChatContactImported, error) {
	contact, _, err := decodeChatContact(raw)
	if err != nil {
		return nil, err
	}
	request, err := presentInviteRequest(contact.AgentID, invite, now)
	if err != nil {
		return nil, err
	}
	if !cleanAbsolute(out) {
		return nil, errors.New("servicebridge: --out must be an absolute clean path")
	}
	if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
		return nil, errors.New("servicebridge: --out names an existing file; it is never replaced")
	}
	imported, err := doImport()
	if err != nil {
		return nil, err
	}
	prepared, err := prepareToFile(ctx, owner, request, out)
	if err != nil {
		return imported, fmt.Errorf("servicebridge: the contact %s was imported, but its invite decision was "+
			"not prepared; run `openfox chat invite present`: %w", imported.AgentID, err)
	}
	imported.InviteDecision = &prepared
	return imported, nil
}

// openChatVerification opens the pinned tosctl verifier and the finalized
// Agent reader a card verification needs.
func openChatVerification(config NodeConfig) (mldsa44.Verifier, agentpacket.AgentResolver, error) {
	network := networkOf(config)
	reader, err := openServiceActorReader(config, network, config.StateDir)
	if err != nil {
		return nil, nil, err
	}
	vaultURL := ""
	if config.TOSCTL.VaultURLEnv != "" {
		vaultURL = os.Getenv(config.TOSCTL.VaultURLEnv)
	}
	helper, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{
		Binary: config.TOSCTL.Binary, SHA256: config.TOSCTL.SHA256,
		ConfigPath: config.TOSCTL.ConfigPath, VaultURL: vaultURL,
	})
	if err != nil {
		return nil, nil, err
	}
	return helper, FinalizedAgents{Sessions: ChainSessions{Reader: reader}}, nil
}

// readBoundedFile reads a regular file of at most limit bytes that need not
// be owner-only: a contact file arrives from another operator.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("servicebridge: the file must be a non-empty regular file within its bound")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("servicebridge: open the file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("servicebridge: read the file within its bound")
	}
	return raw, nil
}

// ChatStatusReport is what `chat status` shows.
type ChatStatusReport struct {
	AgentID                string            `json:"agent_id"`
	Relays                 []string          `json:"relays"`
	CarrierSocket          string            `json:"carrier_socket"`
	MessengerCarrierSocket string            `json:"messenger_carrier_socket"`
	CardPath               string            `json:"card_path"`
	CardPublished          bool              `json:"card_published"`
	CurrentKey             *RelayKeyView     `json:"current_key,omitempty"`
	CurrentKeyProblem      string            `json:"current_key_problem,omitempty"`
	PeerCards              []PeerCardView    `json:"peer_cards"`
	Outbox                 []RelayOutboxView `json:"outbox"`
	// Rooms are the rooms whose rosters admitted peer cards, and
	// RoomAdmissions each such peer's admissions.
	Rooms          []RoomCardsView     `json:"rooms"`
	RoomAdmissions []RoomAdmissionView `json:"room_admissions"`
	// PeerEnvelopes are the journal's per-peer counts against the caps of 24
	// chat and 16 kind-3 envelopes.
	PeerEnvelopes []PeerEnvelopeCount `json:"peer_envelopes"`
	// DaemonRooms are the daemon's private rooms and pending room invites,
	// read from the owner socket when one is configured; DaemonRoomsProblem
	// says why they could not be read.
	DaemonRooms        *ChatRooms `json:"daemon_rooms,omitempty"`
	DaemonRoomsProblem string     `json:"daemon_rooms_problem,omitempty"`
}

// ReadChatStatus reads the chat lane's state without taking it over, so it
// runs beside `serve`.
func ReadChatStatus(configPath string, now time.Time) (*ChatStatusReport, error) {
	return readChatStatus(context.Background(), configPath, now)
}

func readChatStatus(ctx context.Context, configPath string, now time.Time) (*ChatStatusReport, error) {
	config, err := loadChatConfig(configPath)
	if err != nil {
		return nil, err
	}
	relays, err := chatRelays(config)
	if err != nil {
		return nil, err
	}
	report := &ChatStatusReport{
		AgentID: config.AgentID, Relays: relays, CarrierSocket: config.Chat.CarrierSocket,
		MessengerCarrierSocket: config.Chat.MessengerCarrierSocket, CardPath: config.Chat.CardPath,
		PeerCards: []PeerCardView{}, Outbox: []RelayOutboxView{}, Rooms: []RoomCardsView{},
		RoomAdmissions: []RoomAdmissionView{}, PeerEnvelopes: []PeerEnvelopeCount{},
	}
	if key, published, keyErr := heldChatCard(config, now); keyErr != nil {
		report.CurrentKeyProblem = strings.TrimPrefix(keyErr.Error(), "servicebridge: ")
	} else {
		views := relayKeyViews([]OwnRelayKey{key})
		report.CurrentKey = &views[0]
		report.CardPublished = published
	}
	root := filepath.Join(config.StateDir, relayStateDir)
	held, err := readPeerCards(filepath.Join(root, relayChatPeersDir))
	if err != nil {
		return nil, err
	}
	for _, card := range held {
		report.PeerCards = append(report.PeerCards, PeerCardView{
			AgentID: card.AgentID, KeyID: agentpacketseal.KeyIDText(card.Key.KeyID),
			NotBeforeUnix: card.Card.NotBeforeUnix, NotAfterUnix: card.Card.NotAfterUnix,
			Relays: append([]string(nil), card.Card.Relays...),
		})
	}
	outbox, err := ReadRelayOutbox(filepath.Join(root, relayChatOutboxDir))
	if err != nil {
		return nil, err
	}
	if outbox != nil {
		report.Outbox = outbox
	}
	admissions, err := readRoomAdmissions(filepath.Join(root, relayChatRoomAdmissionsDir))
	if err != nil {
		return nil, err
	}
	if admissions != nil {
		report.RoomAdmissions, report.Rooms = admissions, roomCardsViews(admissions)
	}
	counts, err := ReadPeerEnvelopeCounts(filepath.Join(root, relayChatOutboxDir), now)
	if err != nil {
		return nil, err
	}
	if counts != nil {
		report.PeerEnvelopes = counts
	}
	if config.Chat.OwnerSocket != "" {
		owner, ownerErr := chatOwnerClient(config)
		var rooms ChatRooms
		if ownerErr == nil {
			rooms, ownerErr = listChatRooms(ctx, owner)
		}
		if ownerErr != nil {
			report.DaemonRoomsProblem = strings.TrimPrefix(ownerErr.Error(), "servicebridge: ")
		} else {
			report.DaemonRooms = &rooms
		}
	}
	return report, nil
}
