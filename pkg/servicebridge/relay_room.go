package servicebridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// Room carriage: kind-3 frames of private rooms, the chat cards a room's
// roster admits, and the pacing of kind-3 deposits. The carrier still sees
// no Messenger plaintext: it reads only a frame's kind, part index and the
// room object's type and room from part 0.

// Room carriage bounds.
const (
	// ChatPeerRoomEnvelopeCap is the share of ChatPeerEnvelopeCap kind-3
	// envelopes may hold for one peer, so at least 8 stay for copies, acks
	// and evidence.
	ChatPeerRoomEnvelopeCap = 16
	// RoomDepositsPerMinute and RoomDepositBurst pace kind-3 deposits per
	// relay, so the rail and kinds 1, 2 and 4 keep at least half of a
	// relay's deposit rate.
	RoomDepositsPerMinute = 30
	RoomDepositBurst      = 16
	// roomDepositInterval is the time one paced deposit token takes to
	// refill.
	roomDepositInterval = time.Minute / RoomDepositsPerMinute
	// maxRoomPacingRelays bounds the relays with a bucket in memory; a full
	// bucket is the same as none, so those are dropped first.
	maxRoomPacingRelays = 1024
	// maxAgentRoomAdmissions bounds the rooms one peer's card is admitted
	// under: the Messenger daemon holds at most 64 private rooms, joined or
	// being joined.
	maxAgentRoomAdmissions = 64
	// maxRoomAdmissionRecordBytes bounds one admission record read back.
	maxRoomAdmissionRecordBytes = 16 << 10
)

// The caps are the carrier contract's; a change of either side cannot
// build until the other follows.
var (
	_ [ChatPeerEnvelopeCap - carrierapi.MaxPeerEnvelopes]struct{}
	_ [carrierapi.MaxPeerEnvelopes - ChatPeerEnvelopeCap]struct{}
	_ [ChatPeerRoomEnvelopeCap - carrierapi.MaxPeerRoomEnvelopes]struct{}
	_ [carrierapi.MaxPeerRoomEnvelopes - ChatPeerRoomEnvelopeCap]struct{}
)

const (
	relayChatRoomAdmissionsDir = "chat-room-admissions"
	roomAdmissionSchema        = "tos.openfox.chat-room-admission.v1"
)

var roomIDPattern = regexp.MustCompile(`^room_[0-9a-f]{64}$`)

// chatRoomAdmissionsDir is the admission store beside a chat card store.
func chatRoomAdmissionsDir(cardsDir string) string {
	return filepath.Join(filepath.Dir(cardsDir), relayChatRoomAdmissionsDir)
}

// roomAdmissionRecord records why the chat cards of one peer Agent are held
// when a room admitted them. An Agent without a record has every stored
// card under a direct admission (a contact file, an admitted copy), as
// before any room existed. With a record, Direct says whether such an
// admission also holds them, and Rooms are the rooms whose roster admitted
// them. The cards are forgotten only when neither holds them any more.
type roomAdmissionRecord struct {
	Schema  string               `json:"schema"`
	AgentID string               `json:"agent_id"`
	Direct  bool                 `json:"direct"`
	Rooms   []roomAdmissionEntry `json:"rooms"`
}

// roomAdmissionEntry is one room's admission of the cards. EndsAtUnix is the
// room's end (D18), fixed for the room's life: the carrier drops the entry
// on its own at carrierapi.RoomAdmissionDropAtUnix of it, so a daemon that
// never forgets cannot leave an admission behind.
type roomAdmissionEntry struct {
	RoomID         string `json:"room_id"`
	AdmittedAtUnix uint64 `json:"admitted_at_unix"`
	EndsAtUnix     uint64 `json:"ends_at_unix"`
}

// dropAt is when the sweep drops the entry.
func (e roomAdmissionEntry) dropAt() (uint64, bool) {
	return carrierapi.RoomAdmissionDropAtUnix(e.EndsAtUnix)
}

func (r roomAdmissionRecord) hasRoom(roomID string) bool {
	_, held := r.room(roomID)
	return held
}

// room returns the entry of roomID.
func (r roomAdmissionRecord) room(roomID string) (roomAdmissionEntry, bool) {
	for _, entry := range r.Rooms {
		if entry.RoomID == roomID {
			return entry, true
		}
	}
	return roomAdmissionEntry{}, false
}

// withoutRoom returns the record without roomID and whether it was there.
func (r roomAdmissionRecord) withoutRoom(roomID string) (roomAdmissionRecord, bool) {
	kept := make([]roomAdmissionEntry, 0, len(r.Rooms))
	removed := false
	for _, entry := range r.Rooms {
		if entry.RoomID == roomID {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	r.Rooms = kept
	return r, removed
}

// holds reports whether any admission holds the cards.
func (r roomAdmissionRecord) holds() bool { return r.Direct || len(r.Rooms) > 0 }

// roomAdmissions is the owner-private store of admission records, one file
// per peer Agent.
type roomAdmissions struct {
	directory string
}

// openRoomAdmissions opens the store, creating its directory.
func openRoomAdmissions(directory string) (*roomAdmissions, error) {
	if !cleanAbsolute(directory) {
		return nil, errors.New("servicebridge: invalid room admission directory")
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &roomAdmissions{directory: directory}, nil
}

func (a *roomAdmissions) path(agentID string) string {
	return filepath.Join(a.directory, strings.TrimPrefix(agentID, "agent_")+".json")
}

var errRoomAdmissionRecord = errors.New("servicebridge: invalid room admission record")

// load reads the record of agentID; a missing record is not an error.
func (a *roomAdmissions) load(agentID string) (roomAdmissionRecord, bool, error) {
	if a == nil || !agentIDPattern.MatchString(agentID) {
		return roomAdmissionRecord{}, false, errRoomAdmissionRecord
	}
	var record roomAdmissionRecord
	err := readJSON(a.path(agentID), maxRoomAdmissionRecordBytes, &record)
	if errors.Is(err, os.ErrNotExist) {
		return roomAdmissionRecord{}, false, nil
	}
	if err != nil {
		return roomAdmissionRecord{}, false, fmt.Errorf("%w: %w", errRoomAdmissionRecord, err)
	}
	if err := validRoomAdmission(record); err != nil || record.AgentID != agentID {
		return roomAdmissionRecord{}, false, errRoomAdmissionRecord
	}
	return record, true, nil
}

func validRoomAdmission(record roomAdmissionRecord) error {
	if record.Schema != roomAdmissionSchema || !agentIDPattern.MatchString(record.AgentID) ||
		len(record.Rooms) > maxAgentRoomAdmissions || !record.holds() {
		return errRoomAdmissionRecord
	}
	seen := make(map[string]struct{}, len(record.Rooms))
	for _, entry := range record.Rooms {
		if _, valid := entry.dropAt(); !roomIDPattern.MatchString(entry.RoomID) || !valid {
			return errRoomAdmissionRecord
		}
		if _, duplicate := seen[entry.RoomID]; duplicate {
			return errRoomAdmissionRecord
		}
		seen[entry.RoomID] = struct{}{}
	}
	return nil
}

// store writes a record. A record that only says Direct is the same as no
// record and is removed instead; one no admission holds is refused, since
// the caller must forget the cards first.
func (a *roomAdmissions) store(record roomAdmissionRecord) error {
	if a == nil {
		return errRoomAdmissionRecord
	}
	record.Schema = roomAdmissionSchema
	if record.Direct && len(record.Rooms) == 0 && agentIDPattern.MatchString(record.AgentID) {
		return a.remove(record.AgentID)
	}
	if err := validRoomAdmission(record); err != nil {
		return err
	}
	return writeJSON(a.path(record.AgentID), record, false)
}

// remove deletes the record of agentID; a missing one is not an error.
func (a *roomAdmissions) remove(agentID string) error {
	if a == nil || !agentIDPattern.MatchString(agentID) {
		return errRoomAdmissionRecord
	}
	if err := os.Remove(a.path(agentID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("servicebridge: remove a room admission record")
	}
	return syncDirectory(a.directory)
}

// restore puts back the state of agentID read before a change: the record,
// or no record.
func (a *roomAdmissions) restore(previous roomAdmissionRecord, existed bool, agentID string) error {
	if !existed {
		return a.remove(agentID)
	}
	return a.store(previous)
}

// RoomAdmissionView is one peer's room admissions as status shows them.
type RoomAdmissionView struct {
	AgentID string `json:"agent_id"`
	// Direct reports that a contact file or an admitted copy also holds the
	// peer's cards, so forgetting the rooms keeps them.
	Direct bool     `json:"direct"`
	Rooms  []string `json:"rooms"`
	// RoomEndsAtUnix is each room's end; the carrier drops the room's
	// admission one RoomEndSlackSeconds after it.
	RoomEndsAtUnix map[string]uint64 `json:"room_ends_at_unix,omitempty"`
	// Unreadable names a record that failed to load; the other fields are
	// then empty and every forget of that peer is answered retry.
	Unreadable string `json:"unreadable,omitempty"`
}

// readRoomAdmissions lists a store without creating or changing anything.
func readRoomAdmissions(directory string) ([]RoomAdmissionView, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("servicebridge: read the room admission directory")
	}
	store := &roomAdmissions{directory: directory}
	var out []RoomAdmissionView
	for _, entry := range entries {
		name := entry.Name()
		if !relayOutboxFilePattern.MatchString(name) {
			continue
		}
		agentID := "agent_" + strings.TrimSuffix(name, ".json")
		record, found, err := store.load(agentID)
		if err != nil {
			out = append(out, RoomAdmissionView{Unreadable: name, Rooms: []string{}})
			continue
		}
		if !found {
			continue
		}
		view := RoomAdmissionView{
			AgentID: agentID, Direct: record.Direct, Rooms: make([]string, 0, len(record.Rooms)),
			RoomEndsAtUnix: make(map[string]uint64, len(record.Rooms)),
		}
		for _, room := range record.Rooms {
			view.Rooms = append(view.Rooms, room.RoomID)
			view.RoomEndsAtUnix[room.RoomID] = room.EndsAtUnix
		}
		sort.Strings(view.Rooms)
		out = append(out, view)
	}
	return out, nil
}

// RoomCardsView is one room as the carrier's admissions see it: the peers
// whose chat cards its roster admitted.
type RoomCardsView struct {
	RoomID string   `json:"room_id"`
	Agents []string `json:"agents"`
}

// roomCardsViews groups admission views by room.
func roomCardsViews(admissions []RoomAdmissionView) []RoomCardsView {
	rooms := map[string][]string{}
	for _, admission := range admissions {
		for _, room := range admission.Rooms {
			rooms[room] = append(rooms[room], admission.AgentID)
		}
	}
	ids := make([]string, 0, len(rooms))
	for room := range rooms {
		ids = append(ids, room)
	}
	sort.Strings(ids)
	out := make([]RoomCardsView, 0, len(ids))
	for _, room := range ids {
		agents := rooms[room]
		sort.Strings(agents)
		out = append(out, RoomCardsView{RoomID: room, Agents: agents})
	}
	return out
}

// setDirectAdmission records, in the admission store below root, whether a
// direct admission holds agentID's cards: `chat contact import` sets it and
// `chat contact remove` clears it, both from another process than `serve`.
// Only an Agent a room also admitted has a record to change. It reports the
// rooms that still admit the Agent afterwards. The caller holds the
// admission lock (lockRoomAdmissions).
func setDirectAdmission(directory, agentID string, direct bool) ([]string, error) {
	store := &roomAdmissions{directory: directory}
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, err
	}
	record, found, err := store.load(agentID)
	if err != nil || !found {
		return nil, err
	}
	rooms := make([]string, 0, len(record.Rooms))
	for _, entry := range record.Rooms {
		rooms = append(rooms, entry.RoomID)
	}
	sort.Strings(rooms)
	if record.Direct == direct {
		return rooms, nil
	}
	record.Direct = direct
	if !record.holds() {
		// The contact's cards go with the contact, and no room holds them:
		// nothing is left to record.
		return rooms, store.remove(agentID)
	}
	return rooms, store.store(record)
}

// roomAdmissionLockFile is the lock beside the chat card store that
// serializes every change of an admission record, together with the card
// change it guards, across `serve` and the `chat contact` commands.
const roomAdmissionLockFile = "chat-room-admissions.lock"

// roomAdmissionLockWait bounds the wait for the admission lock, in
// nanoseconds (atomic, so a test may shorten it while handlers run);
// roomAdmissionLockPoll is how often a held lock is tried again.
var roomAdmissionLockWait = func() *atomic.Int64 {
	var wait atomic.Int64
	wait.Store(int64(10 * time.Second))
	return &wait
}()

const roomAdmissionLockPoll = 20 * time.Millisecond

// errRoomAdmissionBusy reports an admission lock another process kept past
// the bounded wait.
var errRoomAdmissionBusy = errors.New("servicebridge: another process holds the chat room admission lock " +
	"beyond the wait; try again")

// lockRoomAdmissions takes the inter-process admission lock of the chat
// card store at cardsDir, waiting at most roomAdmissionLockWait. The lock is
// per open file, so it also excludes another handle in the same process.
func lockRoomAdmissions(cardsDir string) (func(), error) {
	if !cleanAbsolute(cardsDir) {
		return nil, errRoomAdmissionRecord
	}
	path := filepath.Join(filepath.Dir(cardsDir), roomAdmissionLockFile)
	deadline := time.Now().Add(time.Duration(roomAdmissionLockWait.Load()))
	for {
		lock, err := acquireRunLock(path)
		if err == nil {
			return func() { releaseRunLock(lock) }, nil
		}
		if !errors.Is(err, ErrSetupBusy) {
			return nil, fmt.Errorf("servicebridge: the chat room admission lock: %w", err)
		}
		if !time.Now().Before(deadline) {
			return nil, errRoomAdmissionBusy
		}
		time.Sleep(roomAdmissionLockPoll)
	}
}

// lockAdmissions takes the carrier's in-process and inter-process admission
// locks, in that order.
func (c *ChatCarrier) lockAdmissions() (func(), error) {
	c.admissions.Lock()
	unlock, err := lockRoomAdmissions(c.Cards.directory)
	if err != nil {
		c.admissions.Unlock()
		return nil, err
	}
	return func() {
		unlock()
		c.admissions.Unlock()
	}, nil
}

// cardSource is why an in-band card is learned, which decides the admission
// it is stored under.
type cardSource int

const (
	// cardEstablished: a copy the daemon admitted (accepted or duplicate),
	// which only the 1:1 contact policy admits on the relay route: a direct
	// admission.
	cardEstablished cardSource = iota + 1
	// cardRenewed: a held copy, a copy ack, an admitted evidence frame. The
	// card keeps the admission the peer already has; a peer with none is
	// stored as a direct admission, as before rooms existed.
	cardRenewed
	// cardRoomRenewed: an admitted kind-3 object or part, a room ack. The
	// card is stored only while some admission already holds the peer, so
	// room traffic renews a card but never creates an admission.
	cardRoomRenewed
)

// learnFrom verifies an in-band card of sender and keeps it under the
// admission its source allows. A card that fails is ignored and never
// invalidates the frame that carried it.
func (c *ChatCarrier) learnFrom(ctx context.Context, sender string, card []byte, source cardSource) {
	if len(card) == 0 {
		return
	}
	verified, err := c.Cards.verified(ctx, card, sender, "")
	if err != nil {
		c.report("chat.card", err)
		return
	}
	unlock, err := c.lockAdmissions()
	if err != nil {
		c.report("chat.card", fmt.Errorf("servicebridge: the card is not stored: %w", err))
		return
	}
	defer unlock()
	record, found, err := c.rooms.load(sender)
	if err != nil {
		c.report("chat.card", fmt.Errorf("servicebridge: the card is not stored: %w", err))
		return
	}
	switch source {
	case cardEstablished:
		if found && !record.Direct {
			record.Direct = true
			if err := c.rooms.store(record); err != nil {
				c.report("chat.card", err)
				return
			}
		}
	case cardRenewed:
	case cardRoomRenewed:
		if !found {
			held, err := c.Cards.holdsAny(sender)
			if err != nil {
				c.report("chat.card", err)
				return
			}
			if !held {
				// No admission holds the sender: room traffic alone stores
				// nothing.
				return
			}
		}
	default:
		c.report("chat.card", errors.New("servicebridge: a card of an unknown source is not stored"))
		return
	}
	if err := c.Cards.keep(verified); err != nil {
		c.report("chat.card", err)
	}
}

// RoomCards implements carrierapi.Handler: carrier.room-cards. Admitting
// stores each card that verifies as its Agent's chat card under the room's
// admission; forgetting drops the room's admission of each Agent and its
// cards only when no other admission (a contact, an admitted copy, another
// room) holds them.
func (c *ChatCarrier) RoomCards(ctx context.Context, request carrierapi.Request) carrierapi.Response {
	if c == nil || ctx == nil {
		return carrierapi.Retry()
	}
	if !roomIDPattern.MatchString(request.RoomID) {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
	switch request.RoomCardsAction {
	case carrierapi.RoomCardsAdmit:
		// The server bounded the end against its clock; a missing one, or one
		// whose drop time overflows, is never stored.
		if _, valid := carrierapi.RoomAdmissionDropAtUnix(request.RoomEndsAtUnix); !valid ||
			len(request.RoomCards) == 0 || len(request.RoomCards) > carrierapi.MaxRoomCards ||
			len(request.ForgetAgentIDs) != 0 {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		return c.admitRoomCards(ctx, request.RoomID, request.RoomEndsAtUnix, request.RoomCards)
	case carrierapi.RoomCardsForget:
		if request.RoomEndsAtUnix != 0 || len(request.ForgetAgentIDs) == 0 ||
			len(request.ForgetAgentIDs) > carrierapi.MaxRoomCards || len(request.RoomCards) != 0 {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		return c.forgetRoomCards(request.RoomID, request.ForgetAgentIDs)
	default:
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
}

// errRoomEndConflict is an admission naming another end than the one held
// for its room: a room's end is fixed for its life (D18).
var errRoomEndConflict = errors.New("servicebridge: the admission names another end than its room's")

// admitRoomCards admits a batch under the room's end. A room already
// admitted under another end refuses the whole batch with invalid-request
// and keeps its end; the same end re-admits as a no-op. A card that does not
// verify, or that the store cannot take, is named in the answer and skipped;
// a check finalized state cannot answer, or a store failure, makes the whole
// batch a retry, which admits the cards already done again as a no-op.
func (c *ChatCarrier) admitRoomCards(ctx context.Context, roomID string, endsAtUnix uint64,
	cards []carrierapi.RoomCard,
) carrierapi.Response {
	seen := make(map[string]struct{}, len(cards))
	for _, offered := range cards {
		if !agentIDPattern.MatchString(offered.AgentID) {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		if _, duplicate := seen[offered.AgentID]; duplicate {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		seen[offered.AgentID] = struct{}{}
	}
	held, found, err := c.roomEnd(roomID)
	if err != nil {
		c.report("chat.room-cards", err)
		return carrierapi.Retry()
	}
	if found && held != endsAtUnix {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
	refused := []string{}
	for _, offered := range cards {
		raw, err := base64.StdEncoding.Strict().DecodeString(offered.CardBase64)
		if offered.AgentID == c.agentID || err != nil || len(raw) == 0 || len(raw) > relayframe.MaxCardBytes {
			refused = append(refused, offered.AgentID)
			continue
		}
		card, err := c.Cards.verified(ctx, raw, offered.AgentID, "")
		if errors.Is(err, errCardUnavailable) {
			c.report("chat.room-cards", err)
			return carrierapi.Retry()
		}
		if err != nil {
			refused = append(refused, offered.AgentID)
			continue
		}
		admitted, err := c.admitRoomCard(roomID, endsAtUnix, card)
		if errors.Is(err, errRoomEndConflict) {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		if err != nil {
			c.report("chat.room-cards", err)
			return carrierapi.Retry()
		}
		if !admitted {
			refused = append(refused, offered.AgentID)
		}
	}
	response := carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied}
	if len(refused) > 0 {
		response.RefusedAgentIDs = refused
	}
	return response
}

// admitRoomCard records the room's admission of a verified card, then stores
// the card. The record is written first, so a crash in between leaves an
// admission without its card, never a card no admission names; a store that
// fails puts the record back. It reports false for a card the store cannot
// take: the peer is at its room bound, or the card directory is full, and
// errRoomEndConflict when the peer holds the room under another end.
func (c *ChatCarrier) admitRoomCard(roomID string, endsAtUnix uint64, card *peerCard) (bool, error) {
	agentID := card.AgentID
	unlock, err := c.lockAdmissions()
	if err != nil {
		return false, err
	}
	defer unlock()
	previous, found, err := c.rooms.load(agentID)
	if err != nil {
		return false, err
	}
	record := previous
	record.Rooms = append([]roomAdmissionEntry(nil), previous.Rooms...)
	if !found {
		// The cards held before any room admitted them are a contact's or a
		// session's.
		held, err := c.Cards.holdsAny(agentID)
		if err != nil {
			return false, err
		}
		record = roomAdmissionRecord{Schema: roomAdmissionSchema, AgentID: agentID, Direct: held}
	}
	if entry, held := record.room(roomID); held {
		if entry.EndsAtUnix != endsAtUnix {
			return false, errRoomEndConflict
		}
	} else {
		if len(record.Rooms) >= maxAgentRoomAdmissions {
			return false, nil
		}
		record.Rooms = append(record.Rooms, roomAdmissionEntry{
			RoomID: roomID, AdmittedAtUnix: c.nowUnix(), EndsAtUnix: endsAtUnix,
		})
		if err := c.rooms.store(record); err != nil {
			return false, err
		}
	}
	if err := c.Cards.keep(card); err != nil {
		restoreErr := c.rooms.restore(previous, found, agentID)
		if errors.Is(err, errPeerCardsFull) && restoreErr == nil {
			return false, nil
		}
		return false, errors.Join(err, restoreErr)
	}
	return true, nil
}

// forgetRoomCards drops the room's admission of each Agent. Any failure is
// a retry of the whole batch; an Agent already forgotten is a no-op.
func (c *ChatCarrier) forgetRoomCards(roomID string, agentIDs []string) carrierapi.Response {
	seen := make(map[string]struct{}, len(agentIDs))
	for _, agentID := range agentIDs {
		if !agentIDPattern.MatchString(agentID) {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		if _, duplicate := seen[agentID]; duplicate {
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		}
		seen[agentID] = struct{}{}
	}
	for _, agentID := range agentIDs {
		if err := c.forgetRoomCard(roomID, agentID); err != nil {
			c.report("chat.room-cards", err)
			return carrierapi.Retry()
		}
	}
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied}
}

// forgetRoomCard drops one room's admission of agentID. Its cards are
// removed only when no admission is left; they go before the record, so a
// crash in between leaves the record to finish the removal on a retry.
func (c *ChatCarrier) forgetRoomCard(roomID, agentID string) error {
	unlock, err := c.lockAdmissions()
	if err != nil {
		return err
	}
	defer unlock()
	record, found, err := c.rooms.load(agentID)
	if err != nil {
		return err
	}
	if !found {
		// A direct admission holds the cards, or nothing is held at all.
		return nil
	}
	remaining, removed := record.withoutRoom(roomID)
	if remaining.holds() {
		if !removed {
			return nil
		}
		return c.rooms.store(remaining)
	}
	if _, err := c.Cards.forgetAgent(agentID); err != nil {
		return err
	}
	return c.rooms.remove(agentID)
}

// agents lists the Agents the store holds a record file for, by file name.
func (a *roomAdmissions) agents() ([]string, error) {
	entries, err := os.ReadDir(a.directory)
	if err != nil {
		return nil, errors.New("servicebridge: read the room admission directory")
	}
	var out []string
	for _, entry := range entries {
		if relayOutboxFilePattern.MatchString(entry.Name()) {
			out = append(out, "agent_"+strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	return out, nil
}

// roomEnd returns the end the store holds for roomID, if any peer is
// admitted under it. An unreadable record is reported and skipped.
func (c *ChatCarrier) roomEnd(roomID string) (uint64, bool, error) {
	unlock, err := c.lockAdmissions()
	if err != nil {
		return 0, false, err
	}
	defer unlock()
	agents, err := c.rooms.agents()
	if err != nil {
		return 0, false, err
	}
	for _, agentID := range agents {
		record, found, err := c.rooms.load(agentID)
		if err != nil {
			c.report("chat.room-cards", fmt.Errorf("servicebridge: room admission record of %s skipped: %w",
				agentID, err))
			continue
		}
		if !found {
			continue
		}
		if entry, held := record.room(roomID); held {
			return entry.EndsAtUnix, true, nil
		}
	}
	return 0, false, nil
}

// roomAdmissionDue is one room admission past its drop time.
type roomAdmissionDue struct {
	roomID  string
	agentID string
}

// sweepRoomAdmissions drops every room admission whose room ended at least
// carrierapi.RoomEndSlackSeconds ago, through the forget path, which keeps
// the cards another admission holds. It runs when the carrier opens and on
// every maintenance pass, so admissions a daemon never forgot (it crashed,
// or its forget failed) end with their room. An unreadable record is
// reported and skipped; the others are still swept.
func (c *ChatCarrier) sweepRoomAdmissions() error {
	if c == nil {
		return errChatInvalidLane
	}
	now := c.nowUnix()
	if now == 0 {
		return errors.New("servicebridge: the clock is not set")
	}
	unlock, err := c.lockAdmissions()
	if err != nil {
		return err
	}
	agents, err := c.rooms.agents()
	var due []roomAdmissionDue
	for _, agentID := range agents {
		record, found, loadErr := c.rooms.load(agentID)
		if loadErr != nil {
			c.report("chat.room-cards", fmt.Errorf("servicebridge: room admission record of %s skipped by the "+
				"sweep: %w", agentID, loadErr))
			continue
		}
		if !found {
			continue
		}
		for _, entry := range record.Rooms {
			if drop, valid := entry.dropAt(); valid && now >= drop {
				due = append(due, roomAdmissionDue{roomID: entry.RoomID, agentID: agentID})
			}
		}
	}
	unlock()
	if err != nil {
		return err
	}
	var failures []error
	for _, admission := range due {
		if err := c.forgetRoomCard(admission.roomID, admission.agentID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Withdraw implements carrierapi.Handler: carrier.withdraw. The envelope
// journaled under the key is withdrawn from every relay that may hold it,
// in the background passes, and never deposited again; a key this node
// never journaled is ignored, and one journaled for another peer refused.
func (c *ChatCarrier) Withdraw(ctx context.Context, request carrierapi.Request) carrierapi.Response {
	if c == nil || ctx == nil {
		return carrierapi.Retry()
	}
	peer := request.RecipientAgentID
	if !agentIDPattern.MatchString(peer) || !idempotencyKeyPattern.MatchString(request.IdempotencyKey) {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
	unlock := c.lockPeer(peer)
	defer unlock()
	entry, err := c.Transport.journalState(request.IdempotencyKey)
	if err != nil {
		c.report("chat.withdraw", err)
		return carrierapi.Retry()
	}
	if !entry.Found {
		return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultIgnored}
	}
	if entry.Packet.RecipientAgentID != peer {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest)
	}
	if _, err := c.Transport.Withdraw(request.IdempotencyKey); err != nil {
		c.report("chat.withdraw", err)
		return carrierapi.Retry()
	}
	return carrierapi.Withdrawn()
}

// roomPacer is a token bucket per relay for kind-3 deposits.
type roomPacer struct {
	now     func() time.Time
	mutex   sync.Mutex
	buckets map[string]*roomBucket
}

type roomBucket struct {
	tokens int
	at     time.Time
}

func newRoomPacer(now func() time.Time) *roomPacer {
	if now == nil {
		now = time.Now
	}
	return &roomPacer{now: now, buckets: map[string]*roomBucket{}}
}

// refill adds the tokens elapsed since the bucket's time, up to the burst.
// A clock that went back adds nothing and restarts the interval.
func (b *roomBucket) refill(now time.Time) {
	if now.Before(b.at) || b.tokens >= RoomDepositBurst {
		b.at = now
		if b.tokens > RoomDepositBurst {
			b.tokens = RoomDepositBurst
		}
		return
	}
	steps := int64(now.Sub(b.at) / roomDepositInterval)
	if steps <= 0 {
		return
	}
	missing := int64(RoomDepositBurst - b.tokens)
	if steps >= missing {
		b.tokens, b.at = RoomDepositBurst, now
		return
	}
	// steps < missing <= RoomDepositBurst: neither sum below can overflow.
	b.tokens += int(steps)
	b.at = b.at.Add(time.Duration(steps * int64(roomDepositInterval)))
}

// allow reports whether one deposit of a frame kind may go to relay now,
// taking its token. Only kind 3 is paced. With every bucket slot taken by a
// relay that is not full, a new relay waits.
func (p *roomPacer) allow(relay string, kind uint8) bool {
	if kind != relayframe.KindRoom {
		return true
	}
	if p == nil || relay == "" {
		return false
	}
	now := p.now()
	p.mutex.Lock()
	defer p.mutex.Unlock()
	bucket := p.buckets[relay]
	if bucket == nil {
		if len(p.buckets) >= maxRoomPacingRelays {
			p.dropFullLocked(now)
			if len(p.buckets) >= maxRoomPacingRelays {
				return false
			}
		}
		bucket = &roomBucket{tokens: RoomDepositBurst, at: now}
		p.buckets[relay] = bucket
	}
	bucket.refill(now)
	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

// dropFullLocked forgets the buckets that are full again: the same as none.
func (p *roomPacer) dropFullLocked(now time.Time) {
	for relay, bucket := range p.buckets {
		bucket.refill(now)
		if bucket.tokens >= RoomDepositBurst {
			delete(p.buckets, relay)
		}
	}
}

// RoomPacingView is one relay's kind-3 deposit bucket as status shows it.
type RoomPacingView struct {
	Relay     string `json:"relay"`
	Tokens    int    `json:"tokens"`
	Burst     int    `json:"burst"`
	PerMinute int    `json:"per_minute"`
}

// views lists the buckets not yet full again; a relay not listed has its
// full burst.
func (p *roomPacer) views() []RoomPacingView {
	if p == nil {
		return nil
	}
	now := p.now()
	p.mutex.Lock()
	defer p.mutex.Unlock()
	out := []RoomPacingView{}
	for relay, bucket := range p.buckets {
		bucket.refill(now)
		if bucket.tokens >= RoomDepositBurst {
			continue
		}
		out = append(out, RoomPacingView{
			Relay: relay, Tokens: bucket.tokens, Burst: RoomDepositBurst, PerMinute: RoomDepositsPerMinute,
		})
	}
	slices.SortFunc(out, func(a, b RoomPacingView) int { return strings.Compare(a.Relay, b.Relay) })
	return out
}

// roomFrameIsApplication reports whether a kind-3 frame is an application
// object, whose packet lives only the smallest relay TTL of the peer's card
// (it is deposited once), or a handshake part, which takes the copy rule.
// A part 0 whose room object does not parse is malformed; applications are
// never split.
func roomFrameIsApplication(frame relayframe.Frame) (bool, error) {
	if frame.Kind != relayframe.KindRoom || frame.PartIndex != 0 {
		return false, nil
	}
	_, objectType, err := relayframe.RoomObjectPrefix(frame.Part)
	if err != nil {
		return false, err
	}
	if objectType == relayframe.RoomApplication && frame.PartCount != 1 {
		return false, relayframe.ErrRoomObjectMalformed
	}
	return objectType == relayframe.RoomApplication, nil
}
