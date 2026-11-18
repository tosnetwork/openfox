package servicebridge

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// Inbox limits.
const (
	DefaultMaxAssembliesPerSender = 8
	DefaultMaxAssemblies          = 64
	doneMarker                    = "done"
	heldMarker                    = "held"
	senderFile                    = "sender"
	packetFile                    = "packet"
)

var assemblyNamePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrInboxRefused reports a frame the inbox refuses for what it is or for
// the inbox's bounds, not for a failing disk: storing it again later gives
// the same answer until the sender delivers again.
var ErrInboxRefused = errors.New("servicebridge: the inbox refuses the frame")

// InboxStatus tells what a Put did.
type InboxStatus int

const (
	// InboxPartial stored the frame; the message is not complete yet.
	InboxPartial InboxStatus = iota
	// InboxComplete stored the last frame; the message is ready.
	InboxComplete
	// InboxDuplicate saw a frame of a message already processed.
	InboxDuplicate
)

// PacketFields are the Agent Packet fields a rail frame arrived with
// (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 2.1): the purchased
// Capability and the Accepted Quote commitment. The sender sets them; the
// handlers compare them with the task's Quote or the stored request.
type PacketFields struct {
	CapabilityID    string
	QuoteCommitment string
}

var quoteCommitmentPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)

func (f PacketFields) valid() bool {
	return capabilityPattern.MatchString(f.CapabilityID) && quoteCommitmentPattern.MatchString(f.QuoteCommitment)
}

func (f PacketFields) encode() []byte {
	return []byte(f.CapabilityID + "\n" + f.QuoteCommitment)
}

func decodePacketFields(raw []byte) (PacketFields, bool) {
	capability, quote, found := strings.Cut(string(raw), "\n")
	fields := PacketFields{CapabilityID: capability, QuoteCommitment: quote}
	return fields, found && fields.valid()
}

// Message is a complete, digest-checked rail message from one sender.
type Message struct {
	Key           string
	SenderAgentID string
	Kind          byte
	ActorAccount  [32]byte
	RequestID     uint64
	RequestHash   [32]byte
	Body          []byte
	// Packet holds the packet fields every frame of the message arrived
	// with; frames whose packets name other values are refused.
	Packet PacketFields
}

func (m Message) shared() railwork.Message {
	return railwork.Message{
		SenderAgentID: m.SenderAgentID, Kind: railwork.Kind(m.Kind),
		Binding:       railwork.Binding{ActorAccount: m.ActorAccount, RequestID: m.RequestID, RequestHash: m.RequestHash},
		MessageDigest: sha256.Sum256(m.Body), Body: m.Body,
	}
}

// Inbox durably assembles frames from verified packets. One process owns
// it. A frame is on disk (file and directory synced) before Put returns, so
// the packet may be acknowledged to the Messenger only afterwards.
type Inbox struct {
	root                 string
	mutex                sync.Mutex
	maxPerSender, maxAll int
}

// OpenInbox opens or creates an owner-private inbox directory.
func OpenInbox(directory string, maxPerSender, maxAll int) (*Inbox, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("servicebridge: inbox directory must be clean and absolute")
	}
	if maxPerSender <= 0 || maxAll <= 0 || maxPerSender > maxAll || maxAll > 4096 {
		return nil, errors.New("servicebridge: inbox bounds are invalid")
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	if err := removeStaging(directory); err != nil {
		return nil, err
	}
	return &Inbox{root: directory, maxPerSender: maxPerSender, maxAll: maxAll}, nil
}

func assemblyKey(sender string, frame Frame) string {
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], frame.RequestID)
	hash := sha256.New()
	hash.Write([]byte("tos.openfox.rail-assembly.v1\x00" + sender + "\x00"))
	hash.Write([]byte{frame.Kind})
	hash.Write(frame.ActorAccount[:])
	hash.Write(number[:])
	hash.Write(frame.RequestHash[:])
	hash.Write(frame.MessageDigest[:])
	return hex.EncodeToString(hash.Sum(nil))
}

// Put stores one frame from a verified sender Agent with the packet fields
// it arrived with. Every frame of one message must arrive with the same
// fields: a frame whose packet names others is refused.
func (inbox *Inbox) Put(sender string, packet PacketFields, frame Frame) (InboxStatus, *Message, error) {
	if inbox == nil || !agentIDPattern.MatchString(sender) {
		return 0, nil, errors.New("servicebridge: invalid inbox write")
	}
	if !packet.valid() {
		return 0, nil, fmt.Errorf("%w: the packet does not name a Capability and an Accepted Quote", ErrInboxRefused)
	}
	if err := validateFrame(frame); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrInboxRefused, err)
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	key := assemblyKey(sender, frame)
	directory := filepath.Join(inbox.root, key)
	if _, err := os.Lstat(directory); err == nil {
		if err = inbox.matchPacket(directory, packet); err != nil {
			return 0, nil, err
		}
	}
	if _, err := os.Lstat(filepath.Join(directory, doneMarker)); err == nil {
		// The frames stay until pruning, so the processed message is handed
		// back whole: a duplicate is handled again (re-acknowledged,
		// re-admitted idempotently), never with an empty body.
		message, complete, err := inbox.assemble(key)
		if err != nil {
			return 0, nil, err
		}
		if !complete {
			return 0, nil, errors.New("servicebridge: a processed message lost its frames")
		}
		return InboxDuplicate, message, nil
	}
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		if err = inbox.admitAssembly(sender); err != nil {
			return 0, nil, err
		}
		if err = inbox.createAssembly(key, sender, packet); err != nil {
			return 0, nil, err
		}
	} else if err != nil {
		return 0, nil, errors.New("servicebridge: stat assembly")
	}
	encoded, err := EncodeFrame(frame)
	if err != nil {
		return 0, nil, err
	}
	path := filepath.Join(directory, strconv.Itoa(int(frame.Index)))
	if existing, existingErr := readPrivateFile(path, frameHeader+MaxChunkData); existingErr == nil {
		if string(existing) != string(encoded) {
			return 0, nil, fmt.Errorf("%w: a frame conflicts with the stored frame of the same index",
				ErrInboxRefused)
		}
	} else if errors.Is(existingErr, os.ErrNotExist) {
		if existingErr = writeSynced(path, encoded); existingErr != nil {
			return 0, nil, existingErr
		}
	} else {
		return 0, nil, existingErr
	}
	message, complete, err := inbox.assemble(key)
	if err != nil {
		// A complete set that does not reproduce its digest can only come
		// from its own authenticated sender; it is discarded so a fresh
		// delivery of the real message can assemble.
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			return 0, nil, errors.Join(err, errors.New("servicebridge: discard inconsistent assembly"))
		}
		return 0, nil, err
	}
	if !complete {
		return InboxPartial, nil, nil
	}
	return InboxComplete, message, nil
}

// createAssembly makes an assembly directory visible only once its sender is
// durable: a crash part way leaves a staging directory no listing reads, so
// it cannot block the other messages.
func (inbox *Inbox) createAssembly(key, sender string, packet PacketFields) error {
	staging := filepath.Join(inbox.root, stagingPrefix+key)
	if err := os.RemoveAll(staging); err != nil {
		return errors.New("servicebridge: clear assembly staging")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.Mkdir(staging, 0o700); err != nil {
		return errors.New("servicebridge: create assembly")
	}
	if err := writeSynced(filepath.Join(staging, senderFile), []byte(sender)); err != nil {
		return err
	}
	if err := writeSynced(filepath.Join(staging, packetFile), packet.encode()); err != nil {
		return err
	}
	if err := os.Rename(staging, filepath.Join(inbox.root, key)); err != nil {
		return errors.New("servicebridge: publish assembly")
	}
	published = true
	return syncDirectory(inbox.root)
}

// matchPacket requires a frame's packet fields to equal the ones the
// assembly holds. An assembly stored before packet fields were kept takes
// the fields of the next frame that reaches it.
func (inbox *Inbox) matchPacket(directory string, packet PacketFields) error {
	path := filepath.Join(directory, packetFile)
	raw, err := readPrivateFile(path, 256)
	if errors.Is(err, os.ErrNotExist) {
		return writeSynced(path, packet.encode())
	}
	if err != nil {
		return err
	}
	stored, ok := decodePacketFields(raw)
	if !ok {
		return errors.New("servicebridge: an assembly's packet fields are unreadable")
	}
	if stored != packet {
		return fmt.Errorf("%w: the packet names another Capability or Accepted Quote than the message's other frames",
			ErrInboxRefused)
	}
	return nil
}

// countOpen counts the assemblies not marked done whose held state equals
// held, in total and from sender. Held tasks have their own bound, so tasks
// parked while admission is paused never take the room that results and
// acknowledgements of already admitted work need.
func (inbox *Inbox) countOpen(sender string, held bool, except string) (int, int, error) {
	entries, err := os.ReadDir(inbox.root)
	if err != nil {
		return 0, 0, errors.New("servicebridge: read inbox")
	}
	open, fromSender := 0, 0
	for _, entry := range entries {
		if !assemblyNamePattern.MatchString(entry.Name()) || entry.Name() == except {
			continue
		}
		directory := filepath.Join(inbox.root, entry.Name())
		if _, err := os.Lstat(filepath.Join(directory, doneMarker)); err == nil {
			continue
		}
		_, heldErr := os.Lstat(filepath.Join(directory, heldMarker))
		if (heldErr == nil) != held {
			continue
		}
		open++
		if owner, err := readPrivateFile(
			filepath.Join(directory, senderFile),
			128,
		); err == nil &&
			string(owner) == sender {
			fromSender++
		}
	}
	return open, fromSender, nil
}

func (inbox *Inbox) admitAssembly(sender string) error {
	open, fromSender, err := inbox.countOpen(sender, false, "")
	if err != nil {
		return err
	}
	if open >= inbox.maxAll || fromSender >= inbox.maxPerSender {
		return fmt.Errorf("%w: too many open rail messages; retry later", ErrInboxRefused)
	}
	return nil
}

// ErrHoldFull reports that no more messages may be held; the caller retires
// the message instead.
var ErrHoldFull = errors.New("servicebridge: too many held rail messages")

// Hold parks a complete message that cannot be handled yet (a task while
// admission is paused). A held message stays pending, so it is handled again
// on every round, but it no longer counts against the open-message bounds;
// held messages have the same bounds of their own. Holding an already held
// or processed message does nothing.
func (inbox *Inbox) Hold(key string) error {
	return inbox.hold(key, holdForPause)
}

// Why a message is held. A held marker written before causes existed holds
// the pause's value.
const (
	holdForPause    = "1"
	holdForExecutor = "executor"
)

// HoldForExecutor parks a task that was not admitted because the executor
// service could not run it then. It is held as Hold holds a paused task, and
// UnreadySince finds it.
func (inbox *Inbox) HoldForExecutor(key string) error {
	return inbox.hold(key, holdForExecutor)
}

// UnreadySince lists the pending messages held for the executor, with the
// time each was first held.
func (inbox *Inbox) UnreadySince() (map[string]time.Time, error) {
	if inbox == nil {
		return nil, errors.New("servicebridge: invalid inbox")
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	entries, err := os.ReadDir(inbox.root)
	if err != nil {
		return nil, errors.New("servicebridge: read inbox")
	}
	out := map[string]time.Time{}
	for _, entry := range entries {
		if !assemblyNamePattern.MatchString(entry.Name()) {
			continue
		}
		directory := filepath.Join(inbox.root, entry.Name())
		if _, doneErr := os.Lstat(filepath.Join(directory, doneMarker)); doneErr == nil {
			continue
		}
		marker := filepath.Join(directory, heldMarker)
		info, statErr := os.Lstat(marker)
		if statErr != nil {
			continue
		}
		cause, readErr := readPrivateFile(marker, 16)
		if readErr != nil {
			return nil, readErr
		}
		if string(cause) == holdForExecutor {
			out[entry.Name()] = info.ModTime()
		}
	}
	return out, nil
}

func (inbox *Inbox) hold(key, cause string) error {
	if inbox == nil || !assemblyNamePattern.MatchString(key) {
		return errors.New("servicebridge: invalid inbox hold")
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	directory := filepath.Join(inbox.root, key)
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() {
		return errors.New("servicebridge: no such assembly")
	}
	for _, marker := range []string{doneMarker, heldMarker} {
		if _, err := os.Lstat(filepath.Join(directory, marker)); err == nil {
			return nil
		}
	}
	sender, err := readPrivateFile(filepath.Join(directory, senderFile), 128)
	if err != nil {
		return errors.New("servicebridge: assembly sender is unreadable")
	}
	held, fromSender, err := inbox.countOpen(string(sender), true, key)
	if err != nil {
		return err
	}
	if held >= inbox.maxAll || fromSender >= inbox.maxPerSender {
		return ErrHoldFull
	}
	if err := writeSynced(filepath.Join(directory, heldMarker), []byte(cause)); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func (inbox *Inbox) assemble(key string) (*Message, bool, error) {
	directory := filepath.Join(inbox.root, key)
	sender, err := readPrivateFile(filepath.Join(directory, senderFile), 128)
	if err != nil || !agentIDPattern.Match(sender) {
		return nil, false, errors.New("servicebridge: assembly sender is unreadable")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, false, errors.New("servicebridge: read assembly")
	}
	var frames []Frame
	for _, entry := range entries {
		name := entry.Name()
		if name == senderFile || name == packetFile || name == doneMarker || name == attemptsFile || name == heldMarker {
			continue
		}
		// A crash between creating and renaming a counter update leaves its
		// temporary file behind. It never holds a frame, so it must not make
		// the assembly unreadable and block dispatch of every other message.
		if strings.HasPrefix(name, stateUpdatePrefix) && entry.Type().IsRegular() {
			continue
		}
		index, indexErr := strconv.Atoi(name)
		if indexErr != nil || index < 0 || index >= MaxChunks || strconv.Itoa(index) != name {
			return nil, false, fmt.Errorf("servicebridge: unexpected assembly entry %q", name)
		}
		raw, indexErr := readPrivateFile(filepath.Join(directory, name), frameHeader+MaxChunkData)
		if indexErr != nil {
			return nil, false, indexErr
		}
		frame, indexErr := DecodeFrame(raw)
		if indexErr != nil || int(frame.Index) != index || assemblyKey(string(sender), frame) != key {
			return nil, false, errors.New("servicebridge: a stored frame does not belong to its assembly")
		}
		frames = append(frames, frame)
	}
	if len(frames) == 0 || len(frames) < int(frames[0].Count) {
		return nil, false, nil
	}
	body, err := JoinFrames(frames)
	if err != nil {
		return nil, false, err
	}
	// An assembly stored before packet fields were kept has none; its
	// message then names no Capability or Quote and the handlers refuse it,
	// and the sender's next delivery records the fields.
	var packet PacketFields
	if raw, packetErr := readPrivateFile(filepath.Join(directory, packetFile), 256); packetErr == nil {
		stored, ok := decodePacketFields(raw)
		if !ok {
			return nil, false, errors.New("servicebridge: an assembly's packet fields are unreadable")
		}
		packet = stored
	} else if !errors.Is(packetErr, os.ErrNotExist) {
		return nil, false, packetErr
	}
	first := frames[0]
	return &Message{
		Key: key, SenderAgentID: string(sender), Kind: first.Kind, ActorAccount: first.ActorAccount,
		RequestID: first.RequestID, RequestHash: first.RequestHash, Body: body, Packet: packet,
	}, true, nil
}

// Pending returns every complete message not yet marked done, oldest key
// first, so a restart processes what was acknowledged before the crash.
func (inbox *Inbox) Pending() ([]Message, error) {
	if inbox == nil {
		return nil, errors.New("servicebridge: invalid inbox")
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	entries, err := os.ReadDir(inbox.root)
	if err != nil {
		return nil, errors.New("servicebridge: read inbox")
	}
	var out []Message
	for _, entry := range entries {
		if !assemblyNamePattern.MatchString(entry.Name()) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(inbox.root, entry.Name(), doneMarker)); err == nil {
			continue
		}
		message, complete, err := inbox.assemble(entry.Name())
		if err != nil {
			return nil, err
		}
		if complete {
			out = append(out, *message)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Done marks a message processed; later frames of it report a duplicate.
// The frames are kept until Prune so the decision stays auditable.
func (inbox *Inbox) Done(key string) error {
	if inbox == nil || !assemblyNamePattern.MatchString(key) {
		return errors.New("servicebridge: invalid inbox completion")
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	directory := filepath.Join(inbox.root, key)
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() {
		return errors.New("servicebridge: no such assembly")
	}
	if err := writeSynced(
		filepath.Join(directory, doneMarker),
		[]byte("1"),
	); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// Inbox retention defaults. An incomplete message whose frames stop
// arriving frees its slot after IncompleteRetention; a processed message is
// kept for DoneRetention so its duplicates are recognized while the peer can
// still redeliver (results are redelivered for at most the manifest
// retention, packets live at most a day).
const (
	IncompleteRetention = time.Hour
	DoneRetention       = 48 * time.Hour
	maxHandlingAttempts = 8
	attemptsFile        = "attempts"
)

// Prune removes incomplete assemblies untouched for longer than incomplete
// and processed ones older than done.
func (inbox *Inbox) Prune(now time.Time, incomplete, done time.Duration) error {
	if inbox == nil || incomplete <= 0 || done <= 0 {
		return errors.New("servicebridge: invalid inbox prune")
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	entries, err := os.ReadDir(inbox.root)
	if err != nil {
		return errors.New("servicebridge: read inbox")
	}
	for _, entry := range entries {
		if !assemblyNamePattern.MatchString(entry.Name()) {
			continue
		}
		directory := filepath.Join(inbox.root, entry.Name())
		age := incomplete
		marker, markerErr := os.Lstat(filepath.Join(directory, doneMarker))
		info, statErr := entry.Info()
		if statErr != nil {
			return errors.New("servicebridge: stat assembly")
		}
		touched := info.ModTime()
		if markerErr == nil {
			age, touched = done, marker.ModTime()
		}
		if now.Sub(touched) > age {
			if err := os.RemoveAll(directory); err != nil {
				return errors.New("servicebridge: prune assembly")
			}
		}
	}
	return syncDirectory(inbox.root)
}

// Failed records one failed handling of a complete message; after
// maxHandlingAttempts it is marked done, so a message that can never be
// handled stops being retried while a transient failure is retried.
func (inbox *Inbox) Failed(key string) error {
	if inbox == nil || !assemblyNamePattern.MatchString(key) {
		return errors.New("servicebridge: invalid inbox failure")
	}
	inbox.mutex.Lock()
	path := filepath.Join(inbox.root, key, attemptsFile)
	count := 0
	if raw, err := readPrivateFile(path, 16); err == nil {
		parsed, parseErr := strconv.Atoi(string(raw))
		if parseErr != nil || parsed <= 0 || parsed >= maxHandlingAttempts || strconv.Itoa(parsed) != string(raw) {
			// A corrupt counter retires the message rather than blocking
			// every later dispatch on the same unreadable file.
			inbox.mutex.Unlock()
			return errors.Join(errors.New("servicebridge: corrupt handling attempt counter; message retired"),
				inbox.Done(key))
		}
		count = parsed
	} else if !errors.Is(err, os.ErrNotExist) {
		inbox.mutex.Unlock()
		return err
	}
	count++
	var err error
	if count == 1 {
		err = writeSynced(path, []byte(strconv.Itoa(count)))
	} else {
		err = replaceSynced(path, []byte(strconv.Itoa(count)))
	}
	inbox.mutex.Unlock()
	if err != nil {
		return err
	}
	if count >= maxHandlingAttempts {
		return inbox.Done(key)
	}
	return nil
}
