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
)

// Inbox limits.
const (
	DefaultMaxAssembliesPerSender = 8
	DefaultMaxAssemblies          = 64
	doneMarker                    = "done"
	heldMarker                    = "held"
	senderFile                    = "sender"
)

var assemblyNamePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

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

// Message is a complete, digest-checked rail message from one sender.
type Message struct {
	Key           string
	SenderAgentID string
	Kind          byte
	ActorAccount  [32]byte
	RequestID     uint64
	RequestHash   [32]byte
	Body          []byte
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

// Put stores one frame from a verified sender Agent.
func (inbox *Inbox) Put(sender string, frame Frame) (InboxStatus, *Message, error) {
	if inbox == nil || !agentIDPattern.MatchString(sender) {
		return 0, nil, errors.New("servicebridge: invalid inbox write")
	}
	if err := validateFrame(frame); err != nil {
		return 0, nil, err
	}
	inbox.mutex.Lock()
	defer inbox.mutex.Unlock()
	key := assemblyKey(sender, frame)
	directory := filepath.Join(inbox.root, key)
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
		if err = inbox.createAssembly(key, sender); err != nil {
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
			return 0, nil, errors.New("servicebridge: a frame conflicts with the stored frame of the same index")
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
func (inbox *Inbox) createAssembly(key, sender string) error {
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
	if err := os.Rename(staging, filepath.Join(inbox.root, key)); err != nil {
		return errors.New("servicebridge: publish assembly")
	}
	published = true
	return syncDirectory(inbox.root)
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
		return errors.New("servicebridge: too many open rail messages; retry later")
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
	if err := writeSynced(filepath.Join(directory, heldMarker), []byte("1")); err != nil &&
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
		if name == senderFile || name == doneMarker || name == attemptsFile || name == heldMarker {
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
	first := frames[0]
	return &Message{
		Key: key, SenderAgentID: string(sender), Kind: first.Kind, ActorAccount: first.ActorAccount,
		RequestID: first.RequestID, RequestHash: first.RequestHash, Body: body,
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
