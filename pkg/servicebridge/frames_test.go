package servicebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fill(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = seed + byte(i*7)
	}
	return out
}

var (
	testActor   = [32]byte{0x77}
	testRequest = [32]byte{0x99}
	testBuyer   = "agent_" + strings.Repeat("b1", 32)
	testSeller  = "agent_" + strings.Repeat("5e", 32)
)

func TestAOneMiBTaskSplitsIntoEighteenCanonicalFramesAndRejoins(t *testing.T) {
	task := Task{Header: TaskHeader{
		BuyerAgentID: testBuyer,
		BuyerWallet:  "0:" + strings.Repeat("21", 32),
		CapabilityID: "cap_" + strings.Repeat(
			"33",
			32,
		),
		CapabilityVersion: "1.0.0",
		ExecutionID:       strings.Repeat("01", 32),
		ExecutionNonce:    strings.Repeat("4e", 32),
		RequestID:         4,
		CallLT:            10,
		CallHash:          strings.Repeat("0a", 32),
	}, Package: fill(3000, 1), Archive: fill(MaxInlineInputBytes, 3)}
	body, err := EncodeTask(task)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := SplitMessage(FrameTask, testActor, 4, testRequest, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 18 {
		t.Fatalf("a 1 MiB task took %d frames", len(frames))
	}
	shuffled := append([]Frame(nil), frames...)
	rand.New(rand.NewSource(1)).
		Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	for i, frame := range shuffled {
		encoded, encodedErr := EncodeFrame(frame)
		if encodedErr != nil || len(encoded) > frameHeader+MaxChunkData {
			t.Fatalf("frame %d: %d bytes %v", i, len(encoded), encodedErr)
		}
		decoded, encodedErr := DecodeFrame(encoded)
		if encodedErr != nil {
			t.Fatal(encodedErr)
		}
		shuffled[i] = decoded
	}
	joined, err := JoinFrames(shuffled)
	if err != nil || !bytes.Equal(joined, body) {
		t.Fatalf("rejoin: %v", err)
	}
	decoded, err := DecodeTask(joined)
	if err != nil || !bytes.Equal(decoded.Archive, task.Archive) || !bytes.Equal(decoded.Package, task.Package) {
		t.Fatalf("decode: %v", err)
	}
}

func TestATaskOverTheInlineLimitIsRefusedBeforeItIsFramed(t *testing.T) {
	task := Task{Header: TaskHeader{
		BuyerAgentID: testBuyer,
		BuyerWallet:  "0:" + strings.Repeat("21", 32),
		CapabilityID: "cap_" + strings.Repeat(
			"33",
			32,
		),
		CapabilityVersion: "1.0.0",
		ExecutionID:       strings.Repeat("01", 32),
		ExecutionNonce:    strings.Repeat("4e", 32),
		RequestID:         4,
		CallLT:            10,
		CallHash:          strings.Repeat("0a", 32),
	}, Package: fill(10, 1), Archive: fill(MaxInlineInputBytes+1, 3)}
	if _, err := EncodeTask(task); err == nil {
		t.Fatal("a 1 MiB + 1 archive was encoded")
	}
	if _, err := SplitMessage(FrameTask, testActor, 4, testRequest, fill(maxTaskMessageBytes+1, 1)); err == nil {
		t.Fatal("an oversized task message was framed")
	}
	task.Archive = nil
	if _, err := EncodeTask(task); err == nil {
		t.Fatal("an empty archive was encoded")
	}
}

func TestFramesRefuseEveryNonCanonicalShape(t *testing.T) {
	frames, err := SplitMessage(FrameResult, testActor, 1, testRequest, fill(2*MaxChunkData+5, 9))
	if err != nil {
		t.Fatal(err)
	}
	good, err := EncodeFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"magic":          func(b []byte) []byte { b[0] ^= 1; return b },
		"kind":           func(b []byte) []byte { b[6] = 9; return b },
		"index past end": func(b []byte) []byte { b[115] = 3; return b },
		"count":          func(b []byte) []byte { b[116] = 2; return b },
		"length":         func(b []byte) []byte { b[120] ^= 1; return b },
		"truncated":      func(b []byte) []byte { return b[:len(b)-1] },
	} {
		if _, err := DecodeFrame(mutate(append([]byte(nil), good...))); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	short := frames[0]
	short.Data = short.Data[:10]
	if _, err := EncodeFrame(short); err == nil {
		t.Error("a short non-final chunk was encoded")
	}
	if _, err := JoinFrames(frames[:2]); err == nil {
		t.Error("an incomplete set joined")
	}
	if _, err := JoinFrames([]Frame{frames[0], frames[0], frames[2]}); err == nil {
		t.Error("a repeated index joined")
	}
	tampered := append([]Frame(nil), frames...)
	tampered[2].Data = append([]byte(nil), tampered[2].Data...)
	tampered[2].Data[0] ^= 1
	if _, err := JoinFrames(tampered); err == nil {
		t.Error("a set whose content misses its digest joined")
	}
}

func TestMessageHeadersAreStrictAndCanonical(t *testing.T) {
	ack, err := EncodeAck(testRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeAck(ack); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"unknown field": append([]byte{0, 0, 0, 0}, []byte(`{"schema":"tos.openfox.rail-result-ack.v1","response_hash":"`+hex.EncodeToString(testRequest[:])+`","x":1}`)...),
		"spaced":        append([]byte{0, 0, 0, 0}, []byte(` {"schema":"tos.openfox.rail-result-ack.v1","response_hash":"`+hex.EncodeToString(testRequest[:])+`"}`)...),
		"other schema":  append([]byte{0, 0, 0, 0}, []byte(`{"schema":"tos.openfox.rail-task.v1","response_hash":"`+hex.EncodeToString(testRequest[:])+`"}`)...),
	} {
		length := len(raw) - 4
		raw[0], raw[1], raw[2], raw[3] = byte(length>>24), byte(length>>16), byte(length>>8), byte(length)
		if _, err = DecodeAck(raw); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	task := Task{Header: TaskHeader{
		BuyerAgentID: testBuyer,
		BuyerWallet:  "0:" + strings.Repeat("21", 32),
		CapabilityID: "cap_" + strings.Repeat(
			"33",
			32,
		),
		CapabilityVersion: "1.0.0",
		ExecutionID:       strings.Repeat("01", 32),
		ExecutionNonce:    strings.Repeat("4e", 32),
		RequestID:         4,
		CallLT:            10,
		CallHash:          strings.Repeat("0a", 32),
	}, Package: fill(10, 1), Archive: fill(100, 3)}
	body, err := EncodeTask(task)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if _, err := DecodeTask(body); err == nil {
		t.Error("a task whose archive misses its digest decoded")
	}
}

func openTestInbox(t *testing.T, perSender, all int) (*Inbox, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "inbox")
	inbox, err := OpenInbox(directory, perSender, all)
	if err != nil {
		t.Fatal(err)
	}
	return inbox, directory
}

func TestInboxAssemblesDurablyAndReportsDuplicatesAfterDone(t *testing.T) {
	inbox, directory := openTestInbox(t, 2, 4)
	body := fill(3*MaxChunkData-7, 5)
	frames, err := SplitMessage(FrameResult, testActor, 2, testRequest, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{2, 0} {
		status, _, statusErr := inbox.Put(testSeller, frames[index])
		if statusErr != nil || status != InboxPartial {
			t.Fatalf("frame %d: %v %v", index, status, statusErr)
		}
	}
	if status, _, statusErr := inbox.Put(testSeller, frames[0]); statusErr != nil || status != InboxPartial {
		t.Fatalf("a repeated frame: %v %v", status, statusErr)
	}
	stored := frames[0]
	stored.Data = fill(MaxChunkData, 7)
	if _, _, err = inbox.Put(testSeller, stored); err == nil {
		t.Fatal("a frame conflicting with the stored frame of its index was taken")
	}
	conflict := frames[1]
	conflict.Data = fill(MaxChunkData, 6)
	// A different body is a different message; a frame claiming the same
	// digest with other data fails when the set is joined.
	if _, _, err = inbox.Put(testSeller, conflict); err == nil {
		t.Fatal("a frame inconsistent with its message digest completed the message")
	}
	reopened, err := OpenInbox(directory, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Pending()
	if err == nil && len(pending) != 0 {
		t.Fatalf("an incomplete message is pending: %d", len(pending))
	}
	if _, err = os.Lstat(
		filepath.Join(directory, assemblyKey(testSeller, frames[0])),
	); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("the inconsistent assembly was kept: %v", err)
	}
	for _, index := range []int{0, 2} {
		if _, _, err = reopened.Put(testSeller, frames[index]); err != nil {
			t.Fatal(err)
		}
	}
	status, message, err := reopened.Put(testSeller, frames[1])
	if err != nil || status != InboxComplete || !bytes.Equal(message.Body, body) ||
		message.SenderAgentID != testSeller {
		t.Fatalf("complete: %v %v", status, err)
	}
	pending, err = reopened.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending after completion: %d %v", len(pending), err)
	}
	if err = reopened.Done(message.Key); err != nil {
		t.Fatal(err)
	}
	if pending, pendingErr := reopened.Pending(); pendingErr != nil || len(pending) != 0 {
		t.Fatalf("a done message is pending: %d %v", len(pending), pendingErr)
	}
	status, duplicate, err := reopened.Put(testSeller, frames[0])
	if err != nil || status != InboxDuplicate || duplicate == nil || !bytes.Equal(duplicate.Body, body) {
		t.Fatalf("a frame of a done message must hand back the whole message: %v %v", status, err)
	}
	// The same frames from another sender are another message.
	if status, _, err := reopened.Put(testBuyer, frames[0]); err != nil || status != InboxPartial {
		t.Fatalf("another sender's frame: %v %v", status, err)
	}
}

func TestInboxBoundsOpenMessagesPerSenderAndInTotal(t *testing.T) {
	inbox, _ := openTestInbox(t, 1, 2)
	message := func(seed byte) Frame {
		frames, err := SplitMessage(FrameTask, testActor, uint64(seed), testRequest, fill(2*MaxChunkData, seed))
		if err != nil {
			t.Fatal(err)
		}
		return frames[0]
	}
	if _, _, err := inbox.Put(testBuyer, message(1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inbox.Put(testBuyer, message(2)); err == nil {
		t.Fatal("a second open message from one sender was admitted")
	}
	if _, _, err := inbox.Put(testSeller, message(3)); err != nil {
		t.Fatal(err)
	}
	third := "agent_" + strings.Repeat("c3", 32)
	if _, _, err := inbox.Put(third, message(4)); err == nil {
		t.Fatal("an open message beyond the total bound was admitted")
	}
	if err := inbox.Prune(time.Now().Add(2*time.Hour), IncompleteRetention, DoneRetention); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inbox.Put(third, message(4)); err != nil {
		t.Fatalf("after pruning stale messages: %v", err)
	}
}

func TestInputDigestIsDomainSeparatedFromTheSourceDigest(t *testing.T) {
	source := sha256.Sum256([]byte("archive"))
	input := InputDigest(source)
	if input == source || input == ([32]byte{}) {
		t.Fatal("the input digest is the source digest")
	}
	if !errors.Is(ErrGenerationExpired, ErrGenerationExpired) {
		t.Fatal("unreachable")
	}
}

func TestInboxRetriesAFailedMessageAndThenGivesUp(t *testing.T) {
	inbox, _ := openTestInbox(t, 2, 4)
	frames, err := SplitMessage(FrameResult, testActor, 2, testRequest, fill(100, 5))
	if err != nil {
		t.Fatal(err)
	}
	_, message, err := inbox.Put(testSeller, frames[0])
	if err != nil || message == nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt < maxHandlingAttempts; attempt++ {
		if err := inbox.Failed(message.Key); err != nil {
			t.Fatal(err)
		}
		if pending, err := inbox.Pending(); err != nil || len(pending) != 1 {
			t.Fatalf("after %d failures the message is not retried: %d %v", attempt, len(pending), err)
		}
	}
	if err := inbox.Failed(message.Key); err != nil {
		t.Fatal(err)
	}
	if pending, err := inbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("a message that keeps failing is retried forever: %d %v", len(pending), err)
	}
}

func TestInboxIgnoresACounterUpdateLeftByAnInterruptedFailure(t *testing.T) {
	inbox, directory := openTestInbox(t, 2, 4)
	frames, err := SplitMessage(FrameResult, testActor, 2, testRequest, fill(100, 6))
	if err != nil {
		t.Fatal(err)
	}
	_, message, err := inbox.Put(testSeller, frames[0])
	if err != nil || message == nil {
		t.Fatal(err)
	}
	if err = inbox.Failed(message.Key); err != nil {
		t.Fatal(err)
	}
	// The temporary file replaceSynced writes before its rename, left as a
	// crash between the two would leave it.
	leftover, err := os.CreateTemp(filepath.Join(directory, message.Key), stateUpdatePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = leftover.WriteString("2"); err != nil {
		t.Fatal(err)
	}
	if err = leftover.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := inbox.Pending()
	if err != nil || len(pending) != 1 || pending[0].Key != message.Key {
		t.Fatalf("a leftover counter update blocks dispatch: %d %v", len(pending), err)
	}
	if err := inbox.Failed(message.Key); err != nil {
		t.Fatalf("the next failure cannot be recorded beside a leftover update: %v", err)
	}
}

func TestInboxStillRejectsAnUnexpectedDirectoryNamedLikeAnUpdate(t *testing.T) {
	inbox, directory := openTestInbox(t, 2, 4)
	frames, err := SplitMessage(FrameResult, testActor, 2, testRequest, fill(100, 7))
	if err != nil {
		t.Fatal(err)
	}
	_, message, err := inbox.Put(testSeller, frames[0])
	if err != nil || message == nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, message.Key, stateUpdatePrefix+"x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Pending(); err == nil {
		t.Fatal("an unexpected directory inside an assembly is accepted")
	}
}

func TestInboxPruneKeepsProcessedMessagesLongerThanIncompleteOnes(t *testing.T) {
	inbox, directory := openTestInbox(t, 4, 8)
	partial, err := SplitMessage(FrameTask, testActor, 1, testRequest, fill(2*MaxChunkData, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inbox.Put(testBuyer, partial[0]); err != nil {
		t.Fatal(err)
	}
	whole, err := SplitMessage(FrameResult, testActor, 2, testRequest, fill(10, 2))
	if err != nil {
		t.Fatal(err)
	}
	_, message, err := inbox.Put(testSeller, whole[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.Done(message.Key); err != nil {
		t.Fatal(err)
	}
	if err := inbox.Prune(time.Now().Add(2*time.Hour), IncompleteRetention, DoneRetention); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(
		filepath.Join(directory, assemblyKey(testBuyer, partial[0])),
	); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatal("a stale incomplete message kept its slot")
	}
	if status, _, err := inbox.Put(testSeller, whole[0]); err != nil || status != InboxDuplicate {
		t.Fatalf("a processed message was forgotten too early: %v %v", status, err)
	}
	if err := inbox.Prune(time.Now().Add(DoneRetention+time.Hour), IncompleteRetention, DoneRetention); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directory, message.Key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an old processed message was kept")
	}
}
