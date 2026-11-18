package servicebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// railVectorPath is a copy of the rail work frame vectors
// (spec/test-vectors/service-actor-rail-work-frames-v1.json) at the pinned
// ai commit; railVectorSHA256 pins the copy.
const (
	railVectorPath   = "testdata/service-actor-rail-work-frames-v1.json"
	railVectorSHA256 = "25392468743ed1f028aeb2146246310a4d13394ddd9fa7eb8bbaaaede347eed8"
)

type railVectors struct {
	Binding struct {
		ActorAccountHex string `json:"actor_account_hex"`
		RequestID       uint64 `json:"request_id"`
		RequestHashHex  string `json:"request_hash_hex"`
	} `json:"binding"`
	Messages []struct {
		Name          string         `json:"name"`
		Kind          byte           `json:"kind"`
		RequestID     *uint64        `json:"request_id"`
		Fields        map[string]any `json:"fields"`
		MessageBase64 string         `json:"message_base64"`
		MessageSHA256 string         `json:"message_sha256"`
		HeaderJSON    string         `json:"header_json"`
		Frames        []struct {
			HeaderHex   string `json:"header_hex"`
			FrameSHA256 string `json:"frame_sha256"`
		} `json:"frames"`
	} `json:"messages"`
	NegativeMessages []struct {
		Name   string `json:"name"`
		Kind   byte   `json:"kind"`
		Base64 string `json:"base64"`
	} `json:"negative_messages"`
}

var railArchiveRule = regexp.MustCompile(`^byte i is \((\d+) \+ 7\*i\) mod 256$`)

func loadRailVectors(t *testing.T) *railVectors {
	t.Helper()
	raw, err := os.ReadFile(railVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(raw); hex.EncodeToString(digest[:]) != railVectorSHA256 {
		t.Fatal("the vector copy differs from the pinned file")
	}
	var vectors railVectors
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return &vectors
}

func railHex32(t *testing.T, text string) [32]byte {
	t.Helper()
	var out [32]byte
	if err := decodeHex32(text, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// reencode decodes a message with OpenFox's own entry points and encodes it
// again from the decoded values.
func reencode(t *testing.T, kind byte, raw []byte) []byte {
	t.Helper()
	var (
		again []byte
		err   error
	)
	switch kind {
	case FrameTask:
		task, decodeErr := DecodeTask(raw)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		again, err = EncodeTask(task)
	case FrameResult:
		result, decodeErr := DecodeResult(raw)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		var card []byte
		if result.Header.ProviderKeyCard != "" {
			if card, err = base64.StdEncoding.DecodeString(result.Header.ProviderKeyCard); err != nil {
				t.Fatal(err)
			}
		}
		again, err = EncodeResultWithCard(railHex32(t, result.Header.ResponseHash), result.Receipt, result.Artifact, card)
	case FrameResultAck:
		ack, decodeErr := DecodeAck(raw)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		var card []byte
		if ack.BuyerKeyCard != "" {
			if card, err = base64.StdEncoding.DecodeString(ack.BuyerKeyCard); err != nil {
				t.Fatal(err)
			}
		}
		again, err = EncodeAckWithCard(railHex32(t, ack.ResponseHash), card)
	case FrameResultRequest:
		request, decodeErr := DecodeResultRequest(raw)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		var card []byte
		if request.BuyerKeyCard != "" {
			if card, err = base64.StdEncoding.DecodeString(request.BuyerKeyCard); err != nil {
				t.Fatal(err)
			}
		}
		again, err = EncodeResultRequest(card)
	default:
		t.Fatalf("kind %d", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return again
}

// The OpenFox entry points, now backed by the shared implementation, stay
// byte-compatible with the frames and messages OpenFox emitted before the
// switch: every positive vector re-encodes and re-frames to its exact bytes,
// and every negative message is refused.
func TestRailVectorsPassThroughOpenFoxsEntryPoints(t *testing.T) {
	vectors := loadRailVectors(t)
	actor := railHex32(t, vectors.Binding.ActorAccountHex)
	requestHash := railHex32(t, vectors.Binding.RequestHashHex)
	for _, message := range vectors.Messages {
		var raw []byte
		if message.MessageBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(message.MessageBase64)
			if err != nil {
				t.Fatal(err)
			}
			raw = decoded
		} else {
			rule, _ := message.Fields["archive_rule"].(string)
			size, _ := message.Fields["archive_bytes"].(float64)
			match := railArchiveRule.FindStringSubmatch(rule)
			if match == nil {
				t.Fatalf("%s: archive rule %q", message.Name, rule)
			}
			seed, err := strconv.Atoi(match[1])
			if err != nil {
				t.Fatal(err)
			}
			raw = binary.BigEndian.AppendUint32(nil, uint32(len(message.HeaderJSON)))
			raw = append(raw, message.HeaderJSON...)
			for index := 0; index < int(size); index++ {
				raw = append(raw, byte((seed+7*index)%256))
			}
		}
		if digest := sha256.Sum256(raw); hex.EncodeToString(digest[:]) != message.MessageSHA256 {
			t.Fatalf("%s: message digest", message.Name)
		}
		if again := reencode(t, message.Kind, raw); !bytes.Equal(again, raw) {
			t.Errorf("%s: re-encoding differs", message.Name)
		}
		requestID := vectors.Binding.RequestID
		if message.RequestID != nil {
			requestID = *message.RequestID
		}
		frames, err := SplitMessage(message.Kind, actor, requestID, requestHash, raw)
		if err != nil || len(frames) != len(message.Frames) {
			t.Fatalf("%s: %d frames err=%v", message.Name, len(frames), err)
		}
		for index, frame := range frames {
			encoded, encodeErr := EncodeFrame(frame)
			digest := sha256.Sum256(encoded)
			if encodeErr != nil || hex.EncodeToString(encoded[:frameHeader]) != message.Frames[index].HeaderHex ||
				hex.EncodeToString(digest[:]) != message.Frames[index].FrameSHA256 {
				t.Fatalf("%s: frame %d differs: %v", message.Name, index, encodeErr)
			}
		}
		joined, err := JoinFrames(frames)
		if err != nil || !bytes.Equal(joined, raw) {
			t.Fatalf("%s: join: %v", message.Name, err)
		}
	}
	for _, negative := range vectors.NegativeMessages {
		raw, err := base64.StdEncoding.DecodeString(negative.Base64)
		if err != nil {
			t.Fatal(err)
		}
		switch negative.Kind {
		case FrameTask:
			_, err = DecodeTask(raw)
		case FrameResult:
			_, err = DecodeResult(raw)
		case FrameResultAck:
			_, err = DecodeAck(raw)
		case FrameResultRequest:
			_, err = DecodeResultRequest(raw)
		}
		if err == nil {
			t.Errorf("negative message %s accepted", negative.Name)
		}
	}
}
