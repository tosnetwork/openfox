// Package servicebridge carries paid software work between an OpenFox buyer
// and an OpenFox provider on the Service Actor rail. The buyer discovers a
// published Capability, takes a Quote, and calls the Service Actor; the work
// and its result then travel as signed Agent Packets through the Messenger.
// Nothing a packet says is trusted: the provider admits work only while
// finalized state shows the paid request pending, and the buyer accepts a
// result only when its Receipt hashes to the finalized attested response.
package servicebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame kinds.
const (
	FrameTask      byte = 1
	FrameResult    byte = 2
	FrameResultAck byte = 3
)

const (
	frameMagic   = 0x4f465231 // OFR1
	frameVersion = 1
	frameHeader  = 4 + 2 + 1 + 32 + 8 + 32 + 32 + 4 + 1 + 1 + 4

	// MaxChunkData bounds the data one frame carries, so that the signed
	// Agent Packet JSON holding it stays inside the Messenger direct
	// application bound (96 KiB) with room for the signature and fields.
	MaxChunkData = 60 << 10
	// MaxChunks bounds the frames of one message.
	MaxChunks = 32
	// MaxMessageBytes bounds any one rail message.
	MaxMessageBytes = MaxChunks * MaxChunkData
	// MaxInlineInputBytes is the advertised inline work input: the largest
	// source archive a buyer may deliver.
	MaxInlineInputBytes = 1 << 20
	// MaxResultBytes bounds the artifact a result delivers.
	MaxResultBytes = 1<<20 + 64<<10
)

// Frame is one chunk of a rail message, bound to one Service Actor request.
type Frame struct {
	Kind          byte
	ActorAccount  [32]byte
	RequestID     uint64
	RequestHash   [32]byte
	MessageDigest [32]byte
	TotalLength   uint32
	Index         uint8
	Count         uint8
	Data          []byte
}

// EncodeFrame returns the canonical binary frame.
func EncodeFrame(frame Frame) ([]byte, error) {
	if err := validateFrame(frame); err != nil {
		return nil, err
	}
	out := make([]byte, 0, frameHeader+len(frame.Data))
	out = binary.BigEndian.AppendUint32(out, frameMagic)
	out = binary.BigEndian.AppendUint16(out, frameVersion)
	out = append(out, frame.Kind)
	out = append(out, frame.ActorAccount[:]...)
	out = binary.BigEndian.AppendUint64(out, frame.RequestID)
	out = append(out, frame.RequestHash[:]...)
	out = append(out, frame.MessageDigest[:]...)
	out = binary.BigEndian.AppendUint32(out, frame.TotalLength)
	out = append(out, frame.Index, frame.Count)
	out = binary.BigEndian.AppendUint32(out, uint32(len(frame.Data)))
	return append(out, frame.Data...), nil
}

// DecodeFrame parses one canonical frame and refuses any other shape.
func DecodeFrame(raw []byte) (Frame, error) {
	if len(raw) < frameHeader || len(raw) > frameHeader+MaxChunkData {
		return Frame{}, errors.New("servicebridge: frame is outside its size bounds")
	}
	if binary.BigEndian.Uint32(raw[0:4]) != frameMagic || binary.BigEndian.Uint16(raw[4:6]) != frameVersion {
		return Frame{}, errors.New("servicebridge: not a rail frame")
	}
	var frame Frame
	frame.Kind = raw[6]
	copy(frame.ActorAccount[:], raw[7:39])
	frame.RequestID = binary.BigEndian.Uint64(raw[39:47])
	copy(frame.RequestHash[:], raw[47:79])
	copy(frame.MessageDigest[:], raw[79:111])
	frame.TotalLength = binary.BigEndian.Uint32(raw[111:115])
	frame.Index, frame.Count = raw[115], raw[116]
	length := binary.BigEndian.Uint32(raw[117:121])
	if uint64(length) != uint64(len(raw)-frameHeader) {
		return Frame{}, errors.New("servicebridge: frame data length does not match")
	}
	frame.Data = append([]byte(nil), raw[frameHeader:]...)
	if err := validateFrame(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func messageBound(kind byte) (uint32, error) {
	switch kind {
	case FrameTask:
		return maxTaskMessageBytes, nil
	case FrameResult:
		return maxResultMessageBytes, nil
	case FrameResultAck:
		return maxAckMessageBytes, nil
	default:
		return 0, errors.New("servicebridge: unknown frame kind")
	}
}

func validateFrame(frame Frame) error {
	bound, err := messageBound(frame.Kind)
	if err != nil {
		return err
	}
	if frame.ActorAccount == ([32]byte{}) || frame.RequestHash == ([32]byte{}) || frame.MessageDigest == ([32]byte{}) {
		return errors.New("servicebridge: frame binding is incomplete")
	}
	if frame.TotalLength == 0 || frame.TotalLength > bound || frame.Count == 0 || frame.Count > MaxChunks ||
		frame.Index >= frame.Count || len(frame.Data) == 0 || len(frame.Data) > MaxChunkData {
		return errors.New("servicebridge: frame is outside its bounds")
	}
	expected, err := chunkLength(frame.TotalLength, frame.Index, frame.Count)
	if err != nil || expected != len(frame.Data) {
		return errors.New("servicebridge: frame chunking is not canonical")
	}
	return nil
}

// chunkLength is the exact length chunk index of a message of total bytes
// split into count chunks carries: every chunk is MaxChunkData except the
// last, so one message has exactly one chunking.
func chunkLength(total uint32, index, count uint8) (int, error) {
	want := (uint64(total) + MaxChunkData - 1) / MaxChunkData
	if want != uint64(count) || index >= count {
		return 0, errors.New("servicebridge: chunk count does not match the length")
	}
	if index+1 < count {
		return MaxChunkData, nil
	}
	return int(uint64(total) - uint64(count-1)*MaxChunkData), nil
}

// SplitMessage chunks one rail message into canonical frames.
func SplitMessage(
	kind byte,
	actorAccount [32]byte,
	requestID uint64,
	requestHash [32]byte,
	message []byte,
) ([]Frame, error) {
	bound, err := messageBound(kind)
	if err != nil {
		return nil, err
	}
	if len(message) == 0 || uint64(len(message)) > uint64(bound) {
		return nil, fmt.Errorf("servicebridge: a %d-byte message is outside the %d-byte bound", len(message), bound)
	}
	count := (len(message) + MaxChunkData - 1) / MaxChunkData
	digest := sha256.Sum256(message)
	frames := make([]Frame, 0, count)
	for index := 0; index < count; index++ {
		start := index * MaxChunkData
		end := min(start+MaxChunkData, len(message))
		frames = append(frames, Frame{
			Kind: kind, ActorAccount: actorAccount, RequestID: requestID, RequestHash: requestHash,
			MessageDigest: digest, TotalLength: uint32(len(message)), Index: uint8(index), Count: uint8(count),
			Data: append([]byte(nil), message[start:end]...),
		})
	}
	return frames, nil
}

// JoinFrames reassembles a complete, consistent set of frames and checks the
// message digest. Frames may arrive in any order; each index appears once.
func JoinFrames(frames []Frame) ([]byte, error) {
	if len(frames) == 0 || len(frames) > MaxChunks {
		return nil, errors.New("servicebridge: no complete frame set")
	}
	first := frames[0]
	ordered := make([][]byte, first.Count)
	for _, frame := range frames {
		if err := validateFrame(frame); err != nil {
			return nil, err
		}
		if frame.Kind != first.Kind || frame.ActorAccount != first.ActorAccount || frame.RequestID != first.RequestID ||
			frame.RequestHash != first.RequestHash || frame.MessageDigest != first.MessageDigest ||
			frame.TotalLength != first.TotalLength || frame.Count != first.Count {
			return nil, errors.New("servicebridge: frames belong to different messages")
		}
		if ordered[frame.Index] != nil {
			return nil, errors.New("servicebridge: a frame index repeats")
		}
		ordered[frame.Index] = frame.Data
	}
	var buffer bytes.Buffer
	for _, chunk := range ordered {
		if chunk == nil {
			return nil, errors.New("servicebridge: the frame set is incomplete")
		}
		buffer.Write(chunk)
	}
	message := buffer.Bytes()
	if uint64(len(message)) != uint64(first.TotalLength) || sha256.Sum256(message) != first.MessageDigest {
		return nil, errors.New("servicebridge: the reassembled message does not match its digest")
	}
	return message, nil
}
