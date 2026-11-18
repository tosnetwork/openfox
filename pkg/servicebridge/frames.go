// Package servicebridge carries paid software work between an OpenFox buyer
// and an OpenFox provider on the Service Actor rail. The buyer discovers a
// published Capability, takes a Quote, and calls the Service Actor; the work
// and its result then travel as signed Agent Packets through the Messenger.
// Nothing a packet says is trusted: the provider admits work only while
// finalized state shows the paid request pending, and the buyer accepts a
// result only when its Receipt hashes to the finalized attested response.
//
// The frames, messages, derived values and receiver checks are the shared
// implementation of SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 in
// github.com/tosnetwork/ai/protocol/pkg/railwork; this file, messages.go
// and receipt.go keep the names the rest of the package uses.
package servicebridge

import (
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// Frame kinds.
const (
	FrameTask      = byte(railwork.KindTask)
	FrameResult    = byte(railwork.KindResult)
	FrameResultAck = byte(railwork.KindResultAck)
	// FrameResultRequest asks the provider of a responded request to deliver
	// its result again, carrying the buyer's current key card. It never
	// admits, executes or responds.
	FrameResultRequest = byte(railwork.KindResultRequest)
)

const (
	frameHeader = railwork.FrameHeaderBytes

	// MaxChunkData bounds the data one frame carries, so that the signed
	// Agent Packet JSON holding it stays inside the Messenger direct
	// application bound (96 KiB) with room for the signature and fields.
	MaxChunkData = railwork.MaxChunkData
	// MaxChunks bounds the frames of one message.
	MaxChunks = railwork.MaxChunks
	// MaxMessageBytes bounds any one rail message.
	MaxMessageBytes = MaxChunks * MaxChunkData
	// MaxInlineInputBytes is the advertised inline work input: the largest
	// source archive a buyer may deliver.
	MaxInlineInputBytes = railwork.MaxInlineInputBytes
	// MaxResultBytes bounds the artifact a result delivers.
	MaxResultBytes = railwork.MaxResultBytes
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

func (f Frame) shared() railwork.Frame {
	return railwork.Frame{
		Kind:          railwork.Kind(f.Kind),
		Binding:       railwork.Binding{ActorAccount: f.ActorAccount, RequestID: f.RequestID, RequestHash: f.RequestHash},
		MessageDigest: f.MessageDigest, TotalLength: f.TotalLength, Index: f.Index, Count: f.Count, Data: f.Data,
	}
}

func frameOf(f railwork.Frame) Frame {
	return Frame{
		Kind: byte(f.Kind), ActorAccount: f.Binding.ActorAccount, RequestID: f.Binding.RequestID,
		RequestHash: f.Binding.RequestHash, MessageDigest: f.MessageDigest, TotalLength: f.TotalLength,
		Index: f.Index, Count: f.Count, Data: f.Data,
	}
}

// EncodeFrame returns the canonical binary frame.
func EncodeFrame(frame Frame) ([]byte, error) {
	return railwork.EncodeFrame(frame.shared())
}

// isRailPayload reports whether a packet payload starts as a rail frame
// (magic and version). It is the purpose check a rail key applies before any
// verification or write.
func isRailPayload(raw []byte) bool {
	return railwork.IsRailPayload(raw)
}

// DecodeFrame parses one canonical frame and refuses any other shape.
func DecodeFrame(raw []byte) (Frame, error) {
	frame, err := railwork.DecodeFrame(raw)
	if err != nil {
		return Frame{}, err
	}
	return frameOf(frame), nil
}

// validateFrame refuses a frame EncodeFrame would not encode.
func validateFrame(frame Frame) error {
	_, err := railwork.EncodeFrame(frame.shared())
	return err
}

// SplitMessage chunks one rail message into canonical frames.
func SplitMessage(
	kind byte,
	actorAccount [32]byte,
	requestID uint64,
	requestHash [32]byte,
	message []byte,
) ([]Frame, error) {
	frames, err := railwork.SplitMessage(railwork.Kind(kind),
		railwork.Binding{ActorAccount: actorAccount, RequestID: requestID, RequestHash: requestHash}, message)
	if err != nil {
		return nil, err
	}
	out := make([]Frame, 0, len(frames))
	for _, frame := range frames {
		out = append(out, frameOf(frame))
	}
	return out, nil
}

// JoinFrames reassembles a complete, consistent set of frames and checks the
// message digest. Frames may arrive in any order; each index appears once.
func JoinFrames(frames []Frame) ([]byte, error) {
	shared := make([]railwork.Frame, 0, len(frames))
	for _, frame := range frames {
		shared = append(shared, frame.shared())
	}
	return railwork.JoinFrames(shared)
}
