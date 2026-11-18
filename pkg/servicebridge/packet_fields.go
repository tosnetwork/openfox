package servicebridge

import (
	"errors"
	"fmt"

	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// ErrPacketFieldsMismatch reports a rail message whose Agent Packets name
// another Capability or Accepted Quote than the request it is bound to
// (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 2.1). Conforming senders set
// both from the purchase, so only a mis-built or forged sender produces it.
var ErrPacketFieldsMismatch = errors.New(
	"servicebridge: the packets name another Capability or Accepted Quote than the request",
)

// packetRefusal is the section 12 label a packet-field mismatch of a
// message kind is refused with.
func packetRefusal(kind byte) railwork.Refusal {
	switch kind {
	case FrameTask:
		return railwork.RefusalTaskNotAdmitted
	case FrameResult:
		return railwork.RefusalResultNotAccepted
	case FrameResultAck:
		return railwork.RefusalAckUnmatched
	default:
		return railwork.RefusalResultRequestRefused
	}
}

// checkPacketFields requires a message's packets to name capabilityID and
// quoteCommitment, both taken from the stored purchase or request, never
// from the message. It is railwork's packet-field check.
func checkPacketFields(message Message, capabilityID, quoteCommitment string) error {
	return packetFieldsError(railwork.CheckPacketFields(message.Packet.CapabilityID, message.Packet.QuoteCommitment,
		capabilityID, quoteCommitment, packetRefusal(message.Kind)))
}

// packetFieldsError marks a refused packet-field check with
// ErrPacketFieldsMismatch, keeping railwork's labelled refusal; a caller
// error passes unchanged.
func packetFieldsError(err error) error {
	if err == nil {
		return nil
	}
	if _, refused := railwork.RefusalOf(err); refused {
		return fmt.Errorf("%w: %w", ErrPacketFieldsMismatch, err)
	}
	return fmt.Errorf("servicebridge: no Capability or Accepted Quote to check the packets against: %w", err)
}
