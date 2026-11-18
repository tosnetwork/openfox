package servicebridge

import (
	"errors"
)

// ErrPacketFieldsMismatch reports a rail message whose Agent Packets name
// another Capability or Accepted Quote than the request it is bound to
// (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 2.1). Conforming senders set
// both from the purchase, so only a mis-built or forged sender produces it.
var ErrPacketFieldsMismatch = errors.New(
	"servicebridge: the packets name another Capability or Accepted Quote than the request",
)

// checkPacketFields requires a message's packets to name capabilityID and
// quoteCommitment, both taken from the provider's own Capability, the
// verified Quote or the stored request, never from the message.
func checkPacketFields(message Message, capabilityID, quoteCommitment string) error {
	if capabilityID == "" || quoteCommitment == "" {
		return errors.New("servicebridge: no Capability or Accepted Quote to check the packets against")
	}
	if message.Packet.CapabilityID != capabilityID || message.Packet.QuoteCommitment != quoteCommitment {
		return ErrPacketFieldsMismatch
	}
	return nil
}
