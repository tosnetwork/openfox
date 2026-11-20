package servicebridge

import (
	"errors"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// ErrChatTestSettingRefused is the refusal of a production build to run with
// the chat test card lifetime.
var ErrChatTestSettingRefused = errors.New("servicebridge: chat.test_card_lifetime_seconds is a test setting " +
	"that only a build with the roomtest tag accepts; this production build refuses it")

// minChatTestCardLifetime is the shortest chat test card lifetime: ten
// maintenance passes, so a card is replaced at half its life with room for
// a pass that is late.
const minChatTestCardLifetime = 10 * time.Minute

// cardLifetime is the chat card lifetime the section names: zero for the
// production rotation (a 30-day card replaced once less than half of it is
// left), or the test lifetime, which only a roomtest build accepts.
func (c ChatConfig) cardLifetime() (time.Duration, error) {
	if c.TestCardLifetimeSeconds == 0 {
		return 0, nil
	}
	if !chatTestSettings {
		return 0, ErrChatTestSettingRefused
	}
	if c.TestCardLifetimeSeconds < uint64(minChatTestCardLifetime/time.Second) ||
		c.TestCardLifetimeSeconds > uint64(agentpacketseal.MaxKeyCardLifetime/time.Second) {
		return 0, errors.New("chat.test_card_lifetime_seconds must be 600 to 2,592,000")
	}
	return time.Duration(c.TestCardLifetimeSeconds) * time.Second, nil
}

// ChatBuildVariant names the build variant for a record: production, or
// roomtest, the only one that accepts the chat test card lifetime.
func ChatBuildVariant() string {
	if chatTestSettings {
		return "roomtest"
	}
	return "production"
}
