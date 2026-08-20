package tosmessenger

import (
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels"
	"github.com/tosnetwork/openfox/pkg/config"
)

func init() {
	config.RegisterChannelSettings(config.ChannelTOSMessenger, config.TOSMessengerSettings{})
	channels.RegisterSafeFactory(
		config.ChannelTOSMessenger,
		func(bc *config.Channel, settings *config.TOSMessengerSettings, messageBus *bus.MessageBus) (channels.Channel, error) {
			return New(bc, settings, messageBus)
		},
	)
}
