package tosmessengerlab

import (
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels"
	"github.com/tosnetwork/openfox/pkg/config"
)

func init() {
	config.RegisterChannelSettings(config.ChannelTOSMessengerLab, config.TOSMessengerLabSettings{})
	channels.RegisterSafeFactory(
		config.ChannelTOSMessengerLab,
		func(bc *config.Channel, settings *config.TOSMessengerLabSettings, messageBus *bus.MessageBus) (channels.Channel, error) {
			return New(bc, settings, messageBus)
		},
	)
}
