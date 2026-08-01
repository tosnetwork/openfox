package mqtt

import (
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/channels"
	"github.com/tosnetwork/openfox/pkg/config"
)

func init() {
	channels.RegisterSafeFactory(
		config.ChannelMQTT,
		func(bc *config.Channel, cfg *config.MQTTSettings, b *bus.MessageBus) (channels.Channel, error) {
			return NewMQTTChannel(bc, cfg, b)
		},
	)
}
