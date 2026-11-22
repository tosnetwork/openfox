package servicebridge

import "testing"

// chatLifetimeConfig is a valid chat node configuration naming the test card
// lifetime seconds.
func chatLifetimeConfig(seconds uint64) NodeConfig {
	return NodeConfig{
		RelayURLs: []string{"https://relay.example"}, ReceiverSocket: "/state/rail.sock",
		Chat: NewChatSection(&ChatConfig{
			CarrierSocket: "/state/chat.sock", MessengerCarrierSocket: "/run/m/carrier.sock",
			CardPath: "/state/relay/chat-card.json", TestCardLifetimeSeconds: seconds,
		}),
	}
}

// Unset, the chat card keeps the production rotation in every build.
func TestAnUnsetChatTestCardLifetimeIsTheProductionRotation(t *testing.T) {
	config := chatLifetimeConfig(0)
	if err := validateChatConfig(config); err != nil {
		t.Fatal(err)
	}
	if lifetime, err := ChatSection(config).cardLifetime(); err != nil || lifetime != 0 {
		t.Fatalf("an unset test card lifetime is %v, %v", lifetime, err)
	}
}
