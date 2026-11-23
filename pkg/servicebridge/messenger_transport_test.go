package servicebridge

import (
	"testing"
)

// The Messenger transport is registered as the fallback transport, and a
// messenger_socket it cannot use stops the node's transport from opening.
func TestTheMessengerTransportRefusesARelativeSocket(t *testing.T) {
	relative := NodeConfig{AgentID: testBuyer, MessengerSocket: "messenger.sock"}
	if _, err := openPacketTransport(relative, nil); err == nil {
		t.Fatal("a relative messenger socket: a transport was opened")
	}
	absolute := NodeConfig{AgentID: testBuyer, MessengerSocket: "/run/openfox/messenger.sock"}
	transport, err := openPacketTransport(absolute, nil)
	if err != nil {
		t.Fatal(err)
	}
	fallback := transport.(RoutedTransport).Fallback
	if _, messenger := fallback.(MessengerTransport); !messenger {
		t.Fatalf("the fallback transport is %T, not the Messenger transport", fallback)
	}
}
