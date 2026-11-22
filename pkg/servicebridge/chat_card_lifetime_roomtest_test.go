//go:build roomtest

package servicebridge

import (
	"testing"
	"time"
)

// A roomtest build accepts the chat test card lifetime within 600 s to 30
// days and refuses it outside.
func TestARoomtestBuildBoundsTheChatTestCardLifetime(t *testing.T) {
	if ChatBuildVariant() != "roomtest" {
		t.Fatalf("build variant %q", ChatBuildVariant())
	}
	for _, seconds := range []uint64{600, 1800, 2_592_000} {
		config := chatLifetimeConfig(seconds)
		if err := validateChatConfig(config); err != nil {
			t.Fatalf("%d s: %v", seconds, err)
		}
		lifetime, err := ChatSection(config).cardLifetime()
		if err != nil || lifetime != time.Duration(seconds)*time.Second {
			t.Fatalf("%d s: read as %v, %v", seconds, lifetime, err)
		}
	}
	for _, seconds := range []uint64{1, 599, 2_592_001} {
		if err := validateChatConfig(chatLifetimeConfig(seconds)); err == nil {
			t.Fatalf("%d s: accepted outside its bound", seconds)
		}
	}
}
