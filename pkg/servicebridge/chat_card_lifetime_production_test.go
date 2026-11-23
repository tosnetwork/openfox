//go:build !roomtest

package servicebridge

import (
	"errors"
	"testing"
)

// A production build refuses any chat test card lifetime, whatever its
// value, at configuration validation and when the lane reads it.
func TestAProductionBuildRefusesTheChatTestCardLifetime(t *testing.T) {
	if ChatBuildVariant() != "production" {
		t.Fatalf("build variant %q", ChatBuildVariant())
	}
	for _, seconds := range []uint64{1, 600, 1800, 2_592_000} {
		config := chatLifetimeConfig(seconds)
		if err := validateChatConfig(config); !errors.Is(err, ErrChatTestSettingRefused) {
			t.Fatalf("%d s: the production build accepted the test card lifetime: %v", seconds, err)
		}
		if _, err := ChatSection(config).cardLifetime(); !errors.Is(err, ErrChatTestSettingRefused) {
			t.Fatalf("%d s: the lane read the test card lifetime: %v", seconds, err)
		}
	}
}
