package nativeimpl

import (
	"testing"
)

func TestNewNativeProviderReceiversRejectsEmptyConfig(t *testing.T) {
	// A partial config cannot be constructed in a unit test without a live node
	// (the real escrow resolver, Gate, and runner all need chain wiring), so the
	// runtime assertion here is that an incomplete stack fails closed. The
	// compile-time assertion — that *toschain.EscrowResolver, *executiongate.Gate,
	// and *softwarework.Runner satisfy the bridge interfaces — is what the build
	// of provider_native.go proves.
	if _, err := NewNativeProviderReceivers(NativeProviderConfig{}); err == nil {
		t.Fatalf("an empty native provider config must fail closed")
	}
}
