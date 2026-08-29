package mcp

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func TestMCPEffectActionIsReleasedExecutorEffectIdentity(t *testing.T) {
	bundle := CapabilityAuthorizationBundle{
		ConfigurationDigest:         bytes.Repeat([]byte{1}, sha256.Size),
		ExpectedObservationDigest:   bytes.Repeat([]byte{2}, sha256.Size),
		ExpectedEffectTool:          "write-record",
		ExpectedEffectRequestDigest: bytes.Repeat([]byte{3}, sha256.Size),
		Start:                       capabilitycontrol.StartRequest{Binding: capabilityUseBindingFixture()},
	}
	action, err := MCPEffectActionID(bundle, bundle.ExpectedEffectTool)
	if err != nil || len(action) != sha256.Size {
		t.Fatalf("derive executor.effect: %x %v", action, err)
	}
	bundle.ExpectedEffectActionID = action
	descriptor, err := MCPInvocationDescriptorDigest(bundle.ConfigurationDigest, bundle.ExpectedObservationDigest,
		[]string{"write-record"}, 1024, bundle.ExpectedEffectTool, bundle.ExpectedEffectRequestDigest, action)
	if err != nil || len(descriptor) != sha256.Size {
		t.Fatalf("derive invocation closure: %x %v", descriptor, err)
	}
	mutated := append([]byte(nil), bundle.ExpectedEffectRequestDigest...)
	mutated[0] ^= 0xff
	other, err := MCPInvocationDescriptorDigest(bundle.ConfigurationDigest, bundle.ExpectedObservationDigest,
		[]string{"write-record"}, 1024, bundle.ExpectedEffectTool, mutated, action)
	if err != nil || bytes.Equal(descriptor, other) {
		t.Fatal("exact MCP arguments were not committed by the invocation closure")
	}
}

func capabilityUseBindingFixture() trusted.CapabilityUseBindingV1 {
	return trusted.CapabilityUseBindingV1{
		OwnerID: []byte("owner"), AgentID: []byte("agent"), AgreementDigest: bytes.Repeat([]byte{4}, 32),
		ObligationID: []byte("obligation"), ExecutionID: bytes.Repeat([]byte{5}, 32), ActionID: bytes.Repeat([]byte{6}, 32),
	}
}
