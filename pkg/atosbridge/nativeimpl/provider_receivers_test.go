package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-protocol/pkg/executiongate"
)

type countingGate struct{ claims int }

func (g *countingGate) ClaimExecution(context.Context, executiongate.Request) (executiongate.Evidence, error) {
	g.claims++
	return executiongate.Evidence{}, nil
}

type staticLocator struct {
	url string
	err error
}

func (l staticLocator) ArtifactURL(artifactstore.Descriptor) (string, error) {
	return l.url, l.err
}

func TestNewProviderReceiversMountsAllThreeOnOneGate(t *testing.T) {
	gate := &countingGate{}
	inner := &fakeRunner{outcome: sampleOutcome()}
	settler, err := NewReceiptSettler(sampleContext(), &fakeExecSigner{}, &fakeSubmitter{})
	if err != nil {
		t.Fatalf("settler: %v", err)
	}
	runner, err := NewSettlingRunner(inner, settler)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}

	recv, err := NewProviderReceivers(gate, runner, staticLocator{url: "https://cdn.example/artifact"})
	if err != nil {
		t.Fatalf("new receivers: %v", err)
	}
	if recv.A2A == nil || recv.MCP == nil || recv.AgentPacket == nil {
		t.Fatalf("all three transports must be mounted: %+v", recv)
	}
}

func TestNewProviderReceiversRejectsIncompleteWiring(t *testing.T) {
	gate := &countingGate{}
	runner := &fakeRunner{}
	loc := staticLocator{url: "https://cdn.example/a"}

	cases := []struct {
		name    string
		gate    ProviderGate
		runner  softwareRunner
		locator ProviderArtifactLocator
	}{
		{"no gate", nil, runner, loc},
		{"no runner", gate, nil, loc},
		{"no locator", gate, runner, nil},
	}
	for _, c := range cases {
		if _, err := NewProviderReceivers(c.gate, c.runner, c.locator); err == nil {
			t.Fatalf("%s: must fail closed", c.name)
		}
	}
}

func TestA2ALocatorShimPropagatesError(t *testing.T) {
	shim := a2aLocatorShim{inner: staticLocator{err: errors.New("no such artifact")}}
	if _, err := shim.URL(artifactstore.Descriptor{}); err == nil {
		t.Fatalf("locator error must propagate through the a2a shim")
	}
}
