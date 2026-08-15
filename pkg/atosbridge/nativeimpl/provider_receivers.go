package nativeimpl

import (
	"context"
	"errors"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/tosnetwork/tos-ai/pkg/a2aadapter"
	"github.com/tosnetwork/tos-ai/pkg/agentpacketadapter"
	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/mcpadapter"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-protocol/pkg/executiongate"
)

// ProviderGate is the shared Native execution Gate behaviour the three receiver
// adapters depend on. A *executiongate.Gate satisfies it; keeping it an
// interface makes the assembly testable and, more importantly, lets one Gate
// instance back every transport.
type ProviderGate interface {
	ClaimExecution(context.Context, executiongate.Request) (executiongate.Evidence, error)
}

// ProviderSettler releases escrow after a completed execution. One settler
// backs every transport, so a purchase settles through the same canonical
// release path no matter which transport delivered it. An *EscrowReleaseSettler
// satisfies it.
type ProviderSettler interface {
	Settle(context.Context, executiongate.Evidence, softwarework.Outcome) error
}

// ProviderArtifactLocator resolves a content-addressed artifact descriptor to
// the https URL where the buyer fetches it. One locator serves every transport.
type ProviderArtifactLocator interface {
	ArtifactURL(artifactstore.Descriptor) (string, error)
}

// ProviderReceivers holds the A2A, MCP, and Agent Packet receiver adapters a
// provider exposes. They are constructed from ONE execution Gate and ONE runner,
// so the shared Native execution Gate enforces at-most-once execution across all
// three transports: whichever transport a purchase-bound task arrives on, it
// claims the same (quote_commitment, escrow) slot before the runner is reached.
// A duplicate delivered on a second transport is rejected by the same Gate, not
// by three independent guards that could disagree.
type ProviderReceivers struct {
	A2A         *a2aadapter.Adapter
	MCP         *mcpadapter.Adapter
	AgentPacket *agentpacketadapter.Adapter
}

// a2aLocatorShim / mcpLocatorShim adapt one ProviderArtifactLocator to the two
// adapter-specific locator interfaces (a2a.URL vs string). Both delegate to the
// same underlying locator so every transport advertises identical artifact URLs.
type a2aLocatorShim struct{ inner ProviderArtifactLocator }

func (s a2aLocatorShim) URL(d artifactstore.Descriptor) (a2a.URL, error) {
	u, err := s.inner.ArtifactURL(d)
	if err != nil {
		return "", err
	}
	return a2a.URL(u), nil
}

type mcpLocatorShim struct{ inner ProviderArtifactLocator }

func (s mcpLocatorShim) URL(d artifactstore.Descriptor) (string, error) {
	return s.inner.ArtifactURL(d)
}

// NewProviderReceivers builds all three receiver adapters over the same Gate,
// runner, artifact locator, and settler. Because all four are shared, every
// admitted task — regardless of transport — executes at most once behind the
// one Gate and settles through the one canonical release path.
func NewProviderReceivers(gate ProviderGate, runner softwareRunner, locator ProviderArtifactLocator, settler ProviderSettler) (*ProviderReceivers, error) {
	if gate == nil || runner == nil || locator == nil || settler == nil {
		return nil, errors.New("nativeimpl: provider receivers need a gate, a runner, an artifact locator, and a settler")
	}
	a2aAdapter, err := a2aadapter.NewSettling(gate, runner, a2aLocatorShim{inner: locator}, settler)
	if err != nil {
		return nil, err
	}
	mcpAdapter, err := mcpadapter.NewSettling(gate, runner, mcpLocatorShim{inner: locator}, settler)
	if err != nil {
		return nil, err
	}
	packetAdapter, err := agentpacketadapter.NewSettling(gate, runner, settler)
	if err != nil {
		return nil, err
	}
	return &ProviderReceivers{A2A: a2aAdapter, MCP: mcpAdapter, AgentPacket: packetAdapter}, nil
}
