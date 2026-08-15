package nativeimpl

import (
	"errors"

	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-service-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// NativeProviderConfig is the chain-backed provider stack: the finalized escrow
// resolver both the settler and any escrow read use, the shared Native execution
// Gate, the bounded software-work runner, the artifact locator, and the custody
// signer plus escrow-release broadcaster. Escrow, Gate, and Runner are the real
// tos-service-protocol / tos-ai types, so this constructor is the compile-time proof
// that they satisfy the bridge's interfaces; Signer and Release stay pluggable
// so custody (in-process, hardware, or tosctl) and broadcast remain the
// operator's choice.
type NativeProviderConfig struct {
	Escrow  *toschain.EscrowResolver
	Gate    *executiongate.Gate
	Runner  *softwarework.Runner
	Locator ProviderArtifactLocator
	Signer  ExecutionSigner
	Release ReleaseSubmitter
}

// NewNativeProviderReceivers wires the real chain-backed provider stack into the
// three receiver adapters. All three share the one Gate (at-most-once execution)
// and the one EscrowReleaseSettler (one canonical release path), so a purchase
// executes once and settles once regardless of the transport it arrived on.
func NewNativeProviderReceivers(c NativeProviderConfig) (*ProviderReceivers, error) {
	if c.Escrow == nil || c.Gate == nil || c.Runner == nil || c.Locator == nil || c.Signer == nil || c.Release == nil {
		return nil, errors.New("nativeimpl: native provider needs escrow resolver, gate, runner, locator, signer, and release broadcaster")
	}
	settler, err := NewEscrowReleaseSettler(c.Escrow, c.Signer, c.Release)
	if err != nil {
		return nil, err
	}
	return NewProviderReceivers(c.Gate, c.Runner, c.Locator, settler)
}
