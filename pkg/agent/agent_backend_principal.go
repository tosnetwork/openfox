package agent

import (
	"context"

	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/providers"
)

// withAgentBackendPrincipal translates authenticated ingress metadata into the
// private context capability consumed by local-personal subscription backends.
// A nil inbound context denotes OpenFox-owned background work, which still
// requires allow_internal to be enabled explicitly.
func withAgentBackendPrincipal(ctx context.Context, inbound *bus.InboundContext) context.Context {
	if inbound == nil {
		return providers.WithInternalAgentBackendPrincipal(ctx)
	}
	return providers.WithAgentBackendPrincipal(ctx, inbound.Channel, inbound.SenderID)
}
