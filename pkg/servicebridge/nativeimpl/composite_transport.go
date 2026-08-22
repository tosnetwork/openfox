package nativeimpl

import (
	"context"
	"errors"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

// CompositeTaskTransport routes a dispatch to the transport-specific sender the
// bridge selected for a purchase. The buyer holds one TaskTransport but chooses
// the channel per purchase; this composite lets a buyer support A2A, MCP, and
// Agent Packet at once, dispatching each over exactly the configured sender.
type CompositeTaskTransport struct {
	routes map[servicebridge.Transport]servicebridge.TaskTransport
}

// NewCompositeTaskTransport builds a router from a non-empty set of per-transport
// senders. Each sender is expected to handle its own transport; the router
// enforces that a purchase is only dispatched over a configured channel.
func NewCompositeTaskTransport(
	routes map[servicebridge.Transport]servicebridge.TaskTransport,
) (*CompositeTaskTransport, error) {
	if len(routes) == 0 {
		return nil, errors.New("nativeimpl: composite transport needs at least one route")
	}
	owned := make(map[servicebridge.Transport]servicebridge.TaskTransport, len(routes))
	for transport, sender := range routes {
		if sender == nil {
			return nil, errors.New("nativeimpl: composite transport route has no sender")
		}
		owned[transport] = sender
	}
	return &CompositeTaskTransport{routes: owned}, nil
}

// Dispatch routes to the sender configured for the selected transport, failing
// closed if the buyer was not configured for that channel rather than silently
// dropping or misrouting the task.
func (t *CompositeTaskTransport) Dispatch(
	ctx context.Context,
	transport servicebridge.Transport,
	task servicebridge.Task,
) error {
	route, ok := t.routes[transport]
	if !ok {
		return errors.New("nativeimpl: no transport is configured for the selected channel")
	}
	return route.Dispatch(ctx, transport, task)
}

var _ servicebridge.TaskTransport = (*CompositeTaskTransport)(nil)
