package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type recordingTransport struct {
	got  servicebridge.Transport
	hits int
	err  error
}

func (r *recordingTransport) Dispatch(
	_ context.Context,
	transport servicebridge.Transport,
	_ servicebridge.Task,
) error {
	r.hits++
	r.got = transport
	return r.err
}

func TestCompositeRoutesToSelectedTransport(t *testing.T) {
	a2a := &recordingTransport{}
	mcp := &recordingTransport{}
	composite, err := NewCompositeTaskTransport(map[servicebridge.Transport]servicebridge.TaskTransport{
		servicebridge.TransportA2A: a2a,
		servicebridge.TransportMCP: mcp,
	})
	if err != nil {
		t.Fatalf("new composite: %v", err)
	}
	if err := composite.Dispatch(context.Background(), servicebridge.TransportMCP, sampleTask()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if mcp.hits != 1 || mcp.got != servicebridge.TransportMCP || a2a.hits != 0 {
		t.Fatalf("dispatch must route only to the selected transport: a2a=%d mcp=%d", a2a.hits, mcp.hits)
	}
}

func TestCompositeFailsClosedForUnconfiguredTransport(t *testing.T) {
	composite, _ := NewCompositeTaskTransport(map[servicebridge.Transport]servicebridge.TaskTransport{
		servicebridge.TransportA2A: &recordingTransport{},
	})
	if err := composite.Dispatch(context.Background(), servicebridge.TransportAgentPacket, sampleTask()); err == nil {
		t.Fatalf("a channel the buyer was not configured for must fail closed")
	}
}

func TestCompositePropagatesRouteError(t *testing.T) {
	composite, _ := NewCompositeTaskTransport(map[servicebridge.Transport]servicebridge.TaskTransport{
		servicebridge.TransportA2A: &recordingTransport{err: errors.New("send failed")},
	})
	if err := composite.Dispatch(context.Background(), servicebridge.TransportA2A, sampleTask()); err == nil {
		t.Fatalf("the selected route's error must propagate")
	}
}

func TestNewCompositeRejectsEmptyAndNil(t *testing.T) {
	if _, err := NewCompositeTaskTransport(nil); err == nil {
		t.Fatalf("an empty route set must be rejected")
	}
	if _, err := NewCompositeTaskTransport(map[servicebridge.Transport]servicebridge.TaskTransport{
		servicebridge.TransportA2A: nil,
	}); err == nil {
		t.Fatalf("a nil route sender must be rejected")
	}
}
