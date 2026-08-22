package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type fakeMCPCaller struct {
	gotParams *mcp.CallToolParams
	result    *mcp.CallToolResult
	err       error
}

func (f *fakeMCPCaller) CallTool(_ context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	f.gotParams = p
	return f.result, f.err
}

func TestMCPTransportDispatchesSuccessfulToolCall(t *testing.T) {
	caller := &fakeMCPCaller{result: &mcp.CallToolResult{IsError: false}}
	transport, err := NewMCPTaskTransport(caller)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	if err := transport.Dispatch(context.Background(), servicebridge.TransportMCP, sampleTask()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if caller.gotParams == nil || caller.gotParams.Name == "" {
		t.Fatalf("a tool call must have been made: %+v", caller.gotParams)
	}
}

func TestMCPTransportRejectsWrongTransport(t *testing.T) {
	caller := &fakeMCPCaller{result: &mcp.CallToolResult{}}
	transport, _ := NewMCPTaskTransport(caller)
	if err := transport.Dispatch(context.Background(), servicebridge.TransportA2A, sampleTask()); err == nil {
		t.Fatalf("an A2A dispatch must not be sent over the MCP transport")
	}
	if caller.gotParams != nil {
		t.Fatalf("nothing may be called for the wrong transport")
	}
}

func TestMCPTransportFailsOnToolError(t *testing.T) {
	caller := &fakeMCPCaller{result: &mcp.CallToolResult{IsError: true}}
	transport, _ := NewMCPTaskTransport(caller)
	if err := transport.Dispatch(context.Background(), servicebridge.TransportMCP, sampleTask()); err == nil {
		t.Fatalf("an errored tool result must be a dispatch error")
	}
}

func TestMCPTransportPropagatesCallError(t *testing.T) {
	caller := &fakeMCPCaller{err: errors.New("session closed")}
	transport, _ := NewMCPTaskTransport(caller)
	if err := transport.Dispatch(context.Background(), servicebridge.TransportMCP, sampleTask()); err == nil {
		t.Fatalf("a call error must propagate")
	}
}

func TestMCPTransportRejectsUnboundTask(t *testing.T) {
	caller := &fakeMCPCaller{result: &mcp.CallToolResult{}}
	transport, _ := NewMCPTaskTransport(caller)
	task := sampleTask()
	task.SourceArchive = nil
	if err := transport.Dispatch(context.Background(), servicebridge.TransportMCP, task); err == nil {
		t.Fatalf("a task without a source archive must fail closed before calling")
	}
	if caller.gotParams != nil {
		t.Fatalf("nothing may be called for an unbuildable task")
	}
}
