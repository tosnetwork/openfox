package nativeimpl

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
	"github.com/tosnetwork/tos-ai/pkg/mcpadapter"
)

// mcpToolCaller is the narrow behaviour of an mcp client session the dispatcher
// uses. A *mcp.ClientSession satisfies it; keeping it an interface makes the
// Task -> tool-call mapping unit-testable without a live MCP server.
type mcpToolCaller interface {
	CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
}

// MCPTaskTransport dispatches a purchase-bound Task to a provider over MCP. Like
// the other transports it carries no authority: it invokes the provider's
// software-work tool for the already-funded task, and a non-error tool result is
// a successful dispatch; the escrow release is still confirmed by the buyer's
// own finalized read.
type MCPTaskTransport struct {
	caller mcpToolCaller
}

// NewMCPTaskTransport wraps an MCP tool caller.
func NewMCPTaskTransport(caller mcpToolCaller) (*MCPTaskTransport, error) {
	if caller == nil {
		return nil, errors.New("nativeimpl: MCP task transport needs a tool caller")
	}
	return &MCPTaskTransport{caller: caller}, nil
}

// Dispatch delivers the bound Task over MCP. It handles only TransportMCP and
// fails closed on any other transport or an unbuildable task before calling.
func (t *MCPTaskTransport) Dispatch(ctx context.Context, transport servicebridge.Transport, task servicebridge.Task) error {
	if transport != servicebridge.TransportMCP {
		return errors.New("nativeimpl: MCP task transport was asked to dispatch a non-MCP transport")
	}
	input, err := mcpadapter.PrepareInput(task.EscrowAddress, task.QuoteCommitment, task.ExecutionID, task.SourceArchive)
	if err != nil {
		return err
	}
	result, err := t.caller.CallTool(ctx, &mcp.CallToolParams{Name: mcpadapter.ToolName, Arguments: input})
	if err != nil {
		return err
	}
	if result == nil || result.IsError {
		return errors.New("nativeimpl: MCP dispatch did not complete the purchase-bound execution")
	}
	return nil
}

var _ servicebridge.TaskTransport = (*MCPTaskTransport)(nil)
