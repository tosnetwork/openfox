package nativeimpl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/tosnetwork/openfox/pkg/servicebridge"
	"github.com/tosnetwork/tos-ai/pkg/a2aadapter"
)

// a2aMessageSender is the narrow behaviour of an a2aclient.Transport the
// dispatcher uses. An a2aclient.Transport (e.g. from a2aclient.NewJSONRPCTransport
// over a TLS+bearer http.Client) satisfies it; keeping it an interface makes the
// Task -> request mapping unit-testable without a live server.
type a2aMessageSender interface {
	SendMessage(context.Context, a2aclient.ServiceParams, *a2a.SendMessageRequest) (a2a.SendMessageResult, error)
}

// A2ATaskTransport dispatches a purchase-bound Task to a provider over A2A. The
// transport carries no authority: it only delivers the task the buyer already
// funded, and success means the provider's adapter admitted, executed, and
// settled it (an A2A completed Task). Whether the escrow actually released is
// still confirmed by the buyer's own finalized read afterwards.
type A2ATaskTransport struct {
	sender a2aMessageSender
	newID  func() (string, error)
}

// NewA2ATaskTransport wraps an A2A message sender.
func NewA2ATaskTransport(sender a2aMessageSender) (*A2ATaskTransport, error) {
	if sender == nil {
		return nil, errors.New("nativeimpl: A2A task transport needs a message sender")
	}
	return &A2ATaskTransport{sender: sender, newID: randomID}, nil
}

// Dispatch delivers the bound Task over A2A. It handles only TransportA2A; the
// bridge selects the transport, so an unexpected transport is a programming
// error and fails closed rather than silently sending over the wrong channel.
func (t *A2ATaskTransport) Dispatch(ctx context.Context, transport servicebridge.Transport, task servicebridge.Task) error {
	if transport != servicebridge.TransportA2A {
		return errors.New("nativeimpl: A2A task transport was asked to dispatch a non-A2A transport")
	}
	messageID, err := t.newID()
	if err != nil {
		return err
	}
	contextID, err := t.newID()
	if err != nil {
		return err
	}
	request, err := a2aadapter.NewTaskRequest(messageID, contextID, task.EscrowAddress, task.QuoteCommitment, task.ExecutionID, task.SourceArchive)
	if err != nil {
		return err
	}
	result, err := t.sender.SendMessage(ctx, a2aclient.ServiceParams{}, request)
	if err != nil {
		return err
	}
	completed, ok := result.(*a2a.Task)
	if !ok || completed.Status.State != a2a.TaskStateCompleted {
		return errors.New("nativeimpl: A2A dispatch did not complete the purchase-bound execution")
	}
	return nil
}

var _ servicebridge.TaskTransport = (*A2ATaskTransport)(nil)

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("nativeimpl: could not generate a message id")
	}
	return hex.EncodeToString(buf), nil
}
