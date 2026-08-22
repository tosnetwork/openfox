package nativeimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

type fakeA2ASender struct {
	gotRequest *a2a.SendMessageRequest
	result     a2a.SendMessageResult
	err        error
}

func (f *fakeA2ASender) SendMessage(
	_ context.Context,
	_ a2aclient.ServiceParams,
	req *a2a.SendMessageRequest,
) (a2a.SendMessageResult, error) {
	f.gotRequest = req
	return f.result, f.err
}

func sampleTask() servicebridge.Task {
	return servicebridge.Task{
		EscrowAddress:   "0:" + hex64,
		QuoteCommitment: "tvm-cell-sha256:" + hex64,
		ExecutionID:     "sha256:" + hex64,
		InputDigest:     "sha256:" + hex64,
		SourceDigest:    "sha256:" + hex64,
		SourceArchive:   []byte("bounded source archive"),
	}
}

func TestA2ATransportDispatchesCompletedTask(t *testing.T) {
	sender := &fakeA2ASender{result: &a2a.Task{Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}}
	transport, err := NewA2ATaskTransport(sender)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	if err := transport.Dispatch(context.Background(), servicebridge.TransportA2A, sampleTask()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if sender.gotRequest == nil {
		t.Fatalf("a request must have been sent")
	}
}

func TestA2ATransportRejectsWrongTransport(t *testing.T) {
	sender := &fakeA2ASender{result: &a2a.Task{Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}}
	transport, _ := NewA2ATaskTransport(sender)
	if err := transport.Dispatch(context.Background(), servicebridge.TransportMCP, sampleTask()); err == nil {
		t.Fatalf("an MCP dispatch must not be sent over the A2A transport")
	}
	if sender.gotRequest != nil {
		t.Fatalf("nothing may be sent for the wrong transport")
	}
}

func TestA2ATransportFailsOnIncompleteTask(t *testing.T) {
	sender := &fakeA2ASender{result: &a2a.Task{Status: a2a.TaskStatus{State: a2a.TaskStateFailed}}}
	transport, _ := NewA2ATaskTransport(sender)
	if err := transport.Dispatch(context.Background(), servicebridge.TransportA2A, sampleTask()); err == nil {
		t.Fatalf("a non-completed task must be a dispatch error")
	}
}

func TestA2ATransportPropagatesSendError(t *testing.T) {
	sender := &fakeA2ASender{err: errors.New("transport unreachable")}
	transport, _ := NewA2ATaskTransport(sender)
	if err := transport.Dispatch(context.Background(), servicebridge.TransportA2A, sampleTask()); err == nil {
		t.Fatalf("a send error must propagate")
	}
}

func TestA2ATransportRejectsUnboundTask(t *testing.T) {
	sender := &fakeA2ASender{result: &a2a.Task{Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}}
	transport, _ := NewA2ATaskTransport(sender)
	// No source archive: NewTaskRequest must refuse to build a purchase-bound task.
	task := sampleTask()
	task.SourceArchive = nil
	if err := transport.Dispatch(context.Background(), servicebridge.TransportA2A, task); err == nil {
		t.Fatalf("a task without a source archive must fail closed before sending")
	}
	if sender.gotRequest != nil {
		t.Fatalf("nothing may be sent for an unbuildable task")
	}
}
