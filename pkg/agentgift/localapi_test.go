package agentgift

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startLocalTestServer(t *testing.T, service *Service, principal LocalPrincipal) *LocalClient {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "gift.sock")
	listener, err := ListenLocalUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewLocalServer(service, principal, "tos-local", 42, "agent_"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})
	client, err := NewLocalClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestModelLocalAPIExposesProposalAndRedactedStateOnly(t *testing.T) {
	r := &fakeResolver{recipient: "agent_" + strings.Repeat("b", 64)}
	service := newTestService(t, openTestJournal(t, "model-api"), fakeProtocol{}, r, &fakeMessenger{}, &fakeCustody{}, &fakeBroadcast{}, &fakeAddress{value: "0:" + strings.Repeat("d", 64)}, &fakeOwner{})
	client := startLocalTestServer(t, service, LocalPrincipalModel)
	response, err := client.Call(context.Background(), LocalRequest{Operation: LocalStartSender,
		Proposal: &ModelProposal{Recipient: "bob.tos", AmountAtomic: "1000000000", RequestedValidUntil: 1_800_003_600, Greeting: "hi"}})
	if err != nil || response.Record == nil || response.Record.State != string(StateRecipientResolved) || response.Record.FundsLocked || response.Record.IntentID == "" {
		t.Fatalf("model start: %+v %v", response, err)
	}
	if _, err := client.Call(context.Background(), LocalRequest{Operation: LocalAuthorize, IntentID: response.Record.IntentID}); err == nil {
		t.Fatal("model principal invoked owner/custody authority")
	}
	listed, err := client.Call(context.Background(), LocalRequest{Operation: LocalList})
	if err != nil || len(listed.Records) != 1 || listed.Records[0].AmountAtomic != "1000000000" {
		t.Fatalf("redacted list: %+v %v", listed, err)
	}
}

func TestLocalAPIRejectsUnknownFields(t *testing.T) {
	r := &fakeResolver{recipient: "agent_" + strings.Repeat("b", 64)}
	service := newTestService(t, openTestJournal(t, "strict-api"), fakeProtocol{}, r, &fakeMessenger{}, &fakeCustody{}, &fakeBroadcast{}, &fakeAddress{value: "0:" + strings.Repeat("d", 64)}, &fakeOwner{})
	client := startLocalTestServer(t, service, LocalPrincipalRuntime)
	connection, err := net.Dial("unix", client.path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := []byte(`{"schema":"tos.openfox.agent-gift.local-request.v1","operation":"gift.list","address":"model supplied"}`)
	if _, err := connection.Write(frameLocal(unknown)); err != nil {
		t.Fatal(err)
	}
	response, err := readLocalFrame(bufio.NewReader(connection))
	connection.Close()
	if err != nil || !strings.Contains(string(response), `"ok":false`) {
		t.Fatalf("unknown field was not refused: %s %v", response, err)
	}
}

func TestLocalClientTimeoutCanOutliveMaximumCustodyCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gift.sock")
	client, err := NewLocalClient(path, 0)
	if err != nil || client.timeout != LocalOperationTimeout+2*localIOTimeout {
		t.Fatalf("default client timeout does not cover the full server budget: %+v %v", client, err)
	}
	if _, err := NewLocalClient(path, maxLocalClientTimeout); err != nil {
		t.Fatalf("bounded client timeout cannot cover custody operation: %v", err)
	}
	if _, err := NewLocalClient(path, maxLocalClientTimeout+time.Second); err == nil {
		t.Fatal("unbounded local client timeout was accepted")
	}
}
