package servicebridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEndpointRedactionCoversEverySpellingOfTheURL(t *testing.T) {
	endpoints := []string{"https://rpc.example/v1/secret-token#", "https://other.example"}
	message := strings.Join([]string{
		`Post "https://rpc.example/v1/secret-token": connection refused`, // the client drops the empty fragment
		"https://rpc.example/v1/secret-token#",
		"rpc.example/v1/secret-token",
		"path /v1/secret-token",
		"https://other.example ok",
	}, "; ")
	redacted := redactEndpoints(message, endpoints)
	if strings.Contains(redacted, "secret-token") || strings.Contains(redacted, "rpc.example") {
		t.Fatalf("an endpoint spelling escaped redaction: %s", redacted)
	}
	if !strings.Contains(redacted, "rpc_endpoints[0]") || !strings.Contains(redacted, "rpc_endpoints[1] ok") {
		t.Fatalf("redaction lost the endpoint positions: %s", redacted)
	}
	if got := redactEndpoints("nothing to hide", endpoints); got != "nothing to hide" {
		t.Fatalf("an unrelated message changed: %s", got)
	}
}

func TestStatusRedactsEndpointsAndStaysOfflineWhenTheReaderCannotOpen(t *testing.T) {
	config, _ := statusNode(t)
	config.RPCEndpoints = []string{"https://rpc.example/key-123#", "https://b.example", "https://c.example"}
	chain := UnavailableStatusChain(
		errors.New(`open the finalized reader: Post "https://rpc.example/key-123": refused`),
	)
	status, err := ReadProviderStatus(context.Background(), config, chain, time.Unix(1_800_000_100, 0))
	if err != nil {
		t.Fatalf("an unopenable reader stopped the report: %v", err)
	}
	if status.Actor.Read || !strings.Contains(status.Actor.Error, "open the finalized reader") {
		t.Fatalf("the reader failure is not reported: %+v", status.Actor)
	}
	if strings.Contains(status.Actor.Error, "key-123") {
		t.Fatalf("the actor error prints an endpoint token: %s", status.Actor.Error)
	}
	if len(status.Requests) != 1 || status.Requests[0].OperatorState != OperatorOutcomeUnknown {
		t.Fatalf("a chain-decided state was guessed without the chain: %+v", status.Requests)
	}
}
