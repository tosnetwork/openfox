package messengerauth

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
)

func TestClientRequestsAndClaimsOneShotToolGrant(t *testing.T) {
	var mu sync.Mutex
	var operations []string
	server := newFakeServer(t, func(raw []byte) []byte {
		var request struct {
			Schema   string          `json:"schema"`
			Op       string          `json:"op"`
			Action   *proposedAction `json:"action"`
			ActionID string          `json:"action_id"`
		}
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		operations = append(operations, request.Op)
		mu.Unlock()
		if request.Op == "actions.request" {
			if request.Schema != requestSchema || request.Action == nil || request.Action.IdempotencyKey == "" {
				t.Fatalf("request = %+v", request)
			}
			return encodeResponse(
				t,
				response{OK: true, ActionID: "act_" + repeat("a", 64), Decision: "allow", State: "granted"},
			)
		}
		return encodeResponse(t, response{OK: true, ActionID: request.ActionID, State: "spent", Authorized: true})
	})
	client, err := NewClient(server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Authorize(context.Background(), actionauth.Action{
		Effect: actionauth.EffectToolCall, Summary: "invoke scanner",
		IdempotencyKey: "idem_" + repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(operations) != 2 || operations[0] != "actions.request" || operations[1] != "actions.claim" {
		t.Fatalf("operations = %v", operations)
	}
}

func TestClientWaitsForOwnerThenClaims(t *testing.T) {
	var statusCalls atomic.Int32
	server := newFakeServer(t, func(raw []byte) []byte {
		var req request
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		switch req.Op {
		case "actions.request":
			return encodeResponse(t, response{OK: true, ActionID: "act_" + repeat("a", 64), State: "pending"})
		case "actions.status":
			statusCalls.Add(1)
			return encodeResponse(t, response{OK: true, ActionID: req.ActionID, State: "granted"})
		default:
			return encodeResponse(t, response{OK: true, Authorized: true, State: "spent"})
		}
	})
	client, err := NewClient(server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authorize(context.Background(), actionauth.Action{
		Effect: actionauth.EffectToolCall, Summary: "invoke scanner",
		IdempotencyKey: "idem_" + repeat("b", 64),
	}); err != nil {
		t.Fatal(err)
	}
	if statusCalls.Load() != 1 {
		t.Fatalf("status calls = %d", statusCalls.Load())
	}
}

func TestClientSurfacesOwnerHoldWithoutClaiming(t *testing.T) {
	server := newFakeServer(t, func([]byte) []byte {
		return encodeResponse(
			t,
			response{
				OK:       true,
				ActionID: "act_" + repeat("a", 64),
				Decision: "require-owner-approval",
				State:    "pending",
			},
		)
	})
	client, err := NewClient(server, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Authorize(context.Background(), actionauth.Action{
		Effect: actionauth.EffectToolCall, Summary: "invoke scanner",
		IdempotencyKey: "idem_" + repeat("b", 64),
	})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("error = %v", err)
	}
}

func TestClientCarriesExactSpendTermsAndMandate(t *testing.T) {
	wantMandate := "mdt_" + repeat("9", 64)
	wantPrice := "184467440737095516160"
	server := newFakeServer(t, func(raw []byte) []byte {
		var req request
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		if req.Op == "actions.request" {
			if req.MandateID != wantMandate || req.Action == nil || req.Action.Terms == nil ||
				req.Action.Terms.PriceAtomic != wantPrice {
				t.Fatalf("request = %+v", req)
			}
			return encodeResponse(t, response{OK: true, ActionID: "act_" + repeat("a", 64), State: "granted"})
		}
		return encodeResponse(t, response{OK: true, Authorized: true, State: "spent"})
	})
	client, err := NewClient(server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Authorize(context.Background(), actionauth.Action{
		Effect: actionauth.EffectSpend, Summary: "fund accepted quote", MandateID: wantMandate,
		Terms: &actionauth.PurchaseTerms{PriceAtomic: wantPrice},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientVerifiesFinalizedQuoteWithExactExpectedTerms(t *testing.T) {
	commitment := "tvm-cell-sha256:" + repeat("a", 64)
	server := newFakeServer(t, func(raw []byte) []byte {
		var req request
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		if req.Op != "quotes.verify" || req.QuoteCommitment != commitment ||
			req.ExpectedQuoteTerms == nil || req.ExpectedQuoteTerms.PriceAtomic != "42" {
			t.Fatalf("request = %+v", req)
		}
		return encodeResponse(t, response{OK: true, FinalizedQuote: &finalizedQuoteEvidence{
			Commitment: commitment, EscrowAccount: "0:" + repeat("b", 64),
			TransactionHash:     "sha256:" + repeat("c", 64),
			ContractCodeHash:    "tvm-cell-sha256:" + repeat("d", 64),
			FinalizedCheckpoint: 19, FinalizedAtUnix: 2_000_000_000,
		}})
	})
	client, err := NewClient(server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyAcceptedQuote(
		context.Background(), commitment, actionauth.PurchaseTerms{PriceAtomic: "42"},
	); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsIncompleteFinalizedQuoteEvidence(t *testing.T) {
	commitment := "tvm-cell-sha256:" + repeat("a", 64)
	server := newFakeServer(t, func([]byte) []byte {
		return encodeResponse(t, response{OK: true, FinalizedQuote: &finalizedQuoteEvidence{
			Commitment: commitment,
		}})
	})
	client, err := NewClient(server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyAcceptedQuote(
		context.Background(), commitment, actionauth.PurchaseTerms{PriceAtomic: "42"},
	); !errors.Is(err, ErrQuoteUnverified) {
		t.Fatalf("error = %v", err)
	}
}

func TestClientRefusesMalformedSpendBeforeConnecting(t *testing.T) {
	client, err := NewClient(filepath.Join(t.TempDir(), "absent.sock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authorize(context.Background(), actionauth.Action{
		Effect: actionauth.EffectSpend, Summary: "fund",
	}); !errors.Is(err, ErrRefused) {
		t.Fatalf("error = %v", err)
	}
}

func TestConcurrentRetryConsumesOneToolGrant(t *testing.T) {
	var claims atomic.Int32
	server := newFakeServer(t, func(raw []byte) []byte {
		var req request
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		if req.Op == "actions.request" {
			return encodeResponse(t, response{OK: true, ActionID: "act_" + repeat("a", 64), State: "granted"})
		}
		first := claims.Add(1) == 1
		return encodeResponse(t, response{OK: true, Authorized: first, State: "spent"})
	})
	client, err := NewClient(server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	action := actionauth.Action{
		Effect:         actionauth.EffectToolCall,
		Summary:        "invoke scanner",
		IdempotencyKey: "idem_" + repeat("b", 64),
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- client.Authorize(context.Background(), action) }()
	}
	allowed := 0
	refused := 0
	for range 2 {
		if err := <-results; err == nil {
			allowed++
		} else if errors.Is(err, ErrRefused) {
			refused++
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if allowed != 1 || refused != 1 {
		t.Fatalf("allowed=%d refused=%d", allowed, refused)
	}
}

func newFakeServer(t *testing.T, respond func([]byte) []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var header [4]byte
			if _, err := io.ReadFull(connection, header[:]); err != nil {
				connection.Close()
				continue
			}
			body := make([]byte, binary.BigEndian.Uint32(header[:]))
			if _, err := io.ReadFull(connection, body); err != nil {
				connection.Close()
				continue
			}
			answer := respond(body)
			binary.BigEndian.PutUint32(header[:], uint32(len(answer)))
			_ = writeAll(connection, header[:])
			_ = writeAll(connection, answer)
			connection.Close()
		}
	}()
	return path
}

func encodeResponse(t *testing.T, value response) []byte {
	t.Helper()
	value.Schema = responseSchema
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func repeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
