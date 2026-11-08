package servicebridge

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
)

// A carrier or anyone who knows the source can copy a paid task, but naming
// itself as the return Agent must not open the paid execution id.
func TestAPaidTaskResentUnderAnotherAgentIsRefused(t *testing.T) {
	provider := &Provider{config: ProviderConfig{AgentID: testSeller, Network: testNetwork}}
	message, task := taskMessage(t, testPackage(t, nil), fill(100, 1), testBuyer)
	if _, _, _, err := provider.claimFor(message, task); err != nil {
		t.Fatalf("the buyer's own task was refused: %v", err)
	}
	attacker := "agent_" + strings.Repeat("c3", 32)
	stolen := task
	stolen.Header.BuyerAgentID = attacker
	resent := message
	resent.SenderAgentID = attacker
	if _, _, _, err := provider.claimFor(resent, stolen); err == nil {
		t.Fatal("a paid task resent under another Agent was admitted")
	}
	var forged [32]byte
	if _, err := rand.Read(forged[:]); err != nil {
		t.Fatal(err)
	}
	stolen.Header.ExecutionNonce = hex.EncodeToString(forged[:])
	if _, _, _, err := provider.claimFor(resent, stolen); err == nil {
		t.Fatal("a fresh nonce opened the paid execution id to another Agent")
	}
	unopened := task
	unopened.Header.ExecutionNonce = ""
	if _, _, _, err := provider.claimFor(message, unopened); err == nil {
		t.Fatal("a task without an execution nonce was admitted")
	}
}

func TestTheBuyersDrawnExecutionOpensOnlyToItsOwnAgent(t *testing.T) {
	id, nonce, err := drawExecution(testBuyer, func(b []byte) error { _, err := rand.Read(b); return err })
	if err != nil {
		t.Fatal(err)
	}
	if ExecutionIDFor(testBuyer, nonce) != id || ExecutionIDFor(testSeller, nonce) == id {
		t.Fatal("the drawn execution id does not commit to the buyer Agent alone")
	}
	if _, _, err = drawExecution(testBuyer, func([]byte) error { return nil }); err == nil {
		t.Fatal("an all-zero nonce was accepted")
	}
	if _, _, err = drawExecution(testBuyer, func([]byte) error { return errors.New("no entropy") }); err == nil {
		t.Fatal("a failed draw was accepted")
	}
}

func TestResultRetentionRunsFromTheEndOfTheResponseWindow(t *testing.T) {
	end, err := resultRetentionEnd(1_000, 3_600)
	if err != nil || end != 4_600 {
		t.Fatalf("retention end %d %v", end, err)
	}
	if _, err := resultRetentionEnd(1_000, 0); err == nil {
		t.Fatal("a manifest retaining nothing was accepted")
	}
	if _, err := resultRetentionEnd(math.MaxUint64-10, 11); err == nil {
		t.Fatal("an overflowing retention was accepted")
	}
}
