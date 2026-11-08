package servicebridge

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	"google.golang.org/protobuf/proto"
)

// scriptedChecker answers the pre-respond check with a configured error.
type scriptedChecker struct {
	err      error
	rechecks int
}

func (c *scriptedChecker) Lookup(key railgate.SlotKey) (railgate.Slot, bool, error) {
	return railgate.Slot{
		QuoteCommitment: key.QuoteCommitment, Actor: key.Actor, RequestID: key.RequestID,
		State: railgate.SlotCompleted,
	}, true, nil
}

func (c *scriptedChecker) Recheck(context.Context, railgate.Slot, railgate.Claim, *railgate.Verified) error {
	c.rechecks++
	return c.err
}

func executedProvider(
	t *testing.T,
	now time.Time,
	deadline uint64,
) (*Provider, *scriptedChecker, *countingLifecycle, string) {
	t.Helper()
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testSeller), &recordingTransport{})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "provider")
	if err = ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	checker := &scriptedChecker{err: errors.New("finalized read unavailable")}
	lifecycle := &countingLifecycle{}
	provider := &Provider{config: ProviderConfig{
		Directory: directory, Lifecycle: lifecycle, Courier: courier, History: emptyHistoryReader{},
		AttestorController: "attestor", Now: func() time.Time { return now },
	}, checker: checker}
	raw, err := proto.Marshal(testPackage(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	key := railgate.SlotKey{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("ab", 32),
		Actor:           "0:" + strings.Repeat("77", 32), RequestID: 7,
	}
	record := ProviderRecord{
		State:            ProviderExecuted,
		BuyerAgentID:     testBuyer,
		QuoteCommitment:  key.QuoteCommitment,
		Actor:            key.Actor,
		RequestID:        key.RequestID,
		RequestHash:      strings.Repeat("99", 32),
		ResponseHash:     strings.Repeat("aa", 32),
		ResponseDeadline: deadline,
		RetentionEndUnix: deadline + 3600,
		PackageBase64:    base64.StdEncoding.EncodeToString(raw),
		BuyerWallet:      testWallet,
		ExecutionID:      strings.Repeat("01", 32),
		InputDigest:      strings.Repeat("02", 32),
		PriceNanoTOS:     "1000",
	}
	if err := provider.store(key, record, true); err != nil {
		t.Fatal(err)
	}
	return provider, checker, lifecycle, provider.recordPath(key)
}

func providerState(t *testing.T, path string) string {
	t.Helper()
	var record ProviderRecord
	if err := readJSON(path, 64<<10, &record); err != nil {
		t.Fatal(err)
	}
	return record.State
}

func TestTheProviderRespondsOnceAFailedPreRespondCheckPasses(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	provider, checker, lifecycle, path := executedProvider(t, now, uint64(now.Unix())+600)
	if err := provider.Tick(context.Background()); err == nil {
		t.Fatal("a failing pre-respond check was not reported")
	}
	if state := providerState(t, path); state != ProviderExecuted || lifecycle.responds != 0 {
		t.Fatalf("after a failed check: state %s, %d responds", state, lifecycle.responds)
	}
	checker.err = nil
	if err := provider.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := providerState(
		t,
		path,
	); state != ProviderResponding || lifecycle.responds != 1 ||
		checker.rechecks != 2 {
		t.Fatalf("after the check passed: state %s, %d responds, %d rechecks",
			state, lifecycle.responds, checker.rechecks)
	}
}

func TestTheProviderNeverRespondsToExecutedWorkPastTheResponseDeadline(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	provider, checker, lifecycle, path := executedProvider(t, now, uint64(now.Unix()))
	checker.err = nil
	if err := provider.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := providerState(t, path); state != ProviderAbandoned || lifecycle.responds != 0 || checker.rechecks != 0 {
		t.Fatalf("past the deadline: state %s, %d responds, %d rechecks", state, lifecycle.responds, checker.rechecks)
	}
}
