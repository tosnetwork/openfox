package earning

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

func TestGuarantorAutonomyCompletesOnlyDurableHandling(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	caller, inbox := guarantorAutonomyTestInbox(t, now)
	handled := 0
	autonomy := GuarantorAutonomy{Inbox: inbox, Handler: GuarantorProfileEventHandlerFunc(
		func(context.Context, *ClaimedCommerceProfileEvent) error { handled++; return nil })}
	processed, err := autonomy.Process(context.Background(), 10)
	if err != nil || processed != 1 || handled != 1 || !caller.complete || caller.reject {
		t.Fatalf("durable Guarantor event was not completed exactly once: processed=%d handled=%d caller=%#v err=%v",
			processed, handled, caller, err)
	}

	caller, inbox = guarantorAutonomyTestInbox(t, now)
	autonomy = GuarantorAutonomy{Inbox: inbox, Handler: GuarantorProfileEventHandlerFunc(
		func(context.Context, *ClaimedCommerceProfileEvent) error { return errors.New("authority unavailable") })}
	if processed, err = autonomy.Process(context.Background(), 1); err == nil || processed != 0 || caller.complete || caller.reject {
		t.Fatalf("ambiguous Guarantor event was acknowledged: processed=%d caller=%#v err=%v", processed, caller, err)
	}

	caller, inbox = guarantorAutonomyTestInbox(t, now)
	autonomy = GuarantorAutonomy{Inbox: inbox, Handler: GuarantorProfileEventHandlerFunc(
		func(context.Context, *ClaimedCommerceProfileEvent) error {
			return PermanentGuarantorEventError{Code: fault.CodePayloadMalformed, Err: errors.New("bad claim")}
		})}
	if processed, err = autonomy.Process(context.Background(), 10); err != nil || processed != 1 || !caller.reject || caller.complete {
		t.Fatalf("permanent Guarantor event was not rejected exactly: processed=%d caller=%#v err=%v", processed, caller, err)
	}
}

func guarantorAutonomyTestInbox(t *testing.T, now time.Time) (*profileInboxCaller, CommerceProfileInbox) {
	t.Helper()
	// Reuse the exact authenticated fixture builder exercised by the inbox test.
	caller, inbox := newProfileInboxFixture(t, now)
	return caller, inbox
}
