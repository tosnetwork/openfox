package earning

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

// GuarantorProfileEventHandler is the business-profile boundary behind the
// generic Messenger inbox. The handler must durably commit or recover the exact
// object before returning nil; only then may the Messenger lease be completed.
type GuarantorProfileEventHandler interface {
	HandleGuarantorProfileEvent(context.Context, *ClaimedCommerceProfileEvent) error
}

type GuarantorProfileEventHandlerFunc func(context.Context, *ClaimedCommerceProfileEvent) error

func (handler GuarantorProfileEventHandlerFunc) HandleGuarantorProfileEvent(ctx context.Context,
	event *ClaimedCommerceProfileEvent) error {
	return handler(ctx, event)
}

// PermanentGuarantorEventError marks an authenticated but semantically invalid
// profile object. Transient storage, authority, network, or recovery errors are
// deliberately not wrapped in this type and therefore remain leased for retry.
type PermanentGuarantorEventError struct {
	Code fault.Code
	Err  error
}

func (failure PermanentGuarantorEventError) Error() string {
	if failure.Err == nil {
		return "permanent Guarantor profile event failure"
	}
	return failure.Err.Error()
}

func (failure PermanentGuarantorEventError) Unwrap() error { return failure.Err }

type GuarantorAutonomy struct {
	Inbox   CommerceProfileInbox
	Handler GuarantorProfileEventHandler
}

// Process drains at most limit events. Exactly handled events are completed,
// permanent semantic failures are rejected with a bounded protocol code, and
// ambiguous/transient failures retain their lease for deterministic replay.
func (autonomy *GuarantorAutonomy) Process(ctx context.Context, limit int) (int, error) {
	if autonomy == nil || autonomy.Handler == nil || limit <= 0 || limit > 1000 {
		return 0, errors.New("Guarantor autonomous worker is unavailable or unbounded")
	}
	processed := 0
	for processed < limit {
		event, err := autonomy.Inbox.ClaimNext(ctx)
		if err != nil {
			return processed, err
		}
		if event == nil {
			return processed, nil
		}
		if err := autonomy.Handler.HandleGuarantorProfileEvent(ctx, event); err != nil {
			var permanent PermanentGuarantorEventError
			if errors.As(err, &permanent) {
				code := permanent.Code
				if !fault.Known(code) {
					code = fault.CodeRejected
				}
				if rejectErr := autonomy.Inbox.Reject(ctx, event.EventID, event.LeaseID, code); rejectErr != nil {
					return processed, errors.Join(err, rejectErr)
				}
				processed++
				continue
			}
			return processed, err
		}
		if err := autonomy.Inbox.Complete(ctx, event); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}
