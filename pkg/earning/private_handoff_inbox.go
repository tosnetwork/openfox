package earning

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

type ClaimedPrivateHandoffEvent struct {
	EventID, LeaseID, SenderAgentID, ConversationID string
	Kind, SemanticActionID                          string
	Challenge                                       *payload.PrivateHandoffChallenge
	Authorization                                   *payload.PrivateHandoffAuthorization
	Acknowledgement                                 *payload.PrivateHandoffAcknowledgement
	Status                                          *payload.PrivateHandoffStatus
	Delete                                          *payload.PrivateHandoffDelete
}

type PrivateHandoffInbox struct {
	Client       MessengerCaller
	LeaseSeconds uint64
}

func (inbox PrivateHandoffInbox) ClaimNext(ctx context.Context) (*ClaimedPrivateHandoffEvent, error) {
	if inbox.Client == nil {
		return nil, errors.New("private handoff inbox is unavailable")
	}
	listing, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpPendingPrivateHandoffs, Limit: 1})
	if err != nil || len(listing.Events) == 0 {
		return nil, err
	}
	lease, err := newAgreementLeaseID()
	if err != nil {
		return nil, err
	}
	seconds := inbox.LeaseSeconds
	if seconds == 0 {
		seconds = uint64((2 * time.Minute) / time.Second)
	}
	claimed, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpClaimPrivateHandoff,
		EventID: listing.Events[0].EventID, LeaseID: lease, LeaseSeconds: seconds})
	if err != nil || claimed.Event == nil {
		return nil, errors.New("Messenger did not return a claimed private handoff event")
	}
	decoded, err := envelope.DecodeEventJSON(claimed.Event.Event)
	if err != nil || !economicIdempotencyPattern.MatchString(decoded.IdempotencyKey) {
		_ = inbox.Reject(ctx, claimed.Event.EventID, lease, fault.CodeNotAuthentic)
		return nil, errors.New("private handoff Event authentication metadata is invalid")
	}
	value, err := payload.DecodeSchema(decoded.Kind, decoded.PayloadSchema, decoded.Content)
	if err != nil {
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
		return nil, err
	}
	result := &ClaimedPrivateHandoffEvent{EventID: decoded.EventID, LeaseID: lease, SenderAgentID: decoded.SenderAgentID,
		ConversationID: decoded.ConversationID, Kind: decoded.Kind,
		SemanticActionID: "sha256:" + strings.TrimPrefix(decoded.IdempotencyKey, "idem_")}
	switch typed := value.(type) {
	case payload.PrivateHandoffChallenge:
		result.Challenge = &typed
	case payload.PrivateHandoffAuthorization:
		result.Authorization = &typed
	case payload.PrivateHandoffAcknowledgement:
		result.Acknowledgement = &typed
	case payload.PrivateHandoffStatus:
		result.Status = &typed
	case payload.PrivateHandoffDelete:
		result.Delete = &typed
	default:
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeUnknownEventKind)
		return nil, errors.New("typed private handoff inbox returned another payload class")
	}
	return result, nil
}

func (inbox PrivateHandoffInbox) Complete(ctx context.Context, event *ClaimedPrivateHandoffEvent) error {
	if event == nil || event.EventID == "" || event.LeaseID == "" {
		return errors.New("private handoff completion lacks its exact lease")
	}
	_, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpComplete, EventID: event.EventID, LeaseID: event.LeaseID})
	return err
}

func (inbox PrivateHandoffInbox) Reject(ctx context.Context, eventID, leaseID string, code fault.Code) error {
	if eventID == "" || leaseID == "" || !fault.Known(code) {
		return errors.New("private handoff rejection is invalid")
	}
	_, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpReject, EventID: eventID, LeaseID: leaseID, Code: code})
	return err
}
