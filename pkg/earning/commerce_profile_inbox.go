package earning

import (
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// ClaimedCommerceProfileEvent is an authenticated, leased economic protocol
// object. It is deliberately separate from chat/model input; receiving it does
// not authorize any Agreement, claim, execution, or payment.
type ClaimedCommerceProfileEvent struct {
	EventID, LeaseID, SenderAgentID, SenderEndpointID, SenderDeviceID, ConversationID string
	SemanticActionID                                                                  string
	ProfileEvent                                                                      commerce.CommerceProfileEventV1
	CanonicalObjectBytes                                                              []byte
}

type CommerceContentRetriever interface {
	Fetch(context.Context, commerce.ContentFetchRequest) ([]byte, error)
}

type CommerceProfileInbox struct {
	Client       MessengerCaller
	Verifier     commerce.CommerceObjectVerifier
	Retriever    CommerceContentRetriever
	LeaseSeconds uint64
	Now          func() time.Time
}

func (inbox CommerceProfileInbox) ClaimNext(ctx context.Context) (*ClaimedCommerceProfileEvent, error) {
	if inbox.Client == nil || inbox.Verifier == nil {
		return nil, errors.New("commerce profile inbox is unavailable")
	}
	listing, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpPendingCommerceProfileEvents, Limit: 1})
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
	claimed, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpClaimCommerceProfileEvent,
		EventID: listing.Events[0].EventID, LeaseID: lease, LeaseSeconds: seconds})
	if err != nil || claimed.Event == nil {
		return nil, errors.New("Messenger did not return a claimed commerce profile event")
	}
	decoded, err := envelope.DecodeEventJSON(claimed.Event.Event)
	if err != nil || decoded.Kind != "commerce.profile-event" || !economicIdempotencyPattern.MatchString(decoded.IdempotencyKey) {
		_ = inbox.Reject(ctx, claimed.Event.EventID, lease, fault.CodeNotAuthentic)
		return nil, errors.New("commerce profile Event authentication metadata is invalid")
	}
	value, err := payload.DecodeSchema(decoded.Kind, decoded.PayloadSchema, decoded.Content)
	wrapped, ok := value.(payload.CommerceProfileEvent)
	if err != nil || !ok {
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
		return nil, errors.New("commerce profile Event payload is invalid")
	}
	now := time.Now().UTC()
	if inbox.Now != nil {
		now = inbox.Now().UTC()
	}
	profileEvent, err := commerce.DecodeCommerceProfileEventV1(wrapped.CanonicalEvent, now)
	if err != nil || profileEvent.ObjectDigest != wrapped.ObjectDigest ||
		commerce.VerifyCommerceProfileEventV1(profileEvent, now, inbox.Verifier) != nil {
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
		return nil, errors.New("commerce profile object failed installed profile verification")
	}
	canonicalObject := append([]byte(nil), profileEvent.CanonicalObjectBytes...)
	if profileEvent.CarriageKind == "content_addressed" {
		if inbox.Retriever == nil || profileEvent.ObjectDescriptor == nil {
			_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
			return nil, errors.New("content-addressed commerce object has no owner-controlled retriever")
		}
		var failures []error
		hadInvalidContent := false
		canonicalObject = nil
		for _, hint := range profileEvent.ObjectDescriptor.RetrievalHints {
			candidate, fetchErr := inbox.Retriever.Fetch(ctx, commerce.ContentFetchRequest{CandidateURL: hint,
				ContentDigest: profileEvent.ObjectDigest, ContentSize: profileEvent.ObjectSizeBytes})
			if fetchErr != nil || len(candidate) == 0 {
				failures = append(failures, fetchErr)
				continue
			}
			if uint64(len(candidate)) != profileEvent.ObjectSizeBytes ||
				inbox.Verifier.VerifyCommerceObject(profileEvent.ProfileURI, profileEvent.ProfileVersion,
					profileEvent.ObjectKind, profileEvent.ObjectContentType, profileEvent.ObjectDigest, candidate) != nil {
				hadInvalidContent = true
				failures = append(failures, errors.New("retrieved commerce object failed exact profile verification"))
				continue
			}
			canonicalObject = candidate
			if len(canonicalObject) != 0 {
				break
			}
		}
		if len(canonicalObject) == 0 {
			if hadInvalidContent {
				_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
			}
			// A transport-only failure is not evidence that a signed descriptor
			// is inauthentic, so it keeps the lease unresolved. At least one
			// digest/size/codec mismatch is an authenticated-content failure.
			return nil, errors.Join(append([]error{errors.New("content-addressed commerce object retrieval failed")}, failures...)...)
		}
	}
	return &ClaimedCommerceProfileEvent{EventID: decoded.EventID, LeaseID: lease, SenderAgentID: decoded.SenderAgentID,
		SenderEndpointID: decoded.SenderEndpointID, SenderDeviceID: decoded.SenderDeviceID,
		ConversationID: decoded.ConversationID, SemanticActionID: "sha256:" + decoded.IdempotencyKey,
		ProfileEvent: profileEvent, CanonicalObjectBytes: canonicalObject}, nil
}

func (inbox CommerceProfileInbox) Complete(ctx context.Context, event *ClaimedCommerceProfileEvent) error {
	if event == nil || event.EventID == "" || event.LeaseID == "" {
		return errors.New("commerce profile completion lacks its exact lease")
	}
	_, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpComplete, EventID: event.EventID, LeaseID: event.LeaseID})
	return err
}

func (inbox CommerceProfileInbox) Reject(ctx context.Context, eventID, leaseID string, code fault.Code) error {
	if eventID == "" || leaseID == "" || !fault.Known(code) {
		return errors.New("commerce profile rejection is invalid")
	}
	_, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpReject, EventID: eventID, LeaseID: leaseID, Code: code})
	return err
}
