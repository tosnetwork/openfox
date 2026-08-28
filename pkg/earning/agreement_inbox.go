package earning

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// ClaimedAgreementEvent is authenticated conversation evidence released only
// from Messenger's typed Agreement inbox. It is never routed through a model
// or treated as authorization merely because it was received.
type ClaimedAgreementEvent struct {
	EventID, LeaseID, SenderAgentID, SenderEndpointID, SenderDeviceID, ConversationID string
	Kind, SemanticActionID                                                            string
	Application                                                                       *commerce.IntentApplication
	Proposal                                                                          *payload.AgreementPropose
	Acceptance                                                                        *payload.AgreementAccept
	Evidence                                                                          *payload.AgreementEvidence
	ProviderOffer                                                                     *payload.PaidDemandProviderOffer
	Withdrawal                                                                        *payload.AgreementWithdraw
	Delivery                                                                          *payload.AgreementDelivery
}

type AgreementInbox struct {
	Client       MessengerCaller
	LeaseSeconds uint64
}

func (inbox AgreementInbox) ClaimNext(ctx context.Context) (*ClaimedAgreementEvent, error) {
	if inbox.Client == nil {
		return nil, errors.New("Agreement inbox is unavailable")
	}
	listing, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpPendingAgreements, Limit: 1})
	if err != nil || len(listing.Events) == 0 {
		return nil, err
	}
	lease, err := newAgreementLeaseID()
	if err != nil {
		return nil, err
	}
	duration := inbox.LeaseSeconds
	if duration == 0 {
		duration = uint64((2 * time.Minute) / time.Second)
	}
	claimed, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpClaimAgreement,
		EventID: listing.Events[0].EventID, LeaseID: lease, LeaseSeconds: duration})
	if err != nil {
		return nil, err
	}
	if claimed.Event == nil {
		return nil, errors.New("Messenger omitted the claimed Agreement event")
	}
	decoded, err := envelope.DecodeEventJSON(claimed.Event.Event)
	if err != nil {
		_ = inbox.Reject(ctx, claimed.Event.EventID, lease, fault.CodeNotAuthentic)
		return nil, err
	}
	body, err := payload.DecodeSchema(decoded.Kind, decoded.PayloadSchema, decoded.Content)
	if err != nil {
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
		return nil, err
	}
	if !economicIdempotencyPattern.MatchString(decoded.IdempotencyKey) {
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
		return nil, errors.New("Agreement event lacks its stable economic action identity")
	}
	result := &ClaimedAgreementEvent{EventID: decoded.EventID, LeaseID: lease, SenderAgentID: decoded.SenderAgentID,
		SenderEndpointID: decoded.SenderEndpointID, SenderDeviceID: decoded.SenderDeviceID,
		ConversationID: decoded.ConversationID, Kind: decoded.Kind,
		SemanticActionID: "sha256:" + decoded.IdempotencyKey}
	switch value := body.(type) {
	case payload.IntentApplication:
		application, decodeErr := commerce.DecodeIntentApplication(value.CanonicalApplication)
		if decodeErr != nil || application.ApplicantAgentID != decoded.SenderAgentID {
			_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeNotAuthentic)
			return nil, errors.New("Intent application sender binding is invalid")
		}
		result.Application = &application
	case payload.AgreementPropose:
		result.Proposal = &value
	case payload.AgreementAccept:
		result.Acceptance = &value
	case payload.AgreementEvidence:
		result.Evidence = &value
	case payload.PaidDemandProviderOffer:
		result.ProviderOffer = &value
	case payload.AgreementWithdraw:
		result.Withdrawal = &value
	case payload.AgreementDelivery:
		result.Delivery = &value
	default:
		_ = inbox.Reject(ctx, decoded.EventID, lease, fault.CodeUnknownEventKind)
		return nil, errors.New("typed Agreement inbox returned another payload class")
	}
	return result, nil
}

// Messenger's owner-private API accepts idem_<hex>, but the immutable Event
// wire format intentionally carries only the canonical 32-byte hex token.
var economicIdempotencyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (inbox AgreementInbox) Complete(ctx context.Context, event *ClaimedAgreementEvent) error {
	if event == nil || event.EventID == "" || event.LeaseID == "" {
		return errors.New("Agreement completion lacks its exact lease")
	}
	_, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpComplete, EventID: event.EventID, LeaseID: event.LeaseID})
	return err
}

func (inbox AgreementInbox) Reject(ctx context.Context, eventID, leaseID string, code fault.Code) error {
	if eventID == "" || leaseID == "" || !fault.Known(code) {
		return errors.New("Agreement rejection is invalid")
	}
	_, err := inbox.Client.Call(ctx, localapi.Request{Op: localapi.OpReject, EventID: eventID, LeaseID: leaseID, Code: code})
	return err
}

func newAgreementLeaseID() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "lease_" + hex.EncodeToString(value[:]), nil
}
