package earning

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-messenger/pkg/payload"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type MessengerDeliverySink struct{ Messenger *MessengerSink }

func (sink MessengerDeliverySink) AuthorizationRequest(request DeliveryReleaseRequest) ([]byte, error) {
	body, err := payload.Encode(payload.AgreementDelivery{AgreementBodyDigest: request.AgreementBodyDigest,
		ObligationID: request.ObligationID, DeliverableManifestDigest: request.DeliverableManifestDigest})
	if err != nil {
		return nil, err
	}
	return commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: []string{request.RecipientAgentID}, EventKind: "agreement.delivery",
		ContentType: payload.AgreementDelivery{}.Schema(), Payload: body})
}

func (sink MessengerDeliverySink) SubmitDelivery(ctx context.Context, action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, exactRequest []byte, request DeliveryReleaseRequest) (commerce.ActionResolution, error) {
	if sink.Messenger == nil {
		return commerce.ActionResolution{}, errors.New("Messenger delivery sink is unavailable")
	}
	expected, err := sink.AuthorizationRequest(request)
	if err != nil || string(expected) != string(exactRequest) {
		return commerce.ActionResolution{}, errors.New("Messenger delivery differs from its exact authorized request")
	}
	effect, err := commerce.DecodeMessengerEffectRequest(exactRequest)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	return sink.Messenger.Submit(ctx, action, fence, fields, exactRequest, OutboundMessage{Kind: effect.EventKind,
		RecipientAgentIDs: effect.RecipientAgentIDs, ContentType: effect.ContentType, Payload: effect.Payload})
}

func (sink MessengerDeliverySink) ResolveAction(ctx context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	if sink.Messenger == nil {
		return commerce.ActionResolution{}, errors.New("Messenger delivery sink is unavailable")
	}
	return sink.Messenger.ResolveAction(ctx, actionID, requestDigest)
}
