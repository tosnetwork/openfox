package earning

import (
	"context"
	"errors"
	"strings"

	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type MessengerCaller interface {
	Call(context.Context, localapi.Request) (localapi.Response, error)
}

// MessengerSink maps one proof-admitted OpenFox semantic action to one
// daemon-owned direct Event. Recipient routing, Endpoint selection, sessions,
// encryption, Event identity and delivery remain inside tos-messengerd.
type MessengerSink struct {
	Client MessengerCaller
}

func (sink *MessengerSink) Submit(ctx context.Context, action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, exactRequest []byte, message OutboundMessage) (commerce.ActionResolution, error) {
	if sink == nil || sink.Client == nil || len(message.RecipientAgentIDs) != 1 || action.StableActionID == "" || action.ExactRequestDigest == "" {
		return commerce.ActionResolution{}, errors.New("Messenger economic submission is invalid")
	}
	effect, err := commerce.DecodeMessengerEffectRequest(exactRequest)
	if err != nil || effect.EventKind != message.Kind || effect.ContentType != message.ContentType ||
		len(effect.RecipientAgentIDs) != 1 || effect.RecipientAgentIDs[0] != message.RecipientAgentIDs[0] || string(effect.Payload) != string(message.Payload) {
		return commerce.ActionResolution{}, errors.New("Messenger effect differs from the exact authorized request")
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	response, err := sink.Client.Call(ctx, localapi.Request{Op: localapi.OpEconomicSendDirect,
		EconomicAction: &action, EconomicWriterFence: &fence, EconomicFields: wireFields,
		ExactEconomicRequest: append([]byte(nil), exactRequest...)})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	if response.EconomicResolution == nil || response.EconomicResolution.StableActionID != action.StableActionID ||
		response.EconomicResolution.ExactRequestDigest != action.ExactRequestDigest {
		return commerce.ActionResolution{}, errors.New("Messenger returned an unrelated economic resolution")
	}
	resolution := *response.EconomicResolution
	if err := commerce.ValidateActionResolution(resolution); err != nil {
		return commerce.ActionResolution{}, err
	}
	return resolution, nil
}

func (sink *MessengerSink) ResolveAction(ctx context.Context, stableActionID, requestDigest string) (commerce.ActionResolution, error) {
	if sink == nil || sink.Client == nil || !strings.HasPrefix(stableActionID, "sha256:") {
		return commerce.ActionResolution{}, errors.New("Messenger sink is unavailable")
	}
	response, err := sink.Client.Call(ctx, localapi.Request{Op: localapi.OpEconomicActionStatus,
		EconomicStableID: stableActionID, EconomicRequestDigest: requestDigest})
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	if response.EconomicResolution == nil {
		return commerce.ActionResolution{}, errors.New("Messenger omitted economic action status")
	}
	return *response.EconomicResolution, commerce.ValidateActionResolution(*response.EconomicResolution)
}
