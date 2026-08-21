package agent

import (
	"errors"

	"github.com/tosnetwork/openfox/pkg/bus"
)

var errAuthenticatedInboundReplay = errors.New("authenticated inbound Event was already applied")

func reportApplicationResult(result chan error, err error) {
	if result == nil {
		return
	}
	select {
	case result <- err:
	default:
	}
}

func authenticatedApplicationEventID(opts processOptions) (string, error) {
	if opts.ApplicationResult == nil {
		return "", nil
	}
	if opts.NoHistory || opts.Dispatch.InboundContext == nil ||
		opts.Dispatch.InboundContext.AuthenticatedMessagingOrigin == nil {
		return "", errors.New("durable application result requires authenticated session history")
	}
	eventID := opts.Dispatch.InboundContext.AuthenticatedMessagingOrigin.EventID
	if eventID == "" || eventID != opts.Dispatch.InboundContext.MessageID {
		return "", errors.New("durable application result has an invalid Event ID binding")
	}
	return eventID, nil
}

func reportMessageApplication(msg bus.InboundMessage, err error) {
	reportApplicationResult(msg.ApplicationResult, err)
}
