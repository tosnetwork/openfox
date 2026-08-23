package cliprovider

import (
	"context"
	"fmt"
	"strings"
)

type agentBackendPrincipal struct {
	channel  string
	senderID string
	internal bool
}

type agentBackendPrincipalKey struct{}

func WithAgentBackendPrincipal(ctx context.Context, channel, senderID string) context.Context {
	return context.WithValue(ctx, agentBackendPrincipalKey{}, agentBackendPrincipal{
		channel: strings.TrimSpace(channel), senderID: strings.TrimSpace(senderID),
	})
}

func WithInternalAgentBackendPrincipal(ctx context.Context) context.Context {
	return context.WithValue(ctx, agentBackendPrincipalKey{}, agentBackendPrincipal{internal: true})
}

func (o RuntimeOptions) authorizePrincipal(ctx context.Context) error {
	if o.SubscriptionUse != "local-personal" {
		return nil
	}
	principal, ok := ctx.Value(agentBackendPrincipalKey{}).(agentBackendPrincipal)
	if !ok {
		return fmt.Errorf("personal subscription request has no trusted caller principal")
	}
	if principal.internal {
		if o.AllowInternal {
			return nil
		}
		return fmt.Errorf("personal subscription does not allow internal automation")
	}
	if principal.channel != o.OwnerChannel || principal.senderID != o.OwnerSenderID {
		return fmt.Errorf("personal subscription request principal is not the configured owner")
	}
	return nil
}
