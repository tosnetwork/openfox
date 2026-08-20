package agent

import (
	"strings"

	"github.com/tosnetwork/openfox/pkg/actionauth"
	"github.com/tosnetwork/openfox/pkg/bus"
	"github.com/tosnetwork/openfox/pkg/providers"
)

const (
	provenanceAuthenticated = "authenticated-messaging"
	provenanceTrustedLocal  = "trusted-local"
	provenanceUnattributed  = "untrusted-unattributed"
)

// markUserMessageProvenance attaches runtime facts to the session message. It
// never derives them from message text or model output.
func markUserMessageProvenance(message *providers.Message, inbound *bus.InboundContext) {
	if message == nil || message.Role != "user" {
		return
	}
	message.ActionOrigins = nil
	if inbound == nil || strings.EqualFold(strings.TrimSpace(inbound.Channel), "system") {
		message.ActionProvenanceState = provenanceTrustedLocal
		return
	}
	if inbound.AuthenticatedMessagingOrigin != nil {
		message.ActionProvenanceState = provenanceAuthenticated
		message.ActionOrigins = []actionauth.Origin{*inbound.AuthenticatedMessagingOrigin}
		return
	}
	message.ActionProvenanceState = provenanceUnattributed
}

// actionLineage returns all authenticated received content still represented
// in the live model context. Missing legacy metadata, unattributed remote
// input, a lossy summary, duplicate disagreement, or an unreadably large
// lineage fails closed.
func actionLineage(messages []providers.Message, summary string) ([]actionauth.Origin, bool) {
	if strings.TrimSpace(summary) != "" {
		return nil, false
	}
	origins := make([]actionauth.Origin, 0)
	seen := make(map[string]actionauth.Origin)
	for _, message := range messages {
		if message.Role != "user" {
			continue
		}
		switch message.ActionProvenanceState {
		case provenanceTrustedLocal:
			if len(message.ActionOrigins) != 0 {
				return nil, false
			}
		case provenanceAuthenticated:
			if len(message.ActionOrigins) == 0 {
				return nil, false
			}
			for _, origin := range message.ActionOrigins {
				if existing, duplicate := seen[origin.EventID]; duplicate {
					if existing != origin {
						return nil, false
					}
					continue
				}
				seen[origin.EventID] = origin
				origins = append(origins, origin)
				if len(origins) > actionauth.MaxProvenance {
					return nil, false
				}
			}
		case provenanceUnattributed, "":
			return nil, false
		default:
			return nil, false
		}
	}
	return origins, true
}
