package earning

import (
	"errors"
	"time"

	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

// GuarantorProviderRuntimeConfig is the explicit production assembly boundary
// for a Guarantor Provider. No model output, Carrier metadata, or inbound
// message may populate these dependencies. Deployments are expected to source
// them from owner-authored configuration and independently authenticated
// authority/Adapter clients.
type GuarantorProviderRuntimeConfig struct {
	Inbox              CommerceProfileInbox
	Coordinator        *GuarantorProviderCoordinator
	Engine             *Engine
	Fence              WriterFenceProvider
	Planner            GuarantorFirmOfferPlanner
	Unhandled          GuarantorUnhandledEventHandler
	ImmutablePublisher guarantor.ImmutableCommerceObjectPublisher
	PolicyRevision     uint64
	MaximumEventTTL    time.Duration
}

// NewGuarantorProviderRuntime assembles the production Messenger-to-provider
// coordinator. It intentionally refuses partial deployments: quote planning,
// economic authority, historical signature resolution, durable journals, and
// outbound Messenger admission must all be installed before any event can be
// claimed from the isolated commerce inbox.
func NewGuarantorProviderRuntime(config GuarantorProviderRuntimeConfig) (*GuarantorAutonomy, error) {
	coordinator := config.Coordinator
	if coordinator == nil || coordinator.Authority == nil || coordinator.Journal == nil || coordinator.Signer == nil ||
		coordinator.ActionAuthoritySigner == nil || coordinator.FallbackSigner == nil || coordinator.Resolver == nil ||
		coordinator.PublicationResolver == nil || coordinator.UnderlyingAgreementResolver == nil ||
		coordinator.AgreementVerifier == nil || coordinator.Underwriter == nil || coordinator.Eligibility == nil ||
		coordinator.RiskBuckets == nil || coordinator.OwnerID == "" || coordinator.AgentID == "" ||
		coordinator.PolicyRevision == 0 || config.Engine == nil || config.Engine.Authority != coordinator.Authority ||
		config.Engine.OwnerID != coordinator.OwnerID || config.Engine.AgentID != coordinator.AgentID ||
		config.Engine.MandateDigest != coordinator.MandateDigest || config.Engine.Sink == nil ||
		config.Inbox.Client == nil || config.Inbox.Verifier == nil ||
		!config.Engine.Gates.AgentGuarantor || config.Fence == nil || config.Planner == nil || config.PolicyRevision == 0 ||
		config.PolicyRevision != coordinator.PolicyRevision || config.MaximumEventTTL < time.Second ||
		config.MaximumEventTTL > 30*24*time.Hour {
		return nil, errors.New("Guarantor Provider runtime dependencies are incomplete, inconsistent, or unbounded")
	}
	handler := &GuarantorProviderEventHandler{Coordinator: coordinator, Engine: config.Engine, Fence: config.Fence,
		Planner: config.Planner, Unhandled: config.Unhandled, ImmutablePublisher: config.ImmutablePublisher,
		PolicyRevision: config.PolicyRevision, MaximumEventTTL: config.MaximumEventTTL}
	return &GuarantorAutonomy{Inbox: config.Inbox, Handler: handler}, nil
}
