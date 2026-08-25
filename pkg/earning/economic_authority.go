package earning

import (
	"context"
	"crypto/ed25519"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// EconomicAuthority is the owner-scoped linearization boundary. The personal
// profile implements it with one locked local journal. The shared profile must
// implement the same calls through one authenticated strongly-consistent
// authority service; callers never receive its signing key.
type EconomicAuthority interface {
	AcquireWriter(context.Context, string, []string, time.Duration) (commerce.WriterFence, error)
	Admit(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence, *ExposureReservation) (commerce.ActionResolution, error)
	Resolve(string, string) commerce.ActionResolution
	Transition(string, string, commerce.ActionResolutionState, string, []string) (commerce.ActionResolution, error)
	AllocateInstance(commerce.AuthorityInstanceAllocationRequest, commerce.WriterFence) (commerce.AuthorityInstanceRecord, error)
	Snapshot() (uint64, PortfolioLimits, []ExposureReservation)
	ReleaseReservation(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence) (commerce.ActionResolution, error)
	AuthorizeFenceKey(string, ed25519.PublicKey, time.Time) error
	ConfirmCurrentWriterFence(commerce.WriterFence, time.Time) error
	AuthorityNow() time.Time
	SignAction(commerce.AuthorizedAction, commerce.WriterFence) (commerce.AuthorizedAction, error)
	AuthorizeCustodyPayment(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		commerce.AgreementPaymentRequest, string, int32) (commerce.CustodyActionAuthorization, error)
	AuthorizeCustodyEffect(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		commerce.CustodyEffectAuthorization) (commerce.CustodyEffectAuthorization, error)

	RecordAgreementProposal(commerce.AgentAgreementBody, string, string, string) (EngagementRecord, error)
	ObserveAgreementWithdrawal(string, string, string, string) (EngagementRecord, error)
	ObserveAgreementDelivery(string, string, string, string, string) (EngagementRecord, error)
	RecordAgreementEvidence(string, commerce.AgreementAuthorizationEvidence, commerce.AgreementEvidenceVerifier) (EngagementRecord, error)
	ReserveEngagement(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		PortfolioReservationRequest) (commerce.ActionResolution, EngagementRecord, error)
	Engagement(string) (EngagementRecord, bool)
	EngagementSnapshot() []EngagementRecord
	BindAcceptedPrivateInput(string, string, commerce.AcceptedPrivateContentRecord) (EngagementRecord, error)
	RecordPrivateHandoffChallenge(string, string, string, string) (EngagementRecord, error)
	transitionEngagement(string, EngagementState, EngagementState, string, []string) (EngagementRecord, error)
	transitionObligation(string, string, ObligationRuntimeState, ObligationRuntimeState, string, []string, string) (EngagementRecord, error)
	completeNoPaymentEngagement(string, string) (EngagementRecord, error)

	AdmitScheduleTransition(commerce.AuthorizedAction, []byte, commerce.WriterFence) (commerce.ActionResolution, error)
	AdmitDependencyTransition(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		DependencyTransitionRequest) (commerce.ActionResolution, error)
	ScheduleSnapshot() ([]commerce.EngagementScheduleEntry, []commerce.PortfolioDependency)
	ResolveSettlementState(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		BillingStateTransitionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error)
	MaterializeSettlement(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		commerce.SettlementObligation) (commerce.ActionResolution, SettlementLedgerRecord, error)
	SettlementSnapshot(string) []SettlementLedgerRecord
	ApplySettlementPayment(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		BillingResolutionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error)
	RecordAccounting(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		AccountingEntry) (commerce.ActionResolution, AccountingEntry, error)
	AccountingSnapshot() []AccountingEntry
	reconciliationSnapshot() (uint64, []ExposureReservation, map[string]EngagementRecord)
}

var _ EconomicAuthority = (*PersonalAuthority)(nil)
