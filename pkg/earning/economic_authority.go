package earning

import (
	"context"
	"crypto/ed25519"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
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
	ReleaseGuarantorReservation(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence, uint64, uint64) (commerce.ActionResolution, error)
	AuthorizeFenceKey(string, ed25519.PublicKey, time.Time) error
	ConfirmCurrentWriterFence(commerce.WriterFence, time.Time) error
	AuthorityNow() time.Time
	SignAction(commerce.AuthorizedAction, commerce.WriterFence) (commerce.AuthorizedAction, error)
	AuthorizeCustodyPayment(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte, commerce.WriterFence,
		commerce.AgreementPaymentRequest, string, commerce.CustodyNetworkDomain,
		*SponsorshipCustodyBinding) (commerce.CustodyActionAuthorization, error)
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

// RelaySponsorshipCustodyPurpose is the exact semantic purpose stored by the
// owner authority when it atomically admits a Provider-funded gas top-up and
// its maximum-loss hold. Its digest also binds the AuthorizedAction, but that
// caller-provided digest is never sufficient authorization by itself.
type RelaySponsorshipCustodyPurpose struct {
	SchemaVersion                    uint16                           `json:"schema_version"`
	PaymentRequestDigest             string                           `json:"payment_request_digest"`
	RelayExecutionDigest             string                           `json:"relay_execution_request_digest"`
	QuoteRequest                     agentrelay.RelayQuoteRequestBody `json:"quote_request"`
	AgreementBody                    commerce.AgentAgreementBody      `json:"agreement_body"`
	AgreementBodyDigest              string                           `json:"agreement_body_digest"`
	AgreementObligationID            string                           `json:"agreement_obligation_id"`
	ProviderQuoteDigest              string                           `json:"provider_quote_digest"`
	SponsorshipTerminalProfileDigest string                           `json:"sponsorship_terminal_profile_digest"`
	FinalityProfileCBORDigest        string                           `json:"finality_profile_cbor_digest"`
	ReleaseProfileDigest             string                           `json:"release_profile_digest"`
	CorroborationSnapshotID          string                           `json:"corroboration_snapshot_identity"`
}

// SponsorshipCustodyBinding identifies the exact durable owner-authority
// admission that custody must look up. The authority revalidates its stored
// purpose, payment, retained action and live reservation; this value is not a
// bearer permission. The three evidence digests are emitted for tosctl.
type SponsorshipCustodyBinding struct {
	AdmissionID               string `json:"admission_id"`
	PaymentRequestDigest      string `json:"payment_request_digest"`
	PurposeDigest             string `json:"purpose_digest"`
	ReservationID             string `json:"reservation_id"`
	FinalityProfileCBORDigest string `json:"finality_profile_cbor_digest"`
	ReleaseProfileDigest      string `json:"release_profile_digest"`
	CorroborationSnapshotID   string `json:"corroboration_snapshot_identity"`
}

// RelaySponsorshipAdmissionAuthority atomically persists both the exact relay
// purpose and its live maximum-loss reservation with the prepared payment
// action. Custody accepts only the returned admission identity.
type RelaySponsorshipAdmissionAuthority interface {
	AdmitRelaySponsorshipPayment(commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte,
		commerce.WriterFence, commerce.AgreementPaymentRequest, RelaySponsorshipCustodyPurpose) (
		commerce.ActionResolution, SponsorshipCustodyBinding, error)
}

var _ EconomicAuthority = (*PersonalAuthority)(nil)
var _ RelaySponsorshipAdmissionAuthority = (*PersonalAuthority)(nil)
var _ RelaySponsorshipAdmissionAuthority = (*SharedAuthorityClient)(nil)
var _ RelaySponsorshipAdmissionAuthority = (*OutcomeRecordingAuthority)(nil)
