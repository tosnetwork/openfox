package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

const (
	authoritySchema                    = "tos.openfox.owner-economic-action-authority.v1"
	authorityFile                      = "economic-authority.json"
	authorityLock                      = "economic-authority.lock"
	maximumRelayAdmissions             = 4096
	maximumIssuedCustodyAuthorizations = 4096
)

type ExposureReservation struct {
	ReservationID   string `json:"reservation_id"`
	AgreementDigest string `json:"agreement_digest"`
	// Asset is present for asset-denominated economic exposure. A nil value
	// retains the legacy deployment-wide bucket used by non-monetary and
	// pre-V1 callers; different exact assets are never numerically added.
	Asset               *commerce.AssetIdentityV1 `json:"asset,omitempty"`
	ComputeUnits        uint64                    `json:"compute_units"`
	SpendAtomic         uint64                    `json:"spend_atomic"`
	LockedCapitalAtomic uint64                    `json:"locked_capital_atomic"`
	ReceivableAtomic    uint64                    `json:"receivable_atomic"`
	MaximumLossAtomic   uint64                    `json:"maximum_loss_atomic"`
	Released            bool                      `json:"released"`
}

type relaySponsorshipPaymentAdmission struct {
	AdmissionID                       string                           `json:"admission_id"`
	Payment                           commerce.AgreementPaymentRequest `json:"payment"`
	PaymentRequestDigest              string                           `json:"payment_request_digest"`
	Purpose                           RelaySponsorshipCustodyPurpose   `json:"purpose"`
	PurposeDigest                     string                           `json:"purpose_digest"`
	Reservation                       ExposureReservation              `json:"reservation"`
	CustodyAuthorizationExpiredAtUnix uint64                           `json:"custody_authorization_expired_at_unix,omitempty"`
	ExpiredCustodyAuthorization       *expiredCustodyAuthorization     `json:"expired_custody_authorization,omitempty"`
}

// issuedCustodyPaymentAuthorization keeps Portfolio exposure live for every
// offline-verifiable native custody capability. A signed authorization can
// outlive its writer process, so neither lease takeover nor a generic action
// transition may make the underlying capacity reusable.
type issuedCustodyPaymentAuthorization struct {
	PaymentRequestDigest   string                              `json:"payment_request_digest"`
	Payment                commerce.AgreementPaymentRequest    `json:"payment"`
	ReservationID          string                              `json:"reservation_id"`
	SponsorshipAdmissionID string                              `json:"sponsorship_admission_id,omitempty"`
	Authorization          commerce.CustodyActionAuthorization `json:"authorization"`
	AuthorizationDigest    string                              `json:"authorization_digest"`
	// FinalityGraceSeconds and ReleaseAfterUnix are frozen when the bearer is
	// issued. A later configuration change can therefore never shorten the
	// owner-approved absence/finality horizon for an already signed payment.
	FinalityGraceSeconds   uint64 `json:"finality_grace_seconds,omitempty"`
	ReleaseAfterUnix       uint64 `json:"release_after_unix,omitempty"`
	TerminalEvidenceDigest string `json:"terminal_evidence_digest,omitempty"`
	TerminalReference      string `json:"terminal_reference,omitempty"`
}

// expiredCustodyAuthorization is a durable, non-executable tombstone. It
// proves that the released reservation used to cover this exact signed bearer
// and that the owner-pinned horizon elapsed; a naked timestamp is not enough
// to justify reopening aggregate maximum-loss capacity after restart.
type expiredCustodyAuthorization struct {
	Issuance      issuedCustodyPaymentAuthorization `json:"issuance"`
	ExpiredAtUnix uint64                            `json:"expired_at_unix"`
}

var ErrCustodyAuthorizationLive = errors.New("issued native custody authorization is still live")

func (authority *PersonalAuthority) AuthorizeCustodyPayment(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	payment commerce.AgreementPaymentRequest, sourceAccount string,
	networkDomain commerce.CustodyNetworkDomain,
	sponsorship *SponsorshipCustodyBinding) (commerce.CustodyActionAuthorization, error) {
	payment = detachedAgreementPaymentRequest(payment)
	// This method mints the capability consumed by the native tosctl custody
	// primitive. External adapters have their own attested settlement boundary
	// and must never enter the native signing path, even if a caller prepared an
	// otherwise valid AuthorizedAction for that adapter.
	if payment.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI {
		return commerce.CustodyActionAuthorization{}, errors.New("native custody only authorizes the direct payment adapter")
	}
	if authority == nil || sourceAccount == "" || commerce.ValidateCustodyNetworkDomain(networkDomain) != nil ||
		networkDomain.NetworkID != payment.NetworkID || networkDomain.GlobalID == 0 {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment binding is incomplete")
	}
	domainDigest, err := agentrelay.NetworkDomainDigest(agentrelay.NetworkDomain{NetworkID: networkDomain.NetworkID,
		GlobalID: networkDomain.GlobalID, ZeroStateRootHash: networkDomain.ZeroStateRootHash,
		ZeroStateFileHash: networkDomain.ZeroStateFileHash, WorkchainID: networkDomain.WorkchainID})
	if err != nil || payment.SchemaVersion != 3 || payment.NetworkDomainDigest != domainDigest {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment does not bind the pinned network domain")
	}
	relaySponsorship := sponsorship != nil
	if relaySponsorship && (!canonicalSHA256(sponsorship.AdmissionID) ||
		!canonicalSHA256(sponsorship.PaymentRequestDigest) || !canonicalSHA256(sponsorship.PurposeDigest) ||
		!canonicalSHA256(sponsorship.ReservationID) || !canonicalSHA256(sponsorship.FinalityProfileCBORDigest) ||
		!canonicalSHA256(sponsorship.ReleaseProfileDigest) || !canonicalSHA256(sponsorship.CorroborationSnapshotID)) {
		return commerce.CustodyActionAuthorization{}, errors.New("custody sponsorship lacks an exact owner-authorized relay purpose")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	if err := authority.expireIssuedCustodyLocked(); err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	if authority.doc.Limits.CustodyNetworkDomainDigest == "" ||
		authority.doc.Limits.CustodyNetworkDomainDigest != domainDigest {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment network domain is not owner-pinned by this authority")
	}
	if authority.doc.Limits.CustodySourceAccount == "" ||
		authority.doc.Limits.CustodySourceAccount != sourceAccount {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment source account is not owner-pinned by this authority")
	}
	nativeAsset := authority.doc.Limits.CustodyNativeAsset
	if nativeAsset == nil || payment.Amount.AssetNamespace != nativeAsset.AssetNamespace ||
		payment.Amount.AssetIdentifier != nativeAsset.AssetIdentifier || payment.Amount.Unit != nativeAsset.Unit {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment asset is not the owner-pinned native asset")
	}
	engagement, engagementFound := authority.doc.Engagements[payment.AgreementBodyDigest]
	if engagementFound && engagement.NegotiationAmbiguous {
		return commerce.CustodyActionAuthorization{}, errors.New("ambiguous Agreement lineage cannot authorize a custody payment")
	}
	// A caller cannot select a custody exception. The authority either finds
	// the exact durable sponsorship admission (which atomically owns its hold),
	// or requires the ordinary Agreement reservation and settlement ledger.
	if relaySponsorship {
		admission, found := authority.doc.RelaySponsorshipPayments[sponsorship.AdmissionID]
		if !found || !exactLiveRelaySponsorshipAdmission(authority.doc, action, payment, *sponsorship, admission) {
			return commerce.CustodyActionAuthorization{}, errors.New("direct sponsorship payment has no exact live authority admission")
		}
	} else if !engagementFound || !exactLiveDirectPaymentReservation(authority.doc, engagement, payment,
		action, authority.now().UTC()) {
		return commerce.CustodyActionAuthorization{}, errors.New("direct payment has no exact live Agreement reservation")
	}
	custodyReservationID := engagement.ReservationID
	if relaySponsorship {
		custodyReservationID = sponsorship.ReservationID
	}
	issuedPaymentDigest, err := commerce.AgreementPaymentRequestDigest(payment)
	if err != nil {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment request digest is invalid")
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.CustodyActionAuthorization{}, errors.New("stale writer cannot authorize custody")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != commerce.PaymentActionKind(payment) || action.StableActionID != payment.StableActionID ||
		commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment is not the exact authorized action")
	}
	prior, found := authority.doc.Actions[action.StableActionID]
	if !found || prior.ExactRequestDigest != action.ExactRequestDigest || prior.State != commerce.ActionPrepared {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment has no prepared authority record")
	}
	if relaySponsorship {
		retained, retainedFound := authority.doc.AuthorizedActions[action.StableActionID]
		if !retainedFound || !sameJSON(retained, action) {
			return commerce.CustodyActionAuthorization{}, errors.New("relay sponsorship purpose is not the exact retained AuthorizedAction")
		}
	}
	amount, err := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
	if err != nil || amount == 0 {
		return commerce.CustodyActionAuthorization{}, errors.New("native custody amount exceeds uint64")
	}
	if retained, retainedFound := authority.doc.IssuedCustodyPayments[issuedPaymentDigest]; retainedFound {
		authorizationDigest, digestErr := codec.Digest("tos.openfox.issued-native-custody-authorization.v1",
			retained.Authorization)
		if retained.TerminalEvidenceDigest != "" || !sameJSON(retained.Payment, payment) ||
			retained.ReservationID != custodyReservationID ||
			(retained.SponsorshipAdmissionID == "") != !relaySponsorship ||
			relaySponsorship && retained.SponsorshipAdmissionID != sponsorship.AdmissionID ||
			retained.AuthorizationDigest != authorizationDigest || digestErr != nil ||
			retained.Authorization.SourceAccount != sourceAccount ||
			retained.Authorization.NetworkDomain == nil || *retained.Authorization.NetworkDomain != networkDomain ||
			retained.Authorization.StableActionID != action.StableActionID ||
			retained.Authorization.ExactRequestDigest != action.ExactRequestDigest ||
			retained.Authorization.AgreementPaymentRequestDigest != issuedPaymentDigest ||
			retained.Authorization.Destination != string(payment.Destination) ||
			retained.Authorization.AmountAtomic != amount {
			return commerce.CustodyActionAuthorization{}, errors.New("custody payment conflicts with a retained issuance lifecycle")
		}
		return detachedCustodyAuthorization(retained.Authorization), nil
	}
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	approval := action.ApprovalDigest
	if approval == "" {
		approval = zeroSHA256Digest()
	}
	authorizationSchema := uint16(2)
	paymentRequestDigest := ""
	if payment.SchemaVersion == 3 {
		authorizationSchema = 3
		paymentRequestDigest = issuedPaymentDigest
	}
	body := commerce.CustodyActionAuthorization{SchemaVersion: authorizationSchema, AuthorityID: authority.doc.AuthorityID,
		OwnerID: authority.doc.OwnerID, AgentID: authority.doc.AgentID, SourceAccount: sourceAccount,
		NetworkID: payment.NetworkID, NetworkGlobalID: networkDomain.GlobalID,
		NetworkDomain: &commerce.CustodyNetworkDomain{NetworkID: networkDomain.NetworkID, GlobalID: networkDomain.GlobalID,
			ZeroStateRootHash: networkDomain.ZeroStateRootHash, ZeroStateFileHash: networkDomain.ZeroStateFileHash,
			WorkchainID: networkDomain.WorkchainID}, StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration, WriterFenceDigest: fenceDigest,
		AgreementPaymentRequestDigest: paymentRequestDigest,
		PolicyRevision:                action.PolicyRevision, MandateDigest: action.MandateDigest, ApprovalDigestOrZero: approval,
		AgreementBodyDigest: payment.AgreementBodyDigest, ObligationInstanceID: payment.ObligationInstanceID,
		Destination: string(payment.Destination), AmountAtomic: amount, ExpiresAtUnix: action.ExpiresAtUnix}
	if sponsorship != nil {
		body.SponsorshipFinalityProfileCBORDigest = sponsorship.FinalityProfileCBORDigest
		body.SponsorshipReleaseProfileDigest = sponsorship.ReleaseProfileDigest
		body.SponsorshipCorroborationSnapshotIdentity = sponsorship.CorroborationSnapshotID
	}
	authorization, err := commerce.SignCustodyActionAuthorization(body, authority.key)
	if err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	authorizationDigest, err := codec.Digest("tos.openfox.issued-native-custody-authorization.v1", authorization)
	if err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	issued := issuedCustodyPaymentAuthorization{PaymentRequestDigest: issuedPaymentDigest, Payment: payment,
		ReservationID: custodyReservationID, Authorization: authorization, AuthorizationDigest: authorizationDigest}
	if relaySponsorship {
		issued.SponsorshipAdmissionID = sponsorship.AdmissionID
	}
	issued.FinalityGraceSeconds = authority.doc.Limits.CustodyFinalityGraceSeconds
	if issued.FinalityGraceSeconds != 0 {
		releaseAfter, horizonErr := custodyAuthorizationReleaseAfter(authority.doc, issued)
		if horizonErr != nil {
			return commerce.CustodyActionAuthorization{}, horizonErr
		}
		issued.ReleaseAfterUnix = releaseAfter
	}
	for priorDigest, prior := range authority.doc.IssuedCustodyPayments {
		if prior.ReservationID == custodyReservationID && priorDigest != issuedPaymentDigest {
			return commerce.CustodyActionAuthorization{}, errors.New("Portfolio reservation already has a different live native custody bearer")
		}
	}
	if len(authority.doc.IssuedCustodyPayments) >= maximumIssuedCustodyAuthorizations {
		return commerce.CustodyActionAuthorization{}, errors.New("custody payment issuance capacity is exhausted")
	}
	// Persist before returning the offline-verifiable capability. If this write
	// fails no authorization bytes escape and the Portfolio hold remains in its
	// prior state.
	next := cloneAuthorityDocument(authority.doc)
	next.IssuedCustodyPayments[issuedPaymentDigest] = detachedIssuedCustodyPayment(issued)
	if err := authority.persist(next); err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	authority.doc = next
	return detachedCustodyAuthorization(authorization), nil
}

// AuthorizeCustodyEffect turns an already admitted semantic action into a
// purpose-limited custody capability for one exact TVM effect. The caller may
// describe the contract effect, but cannot choose the authority identity,
// writer generation, policy, mandate, approval or semantic action identity.
func (authority *PersonalAuthority) AuthorizeCustodyEffect(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	template commerce.CustodyEffectAuthorization) (commerce.CustodyEffectAuthorization, error) {
	if authority == nil || template.NetworkDomain == nil ||
		commerce.ValidateCustodyNetworkDomain(*template.NetworkDomain) != nil ||
		template.NetworkID != template.NetworkDomain.NetworkID ||
		template.NetworkGlobalID != template.NetworkDomain.GlobalID {
		return commerce.CustodyEffectAuthorization{}, errors.New("custody effect authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	if template.ActionKind == "escrow.accept" || template.ActionKind == "escrow.fund" {
		engagement, found := authority.doc.Engagements[template.AgreementBodyDigest]
		if !found || engagement.NegotiationAmbiguous ||
			!exactLivePaidDemandReservation(authority.doc, engagement, authority.doc.AgentID,
				template.AgreementBodyDigest, template.ObligationID) {
			return commerce.CustodyEffectAuthorization{}, errors.New("Agreement is absent, ambiguous, or unreserved for new escrow exposure")
		}
	}
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.CustodyEffectAuthorization{}, errors.New("stale writer cannot authorize custody effect")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "escrow.transition" ||
		commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, now) != nil {
		return commerce.CustodyEffectAuthorization{}, errors.New("custody effect is not the exact authorized action")
	}
	prior, found := authority.doc.Actions[action.StableActionID]
	if !found || prior.ExactRequestDigest != action.ExactRequestDigest || prior.State != commerce.ActionPrepared {
		return commerce.CustodyEffectAuthorization{}, errors.New("custody effect has no prepared authority record")
	}
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	approval := action.ApprovalDigest
	if approval == "" {
		approval = zeroSHA256Digest()
	}
	domain := *template.NetworkDomain
	template.SchemaVersion = 2
	template.NetworkDomain = &domain
	template.AuthorityID = authority.doc.AuthorityID
	template.OwnerID = authority.doc.OwnerID
	template.AgentID = authority.doc.AgentID
	template.StableActionID = action.StableActionID
	template.ExactRequestDigest = action.ExactRequestDigest
	template.WriterGeneration = action.WriterGeneration
	template.WriterFenceDigest = fenceDigest
	template.PolicyRevision = action.PolicyRevision
	template.MandateDigest = action.MandateDigest
	template.ApprovalDigestOrZero = approval
	template.ExpiresAtUnix = minUint64(template.ExpiresAtUnix, action.ExpiresAtUnix)
	return commerce.SignCustodyEffectAuthorization(template, authority.key)
}

// exactLivePaidDemandReservation is called while the PersonalAuthority mutex
// is held at the final accept/fund signing boundary. It reconstructs the
// profile-specific buyer exposure from the retained Agreement: a caller cannot
// turn a zero, undersized, wrong-asset, or released reservation into custody
// authority merely by attaching its ID to the Engagement.
func exactLivePaidDemandReservation(document authorityDocument, engagement EngagementRecord,
	buyerAgentID, agreementDigest, obligationID string) bool {
	if engagement.AgreementDigest != agreementDigest || buyerAgentID == "" ||
		!paidDemandBuyerPaymentObligation(engagement, buyerAgentID, obligationID) {
		return false
	}
	expected, err := paidDemandBuyerReservation(engagement, buyerAgentID)
	if err != nil || engagement.ReservationID != expected.ReservationID {
		return false
	}
	reservation, found := document.Reservations[expected.ReservationID]
	return found && sameExposureReservation(reservation, expected)
}

// exactLiveDirectPaymentReservation is called under the PersonalAuthority
// mutex at the last boundary before custody can move funds. An admitted action
// alone is insufficient: the payment must still match one materialized,
// outstanding Agreement obligation and its exact live buyer loss reservation.
func exactLiveDirectPaymentReservation(document authorityDocument, engagement EngagementRecord,
	payment commerce.AgreementPaymentRequest, action commerce.AuthorizedAction, now time.Time) bool {
	if payment.SettlementAdapterURI != "tos.payment.direct.v1" || payment.OwnerID != document.OwnerID ||
		payment.AgentID != document.AgentID || payment.PayerAgentID != document.AgentID ||
		payment.AgreementBodyDigest != engagement.AgreementDigest || engagement.ReservationID == "" ||
		!retainedAgreementFullyAuthorized(engagement, document.AgentID) ||
		engagement.State != EngagementSettling || now.Unix() < 0 || uint64(now.Unix()) >= payment.ExpiresAtUnix ||
		action.MandateDigest == "" || action.ExpiresAtUnix == 0 || action.ExpiresAtUnix > payment.ExpiresAtUnix ||
		commerce.ValidateAgreementBody(engagement.Agreement.Body) != nil ||
		commerce.ValidateAgreementPaymentRequest(payment) != nil {
		return false
	}
	exposure, err := localAgreementPaymentExposure(engagement.Agreement.Body, document.AgentID)
	if err != nil || exposure.Asset == nil || !exposure.MaximumLoss.IsUint64() || exposure.MaximumLoss.Sign() <= 0 {
		return false
	}
	reservation, found := document.Reservations[engagement.ReservationID]
	if !found || reservation.ReservationID != engagement.ReservationID || reservation.AgreementDigest != engagement.AgreementDigest ||
		reservation.Released || !sameExposureAsset(reservation.Asset, exposure.Asset) ||
		reservation.MaximumLossAtomic != exposure.MaximumLoss.Uint64() || reservation.SpendAtomic < exposure.MaximumLoss.Uint64() {
		return false
	}
	ledger, found := document.SettlementLedger[payment.ObligationInstanceID]
	if !found || ledger.Obligation.AgreementBodyDigest != payment.AgreementBodyDigest ||
		ledger.Obligation.AgreementObligationID != payment.AgreementObligationID ||
		ledger.Obligation.ObligationInstanceID != payment.ObligationInstanceID ||
		ledger.Obligation.PayerAgentID != payment.PayerAgentID || ledger.Obligation.PayeeAgentID != payment.PayeeAgentID ||
		ledger.Obligation.SettlementAdapterURI != payment.SettlementAdapterURI ||
		ledger.Obligation.MandateDigest != action.MandateDigest ||
		ledger.Obligation.ExpiresAtUnix != payment.ExpiresAtUnix || ledger.State.StateRevision == 0 {
		return false
	}
	switch ledger.State.State {
	case commerce.SettlementPending, commerce.SettlementPartiallyPaid, commerce.SettlementOverdue:
	default:
		return false
	}
	var agreementObligation *commerce.AgreementObligation
	for index := range engagement.Agreement.Body.Obligations {
		candidate := &engagement.Agreement.Body.Obligations[index]
		if candidate.ObligationID == payment.AgreementObligationID {
			agreementObligation = candidate
			break
		}
	}
	if agreementObligation == nil || agreementObligation.Amount == nil ||
		agreementObligation.ObligorAgentID != payment.PayerAgentID ||
		agreementObligation.BeneficiaryAgentID != payment.PayeeAgentID ||
		agreementObligation.SettlementAdapterURI != payment.SettlementAdapterURI ||
		engagement.Agreement.Body.NetworkContext != payment.NetworkID ||
		!bytes.Equal(agreementObligation.SettlementParameters, payment.Destination) {
		return false
	}
	materialized, err := commerce.MaterializeSettlementObligations(document.OwnerID, document.AgentID,
		engagement.AgreementDigest, agreementObligation.ObligationID, ledger.Obligation.MandateDigest, *agreementObligation)
	if err != nil {
		return false
	}
	exactLedger := false
	for _, candidate := range materialized {
		if candidate.ObligationInstanceID == payment.ObligationInstanceID && sameJSON(candidate, ledger.Obligation) {
			exactLedger = true
			break
		}
	}
	obligationDigest, err := codec.Digest("tos.settlement-obligation.v1", ledger.Obligation)
	if !exactLedger || err != nil || ledger.State.ObligationDigest != obligationDigest ||
		commerce.ValidateSettlementState(ledger.State) != nil {
		return false
	}
	parametersDigest, err := codec.Digest("tos.settlement-adapter-parameters.v1", agreementObligation.SettlementParameters)
	if err != nil || parametersDigest != ledger.Obligation.SettlementParametersDigest {
		return false
	}
	if !sameAgreementAmountAsset(payment.Amount, ledger.Obligation.Amount) ||
		!sameAgreementAmountAsset(payment.Amount, ledger.State.OutstandingAmount) {
		return false
	}
	requested, requestErr := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
	outstanding, outstandingErr := strconv.ParseUint(ledger.State.OutstandingAmount.AmountAtomic, 10, 64)
	return requestErr == nil && outstandingErr == nil && requested > 0 && requested <= outstanding
}

func sameAgreementAmountAsset(left, right commerce.AgreementAmount) bool {
	return left.AssetNamespace == right.AssetNamespace && left.AssetIdentifier == right.AssetIdentifier && left.Unit == right.Unit
}

func exactRelaySponsorshipCustodyPurpose(action commerce.AuthorizedAction,
	payment commerce.AgreementPaymentRequest, purpose RelaySponsorshipCustodyPurpose) bool {
	if payment.SchemaVersion != 3 || payment.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI ||
		action.ActionKind != commerce.PaymentActionKind(payment) || action.StableActionID != payment.StableActionID ||
		purpose.SchemaVersion != 1 || !canonicalSHA256(purpose.PaymentRequestDigest) ||
		!canonicalSHA256(purpose.RelayExecutionDigest) || !canonicalSHA256(purpose.AgreementBodyDigest) ||
		!canonicalSHA256(purpose.ProviderQuoteDigest) || !canonicalSHA256(purpose.SponsorshipTerminalProfileDigest) ||
		!canonicalSHA256(purpose.FinalityProfileCBORDigest) || !canonicalSHA256(purpose.ReleaseProfileDigest) ||
		!canonicalSHA256(purpose.CorroborationSnapshotID) ||
		purpose.AgreementBodyDigest != payment.AgreementBodyDigest ||
		purpose.AgreementObligationID != payment.AgreementObligationID {
		return false
	}
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(payment)
	agreementDigest, agreementErr := commerce.AgreementBodyDigest(purpose.AgreementBody)
	quoteRequestDigest, quoteRequestErr := agentrelay.RelayQuoteRequestDigest(purpose.QuoteRequest)
	networkDigest, networkErr := agentrelay.NetworkDomainDigest(purpose.QuoteRequest.Network)
	purposeDigest, purposeErr := relaySponsorshipCustodyPurposeDigest(purpose)
	requested := purpose.QuoteRequest.RequestedSponsorship
	if paymentErr != nil || agreementErr != nil || quoteRequestErr != nil || networkErr != nil || purposeErr != nil ||
		purpose.PaymentRequestDigest != paymentDigest || purpose.AgreementBodyDigest != agreementDigest ||
		action.ApprovalDigest != purposeDigest || purpose.AgreementBody.NetworkContext != payment.NetworkID ||
		requested == nil || !sameRelayAgreementAssetAmount(payment.Amount, *requested) ||
		purpose.QuoteRequest.ProviderAgentID != payment.PayerAgentID ||
		purpose.QuoteRequest.RequesterAgentID != payment.PayeeAgentID ||
		purpose.QuoteRequest.Mode == agentrelay.ModeRelayExact ||
		purpose.QuoteRequest.Network.NetworkID != payment.NetworkID || networkDigest != payment.NetworkDomainDigest ||
		purpose.QuoteRequest.SourceAccount != string(payment.Destination) ||
		purpose.QuoteRequest.SponsorshipReleaseProfileDigest != purpose.ReleaseProfileDigest ||
		purpose.QuoteRequest.SponsorshipTerminalProfileDigest != purpose.SponsorshipTerminalProfileDigest {
		return false
	}
	var matched *commerce.AgreementObligation
	for index := range purpose.AgreementBody.Obligations {
		candidate := &purpose.AgreementBody.Obligations[index]
		if candidate.ObligationID == purpose.AgreementObligationID {
			if matched != nil {
				return false
			}
			matched = candidate
		}
	}
	if matched == nil || matched.Amount == nil || matched.Kind != agentrelay.ObligationSponsorDelivery ||
		matched.ObligorAgentID != payment.PayerAgentID || matched.BeneficiaryAgentID != payment.PayeeAgentID ||
		matched.SettlementAdapterURI != payment.SettlementAdapterURI ||
		matched.SubjectContentType != agentrelay.AgreementBindingContentType ||
		!sameAgreementAmountAsset(*matched.Amount, payment.Amount) ||
		matched.Amount.AmountAtomic != payment.Amount.AmountAtomic || matched.ExpiresAtUnix == 0 ||
		payment.ExpiresAtUnix > matched.ExpiresAtUnix || payment.ExpiresAtUnix > purpose.AgreementBody.ExpiresAtUnix {
		return false
	}
	var relayBinding agentrelay.RelayAgreementBinding
	if codec.Unmarshal(matched.Subject, &relayBinding) != nil {
		return false
	}
	canonicalBinding, bindingErr := agentrelay.RelayAgreementBindingBytes(relayBinding)
	return bindingErr == nil && bytes.Equal(canonicalBinding, matched.Subject) &&
		relayBinding.QuoteRequestDigest == quoteRequestDigest &&
		relayBinding.ProviderQuoteDigest == purpose.ProviderQuoteDigest &&
		relayBinding.ProviderAgentID == payment.PayerAgentID && relayBinding.RequesterAgentID == payment.PayeeAgentID &&
		relayBinding.Mode != agentrelay.ModeRelayExact &&
		relayBinding.SponsorshipReleaseProfileDigest == purpose.ReleaseProfileDigest &&
		relayBinding.SponsorshipTerminalProfileDigest == purpose.SponsorshipTerminalProfileDigest
}

func exactLiveRelaySponsorshipAdmission(document authorityDocument, action commerce.AuthorizedAction,
	payment commerce.AgreementPaymentRequest, binding SponsorshipCustodyBinding,
	admission relaySponsorshipPaymentAdmission) bool {
	if admission.AdmissionID != binding.AdmissionID || admission.PaymentRequestDigest != binding.PaymentRequestDigest ||
		admission.PurposeDigest != binding.PurposeDigest || admission.Reservation.ReservationID != binding.ReservationID ||
		admission.Purpose.FinalityProfileCBORDigest != binding.FinalityProfileCBORDigest ||
		admission.Purpose.ReleaseProfileDigest != binding.ReleaseProfileDigest ||
		admission.Purpose.CorroborationSnapshotID != binding.CorroborationSnapshotID ||
		!sameJSON(admission.Payment, payment) || !exactRelaySponsorshipCustodyPurpose(action, payment, admission.Purpose) {
		return false
	}
	purposeDigest, purposeErr := relaySponsorshipCustodyPurposeDigest(admission.Purpose)
	expectedReservation, reservationErr := relaySponsorshipExposureReservation(payment,
		admission.PaymentRequestDigest, purposeDigest)
	expectedAdmissionID, admissionErr := relaySponsorshipPaymentAdmissionID(action,
		admission.PaymentRequestDigest, purposeDigest, expectedReservation.ReservationID)
	reservation, reservationFound := document.Reservations[expectedReservation.ReservationID]
	retainedAction, actionFound := document.AuthorizedActions[action.StableActionID]
	return purposeErr == nil && reservationErr == nil && admissionErr == nil &&
		purposeDigest == admission.PurposeDigest && expectedAdmissionID == admission.AdmissionID &&
		sameExposureReservation(admission.Reservation, expectedReservation) && reservationFound &&
		sameExposureReservation(reservation, expectedReservation) && !reservation.Released &&
		actionFound && sameJSON(retainedAction, action)
}

func paidDemandBuyerPaymentObligation(engagement EngagementRecord, buyerAgentID, obligationID string) bool {
	if buyerAgentID == "" || obligationID == "" {
		return false
	}
	for _, obligation := range engagement.Agreement.Body.Obligations {
		if obligation.ObligationID == obligationID && obligation.Amount != nil &&
			obligation.ObligorAgentID == buyerAgentID && obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI {
			return true
		}
	}
	return false
}

func sameExposureReservation(left, right ExposureReservation) bool {
	if left.ReservationID != right.ReservationID || left.AgreementDigest != right.AgreementDigest ||
		left.ComputeUnits != right.ComputeUnits || left.SpendAtomic != right.SpendAtomic ||
		left.LockedCapitalAtomic != right.LockedCapitalAtomic || left.ReceivableAtomic != right.ReceivableAtomic ||
		left.MaximumLossAtomic != right.MaximumLossAtomic || left.Released != right.Released ||
		(left.Asset == nil) != (right.Asset == nil) {
		return false
	}
	return left.Asset == nil || *left.Asset == *right.Asset
}

type PortfolioLimits struct {
	ComputeUnits        uint64 `json:"compute_units"`
	SpendAtomic         uint64 `json:"spend_atomic"`
	LockedCapitalAtomic uint64 `json:"locked_capital_atomic"`
	ReceivableAtomic    uint64 `json:"receivable_atomic"`
	MaximumLossAtomic   uint64 `json:"maximum_loss_atomic"`
	// CustodyNetworkDomainDigest pins the complete native network identity at
	// authority creation. CustodyFinalityGraceSeconds is an explicit owner risk
	// assumption; zero means an offline bearer can never be expired by wall
	// clock alone and its hold remains fail-closed.
	CustodyNetworkDomainDigest  string                    `json:"custody_network_domain_digest,omitempty"`
	CustodyFinalityGraceSeconds uint64                    `json:"custody_finality_grace_seconds,omitempty"`
	CustodyNativeAsset          *commerce.AssetIdentityV1 `json:"custody_native_asset,omitempty"`
	CustodySourceAccount        string                    `json:"custody_source_account,omitempty"`
}

type PortfolioReleaseRequest struct {
	ReservationID             string `json:"reservation_id"`
	AgreementDigest           string `json:"agreement_digest"`
	TargetPortfolioRevision   uint64 `json:"target_portfolio_revision"`
	TerminalEvidenceSetDigest string `json:"terminal_evidence_set_digest"`
}

type EngagementState string

const (
	EngagementProposed              EngagementState = "proposed"
	EngagementAuthorizing           EngagementState = "authorizing"
	EngagementAgreed                EngagementState = "agreed"
	EngagementReserved              EngagementState = "reserved"
	EngagementFundingPending        EngagementState = "funding_pending"
	EngagementReady                 EngagementState = "ready"
	EngagementExecutionPrepared     EngagementState = "execution_prepared"
	EngagementExecuting             EngagementState = "executing"
	EngagementExecutionSucceeded    EngagementState = "execution_succeeded"
	EngagementDelivered             EngagementState = "delivered"
	EngagementSettling              EngagementState = "settling"
	EngagementSettled               EngagementState = "settled"
	EngagementUnpaid                EngagementState = "unpaid"
	EngagementCancellationResolving EngagementState = "cancellation_resolving"
	EngagementCancelled             EngagementState = "cancelled"
	EngagementFailed                EngagementState = "failed"
	EngagementAmbiguous             EngagementState = "ambiguous"
)

type EngagementRecord struct {
	Agreement       commerce.AgentAgreement `json:"agreement"`
	AgreementDigest string                  `json:"agreement_digest"`
	// Written only after the configured verifier has accepted every
	// authorization predicate under the authority lock. Native custody binds
	// this marker back to the exact retained body and evidence bytes.
	FullyAuthorizedEvidenceSetDigest string `json:"fully_authorized_evidence_set_digest,omitempty"`
	ProposerAgentID                  string `json:"proposer_agent_id"`
	ProposalEventID                  string `json:"proposal_event_id"`
	ProposalActionID                 string `json:"proposal_action_id"`
	// NegotiationAmbiguous is a durable fail-closed observation. It is
	// independent of lifecycle State so a body fork discovered after an
	// Agreement was accepted cannot erase already-incurred obligations.
	NegotiationAmbiguous       bool            `json:"negotiation_ambiguous,omitempty"`
	NegotiationConflictCodes   []string        `json:"negotiation_conflict_codes,omitempty"`
	NegotiationConflictDigests []string        `json:"negotiation_conflict_digests,omitempty"`
	State                      EngagementState `json:"state"`
	StateRevision              uint64          `json:"state_revision"`
	ReservationID              string          `json:"reservation_id,omitempty"`
	// ReservationActionID/ExactRequestDigest retain the linearized hold
	// operation so a crash or successor writer can recognize and return the
	// exact committed phase instead of trying to reserve a second revision.
	ReservationActionID                 string                                  `json:"reservation_action_id,omitempty"`
	ReservationActionExactRequestDigest string                                  `json:"reservation_action_exact_request_digest,omitempty"`
	CustodyAuthorizationExpiredAtUnix   uint64                                  `json:"custody_authorization_expired_at_unix,omitempty"`
	ExpiredCustodyAuthorization         *expiredCustodyAuthorization            `json:"expired_custody_authorization,omitempty"`
	ExecutionID                         string                                  `json:"execution_id,omitempty"`
	FundingEvidence                     []string                                `json:"funding_evidence,omitempty"`
	ExecutionEvidence                   []string                                `json:"execution_evidence,omitempty"`
	DeliveryEvidence                    []string                                `json:"delivery_evidence,omitempty"`
	DeliveryEventID                     string                                  `json:"delivery_event_id,omitempty"`
	SettlementEvidence                  []string                                `json:"settlement_evidence,omitempty"`
	AcceptedPrivateInputs               []commerce.AcceptedPrivateContentRecord `json:"accepted_private_inputs,omitempty"`
	BoundPrivateInputs                  []BoundAcceptedPrivateInput             `json:"bound_private_inputs,omitempty"`
	PrivateHandoffChallenges            []BoundPrivateHandoffChallenge          `json:"private_handoff_challenges,omitempty"`
	// ObligationRuntime is the durable, obligation-scoped execution and
	// settlement projection. Agreement is still the authority; this map only
	// records verified progress and must contain exactly one entry for every
	// canonical Agreement obligation.
	ObligationRuntime    map[string]ObligationRuntimeRecord `json:"obligation_runtime,omitempty"`
	LastTransitionAtUnix uint64                             `json:"last_transition_at_unix"`
}

type SettlementLedgerRecord struct {
	Obligation commerce.SettlementObligation      `json:"obligation"`
	State      commerce.SettlementObligationState `json:"state"`
}

type authorityDocument struct {
	Schema                          string                                                      `json:"schema"`
	OwnerID                         string                                                      `json:"owner_id"`
	AgentID                         string                                                      `json:"agent_id"`
	AuthorityID                     string                                                      `json:"authority_id"`
	WriterGeneration                uint64                                                      `json:"writer_generation"`
	CurrentFence                    *commerce.WriterFence                                       `json:"current_fence,omitempty"`
	Actions                         map[string]commerce.ActionResolution                        `json:"actions"`
	AuthorizedActions               map[string]commerce.AuthorizedAction                        `json:"authorized_actions,omitempty"`
	OutcomeJournalHeads             map[string]OutcomeJournalAuthorityHeadV1                    `json:"outcome_journal_heads,omitempty"`
	AuthorityInstances              map[string]commerce.AuthorityInstanceRecord                 `json:"authority_instances"`
	NextInstanceSequence            uint64                                                      `json:"next_instance_sequence"`
	NextRelayAdmissionSequence      uint64                                                      `json:"next_relay_admission_sequence"`
	RelayAdmissions                 map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt `json:"relay_admissions"`
	RelayAdmissionBindings          map[string]string                                           `json:"relay_admission_bindings"`
	RelaySponsorshipPayments        map[string]relaySponsorshipPaymentAdmission                 `json:"relay_sponsorship_payments,omitempty"`
	IssuedCustodyPayments           map[string]issuedCustodyPaymentAuthorization                `json:"issued_custody_payments,omitempty"`
	PortfolioRevision               uint64                                                      `json:"portfolio_revision"`
	Limits                          PortfolioLimits                                             `json:"limits"`
	ConsumedMaximumLossAtomic       uint64                                                      `json:"consumed_maximum_loss_atomic"`
	RetainedDefaultLiabilityAtomic  uint64                                                      `json:"retained_default_liability_atomic"`
	ConsumedMaximumLossByAsset      map[string]uint64                                           `json:"consumed_maximum_loss_by_asset"`
	RetainedDefaultLiabilityByAsset map[string]uint64                                           `json:"retained_default_liability_by_asset"`
	Reservations                    map[string]ExposureReservation                              `json:"reservations"`
	ScheduleEntries                 map[string]commerce.EngagementScheduleEntry                 `json:"schedule_entries"`
	Dependencies                    []commerce.PortfolioDependency                              `json:"portfolio_dependencies"`
	Engagements                     map[string]EngagementRecord                                 `json:"engagements"`
	SettlementLedger                map[string]SettlementLedgerRecord                           `json:"settlement_ledger"`
	Accounting                      map[string]AccountingEntry                                  `json:"accounting"`
}

type PersonalAuthority struct {
	mu         sync.Mutex
	directory  string
	root       *os.Root
	path       string
	lock       *os.File
	domainLock *localEconomicDomainLock
	poisoned   bool
	key        ed25519.PrivateKey
	doc        authorityDocument
	now        func() time.Time
}

func (authority *PersonalAuthority) AuthorityNow() time.Time {
	if authority == nil {
		return time.Time{}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return time.Time{}
	}
	return authority.now().UTC()
}

func OpenPersonalAuthority(directory, ownerID, agentID, authorityID string, key ed25519.PrivateKey, limits PortfolioLimits) (*PersonalAuthority, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || ownerID == "" || agentID == "" || authorityID == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("personal authority configuration is invalid")
	}
	if err := validateRelayJournalDirectorySecurity(directory); err != nil {
		return nil, errors.New("personal authority directory must be owner-private")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, errors.New("stat personal authority directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("open personal authority directory capability")
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(info, rootInfo) {
		_ = root.Close()
		return nil, errors.New("personal authority directory changed while opening")
	}
	domainIdentity := ownerID + "\x00" + agentID + "\x00" + authorityID
	domainLock, err := acquireLocalEconomicDomainLock("personal-authority\x00" + domainIdentity)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	lock, err := acquireAuthorityLockRoot(root)
	if err != nil {
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	}
	pathInfo, pathErr := os.Lstat(directory)
	if pathErr != nil || !os.SameFile(rootInfo, pathInfo) {
		_ = releaseAuthorityLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, errors.New("personal authority directory changed while locking")
	}
	limits = clonePortfolioLimits(limits)
	authority := &PersonalAuthority{directory: directory, root: root, path: authorityFile, lock: lock, domainLock: domainLock,
		key: append(ed25519.PrivateKey(nil), key...), now: time.Now}
	authority.doc = authorityDocument{Schema: authoritySchema, OwnerID: ownerID, AgentID: agentID, AuthorityID: authorityID,
		Actions: map[string]commerce.ActionResolution{}, AuthorizedActions: map[string]commerce.AuthorizedAction{}, OutcomeJournalHeads: map[string]OutcomeJournalAuthorityHeadV1{},
		AuthorityInstances:   map[string]commerce.AuthorityInstanceRecord{},
		NextInstanceSequence: 1, NextRelayAdmissionSequence: 1,
		RelayAdmissions:          map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt{},
		RelayAdmissionBindings:   map[string]string{},
		RelaySponsorshipPayments: map[string]relaySponsorshipPaymentAdmission{},
		IssuedCustodyPayments:    map[string]issuedCustodyPaymentAuthorization{},
		PortfolioRevision:        1, Limits: limits, Reservations: map[string]ExposureReservation{},
		ConsumedMaximumLossByAsset: map[string]uint64{}, RetainedDefaultLiabilityByAsset: map[string]uint64{},
		ScheduleEntries: map[string]commerce.EngagementScheduleEntry{}}
	authority.doc.Engagements = map[string]EngagementRecord{}
	authority.doc.SettlementLedger = map[string]SettlementLedgerRecord{}
	authority.doc.Accounting = map[string]AccountingEntry{}
	if _, err := root.Lstat(authority.path); errors.Is(err, os.ErrNotExist) {
		if err := authority.persist(authority.doc); err != nil {
			_ = releaseAuthorityLock(lock)
			_ = domainLock.Close()
			_ = root.Close()
			return nil, err
		}
	} else if err != nil {
		_ = releaseAuthorityLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	} else if err := authority.load(ownerID, agentID, authorityID); err != nil {
		_ = releaseAuthorityLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	}
	if !sameJSON(authority.doc.Limits, limits) {
		_ = releaseAuthorityLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, errors.New("personal authority owner limits or custody pins changed; use a new authority generation")
	}
	if err := authority.expireIssuedCustodyLocked(); err != nil {
		_ = releaseAuthorityLock(lock)
		_ = domainLock.Close()
		_ = root.Close()
		return nil, err
	}
	return authority, nil
}

func (authority *PersonalAuthority) Close() error {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.lock == nil {
		return nil
	}
	err := releaseAuthorityLock(authority.lock)
	authority.lock = nil
	if rootErr := authority.root.Close(); err == nil && rootErr != nil {
		err = errors.New("close personal authority directory capability")
	}
	authority.root = nil
	if domainErr := authority.domainLock.Close(); err == nil && domainErr != nil {
		err = domainErr
	}
	authority.domainLock = nil
	for index := range authority.key {
		authority.key[index] = 0
	}
	return err
}

// ensureStorageIdentityLocked prevents an owner-authority namespace split. A
// retained os.Root deliberately follows the original directory across rename,
// but the economic authority must stop issuing new authorization as soon as
// its configured pathname no longer names that exact directory. Otherwise a
// replacement directory could acquire a second lock and create a concurrent
// authority domain while this process continued using the detached inode.
// The caller must hold authority.mu.
func (authority *PersonalAuthority) ensureStorageIdentityLocked() error {
	if authority == nil || authority.poisoned || authority.lock == nil || authority.domainLock == nil ||
		authority.root == nil || authority.directory == "" {
		return errors.New("personal authority storage identity is unavailable")
	}
	opened, err := authority.root.Stat(".")
	current, pathErr := os.Lstat(authority.directory)
	if err != nil || pathErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, current) || validateRelayJournalDirectorySecurity(authority.directory) != nil {
		authority.poisoned = true
		return errors.New("personal authority storage directory was replaced")
	}
	return nil
}

func (authority *PersonalAuthority) storageIdentityAttached() bool {
	if authority == nil {
		return false
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.ensureStorageIdentityLocked() == nil
}

func (authority *PersonalAuthority) AcquireWriter(_ context.Context, instanceID string, scope []string, ttl time.Duration) (commerce.WriterFence, error) {
	if authority == nil || instanceID == "" || ttl < time.Second || ttl > 24*time.Hour {
		return commerce.WriterFence{}, errors.New("writer acquisition is invalid")
	}
	scope = append([]string(nil), scope...)
	sort.Strings(scope)
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.WriterFence{}, err
	}
	now := authority.now().UTC()
	next := cloneAuthorityDocument(authority.doc)
	if next.WriterGeneration == ^uint64(0) {
		return commerce.WriterFence{}, errors.New("writer generation exhausted")
	}
	next.WriterGeneration++
	leaseID, err := randomIdentifier("lease:")
	if err != nil {
		return commerce.WriterFence{}, err
	}
	fence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: next.OwnerID, AgentID: next.AgentID,
		InstanceID: instanceID, LeaseID: leaseID, WriterGeneration: next.WriterGeneration, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(ttl).Unix()), AuthorityID: next.AuthorityID, Scope: scope}, authority.key)
	if err != nil {
		return commerce.WriterFence{}, err
	}
	retainedFence := fence
	retainedFence.Body.Scope = append([]string(nil), fence.Body.Scope...)
	next.CurrentFence = &retainedFence
	if err := authority.persist(next); err != nil {
		return commerce.WriterFence{}, err
	}
	authority.doc = next
	fence.Body.Scope = append([]string(nil), fence.Body.Scope...)
	return fence, nil
}

func (authority *PersonalAuthority) Admit(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte,
	fence commerce.WriterFence, reservation *ExposureReservation) (commerce.ActionResolution, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, err
	}
	if err := authority.expireIssuedCustodyLocked(); err != nil {
		return commerce.ActionResolution{}, err
	}
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || authority.doc.CurrentFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, errors.New("stale writer cannot admit an action")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if err := commerce.VerifyAuthorizedAction(action, fields, request, fence, resolver, now); err != nil {
		return commerce.ActionResolution{}, err
	}
	if existing, found := authority.doc.Actions[action.StableActionID]; found {
		if existing.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
				State: commerce.ActionConflict, StateRevision: existing.StateRevision + 1}, errors.New("semantic action identity conflicts with prior request")
		}
		return detachedActionResolution(existing), nil
	}
	next := cloneAuthorityDocument(authority.doc)
	if err := validateAndAdvanceOutcomeJournalAuthorityHead(&next, action, fields, request, fence); err != nil {
		return commerce.ActionResolution{}, err
	}
	if reservation != nil {
		candidate := cloneExposureReservation(*reservation)
		if err := admitReservation(next, candidate); err != nil {
			return commerce.ActionResolution{}, err
		}
		next.Reservations[candidate.ReservationID] = candidate
		next.PortfolioRevision++
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionPrepared, StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return detachedActionResolution(resolution), nil
}

// AdmitRelaySponsorshipPayment is the single owner-authority linearization
// point for a Provider-funded top-up. The exact typed relay purpose, payment
// action, and maximum-loss reservation either become durable together or not
// at all. A SponsorshipCustodyBinding is therefore only a lookup capability
// for this record; it is never authorization by itself.
func (authority *PersonalAuthority) AdmitRelaySponsorshipPayment(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence,
	payment commerce.AgreementPaymentRequest, purpose RelaySponsorshipCustodyPurpose) (
	commerce.ActionResolution, SponsorshipCustodyBinding, error) {
	if authority == nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("relay sponsorship authority is unavailable")
	}
	payment = detachedAgreementPaymentRequest(payment)
	detachedPurpose, err := cloneRelaySponsorshipPurpose(purpose)
	if err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	purpose = detachedPurpose
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	if err := authority.expireIssuedCustodyLocked(); err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("stale writer cannot admit relay sponsorship exposure")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if commerce.VerifyAuthorizedAction(action, fields, canonicalRequest, fence, resolver, authority.now().UTC()) != nil ||
		!exactRelaySponsorshipCustodyPurpose(action, payment, purpose) {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("relay sponsorship payment purpose is not exactly authorized")
	}
	expectedRequest, expectedFields, err := commerce.PaymentAuthorizationMaterial(payment)
	if err != nil || !bytes.Equal(expectedRequest, canonicalRequest) || !sameJSON(expectedFields, fields) {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("relay sponsorship payment material is not canonical")
	}
	purposeDigest, err := relaySponsorshipCustodyPurposeDigest(purpose)
	if err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	reservation, err := relaySponsorshipExposureReservation(payment, purpose.PaymentRequestDigest, purposeDigest)
	if err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	admissionID, err := relaySponsorshipPaymentAdmissionID(action, purpose.PaymentRequestDigest,
		purposeDigest, reservation.ReservationID)
	if err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	admission := relaySponsorshipPaymentAdmission{AdmissionID: admissionID, Payment: payment,
		PaymentRequestDigest: purpose.PaymentRequestDigest, Purpose: purpose, PurposeDigest: purposeDigest,
		Reservation: reservation}
	admission = detachedRelaySponsorshipPayment(admission)
	binding := SponsorshipCustodyBinding{AdmissionID: admissionID, PaymentRequestDigest: purpose.PaymentRequestDigest,
		PurposeDigest: purposeDigest, ReservationID: reservation.ReservationID,
		FinalityProfileCBORDigest: purpose.FinalityProfileCBORDigest,
		ReleaseProfileDigest:      purpose.ReleaseProfileDigest, CorroborationSnapshotID: purpose.CorroborationSnapshotID}
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		retained, retainedFound := authority.doc.RelaySponsorshipPayments[admissionID]
		reservationRecord, reservationFound := authority.doc.Reservations[reservation.ReservationID]
		expectedReservation := reservation
		switch prior.State {
		case commerce.ActionPrepared, commerce.ActionSubmitted:
		case commerce.ActionAccepted, commerce.ActionTerminal, commerce.ActionRejected:
			expectedReservation.Released = true
		default:
			return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("relay sponsorship admission has an invalid retained lifecycle")
		}
		if prior.ExactRequestDigest != action.ExactRequestDigest || !retainedFound ||
			!sameJSON(retained, admission) || !reservationFound ||
			!sameExposureReservation(reservationRecord, expectedReservation) {
			return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("relay sponsorship admission conflicts with retained authority state")
		}
		// A successor writer may re-envelope only the same stable/exact request.
		// Persisting the currently verified envelope here lets crash recovery call
		// custody under the live fence without changing the admitted payment,
		// purpose, hold, action resolution, or Portfolio revision.
		retainedAction, actionFound := authority.doc.AuthorizedActions[action.StableActionID]
		if !actionFound || !sameJSON(retainedAction, action) {
			next := cloneAuthorityDocument(authority.doc)
			recordAuthorizedAction(&next, action)
			if err := authority.persist(next); err != nil {
				return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
			}
			authority.doc = next
		}
		return detachedActionResolution(prior), binding, nil
	}
	if len(authority.doc.RelaySponsorshipPayments) >= maximumRelayAdmissions {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, errors.New("relay sponsorship admission capacity is exhausted")
	}
	next := cloneAuthorityDocument(authority.doc)
	if err := admitReservation(next, reservation); err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	next.Reservations[reservation.ReservationID] = cloneExposureReservation(reservation)
	next.RelaySponsorshipPayments[admissionID] = detachedRelaySponsorshipPayment(admission)
	next.PortfolioRevision++
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, State: commerce.ActionPrepared, StateRevision: 1}
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, SponsorshipCustodyBinding{}, err
	}
	authority.doc = next
	return detachedActionResolution(resolution), binding, nil
}

func relaySponsorshipExposureReservation(payment commerce.AgreementPaymentRequest,
	paymentDigest, purposeDigest string) (ExposureReservation, error) {
	amount, err := strconv.ParseUint(payment.Amount.AmountAtomic, 10, 64)
	if err != nil || amount == 0 || !canonicalSHA256(paymentDigest) || !canonicalSHA256(purposeDigest) {
		return ExposureReservation{}, errors.New("relay sponsorship exposure is invalid")
	}
	reservationID, err := codec.Digest("tos.openfox.relay-sponsorship-exposure-reservation.v1", struct {
		PaymentRequestDigest string `json:"payment_request_digest"`
		PurposeDigest        string `json:"purpose_digest"`
	}{paymentDigest, purposeDigest})
	if err != nil {
		return ExposureReservation{}, err
	}
	asset := commerce.AssetIdentityV1{AssetNamespace: payment.Amount.AssetNamespace,
		AssetIdentifier: payment.Amount.AssetIdentifier, Unit: payment.Amount.Unit}
	return ExposureReservation{ReservationID: reservationID, AgreementDigest: payment.AgreementBodyDigest,
		Asset: &asset, SpendAtomic: amount, MaximumLossAtomic: amount}, nil
}

func relaySponsorshipPaymentAdmissionID(action commerce.AuthorizedAction, paymentDigest,
	purposeDigest, reservationID string) (string, error) {
	return codec.Digest("tos.openfox.relay-sponsorship-payment-admission.v1", struct {
		StableActionID     string `json:"stable_action_id"`
		ExactRequestDigest string `json:"exact_request_digest"`
		PaymentDigest      string `json:"payment_request_digest"`
		PurposeDigest      string `json:"purpose_digest"`
		ReservationID      string `json:"reservation_id"`
	}{action.StableActionID, action.ExactRequestDigest, paymentDigest, purposeDigest, reservationID})
}

func (authority *PersonalAuthority) Resolve(stableActionID, requestDigest string) commerce.ActionResolution {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return commerce.ActionResolution{StableActionID: stableActionID, ExactRequestDigest: requestDigest,
			State: commerce.ActionConflict, StateRevision: 1}
	}
	resolution, found := authority.doc.Actions[stableActionID]
	if !found {
		return commerce.ActionResolution{StableActionID: stableActionID, ExactRequestDigest: requestDigest, State: commerce.ActionUnknown, StateRevision: 1}
	}
	if resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{StableActionID: stableActionID, ExactRequestDigest: requestDigest, State: commerce.ActionConflict,
			StateRevision: resolution.StateRevision + 1}
	}
	return detachedActionResolution(resolution)
}

// ResolveAuthorizedAction returns the exact signed authorization that was
// linearized with an Action resolution. Outcome recovery uses this object to
// reproduce the original immutable assertion after a process or writer
// takeover; it never reconstructs authorization from mutable policy state.
func (authority *PersonalAuthority) ResolveAuthorizedAction(stableActionID, requestDigest string) (commerce.AuthorizedAction, bool) {
	if authority == nil {
		return commerce.AuthorizedAction{}, false
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return commerce.AuthorizedAction{}, false
	}
	action, found := authority.doc.AuthorizedActions[stableActionID]
	resolution, resolved := authority.doc.Actions[stableActionID]
	if !found || !resolved || action.StableActionID != stableActionID ||
		action.ExactRequestDigest != requestDigest || resolution.ExactRequestDigest != requestDigest {
		return commerce.AuthorizedAction{}, false
	}
	return action, true
}

func (authority *PersonalAuthority) Transition(stableActionID, requestDigest string, state commerce.ActionResolutionState,
	sinkReference string, evidence []string) (commerce.ActionResolution, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, err
	}
	existing, found := authority.doc.Actions[stableActionID]
	if !found || existing.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{}, errors.New("action transition has no exact admitted predecessor")
	}
	if existing.State == commerce.ActionTerminal || existing.State == commerce.ActionRejected || existing.State == commerce.ActionConflict {
		return commerce.ActionResolution{}, errors.New("terminal action cannot transition")
	}
	for _, admission := range authority.doc.RelaySponsorshipPayments {
		if admission.Payment.StableActionID != stableActionID {
			continue
		}
		if state == commerce.ActionAccepted || state == commerce.ActionTerminal {
			return commerce.ActionResolution{}, errors.New("relay sponsorship terminal state requires authority-verified payment evidence")
		}
		if state == commerce.ActionRejected {
			for _, issued := range authority.doc.IssuedCustodyPayments {
				if issued.SponsorshipAdmissionID == admission.AdmissionID {
					return commerce.ActionResolution{}, errors.New("issued relay sponsorship custody cannot be rejected or release its hold")
				}
			}
		}
		break
	}
	next := cloneAuthorityDocument(authority.doc)
	resolution := existing
	resolution.State, resolution.SinkReference, resolution.EvidenceRefs = state, sinkReference, append([]string(nil), evidence...)
	resolution.StateRevision++
	if err := commerce.ValidateActionResolution(resolution); err != nil {
		return commerce.ActionResolution{}, err
	}
	next.Actions[stableActionID] = resolution
	if state == commerce.ActionRejected {
		for _, admission := range next.RelaySponsorshipPayments {
			if admission.Payment.StableActionID != stableActionID {
				continue
			}
			reservation, found := next.Reservations[admission.Reservation.ReservationID]
			if !found || reservation.AgreementDigest != admission.Payment.AgreementBodyDigest {
				return commerce.ActionResolution{}, errors.New("relay sponsorship terminal transition lost its exposure hold")
			}
			if !reservation.Released {
				reservation.Released = true
				next.Reservations[reservation.ReservationID] = reservation
				next.PortfolioRevision++
			}
			break
		}
	}
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return detachedActionResolution(resolution), nil
}

func (authority *PersonalAuthority) AllocateInstance(request commerce.AuthorityInstanceAllocationRequest,
	fence commerce.WriterFence) (commerce.AuthorityInstanceRecord, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return commerce.AuthorityInstanceRecord{}, errors.New("stale writer cannot allocate an authority instance")
	}
	digest, err := commerce.AuthorityInstanceAllocationRequestDigest(request)
	if err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	if existing, found := authority.doc.AuthorityInstances[digest]; found {
		return existing, nil
	}
	next := cloneAuthorityDocument(authority.doc)
	sequence := next.NextInstanceSequence
	identifier, err := commerce.DeriveAuthorityInstanceID(request, sequence)
	if err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	record := commerce.AuthorityInstanceRecord{RequestDigest: digest, AllocationSequence: sequence, AuthorityInstanceID: identifier,
		PolicyRevision: next.PortfolioRevision}
	next.AuthorityInstances[digest] = record
	next.NextInstanceSequence++
	if err := authority.persist(next); err != nil {
		return commerce.AuthorityInstanceRecord{}, err
	}
	authority.doc = next
	return record, nil
}

func (authority *PersonalAuthority) Snapshot() (uint64, PortfolioLimits, []ExposureReservation) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ensureStorageIdentityLocked() != nil {
		return 0, PortfolioLimits{}, nil
	}
	if authority.expireIssuedCustodyLocked() != nil {
		return 0, PortfolioLimits{}, nil
	}
	reservations := make([]ExposureReservation, 0, len(authority.doc.Reservations))
	for _, reservation := range authority.doc.Reservations {
		reservations = append(reservations, cloneExposureReservation(reservation))
	}
	sort.Slice(reservations, func(i, j int) bool { return reservations[i].ReservationID < reservations[j].ReservationID })
	return authority.doc.PortfolioRevision, clonePortfolioLimits(authority.doc.Limits), reservations
}

// ReleaseReservation admits portfolio.release and applies it in one journal
// transaction. A fence alone cannot release economic capacity.
func (authority *PersonalAuthority) ReleaseReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	return authority.releaseReservation(action, fields, request, fence, 0, 0)
}

// ReleaseGuarantorReservation removes the terminal reservation while retaining
// spent value and unresolved default liability in the aggregate underwriting
// limit.  The caller must have derived the two buckets from the verified
// terminal evidence graph; their sum can never exceed the original reservation.
func (authority *PersonalAuthority) ReleaseGuarantorReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	realizedLossAtomic, retainedDefaultLiabilityAtomic uint64) (commerce.ActionResolution, error) {
	return authority.releaseReservation(action, fields, request, fence, realizedLossAtomic, retainedDefaultLiabilityAtomic)
}

func (authority *PersonalAuthority) releaseReservation(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	realizedLossAtomic, retainedDefaultLiabilityAtomic uint64) (commerce.ActionResolution, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.ActionResolution{}, err
	}
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || !authority.now().UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0)) {
		return commerce.ActionResolution{}, errors.New("stale writer cannot release a reservation")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID, key: authority.key.Public().(ed25519.PublicKey)}
	if action.ActionKind != "portfolio.release" || commerce.VerifyAuthorizedAction(action, fields, request, fence, resolver, authority.now().UTC()) != nil {
		return commerce.ActionResolution{}, errors.New("portfolio release action is not authorized")
	}
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{}, errors.New("portfolio release identity conflicts")
		}
		if prior.State == commerce.ActionTerminal {
			return detachedActionResolution(prior), nil
		}
		if prior.State != commerce.ActionPrepared {
			return commerce.ActionResolution{}, errors.New("portfolio release has an unresolved non-prepared predecessor")
		}
	}
	var release PortfolioReleaseRequest
	if err := codec.Unmarshal(request, &release); err != nil {
		var guarantorRelease guarantor.PreAcceptanceExposureReleaseActionBodyV1
		if decodeErr := codec.Unmarshal(request, &guarantorRelease); decodeErr != nil ||
			guarantorRelease.SchemaVersion != 1 || guarantorRelease.ReleaseVariant != "pre_acceptance" ||
			guarantorRelease.TargetPortfolioRevision != guarantorRelease.ExpectedPortfolioRevision+1 {
			return commerce.ActionResolution{}, errors.New("portfolio release request is invalid")
		}
		nonAcceptanceDigest, digestErr := guarantor.OfferNonAcceptanceDigestV1(guarantorRelease.AuthorizedNonAcceptanceEvidence)
		if digestErr != nil {
			return commerce.ActionResolution{}, errors.New("portfolio release terminal evidence is invalid")
		}
		release = PortfolioReleaseRequest{ReservationID: guarantorRelease.AuthorizedNonAcceptanceEvidence.Body.ReservationID,
			AgreementDigest:         guarantorRelease.AuthorizedNonAcceptanceEvidence.AuthorizedFirmOffer.Body.CoverageAgreementBodyDigest,
			TargetPortfolioRevision: guarantorRelease.TargetPortfolioRevision, TerminalEvidenceSetDigest: nonAcceptanceDigest}
	}
	if release.TargetPortfolioRevision != authority.doc.PortfolioRevision+1 {
		return commerce.ActionResolution{}, errors.New("portfolio release request or target revision is invalid")
	}
	existing, found := authority.doc.Reservations[release.ReservationID]
	if !found || existing.AgreementDigest != release.AgreementDigest || existing.Released {
		return commerce.ActionResolution{}, errors.New("portfolio reservation does not match or is already released")
	}
	for _, issued := range authority.doc.IssuedCustodyPayments {
		if issued.ReservationID != existing.ReservationID {
			continue
		}
		return commerce.ActionResolution{}, ErrCustodyAuthorizationLive
	}
	if engagement, engagementFound := authority.doc.Engagements[existing.AgreementDigest]; engagementFound {
		switch engagement.State {
		case EngagementSettled:
			for _, ledger := range authority.doc.SettlementLedger {
				if ledger.Obligation.AgreementBodyDigest == engagement.AgreementDigest &&
					ledger.State.State != commerce.SettlementPaid {
					return commerce.ActionResolution{}, errors.New("settled Agreement retains a non-paid settlement obligation")
				}
			}
		case EngagementCancelled, EngagementFailed:
			// No issued custody capability remains above, so a terminal
			// pre-payment cancellation/failure can safely free capacity.
		default:
			return commerce.ActionResolution{}, errors.New("non-terminal Agreement cannot release its Portfolio reservation")
		}
	}
	bucket, bucketErr := exposureAssetBucket(existing.Asset)
	if bucketErr != nil {
		return commerce.ActionResolution{}, bucketErr
	}
	consumedBefore, retainedBefore := authority.doc.ConsumedMaximumLossAtomic, authority.doc.RetainedDefaultLiabilityAtomic
	if bucket != "" {
		consumedBefore = authority.doc.ConsumedMaximumLossByAsset[bucket]
		retainedBefore = authority.doc.RetainedDefaultLiabilityByAsset[bucket]
	}
	if exceeds(realizedLossAtomic, retainedDefaultLiabilityAtomic, existing.MaximumLossAtomic) ||
		exceeds(consumedBefore, realizedLossAtomic, authority.doc.Limits.MaximumLossAtomic) {
		return commerce.ActionResolution{}, errors.New("portfolio release disposition exceeds the reserved or aggregate maximum loss")
	}
	consumedAfter := consumedBefore + realizedLossAtomic
	if exceeds(consumedAfter, retainedBefore, authority.doc.Limits.MaximumLossAtomic) ||
		exceeds(consumedAfter+retainedBefore,
			retainedDefaultLiabilityAtomic, authority.doc.Limits.MaximumLossAtomic) {
		return commerce.ActionResolution{}, errors.New("portfolio release retained liability exceeds the aggregate maximum loss")
	}
	next := cloneAuthorityDocument(authority.doc)
	existing.Released = true
	next.Reservations[release.ReservationID] = existing
	if bucket == "" {
		next.ConsumedMaximumLossAtomic += realizedLossAtomic
		next.RetainedDefaultLiabilityAtomic += retainedDefaultLiabilityAtomic
	} else {
		next.ConsumedMaximumLossByAsset[bucket] = consumedAfter
		next.RetainedDefaultLiabilityByAsset[bucket] = retainedBefore + retainedDefaultLiabilityAtomic
	}
	next.PortfolioRevision++
	stateRevision := uint64(1)
	if prior, found := authority.doc.Actions[action.StableActionID]; found {
		stateRevision = prior.StateRevision + 1
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, EvidenceRefs: []string{release.TerminalEvidenceSetDigest}, StateRevision: stateRevision}
	if err := commerce.ValidateActionResolution(resolution); err != nil {
		return commerce.ActionResolution{}, err
	}
	next.Actions[action.StableActionID] = resolution
	recordAuthorizedAction(&next, action)
	if err := authority.persist(next); err != nil {
		return commerce.ActionResolution{}, err
	}
	authority.doc = next
	return detachedActionResolution(resolution), nil
}

func validateExpiredCustodyAuthorization(document authorityDocument, tombstone expiredCustodyAuthorization,
	marker uint64, reservationID, sponsorshipAdmissionID string, key ed25519.PrivateKey, now time.Time) error {
	// Kept as a separate validator because an expired bearer is no longer in
	// IssuedCustodyPayments, yet it remains the sole durable proof that a signed
	// offline capability once owned the released hold.
	issued := tombstone.Issuance
	paymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(issued.Payment)
	authorizationDigest, authorizationErr := codec.Digest(
		"tos.openfox.issued-native-custody-authorization.v1", issued.Authorization)
	resigned, signatureErr := commerce.SignCustodyActionAuthorization(issued.Authorization, key)
	reservation, reservationFound := document.Reservations[reservationID]
	resolution, resolutionFound := document.Actions[issued.Payment.StableActionID]
	if marker == 0 || tombstone.ExpiredAtUnix != marker || issued.ReleaseAfterUnix == 0 ||
		issued.FinalityGraceSeconds == 0 || issued.ReleaseAfterUnix > marker || now.Unix() < 0 ||
		issued.FinalityGraceSeconds != document.Limits.CustodyFinalityGraceSeconds ||
		uint64(now.Unix()) < issued.ReleaseAfterUnix || paymentErr != nil || authorizationErr != nil ||
		signatureErr != nil || issued.PaymentRequestDigest != paymentDigest ||
		issued.AuthorizationDigest != authorizationDigest || !sameJSON(resigned, issued.Authorization) ||
		issued.ReservationID != reservationID || !reservationFound || !reservation.Released ||
		!resolutionFound || resolution.ExactRequestDigest != issued.Authorization.ExactRequestDigest ||
		issued.Authorization.SchemaVersion != 3 || issued.Payment.SchemaVersion != 3 ||
		issued.Payment.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI ||
		issued.Authorization.AgreementPaymentRequestDigest != paymentDigest ||
		issued.Authorization.StableActionID != issued.Payment.StableActionID ||
		issued.Authorization.AgreementBodyDigest != issued.Payment.AgreementBodyDigest ||
		issued.Authorization.ObligationInstanceID != issued.Payment.ObligationInstanceID ||
		issued.Authorization.Destination != string(issued.Payment.Destination) ||
		issued.Authorization.ExpiresAtUnix > issued.Payment.ExpiresAtUnix ||
		issued.TerminalEvidenceDigest != "" || issued.TerminalReference != "" {
		return errors.New("personal authority expired custody tombstone is invalid")
	}
	if _, stillLive := document.IssuedCustodyPayments[paymentDigest]; stillLive {
		return errors.New("personal authority custody bearer is both live and expired")
	}
	if sponsorshipAdmissionID == "" {
		engagement, found := document.Engagements[issued.Payment.AgreementBodyDigest]
		if !found || engagement.ReservationID != reservationID || issued.SponsorshipAdmissionID != "" {
			return errors.New("personal authority expired Agreement custody binding is invalid")
		}
	} else if issued.SponsorshipAdmissionID != sponsorshipAdmissionID {
		return errors.New("personal authority expired sponsorship custody binding is invalid")
	}
	if issued.Authorization.NetworkDomain == nil {
		return errors.New("personal authority expired custody network domain is absent")
	}
	domain := *issued.Authorization.NetworkDomain
	domainDigest, domainErr := agentrelay.NetworkDomainDigest(agentrelay.NetworkDomain{NetworkID: domain.NetworkID,
		GlobalID: domain.GlobalID, ZeroStateRootHash: domain.ZeroStateRootHash,
		ZeroStateFileHash: domain.ZeroStateFileHash, WorkchainID: domain.WorkchainID})
	nativeAsset := document.Limits.CustodyNativeAsset
	if domainErr != nil || domainDigest != document.Limits.CustodyNetworkDomainDigest ||
		domainDigest != issued.Payment.NetworkDomainDigest || nativeAsset == nil ||
		issued.Authorization.SourceAccount != document.Limits.CustodySourceAccount ||
		issued.Payment.Amount.AssetNamespace != nativeAsset.AssetNamespace ||
		issued.Payment.Amount.AssetIdentifier != nativeAsset.AssetIdentifier ||
		issued.Payment.Amount.Unit != nativeAsset.Unit {
		return errors.New("personal authority expired custody owner pins are invalid")
	}
	releaseAfter, horizonErr := custodyAuthorizationReleaseAfter(document, issued)
	if horizonErr != nil || releaseAfter != issued.ReleaseAfterUnix {
		return errors.New("personal authority expired custody horizon is invalid")
	}
	return nil
}

func (authority *PersonalAuthority) load(ownerID, agentID, authorityID string) error {
	info, err := authority.root.Lstat(authority.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 32<<20 {
		return errors.New("personal authority journal is not an owner-only bounded regular file")
	}
	file, err := authority.root.Open(authority.path)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || validateAuthorityJournalFile(file, openedInfo) != nil {
		return errors.New("personal authority journal changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (32<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 32<<20 {
		return errors.New("read bounded personal authority journal")
	}
	var document authorityDocument
	if decodeStrictJSON(raw, &document) != nil || document.Schema != authoritySchema || document.OwnerID != ownerID || document.AgentID != agentID ||
		document.AuthorityID != authorityID || document.PortfolioRevision == 0 || document.NextInstanceSequence == 0 || document.Actions == nil ||
		document.AuthorityInstances == nil || document.Reservations == nil {
		return errors.New("personal authority journal is invalid")
	}
	if exceeds(document.ConsumedMaximumLossAtomic, document.RetainedDefaultLiabilityAtomic,
		document.Limits.MaximumLossAtomic) {
		return errors.New("personal authority loss disposition exceeds its portfolio limit")
	}
	if document.ConsumedMaximumLossByAsset == nil {
		document.ConsumedMaximumLossByAsset = map[string]uint64{}
	}
	if document.RetainedDefaultLiabilityByAsset == nil {
		document.RetainedDefaultLiabilityByAsset = map[string]uint64{}
	}
	for bucket, consumed := range document.ConsumedMaximumLossByAsset {
		retained, found := document.RetainedDefaultLiabilityByAsset[bucket]
		if !found || !canonicalSHA256(bucket) || exceeds(consumed, retained, document.Limits.MaximumLossAtomic) {
			return errors.New("personal authority asset loss disposition is invalid")
		}
	}
	for bucket, retained := range document.RetainedDefaultLiabilityByAsset {
		consumed, found := document.ConsumedMaximumLossByAsset[bucket]
		if !found || !canonicalSHA256(bucket) || exceeds(consumed, retained, document.Limits.MaximumLossAtomic) {
			return errors.New("personal authority asset liability disposition is invalid")
		}
	}
	if _, _, err := portfolioUsage(document); err != nil {
		return err
	}
	if document.ScheduleEntries == nil {
		document.ScheduleEntries = map[string]commerce.EngagementScheduleEntry{}
	}
	if document.Engagements == nil {
		document.Engagements = map[string]EngagementRecord{}
	}
	if document.SettlementLedger == nil {
		document.SettlementLedger = map[string]SettlementLedgerRecord{}
	}
	if document.Accounting == nil {
		document.Accounting = map[string]AccountingEntry{}
	}
	if document.AuthorizedActions == nil {
		document.AuthorizedActions = map[string]commerce.AuthorizedAction{}
	}
	if document.OutcomeJournalHeads == nil {
		document.OutcomeJournalHeads = map[string]OutcomeJournalAuthorityHeadV1{}
	}
	for domain, head := range document.OutcomeJournalHeads {
		resolution, found := document.Actions[head.StableActionID]
		if !canonicalSHA256(domain) || head.Epoch == 0 || head.Sequence == 0 || !canonicalSHA256(head.EventContentID) ||
			!canonicalSHA256(head.OperationEnvelopeDigest) || !canonicalSHA256(head.GapSetDigest) || !found ||
			resolution.ExactRequestDigest != head.ExactRequestDigest {
			return errors.New("personal authority outcome journal high-water is invalid")
		}
	}
	for stableActionID, action := range document.AuthorizedActions {
		resolution, found := document.Actions[stableActionID]
		if !found || action.StableActionID != stableActionID || action.ExactRequestDigest != resolution.ExactRequestDigest {
			return errors.New("personal authority authorized Action index is invalid")
		}
		if _, err := commerce.AuthorizedActionDigest(action); err != nil {
			return errors.New("personal authority stored AuthorizedAction is invalid")
		}
	}
	if document.RelayAdmissions == nil {
		document.RelayAdmissions = map[string]agentrelay.SignedRelaySideEffectAdmissionReceipt{}
	}
	if document.RelayAdmissionBindings == nil {
		document.RelayAdmissionBindings = map[string]string{}
	}
	if document.RelaySponsorshipPayments == nil {
		document.RelaySponsorshipPayments = map[string]relaySponsorshipPaymentAdmission{}
	}
	if document.IssuedCustodyPayments == nil {
		document.IssuedCustodyPayments = map[string]issuedCustodyPaymentAuthorization{}
	}
	if document.NextRelayAdmissionSequence == 0 && len(document.RelayAdmissions) == 0 {
		document.NextRelayAdmissionSequence = 1
	}
	if len(document.RelayAdmissions) > maximumRelayAdmissions || len(document.RelayAdmissionBindings) > maximumRelayAdmissions {
		return errors.New("personal authority relay admission capacity is exceeded")
	}
	relayAdmissionSequences := make(map[uint64]struct{}, len(document.RelayAdmissions))
	expectedRelayAdmissionBindings := make(map[string]string, len(document.RelayAdmissions))
	type relayAdmissionRouteEntry struct {
		lookupDigest string
		receipt      agentrelay.SignedRelaySideEffectAdmissionReceipt
	}
	relayAdmissionRoutes := make(map[string][]relayAdmissionRouteEntry, len(document.RelayAdmissions))
	var maximumRelayAdmissionSequence uint64
	for lookupDigest, receipt := range document.RelayAdmissions {
		body := receipt.Body
		lookup := agentrelay.RelaySideEffectAdmissionLookup{SchemaVersion: 1, OwnerID: body.OwnerID, AgentID: body.AgentID,
			AuthenticatedPrincipal: body.AuthenticatedPrincipal, AuthorityID: body.AuthorityID,
			ProviderAgentID: body.ProviderAgentID, ServiceProfileDigest: body.ServiceProfileDigest,
			ProviderQuoteDigest: body.ProviderQuoteDigest, NetworkDigest: body.NetworkDigest,
			TransactionIdentityDigest: body.TransactionIdentityDigest, Mode: body.Mode,
			AssuranceLevel: body.AssuranceLevel,
			RouteAttempt:   body.RouteAttempt, PredecessorReceiptDigest: body.PredecessorReceiptDigest,
			StableActionID:     body.StableActionID,
			ExactRequestDigest: body.ExactRequestDigest, RelayExecutionDigest: body.RelayExecutionDigest,
			StageMask: append([]agentrelay.SideEffectStage(nil), body.StageMask...)}
		computed, digestErr := agentrelay.RelaySideEffectAdmissionLookupDigest(lookup)
		if digestErr != nil || computed != lookupDigest || body.OwnerID != document.OwnerID ||
			body.AgentID != document.AgentID || body.AuthorityID != document.AuthorityID ||
			body.AdmissionSequence == 0 ||
			receipt.PublicKey != "ed25519:"+hex.EncodeToString(authority.key.Public().(ed25519.PublicKey)) ||
			agentrelay.VerifyRelaySideEffectAdmissionReceiptSignature(receipt) != nil {
			return errors.New("personal authority relay admission ledger is invalid")
		}
		if _, duplicate := relayAdmissionSequences[body.AdmissionSequence]; duplicate {
			return errors.New("personal authority relay admission sequence is reused")
		}
		relayAdmissionSequences[body.AdmissionSequence] = struct{}{}
		if body.AdmissionSequence > maximumRelayAdmissionSequence {
			maximumRelayAdmissionSequence = body.AdmissionSequence
		}
		bindingKey := relayAdmissionStableBindingKey(body.OwnerID, body.AgentID, body.StableActionID)
		relayAdmissionRoutes[bindingKey] = append(relayAdmissionRoutes[bindingKey], relayAdmissionRouteEntry{
			lookupDigest: lookupDigest, receipt: receipt,
		})
	}
	for bindingKey, route := range relayAdmissionRoutes {
		if len(route) > int(agentrelay.MaxRelayRouteAttempts) {
			return errors.New("personal authority relay admission route chain exceeds the V1 limit")
		}
		sort.Slice(route, func(left, right int) bool {
			return route[left].receipt.Body.RouteAttempt < route[right].receipt.Body.RouteAttempt
		})
		chain := make([]agentrelay.SignedRelaySideEffectAdmissionReceipt, len(route))
		for index := range route {
			chain[index] = route[index].receipt
		}
		if agentrelay.ValidateRelaySideEffectAdmissionRouteChain(chain) != nil {
			return errors.New("personal authority relay admission route chain is invalid")
		}
		expectedRelayAdmissionBindings[bindingKey] = route[len(route)-1].lookupDigest
	}
	if maximumRelayAdmissionSequence == ^uint64(0) ||
		document.NextRelayAdmissionSequence != maximumRelayAdmissionSequence+1 {
		return errors.New("personal authority relay admission high-water is invalid")
	}
	if len(document.RelayAdmissionBindings) == 0 && len(expectedRelayAdmissionBindings) != 0 {
		// Migrate only from already verified, contiguous receipt chains. The
		// highest route attempt is the one and only successor admission point.
		document.RelayAdmissionBindings = expectedRelayAdmissionBindings
	} else if !equalRelayAdmissionBindings(document.RelayAdmissionBindings, expectedRelayAdmissionBindings) {
		return errors.New("personal authority relay admission binding index is invalid")
	}
	if len(document.RelaySponsorshipPayments) > maximumRelayAdmissions {
		return errors.New("personal authority relay sponsorship admission capacity is exceeded")
	}
	seenSponsorshipActions := make(map[string]struct{}, len(document.RelaySponsorshipPayments))
	for admissionID, admission := range document.RelaySponsorshipPayments {
		action, actionFound := document.AuthorizedActions[admission.Payment.StableActionID]
		resolution, resolutionFound := document.Actions[admission.Payment.StableActionID]
		purposeDigest, purposeErr := relaySponsorshipCustodyPurposeDigest(admission.Purpose)
		expectedReservation, reservationErr := relaySponsorshipExposureReservation(admission.Payment,
			admission.PaymentRequestDigest, purposeDigest)
		expectedAdmissionID, admissionErr := relaySponsorshipPaymentAdmissionID(action,
			admission.PaymentRequestDigest, purposeDigest, expectedReservation.ReservationID)
		actualReservation, reservationFound := document.Reservations[expectedReservation.ReservationID]
		_, duplicateAction := seenSponsorshipActions[admission.Payment.StableActionID]
		if !actionFound || !resolutionFound || purposeErr != nil || reservationErr != nil || admissionErr != nil ||
			admissionID != admission.AdmissionID || admissionID != expectedAdmissionID || duplicateAction ||
			purposeDigest != admission.PurposeDigest || !sameExposureReservation(admission.Reservation, expectedReservation) ||
			!reservationFound || !exactRelaySponsorshipCustodyPurpose(action, admission.Payment, admission.Purpose) {
			return errors.New("personal authority relay sponsorship admission ledger is invalid")
		}
		hasExpiryMarker := admission.CustodyAuthorizationExpiredAtUnix != 0
		if hasExpiryMarker != (admission.ExpiredCustodyAuthorization != nil) {
			return errors.New("personal authority sponsorship custody expiry marker is incomplete")
		}
		if admission.ExpiredCustodyAuthorization != nil {
			if err := validateExpiredCustodyAuthorization(document, *admission.ExpiredCustodyAuthorization,
				admission.CustodyAuthorizationExpiredAtUnix, admission.Reservation.ReservationID,
				admissionID, authority.key, authority.now().UTC()); err != nil {
				return err
			}
		}
		expectReleased := resolution.State == commerce.ActionRejected || hasExpiryMarker
		expectedReservation.Released = expectReleased
		if !sameExposureReservation(actualReservation, expectedReservation) {
			return errors.New("personal authority relay sponsorship exposure lifecycle is invalid")
		}
		seenSponsorshipActions[admission.Payment.StableActionID] = struct{}{}
	}
	if len(document.IssuedCustodyPayments) > maximumIssuedCustodyAuthorizations {
		return errors.New("personal authority issued custody capacity is exceeded")
	}
	issuedReservations := make(map[string]string, len(document.IssuedCustodyPayments))
	for paymentDigest, issued := range document.IssuedCustodyPayments {
		computedPaymentDigest, paymentErr := commerce.AgreementPaymentRequestDigest(issued.Payment)
		computedAuthorizationDigest, authorizationDigestErr := codec.Digest(
			"tos.openfox.issued-native-custody-authorization.v1", issued.Authorization)
		resigned, signatureErr := commerce.SignCustodyActionAuthorization(issued.Authorization, authority.key)
		reservation, reservationFound := document.Reservations[issued.ReservationID]
		actionResolution, actionFound := document.Actions[issued.Payment.StableActionID]
		amount, amountErr := strconv.ParseUint(issued.Payment.Amount.AmountAtomic, 10, 64)
		if paymentErr != nil || authorizationDigestErr != nil || signatureErr != nil || amountErr != nil || amount == 0 ||
			paymentDigest != computedPaymentDigest || issued.PaymentRequestDigest != paymentDigest ||
			issued.Payment.SchemaVersion != 3 || issued.Payment.SettlementAdapterURI != agentrelay.DirectPaymentAdapterURI ||
			issued.AuthorizationDigest != computedAuthorizationDigest || !sameJSON(resigned, issued.Authorization) ||
			!reservationFound || reservation.Released || !actionFound ||
			actionResolution.ExactRequestDigest != issued.Authorization.ExactRequestDigest ||
			issued.Authorization.SchemaVersion != 3 || issued.Authorization.NetworkDomain == nil ||
			issued.Authorization.AgreementPaymentRequestDigest != paymentDigest ||
			issued.Authorization.StableActionID != issued.Payment.StableActionID ||
			issued.Authorization.AgreementBodyDigest != issued.Payment.AgreementBodyDigest ||
			issued.Authorization.ObligationInstanceID != issued.Payment.ObligationInstanceID ||
			issued.Authorization.Destination != string(issued.Payment.Destination) ||
			issued.Authorization.AmountAtomic != amount ||
			issued.Authorization.ExpiresAtUnix > issued.Payment.ExpiresAtUnix ||
			issued.TerminalEvidenceDigest != "" || issued.TerminalReference != "" {
			return errors.New("personal authority issued native custody ledger is invalid")
		}
		if priorDigest, duplicate := issuedReservations[issued.ReservationID]; duplicate && priorDigest != paymentDigest {
			return errors.New("personal authority reservation has multiple live custody bearers")
		}
		issuedReservations[issued.ReservationID] = paymentDigest
		if issued.FinalityGraceSeconds == 0 {
			if issued.ReleaseAfterUnix != 0 {
				return errors.New("personal authority permanent custody hold has a release horizon")
			}
		} else if issued.FinalityGraceSeconds != document.Limits.CustodyFinalityGraceSeconds {
			return errors.New("personal authority issued custody grace differs from the owner pin")
		} else if releaseAfter, horizonErr := custodyAuthorizationReleaseAfter(document, issued); horizonErr != nil ||
			releaseAfter != issued.ReleaseAfterUnix {
			return errors.New("personal authority issued custody horizon is invalid")
		}
		domain := *issued.Authorization.NetworkDomain
		domainDigest, domainErr := agentrelay.NetworkDomainDigest(agentrelay.NetworkDomain{NetworkID: domain.NetworkID,
			GlobalID: domain.GlobalID, ZeroStateRootHash: domain.ZeroStateRootHash,
			ZeroStateFileHash: domain.ZeroStateFileHash, WorkchainID: domain.WorkchainID})
		nativeAsset := document.Limits.CustodyNativeAsset
		if domainErr != nil || domainDigest != issued.Payment.NetworkDomainDigest ||
			domainDigest != document.Limits.CustodyNetworkDomainDigest ||
			domain.NetworkID != issued.Payment.NetworkID || nativeAsset == nil ||
			issued.Authorization.SourceAccount != document.Limits.CustodySourceAccount ||
			issued.Payment.Amount.AssetNamespace != nativeAsset.AssetNamespace ||
			issued.Payment.Amount.AssetIdentifier != nativeAsset.AssetIdentifier ||
			issued.Payment.Amount.Unit != nativeAsset.Unit {
			return errors.New("personal authority issued custody network domain is invalid")
		}
		if issued.SponsorshipAdmissionID != "" {
			admission, found := document.RelaySponsorshipPayments[issued.SponsorshipAdmissionID]
			if !found || admission.PaymentRequestDigest != paymentDigest ||
				admission.Reservation.ReservationID != issued.ReservationID {
				return errors.New("personal authority issued sponsorship custody binding is invalid")
			}
		} else {
			engagement, found := document.Engagements[issued.Payment.AgreementBodyDigest]
			if !found || engagement.ReservationID != issued.ReservationID {
				return errors.New("personal authority issued Agreement custody binding is invalid")
			}
		}
	}
	if err := commerce.ValidatePortfolioDependencies(document.Dependencies); err != nil {
		return errors.New("personal authority dependency graph is invalid")
	}
	for _, entry := range document.ScheduleEntries {
		if err := commerce.ValidateScheduleEntry(entry); err != nil {
			return errors.New("personal authority schedule is invalid")
		}
	}
	for digest, engagement := range document.Engagements {
		initializeObligationRuntime(&engagement)
		computed, err := commerce.AgreementBodyDigest(engagement.Agreement.Body)
		if err != nil || computed != digest || engagement.AgreementDigest != digest || engagement.StateRevision == 0 ||
			engagement.LastTransitionAtUnix == 0 || !knownEngagementState(engagement.State) ||
			!validNegotiationConflictRecord(engagement) {
			return errors.New("personal authority engagement ledger is invalid")
		}
		if engagement.FullyAuthorizedEvidenceSetDigest != "" &&
			!retainedAgreementFullyAuthorized(engagement, document.AgentID) {
			return errors.New("personal authority fully authorized Agreement marker is invalid")
		}
		hasExpiryMarker := engagement.CustodyAuthorizationExpiredAtUnix != 0
		if hasExpiryMarker != (engagement.ExpiredCustodyAuthorization != nil) {
			return errors.New("personal authority Agreement custody expiry marker is incomplete")
		}
		if engagement.ExpiredCustodyAuthorization != nil {
			if err := validateExpiredCustodyAuthorization(document, *engagement.ExpiredCustodyAuthorization,
				engagement.CustodyAuthorizationExpiredAtUnix, engagement.ReservationID, "",
				authority.key, authority.now().UTC()); err != nil {
				return err
			}
		}
		if engagement.ReservationID != "" {
			reservation, reservationFound := document.Reservations[engagement.ReservationID]
			reserveAction, actionFound := document.AuthorizedActions[engagement.ReservationActionID]
			reserveResolution, resolutionFound := document.Actions[engagement.ReservationActionID]
			if !reservationFound || reservation.AgreementDigest != engagement.AgreementDigest ||
				engagement.ReservationActionID == "" || engagement.ReservationActionExactRequestDigest == "" ||
				!actionFound || !resolutionFound || reserveAction.ActionKind != "portfolio.reserve" ||
				reserveAction.ExactRequestDigest != engagement.ReservationActionExactRequestDigest ||
				reserveResolution.ExactRequestDigest != engagement.ReservationActionExactRequestDigest ||
				reserveResolution.State != commerce.ActionTerminal {
				return errors.New("personal authority Engagement reservation has no exact linearized action; use a new authority generation")
			}
		}
		for _, evidence := range engagement.Agreement.AuthorizationEvidence {
			if evidence.EvidenceProfileURI != commerce.EvidenceProfileAgentSignature ||
				evidence.AuthoritySubject.SubjectKind != "agent" ||
				evidence.AuthoritySubject.SubjectIdentifier != document.AgentID {
				continue
			}
			exposure, exposureErr := localAgreementPaymentExposure(engagement.Agreement.Body, document.AgentID)
			reservation, reservationFound := document.Reservations[engagement.ReservationID]
			historicalReservation := reservation
			historicalReservation.Released = false
			exactHistoricalHold := reservationFound &&
				reservationExactlyCoversAgreementPayment(historicalReservation, engagement, exposure)
			terminalRelease := false
			if reservationFound && reservation.Released {
				switch engagement.State {
				case EngagementSettled:
					terminalRelease = true
					for _, ledger := range document.SettlementLedger {
						if ledger.Obligation.AgreementBodyDigest == engagement.AgreementDigest &&
							ledger.State.State != commerce.SettlementPaid {
							terminalRelease = false
						}
					}
				case EngagementCancelled, EngagementFailed:
					terminalRelease = true
				case EngagementUnpaid:
					terminalRelease = engagement.ExpiredCustodyAuthorization != nil
				}
			}
			if exposureErr != nil || exposure.MaximumLoss.Sign() > 0 &&
				(!exactHistoricalHold || reservation.Released && !terminalRelease ||
					!reservation.Released && engagement.ExpiredCustodyAuthorization != nil) {
				return errors.New("personal authority contains a local buyer signature without an exact live hold")
			}
		}
		if err := validateObligationRuntime(engagement); err != nil {
			return err
		}
		for _, accepted := range engagement.AcceptedPrivateInputs {
			if commerce.ValidateAcceptedPrivateContent(accepted) != nil {
				return errors.New("personal authority accepted private input is invalid")
			}
		}
		for _, bound := range engagement.BoundPrivateInputs {
			if bound.ObligationID == "" || commerce.ValidateAcceptedPrivateContent(bound.Record) != nil {
				return errors.New("personal authority obligation-bound private input is invalid")
			}
			if _, found := obligationByID(engagement, bound.ObligationID); !found {
				return errors.New("personal authority private input names an absent obligation")
			}
		}
		for index, challenge := range engagement.PrivateHandoffChallenges {
			if challenge.ObligationID == "" || !canonicalSHA256(challenge.ChallengeDigest) || !canonicalSHA256(challenge.SendActionID) ||
				index > 0 && engagement.PrivateHandoffChallenges[index-1].ObligationID >= challenge.ObligationID {
				return errors.New("personal authority private handoff challenge binding is invalid")
			}
			if obligation, found := obligationByID(engagement, challenge.ObligationID); !found ||
				obligation.BeneficiaryAgentID != document.AgentID || !containsString(obligation.RequiredExtensions, "tos.private-handoff.v1") {
				return errors.New("personal authority private handoff challenge names an unauthorized obligation")
			}
		}
		document.Engagements[digest] = engagement
	}
	for instanceID, settlement := range document.SettlementLedger {
		if settlement.Obligation.ObligationInstanceID != instanceID || commerce.ValidateSettlementObligation(settlement.Obligation) != nil ||
			commerce.ValidateSettlementState(settlement.State) != nil {
			return errors.New("personal authority settlement ledger is invalid")
		}
	}
	for entryID, entry := range document.Accounting {
		computed, err := AccountingEntryID(entry.Body)
		if err != nil || computed != entryID || entry.EntryID != entryID || entry.WriterGeneration == 0 {
			return errors.New("personal authority accounting ledger is invalid")
		}
	}
	authority.doc = document
	return nil
}

func knownEngagementState(state EngagementState) bool {
	switch state {
	case EngagementProposed, EngagementAuthorizing, EngagementAgreed, EngagementReserved, EngagementFundingPending,
		EngagementReady, EngagementExecutionPrepared, EngagementExecuting, EngagementExecutionSucceeded, EngagementDelivered, EngagementSettling,
		EngagementSettled, EngagementUnpaid, EngagementCancellationResolving, EngagementCancelled, EngagementFailed,
		EngagementAmbiguous:
		return true
	default:
		return false
	}
}

func (authority *PersonalAuthority) persist(document authorityDocument) error {
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	raw, err := json.Marshal(document)
	if err != nil || len(raw) > 32<<20 {
		return errors.New("encode personal authority journal")
	}
	writeErr := fileutil.WriteFileAtomicRoot(authority.root, authority.path, raw, 0o600)
	protectErr := protectRootedJournalFile(authority.root, authority.path)
	if writeErr != nil {
		authority.poisoned = true
		return writeErr
	}
	if protectErr != nil {
		authority.poisoned = true
		return protectErr
	}
	return nil
}

type localFenceResolver struct {
	authorityID string
	key         ed25519.PublicKey
}

// AuthorizeFenceKey and ConfirmCurrentWriterFence let independent local sinks
// verify both cryptographic authority and the current high-water lease. They
// expose no signing key or mutation surface.
func (authority *PersonalAuthority) AuthorizeFenceKey(authorityID string, publicKey ed25519.PublicKey, _ time.Time) error {
	if authority == nil {
		return errors.New("writer authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	if authorityID != authority.doc.AuthorityID || !authority.key.Public().(ed25519.PublicKey).Equal(publicKey) {
		return errors.New("writer fence key is not the owner authority key")
	}
	return nil
}

func (authority *PersonalAuthority) ConfirmCurrentWriterFence(fence commerce.WriterFence, now time.Time) error {
	if authority == nil {
		return errors.New("writer authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return err
	}
	if authority.doc.CurrentFence == nil || authority.doc.CurrentFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.WriterGeneration != authority.doc.WriterGeneration || fence.Body.AuthorityID != authority.doc.AuthorityID ||
		!now.UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("writer fence is not the current owner lease")
	}
	// Currentness is about the exact authority-issued lease, not merely a
	// generation number. This also rejects a stale/corrupt envelope that happens
	// to reuse the current generation or lease ID with another instance, scope,
	// validity bound, or proof.
	wanted, wantedErr := commerce.WriterFenceDigest(*authority.doc.CurrentFence)
	got, gotErr := commerce.WriterFenceDigest(fence)
	if wantedErr != nil || gotErr != nil || got != wanted {
		return errors.New("writer fence is not the current owner lease")
	}
	return nil
}

// AdmitRelaySideEffects atomically checks the current writer high-water and
// persists the one recoverable receipt that authorizes the exact Provider
// route. Receipt issuance is the linearization point; a later takeover cannot
// revoke already-admitted stages, while a stale writer can never mint a new
// receipt after takeover.
func (authority *PersonalAuthority) admitRelaySideEffects(ctx context.Context,
	descriptor agentrelay.RelaySideEffectAdmissionDescriptor) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if authority == nil || ctx == nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || descriptor.OwnerID != authority.doc.OwnerID ||
		descriptor.AgentID != authority.doc.AgentID || descriptor.WriterFence.Body.AuthorityID != authority.doc.AuthorityID ||
		descriptor.WriterFence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		descriptor.WriterFence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("stale writer cannot admit relay side effects")
	}
	wantedFence, wantedErr := commerce.WriterFenceDigest(*authority.doc.CurrentFence)
	gotFence, gotErr := commerce.WriterFenceDigest(descriptor.WriterFence)
	if wantedErr != nil || gotErr != nil || wantedFence != gotFence {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission does not carry the current writer fence")
	}
	resolver := localFenceResolver{authorityID: authority.doc.AuthorityID,
		key: authority.key.Public().(ed25519.PublicKey)}
	if err := agentrelay.ValidateRelaySideEffectAdmissionDescriptor(descriptor, resolver, now); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if descriptor.RouteAttempt > maximumRelayRouteHops {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission route attempt exceeds the V1 limit")
	}
	lookupDigest, err := agentrelay.RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if existing, found := authority.doc.RelayAdmissions[lookupDigest]; found {
		issuedAt := time.Unix(int64(existing.Body.IssuedAtUnix), 0).UTC()
		if err := agentrelay.VerifyRelaySideEffectAdmissionReceiptForDescriptor(existing, descriptor,
			agentrelay.RelayExecutionRequest{}, issuedAt); err != nil {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("stored relay admission conflicts with exact retry")
		}
		return cloneRelayAdmissionReceipt(existing), nil
	}
	if len(authority.doc.RelayAdmissions) >= maximumRelayAdmissions {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission authority capacity is exhausted")
	}
	bindingKey := relayAdmissionStableBindingKey(descriptor.OwnerID, descriptor.AgentID, descriptor.StableActionID)
	boundLookup, hasBoundRoute := authority.doc.RelayAdmissionBindings[bindingKey]
	if !hasBoundRoute {
		if descriptor.RouteAttempt != 1 || descriptor.PredecessorReceiptDigest != "" {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
		}
	} else {
		predecessor, found := authority.doc.RelayAdmissions[boundLookup]
		if !found || agentrelay.ValidateRelaySideEffectAdmissionRouteTransition(predecessor, descriptor) != nil {
			return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayConflict
		}
	}
	if authority.doc.NextRelayAdmissionSequence == 0 || authority.doc.NextRelayAdmissionSequence == ^uint64(0) ||
		now.Unix() < 0 || descriptor.StartNotAfterCapUnix <= uint64(now.Unix()) {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission sequence or start window is exhausted")
	}
	startNotAfter := uint64(now.Add(agentrelay.MaxRelayAdmissionStartDelay * time.Second).Unix())
	if descriptor.StartNotAfterCapUnix < startNotAfter {
		startNotAfter = descriptor.StartNotAfterCapUnix
	}
	body, err := agentrelay.BuildRelaySideEffectAdmissionReceiptBody(descriptor,
		authority.doc.NextRelayAdmissionSequence, uint64(now.Unix()), startNotAfter)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	receipt, err := agentrelay.SignRelaySideEffectAdmissionReceipt(body, authority.key)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	next := cloneAuthorityDocument(authority.doc)
	next.RelayAdmissions[lookupDigest] = receipt
	next.RelayAdmissionBindings[bindingKey] = lookupDigest
	next.NextRelayAdmissionSequence++
	if err := authority.persist(next); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.doc = next
	return cloneRelayAdmissionReceipt(receipt), nil
}

func (authority *PersonalAuthority) resolveRelaySideEffectAdmission(ctx context.Context,
	lookup agentrelay.RelaySideEffectAdmissionLookup) (agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	if authority == nil || ctx == nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay admission authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	lookupDigest, err := agentrelay.RelaySideEffectAdmissionLookupDigest(lookup)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if lookup.OwnerID != authority.doc.OwnerID || lookup.AgentID != authority.doc.AgentID ||
		lookup.AuthorityID != authority.doc.AuthorityID {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New("relay side-effect admission lookup is outside this authority")
	}
	receipt, found := authority.doc.RelayAdmissions[lookupDigest]
	if !found {
		// This typed result is safe because it comes from the same locked journal
		// that linearizes Admit. Callers must not translate transport failures or
		// arbitrary remote strings into ErrRelayUnknown.
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, agentrelay.ErrRelayUnknown
	}
	return cloneRelayAdmissionReceipt(receipt), nil
}

func cloneRelayAdmissionReceipt(receipt agentrelay.SignedRelaySideEffectAdmissionReceipt) agentrelay.SignedRelaySideEffectAdmissionReceipt {
	receipt.Body.StageMask = append([]agentrelay.SideEffectStage(nil), receipt.Body.StageMask...)
	return receipt
}

func relayAdmissionStableBindingKey(ownerID, agentID, stableActionID string) string {
	return ownerID + "\x00" + agentID + "\x00" + stableActionID
}

func equalRelayAdmissionBindings(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

// SignAction is the only production path that turns a deterministic action
// body into authority. Holding or observing a WriterFence is insufficient.
func (authority *PersonalAuthority) SignAction(action commerce.AuthorizedAction,
	fence commerce.WriterFence) (commerce.AuthorizedAction, error) {
	if authority == nil {
		return commerce.AuthorizedAction{}, errors.New("action authority is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := authority.ensureStorageIdentityLocked(); err != nil {
		return commerce.AuthorizedAction{}, err
	}
	now := authority.now().UTC()
	if authority.doc.CurrentFence == nil || fence.Body.WriterGeneration != authority.doc.WriterGeneration ||
		fence.Body.LeaseID != authority.doc.CurrentFence.Body.LeaseID || action.AuthorityID != authority.doc.AuthorityID ||
		action.OwnerID != authority.doc.OwnerID || action.AgentID != authority.doc.AgentID ||
		!now.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return commerce.AuthorizedAction{}, errors.New("stale writer cannot sign an action")
	}
	return commerce.SignAuthorizedAction(action, authority.key)
}

func (resolver localFenceResolver) AuthorizeFenceKey(authorityID string, publicKey ed25519.PublicKey, _ time.Time) error {
	if authorityID != resolver.authorityID || !resolver.key.Equal(publicKey) {
		return errors.New("writer fence key is not the local authority key")
	}
	return nil
}

func admitReservation(document authorityDocument, candidate ExposureReservation) error {
	if candidate.ReservationID == "" || candidate.AgreementDigest == "" || candidate.Released {
		return errors.New("portfolio reservation is invalid")
	}
	candidateBucket, err := exposureAssetBucket(candidate.Asset)
	if err != nil {
		return err
	}
	if existing, found := document.Reservations[candidate.ReservationID]; found {
		if sameJSON(existing, candidate) {
			return nil
		}
		return errors.New("portfolio reservation identity conflicts")
	}
	used, lossByAsset, err := portfolioUsage(document)
	if err != nil {
		return err
	}
	if exceeds(used.ComputeUnits, candidate.ComputeUnits, document.Limits.ComputeUnits) || exceeds(used.SpendAtomic, candidate.SpendAtomic, document.Limits.SpendAtomic) ||
		exceeds(used.LockedCapitalAtomic, candidate.LockedCapitalAtomic, document.Limits.LockedCapitalAtomic) ||
		exceeds(used.ReceivableAtomic, candidate.ReceivableAtomic, document.Limits.ReceivableAtomic) ||
		exceeds(lossByAsset[candidateBucket], candidate.MaximumLossAtomic, document.Limits.MaximumLossAtomic) {
		return errors.New("aggregate Portfolio limit would be exceeded")
	}
	return nil
}

func portfolioUsage(document authorityDocument) (PortfolioLimits, map[string]uint64, error) {
	used := PortfolioLimits{}
	if exceeds(document.ConsumedMaximumLossAtomic, document.RetainedDefaultLiabilityAtomic,
		document.Limits.MaximumLossAtomic) {
		return used, nil, errors.New("persisted legacy loss disposition exceeds its limit")
	}
	lossByAsset := map[string]uint64{"": document.ConsumedMaximumLossAtomic + document.RetainedDefaultLiabilityAtomic}
	for bucket, consumed := range document.ConsumedMaximumLossByAsset {
		retained, found := document.RetainedDefaultLiabilityByAsset[bucket]
		if !found || !canonicalSHA256(bucket) || exceeds(consumed, retained, document.Limits.MaximumLossAtomic) {
			return used, nil, errors.New("persisted asset loss disposition exceeds its limit")
		}
		lossByAsset[bucket] = consumed + retained
	}
	for _, reservation := range document.Reservations {
		if reservation.Released {
			continue
		}
		bucket, bucketErr := exposureAssetBucket(reservation.Asset)
		if bucketErr != nil || exceeds(lossByAsset[bucket], reservation.MaximumLossAtomic, document.Limits.MaximumLossAtomic) {
			return used, nil, errors.New("persisted asset Portfolio use exceeds its limit")
		}
		if exceeds(used.ComputeUnits, reservation.ComputeUnits, document.Limits.ComputeUnits) ||
			exceeds(used.SpendAtomic, reservation.SpendAtomic, document.Limits.SpendAtomic) ||
			exceeds(used.LockedCapitalAtomic, reservation.LockedCapitalAtomic, document.Limits.LockedCapitalAtomic) ||
			exceeds(used.ReceivableAtomic, reservation.ReceivableAtomic, document.Limits.ReceivableAtomic) {
			return used, nil, errors.New("persisted aggregate Portfolio use exceeds its limit")
		}
		used.ComputeUnits += reservation.ComputeUnits
		used.SpendAtomic += reservation.SpendAtomic
		used.LockedCapitalAtomic += reservation.LockedCapitalAtomic
		used.ReceivableAtomic += reservation.ReceivableAtomic
		lossByAsset[bucket] += reservation.MaximumLossAtomic
	}
	return used, lossByAsset, nil
}

func exposureAssetBucket(asset *commerce.AssetIdentityV1) (string, error) {
	if asset == nil {
		return "", nil
	}
	if commerce.ValidateAssetIdentityV1(*asset) != nil {
		return "", errors.New("portfolio exposure asset is invalid")
	}
	return codec.Digest("tos.openfox.asset-exposure-bucket.v1", *asset)
}

func exceeds(current, additional, limit uint64) bool {
	return additional > limit || current > limit-additional
}

func cloneAuthorityDocument(document authorityDocument) authorityDocument {
	raw, _ := json.Marshal(document)
	var cloned authorityDocument
	_ = json.Unmarshal(raw, &cloned)
	// Relay sponsorship admissions are omitted from an empty journal on disk.
	// Keep the transactional clone writable without weakening that compact
	// representation or relying on every caller to initialize the index.
	if cloned.RelaySponsorshipPayments == nil {
		cloned.RelaySponsorshipPayments = make(map[string]relaySponsorshipPaymentAdmission)
	}
	if cloned.IssuedCustodyPayments == nil {
		cloned.IssuedCustodyPayments = make(map[string]issuedCustodyPaymentAuthorization)
	}
	return cloned
}

func clonePortfolioLimits(limits PortfolioLimits) PortfolioLimits {
	cloned := limits
	if limits.CustodyNativeAsset != nil {
		asset := *limits.CustodyNativeAsset
		cloned.CustodyNativeAsset = &asset
	}
	return cloned
}

func cloneExposureReservation(reservation ExposureReservation) ExposureReservation {
	cloned := reservation
	if reservation.Asset != nil {
		asset := *reservation.Asset
		cloned.Asset = &asset
	}
	return cloned
}

func cloneAgreementBody(body commerce.AgentAgreementBody) (commerce.AgentAgreementBody, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	var cloned commerce.AgentAgreementBody
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return commerce.AgentAgreementBody{}, err
	}
	return cloned, nil
}

func cloneAgreementEvidence(evidence commerce.AgreementAuthorizationEvidence) (commerce.AgreementAuthorizationEvidence, error) {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return commerce.AgreementAuthorizationEvidence{}, err
	}
	var cloned commerce.AgreementAuthorizationEvidence
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return commerce.AgreementAuthorizationEvidence{}, err
	}
	return cloned, nil
}

func cloneEngagementRecord(record EngagementRecord) (EngagementRecord, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return EngagementRecord{}, err
	}
	var cloned EngagementRecord
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return EngagementRecord{}, err
	}
	return cloned, nil
}

// detachedEngagementRecord is used only for statically JSON-serializable
// journal records after their invariants have already been checked. Keep the
// error-returning clone at ingress; public read/results fail closed to a zero
// record if the representation ever stops being serializable.
func detachedEngagementRecord(record EngagementRecord) EngagementRecord {
	cloned, err := cloneEngagementRecord(record)
	if err != nil {
		return EngagementRecord{}
	}
	return cloned
}

func detachedSettlementLedgerRecord(record SettlementLedgerRecord) SettlementLedgerRecord {
	raw, err := json.Marshal(record)
	if err != nil {
		return SettlementLedgerRecord{}
	}
	var cloned SettlementLedgerRecord
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return SettlementLedgerRecord{}
	}
	return cloned
}

func detachedCustodyAuthorization(authorization commerce.CustodyActionAuthorization) commerce.CustodyActionAuthorization {
	cloned := authorization
	if authorization.NetworkDomain != nil {
		domain := *authorization.NetworkDomain
		cloned.NetworkDomain = &domain
	}
	return cloned
}

func detachedAgreementPaymentRequest(payment commerce.AgreementPaymentRequest) commerce.AgreementPaymentRequest {
	raw, err := json.Marshal(payment)
	if err != nil {
		return commerce.AgreementPaymentRequest{}
	}
	var cloned commerce.AgreementPaymentRequest
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return commerce.AgreementPaymentRequest{}
	}
	return cloned
}

func detachedIssuedCustodyPayment(issued issuedCustodyPaymentAuthorization) issuedCustodyPaymentAuthorization {
	raw, err := json.Marshal(issued)
	if err != nil {
		return issuedCustodyPaymentAuthorization{}
	}
	var cloned issuedCustodyPaymentAuthorization
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return issuedCustodyPaymentAuthorization{}
	}
	return cloned
}

func detachedRelaySponsorshipPayment(admission relaySponsorshipPaymentAdmission) relaySponsorshipPaymentAdmission {
	raw, err := json.Marshal(admission)
	if err != nil {
		return relaySponsorshipPaymentAdmission{}
	}
	var cloned relaySponsorshipPaymentAdmission
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return relaySponsorshipPaymentAdmission{}
	}
	return cloned
}

func cloneRelaySponsorshipPurpose(purpose RelaySponsorshipCustodyPurpose) (RelaySponsorshipCustodyPurpose, error) {
	raw, err := json.Marshal(purpose)
	if err != nil {
		return RelaySponsorshipCustodyPurpose{}, err
	}
	var cloned RelaySponsorshipCustodyPurpose
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return RelaySponsorshipCustodyPurpose{}, err
	}
	return cloned, nil
}

func detachedActionResolution(resolution commerce.ActionResolution) commerce.ActionResolution {
	resolution.EvidenceRefs = append([]string(nil), resolution.EvidenceRefs...)
	return resolution
}

func exactRetainedAgreementBody(record EngagementRecord) bool {
	digest, err := commerce.AgreementBodyDigest(record.Agreement.Body)
	return err == nil && digest == record.AgreementDigest
}

type retainedAgreementAuthorizationSet struct {
	AgreementBodyDigest string                                    `json:"agreement_body_digest"`
	Evidence            []commerce.AgreementAuthorizationEvidence `json:"evidence"`
}

func retainedAgreementAuthorizationSetDigest(record EngagementRecord) (string, error) {
	if !exactRetainedAgreementBody(record) {
		return "", errors.New("Agreement body no longer matches its retained digest")
	}
	return codec.Digest("tos.openfox.agreement-authorization-evidence-set.v1", retainedAgreementAuthorizationSet{
		AgreementBodyDigest: record.AgreementDigest,
		Evidence:            record.Agreement.AuthorizationEvidence,
	})
}

// retainedAgreementFullyAuthorized is deliberately verifier-free: only the
// locked RecordAgreementEvidence path can create its marker, after running the
// configured verifier. This check rebinds that decision to the current exact
// bytes and independently proves complete predicate coverage plus a local
// Agent signature.
func retainedAgreementFullyAuthorized(record EngagementRecord, localAgentID string) bool {
	if localAgentID == "" || !canonicalSHA256(record.FullyAuthorizedEvidenceSetDigest) ||
		!exactRetainedAgreementBody(record) {
		return false
	}
	digest, err := retainedAgreementAuthorizationSetDigest(record)
	if err != nil || digest != record.FullyAuthorizedEvidenceSetDigest {
		return false
	}
	covered := make(map[string]bool, len(record.Agreement.Body.AuthorizationPredicates))
	localAgentSignature := false
	for _, evidence := range record.Agreement.AuthorizationEvidence {
		if evidence.AgreementID != record.Agreement.Body.AgreementID ||
			evidence.AgreementVersion != record.Agreement.Body.Version ||
			evidence.AgreementBodyDigest != record.AgreementDigest ||
			len(evidence.PredicateIDs) == 0 || len(evidence.PredicateIDs) != len(evidence.EvidenceTargetProjectionDigests) {
			return false
		}
		for index, predicateID := range evidence.PredicateIDs {
			matched := false
			for _, predicate := range record.Agreement.Body.AuthorizationPredicates {
				if predicate.PredicateID != predicateID || predicate.AuthoritySubject != evidence.AuthoritySubject ||
					predicate.EvidenceProfileURI != evidence.EvidenceProfileURI ||
					predicate.EvidenceProfileVersion != evidence.EvidenceProfileVersion ||
					predicate.EvidenceProfileDigest != evidence.EvidenceProfileDigest ||
					predicate.EvidenceTargetProjectionDigest != evidence.EvidenceTargetProjectionDigests[index] || covered[predicateID] {
					continue
				}
				covered[predicateID] = true
				matched = true
				if evidence.EvidenceProfileURI == commerce.EvidenceProfileAgentSignature &&
					evidence.AuthoritySubject.SubjectKind == "agent" &&
					evidence.AuthoritySubject.SubjectIdentifier == localAgentID {
					localAgentSignature = true
				}
				break
			}
			if !matched {
				return false
			}
		}
	}
	return localAgentSignature && len(covered) == len(record.Agreement.Body.AuthorizationPredicates)
}

// custodyAuthorizationReleaseAfter derives the exact owner-approved horizon
// frozen into a new issuance. Ordinary Agreement holds cover every local
// outgoing obligation, so one earlier installment can never free the shared
// aggregate reservation while another signed obligation remains payable.
func custodyAuthorizationReleaseAfter(document authorityDocument,
	issued issuedCustodyPaymentAuthorization) (uint64, error) {
	grace := issued.FinalityGraceSeconds
	if grace == 0 {
		return 0, nil
	}
	horizon := issued.Payment.ExpiresAtUnix
	if issued.Authorization.ExpiresAtUnix > horizon {
		horizon = issued.Authorization.ExpiresAtUnix
	}
	if issued.SponsorshipAdmissionID == "" {
		engagement, found := document.Engagements[issued.Payment.AgreementBodyDigest]
		if !found || !exactRetainedAgreementBody(engagement) || engagement.ReservationID != issued.ReservationID {
			return 0, errors.New("custody authorization lost its exact Agreement horizon")
		}
		foundOutgoing := false
		for _, obligation := range engagement.Agreement.Body.Obligations {
			if obligation.Amount == nil || obligation.ObligorAgentID != document.AgentID {
				continue
			}
			foundOutgoing = true
			expires := obligation.ExpiresAtUnix
			if obligation.BillingTerms != nil && obligation.BillingTerms.BillingKind == "periodic" &&
				(expires == 0 || expires > obligation.BillingTerms.RecurrenceEndUnix) {
				expires = obligation.BillingTerms.RecurrenceEndUnix
			}
			if expires == 0 {
				expires = engagement.Agreement.Body.ExpiresAtUnix
			}
			if expires > horizon {
				horizon = expires
			}
		}
		if !foundOutgoing {
			return 0, errors.New("custody authorization Agreement has no local outgoing horizon")
		}
	}
	if horizon == 0 || horizon > ^uint64(0)-grace {
		return 0, errors.New("custody authorization release horizon overflows")
	}
	return horizon + grace, nil
}

// expireIssuedCustodyLocked is the only evidence-free release path for an
// offline native custody bearer. It relies solely on the frozen owner policy
// and all signed payable horizons; caller-provided settlement outcomes cannot
// accelerate it. The caller holds authority.mu (or is opening the authority
// before publication).
func (authority *PersonalAuthority) expireIssuedCustodyLocked() error {
	if len(authority.doc.IssuedCustodyPayments) == 0 {
		return nil
	}
	nowUnix := authority.now().UTC().Unix()
	if nowUnix < 0 {
		return errors.New("authority time cannot expire custody authorizations")
	}
	next := cloneAuthorityDocument(authority.doc)
	changed := false
	for paymentDigest, issued := range authority.doc.IssuedCustodyPayments {
		// Missing/legacy policy fields are deliberately permanent holds. They
		// cannot be upgraded in place from an operator's new, shorter opinion.
		if issued.FinalityGraceSeconds == 0 || issued.ReleaseAfterUnix == 0 {
			continue
		}
		recomputed, err := custodyAuthorizationReleaseAfter(authority.doc, issued)
		if err != nil || recomputed != issued.ReleaseAfterUnix {
			return errors.New("custody authorization has an invalid frozen release horizon")
		}
		if uint64(nowUnix) < issued.ReleaseAfterUnix {
			continue
		}
		reservation, found := next.Reservations[issued.ReservationID]
		if !found || reservation.Released {
			return errors.New("expired custody authorization lost its exact live hold")
		}
		reservation.Released = true
		next.Reservations[reservation.ReservationID] = reservation
		next.PortfolioRevision++
		if issued.SponsorshipAdmissionID != "" {
			admission, found := next.RelaySponsorshipPayments[issued.SponsorshipAdmissionID]
			if !found || admission.Reservation.ReservationID != issued.ReservationID ||
				admission.ExpiredCustodyAuthorization != nil {
				return errors.New("expired sponsorship custody authorization lost its admission")
			}
			admission.CustodyAuthorizationExpiredAtUnix = uint64(nowUnix)
			admission.ExpiredCustodyAuthorization = &expiredCustodyAuthorization{
				Issuance: issued, ExpiredAtUnix: uint64(nowUnix)}
			next.RelaySponsorshipPayments[issued.SponsorshipAdmissionID] = admission
		} else {
			engagement, found := next.Engagements[issued.Payment.AgreementBodyDigest]
			if !found || engagement.ReservationID != issued.ReservationID ||
				engagement.ExpiredCustodyAuthorization != nil {
				return errors.New("expired Agreement custody authorization lost its Engagement")
			}
			engagement.CustodyAuthorizationExpiredAtUnix = uint64(nowUnix)
			engagement.ExpiredCustodyAuthorization = &expiredCustodyAuthorization{
				Issuance: issued, ExpiredAtUnix: uint64(nowUnix)}
			if engagement.State == EngagementSettling {
				engagement.State = EngagementUnpaid
			} else if engagement.State != EngagementSettled && engagement.State != EngagementUnpaid &&
				engagement.State != EngagementCancelled && engagement.State != EngagementFailed {
				return errors.New("expired Agreement custody authorization has a non-terminal lifecycle")
			}
			engagement.StateRevision++
			engagement.LastTransitionAtUnix = uint64(nowUnix)
			next.Engagements[engagement.AgreementDigest] = engagement
		}
		delete(next.IssuedCustodyPayments, paymentDigest)
		changed = true
	}
	if !changed {
		return nil
	}
	if err := authority.persist(next); err != nil {
		return err
	}
	authority.doc = next
	return nil
}

func recordAuthorizedAction(document *authorityDocument, action commerce.AuthorizedAction) {
	if document.AuthorizedActions == nil {
		document.AuthorizedActions = make(map[string]commerce.AuthorizedAction)
	}
	document.AuthorizedActions[action.StableActionID] = action
}

func randomIdentifier(prefix string) (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}
