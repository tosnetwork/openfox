package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const sharedAuthorityMaximumRequestBytes = 8 << 20

type SharedAuthorityClientGrant struct {
	OwnerID    string
	AgentID    string
	InstanceID string
	Scopes     []string
}

// SharedAuthorityServer exposes one PersonalAuthority as a mutually
// authenticated owner control plane. The backing authority remains the only
// signing and linearization boundary; clients receive neither its key nor a
// writable copy of its journal.
type SharedAuthorityServer struct {
	Backing          *PersonalAuthority
	EvidenceVerifier commerce.AgreementEvidenceVerifier
	ClientsBySPKI    map[string]SharedAuthorityClientGrant
}

type sharedAuthorityEnvelope struct {
	Operation string          `json:"operation"`
	Body      json.RawMessage `json:"body"`
}

type sharedAuthorityResult struct {
	Body  json.RawMessage `json:"body,omitempty"`
	Error string          `json:"error,omitempty"`
}

func SharedAuthorityClientSPKI(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", errors.New("client certificate is unavailable")
	}
	parsed, err := cert.Leaf, error(nil)
	if parsed == nil {
		parsed, err = parseCertificate(cert.Certificate[0])
	}
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// parseCertificate is separated to keep the TLS identity computation shared
// by configured and live certificates.
func parseCertificate(raw []byte) (*x509.Certificate, error) { return x509.ParseCertificate(raw) }

func (server *SharedAuthorityServer) Handler() http.Handler {
	return http.HandlerFunc(server.serveHTTP)
}

func (server *SharedAuthorityServer) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	if server == nil || server.Backing == nil || request.Method != http.MethodPost || request.URL.Path != "/v1/economic-authority" {
		writeSharedAuthorityError(writer, http.StatusNotFound, "authority endpoint is unavailable")
		return
	}
	grant, err := server.authorizeClient(request)
	if err != nil {
		writeSharedAuthorityError(writer, http.StatusUnauthorized, err.Error())
		return
	}
	limited := http.MaxBytesReader(writer, request.Body, sharedAuthorityMaximumRequestBytes)
	defer limited.Close()
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var envelope sharedAuthorityEnvelope
	if decoder.Decode(&envelope) != nil || envelope.Operation == "" || len(envelope.Body) == 0 {
		writeSharedAuthorityError(writer, http.StatusBadRequest, "authority request is invalid")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		writeSharedAuthorityError(writer, http.StatusBadRequest, "authority request has trailing bytes")
		return
	}
	result, err := server.dispatch(request.Context(), grant, envelope.Operation, envelope.Body)
	if err != nil {
		writeSharedAuthorityError(writer, http.StatusConflict, err.Error())
		return
	}
	raw, err := json.Marshal(result)
	if err != nil {
		writeSharedAuthorityError(writer, http.StatusInternalServerError, "authority response encoding failed")
		return
	}
	_ = json.NewEncoder(writer).Encode(sharedAuthorityResult{Body: raw})
}

func (server *SharedAuthorityServer) authorizeClient(request *http.Request) (SharedAuthorityClientGrant, error) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.VerifiedChains) == 0 {
		return SharedAuthorityClientGrant{}, errors.New("mutually authenticated TLS is required")
	}
	digest := sha256.Sum256(request.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	grant, found := server.ClientsBySPKI["sha256:"+hex.EncodeToString(digest[:])]
	if !found || grant.OwnerID == "" || grant.AgentID == "" || grant.InstanceID == "" {
		return SharedAuthorityClientGrant{}, errors.New("client certificate has no owner grant")
	}
	return grant, nil
}

func writeSharedAuthorityError(writer http.ResponseWriter, status int, message string) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(sharedAuthorityResult{Error: message})
}

func decodeSharedBody(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errors.New("authority operation body is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("authority operation body has trailing values")
	}
	return nil
}

func (server *SharedAuthorityServer) dispatch(ctx context.Context, grant SharedAuthorityClientGrant, operation string, raw json.RawMessage) (any, error) {
	backing := server.Backing
	validateFence := func(fence commerce.WriterFence) error {
		if fence.Body.OwnerID != grant.OwnerID || fence.Body.AgentID != grant.AgentID || fence.Body.InstanceID != grant.InstanceID {
			return errors.New("writer fence is outside the client grant")
		}
		return nil
	}
	switch operation {
	case "acquire-writer":
		var input struct {
			InstanceID     string   `json:"instance_id"`
			Scope          []string `json:"scope"`
			TTLNanoseconds int64    `json:"ttl_nanoseconds"`
		}
		if decodeSharedBody(raw, &input) != nil || input.InstanceID != grant.InstanceID || !scopeSubset(input.Scope, grant.Scopes) {
			return nil, errors.New("writer request exceeds the client grant")
		}
		return backing.AcquireWriter(ctx, input.InstanceID, input.Scope, time.Duration(input.TTLNanoseconds))
	case "admit":
		var input struct {
			Action      commerce.AuthorizedAction     `json:"action"`
			Fields      []commerce.SemanticFieldValue `json:"fields"`
			Request     []byte                        `json:"request"`
			Fence       commerce.WriterFence          `json:"fence"`
			Reservation *ExposureReservation          `json:"reservation,omitempty"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		return backing.Admit(input.Action, fields, input.Request, input.Fence, input.Reservation)
	case "resolve":
		var input struct {
			StableActionID string `json:"stable_action_id"`
			RequestDigest  string `json:"request_digest"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.Resolve(input.StableActionID, input.RequestDigest), nil
	case "transition":
		var input struct {
			StableActionID string                         `json:"stable_action_id"`
			RequestDigest  string                         `json:"request_digest"`
			State          commerce.ActionResolutionState `json:"state"`
			SinkReference  string                         `json:"sink_reference"`
			Evidence       []string                       `json:"evidence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.Transition(input.StableActionID, input.RequestDigest, input.State, input.SinkReference, input.Evidence)
	case "allocate-instance":
		var input struct {
			Request commerce.AuthorityInstanceAllocationRequest `json:"request"`
			Fence   commerce.WriterFence                        `json:"fence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		return backing.AllocateInstance(input.Request, input.Fence)
	case "snapshot":
		revision, limits, reservations := backing.Snapshot()
		return struct {
			Revision     uint64                `json:"revision"`
			Limits       PortfolioLimits       `json:"limits"`
			Reservations []ExposureReservation `json:"reservations"`
		}{revision, limits, reservations}, nil
	case "release-reservation":
		var input struct {
			Action  commerce.AuthorizedAction     `json:"action"`
			Fields  []commerce.SemanticFieldValue `json:"fields"`
			Request []byte                        `json:"request"`
			Fence   commerce.WriterFence          `json:"fence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		return backing.ReleaseReservation(input.Action, fields, input.Request, input.Fence)
	case "confirm-fence":
		var input struct {
			Fence      commerce.WriterFence `json:"fence"`
			AtUnixNano int64                `json:"at_unix_nano"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		return struct{}{}, backing.ConfirmCurrentWriterFence(input.Fence, time.Unix(0, input.AtUnixNano).UTC())
	case "now":
		return struct {
			UnixNano int64 `json:"unix_nano"`
		}{backing.AuthorityNow().UnixNano()}, nil
	case "sign-action":
		var input struct {
			Action commerce.AuthorizedAction `json:"action"`
			Fence  commerce.WriterFence      `json:"fence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		return backing.SignAction(input.Action, input.Fence)
	case "authorize-custody":
		var input struct {
			Action          commerce.AuthorizedAction        `json:"action"`
			Fields          []commerce.SemanticFieldValue    `json:"fields"`
			Request         []byte                           `json:"request"`
			Fence           commerce.WriterFence             `json:"fence"`
			Payment         commerce.AgreementPaymentRequest `json:"payment"`
			SourceAccount   string                           `json:"source_account"`
			NetworkGlobalID int32                            `json:"network_global_id"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		return backing.AuthorizeCustodyPayment(input.Action, fields, input.Request, input.Fence, input.Payment, input.SourceAccount, input.NetworkGlobalID)
	case "authorize-custody-effect":
		var input struct {
			Action   commerce.AuthorizedAction           `json:"action"`
			Fields   []commerce.SemanticFieldValue       `json:"fields"`
			Request  []byte                              `json:"request"`
			Fence    commerce.WriterFence                `json:"fence"`
			Template commerce.CustodyEffectAuthorization `json:"template"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		return backing.AuthorizeCustodyEffect(input.Action, fields, input.Request, input.Fence, input.Template)
	case "record-proposal":
		var input struct {
			Body             commerce.AgentAgreementBody `json:"body"`
			ProposerAgentID  string                      `json:"proposer_agent_id"`
			EventID          string                      `json:"event_id"`
			ProposalActionID string                      `json:"proposal_action_id"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.RecordAgreementProposal(input.Body, input.ProposerAgentID, input.EventID, input.ProposalActionID)
	case "observe-withdrawal":
		var input struct {
			AgreementDigest  string `json:"agreement_digest"`
			ProposalActionID string `json:"proposal_action_id"`
			SenderAgentID    string `json:"sender_agent_id"`
			EventID          string `json:"event_id"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.ObserveAgreementWithdrawal(input.AgreementDigest, input.ProposalActionID, input.SenderAgentID, input.EventID)
	case "observe-delivery":
		var input struct {
			AgreementDigest string `json:"agreement_digest"`
			ObligationID    string `json:"obligation_id"`
			ManifestDigest  string `json:"manifest_digest"`
			SenderAgentID   string `json:"sender_agent_id"`
			EventID         string `json:"event_id"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.ObserveAgreementDelivery(input.AgreementDigest, input.ObligationID, input.ManifestDigest, input.SenderAgentID, input.EventID)
	case "record-evidence":
		if server.EvidenceVerifier == nil {
			return nil, errors.New("shared authority has no Agreement evidence verifier")
		}
		var input struct {
			AgreementDigest string                                  `json:"agreement_digest"`
			Evidence        commerce.AgreementAuthorizationEvidence `json:"evidence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.RecordAgreementEvidence(input.AgreementDigest, input.Evidence, server.EvidenceVerifier)
	case "reserve":
		var input struct {
			Action      commerce.AuthorizedAction     `json:"action"`
			Fields      []commerce.SemanticFieldValue `json:"fields"`
			Request     []byte                        `json:"request"`
			Fence       commerce.WriterFence          `json:"fence"`
			Reservation PortfolioReservationRequest   `json:"reservation"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		resolution, engagement, err := backing.ReserveEngagement(input.Action, fields, input.Request, input.Fence, input.Reservation)
		return struct {
			Resolution commerce.ActionResolution `json:"resolution"`
			Engagement EngagementRecord          `json:"engagement"`
		}{resolution, engagement}, err
	case "engagement":
		var input struct {
			AgreementDigest string `json:"agreement_digest"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		record, found := backing.Engagement(input.AgreementDigest)
		return struct {
			Record EngagementRecord `json:"record"`
			Found  bool             `json:"found"`
		}{record, found}, nil
	case "engagement-snapshot":
		return backing.EngagementSnapshot(), nil
	case "bind-private-input":
		var input struct {
			AgreementDigest string                                `json:"agreement_digest"`
			ObligationID    string                                `json:"obligation_id"`
			Accepted        commerce.AcceptedPrivateContentRecord `json:"accepted"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.BindAcceptedPrivateInput(input.AgreementDigest, input.ObligationID, input.Accepted)
	case "record-private-challenge":
		var input struct {
			AgreementDigest string `json:"agreement_digest"`
			ObligationID    string `json:"obligation_id"`
			ChallengeDigest string `json:"challenge_digest"`
			SendActionID    string `json:"send_action_id"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.RecordPrivateHandoffChallenge(input.AgreementDigest, input.ObligationID, input.ChallengeDigest, input.SendActionID)
	case "transition-engagement":
		var input struct {
			AgreementDigest string          `json:"agreement_digest"`
			Expected        EngagementState `json:"expected"`
			Target          EngagementState `json:"target"`
			ExecutionID     string          `json:"execution_id"`
			Evidence        []string        `json:"evidence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.transitionEngagement(input.AgreementDigest, input.Expected, input.Target, input.ExecutionID, input.Evidence)
	case "transition-obligation":
		var input struct {
			AgreementDigest string                 `json:"agreement_digest"`
			ObligationID    string                 `json:"obligation_id"`
			Expected        ObligationRuntimeState `json:"expected"`
			Target          ObligationRuntimeState `json:"target"`
			ExecutionID     string                 `json:"execution_id"`
			Evidence        []string               `json:"evidence"`
			EventID         string                 `json:"event_id"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.transitionObligation(input.AgreementDigest, input.ObligationID, input.Expected, input.Target, input.ExecutionID, input.Evidence, input.EventID)
	case "complete-no-payment":
		var input struct {
			AgreementDigest string `json:"agreement_digest"`
			Evidence        string `json:"evidence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.completeNoPaymentEngagement(input.AgreementDigest, input.Evidence)
	case "admit-schedule":
		var input struct {
			Action  commerce.AuthorizedAction `json:"action"`
			Request []byte                    `json:"request"`
			Fence   commerce.WriterFence      `json:"fence"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		return backing.AdmitScheduleTransition(input.Action, input.Request, input.Fence)
	case "admit-dependency":
		var input struct {
			Action     commerce.AuthorizedAction     `json:"action"`
			Fields     []commerce.SemanticFieldValue `json:"fields"`
			Request    []byte                        `json:"request"`
			Fence      commerce.WriterFence          `json:"fence"`
			Transition DependencyTransitionRequest   `json:"transition"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		return backing.AdmitDependencyTransition(input.Action, fields, input.Request, input.Fence, input.Transition)
	case "schedule-snapshot":
		entries, dependencies := backing.ScheduleSnapshot()
		return struct {
			Entries      []commerce.EngagementScheduleEntry `json:"entries"`
			Dependencies []commerce.PortfolioDependency     `json:"dependencies"`
		}{entries, dependencies}, nil
	case "resolve-settlement":
		var input struct {
			Action     commerce.AuthorizedAction     `json:"action"`
			Fields     []commerce.SemanticFieldValue `json:"fields"`
			Request    []byte                        `json:"request"`
			Fence      commerce.WriterFence          `json:"fence"`
			Transition BillingStateTransitionRequest `json:"transition"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		resolution, ledger, engagement, err := backing.ResolveSettlementState(input.Action, fields, input.Request, input.Fence, input.Transition)
		return struct {
			Resolution commerce.ActionResolution `json:"resolution"`
			Ledger     SettlementLedgerRecord    `json:"ledger"`
			Engagement EngagementRecord          `json:"engagement"`
		}{resolution, ledger, engagement}, err
	case "materialize-settlement":
		var input struct {
			Action     commerce.AuthorizedAction     `json:"action"`
			Fields     []commerce.SemanticFieldValue `json:"fields"`
			Request    []byte                        `json:"request"`
			Fence      commerce.WriterFence          `json:"fence"`
			Obligation commerce.SettlementObligation `json:"obligation"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		resolution, ledger, err := backing.MaterializeSettlement(input.Action, fields, input.Request, input.Fence, input.Obligation)
		return struct {
			Resolution commerce.ActionResolution `json:"resolution"`
			Ledger     SettlementLedgerRecord    `json:"ledger"`
		}{resolution, ledger}, err
	case "settlement-snapshot":
		var input struct {
			AgreementDigest string `json:"agreement_digest"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		return backing.SettlementSnapshot(input.AgreementDigest), nil
	case "apply-payment":
		var input struct {
			Action     commerce.AuthorizedAction     `json:"action"`
			Fields     []commerce.SemanticFieldValue `json:"fields"`
			Request    []byte                        `json:"request"`
			Fence      commerce.WriterFence          `json:"fence"`
			Resolution BillingResolutionRequest      `json:"resolution"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		resolution, ledger, engagement, err := backing.ApplySettlementPayment(input.Action, fields, input.Request, input.Fence, input.Resolution)
		return struct {
			ActionResolution commerce.ActionResolution `json:"action_resolution"`
			Ledger           SettlementLedgerRecord    `json:"ledger"`
			Engagement       EngagementRecord          `json:"engagement"`
		}{resolution, ledger, engagement}, err
	case "record-accounting":
		var input struct {
			Action  commerce.AuthorizedAction     `json:"action"`
			Fields  []commerce.SemanticFieldValue `json:"fields"`
			Request []byte                        `json:"request"`
			Fence   commerce.WriterFence          `json:"fence"`
			Entry   AccountingEntry               `json:"entry"`
		}
		if err := decodeSharedBody(raw, &input); err != nil {
			return nil, err
		}
		if err := validateFence(input.Fence); err != nil {
			return nil, err
		}
		fields, err := commerce.ImportSemanticFields(input.Action.ActionKind, input.Fields)
		if err != nil {
			return nil, err
		}
		resolution, entry, err := backing.RecordAccounting(input.Action, fields, input.Request, input.Fence, input.Entry)
		return struct {
			Resolution commerce.ActionResolution `json:"resolution"`
			Entry      AccountingEntry           `json:"entry"`
		}{resolution, entry}, err
	case "accounting-snapshot":
		return backing.AccountingSnapshot(), nil
	case "reconciliation-snapshot":
		revision, reservations, engagements := backing.reconciliationSnapshot()
		return struct {
			Revision     uint64                      `json:"revision"`
			Reservations []ExposureReservation       `json:"reservations"`
			Engagements  map[string]EngagementRecord `json:"engagements"`
		}{revision, reservations, engagements}, nil
	default:
		return nil, errors.New("shared authority operation is unknown")
	}
}

func scopeSubset(requested, allowed []string) bool {
	allow := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		allow[scope] = true
	}
	for _, scope := range requested {
		if !allow[scope] {
			return false
		}
	}
	return len(requested) != 0
}

type SharedAuthorityClient struct {
	Endpoint      string
	HTTPClient    *http.Client
	AuthorityID   string
	AuthorityKey  ed25519.PublicKey
	LocalVerifier commerce.AgreementEvidenceVerifier
}

func NewSharedAuthorityServerTLSConfig(certificate tls.Certificate, clientRoots *x509.CertPool) (*tls.Config, error) {
	if len(certificate.Certificate) == 0 || clientRoots == nil {
		return nil, errors.New("shared authority server TLS configuration is incomplete")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, SessionTicketsDisabled: true}, nil
}

func NewSharedAuthorityHTTPClient(certificate tls.Certificate, serverRoots *x509.CertPool,
	serverName string, timeout time.Duration) (*http.Client, error) {
	if len(certificate.Certificate) == 0 || serverRoots == nil || serverName == "" || timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("shared authority client TLS configuration is incomplete or unbounded")
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableCompression: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
			RootCAs: serverRoots, ServerName: serverName, SessionTicketsDisabled: true},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("shared authority redirects are forbidden")
	}}, nil
}

func NewSharedAuthorityClient(endpoint string, client *http.Client, authorityID string,
	authorityKey ed25519.PublicKey) (*SharedAuthorityClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "/v1/economic-authority" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || client == nil || authorityID == "" || len(authorityKey) != ed25519.PublicKeySize {
		return nil, errors.New("shared authority client configuration is invalid")
	}
	return &SharedAuthorityClient{Endpoint: parsed.String(), HTTPClient: client, AuthorityID: authorityID,
		AuthorityKey: append(ed25519.PublicKey(nil), authorityKey...)}, nil
}

func (client *SharedAuthorityClient) call(ctx context.Context, operation string, input, output any) error {
	if client == nil || client.HTTPClient == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("shared authority client is unavailable")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	envelope, err := json.Marshal(sharedAuthorityEnvelope{Operation: operation, Body: body})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.Endpoint, bytes.NewReader(envelope))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, sharedAuthorityMaximumRequestBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) > sharedAuthorityMaximumRequestBytes {
		return errors.New("shared authority response is invalid or oversized")
	}
	var result sharedAuthorityResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Error != "" || response.StatusCode != http.StatusOK {
		if result.Error != "" {
			return errors.New(result.Error)
		}
		return errors.New("shared authority rejected the request")
	}
	if output == nil {
		return nil
	}
	decoder = json.NewDecoder(bytes.NewReader(result.Body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return errors.New("shared authority response body is invalid")
	}
	return nil
}

func (client *SharedAuthorityClient) AcquireWriter(ctx context.Context, instanceID string, scope []string, ttl time.Duration) (commerce.WriterFence, error) {
	var out commerce.WriterFence
	err := client.call(ctx, "acquire-writer", struct {
		InstanceID     string   `json:"instance_id"`
		Scope          []string `json:"scope"`
		TTLNanoseconds int64    `json:"ttl_nanoseconds"`
	}{instanceID, scope, int64(ttl)}, &out)
	return out, err
}
func (client *SharedAuthorityClient) Admit(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, reservation *ExposureReservation) (commerce.ActionResolution, error) {
	var out commerce.ActionResolution
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out, err
	}
	err = client.call(context.Background(), "admit", struct {
		Action      commerce.AuthorizedAction     `json:"action"`
		Fields      []commerce.SemanticFieldValue `json:"fields"`
		Request     []byte                        `json:"request"`
		Fence       commerce.WriterFence          `json:"fence"`
		Reservation *ExposureReservation          `json:"reservation,omitempty"`
	}{action, wireFields, request, fence, reservation}, &out)
	return out, err
}
func (client *SharedAuthorityClient) Resolve(id, digest string) commerce.ActionResolution {
	var out commerce.ActionResolution
	if client.call(context.Background(), "resolve", struct {
		StableActionID string `json:"stable_action_id"`
		RequestDigest  string `json:"request_digest"`
	}{id, digest}, &out) != nil {
		return commerce.ActionResolution{StableActionID: id, ExactRequestDigest: digest, State: commerce.ActionUnknown, StateRevision: 1}
	}
	return out
}
func (client *SharedAuthorityClient) Transition(id, digest string, state commerce.ActionResolutionState, reference string, evidence []string) (commerce.ActionResolution, error) {
	var out commerce.ActionResolution
	err := client.call(context.Background(), "transition", struct {
		StableActionID string                         `json:"stable_action_id"`
		RequestDigest  string                         `json:"request_digest"`
		State          commerce.ActionResolutionState `json:"state"`
		SinkReference  string                         `json:"sink_reference"`
		Evidence       []string                       `json:"evidence"`
	}{id, digest, state, reference, evidence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) AllocateInstance(request commerce.AuthorityInstanceAllocationRequest, fence commerce.WriterFence) (commerce.AuthorityInstanceRecord, error) {
	var out commerce.AuthorityInstanceRecord
	err := client.call(context.Background(), "allocate-instance", struct {
		Request commerce.AuthorityInstanceAllocationRequest `json:"request"`
		Fence   commerce.WriterFence                        `json:"fence"`
	}{request, fence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) Snapshot() (uint64, PortfolioLimits, []ExposureReservation) {
	var out struct {
		Revision     uint64                `json:"revision"`
		Limits       PortfolioLimits       `json:"limits"`
		Reservations []ExposureReservation `json:"reservations"`
	}
	if client.call(context.Background(), "snapshot", struct{}{}, &out) != nil {
		return 0, PortfolioLimits{}, nil
	}
	return out.Revision, out.Limits, out.Reservations
}
func (client *SharedAuthorityClient) ReleaseReservation(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	var out commerce.ActionResolution
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out, err
	}
	err = client.call(context.Background(), "release-reservation", struct {
		Action  commerce.AuthorizedAction     `json:"action"`
		Fields  []commerce.SemanticFieldValue `json:"fields"`
		Request []byte                        `json:"request"`
		Fence   commerce.WriterFence          `json:"fence"`
	}{action, wireFields, request, fence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) AuthorizeFenceKey(id string, key ed25519.PublicKey, _ time.Time) error {
	if id != client.AuthorityID || !client.AuthorityKey.Equal(key) {
		return errors.New("writer fence key is not the shared authority key")
	}
	return nil
}
func (client *SharedAuthorityClient) ConfirmCurrentWriterFence(fence commerce.WriterFence, now time.Time) error {
	return client.call(context.Background(), "confirm-fence", struct {
		Fence      commerce.WriterFence `json:"fence"`
		AtUnixNano int64                `json:"at_unix_nano"`
	}{fence, now.UTC().UnixNano()}, &struct{}{})
}
func (client *SharedAuthorityClient) AuthorityNow() time.Time {
	var out struct {
		UnixNano int64 `json:"unix_nano"`
	}
	if client.call(context.Background(), "now", struct{}{}, &out) != nil {
		return time.Time{}
	}
	return time.Unix(0, out.UnixNano).UTC()
}
func (client *SharedAuthorityClient) SignAction(action commerce.AuthorizedAction, fence commerce.WriterFence) (commerce.AuthorizedAction, error) {
	var out commerce.AuthorizedAction
	err := client.call(context.Background(), "sign-action", struct {
		Action commerce.AuthorizedAction `json:"action"`
		Fence  commerce.WriterFence      `json:"fence"`
	}{action, fence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) AuthorizeCustodyPayment(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, payment commerce.AgreementPaymentRequest, source string, network int32) (commerce.CustodyActionAuthorization, error) {
	var out commerce.CustodyActionAuthorization
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out, err
	}
	err = client.call(context.Background(), "authorize-custody", struct {
		Action          commerce.AuthorizedAction        `json:"action"`
		Fields          []commerce.SemanticFieldValue    `json:"fields"`
		Request         []byte                           `json:"request"`
		Fence           commerce.WriterFence             `json:"fence"`
		Payment         commerce.AgreementPaymentRequest `json:"payment"`
		SourceAccount   string                           `json:"source_account"`
		NetworkGlobalID int32                            `json:"network_global_id"`
	}{action, wireFields, request, fence, payment, source, network}, &out)
	return out, err
}
func (client *SharedAuthorityClient) AuthorizeCustodyEffect(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, template commerce.CustodyEffectAuthorization) (commerce.CustodyEffectAuthorization, error) {
	var out commerce.CustodyEffectAuthorization
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out, err
	}
	err = client.call(context.Background(), "authorize-custody-effect", struct {
		Action   commerce.AuthorizedAction           `json:"action"`
		Fields   []commerce.SemanticFieldValue       `json:"fields"`
		Request  []byte                              `json:"request"`
		Fence    commerce.WriterFence                `json:"fence"`
		Template commerce.CustodyEffectAuthorization `json:"template"`
	}{action, wireFields, request, fence, template}, &out)
	return out, err
}
func (client *SharedAuthorityClient) RecordAgreementProposal(body commerce.AgentAgreementBody, proposer, event, action string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "record-proposal", struct {
		Body             commerce.AgentAgreementBody `json:"body"`
		ProposerAgentID  string                      `json:"proposer_agent_id"`
		EventID          string                      `json:"event_id"`
		ProposalActionID string                      `json:"proposal_action_id"`
	}{body, proposer, event, action}, &out)
	return out, err
}
func (client *SharedAuthorityClient) ObserveAgreementWithdrawal(digest, action, sender, event string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "observe-withdrawal", struct {
		AgreementDigest  string `json:"agreement_digest"`
		ProposalActionID string `json:"proposal_action_id"`
		SenderAgentID    string `json:"sender_agent_id"`
		EventID          string `json:"event_id"`
	}{digest, action, sender, event}, &out)
	return out, err
}
func (client *SharedAuthorityClient) ObserveAgreementDelivery(digest, obligation, manifest, sender, event string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "observe-delivery", struct {
		AgreementDigest string `json:"agreement_digest"`
		ObligationID    string `json:"obligation_id"`
		ManifestDigest  string `json:"manifest_digest"`
		SenderAgentID   string `json:"sender_agent_id"`
		EventID         string `json:"event_id"`
	}{digest, obligation, manifest, sender, event}, &out)
	return out, err
}
func (client *SharedAuthorityClient) RecordAgreementEvidence(digest string, evidence commerce.AgreementAuthorizationEvidence, verifier commerce.AgreementEvidenceVerifier) (EngagementRecord, error) {
	if verifier == nil {
		return EngagementRecord{}, errors.New("Agreement evidence verifier is unavailable")
	}
	record, found := client.Engagement(digest)
	if !found {
		return EngagementRecord{}, errors.New("Agreement is absent")
	}
	candidate := record.Agreement
	candidate.AuthorizationEvidence = append(candidate.AuthorizationEvidence, evidence)
	sort.Slice(candidate.AuthorizationEvidence, func(i, j int) bool {
		leftEvidence, rightEvidence := candidate.AuthorizationEvidence[i], candidate.AuthorizationEvidence[j]
		left, right := leftEvidence.AuthoritySubject, rightEvidence.AuthoritySubject
		leftKey := left.SubjectKind + "\x00" + left.SubjectNamespace + "\x00" + left.SubjectIdentifier + "\x00" + left.RepresentedAgentID
		rightKey := right.SubjectKind + "\x00" + right.SubjectNamespace + "\x00" + right.SubjectIdentifier + "\x00" + right.RepresentedAgentID
		leftKey += "\x00" + leftEvidence.EvidenceProfileURI
		rightKey += "\x00" + rightEvidence.EvidenceProfileURI
		return leftKey < rightKey
	})
	if err := commerce.ValidatePartialAgreementAuthorization(candidate, verifier, client.AuthorityNow()); err != nil {
		return EngagementRecord{}, err
	}
	var out EngagementRecord
	err := client.call(context.Background(), "record-evidence", struct {
		AgreementDigest string                                  `json:"agreement_digest"`
		Evidence        commerce.AgreementAuthorizationEvidence `json:"evidence"`
	}{digest, evidence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) ReserveEngagement(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, reservation PortfolioReservationRequest) (commerce.ActionResolution, EngagementRecord, error) {
	var out struct {
		Resolution commerce.ActionResolution `json:"resolution"`
		Engagement EngagementRecord          `json:"engagement"`
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out.Resolution, out.Engagement, err
	}
	err = client.call(context.Background(), "reserve", struct {
		Action      commerce.AuthorizedAction     `json:"action"`
		Fields      []commerce.SemanticFieldValue `json:"fields"`
		Request     []byte                        `json:"request"`
		Fence       commerce.WriterFence          `json:"fence"`
		Reservation PortfolioReservationRequest   `json:"reservation"`
	}{action, wireFields, request, fence, reservation}, &out)
	return out.Resolution, out.Engagement, err
}
func (client *SharedAuthorityClient) Engagement(digest string) (EngagementRecord, bool) {
	var out struct {
		Record EngagementRecord `json:"record"`
		Found  bool             `json:"found"`
	}
	if client.call(context.Background(), "engagement", struct {
		AgreementDigest string `json:"agreement_digest"`
	}{digest}, &out) != nil {
		return EngagementRecord{}, false
	}
	return out.Record, out.Found
}
func (client *SharedAuthorityClient) EngagementSnapshot() []EngagementRecord {
	var out []EngagementRecord
	if client.call(context.Background(), "engagement-snapshot", struct{}{}, &out) != nil {
		return nil
	}
	return out
}
func (client *SharedAuthorityClient) BindAcceptedPrivateInput(digest, obligation string, accepted commerce.AcceptedPrivateContentRecord) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "bind-private-input", struct {
		AgreementDigest string                                `json:"agreement_digest"`
		ObligationID    string                                `json:"obligation_id"`
		Accepted        commerce.AcceptedPrivateContentRecord `json:"accepted"`
	}{digest, obligation, accepted}, &out)
	return out, err
}

func (client *SharedAuthorityClient) RecordPrivateHandoffChallenge(digest, obligation, challengeDigest,
	sendActionID string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "record-private-challenge", struct {
		AgreementDigest string `json:"agreement_digest"`
		ObligationID    string `json:"obligation_id"`
		ChallengeDigest string `json:"challenge_digest"`
		SendActionID    string `json:"send_action_id"`
	}{digest, obligation, challengeDigest, sendActionID}, &out)
	return out, err
}
func (client *SharedAuthorityClient) transitionEngagement(digest string, expected, target EngagementState, execution string, evidence []string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "transition-engagement", struct {
		AgreementDigest string          `json:"agreement_digest"`
		Expected        EngagementState `json:"expected"`
		Target          EngagementState `json:"target"`
		ExecutionID     string          `json:"execution_id"`
		Evidence        []string        `json:"evidence"`
	}{digest, expected, target, execution, evidence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) transitionObligation(digest, obligation string, expected, target ObligationRuntimeState, execution string, evidence []string, event string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "transition-obligation", struct {
		AgreementDigest string                 `json:"agreement_digest"`
		ObligationID    string                 `json:"obligation_id"`
		Expected        ObligationRuntimeState `json:"expected"`
		Target          ObligationRuntimeState `json:"target"`
		ExecutionID     string                 `json:"execution_id"`
		Evidence        []string               `json:"evidence"`
		EventID         string                 `json:"event_id"`
	}{digest, obligation, expected, target, execution, evidence, event}, &out)
	return out, err
}
func (client *SharedAuthorityClient) completeNoPaymentEngagement(digest, evidence string) (EngagementRecord, error) {
	var out EngagementRecord
	err := client.call(context.Background(), "complete-no-payment", struct {
		AgreementDigest string `json:"agreement_digest"`
		Evidence        string `json:"evidence"`
	}{digest, evidence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) AdmitScheduleTransition(action commerce.AuthorizedAction, request []byte, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	var out commerce.ActionResolution
	err := client.call(context.Background(), "admit-schedule", struct {
		Action  commerce.AuthorizedAction `json:"action"`
		Request []byte                    `json:"request"`
		Fence   commerce.WriterFence      `json:"fence"`
	}{action, request, fence}, &out)
	return out, err
}
func (client *SharedAuthorityClient) AdmitDependencyTransition(action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence,
	transition DependencyTransitionRequest) (commerce.ActionResolution, error) {
	var out commerce.ActionResolution
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out, err
	}
	err = client.call(context.Background(), "admit-dependency", struct {
		Action     commerce.AuthorizedAction     `json:"action"`
		Fields     []commerce.SemanticFieldValue `json:"fields"`
		Request    []byte                        `json:"request"`
		Fence      commerce.WriterFence          `json:"fence"`
		Transition DependencyTransitionRequest   `json:"transition"`
	}{action, wireFields, request, fence, transition}, &out)
	return out, err
}
func (client *SharedAuthorityClient) ScheduleSnapshot() ([]commerce.EngagementScheduleEntry, []commerce.PortfolioDependency) {
	var out struct {
		Entries      []commerce.EngagementScheduleEntry `json:"entries"`
		Dependencies []commerce.PortfolioDependency     `json:"dependencies"`
	}
	if client.call(context.Background(), "schedule-snapshot", struct{}{}, &out) != nil {
		return nil, nil
	}
	return out.Entries, out.Dependencies
}
func (client *SharedAuthorityClient) ResolveSettlementState(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, transition BillingStateTransitionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error) {
	var out struct {
		Resolution commerce.ActionResolution `json:"resolution"`
		Ledger     SettlementLedgerRecord    `json:"ledger"`
		Engagement EngagementRecord          `json:"engagement"`
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out.Resolution, out.Ledger, out.Engagement, err
	}
	err = client.call(context.Background(), "resolve-settlement", struct {
		Action     commerce.AuthorizedAction     `json:"action"`
		Fields     []commerce.SemanticFieldValue `json:"fields"`
		Request    []byte                        `json:"request"`
		Fence      commerce.WriterFence          `json:"fence"`
		Transition BillingStateTransitionRequest `json:"transition"`
	}{action, wireFields, request, fence, transition}, &out)
	return out.Resolution, out.Ledger, out.Engagement, err
}
func (client *SharedAuthorityClient) MaterializeSettlement(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, obligation commerce.SettlementObligation) (commerce.ActionResolution, SettlementLedgerRecord, error) {
	var out struct {
		Resolution commerce.ActionResolution `json:"resolution"`
		Ledger     SettlementLedgerRecord    `json:"ledger"`
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out.Resolution, out.Ledger, err
	}
	err = client.call(context.Background(), "materialize-settlement", struct {
		Action     commerce.AuthorizedAction     `json:"action"`
		Fields     []commerce.SemanticFieldValue `json:"fields"`
		Request    []byte                        `json:"request"`
		Fence      commerce.WriterFence          `json:"fence"`
		Obligation commerce.SettlementObligation `json:"obligation"`
	}{action, wireFields, request, fence, obligation}, &out)
	return out.Resolution, out.Ledger, err
}
func (client *SharedAuthorityClient) SettlementSnapshot(digest string) []SettlementLedgerRecord {
	var out []SettlementLedgerRecord
	if client.call(context.Background(), "settlement-snapshot", struct {
		AgreementDigest string `json:"agreement_digest"`
	}{digest}, &out) != nil {
		return nil
	}
	return out
}
func (client *SharedAuthorityClient) ApplySettlementPayment(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue, request []byte, fence commerce.WriterFence, resolution BillingResolutionRequest) (commerce.ActionResolution, SettlementLedgerRecord, EngagementRecord, error) {
	var out struct {
		ActionResolution commerce.ActionResolution `json:"action_resolution"`
		Ledger           SettlementLedgerRecord    `json:"ledger"`
		Engagement       EngagementRecord          `json:"engagement"`
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out.ActionResolution, out.Ledger, out.Engagement, err
	}
	err = client.call(context.Background(), "apply-payment", struct {
		Action     commerce.AuthorizedAction     `json:"action"`
		Fields     []commerce.SemanticFieldValue `json:"fields"`
		Request    []byte                        `json:"request"`
		Fence      commerce.WriterFence          `json:"fence"`
		Resolution BillingResolutionRequest      `json:"resolution"`
	}{action, wireFields, request, fence, resolution}, &out)
	return out.ActionResolution, out.Ledger, out.Engagement, err
}
func (client *SharedAuthorityClient) RecordAccounting(action commerce.AuthorizedAction, fields map[string]commerce.SemanticValue,
	request []byte, fence commerce.WriterFence, entry AccountingEntry) (commerce.ActionResolution, AccountingEntry, error) {
	var out struct {
		Resolution commerce.ActionResolution `json:"resolution"`
		Entry      AccountingEntry           `json:"entry"`
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		return out.Resolution, out.Entry, err
	}
	err = client.call(context.Background(), "record-accounting", struct {
		Action  commerce.AuthorizedAction     `json:"action"`
		Fields  []commerce.SemanticFieldValue `json:"fields"`
		Request []byte                        `json:"request"`
		Fence   commerce.WriterFence          `json:"fence"`
		Entry   AccountingEntry               `json:"entry"`
	}{action, wireFields, request, fence, entry}, &out)
	return out.Resolution, out.Entry, err
}
func (client *SharedAuthorityClient) AccountingSnapshot() []AccountingEntry {
	var out []AccountingEntry
	if client.call(context.Background(), "accounting-snapshot", struct{}{}, &out) != nil {
		return nil
	}
	return out
}
func (client *SharedAuthorityClient) reconciliationSnapshot() (uint64, []ExposureReservation, map[string]EngagementRecord) {
	var out struct {
		Revision     uint64                      `json:"revision"`
		Reservations []ExposureReservation       `json:"reservations"`
		Engagements  map[string]EngagementRecord `json:"engagements"`
	}
	if client.call(context.Background(), "reconciliation-snapshot", struct{}{}, &out) != nil {
		return 0, nil, nil
	}
	return out.Revision, out.Reservations, out.Engagements
}

var _ EconomicAuthority = (*SharedAuthorityClient)(nil)
