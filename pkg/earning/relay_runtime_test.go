package earning

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

func TestRelayClientRuntimeRequiresExplicitEnableMTLSAndDurableJournal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	ca, caKey, _ := issueTestCertificate(t, nil, nil, "relay-ca", true, nil, now)
	server, _, _ := issueTestCertificate(t, ca, caKey, "relay.example", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	clientLeaf, _, clientCertificate := issueTestCertificate(t, ca, caKey, "relay-client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	directory := filepath.Join(t.TempDir(), "attempts")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := RelayClientHTTPRuntimeConfig{AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		VerifiedProfile: fixture.verified, AgentResolver: fixture.resolver,
		TLSConfig: relayRuntimeClientTLS(clientCertificate, roots), ProviderProvenance: *relayHTTPTestProvenance(t, fixture, server),
		RequesterAgentID:        "agent:client",
		AttemptJournalDirectory: directory, Timeout: 5 * time.Second, MaximumResponseBytes: defaultRelayHTTPBytes}
	if _, err := OpenRelayClientHTTPRuntime(settings); err == nil {
		t.Fatal("relay client runtime ignored its explicit owner enable")
	}
	settings.Enabled = true
	runtime, err := OpenRelayClientHTTPRuntime(settings)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Transport == nil || runtime.AttemptJournal == nil {
		t.Fatal("relay client runtime did not construct the authenticated route and journal")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	clientSPKI := sha256.Sum256(clientLeaf.RawSubjectPublicKeyInfo)
	authenticator, err := NewRelayMTLSAgentAuthenticator(map[string]string{
		"sha256:" + hex.EncodeToString(clientSPKI[:]): "agent:client",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientLeaf},
		VerifiedChains: [][]*x509.Certificate{{clientLeaf, ca}}}}
	principal, err := authenticator(request)
	if err != nil || principal.RequesterAgentID != "agent:client" {
		t.Fatalf("verified client SPKI was not bound to its Agent: principal=%+v err=%v", principal, err)
	}
	if _, err := NewRelayMTLSAgentAuthenticator(map[string]string{relayTestDigest("a"): ""}); err == nil {
		t.Fatal("empty Agent identity was accepted for a client certificate")
	}
	settings.TLSConfig.Certificates = nil
	if _, err := OpenRelayClientHTTPRuntime(settings); err == nil {
		t.Fatal("relay client runtime accepted server trust without a client identity")
	}
}

func TestRelayProviderRuntimeOwnsJournalAndRequiresCompleteService(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	ca, caKey, _ := issueTestCertificate(t, nil, nil, "relay-client-ca", true, nil, now)
	_, _, serverCertificate := issueTestCertificate(t, ca, caKey, "relay.example", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	clientCertificate, _, _ := issueTestCertificate(t, ca, caKey, "relay-client", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	clientSPKI := sha256.Sum256(clientCertificate.RawSubjectPublicKeyInfo)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	directory := filepath.Join(t.TempDir(), "provider")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	service := fixture.service(nil, &relayTestBroadcaster{})
	settings := RelayProviderHTTPRuntimeConfig{Enabled: true,
		AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		EnabledModes:   []agentrelay.Mode{agentrelay.ModeRelayExact}, JournalDirectory: directory,
		TLSCertificate: serverCertificate, ClientCAs: clientRoots,
		ClientAgentBySPKI: map[string]string{"sha256:" + hex.EncodeToString(clientSPKI[:]): "agent:client"},
		AdmissionLimits:   fixture.profile.AdmissionLimits,
		TerminalRetention: 24 * time.Hour, MaximumProtectedRecords: 32, MaximumHTTPBytes: defaultRelayHTTPBytes}
	runtime, err := OpenRelayProviderHTTPRuntime(service, settings)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Handler == nil || runtime.Server == nil || runtime.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || runtime.Service.Journal != runtime.Journal {
		t.Fatal("relay provider runtime did not construct one mTLS route over its exclusive journal")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	service.EvidenceSource = relayNonPortableEvidenceSource{relayTestEvidenceSource{now: fixture.now}}
	localRuntime, err := OpenRelayProviderHTTPRuntime(service, settings)
	if err != nil {
		t.Fatalf("authorized single-provider runtime was still gated on production acceptance: %v", err)
	}
	if !localRuntime.Capabilities.Ready() {
		t.Fatal("authorized single-provider runtime did not expose its enabled concrete pair")
	}
	if err := localRuntime.Close(); err != nil {
		t.Fatal(err)
	}
	settings.AssuranceLevel = agentrelay.AssuranceAutonomousDecentralized
	if _, err := OpenRelayProviderHTTPRuntime(service, settings); err == nil {
		t.Fatal("autonomous-decentralized provider accepted local-only finality evidence")
	}
	service.EvidenceSource = relayBackdatableEvidenceSource{relayTestEvidenceSource{now: fixture.now}}
	if _, err := OpenRelayProviderHTTPRuntime(service, settings); err == nil {
		t.Fatal("autonomous-decentralized provider accepted a signer-backdatable terminal evidence epoch")
	}
	service.EvidenceSource = nil
	if _, err := OpenRelayProviderHTTPRuntime(service, settings); err == nil {
		t.Fatal("relay provider runtime reported ready without a finality evidence source")
	}
	settings.AdmissionLimits.MaximumActiveExecutions = fixture.profile.AdmissionLimits.MaximumActiveExecutions + 1
	service.EvidenceSource = relayTestEvidenceSource{now: fixture.now}
	if _, err := OpenRelayProviderHTTPRuntime(service, settings); err == nil {
		t.Fatal("relay provider runtime widened its signed active-work limit")
	}
}

func TestRelayProviderRuntimeEnablesReadyModeWithoutUnrelatedSponsorshipDependency(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.profile.SupportedModes = []agentrelay.Mode{agentrelay.ModeRelayExact, agentrelay.ModeSponsorAndRelay,
		agentrelay.ModeSponsorOnly}
	service := fixture.service(nil, &relayTestBroadcaster{})
	service.Profile = fixture.profile
	ca, caKey, _ := issueTestCertificate(t, nil, nil, "relay-client-ca", true, nil, now)
	_, _, serverCertificate := issueTestCertificate(t, ca, caKey, "relay.example", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	clientCertificate, _, _ := issueTestCertificate(t, ca, caKey, "relay-client", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	clientSPKI := sha256.Sum256(clientCertificate.RawSubjectPublicKeyInfo)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	directory := filepath.Join(t.TempDir(), "provider")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := RelayProviderHTTPRuntimeConfig{Enabled: true,
		AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		EnabledModes:   []agentrelay.Mode{agentrelay.ModeRelayExact}, JournalDirectory: directory,
		TLSCertificate: serverCertificate, ClientCAs: clientRoots,
		ClientAgentBySPKI: map[string]string{"sha256:" + hex.EncodeToString(clientSPKI[:]): "agent:client"},
		AdmissionLimits:   fixture.profile.AdmissionLimits,
		TerminalRetention: 24 * time.Hour, MaximumProtectedRecords: 32, MaximumHTTPBytes: defaultRelayHTTPBytes}
	runtime, err := OpenRelayProviderHTTPRuntime(service, settings)
	if err != nil {
		t.Fatalf("missing sponsor dependency blocked the independent relay_exact pair: %v", err)
	}
	if len(runtime.Capabilities.Capabilities) != 1 ||
		runtime.Capabilities.Capabilities[0].Mode != agentrelay.ModeRelayExact ||
		!runtime.Capabilities.Capabilities[0].Ready {
		t.Fatalf("runtime enabled an unexpected pair: %+v", runtime.Capabilities)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	settings.EnabledModes = []agentrelay.Mode{agentrelay.ModeSponsorOnly}
	if _, err := OpenRelayProviderHTTPRuntime(service, settings); err == nil {
		t.Fatal("sponsor_only pair was enabled without sponsorship custody")
	}
	service.Sponsorship = &AgreementSponsorshipProcessor{}
	report := planRelayProviderCapabilitiesForModes(service, settings.AssuranceLevel, settings.EnabledModes,
		settings.SponsorshipReleasePolicy)
	if report.Ready() || !containsRelayMissing(report.Capabilities[0].Missing,
		"owner-sponsorship-release-policy") {
		t.Fatalf("non-nil custody without exact sponsorship evidence was mislabeled ready: %+v", report)
	}
}

func TestRelayProviderRuntimeBuildsStockSponsorshipEvidenceComposite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	policy := relaySponsorshipReleasePolicyFromRequest(fixture.prepared.QuoteBody)
	resolver := relayCapabilitySponsorshipResolver{capabilities: RelaySponsorshipEvidenceCapabilities{
		SupportedReleasePolicies:    []RelaySponsorshipReleasePolicy{policy},
		FreshBalanceSequenceRecheck: true, TerminalEvidence: true}}
	service := fixture.service(nil, nil)
	service.Sponsorship = resolver
	service.SponsorshipObservationVerifier = relayRejectingSponsorshipObservationVerifier{}
	service.EvidenceSource = relayTestEvidenceSource{now: fixture.now}

	ca, caKey, _ := issueTestCertificate(t, nil, nil, "relay-client-ca", true, nil, now)
	_, _, serverCertificate := issueTestCertificate(t, ca, caKey, "relay.example", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	clientCertificate, _, _ := issueTestCertificate(t, ca, caKey, "relay-client", false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	clientSPKI := sha256.Sum256(clientCertificate.RawSubjectPublicKeyInfo)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	directory := filepath.Join(t.TempDir(), "provider")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRelayProviderHTTPRuntime(service, RelayProviderHTTPRuntimeConfig{Enabled: true,
		AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		EnabledModes:   []agentrelay.Mode{agentrelay.ModeSponsorOnly}, SponsorshipReleasePolicy: policy,
		JournalDirectory: directory, TLSCertificate: serverCertificate, ClientCAs: roots,
		ClientAgentBySPKI: map[string]string{"sha256:" + hex.EncodeToString(clientSPKI[:]): "agent:client"},
		AdmissionLimits:   fixture.profile.AdmissionLimits, TerminalRetention: 24 * time.Hour,
		MaximumProtectedRecords: 32, MaximumHTTPBytes: defaultRelayHTTPBytes})
	if err != nil {
		t.Fatalf("stock sponsorship provider was not directly enabled from concrete dependencies: %v", err)
	}
	defer runtime.Close()
	if !runtime.Capabilities.Ready() {
		t.Fatalf("stock sponsorship pair is not ready: %+v", runtime.Capabilities)
	}
	if _, ok := runtime.Service.EvidenceSource.(*CompositeRelayFinalityEvidenceSource); !ok {
		t.Fatal("provider runtime did not conjunct renderer and sponsorship producer")
	}
	if err := runtime.Service.SponsorshipObservationVerifier.VerifySponsorshipCreditObservation(t.Context(),
		agentrelay.RelaySponsorshipCreditObservation{}, fixture.prepared.QuoteBody.SelectedSponsorshipReleaseProfile()); err != nil {
		t.Fatalf("runtime retained caller verifier A instead of exact sponsorship processor B: %v", err)
	}
}

type relayRejectingSponsorshipObservationVerifier struct{}

func (relayRejectingSponsorshipObservationVerifier) VerifySponsorshipCreditObservation(context.Context,
	agentrelay.RelaySponsorshipCreditObservation, agentrelay.SponsorshipReleaseProfile) error {
	return errors.New("substituted sponsorship observation verifier")
}

type relayNonPortableEvidenceSource struct{ relayTestEvidenceSource }

func (relayNonPortableEvidenceSource) HasRetrievableIndependentProofs() bool { return false }

func (relayNonPortableEvidenceSource) HasRollbackResistantCheckpoint() bool { return false }

func (relayNonPortableEvidenceSource) HasRollbackResistantTerminalCommitment() bool { return false }

type relayBackdatableEvidenceSource struct{ relayTestEvidenceSource }

func (relayBackdatableEvidenceSource) HasRollbackResistantTerminalCommitment() bool { return false }

func relayRuntimeClientTLS(certificate tls.Certificate, roots *x509.CertPool) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: roots}
}

var _ agentrelay.Journal = (*DurableRelayJournal)(nil)
