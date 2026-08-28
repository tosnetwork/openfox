package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

func TestSharedAuthorityMutualTLSAndCrossHostTakeoverFence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caCert, caKey, _ := issueTestCertificate(t, nil, nil, "authority-test-ca", true, nil, now)
	_, _, serverCert := issueTestCertificate(t, caCert, caKey, "authority.test", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	clientACert, _, clientATLS := issueTestCertificate(t, caCert, caKey, "runtime-a", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	clientBCert, _, clientBTLS := issueTestCertificate(t, caCert, caKey, "runtime-b", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	backing, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", authorityKey,
		PortfolioLimits{ComputeUnits: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Close()
	backing.now = func() time.Time { return now }
	spkiA := "sha256:" + strings.Repeat("0", 64)
	spkiB := "sha256:" + strings.Repeat("0", 64)
	for parsed, target := range map[*x509.Certificate]*string{clientACert: &spkiA, clientBCert: &spkiB} {
		digest := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
		*target = "sha256:" + hex.EncodeToString(digest[:])
	}
	scope := []string{"payment.direct", "publication.publish"}
	server := &SharedAuthorityServer{Backing: backing, ClientsBySPKI: map[string]SharedAuthorityClientGrant{
		spkiA: {OwnerID: "owner-1", AgentID: "agent-1", InstanceID: "runtime-a", Scopes: scope},
		spkiB: {OwnerID: "owner-1", AgentID: "agent-1", InstanceID: "runtime-b", Scopes: scope},
	}}
	testServer := httptest.NewUnstartedServer(server.Handler())
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(caCert)
	serverTLS, err := NewSharedAuthorityServerTLSConfig(serverCert, clientRoots)
	if err != nil {
		t.Fatal(err)
	}
	testServer.TLS = serverTLS
	testServer.StartTLS()
	defer testServer.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(caCert)
	makeClient := func(cert tls.Certificate) *SharedAuthorityClient {
		httpClient, clientErr := NewSharedAuthorityHTTPClient(cert, serverRoots, "authority.test", 5*time.Second)
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		client, clientErr := NewSharedAuthorityClient(testServer.URL+"/v1/economic-authority", httpClient,
			"authority-1", authorityKey.Public().(ed25519.PublicKey))
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		return client
	}
	clientA, clientB := makeClient(clientATLS), makeClient(clientBTLS)
	fenceA, err := clientA.AcquireWriter(context.Background(), "runtime-a", scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientA.AcquireWriter(context.Background(), "runtime-b", scope, time.Hour); err == nil {
		t.Fatal("client A acquired another runtime's identity")
	}
	fenceB, err := clientB.AcquireWriter(context.Background(), "runtime-b", scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if fenceB.Body.WriterGeneration != fenceA.Body.WriterGeneration+1 {
		t.Fatalf("generations A=%d B=%d", fenceA.Body.WriterGeneration, fenceB.Body.WriterGeneration)
	}
	if err := clientA.ConfirmCurrentWriterFence(fenceA, now); err == nil {
		t.Fatal("stale remote writer remained current")
	}

	request := []byte("exact-publication")
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
		"carrier_id": commerce.ID("carrier-1"), "intent_object_id": commerce.ID("intent-1"), "revision": commerce.U64(1),
		"operation_digest": commerce.Digest32("sha256:" + strings.Repeat("d", 64))}
	action, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "publication.publish", fields, request, fenceB, 1,
		"sha256:"+strings.Repeat("e", 64), "", "not-published", fenceB.Body.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientA.SignAction(action, fenceA); err == nil {
		t.Fatal("stale host signed after takeover")
	}
	action, err = clientB.SignAction(action, fenceB)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := clientB.Admit(action, fields, request, fenceB, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		t.Fatalf("resolution=%+v err=%v", resolution, err)
	}
	if retry, err := clientB.Admit(action, fields, request, fenceB, nil); err != nil || !reflect.DeepEqual(retry, resolution) {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	if recovered, found := clientB.ResolveAuthorizedAction(action.StableActionID, action.ExactRequestDigest); !found || !reflect.DeepEqual(recovered, action) {
		t.Fatalf("shared authority did not recover exact AuthorizedAction: found=%v recovered=%+v", found, recovered)
	}
	if _, err := clientA.Admit(action, fields, request, fenceA, nil); err == nil {
		t.Fatal("stale host admitted after takeover")
	}

	// Relay admission crosses the host boundary as the released canonical
	// AdmissionRequest wire object, not as OpenFox's richer internal descriptor.
	relayRequest := []byte{0xa1, 0x01, 0x02}
	relayFields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
		"agreement_body_digest":  commerce.Digest32("sha256:" + strings.Repeat("1", 64)),
		"obligation_instance_id": commerce.Digest32("sha256:" + strings.Repeat("2", 64)),
		"payer_id":               commerce.ID("agent-1"), "payee_id": commerce.ID("agent-merchant"),
		"network_id":         commerce.ID("tos:testnet"),
		"asset_digest":       commerce.Digest32("sha256:" + strings.Repeat("3", 64)),
		"amount_atomic":      commerce.ID("25"),
		"destination_digest": commerce.Digest32("sha256:" + strings.Repeat("4", 64)),
	}
	relayAction, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "payment.direct", relayFields,
		relayRequest, fenceB, 1, "sha256:"+strings.Repeat("5", 64), "", "pending", uint64(now.Add(time.Minute).Unix()))
	if err == nil {
		relayAction, err = clientB.SignAction(relayAction, fenceB)
	}
	if err != nil {
		t.Fatal(err)
	}
	wireFields, err := commerce.ExportSemanticFields(relayAction.ActionKind, relayFields)
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, _ := commerce.AuthorizedActionDigest(relayAction)
	fenceDigest, _ := commerce.WriterFenceDigest(fenceB)
	descriptor := agentrelay.RelaySideEffectAdmissionDescriptor{SchemaVersion: 1, OwnerID: "owner-1", AgentID: "agent-1",
		AuthenticatedPrincipal: "agent-1", ProviderAgentID: "agent:relay", ServiceProfileDigest: "sha256:" + strings.Repeat("6", 64),
		ProviderQuoteDigest: "sha256:" + strings.Repeat("7", 64), NetworkDigest: "sha256:" + strings.Repeat("8", 64),
		TransactionIdentityDigest: "sha256:" + strings.Repeat("9", 64), Mode: agentrelay.ModeRelayExact,
		AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		StageMask:      []agentrelay.SideEffectStage{agentrelay.SideEffectBroadcast}, RouteAttempt: 1,
		StableActionID: relayAction.StableActionID, ExactRequestDigest: relayAction.ExactRequestDigest,
		RelayExecutionDigest: "sha256:" + strings.Repeat("a", 64), AuthorizedActionDigest: actionDigest,
		WriterFenceDigest: fenceDigest, StartNotAfterCapUnix: uint64(now.Add(30 * time.Second).Unix()),
		AuthorizedAction: relayAction, WriterFence: fenceB, UnderlyingActionRequest: relayRequest, SemanticFields: wireFields}
	unknownLookup := descriptor.Lookup()
	unknownLookup.ProviderQuoteDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := clientB.ResolveRelaySideEffectAdmission(t.Context(), unknownLookup); !errors.Is(err, agentrelay.ErrRelayUnknown) {
		t.Fatalf("shared authority lost typed linearizable not-found: %v", err)
	}
	receipt, err := clientB.AdmitRelaySideEffects(t.Context(), descriptor)
	if err != nil || receipt.Body.RouteAttempt != 1 || receipt.Body.TransactionIdentityDigest != descriptor.TransactionIdentityDigest {
		t.Fatalf("shared authority did not admit the exact canonical relay wire request: receipt=%+v err=%v", receipt.Body, err)
	}
	resolved, err := clientB.ResolveRelaySideEffectAdmission(t.Context(), descriptor.Lookup())
	if err != nil || !reflect.DeepEqual(resolved, receipt) {
		t.Fatalf("shared authority did not recover the exact relay receipt: resolved=%+v err=%v", resolved.Body, err)
	}
}

func issueTestCertificate(t *testing.T, parent *x509.Certificate, parentKey ed25519.PrivateKey, commonName string,
	isCA bool, usages []x509.ExtKeyUsage, now time.Time) (*x509.Certificate, ed25519.PrivateKey, tls.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, ExtKeyUsage: usages,
		KeyUsage: x509.KeyUsageDigitalSignature}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		parent, parentKey = template, private
	} else if usages[0] == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{commonName}
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, public, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, private, tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: private, Leaf: parsed}
}
