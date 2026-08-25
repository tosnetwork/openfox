package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestExternalPaymentSinkRequiresExactPinnedAttestation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	request := externalPaymentRequest(t, now)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, incoming *http.Request) {
		var call externalPaymentRPC
		if incoming.Method != http.MethodPost || json.NewDecoder(incoming.Body).Decode(&call) != nil || call.Request.StableActionID != request.StableActionID {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		digest, _ := commerce.AgreementPaymentRequestDigest(call.Request)
		attestation, _ := commerce.SignExternalPaymentAttestation(commerce.ExternalPaymentAttestationBody{SchemaVersion: 1,
			AdapterURI: call.Request.SettlementAdapterURI, AttestorID: "attestor:test", PaymentRequestDigest: digest,
			StableActionID: call.Request.StableActionID, ExactTransferReference: "bank:transfer:123", FinalityReference: "bank:statement:9",
			ResolvedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, key)
		response.Header().Set("Content-Type", "application/vnd.tos.external-payment-attestation.v1+json")
		_ = json.NewEncoder(response).Encode(externalPaymentRPCResult{Attestation: attestation})
	}))
	defer server.Close()
	pins := ExternalPaymentAttestorPins{"attestor:test": {AdapterURI: request.SettlementAdapterURI,
		PublicKey: key.Public().(ed25519.PublicKey)}}
	sink := &ExternalAttestedPaymentSink{Endpoint: server.URL + "/v1/agreement-payments", AdapterURI: request.SettlementAdapterURI,
		Client: server.Client(), Resolver: pins, Now: func() time.Time { return now }}
	_, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := sink.SubmitPayment(t.Context(), commerce.AuthorizedAction{ActionKind: "settlement.external", StableActionID: request.StableActionID},
		commerce.WriterFence{}, fields, nil, request)
	if err != nil || evidence.ExactTransferReference != "bank:transfer:123" ||
		sink.VerifyPaymentEvidence(request, evidence, now) != nil {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	mutated := request
	mutated.Destination = []byte("account:attacker")
	if sink.VerifyPaymentEvidence(mutated, evidence, now) == nil {
		t.Fatal("signed external evidence was replayed to another destination")
	}
}

func externalPaymentRequest(t *testing.T, now time.Time) commerce.AgreementPaymentRequest {
	t.Helper()
	amount := commerce.AgreementAmount{AssetNamespace: "iso4217", AssetIdentifier: "USD", AmountAtomic: "5000", Unit: "cent"}
	instances, err := commerce.MaterializeSettlementObligations("owner:test", "agent:payer", "sha256:"+strings.Repeat("1", 64), "pay",
		"sha256:"+strings.Repeat("2", 64), commerce.AgreementObligation{ObligationID: "pay", Kind: "payment",
			ObligorAgentID: "agent:payer", BeneficiaryAgentID: "agent:payee", SubjectContentType: "text/plain",
			Subject: []byte("external payment"), Amount: &amount, DueAtUnix: uint64(now.Add(time.Hour).Unix()),
			ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix()), ConfidentialityPolicy: "participants",
			CancellationPolicy: "before-due", DisputePolicy: "manual", SettlementAdapterURI: "external.payment.v1",
			SettlementParameters: []byte("account:payee"), AuthorizationPredicateIDs: []string{"payer"}})
	if err != nil || len(instances) != 1 {
		t.Fatal(err)
	}
	request, err := commerce.BuildExternalAgreementPaymentRequestAmount("owner:test", "agent:payer", "external:test", "bank:test",
		"sha256:"+strings.Repeat("3", 64), []byte("account:payee"), instances[0], instances[0].Amount)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
