package earning

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestHTTPPrivateContentUploaderUsesPinnedIngressAndExactEnvelope(t *testing.T) {
	challenge := commerce.SignedPrivateHandoffChallenge{Body: commerce.PrivateHandoffChallengeBody{
		IngressInstanceID: "ingress:receiver:1", MaximumCiphertextBytes: 64,
	}}
	authorization := commerce.SignedPrivateHandoffAuthorization{Body: commerce.PrivateHandoffAuthorizationBody{ChallengeDigest: "sha256:" + strings.Repeat("a", 64)}}
	want := commerce.SignedPrivateHandoffAcknowledgement{Record: commerce.AcceptedPrivateContentRecord{HandoffID: "handoff:1"}}
	server := httptest.NewServer(PrivateIngressHTTPHandler{IngressInstanceID: "ingress:receiver:1", MaximumBodyBytes: 4096,
		Accept: func(_ context.Context, receivedChallenge commerce.SignedPrivateHandoffChallenge,
			receivedAuthorization commerce.SignedPrivateHandoffAuthorization, ciphertext []byte) (commerce.SignedPrivateHandoffAcknowledgement, error) {
			if receivedChallenge.Body.IngressInstanceID != challenge.Body.IngressInstanceID ||
				receivedAuthorization.Body.ChallengeDigest != authorization.Body.ChallengeDigest || string(ciphertext) != "encrypted" {
				t.Fatal("handler changed the private upload envelope")
			}
			return want, nil
		}})
	defer server.Close()
	uploader, err := NewHTTPPrivateContentUploader("ingress:receiver:1", server.URL+"/v1/private-ingress", nil, 64, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := uploader.Upload(context.Background(), challenge, authorization, []byte("encrypted"))
	if err != nil || got.Record.HandoffID != want.Record.HandoffID {
		t.Fatalf("upload failed: acknowledgement=%+v err=%v", got, err)
	}
	wrong := challenge
	wrong.Body.IngressInstanceID = "ingress:attacker"
	if _, err := uploader.Upload(context.Background(), wrong, authorization, []byte("encrypted")); err == nil {
		t.Fatal("remote-selected ingress instance was accepted")
	}
}

func TestPrivateIngressHTTPRejectsRedirectAndOversize(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, "/attacker", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	uploader, err := NewHTTPPrivateContentUploader("ingress:1", redirect.URL+"/upload", nil, 8, true)
	if err != nil {
		t.Fatal(err)
	}
	challenge := commerce.SignedPrivateHandoffChallenge{Body: commerce.PrivateHandoffChallengeBody{IngressInstanceID: "ingress:1", MaximumCiphertextBytes: 8}}
	if _, err := uploader.Upload(context.Background(), challenge, commerce.SignedPrivateHandoffAuthorization{}, []byte("123456789")); err == nil {
		t.Fatal("oversized ciphertext was accepted")
	}
	if _, err := uploader.Upload(context.Background(), challenge, commerce.SignedPrivateHandoffAuthorization{}, []byte("1234")); err == nil ||
		!strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect was followed or misreported: %v", err)
	}
}
