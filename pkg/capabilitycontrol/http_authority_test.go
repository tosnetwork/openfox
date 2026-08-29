package capabilitycontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func TestHTTPSControlAuthorityBindsSignedResponseToExactRequest(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	var replay authorityResponse
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input authorityRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "bad", 400)
			return
		}
		if replay.Operation != "" {
			_ = json.NewEncoder(w).Encode(replay)
			return
		}
		wire, _ := json.Marshal(input)
		requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
		output := authorityResponse{Operation: input.Operation, Scope: input.Scope, Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]), Revision: input.Prior, Commitment: input.Commitment, UnixSeconds: 100, Epoch: 1, Nonce: hex.EncodeToString(bytes.Repeat([]byte{9}, 32))}
		unsigned, _ := json.Marshal(output)
		digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), unsigned...))
		output.Signature = hex.EncodeToString(ed25519.Sign(key, digest[:]))
		replay = output
		_ = json.NewEncoder(w).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef", "ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Check(t.Context(), []byte("scope"), 1, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if err = authority.Check(t.Context(), []byte("scope"), 1, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("signed response replayed across an identical semantic request with a fresh challenge")
	}
}

func TestHTTPSControlAuthorityPreservesSignedTimeEpochAndEvidence(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input authorityRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Operation != "trusted-time" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		wire, _ := json.Marshal(input)
		requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
		output := authorityResponse{Operation: input.Operation, Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]),
			UnixSeconds: 1234, Epoch: 9, Nonce: hex.EncodeToString(bytes.Repeat([]byte{8}, 32))}
		unsigned, _ := json.Marshal(output)
		digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), unsigned...))
		output.Signature = hex.EncodeToString(ed25519.Sign(key, digest[:]))
		_ = json.NewEncoder(w).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef", "ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := authority.ObserveTrustedTime(t.Context())
	if err != nil || observation.UnixSeconds != 1234 || observation.Epoch != 9 || len(observation.EvidenceDigest) != sha256.Size {
		t.Fatalf("signed observation was not preserved: %#v %v", observation, err)
	}
}

func TestHTTPSControlAuthorityBindsInstallationFenceToExactTransaction(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input authorityRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Operation != "verify-installation-fence" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		wire, _ := json.Marshal(input)
		requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
		output := authorityResponse{Operation: input.Operation, Scope: input.Scope, Commitment: input.Commitment, Target: input.Target,
			Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]), ExpiresAtUnix: uint64(time.Now().Add(time.Minute).Unix()),
			Nonce: hex.EncodeToString(bytes.Repeat([]byte{13}, 32))}
		unsigned, _ := json.Marshal(output)
		digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), unsigned...))
		output.Signature = hex.EncodeToString(ed25519.Sign(key, digest[:]))
		_ = json.NewEncoder(w).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef", "ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	transaction := trusted.CapabilityInstallationTransactionV1{SchemaVersion: 1, WriterFenceDigest: bytes.Repeat([]byte{1}, 32), ExactRequestDigest: bytes.Repeat([]byte{2}, 32)}
	if err := authority.VerifyCapabilityInstallation(t.Context(), transaction); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSControlAuthorityResolvesStableInstallationIdentity(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, ed25519.SeedSize))
	installationID := bytes.Repeat([]byte{23}, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input authorityRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Operation != "resolve-installation-id" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		wire, _ := json.Marshal(input)
		requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
		output := authorityResponse{Operation: input.Operation, Scope: input.Scope, Target: hex.EncodeToString(installationID), Challenge: input.Challenge,
			RequestDigest: hex.EncodeToString(requestDigest[:]), Nonce: hex.EncodeToString(bytes.Repeat([]byte{24}, 32))}
		unsigned, _ := json.Marshal(output)
		digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), unsigned...))
		output.Signature = hex.EncodeToString(ed25519.Sign(key, digest[:]))
		_ = json.NewEncoder(w).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef", "ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	got, err := authority.ResolveInstallationID(t.Context(), trusted.DomainOwnerLocal, []byte("domain"), []byte("owner"), []byte("agent"))
	if err != nil || !bytes.Equal(got, installationID) {
		t.Fatalf("stable installation identity: %x %v", got, err)
	}
}

func TestHTTPSControlAuthorityBindsCapabilityAcquisitionPhase(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{25}, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input authorityRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Operation != "admit-capability-acquisition" || input.Target != "reserve" ||
			input.Prior != 8 || input.Next != 9 || len(decodeHex(input.OwnerScope)) != 16 || len(decodeHex(input.Commitment)) != sha256.Size {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		wire, _ := json.Marshal(input)
		requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
		output := authorityResponse{Operation: input.Operation, Scope: input.Scope, Commitment: input.Commitment, Target: input.Target,
			Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]), Revision: input.Next, Epoch: 4,
			ExpiresAtUnix: uint64(time.Now().Add(time.Minute).Unix()), Nonce: hex.EncodeToString(bytes.Repeat([]byte{26}, 32))}
		unsigned, _ := json.Marshal(output)
		digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), unsigned...))
		output.Signature = hex.EncodeToString(ed25519.Sign(key, digest[:]))
		_ = json.NewEncoder(w).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef", "ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.AdmitCapabilityAcquisition(t.Context(), CapabilityAcquisitionRequest{SchemaVersion: 1, OwnerID: []byte("owner"), AgentID: []byte("agent"),
		LedgerID: bytes.Repeat([]byte{7}, 16), AcquisitionID: "0123456789abcdef0123456789abcdef", Phase: "reserve", Principal: "owner:test",
		SourceID: "registry:test", SourceGeneration: 1, ReservedBytes: 1024, ReservedFiles: 2, ExpiresAtUnix: uint64(time.Now().Add(time.Minute).Unix()),
		ContentDigest: []byte{}, PriorRevision: 8, NextRevision: 9}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSControlAuthorityRejectsRedirectBeforeCredentialReplay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, ed25519.SeedSize))
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/v1/openfox-control-authority", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef",
		"ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authority.Read(t.Context(), bytes.Repeat([]byte{1}, sha256.Size)); err == nil {
		t.Fatal("control authority followed a credentialed redirect")
	}
	if hits != 1 {
		t.Fatalf("redirect caused %d authenticated requests, want 1", hits)
	}
}

func TestHTTPSControlAuthorityAtomicallyBindsExitFenceToHighWater(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input authorityRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Operation != "compare-and-advance-capability-control" ||
			input.Prior != 8 || input.Next != 9 || input.Target != "fenced" || len(decodeHex(input.OwnerScope)) != sha256.Size {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		wire, _ := json.Marshal(input)
		requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
		output := authorityResponse{Operation: input.Operation, Scope: input.Scope, Commitment: input.Commitment, Target: input.Target,
			Challenge: input.Challenge, RequestDigest: hex.EncodeToString(requestDigest[:]), Revision: input.Next,
			Nonce: hex.EncodeToString(bytes.Repeat([]byte{28}, 32))}
		unsigned, _ := json.Marshal(output)
		digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), unsigned...))
		output.Signature = hex.EncodeToString(ed25519.Sign(key, digest[:]))
		_ = json.NewEncoder(w).Encode(output)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	authority, err := OpenHTTPSControlAuthority(server.URL+"/v1/openfox-control-authority", "0123456789abcdef0123456789abcdef", "ed25519:"+hex.EncodeToString(key.Public().(ed25519.PublicKey)), client)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.CompareAndAdvanceCapabilityControl(t.Context(), bytes.Repeat([]byte{1}, 32), 8, 9, bytes.Repeat([]byte{2}, 32), []byte("owner"), []byte("agent"), false); err != nil {
		t.Fatal(err)
	}
}
