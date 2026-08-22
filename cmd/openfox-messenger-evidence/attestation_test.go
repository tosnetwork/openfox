package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signedOperatorAttestation(t *testing.T, transcript evidence, digest [sha256.Size]byte,
	operator, site, endpoint string) operatorAttestation {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := operatorAttestation{
		Schema: attestationSchema, OperatorID: operator, SiteID: site, AgentID: transcript.AgentID,
		TranscriptSHA256: hex.EncodeToString(digest[:]), PublicMessengerEndpoint: endpoint,
		NetworkID: "tos-testnet", GenesisRootHash: strings.Repeat("1", 64), GenesisFileHash: strings.Repeat("2", 64),
		OpenFoxCommit: strings.Repeat("3", 40), MessengerCommit: strings.Repeat("4", 40),
		OpenFoxBinarySHA256: strings.Repeat("5", 64), MessengerBinarySHA256: strings.Repeat("6", 64),
		OpenFoxConfigSHA256: strings.Repeat("7", 64), MessengerConfigSHA256: strings.Repeat("8", 64),
		IntervalStartUnix: 1, IntervalEndUnix: 10, AttestationPublicKeyHex: hex.EncodeToString(public),
	}
	message, err := attestationMessage(value)
	if err != nil {
		t.Fatal(err)
	}
	value.AttestationSignatureHex = hex.EncodeToString(ed25519.Sign(private, message))
	if err := validateAttestationShape(value, false); err != nil {
		t.Fatal(err)
	}
	return value
}

func attestationTranscripts() (evidence, evidence, [sha256.Size]byte, [sha256.Size]byte) {
	aID := "agent_" + strings.Repeat("a", 64)
	bID := "agent_" + strings.Repeat("b", 64)
	run := "run_" + strings.Repeat("3", 32)
	a := evidence{Schema: controlSchema, AgentID: aID, RunID: run, Transcript: []transcriptLine{
		{Direction: "outbound", RecipientInput: "bob.tos", EventID: "evt_" + strings.Repeat("1", 64),
			Content: "ping", RunID: run, AppliedUnix: 2},
		{Direction: "inbound", PeerAgentID: bID, EventID: "evt_" + strings.Repeat("2", 64),
			ReplyToEventID: "evt_" + strings.Repeat("1", 64), Content: "ack", RunID: run, AppliedUnix: 4},
	}}
	b := evidence{Schema: controlSchema, AgentID: bID, RunID: run, Transcript: []transcriptLine{
		{Direction: "inbound", PeerAgentID: aID, EventID: "evt_" + strings.Repeat("1", 64),
			Content: "ping", RunID: run, AppliedUnix: 3},
		{Direction: "outbound", EventID: "evt_" + strings.Repeat("2", 64),
			ReplyToEventID: "evt_" + strings.Repeat("1", 64), Content: "ack", RunID: run, AppliedUnix: 4},
	}}
	return a, b, sha256.Sum256([]byte("alice transcript bytes")), sha256.Sum256([]byte("bob transcript bytes"))
}

func TestVerifyAttestationPairBindsDistinctOperatorsAndNetwork(t *testing.T) {
	a, b, aDigest, bDigest := attestationTranscripts()
	left := signedOperatorAttestation(t, a, aDigest, "operator-alice", "site-alice",
		"https://alice.example/v1/tos-messenger/messages")
	right := signedOperatorAttestation(t, b, bDigest, "operator-bob", "site-bob",
		"https://bob.example/v1/tos-messenger/messages")
	if err := verifyAttestationPair(left, right, a, b, aDigest, bDigest); err != nil {
		t.Fatal(err)
	}

	mutated := right
	mutated.NetworkID = "other-network"
	if err := verifyAttestationPair(left, mutated, a, b, aDigest, bDigest); err == nil {
		t.Fatal("network/signature substitution passed")
	}
	right.OperatorID = left.OperatorID
	message, _ := attestationMessage(right)
	// A copied assertion is still rejected even if it could be re-signed by its
	// own operator key; distinctness is an explicit acceptance precondition.
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	right.AttestationPublicKeyHex = hex.EncodeToString(public)
	message, _ = attestationMessage(right)
	right.AttestationSignatureHex = hex.EncodeToString(ed25519.Sign(private, message))
	if err := verifyAttestationPair(left, right, a, b, aDigest, bDigest); err == nil {
		t.Fatal("same asserted operator passed")
	}
}

func TestVerifyAttestationRejectsTranscriptAndIntervalSubstitution(t *testing.T) {
	a, _, digest, _ := attestationTranscripts()
	value := signedOperatorAttestation(t, a, digest, "operator-alice", "site-alice",
		"https://alice.example/v1/tos-messenger/messages")
	wrongDigest := sha256.Sum256([]byte("substituted transcript"))
	if err := verifyAttestation(value, a, wrongDigest); err == nil {
		t.Fatal("transcript substitution passed")
	}
	value.IntervalEndUnix = 3
	if err := verifyAttestation(value, a, digest); err == nil {
		t.Fatal("out-of-interval transcript or signature substitution passed")
	}
}

func TestPublicMessengerEndpointRejectsLocalOrNonCanonicalAuthority(t *testing.T) {
	invalid := []string{
		"http://alice.example/v1/tos-messenger/messages",
		"https://localhost/v1/tos-messenger/messages",
		"https://127.0.0.1/v1/tos-messenger/messages",
		"https://alice.example:444/v1/tos-messenger/messages",
		"https://alice.example/v1/tos-messenger/messages?route=model",
	}
	for _, value := range invalid {
		if validPublicMessengerEndpoint(value) {
			t.Fatalf("invalid public endpoint passed: %s", value)
		}
	}
}

func TestReadAttestationAcceptsUnsignedPreparationAndRejectsSymlink(t *testing.T) {
	a, _, digest, _ := attestationTranscripts()
	value := signedOperatorAttestation(t, a, digest, "operator-alice", "site-alice",
		"https://alice.example/v1/tos-messenger/messages")
	value.AttestationSignatureHex = ""
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "attestation.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAttestation(path, true); err != nil {
		t.Fatal(err)
	}
	if _, err := readAttestation(path, false); err == nil {
		t.Fatal("unsigned attestation passed final verification parsing")
	}
	link := filepath.Join(directory, "attestation-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAttestation(link, true); err == nil {
		t.Fatal("symlinked attestation passed")
	}
}
