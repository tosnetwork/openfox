package nativeimpl

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/agentpacket"
)

const (
	contactNowUnix    uint64 = 1786800000
	contactExpiryUnix uint64 = 1786803600 // now + 1h, within the 24h lifetime
)

func contactNetwork() NetworkTuple {
	return NetworkTuple{
		NetworkID:   "tos-mainnet",
		GenesisRoot: "tvm-cell-sha256:" + repeatHex("dd"),
		GenesisFile: "sha256:" + repeatHex("ee"),
	}
}

// signedValidCard produces a genuinely canonical-signed card so ContactBytes can
// be proven byte-identical to the issuer: only a matching preimage verifies.
func signedValidCard(t *testing.T) (ContactCardFacts, ed25519.PublicKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	net := contactNetwork()
	card := agentpacket.ContactCard{
		AgentID:       "agent_" + hex64,
		Network:       &nativev1.NetworkDomain{NetworkId: net.NetworkID, GenesisRootHash: net.GenesisRoot, GenesisFileHash: net.GenesisFile},
		Endpoint:      "https://provider.example/agent",
		Capabilities:  []string{"cap_" + hex64},
		ExpiresAtUnix: contactExpiryUnix,
	}
	signed, err := agentpacket.SignContactAt(card, key, time.Unix(int64(contactNowUnix), 0))
	if err != nil {
		t.Fatalf("canonical sign: %v", err)
	}
	facts := ContactCardFacts{
		AgentID: signed.AgentID, NetworkID: signed.Network.NetworkId,
		GenesisRoot: signed.Network.GenesisRootHash, GenesisFile: signed.Network.GenesisFileHash,
		Endpoint: signed.Endpoint, Capabilities: signed.Capabilities, ExpiresAtUnix: signed.ExpiresAtUnix,
		PublicKey: signed.PublicKey, Signature: signed.Signature,
	}
	return facts, signed.PublicKey
}

func TestContactBytesMatchesCanonicalIssuer(t *testing.T) {
	facts, pub := signedValidCard(t)
	if !ed25519.Verify(pub, ContactBytes(facts), facts.Signature) {
		t.Fatalf("ContactBytes must reproduce the canonical signing preimage byte-for-byte")
	}
	if ValidateContactStateless(facts, contactNetwork(), contactNowUnix) != ContactOK {
		t.Fatalf("the canonical signed card must pass the stateless gate")
	}
}

type contactVectorCard struct {
	AgentID       string   `json:"agent_id"`
	NetworkID     string   `json:"network_id"`
	GenesisRoot   string   `json:"genesis_root"`
	GenesisFile   string   `json:"genesis_file"`
	Endpoint      string   `json:"endpoint"`
	Capabilities  []string `json:"capabilities"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
	PublicKeyHex  string   `json:"public_key_hex"`
	SignatureHex  string   `json:"signature_hex"`
}

type contactVectorCase struct {
	Name            string            `json:"name"`
	Card            contactVectorCard `json:"card"`
	ContactBytesHex string            `json:"contact_bytes_hex"`
	Expect          string            `json:"expect"`
}

type contactVectors struct {
	Schema  string              `json:"schema"`
	NowUnix uint64              `json:"now_unix"`
	Network NetworkTuple        `json:"network"`
	Cases   []contactVectorCase `json:"cases"`
}

func factsFor(card contactVectorCard) ContactCardFacts {
	pub, _ := hex.DecodeString(card.PublicKeyHex)
	sig, _ := hex.DecodeString(card.SignatureHex)
	return ContactCardFacts{
		AgentID: card.AgentID, NetworkID: card.NetworkID, GenesisRoot: card.GenesisRoot,
		GenesisFile: card.GenesisFile, Endpoint: card.Endpoint, Capabilities: card.Capabilities,
		ExpiresAtUnix: card.ExpiresAtUnix, PublicKey: pub, Signature: sig,
	}
}

func TestContactCardVectors(t *testing.T) {
	valid, _ := signedValidCard(t)
	base := contactVectorCard{
		AgentID: valid.AgentID, NetworkID: valid.NetworkID, GenesisRoot: valid.GenesisRoot,
		GenesisFile: valid.GenesisFile, Endpoint: valid.Endpoint, Capabilities: valid.Capabilities,
		ExpiresAtUnix: valid.ExpiresAtUnix, PublicKeyHex: hex.EncodeToString(valid.PublicKey),
		SignatureHex: hex.EncodeToString(valid.Signature),
	}

	mutate := func(f func(*contactVectorCard)) contactVectorCard {
		c := base
		c.Capabilities = append([]string(nil), base.Capabilities...)
		f(&c)
		return c
	}

	cases := []contactVectorCase{
		{Name: "valid", Card: base, Expect: string(ContactOK)},
		{Name: "agent_id_malformed", Card: mutate(func(c *contactVectorCard) { c.AgentID = "agent_short" }), Expect: string(ContactAgentIDMalformed)},
		{Name: "public_key_malformed", Card: mutate(func(c *contactVectorCard) { c.PublicKeyHex = hex.EncodeToString(make([]byte, 16)) }), Expect: string(ContactPublicKeyMalformed)},
		{Name: "signature_malformed", Card: mutate(func(c *contactVectorCard) { c.SignatureHex = hex.EncodeToString(make([]byte, 32)) }), Expect: string(ContactSignatureMalformed)},
		{Name: "endpoint_non_loopback_http", Card: mutate(func(c *contactVectorCard) { c.Endpoint = "http://provider.example/agent" }), Expect: string(ContactEndpointMalformed)},
		{Name: "expiry_past", Card: mutate(func(c *contactVectorCard) { c.ExpiresAtUnix = contactNowUnix - 1 }), Expect: string(ContactExpiryInvalid)},
		{Name: "expiry_exceeds_lifetime", Card: mutate(func(c *contactVectorCard) { c.ExpiresAtUnix = contactNowUnix + ContactLifetimeSeconds + 1 }), Expect: string(ContactExpiryInvalid)},
		{Name: "capability_malformed", Card: mutate(func(c *contactVectorCard) { c.Capabilities = []string{"cap_short"} }), Expect: string(ContactCapabilityInvalid)},
		{Name: "network_mismatch", Card: mutate(func(c *contactVectorCard) { c.NetworkID = "tos-testnet" }), Expect: string(ContactNetworkMismatch)},
	}

	for i := range cases {
		facts := factsFor(cases[i].Card)
		cases[i].ContactBytesHex = hex.EncodeToString(ContactBytes(facts))
		if got := ValidateContactStateless(facts, contactNetwork(), contactNowUnix); string(got) != cases[i].Expect {
			t.Fatalf("case %s: got reason %q, want %q", cases[i].Name, got, cases[i].Expect)
		}
	}

	vectors := contactVectors{
		Schema: "atos.native.mobile-buyer-contact-card.v1", NowUnix: contactNowUnix,
		Network: contactNetwork(), Cases: cases,
	}
	raw, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "mobile_buyer_contact_card_v1.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write vectors: %v", err)
	}
}
