package nativeimpl

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// ContactCardFacts is a signed, non-canonical locator carried by a QR code or a
// universal link. The mobile client validates it — network tuple, expiry,
// endpoint origin, shape — before opening any connection, and verifies the
// signature over ContactBytes. Finalized Agent state remains the authority for
// who controls the key; that check happens later, against a resolver.
type ContactCardFacts struct {
	AgentID       string
	NetworkID     string
	GenesisRoot   string
	GenesisFile   string
	Endpoint      string
	Capabilities  []string
	ExpiresAtUnix uint64
	PublicKey     []byte
	Signature     []byte
}

// NetworkTuple is the caller's configured TOS network the Contact Card must bind
// to. A locator for another network is refused before any connection.
type NetworkTuple struct {
	NetworkID   string `json:"network_id"`
	GenesisRoot string `json:"genesis_root"`
	GenesisFile string `json:"genesis_file"`
}

// ContactReason is the deterministic verdict of the stateless Contact Card
// check. "ok" means the card is well-formed, unexpired, and on the caller's
// network — the caller may then verify the ed25519 signature over ContactBytes
// and, authoritatively, that the key controls the Agent.
type ContactReason string

const (
	ContactOK                 ContactReason = "ok"
	ContactAgentIDMalformed   ContactReason = "agent_id_malformed"
	ContactPublicKeyMalformed ContactReason = "public_key_malformed"
	ContactSignatureMalformed ContactReason = "signature_malformed"
	ContactEndpointMalformed  ContactReason = "endpoint_malformed"
	ContactExpiryInvalid      ContactReason = "expiry_invalid"
	ContactCapabilityInvalid  ContactReason = "capability_malformed"
	ContactNetworkMismatch    ContactReason = "network_mismatch"
)

// ContactLifetimeSeconds bounds how far in the future a Contact Card may expire,
// matching the canonical issuance lifetime.
const ContactLifetimeSeconds = 24 * 60 * 60

// ValidateContactStateless applies the pre-connection checks in a fixed order so
// the reason is deterministic across platforms. It performs no signature or
// resolver work: it decides only whether the locator is safe to connect to and
// on the right network.
func ValidateContactStateless(card ContactCardFacts, network NetworkTuple, nowUnix uint64) ContactReason {
	if !isAgentID(card.AgentID) {
		return ContactAgentIDMalformed
	}
	if len(card.PublicKey) != 32 {
		return ContactPublicKeyMalformed
	}
	if len(card.Signature) != 64 {
		return ContactSignatureMalformed
	}
	if strings.TrimSpace(card.Endpoint) != card.Endpoint || !validPacketEndpoint(card.Endpoint) {
		return ContactEndpointMalformed
	}
	if card.ExpiresAtUnix == 0 || nowUnix >= card.ExpiresAtUnix ||
		card.ExpiresAtUnix > nowUnix+ContactLifetimeSeconds {
		return ContactExpiryInvalid
	}
	seen := make(map[string]struct{}, len(card.Capabilities))
	for _, capability := range card.Capabilities {
		if !isCapabilityID(capability) {
			return ContactCapabilityInvalid
		}
		if _, ok := seen[capability]; ok {
			return ContactCapabilityInvalid
		}
		seen[capability] = struct{}{}
	}
	if card.NetworkID != network.NetworkID || card.GenesisRoot != network.GenesisRoot ||
		card.GenesisFile != network.GenesisFile {
		return ContactNetworkMismatch
	}
	return ContactOK
}

// ContactBytes builds the ed25519 signing preimage for a Contact Card. It must
// be byte-for-byte identical to the canonical issuer, or every signature check
// fails; the iOS and Android clients reproduce these exact bytes.
func ContactBytes(card ContactCardFacts) []byte {
	buffer := bytes.NewBufferString("atos.agent.contact.v1\x00")
	text := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		buffer.Write(length[:])
		buffer.WriteString(value)
	}
	text(card.AgentID)
	text(card.NetworkID)
	text(card.GenesisRoot)
	text(card.GenesisFile)
	text(card.Endpoint)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(card.Capabilities)))
	buffer.Write(count[:])
	for _, capability := range card.Capabilities {
		text(capability)
	}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], card.ExpiresAtUnix)
	buffer.Write(expiry[:])
	buffer.Write(card.PublicKey)
	return buffer.Bytes()
}

func isAgentID(value string) bool {
	return strings.HasPrefix(value, "agent_") && hexBody(value[len("agent_"):])
}

func isCapabilityID(value string) bool {
	return strings.HasPrefix(value, "cap_") && hexBody(value[len("cap_"):])
}

func hexBody(body string) bool {
	if len(body) != 64 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
