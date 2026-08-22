package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
)

const (
	attestationSchema = "tos.openfox.messenger-operator-attestation.v1"
	attestationDomain = attestationSchema + "\x00"
	maxAttestation    = 64 << 10
)

// operatorAttestation binds one operator's transcript to the exact public
// endpoint, network, binaries, configuration and observation interval used for
// a Phase E run. OperatorID and SiteID are signed assertions; their real-world
// independence still requires an external reviewer.
type operatorAttestation struct {
	Schema                  string `json:"schema"`
	OperatorID              string `json:"operator_id"`
	SiteID                  string `json:"site_id"`
	AgentID                 string `json:"agent_id"`
	TranscriptSHA256        string `json:"transcript_sha256"`
	PublicMessengerEndpoint string `json:"public_messenger_endpoint"`
	NetworkID               string `json:"network_id"`
	GenesisRootHash         string `json:"genesis_root_hash"`
	GenesisFileHash         string `json:"genesis_file_hash"`
	OpenFoxCommit           string `json:"openfox_commit"`
	MessengerCommit         string `json:"messenger_commit"`
	OpenFoxBinarySHA256     string `json:"openfox_binary_sha256"`
	MessengerBinarySHA256   string `json:"messenger_binary_sha256"`
	OpenFoxConfigSHA256     string `json:"openfox_config_sha256"`
	MessengerConfigSHA256   string `json:"messenger_config_sha256"`
	IntervalStartUnix       int64  `json:"interval_start_unix"`
	IntervalEndUnix         int64  `json:"interval_end_unix"`
	AttestationPublicKeyHex string `json:"attestation_public_key_ed25519_hex"`
	AttestationSignatureHex string `json:"attestation_signature_ed25519_hex,omitempty"`
}

type unsignedOperatorAttestation struct {
	Schema                  string `json:"schema"`
	OperatorID              string `json:"operator_id"`
	SiteID                  string `json:"site_id"`
	AgentID                 string `json:"agent_id"`
	TranscriptSHA256        string `json:"transcript_sha256"`
	PublicMessengerEndpoint string `json:"public_messenger_endpoint"`
	NetworkID               string `json:"network_id"`
	GenesisRootHash         string `json:"genesis_root_hash"`
	GenesisFileHash         string `json:"genesis_file_hash"`
	OpenFoxCommit           string `json:"openfox_commit"`
	MessengerCommit         string `json:"messenger_commit"`
	OpenFoxBinarySHA256     string `json:"openfox_binary_sha256"`
	MessengerBinarySHA256   string `json:"messenger_binary_sha256"`
	OpenFoxConfigSHA256     string `json:"openfox_config_sha256"`
	MessengerConfigSHA256   string `json:"messenger_config_sha256"`
	IntervalStartUnix       int64  `json:"interval_start_unix"`
	IntervalEndUnix         int64  `json:"interval_end_unix"`
	AttestationPublicKeyHex string `json:"attestation_public_key_ed25519_hex"`
}

func readAttestation(path string, allowUnsigned bool) (operatorAttestation, error) {
	var result operatorAttestation
	raw, err := readBoundedRegularFile(path, maxAttestation)
	if err != nil {
		return result, errors.New("attestation must be a bounded stable regular file")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil {
		return result, errors.New("invalid operator attestation")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, errors.New("trailing operator attestation data")
	}
	if err := validateAttestationShape(result, allowUnsigned); err != nil {
		return result, err
	}
	return result, nil
}

func validateAttestationShape(value operatorAttestation, allowUnsigned bool) error {
	if value.Schema != attestationSchema || !boundedLabel(value.OperatorID, 256) || !boundedLabel(value.SiteID, 256) ||
		!canonicalAgent(value.AgentID) || !canonicalHex(value.TranscriptSHA256, "", 64) ||
		!validPublicMessengerEndpoint(value.PublicMessengerEndpoint) || !boundedNetwork(value.NetworkID) ||
		!canonicalHex(value.GenesisRootHash, "", 64) || !canonicalHex(value.GenesisFileHash, "", 64) ||
		!canonicalHex(value.OpenFoxCommit, "", 40) || !canonicalHex(value.MessengerCommit, "", 40) ||
		!canonicalHex(value.OpenFoxBinarySHA256, "", 64) || !canonicalHex(value.MessengerBinarySHA256, "", 64) ||
		!canonicalHex(value.OpenFoxConfigSHA256, "", 64) || !canonicalHex(value.MessengerConfigSHA256, "", 64) ||
		value.IntervalStartUnix <= 0 || value.IntervalEndUnix < value.IntervalStartUnix ||
		value.IntervalEndUnix-value.IntervalStartUnix > 7*24*60*60 ||
		!canonicalHex(value.AttestationPublicKeyHex, "", ed25519.PublicKeySize*2) {
		return errors.New("invalid operator attestation fields")
	}
	if value.AttestationSignatureHex == "" && allowUnsigned {
		return nil
	}
	if !canonicalHex(value.AttestationSignatureHex, "", ed25519.SignatureSize*2) {
		return errors.New("invalid operator attestation signature encoding")
	}
	return nil
}

func attestationMessage(value operatorAttestation) ([]byte, error) {
	unsigned := unsignedOperatorAttestation{
		Schema: value.Schema, OperatorID: value.OperatorID, SiteID: value.SiteID, AgentID: value.AgentID,
		TranscriptSHA256: value.TranscriptSHA256, PublicMessengerEndpoint: value.PublicMessengerEndpoint,
		NetworkID: value.NetworkID, GenesisRootHash: value.GenesisRootHash, GenesisFileHash: value.GenesisFileHash,
		OpenFoxCommit: value.OpenFoxCommit, MessengerCommit: value.MessengerCommit,
		OpenFoxBinarySHA256: value.OpenFoxBinarySHA256, MessengerBinarySHA256: value.MessengerBinarySHA256,
		OpenFoxConfigSHA256: value.OpenFoxConfigSHA256, MessengerConfigSHA256: value.MessengerConfigSHA256,
		IntervalStartUnix: value.IntervalStartUnix, IntervalEndUnix: value.IntervalEndUnix,
		AttestationPublicKeyHex: value.AttestationPublicKeyHex,
	}
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return nil, errors.New("encode canonical operator attestation")
	}
	return append([]byte(attestationDomain), canonical...), nil
}

func verifyAttestation(value operatorAttestation, transcript evidence, transcriptDigest [sha256.Size]byte) error {
	if value.AgentID != transcript.AgentID || value.TranscriptSHA256 != hex.EncodeToString(transcriptDigest[:]) {
		return errors.New("attestation does not bind the exact transcript and AgentID")
	}
	for _, line := range transcript.Transcript {
		if line.AppliedUnix < value.IntervalStartUnix || line.AppliedUnix > value.IntervalEndUnix {
			return errors.New("transcript activity falls outside signed observation interval")
		}
	}
	public, _ := hex.DecodeString(value.AttestationPublicKeyHex)
	signature, _ := hex.DecodeString(value.AttestationSignatureHex)
	message, err := attestationMessage(value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return errors.New("invalid operator attestation signature")
	}
	return nil
}

func verifyAttestationPair(left, right operatorAttestation, a, b evidence, aDigest, bDigest [sha256.Size]byte) error {
	if err := verifyAttestation(left, a, aDigest); err != nil {
		return errors.New("first operator: " + err.Error())
	}
	if err := verifyAttestation(right, b, bDigest); err != nil {
		return errors.New("second operator: " + err.Error())
	}
	if left.OperatorID == right.OperatorID || left.SiteID == right.SiteID ||
		left.PublicMessengerEndpoint == right.PublicMessengerEndpoint ||
		left.AttestationPublicKeyHex == right.AttestationPublicKeyHex {
		return errors.New("operator attestations do not assert distinct operators, sites, endpoints, and keys")
	}
	if left.NetworkID != right.NetworkID || left.GenesisRootHash != right.GenesisRootHash ||
		left.GenesisFileHash != right.GenesisFileHash {
		return errors.New("operator attestations bind different network domains")
	}
	return nil
}

func boundedLabel(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func boundedNetwork(value string) bool {
	if !boundedLabel(value, 64) || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validPublicMessengerEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Path != "/v1/tos-messenger/messages" || parsed.Hostname() == "" ||
		parsed.Hostname() != strings.ToLower(parsed.Hostname()) || (parsed.Port() != "" && parsed.Port() != "443") ||
		parsed.String() != value || strings.HasSuffix(parsed.Hostname(), ".") || parsed.Hostname() == "localhost" {
		return false
	}
	if address := net.ParseIP(parsed.Hostname()); address != nil {
		return !address.IsPrivate() && !address.IsLoopback() && !address.IsUnspecified() && !address.IsMulticast()
	}
	return strings.Contains(parsed.Hostname(), ".")
}
