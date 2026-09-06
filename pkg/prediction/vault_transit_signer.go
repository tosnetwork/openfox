package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maximumVaultTransitTokenBytes = 4096
	maximumVaultTransitReplyBytes = 64 << 10
)

// VaultTransitArchiveReceiptSignerConfig binds a receipt signer to one
// version of one Vault Transit Ed25519 key. ExpectedPublicKey is mandatory:
// TLS authenticates the endpoint, while this pin prevents a changed Vault key
// from silently becoming an admitted archive authority.
//
// The token needs only read access to transit/keys/<key> and update access to
// transit/sign/<key>. It must be supplied by the process environment or an
// operator secret manager, never stored in an Oracle profile or evidence file.
type VaultTransitArchiveReceiptSignerConfig struct {
	Address           string
	Token             string
	TransitMount      string
	KeyName           string
	KeyVersion        uint
	ExpectedPublicKey ed25519.PublicKey
}

// VaultTransitArchiveReceiptSigner delegates only archive-receipt digest
// signing to a Vault Transit Ed25519 key. The private key never enters this
// process. It deliberately signs the 32-byte receipt digest as an ordinary
// Ed25519 message (not Ed25519ph), matching ed25519.Verify used by the
// protocol's archive receipt verifier.
type VaultTransitArchiveReceiptSigner struct {
	address    *url.URL
	token      string
	mount      string
	key        string
	keyVersion uint
	publicKey  ed25519.PublicKey
	client     *http.Client
}

func NewVaultTransitArchiveReceiptSigner(
	config VaultTransitArchiveReceiptSignerConfig,
) (*VaultTransitArchiveReceiptSigner, error) {
	return newVaultTransitArchiveReceiptSigner(config, nil)
}

func newVaultTransitArchiveReceiptSigner(
	config VaultTransitArchiveReceiptSignerConfig,
	client *http.Client,
) (*VaultTransitArchiveReceiptSigner, error) {
	address, err := parseVaultTransitAddress(config.Address)
	if err != nil || !validVaultTransitName(config.TransitMount) || !validVaultTransitName(config.KeyName) ||
		config.KeyVersion == 0 || len(config.ExpectedPublicKey) != ed25519.PublicKeySize ||
		len(config.Token) == 0 || len(config.Token) > maximumVaultTransitTokenBytes ||
		strings.TrimSpace(config.Token) != config.Token || strings.ContainsAny(config.Token, "\x00\r\n") {
		return nil, errors.New("prediction Vault Transit archive signer configuration is invalid")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:              nil,
				TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS13},
				DisableCompression: true,
			},
		}
	}
	return &VaultTransitArchiveReceiptSigner{
		address: address, token: config.Token, mount: config.TransitMount, key: config.KeyName,
		keyVersion: config.KeyVersion, publicKey: append(ed25519.PublicKey(nil), config.ExpectedPublicKey...),
		client: client,
	}, nil
}

func (signer *VaultTransitArchiveReceiptSigner) ArchiveReceiptPublicKey(
	ctx context.Context,
) (ed25519.PublicKey, error) {
	if signer == nil || ctx == nil {
		return nil, errors.New("prediction Vault Transit archive signer is unavailable")
	}
	request, err := signer.request(ctx, http.MethodGet, "keys", nil)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if fetchErr := signer.doJSON(request, &reply); fetchErr != nil || reply.Data.Type != "ed25519" {
		return nil, errors.New("prediction Vault Transit public key is unavailable")
	}
	entry, found := reply.Data.Keys[strconv.FormatUint(uint64(signer.keyVersion), 10)]
	if !found {
		return nil, errors.New("prediction Vault Transit key version is unavailable")
	}
	publicKey, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	if err != nil || !bytes.Equal(publicKey, signer.publicKey) {
		return nil, errors.New("prediction Vault Transit public key does not match its pin")
	}
	return append(ed25519.PublicKey(nil), signer.publicKey...), nil
}

func (signer *VaultTransitArchiveReceiptSigner) SignArchiveReceiptDigest(
	ctx context.Context,
	digest [sha256.Size]byte,
) ([ed25519.SignatureSize]byte, error) {
	if signer == nil || ctx == nil {
		return [ed25519.SignatureSize]byte{}, errors.New("prediction Vault Transit archive signer is unavailable")
	}
	payload, err := json.Marshal(struct {
		Input      string `json:"input"`
		KeyVersion uint   `json:"key_version"`
	}{Input: base64.StdEncoding.EncodeToString(digest[:]), KeyVersion: signer.keyVersion})
	if err != nil {
		return [ed25519.SignatureSize]byte{}, errors.New("prediction Vault Transit signing request is invalid")
	}
	request, err := signer.request(ctx, http.MethodPost, "sign", bytes.NewReader(payload))
	if err != nil {
		return [ed25519.SignatureSize]byte{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	var reply struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if fetchErr := signer.doJSON(request, &reply); fetchErr != nil {
		return [ed25519.SignatureSize]byte{}, errors.New("prediction Vault Transit signing failed")
	}
	signature, err := parseVaultTransitEd25519Signature(reply.Data.Signature, signer.keyVersion)
	if err != nil || !ed25519.Verify(signer.publicKey, digest[:], signature[:]) {
		return [ed25519.SignatureSize]byte{}, errors.New(
			"prediction Vault Transit returned an invalid receipt signature",
		)
	}
	return signature, nil
}

func (signer *VaultTransitArchiveReceiptSigner) request(
	ctx context.Context,
	method, operation string,
	body io.Reader,
) (*http.Request, error) {
	if signer.address == nil || signer.client == nil || (operation != "keys" && operation != "sign") {
		return nil, errors.New("prediction Vault Transit archive signer is unavailable")
	}
	target := *signer.address
	target.Path = "/v1/" + signer.mount + "/" + operation + "/" + signer.key
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, errors.New("prediction Vault Transit request is invalid")
	}
	request.Header.Set("X-Vault-Token", signer.token)
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func (signer *VaultTransitArchiveReceiptSigner) doJSON(request *http.Request, result any) error {
	response, err := signer.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		canonicalMediaType(response.Header.Get("Content-Type")) != "application/json" {
		return errors.New("Vault Transit rejected archive signer request")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumVaultTransitReplyBytes+1))
	if err != nil || len(payload) > maximumVaultTransitReplyBytes {
		return errors.New("Vault Transit response exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(result); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Vault Transit response has trailing JSON")
	}
	return nil
}

func parseVaultTransitAddress(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.String() != value {
		return nil, errors.New("invalid Vault Transit HTTPS address")
	}
	return parsed, nil
}

func validVaultTransitName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func parseVaultTransitEd25519Signature(value string, keyVersion uint) ([ed25519.SignatureSize]byte, error) {
	prefix := fmt.Sprintf("vault:v%d:", keyVersion)
	if !strings.HasPrefix(value, prefix) || strings.Count(value, ":") != 2 {
		return [ed25519.SignatureSize]byte{}, errors.New("invalid Vault Transit signature envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return [ed25519.SignatureSize]byte{}, errors.New("invalid Vault Transit Ed25519 signature")
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], raw)
	return signature, nil
}

var _ ArchiveReceiptSigner = (*VaultTransitArchiveReceiptSigner)(nil)
