package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/utils"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type HTTPSControlAuthority struct {
	endpoint, token string
	publicKey       ed25519.PublicKey
	client          *http.Client
}

type authorityRequest struct {
	Operation  string `json:"operation"`
	Scope      string `json:"scope"`
	Prior      uint64 `json:"prior"`
	Next       uint64 `json:"next"`
	Commitment string `json:"commitment"`
	Target     string `json:"target"`
	OwnerScope string `json:"owner_scope"`
	Challenge  string `json:"challenge"`
}
type authorityResponse struct {
	Operation     string `json:"operation"`
	Scope         string `json:"scope"`
	RequestDigest string `json:"request_digest"`
	Challenge     string `json:"challenge"`
	Revision      uint64 `json:"revision"`
	Commitment    string `json:"commitment"`
	Target        string `json:"target"`
	UnixSeconds   uint64 `json:"unix_seconds"`
	Epoch         uint64 `json:"epoch"`
	ExpiresAtUnix uint64 `json:"expires_at_unix"`
	Nonce         string `json:"nonce"`
	Signature     string `json:"signature"`
}

func OpenHTTPSControlAuthority(endpoint, token, publicKeyText string, client *http.Client) (*HTTPSControlAuthority, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "/v1/openfox-control-authority" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("OpenFox control authority must be an absolute HTTPS /v1/openfox-control-authority endpoint")
	}
	if len(token) < 32 || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") || !strings.HasPrefix(publicKeyText, "ed25519:") {
		return nil, errors.New("OpenFox control authority credential or key is invalid")
	}
	key, err := hex.DecodeString(strings.TrimPrefix(publicKeyText, "ed25519:"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("OpenFox control authority public key is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		return nil, errors.New("OpenFox control authority timeout is unbounded")
	}
	clone := *client
	baseTransport, ok := clone.Transport.(*http.Transport)
	if !ok && clone.Transport != nil {
		return nil, errors.New("OpenFox control authority requires an inspectable HTTP transport")
	}
	if baseTransport == nil {
		baseTransport = http.DefaultTransport.(*http.Transport)
	}
	transport := baseTransport.Clone()
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	loopback := isExactLoopbackAuthorityHost(parsed.Hostname())
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify && !loopback {
		return nil, errors.New("OpenFox control authority forbids insecure TLS outside literal loopback tests")
	}
	whitelist := []string(nil)
	if loopback {
		whitelist = []string{parsed.Hostname()}
	}
	allowed, err := utils.NewPrivateHostWhitelist(whitelist)
	if err != nil {
		return nil, err
	}
	transport.DialContext = utils.NewSafeDialContext(&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, allowed, nil)
	clone.Transport = transport
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("OpenFox control authority redirects are forbidden")
	}
	return &HTTPSControlAuthority{parsed.String(), token, ed25519.PublicKey(key), &clone}, nil
}

func isExactLoopbackAuthorityHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func OpenHTTPSControlAuthorityFromFile(endpoint, tokenFile, publicKeyText string) (*HTTPSControlAuthority, error) {
	info, err := os.Stat(tokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("OpenFox control authority token must be a private 0600 regular file")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("OpenFox control authority token is unavailable or oversized")
	}
	return OpenHTTPSControlAuthority(endpoint, strings.TrimSpace(string(raw)), publicKeyText, nil)
}
func (a *HTTPSControlAuthority) Close() error { return nil }
func (a *HTTPSControlAuthority) ResolveInstallationID(ctx context.Context, domainKind trusted.DomainKind, domainID, ownerID, agentID []byte) ([]byte, error) {
	if len(domainID) == 0 || len(ownerID) == 0 || len(agentID) == 0 {
		return nil, errors.New("installation identity scope is incomplete")
	}
	scope := sha256.Sum256(bytes.Join([][]byte{[]byte("tos.openfox-installation-identity.v1"), []byte{byte(domainKind)}, domainID, ownerID, agentID}, []byte{0}))
	r, err := a.call(ctx, authorityRequest{Operation: "resolve-installation-id", Scope: hex.EncodeToString(scope[:])})
	if err != nil {
		return nil, err
	}
	return decodeHexExact(r.Target, 16)
}
func (a *HTTPSControlAuthority) Read(ctx context.Context, scope []byte) (uint64, []byte, error) {
	r, e := a.call(ctx, authorityRequest{Operation: "read", Scope: hex.EncodeToString(scope)})
	if e != nil {
		return 0, nil, e
	}
	if r.Revision == 0 && r.Commitment == "" {
		return 0, nil, nil
	}
	commitment, err := decodeHexExact(r.Commitment, sha256.Size)
	if err != nil {
		return 0, nil, errors.New("control authority read response is invalid")
	}
	return r.Revision, commitment, nil
}
func (a *HTTPSControlAuthority) Check(ctx context.Context, scope []byte, revision uint64, commitment []byte) error {
	_, err := a.call(ctx, authorityRequest{Operation: "check", Scope: hex.EncodeToString(scope), Prior: revision, Commitment: hex.EncodeToString(commitment)})
	return err
}
func (a *HTTPSControlAuthority) CompareAndAdvance(ctx context.Context, scope []byte, prior, next uint64, commitment []byte) error {
	_, err := a.call(ctx, authorityRequest{Operation: "compare-and-advance", Scope: hex.EncodeToString(scope), Prior: prior, Next: next, Commitment: hex.EncodeToString(commitment)})
	return err
}

func (a *HTTPSControlAuthority) CompareAndAdvanceCapabilityControl(ctx context.Context, scope []byte, prior, next uint64, commitment, ownerID, agentID []byte, accepting bool) error {
	if len(scope) != sha256.Size || len(commitment) != sha256.Size || len(ownerID) == 0 || len(agentID) == 0 || next != prior+1 {
		return errors.New("atomic acquisition-control transition is incomplete")
	}
	ownerScope := capabilityAcquisitionScope(ownerID, agentID)
	target := "fenced"
	if accepting {
		target = "accepting"
	}
	_, err := a.call(ctx, authorityRequest{Operation: "compare-and-advance-capability-control", Scope: hex.EncodeToString(scope),
		Prior: prior, Next: next, Commitment: hex.EncodeToString(commitment), OwnerScope: hex.EncodeToString(ownerScope), Target: target})
	return err
}
func (a *HTTPSControlAuthority) Now(ctx context.Context) (time.Time, error) {
	observation, err := a.ObserveTrustedTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(observation.UnixSeconds), 0).UTC(), nil
}

func (a *HTTPSControlAuthority) ObserveTrustedTime(ctx context.Context) (TrustedTimeEvidenceObservation, error) {
	r, err := a.call(ctx, authorityRequest{Operation: "trusted-time"})
	if err != nil || r.UnixSeconds == 0 || r.Epoch == 0 {
		return TrustedTimeEvidenceObservation{}, errors.Join(errors.New("trusted time unavailable"), err)
	}
	wire, marshalErr := json.Marshal(r)
	if marshalErr != nil {
		return TrustedTimeEvidenceObservation{}, errors.New("trusted time evidence is not canonical")
	}
	evidence := sha256.Sum256(append([]byte("tos.openfox-control-authority-time-evidence.v1\x00"), wire...))
	return TrustedTimeEvidenceObservation{UnixSeconds: r.UnixSeconds, Epoch: r.Epoch, EvidenceDigest: evidence[:]}, nil
}

// VerifyCapabilityInstallation asks the pinned external control authority to
// admit the exact installation transaction. The challenge-bound signed reply
// is the writer-fence acknowledgement; local files are never authority.
func (a *HTTPSControlAuthority) VerifyCapabilityInstallation(ctx context.Context, transaction trusted.CapabilityInstallationTransactionV1) error {
	if len(transaction.WriterFenceDigest) != sha256.Size || len(transaction.ExactRequestDigest) != sha256.Size {
		return errors.New("installation writer-fence binding is invalid")
	}
	wire, err := trusted.MarshalBody(transaction)
	if err != nil {
		return errors.New("installation transaction is not canonical")
	}
	digest := sha256.Sum256(append([]byte("tos.openfox-installation-fence-request.v1\x00"), wire...))
	_, err = a.call(ctx, authorityRequest{Operation: "verify-installation-fence",
		Scope: hex.EncodeToString(transaction.WriterFenceDigest), Commitment: hex.EncodeToString(transaction.ExactRequestDigest), Target: hex.EncodeToString(digest[:])})
	return err
}

func (a *HTTPSControlAuthority) AdmitCapabilityAcquisition(ctx context.Context, acquisition CapabilityAcquisitionRequest) error {
	if acquisition.SchemaVersion != 1 || len(acquisition.OwnerID) == 0 || len(acquisition.AgentID) == 0 || len(acquisition.LedgerID) != 16 ||
		len(acquisition.AcquisitionID) != 32 || (acquisition.Phase != "reserve" && acquisition.Phase != "commit") || acquisition.Principal == "" || acquisition.SourceID == "" ||
		acquisition.SourceGeneration == 0 || acquisition.ReservedBytes == 0 || acquisition.ReservedFiles == 0 || acquisition.ExpiresAtUnix == 0 ||
		acquisition.NextRevision != acquisition.PriorRevision+1 || acquisition.Phase == "reserve" && (acquisition.ContentDigest == nil || len(acquisition.ContentDigest) != 0 || acquisition.ContentBytes != 0 || acquisition.ContentFiles != 0) ||
		acquisition.Phase == "commit" && (len(acquisition.ContentDigest) != sha256.Size || acquisition.ContentFiles == 0 || acquisition.ContentBytes > acquisition.ReservedBytes || acquisition.ContentFiles > acquisition.ReservedFiles) {
		return errors.New("capability acquisition fence request is incomplete")
	}
	wire, err := trusted.MarshalBody(acquisition)
	if err != nil {
		return errors.New("capability acquisition fence request is not canonical")
	}
	scope := capabilityAcquisitionScope(acquisition.OwnerID, acquisition.AgentID)
	commitment := sha256.Sum256(append([]byte("tos.openfox-capability-acquisition.v1\x00"), wire...))
	_, err = a.call(ctx, authorityRequest{Operation: "admit-capability-acquisition", Scope: hex.EncodeToString(scope),
		Prior: acquisition.PriorRevision, Next: acquisition.NextRevision, Commitment: hex.EncodeToString(commitment[:]),
		Target: acquisition.Phase, OwnerScope: hex.EncodeToString(acquisition.LedgerID)})
	return err
}

func (a *HTTPSControlAuthority) call(ctx context.Context, input authorityRequest) (authorityResponse, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return authorityResponse{}, errors.New("control authority challenge generation failed")
	}
	input.Challenge = hex.EncodeToString(challenge)
	wire, _ := json.Marshal(input)
	requestDigest := sha256.Sum256(append([]byte("tos.openfox-control-authority-request.v1\x00"), wire...))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(wire))
	if err != nil {
		return authorityResponse{}, err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return authorityResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return authorityResponse{}, fmt.Errorf("control authority rejected request: HTTP %d", response.StatusCode)
	}
	var output authorityResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return authorityResponse{}, errors.New("control authority response is invalid")
	}
	signature, err := hex.DecodeString(output.Signature)
	if err != nil {
		return authorityResponse{}, errors.New("control authority signature is invalid")
	}
	unsigned := output
	unsigned.Signature = ""
	signedWire, _ := json.Marshal(unsigned)
	digest := sha256.Sum256(append([]byte("tos.openfox-control-authority-response.v1\x00"), signedWire...))
	if output.Operation != input.Operation || output.Scope != input.Scope || output.Challenge != input.Challenge ||
		output.RequestDigest != hex.EncodeToString(requestDigest[:]) || len(decodeHex(output.Nonce)) != 32 || !ed25519.Verify(a.publicKey, digest[:], signature) {
		return authorityResponse{}, errors.New("control authority response signature or binding is invalid")
	}
	switch input.Operation {
	case "read":
		if output.Revision == 0 && output.Commitment != "" || output.Revision > 0 && len(decodeHex(output.Commitment)) != sha256.Size {
			return authorityResponse{}, errors.New("control authority read result is inconsistent")
		}
	case "check":
		if output.Revision != input.Prior || output.Commitment != input.Commitment {
			return authorityResponse{}, errors.New("control authority check result does not acknowledge the exact state")
		}
	case "compare-and-advance":
		if output.Revision != input.Next || output.Commitment != input.Commitment || input.Next != input.Prior+1 {
			return authorityResponse{}, errors.New("control authority advance result does not acknowledge the exact successor")
		}
	case "compare-and-advance-capability-control":
		if output.Revision != input.Next || output.Commitment != input.Commitment || output.Target != input.Target ||
			output.Scope != input.Scope || input.Next != input.Prior+1 || len(decodeHex(input.OwnerScope)) != sha256.Size {
			return authorityResponse{}, errors.New("control authority did not atomically acknowledge the capability-control successor and acquisition state")
		}
	case "trusted-time":
		if output.UnixSeconds == 0 || output.Epoch == 0 {
			return authorityResponse{}, errors.New("control authority trusted-time result is incomplete")
		}
	case "verify-installation-fence":
		if output.Scope != input.Scope || output.Commitment != input.Commitment || output.Target != input.Target ||
			output.ExpiresAtUnix == 0 || uint64(time.Now().UTC().Unix()) >= output.ExpiresAtUnix {
			return authorityResponse{}, errors.New("control authority installation-fence acknowledgement is incomplete or stale")
		}
	case "resolve-installation-id":
		if output.Scope != input.Scope || len(decodeHex(output.Target)) != 16 {
			return authorityResponse{}, errors.New("control authority installation identity is incomplete")
		}
	case "admit-capability-acquisition":
		if output.Scope != input.Scope || output.Commitment != input.Commitment || output.Target != input.Target ||
			output.Revision != input.Next || input.Next != input.Prior+1 || len(decodeHex(input.OwnerScope)) != 16 || output.Epoch == 0 || output.ExpiresAtUnix == 0 || uint64(time.Now().UTC().Unix()) >= output.ExpiresAtUnix {
			return authorityResponse{}, errors.New("control authority capability-acquisition acknowledgement is incomplete or stale")
		}
	default:
		return authorityResponse{}, errors.New("control authority operation is unsupported")
	}
	return output, nil
}
func capabilityAcquisitionScope(ownerID, agentID []byte) []byte {
	scope := sha256.Sum256(bytes.Join([][]byte{[]byte("tos.openfox-capability-acquisition.v1"), ownerID, agentID}, []byte{0}))
	return scope[:]
}
func decodeHex(value string) []byte { raw, _ := hex.DecodeString(value); return raw }
func decodeHexExact(value string, size int) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != size {
		return nil, errors.New("hex value has invalid size")
	}
	return raw, nil
}
