package servicebridge

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

// Relay trust anchor bounds.
const (
	// relayCAFileName is the owner-only copy of the pinned relay
	// certificate authorities in state_dir/relay.
	relayCAFileName = "relay-ca.pem"
	// maxRelayCABytes bounds the CA file `init --relay-ca-file` reads.
	maxRelayCABytes = 1 << 20
	// maxRelayCACertificates bounds the certificates one CA file holds.
	maxRelayCACertificates = 32
)

// Relay trust anchors a relay connection verifies against.
const (
	// RelayTrustPinned is the CA file `init --relay-ca-file` pinned: the
	// system trust store is not used for that relay.
	RelayTrustPinned = "pinned_ca_file"
	// RelayTrustSystem is the system trust store (SSL_CERT_FILE and
	// SSL_CERT_DIR included).
	RelayTrustSystem = "system_roots"
	// RelayTrustLoopback is plaintext http to a loopback host: no TLS.
	RelayTrustLoopback = "loopback_plaintext"
)

// errRelayCAExpired reports a pinned certificate outside its validity.
var errRelayCAExpired = errors.New("servicebridge: a certificate of the relay CA file is expired or not yet valid")

// relayCA is a parsed relay CA file.
type relayCA struct {
	sha256       string
	certificates []*x509.Certificate
	pool         *x509.CertPool
}

// notAfter is the earliest expiry of the file's certificates.
func (c *relayCA) notAfter() time.Time {
	var earliest time.Time
	for _, certificate := range c.certificates {
		if earliest.IsZero() || certificate.NotAfter.Before(earliest) {
			earliest = certificate.NotAfter
		}
	}
	return earliest
}

// checkValidAt requires every certificate to be valid at now.
func (c *relayCA) checkValidAt(now time.Time) error {
	for _, certificate := range c.certificates {
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return fmt.Errorf("%w (%s, valid %s to %s)", errRelayCAExpired, certificate.Subject.CommonName,
				certificate.NotBefore.UTC().Format(time.RFC3339), certificate.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// parseRelayCA decodes a file of one or more PEM certificates and nothing
// else: a private key, any other PEM block, PEM headers or text outside
// the blocks are refused, so a mistaken file is never copied into state.
func parseRelayCA(data []byte) (*relayCA, error) {
	if len(data) == 0 || len(data) > maxRelayCABytes {
		return nil, fmt.Errorf("servicebridge: the relay CA file must hold 1 to %d bytes", maxRelayCABytes)
	}
	digest := sha256.Sum256(data)
	parsed := &relayCA{sha256: hex.EncodeToString(digest[:]), pool: x509.NewCertPool()}
	rest := bytes.TrimLeft(data, " \t\r\n")
	for len(rest) > 0 {
		// pem.Decode skips text before a block; the file may hold none.
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, errors.New("servicebridge: the relay CA file holds data outside PEM certificate blocks")
		}
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("servicebridge: the relay CA file does not decode as PEM")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("servicebridge: the relay CA file may hold only PEM CERTIFICATE blocks (a " +
				"private key or any other block is refused)")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("servicebridge: a certificate of the relay CA file does not parse")
		}
		if len(parsed.certificates) == maxRelayCACertificates {
			return nil, fmt.Errorf("servicebridge: the relay CA file holds more than %d certificates",
				maxRelayCACertificates)
		}
		parsed.certificates = append(parsed.certificates, certificate)
		parsed.pool.AddCert(certificate)
		rest = bytes.TrimLeft(remaining, " \t\r\n")
	}
	if len(parsed.certificates) == 0 {
		return nil, errors.New("servicebridge: the relay CA file holds no PEM certificate")
	}
	return parsed, nil
}

// readRelayCASource reads the owner's CA file for `init`: a regular file,
// bounded, with certificates that are valid now.
func readRelayCASource(path string, now time.Time) ([]byte, *relayCA, error) {
	if !cleanAbsolute(path) {
		return nil, nil, errors.New("servicebridge: --relay-ca-file must be an absolute clean path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRelayCABytes {
		return nil, nil, fmt.Errorf("servicebridge: the relay CA file is not a readable regular file of at most %d "+
			"bytes", maxRelayCABytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, errors.New("servicebridge: read the relay CA file")
	}
	parsed, err := parseRelayCA(data)
	if err != nil {
		return nil, nil, err
	}
	if err = parsed.checkValidAt(now); err != nil {
		return nil, nil, err
	}
	return data, parsed, nil
}

// initRelayCA is the relay trust decision of one `init` run: data to copy
// into state (a new pin), or the path of the pin kept from an earlier
// run, or nothing (system trust store).
type initRelayCA struct {
	data         []byte
	path         string
	sha256       string
	certificates int
}

// chooseRelayCA decides the pin of an `init` run. A new --relay-ca-file
// replaces the pin; --relay-system-roots drops it; a run naming neither
// keeps the pin of the existing configuration, which must still read back
// with its recorded digest. A pin needs at least one https relay of this
// node: plaintext loopback relays have no certificate to verify.
func chooseRelayCA(in InitInput, existing *NodeConfig, relays []string, now time.Time) (initRelayCA, error) {
	var chosen initRelayCA
	switch {
	case in.RelaySystemRoots:
		return chosen, nil
	case in.RelayCAFile != "":
		data, parsed, err := readRelayCASource(in.RelayCAFile, now)
		if err != nil {
			return chosen, err
		}
		chosen = initRelayCA{data: data, sha256: parsed.sha256, certificates: len(parsed.certificates)}
	case existing != nil && existing.RelayCAFile != "":
		if existing.StateDir != in.StateDir || existing.RelayCAFile != relayCAPath(in.StateDir) {
			return chosen, errors.New("servicebridge: the existing rail configuration pins a relay CA file of " +
				"another state directory; pass --relay-ca-file again, or --relay-system-roots")
		}
		parsed, err := loadRelayCA(*existing)
		if err != nil {
			return chosen, err
		}
		chosen = initRelayCA{path: existing.RelayCAFile, sha256: parsed.sha256, certificates: len(parsed.certificates)}
	default:
		return chosen, nil
	}
	if !slices.ContainsFunc(relays, func(relay string) bool { return strings.HasPrefix(relay, "https://") }) {
		return initRelayCA{}, errors.New("servicebridge: a relay CA file needs at least one https --relay-url: " +
			"plaintext loopback relays have no certificate to verify")
	}
	return chosen, nil
}

// relayCAPath is where `init` keeps the pinned CA file.
func relayCAPath(stateDir string) string {
	return filepath.Join(stateDir, relayStateDir, relayCAFileName)
}

// installRelayCA copies the CA file into the owner-only relay state
// directory, atomically.
func installRelayCA(stateDir string, data []byte) (string, error) {
	if err := ensurePrivateDirectory(filepath.Join(stateDir, relayStateDir)); err != nil {
		return "", err
	}
	path := relayCAPath(stateDir)
	if err := replaceSynced(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// loadRelayCA reads the pinned CA file of a configuration: nil without
// one. A configured pin that cannot be read, or whose digest differs from
// the one `init` recorded, is an error and never falls back to the system
// trust store. Validity is not checked here: an expired anchor fails the
// TLS handshake, and preflight reports it.
func loadRelayCA(config NodeConfig) (*relayCA, error) {
	if config.RelayCAFile == "" && config.RelayCASHA256 == "" {
		return nil, nil
	}
	if !cleanAbsolute(config.RelayCAFile) || !hex64Pattern.MatchString(config.RelayCASHA256) {
		return nil, errors.New("servicebridge: relay_ca_file must be an absolute clean path with its relay_ca_sha256")
	}
	data, err := readPrivateFile(config.RelayCAFile, maxRelayCABytes)
	if err != nil {
		return nil, errors.New("servicebridge: the pinned relay CA file cannot be read as an owner-only file; run " +
			"init again with --relay-ca-file")
	}
	parsed, err := parseRelayCA(data)
	if err != nil {
		return nil, err
	}
	if parsed.sha256 != config.RelayCASHA256 {
		return nil, errors.New("servicebridge: the pinned relay CA file changed since init recorded it; run init " +
			"again with --relay-ca-file")
	}
	return parsed, nil
}

// relayTrustOf names the trust anchor a connection to base uses: the
// pinned CA file for this node's own https relays when one is pinned, the
// system trust store for every other https relay (a relay only a peer's
// card names), and none for loopback http.
func relayTrustOf(config NodeConfig, base string) string {
	switch {
	case strings.HasPrefix(base, "http://"):
		return RelayTrustLoopback
	case config.RelayCAFile != "" && slices.Contains(config.RelayURLs, base):
		return RelayTrustPinned
	default:
		return RelayTrustSystem
	}
}

// relayDialerFor opens the relay clients of a configuration. With a
// pinned CA file, this node's own https relays verify their certificates
// against that file only; the system trust store is not consulted for
// them. Every other relay uses the default client.
func relayDialerFor(config NodeConfig) (relayDialer, error) {
	pinned, err := loadRelayCA(config)
	if err != nil {
		return nil, err
	}
	if pinned == nil {
		return dialRelay, nil
	}
	transport := pinnedRelayTransport(pinned.pool)
	own := append([]string(nil), config.RelayURLs...)
	return func(base string) (relayAPI, error) {
		if !slices.Contains(own, base) || !strings.HasPrefix(base, "https://") {
			return dialRelay(base)
		}
		client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{
			BaseURL: base, Timeout: RelayRequestTimeout, Transport: transport,
		})
		if err != nil {
			return nil, errors.New("servicebridge: the relay URL is not a canonical https (or loopback http) base URL")
		}
		return client, nil
	}, nil
}

// pinnedRelayTransport is the relay client's default transport with the
// pinned roots: direct connections only (no proxy environment), TLS 1.2 at
// least, and verification always on.
func pinnedRelayTransport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  RelayRequestTimeout,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		ForceAttemptHTTP2:      true,
	}
}
