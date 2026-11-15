package servicebridge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

// testCAValidUntil covers both the real clock the TLS tests run on and the
// fixtures' chain clock.
var testCAValidUntil = time.Unix(1_950_000_000, 0)

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

func newTestCA(t *testing.T, name string, notBefore, notAfter time.Time) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{certificate: certificate, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func newTestRelayCA(t *testing.T, name string) testCA {
	return newTestCA(t, name, time.Now().Add(-time.Hour), testCAValidUntil)
}

// serverCertificate issues a loopback relay certificate under the CA.
func (c testCA) serverCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.certificate, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSRelay runs the reference relay over TLS with a certificate of ca
// and returns its https base URL.
func startTLSRelay(t *testing.T, ca testCA) string {
	t.Helper()
	store, err := agentpacketrelay.NewMemoryStore(agentpacketrelay.DefaultLimits(4096, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	server, err := agentpacketrelay.NewServer(agentpacketrelay.ServerConfig{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server)
	listener.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCertificate(t)}, MinVersion: tls.VersionTLS12}
	listener.StartTLS()
	t.Cleanup(listener.Close)
	if !strings.HasPrefix(listener.URL, "https://127.0.0.1:") {
		t.Fatalf("relay URL %s", listener.URL)
	}
	return listener.URL
}

// pinnedConfig is a node configuration whose relays are pinned to ca.
func pinnedConfig(t *testing.T, ca testCA, relays ...string) NodeConfig {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDirectory(state); err != nil {
		t.Fatal(err)
	}
	path, err := installRelayCA(state, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ca.pem)
	return NodeConfig{StateDir: state, RelayURLs: relays, RelayCAFile: path, RelayCASHA256: hex.EncodeToString(digest[:])}
}

func describeWith(dial relayDialer, base string) error {
	client, err := dial(base)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.Describe(ctx)
	return err
}

func isUnknownAuthority(err error) bool {
	var unknown x509.UnknownAuthorityError
	return errors.As(err, &unknown)
}

func TestARelayWithAPrivateCAIsTrustedWithThePinOnly(t *testing.T) {
	private, unrelated := newTestRelayCA(t, "private relay CA"), newTestRelayCA(t, "unrelated CA")
	relay := startTLSRelay(t, private)

	pinned, err := relayDialerFor(pinnedConfig(t, private, relay))
	if err != nil {
		t.Fatal(err)
	}
	if err = describeWith(pinned, relay); err != nil {
		t.Fatalf("the pinned relay was refused: %v", err)
	}
	// Without a pin the system trust store decides, and it does not hold
	// the private authority.
	unpinned, err := relayDialerFor(NodeConfig{RelayURLs: []string{relay}})
	if err != nil {
		t.Fatal(err)
	}
	if err = describeWith(unpinned, relay); !isUnknownAuthority(err) {
		t.Fatalf("without the pin: %v", err)
	}
	wrong, err := relayDialerFor(pinnedConfig(t, unrelated, relay))
	if err != nil {
		t.Fatal(err)
	}
	if err = describeWith(wrong, relay); !isUnknownAuthority(err) {
		t.Fatalf("pinned to an unrelated authority: %v", err)
	}
	// A relay only a peer's card names does not get this node's pin.
	other := startTLSRelay(t, private)
	if err = describeWith(pinned, other); !isUnknownAuthority(err) {
		t.Fatalf("a relay outside relay_urls used the pin: %v", err)
	}
	config := pinnedConfig(t, private, relay)
	for base, want := range map[string]string{
		relay: RelayTrustPinned, other: RelayTrustSystem, "http://127.0.0.1:9": RelayTrustLoopback,
	} {
		if got := relayTrustOf(config, base); got != want {
			t.Errorf("trust of %s = %s, want %s", base, got, want)
		}
	}
}

const relayTrustChildEnv = "OPENFOX_RELAY_TRUST_CHILD"

// The system trust store is process-wide and loaded once, so the check
// that a pin never consults it runs in a child process whose only system
// root is the relay's authority.
func TestPinnedRelaysNeverConsultTheSystemTrustStore(t *testing.T) {
	if os.Getenv(relayTrustChildEnv) == "1" {
		relayTrustChild(t)
		return
	}
	dir := t.TempDir()
	systemCA := newTestRelayCA(t, "system relay CA")
	roots := filepath.Join(dir, "system-roots.pem")
	if err := os.WriteFile(roots, systemCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(dir, "empty-cert-dir")
	if err := os.Mkdir(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "system-ca-key.der")
	der, err := x509.MarshalECPrivateKey(systemCA.key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, der, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPinnedRelaysNeverConsultTheSystemTrustStore$", "-test.v")
	command.Env = append(os.Environ(), relayTrustChildEnv+"=1", "SSL_CERT_FILE="+roots, "SSL_CERT_DIR="+certDir,
		"OPENFOX_RELAY_TRUST_CA_KEY="+keyFile)
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("relay trust child: all checks ran")) {
		t.Fatalf("child: %v\n%s", err, output)
	}
}

func relayTrustChild(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("SSL_CERT_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no system root")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := os.ReadFile(os.Getenv("OPENFOX_RELAY_TRUST_CA_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	systemCA := testCA{certificate: certificate, key: key, pem: data}
	relay, peerOnly := startTLSRelay(t, systemCA), startTLSRelay(t, systemCA)

	// The system trust store of this process holds the relay's authority.
	if err = describeWith(dialRelay, relay); err != nil {
		t.Fatalf("the system trust store does not trust the relay: %v", err)
	}
	// Pinned to another authority, the relay is refused although the
	// system trust store would accept it.
	pinned, err := relayDialerFor(pinnedConfig(t, newTestRelayCA(t, "pinned CA"), relay))
	if err != nil {
		t.Fatal(err)
	}
	if err = describeWith(pinned, relay); !isUnknownAuthority(err) {
		t.Fatalf("a pinned relay was verified against the system trust store: %v", err)
	}
	// A relay outside relay_urls keeps the system trust store.
	if err = describeWith(pinned, peerOnly); err != nil {
		t.Fatalf("a peer-only relay did not use the system trust store: %v", err)
	}
	t.Log("relay trust child: all checks ran")
}

func TestTheRelayCAFileHoldsOnlyCurrentCertificates(t *testing.T) {
	ca := newTestRelayCA(t, "relay CA")
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	second := newTestRelayCA(t, "second relay CA")
	if parsed, err := parseRelayCA(append(append([]byte("\n"), ca.pem...), second.pem...)); err != nil ||
		len(parsed.certificates) != 2 {
		t.Fatalf("two certificates: %v", err)
	}
	many := bytes.Repeat(ca.pem, maxRelayCACertificates)
	if _, err := parseRelayCA(many); err != nil {
		t.Fatalf("%d certificates: %v", maxRelayCACertificates, err)
	}
	headed := bytes.Replace(ca.pem, []byte("-----\n"), []byte("-----\nProc-Type: 4,ENCRYPTED\n\n"), 1)
	for name, data := range map[string][]byte{
		"empty":                 {},
		"whitespace only":       []byte("\n\n"),
		"a private key":         keyPEM,
		"a certificate and key": append(append([]byte{}, ca.pem...), keyPEM...),
		"text before":           append([]byte("issuer: relay\n"), ca.pem...),
		"text after":            append(append([]byte{}, ca.pem...), []byte("trailing\n")...),
		"a PEM header":          headed,
		"a broken block":        []byte("-----BEGIN CERTIFICATE-----\nAAAA\n"),
		"not a certificate":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"too many":              append(many, ca.pem...),
	} {
		if _, err := parseRelayCA(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(source, ca.pem, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRelayCASource(source, time.Now()); err != nil {
		t.Fatalf("a current CA file: %v", err)
	}
	if _, _, err := readRelayCASource(source, testCAValidUntil.Add(time.Second)); !errors.Is(err, errRelayCAExpired) {
		t.Fatalf("an expired CA file: %v", err)
	}
	if _, _, err := readRelayCASource(dir, time.Now()); err == nil {
		t.Fatal("a directory was read as a CA file")
	}
}

func TestAPinnedCAFileThatChangedOrIsNotOwnerOnlyStopsTheRelayClient(t *testing.T) {
	ca := newTestRelayCA(t, "relay CA")
	config := pinnedConfig(t, ca, "https://relay.example")
	if _, err := relayDialerFor(config); err != nil {
		t.Fatal(err)
	}
	changed := config
	changed.RelayCASHA256 = strings.Repeat("00", 32)
	if _, err := relayDialerFor(changed); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("a changed digest: %v", err)
	}
	if err := os.Chmod(config.RelayCAFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := relayDialerFor(config); err == nil {
		t.Fatal("a pin readable by others was used")
	}
	missing := config
	missing.RelayCAFile = filepath.Join(config.StateDir, "absent.pem")
	if _, err := relayDialerFor(missing); err == nil {
		t.Fatal("a missing pin fell back to the system trust store")
	}
	half := config
	half.RelayCASHA256 = ""
	if _, err := relayDialerFor(half); err == nil {
		t.Fatal("a pin without its digest was used")
	}
}

func TestInitPinsTheRelayCAKeepsItOnARerunAndDropsItOnRequest(t *testing.T) {
	f := newSetupFixture(t)
	ca := newTestRelayCA(t, "relay CA")
	source := filepath.Join(f.root, "relay-ca.pem")
	writeFixtureFile(t, source, ca.pem, 0o644)
	f.init.MessengerSocket, f.init.RelayURLs, f.init.RelayCAFile = "", []string{"https://relay.example"}, source
	f.mustInit(t)
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ca.pem)
	if config.RelayCAFile != relayCAPath(f.init.StateDir) || config.RelayCASHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("configuration = %+v", config)
	}
	copied, err := readPrivateFile(config.RelayCAFile, maxRelayCABytes)
	if err != nil || !bytes.Equal(copied, ca.pem) {
		t.Fatalf("the pin is not an owner-only copy: %v", err)
	}
	// The original may change or go away: the node uses its copy.
	if err = os.Remove(source); err != nil {
		t.Fatal(err)
	}
	f.init.RelayCAFile = ""
	f.mustInit(t)
	if kept, err := LoadNodeConfig(f.init.RailConfigPath); err != nil || kept.RelayCASHA256 != config.RelayCASHA256 ||
		kept.RelayCAFile != config.RelayCAFile {
		t.Fatalf("a re-run dropped the pin: %+v %v", kept, err)
	}
	f.init.RelaySystemRoots = true
	f.mustInit(t)
	if dropped, err := LoadNodeConfig(f.init.RailConfigPath); err != nil || dropped.RelayCAFile != "" ||
		dropped.RelayCASHA256 != "" {
		t.Fatalf("--relay-system-roots kept the pin: %+v %v", dropped, err)
	}
}

func TestInitRefusesARelayCAFileItCannotPinBeforeTouchingAnything(t *testing.T) {
	ca := newTestRelayCA(t, "relay CA")
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	expired := newTestCA(t, "expired CA", time.Unix(1_000_000_000, 0), time.Unix(1_100_000_000, 0))
	for name, setup := range map[string]func(f *setupFixture){
		"a private key in the file": func(f *setupFixture) {
			writeFixtureFile(t, f.init.RelayCAFile, append(append([]byte{}, ca.pem...),
				pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...), 0o600)
		},
		"an expired certificate": func(f *setupFixture) { writeFixtureFile(t, f.init.RelayCAFile, expired.pem, 0o600) },
		"no https relay": func(f *setupFixture) {
			writeFixtureFile(t, f.init.RelayCAFile, ca.pem, 0o600)
			f.init.RelayURLs = []string{"http://127.0.0.1:9"}
		},
		"both flags": func(f *setupFixture) {
			writeFixtureFile(t, f.init.RelayCAFile, ca.pem, 0o600)
			f.init.RelaySystemRoots = true
		},
		"a relative path": func(f *setupFixture) { f.init.RelayCAFile = "relay-ca.pem" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			f.init.RelayURLs, f.init.RelayCAFile = []string{"https://relay.example"}, filepath.Join(f.root, "ca.pem")
			setup(f)
			want := map[string]string{
				"a private key in the file": "only PEM CERTIFICATE blocks", "an expired certificate": "expired",
				"no https relay": "at least one https", "both flags": "exclude each other",
				"a relative path": "--relay-ca-file must be an absolute clean path",
			}[name]
			if _, err := RunInit(context.Background(), f.init, f.env()); err == nil ||
				!strings.Contains(err.Error(), want) {
				t.Fatalf("init: %v, want %q", err, want)
			}
			if len(f.world().Calls) != 0 {
				t.Fatal("tosctl was run")
			}
			if _, err := os.Lstat(relayCAPath(f.init.StateDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused CA file was copied: %v", err)
			}
		})
	}
}

func TestPreflightReportsEachRelaysTrustAnchorAndFailsOnAnUnusablePin(t *testing.T) {
	f, relay := relayPreflight(t, true)
	_, checks := f.run(t)
	if check := checks["relay.trust"]; check.Status != CheckPass ||
		!strings.Contains(check.Message, relay.URL+": plaintext loopback") {
		t.Fatalf("unpinned: %+v", check)
	}
	ca := newTestRelayCA(t, "relay CA")
	path, err := installRelayCA(f.config.StateDir, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ca.pem)
	f.config.RelayURLs = []string{relay.URL, "https://relay.example"}
	f.config.RelayCAFile, f.config.RelayCASHA256 = path, hex.EncodeToString(digest[:])
	_, checks = f.run(t)
	if check := checks["relay.trust"]; check.Status != CheckPass ||
		!strings.Contains(check.Message, "https://relay.example: the pinned CA file only") ||
		!strings.Contains(check.Message, f.config.RelayCASHA256) {
		t.Fatalf("pinned: %+v", check)
	}
	f.env.Now = func() time.Time { return testCAValidUntil.Add(-24 * time.Hour) }
	if _, checks = f.run(t); checks["relay.trust"].Status != CheckWarn {
		t.Fatalf("expiring: %+v", checks["relay.trust"])
	}
	f.env.Now = func() time.Time { return testCAValidUntil.Add(time.Hour) }
	if _, checks = f.run(t); checks["relay.trust"].Status != CheckFail || checks["relay.reachable"].Status != CheckFail {
		t.Fatalf("expired: %+v %+v", checks["relay.trust"], checks["relay.reachable"])
	}
	f.env.Now = func() time.Time { return pfChainNow }
	if err = os.WriteFile(path, newTestRelayCA(t, "other CA").pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, checks = f.run(t); checks["relay.trust"].Status != CheckFail {
		t.Fatalf("changed: %+v", checks["relay.trust"])
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, checks = f.run(t); checks["relay.trust"].Status != CheckFail {
		t.Fatalf("unreadable: %+v", checks["relay.trust"])
	}
}
