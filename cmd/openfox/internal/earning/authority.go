package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tosnetwork/openfox/cmd/openfox/internal"
	"github.com/tosnetwork/openfox/pkg/config"
	openfoxearning "github.com/tosnetwork/openfox/pkg/earning"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

func authorityCommand() *cobra.Command {
	command := &cobra.Command{Use: "authority", Short: "Run or inspect the owner economic Action Authority", Args: cobra.NoArgs}
	command.AddCommand(authorityServeCommand())
	return command
}

type authorityGrantDocument struct {
	Schema  string                 `json:"schema"`
	Clients []authorityClientGrant `json:"clients"`
}

type authorityClientGrant struct {
	SPKIDigest string   `json:"spki_digest"`
	OwnerID    string   `json:"owner_id"`
	AgentID    string   `json:"agent_id"`
	InstanceID string   `json:"instance_id"`
	Scopes     []string `json:"scopes"`
}

func authorityServeCommand() *cobra.Command {
	var listen, certificatePath, keyPath, clientCAPath, grantsPath string
	command := &cobra.Command{Use: "serve", Short: "Serve the shared owner Authority over mutually authenticated TLS", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			cfg, err := internal.LoadConfig()
			if err != nil {
				return err
			}
			if err := cfg.Earning.Validate(); err != nil {
				return err
			}
			if cfg.Earning.Authority.Mode != "shared" {
				return errors.New("authority serve requires earning.authority.mode=shared")
			}
			certificate, roots, err := loadTLSIdentity(certificatePath, keyPath, clientCAPath, true)
			if err != nil {
				return err
			}
			grants, err := loadAuthorityGrants(grantsPath, cfg.Earning)
			if err != nil {
				return err
			}
			backing, closeAuthority, err := openPersonalAuthority(cfg.Earning, true)
			if err != nil {
				return err
			}
			defer closeAuthority()
			authorities, err := openfoxearning.ParsePinnedIntentAuthorities(cfg.Earning.TrustedIntentIssuerKeys)
			if err != nil {
				return err
			}
			tlsConfig, err := openfoxearning.NewSharedAuthorityServerTLSConfig(certificate, roots)
			if err != nil {
				return err
			}
			listener, err := tls.Listen("tcp", listen, tlsConfig)
			if err != nil {
				return err
			}
			defer listener.Close()
			service := &openfoxearning.SharedAuthorityServer{Backing: backing,
				EvidenceVerifier: openfoxearning.AgreementEvidenceRouter{AgentAuthority: authorities}, ClientsBySPKI: grants}
			server := &http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			fmt.Fprintf(command.OutOrStdout(), "ready=true authority_id=%s listen=%s clients=%d tls=mutual\n", cfg.Earning.AuthorityID, listen, len(grants))
			select {
			case <-command.Context().Done():
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = server.Shutdown(ctx)
				err = <-done
			case err = <-done:
			}
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}}
	command.Flags().StringVar(&listen, "listen", "127.0.0.1:9444", "TCP listen address")
	command.Flags().StringVar(&certificatePath, "tls-cert", "", "absolute server certificate PEM")
	command.Flags().StringVar(&keyPath, "tls-key", "", "absolute mode-0600 server key PEM")
	command.Flags().StringVar(&clientCAPath, "client-ca", "", "absolute client CA PEM")
	command.Flags().StringVar(&grantsPath, "grants", "", "absolute bounded client grant JSON")
	_ = command.MarkFlagRequired("tls-cert")
	_ = command.MarkFlagRequired("tls-key")
	_ = command.MarkFlagRequired("client-ca")
	_ = command.MarkFlagRequired("grants")
	return command
}

func openConfiguredAuthority(settings config.EarningSettings, createPersonal bool) (openfoxearning.EconomicAuthority, func(), error) {
	mode := settings.Authority.Mode
	if mode == "" || mode == "personal" {
		return openPersonalAuthority(settings, createPersonal)
	}
	certificate, roots, err := loadTLSIdentity(settings.Authority.ClientCertFile, settings.Authority.ClientKeyFile, settings.Authority.CAFile, false)
	if err != nil {
		return nil, func() {}, err
	}
	httpClient, err := openfoxearning.NewSharedAuthorityHTTPClient(certificate, roots, settings.Authority.ServerName,
		time.Duration(settings.Authority.TimeoutMillis)*time.Millisecond)
	if err != nil {
		return nil, func() {}, err
	}
	public, err := decodeEd25519PublicKey(settings.Authority.AuthorityPublicKey)
	if err != nil {
		httpClient.CloseIdleConnections()
		return nil, func() {}, err
	}
	client, err := openfoxearning.NewSharedAuthorityClient(settings.Authority.Endpoint, httpClient, settings.AuthorityID, public)
	if err != nil {
		httpClient.CloseIdleConnections()
		return nil, func() {}, err
	}
	return client, httpClient.CloseIdleConnections, nil
}

func openPersonalAuthority(settings config.EarningSettings, create bool) (*openfoxearning.PersonalAuthority, func(), error) {
	directory := filepath.Join(settings.StateDir, "authority")
	if create {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, func() {}, err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, func() {}, err
		}
	}
	var key ed25519.PrivateKey
	var err error
	if create {
		key, err = loadOrCreateAuthorityKey(directory)
	} else {
		key, err = loadAuthorityKey(directory)
	}
	if err != nil {
		return nil, func() {}, err
	}
	maximumLoss, err := parsePortfolioLimit(settings.Policy.MaximumLossAtomic)
	if err != nil {
		return nil, func() {}, err
	}
	limits := openfoxearning.PortfolioLimits{ComputeUnits: settings.Resources.CPUUnits,
		SpendAtomic: settings.Resources.APIAtomicBudget, ReceivableAtomic: maximumLoss,
		MaximumLossAtomic: maximumLoss, CustodyFinalityGraceSeconds: settings.TOSPayment.CustodyFinalityGraceSeconds}
	if settings.Gates.DirectPayment {
		network := configuredRelayNetwork(settings.TOSPayment.Network)
		networkDigest, digestErr := agentrelay.NetworkDomainDigest(network)
		if digestErr != nil {
			for i := range key {
				key[i] = 0
			}
			return nil, func() {}, fmt.Errorf("direct payment authority network domain: %w", digestErr)
		}
		limits.CustodyNetworkDomainDigest = networkDigest
		limits.CustodySourceAccount = settings.TOSPayment.SourceAccount
		limits.CustodyNativeAsset = &commerce.AssetIdentityV1{AssetNamespace: "tos.asset",
			AssetIdentifier: "native", Unit: "nanotos"}
	}
	authority, err := openfoxearning.OpenPersonalAuthority(directory, settings.OwnerID, settings.AgentID, settings.AuthorityID, key, limits)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, func() {}, err
	}
	return authority, func() { _ = authority.Close() }, nil
}

func parsePortfolioLimit(value string) (uint64, error) {
	var parsed uint64
	for _, character := range value {
		if character < '0' || character > '9' || parsed > (^uint64(0)-uint64(character-'0'))/10 {
			return 0, errors.New("maximum loss does not fit the Portfolio implementation")
		}
		parsed = parsed*10 + uint64(character-'0')
	}
	return parsed, nil
}

func authorityInstanceID(settings config.EarningSettings, personalDefault string) string {
	if settings.Authority.Mode == "shared" {
		return settings.Authority.InstanceID
	}
	return personalDefault
}

func loadTLSIdentity(certificatePath, keyPath, rootsPath string, server bool) (tls.Certificate, *x509.CertPool, error) {
	certificatePEM, err := readBoundedRegular(certificatePath, 1<<20, false)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("TLS certificate: %w", err)
	}
	keyPEM, err := readBoundedRegular(keyPath, 1<<20, true)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("TLS private key: %w", err)
	}
	defer zeroBytes(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("TLS identity is invalid")
	}
	rootPEM, err := readBoundedRegular(rootsPath, 4<<20, false)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("TLS CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return tls.Certificate{}, nil, errors.New("TLS CA bundle contains no certificate")
	}
	if server && len(certificate.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("server certificate chain is empty")
	}
	return certificate, roots, nil
}

func readBoundedRegular(path string, maximum int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("path is not canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum ||
		private && info.Mode().Perm() != 0o600 {
		return nil, errors.New("file is not a bounded regular file with required permissions")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errors.New("file read exceeded bound")
	}
	return raw, nil
}

func loadAuthorityGrants(path string, settings config.EarningSettings) (map[string]openfoxearning.SharedAuthorityClientGrant, error) {
	raw, err := readBoundedRegular(path, 4<<20, false)
	if err != nil {
		return nil, err
	}
	var document authorityGrantDocument
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != "tos.openfox.shared-authority-grants.v1" || len(document.Clients) == 0 || len(document.Clients) > 1024 {
		return nil, errors.New("shared Authority grant document is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("shared Authority grant document has trailing values")
	}
	allowed := map[string]bool{}
	for _, scope := range configuredWriterScopes(settings) {
		allowed[scope] = true
	}
	result := make(map[string]openfoxearning.SharedAuthorityClientGrant, len(document.Clients))
	for _, grant := range document.Clients {
		if !canonicalDigest(grant.SPKIDigest) || grant.OwnerID != settings.OwnerID || grant.AgentID != settings.AgentID || grant.InstanceID == "" ||
			len(grant.Scopes) == 0 || len(grant.Scopes) > 64 {
			return nil, errors.New("shared Authority client grant is outside configured owner scope")
		}
		for index, scope := range grant.Scopes {
			if !allowed[scope] || index > 0 && grant.Scopes[index-1] >= scope {
				return nil, errors.New("shared Authority grant scopes must be sorted, unique, and configured")
			}
		}
		if _, duplicate := result[grant.SPKIDigest]; duplicate {
			return nil, errors.New("shared Authority client SPKI is duplicated")
		}
		result[grant.SPKIDigest] = openfoxearning.SharedAuthorityClientGrant{OwnerID: grant.OwnerID, AgentID: grant.AgentID,
			InstanceID: grant.InstanceID, Scopes: append([]string(nil), grant.Scopes...)}
	}
	return result, nil
}

func decodeEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("Authority public key is invalid")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("Authority public key is invalid")
	}
	return ed25519.PublicKey(raw), nil
}

func canonicalDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && strings.ToLower(value) == value
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
