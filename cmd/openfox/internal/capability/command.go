package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type options struct {
	stateDir, authorityEndpoint, authorityTokenFile, authorityPublicKey string
	publisherDir, quarantineRoot, owner, agent                          string
}

func NewCommand() *cobra.Command {
	var opts options
	command := &cobra.Command{Use: "capability", Short: "Inspect and control the owner-scoped trusted capability inventory"}
	command.PersistentFlags().StringVar(&opts.stateDir, "state-dir", "", "trusted capability state directory")
	command.PersistentFlags().StringVar(&opts.authorityEndpoint, "authority-endpoint", "", "external HTTPS control-authority endpoint")
	command.PersistentFlags().StringVar(&opts.authorityTokenFile, "authority-token-file", "", "private 0600 bearer-token file for the control authority")
	command.PersistentFlags().StringVar(&opts.authorityPublicKey, "authority-public-key", "", "pinned ed25519:<hex> control-authority response key")
	command.PersistentFlags().StringVar(&opts.publisherDir, "publisher-observation-dir", "", "signed publisher revocation observation directory")
	command.PersistentFlags().StringVar(&opts.quarantineRoot, "quarantine-root", "", "absolute trusted capability quarantine directory")
	command.PersistentFlags().StringVar(&opts.owner, "owner", "", "owner identity")
	command.PersistentFlags().StringVar(&opts.agent, "agent", "", "Agent identity")
	command.AddCommand(listCommand(&opts), importLegacyCommand(&opts), bootstrapCommand(&opts), rotatePolicyCommand(&opts), issueSessionCommand(&opts),
		quarantineCommand(&opts), verifyCommand(&opts), admitCommand(&opts), promoteCommand(&opts), installCommand(&opts),
		quarantineReceiptsCommand(&opts),
		recoverOutcomeCommand(&opts),
		renderConfirmationCommand(), wrapBodyCommand(), signAuthorizationCommand())
	return command
}

func quarantineReceiptsCommand(opts *options) *cobra.Command {
	return &cobra.Command{Use: "quarantine-receipts", Short: "Export durable acquisition receipts for Inventory registration", RunE: func(cmd *cobra.Command, _ []string) error {
		if opts.owner == "" || opts.agent == "" || !filepath.IsAbs(opts.quarantineRoot) || filepath.Clean(opts.quarantineRoot) != opts.quarantineRoot {
			return errors.New("--owner, --agent, and a canonical absolute --quarantine-root are required")
		}
		authority, err := capabilitycontrol.OpenHTTPSControlAuthorityFromFile(opts.authorityEndpoint, opts.authorityTokenFile, opts.authorityPublicKey)
		if err != nil {
			return err
		}
		defer authority.Close()
		ledger, err := capabilitycontrol.OpenQuarantineLedger(opts.quarantineRoot, time.Now, authority, []byte(opts.owner), []byte(opts.agent))
		if err != nil {
			return err
		}
		defer ledger.Close()
		receipts, err := ledger.CommitReceipts()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(receipts)
	}}
}

type confirmationInput struct {
	Effect        trusted.OwnerCommandEffectV1               `json:"effect"`
	Parameters    capabilitycontrol.OwnerCommandParametersV1 `json:"parameters"`
	ActionID      []byte                                     `json:"action_id"`
	ExpiresAtUnix uint64                                     `json:"expires_at_unix"`
}

func renderConfirmationCommand() *cobra.Command {
	var path string
	command := &cobra.Command{Use: "render-confirmation", Short: "Deterministically render the exact human-facing Owner Command confirmation", RunE: func(cmd *cobra.Command, _ []string) error {
		var input confirmationInput
		if err := decodeStrictJSONFile(path, &input, 2<<20); err != nil {
			return err
		}
		confirmation, err := capabilitycontrol.RenderOwnerCommandConfirmation(input.Effect, input.Parameters, input.ActionID, input.ExpiresAtUnix)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(confirmation)
	}}
	command.Flags().StringVar(&path, "request-file", "", "absolute effect, parameter, Action ID, and expiry JSON")
	_ = command.MarkFlagRequired("request-file")
	return command
}

func lifecycleRequestCommand(opts *options, use, short string, target any, apply func(*capabilitycontrol.Store) error) *cobra.Command {
	var path string
	command := &cobra.Command{Use: use, Short: short, RunE: func(_ *cobra.Command, _ []string) error {
		if err := decodeStrictJSONFile(path, target, 32<<20); err != nil {
			return err
		}
		store, authority, err := opts.open()
		if err != nil {
			return err
		}
		defer store.Close()
		defer authority.Close()
		return apply(store)
	}}
	command.Flags().StringVar(&path, "request-file", "", "absolute typed and signed lifecycle request JSON")
	_ = command.MarkFlagRequired("request-file")
	return command
}

type quarantineRequest struct {
	Entry   capabilitycontrol.Entry                   `json:"entry"`
	Receipt capabilitycontrol.QuarantineCommitReceipt `json:"receipt"`
}

func quarantineCommand(opts *options) *cobra.Command {
	request := &quarantineRequest{}
	return lifecycleRequestCommand(opts, "quarantine", "Register exact downloaded bytes in the quarantine inventory", request, func(store *capabilitycontrol.Store) error {
		now, err := store.TrustedNow()
		if err != nil {
			return err
		}
		return store.RegisterQuarantined(context.Background(), request.Entry, request.Receipt, time.Unix(int64(now), 0).UTC())
	})
}

func verifyCommand(opts *options) *cobra.Command {
	request := &capabilitycontrol.VerificationRequest{}
	return lifecycleRequestCommand(opts, "verify", "Verify a quarantined candidate and its signed evidence", request, func(store *capabilitycontrol.Store) error { return store.VerifyCandidate(*request) })
}

func admitCommand(opts *options) *cobra.Command {
	request := &capabilitycontrol.AdmissionRequest{}
	return lifecycleRequestCommand(opts, "admit", "Apply an exact signed owner admission", request, func(store *capabilitycontrol.Store) error { return store.Admit(*request) })
}

func promoteCommand(opts *options) *cobra.Command {
	request := &capabilitycontrol.PromotionRequest{}
	return lifecycleRequestCommand(opts, "promote", "Apply independent promotion evidence for a high-risk capability", request, func(store *capabilitycontrol.Store) error { return store.Promote(*request) })
}

func installCommand(opts *options) *cobra.Command {
	request := &capabilitycontrol.InstallationRequest{}
	return lifecycleRequestCommand(opts, "install", "Materialize an admitted capability through the installation fence", request, func(store *capabilitycontrol.Store) error {
		_, err := store.Install(*request)
		return err
	})
}

func recoverOutcomeCommand(opts *options) *cobra.Command {
	request := &capabilitycontrol.ActionOutcomeRecoveryRequest{}
	return lifecycleRequestCommand(opts, "recover-outcome", "Resolve an ambiguous MCP or capability execution from exact signed sink evidence", request,
		func(store *capabilitycontrol.Store) error { return store.RecoverAmbiguousAction(*request) })
}

func decodeStrictJSONFile(path string, output any, maximum int64) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("input path must be canonical and absolute")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return errors.New("input file is unavailable or unbounded")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(output); err != nil {
		return err
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("input contains trailing JSON")
	}
	return nil
}

func bootstrapCommand(opts *options) *cobra.Command {
	var path string
	command := &cobra.Command{Use: "bootstrap", Short: "Apply a fully signed owner bootstrap bundle", RunE: func(_ *cobra.Command, _ []string) error {
		var request capabilitycontrol.BootstrapRequest
		if err := decodeStrictJSONFile(path, &request, 8<<20); err != nil {
			return err
		}
		store, authority, err := opts.open()
		if err != nil {
			return err
		}
		defer store.Close()
		defer authority.Close()
		return store.Bootstrap(request)
	}}
	command.Flags().StringVar(&path, "request-file", "", "absolute signed bootstrap request JSON")
	_ = command.MarkFlagRequired("request-file")
	return command
}
func rotatePolicyCommand(opts *options) *cobra.Command {
	var path string
	command := &cobra.Command{Use: "rotate-policy", Short: "Apply a signed successor owner policy", RunE: func(_ *cobra.Command, _ []string) error {
		var request capabilitycontrol.PolicyRotationRequest
		if err := decodeStrictJSONFile(path, &request, 8<<20); err != nil {
			return err
		}
		store, authority, err := opts.open()
		if err != nil {
			return err
		}
		defer store.Close()
		defer authority.Close()
		return store.RotatePolicy(request)
	}}
	command.Flags().StringVar(&path, "request-file", "", "absolute signed policy rotation JSON")
	_ = command.MarkFlagRequired("request-file")
	return command
}
func issueSessionCommand(opts *options) *cobra.Command {
	var path string
	command := &cobra.Command{Use: "issue-session", Short: "Issue a signed owner device session", RunE: func(_ *cobra.Command, _ []string) error {
		var request capabilitycontrol.DeviceSessionRequest
		if err := decodeStrictJSONFile(path, &request, 8<<20); err != nil {
			return err
		}
		store, authority, err := opts.open()
		if err != nil {
			return err
		}
		defer store.Close()
		defer authority.Close()
		return store.IssueDeviceSession(request)
	}}
	command.Flags().StringVar(&path, "request-file", "", "absolute signed device-session request JSON")
	_ = command.MarkFlagRequired("request-file")
	return command
}

func wrapBodyCommand() *cobra.Command {
	var kind, domainHex, input string
	var domainKind uint8
	command := &cobra.Command{Use: "wrap-body", Short: "Create the canonical trusted-capability wrapper for a typed JSON body", RunE: func(cmd *cobra.Command, _ []string) error {
		body, err := trusted.NewBodyValue(kind)
		if err != nil {
			return err
		}
		if err = decodeStrictJSONFile(input, body, trusted.MaxCanonicalBytes); err != nil {
			return err
		}
		domain, err := hex.DecodeString(domainHex)
		if err != nil {
			return err
		}
		object, err := trusted.NewObject(trusted.DomainKind(domainKind), domain, kind, body)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(object)
	}}
	command.Flags().StringVar(&kind, "kind", "", "released object kind")
	command.Flags().Uint8Var(&domainKind, "domain-kind", 0, "1 for TOS network or 2 for owner-local")
	command.Flags().StringVar(&domainHex, "domain-id-hex", "", "canonical domain ID hex")
	command.Flags().StringVar(&input, "body-file", "", "absolute typed body JSON")
	for _, name := range []string{"kind", "domain-kind", "domain-id-hex", "body-file"} {
		_ = command.MarkFlagRequired(name)
	}
	return command
}

type authorizationSigningInput struct {
	Body           trusted.ProfileAuthorizationEnvelopeBodyV1 `json:"body"`
	Proof          trusted.ProfileAuthorizationProofV1        `json:"proof"`
	PrivateKeyFile string                                     `json:"private_key_file"`
}

func signAuthorizationCommand() *cobra.Command {
	var path string
	command := &cobra.Command{Use: "sign-authorization", Short: "Sign one exact authorization envelope with a private Ed25519 key", RunE: func(cmd *cobra.Command, _ []string) error {
		var input authorizationSigningInput
		if err := decodeStrictJSONFile(path, &input, 2<<20); err != nil {
			return err
		}
		info, err := os.Stat(input.PrivateKeyFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("private key must be a 0600 regular file")
		}
		raw, err := os.ReadFile(input.PrivateKeyFile)
		if err != nil {
			return err
		}
		keyBytes, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
		if err != nil {
			return err
		}
		var key ed25519.PrivateKey
		if len(keyBytes) == ed25519.SeedSize {
			key = ed25519.NewKeyFromSeed(keyBytes)
		} else if len(keyBytes) == ed25519.PrivateKeySize {
			key = ed25519.PrivateKey(keyBytes)
		} else {
			return errors.New("private key must contain Ed25519 seed or private-key hex")
		}
		envelope, err := trusted.SignAuthorization(input.Body, []trusted.ProfileAuthorizationProofV1{input.Proof}, []ed25519.PrivateKey{key})
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(envelope)
	}}
	command.Flags().StringVar(&path, "input-file", "", "absolute authorization signing input JSON")
	_ = command.MarkFlagRequired("input-file")
	return command
}

func (opts *options) open() (*capabilitycontrol.Store, capabilitycontrol.ProductionAuthority, error) {
	if opts.owner == "" || opts.agent == "" {
		return nil, nil, errors.New("--owner and --agent are required")
	}
	root := opts.stateDir
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, err
		}
		root = filepath.Join(home, ".openfox", "trusted-capabilities", hex.EncodeToString([]byte(opts.owner)), hex.EncodeToString([]byte(opts.agent)))
	}
	if !filepath.IsAbs(opts.authorityTokenFile) || !filepath.IsAbs(opts.publisherDir) {
		return nil, nil, errors.New("--authority-token-file and --publisher-observation-dir must be absolute")
	}
	authority, err := capabilitycontrol.OpenHTTPSControlAuthorityFromFile(opts.authorityEndpoint, opts.authorityTokenFile, opts.authorityPublicKey)
	if err != nil {
		return nil, nil, err
	}
	store, productionAuthority, err := capabilitycontrol.OpenProduction(capabilitycontrol.ProductionStoreOptions{ProjectionRoot: root, Authority: authority,
		PublisherObservationDirectory: opts.publisherDir,
		DomainKind:                    trusted.DomainOwnerLocal, DomainID: []byte(opts.owner), OwnerID: []byte(opts.owner), AgentID: []byte(opts.agent)})
	if err != nil {
		_ = authority.Close()
		return nil, nil, err
	}
	return store, productionAuthority, nil
}

func listCommand(opts *options) *cobra.Command {
	return &cobra.Command{Use: "list", Short: "Print the evidence-backed local capability projection", RunE: func(cmd *cobra.Command, _ []string) error {
		store, authority, err := opts.open()
		if err != nil {
			return err
		}
		defer store.Close()
		defer authority.Close()
		snapshot, err := store.Inventory(5 * time.Minute)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	}}
}

func importLegacyCommand(opts *options) *cobra.Command {
	var roots []string
	command := &cobra.Command{Use: "import-legacy", Short: "Classify existing Skills as UNVERIFIED_LEGACY", RunE: func(cmd *cobra.Command, _ []string) error {
		if len(roots) == 0 {
			return errors.New("at least one --skill-root is required")
		}
		store, authority, err := opts.open()
		if err != nil {
			return err
		}
		defer store.Close()
		defer authority.Close()
		if err := store.ImportLegacySkillRoots(roots, time.Now()); err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "legacy capabilities imported fail-closed")
		return err
	}}
	command.Flags().StringSliceVar(&roots, "skill-root", nil, "loader-visible Skill root (repeatable)")
	return command
}
