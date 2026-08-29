package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/isolation"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type CapabilityAuthorizationBundle struct {
	SchemaVersion               uint16                         `json:"schema_version"`
	ConfigurationDigest         []byte                         `json:"configuration_digest"`
	ExpectedObservationDigest   []byte                         `json:"expected_observation_digest"`
	AllowedTools                []string                       `json:"allowed_tools"`
	MaximumArgumentBytes        uint64                         `json:"maximum_argument_bytes"`
	ExpectedEffectTool          string                         `json:"expected_effect_tool"`
	ExpectedEffectRequestDigest []byte                         `json:"expected_effect_request_digest"`
	ExpectedEffectActionID      []byte                         `json:"expected_effect_action_id"`
	Start                       capabilitycontrol.StartRequest `json:"start"`
}

type CapabilityAuthorizer struct{ Store *capabilitycontrol.Store }

func (authorizer CapabilityAuthorizer) Connection(ctx context.Context, name string, cfg config.MCPServerConfig) (ConnectionAuthorization, error) {
	bundle, err := authorizer.load(cfg)
	if err != nil {
		return ConnectionAuthorization{}, err
	}
	want, err := MCPConfigurationDigest(name, cfg)
	if err != nil || !bytes.Equal(want, bundle.ConfigurationDigest) {
		return ConnectionAuthorization{}, errors.New("MCP configuration differs from its capability authorization")
	}
	if config.EffectiveMCPTransportType(cfg) != "stdio" {
		return ConnectionAuthorization{}, errors.New("consequential remote MCP is disabled until an authenticated nonce-bound session profile is configured")
	}
	invocation, err := MCPInvocationDescriptorDigest(bundle.ConfigurationDigest, bundle.ExpectedObservationDigest, bundle.AllowedTools,
		bundle.MaximumArgumentBytes, bundle.ExpectedEffectTool, bundle.ExpectedEffectRequestDigest, bundle.ExpectedEffectActionID)
	if err != nil || !bytes.Equal(invocation, bundle.Start.Binding.InvocationDescriptorDigest) {
		return ConnectionAuthorization{}, errors.New("MCP invocation descriptor is not committed by capability authority")
	}
	var selected trusted.CapabilityPermissionManifestV1
	if trusted.DecodeBody(bundle.Start.PermissionSubsetObject, "permission-manifest", &selected) != nil || !equalStrings(selected.ToolCapabilities, bundle.AllowedTools) {
		return ConnectionAuthorization{}, errors.New("MCP tool scope differs from the signed permission subset")
	}
	if !computeOnlyMCPPermissions(selected) || len(cfg.Env) != 0 || cfg.EnvFile != "" {
		return ConnectionAuthorization{}, errors.New("local MCP currently supports only compute-only manifests with no ambient environment, filesystem, network, credential, disclosure, upload, destructive, or subprocess authority")
	}
	runtimeDigest, environmentDigest, credentialDigest, filesystemDigest, networkDigest, err := HermeticMCPRuntimeBindings()
	if err != nil {
		return ConnectionAuthorization{}, err
	}
	observed := bundle.Start.Observed
	if !bytes.Equal(observed.RuntimeAndSandboxDigest, runtimeDigest) || !bytes.Equal(observed.EffectiveEnvironmentDigest, environmentDigest) ||
		!bytes.Equal(observed.CredentialCapabilityReferenceSetDigest, credentialDigest) || !bytes.Equal(observed.FilesystemHandleSetDigest, filesystemDigest) ||
		!bytes.Equal(observed.NetworkBrokerPolicyDigest, networkDigest) || observed.RemoteSessionHandshakeDigest != nil {
		return ConnectionAuthorization{}, errors.New("MCP use binding does not select the released hermetic compute-only runtime")
	}
	entrypoint, source, err := authorizer.Store.OpenInstalledEntrypoint(bundle.Start.Binding.ArtifactVersionDigest)
	if err != nil || cfg.Command != entrypoint.Path || !equalStrings(cfg.Args, entrypoint.Arguments) {
		if source != nil {
			_ = source.Close()
		}
		return ConnectionAuthorization{}, errors.New("MCP command is not the admitted immutable entrypoint")
	}
	sealed, err := sealExecutable(source, entrypoint.ExecutableDigest)
	_ = source.Close()
	if err != nil {
		return ConnectionAuthorization{}, err
	}
	resolutionToken, err := authorizer.Store.PrepareUse(bundle.Start)
	if err != nil {
		_ = sealed.Close()
		return ConnectionAuthorization{}, err
	}
	executionID := append([]byte(nil), bundle.Start.Binding.ExecutionID...)
	return ConnectionAuthorization{Executable: sealed, Hermetic: true, BeforeStart: func() error {
		// The use slot is already durable. This is the last current-authority and
		// immutable-resource check before exec; the supported in-flight policy is
		// completion of that exact started slot, never creation of a successor.
		currentRuntime, _, _, _, _, runtimeErr := HermeticMCPRuntimeBindings()
		if runtimeErr != nil || !bytes.Equal(currentRuntime, runtimeDigest) {
			return errors.New("hermetic sandbox launcher changed after authorization")
		}
		return authorizer.Store.RevalidateUse(bundle.Start)
	}, Resolve: func(disposition string) error {
		return authorizer.Store.ResolveUse(executionID, resolutionToken, disposition)
	}}, nil
}

func (authorizer CapabilityAuthorizer) Session(_ context.Context, _ string, cfg config.MCPServerConfig, observation ConnectionObservation) error {
	bundle, err := authorizer.load(cfg)
	if err != nil {
		return err
	}
	digest, err := ConnectionObservationDigest(observation)
	if err != nil || !bytes.Equal(digest, bundle.ExpectedObservationDigest) {
		return errors.New("MCP session identity or tool descriptors changed")
	}
	return nil
}

func (authorizer CapabilityAuthorizer) Effect(ctx context.Context, server string, cfg config.MCPServerConfig, observation ConnectionObservation, tool string, exactArguments, exactRequestDigest []byte) ([]byte, error) {
	bundle, err := authorizer.load(cfg)
	if err != nil {
		return nil, err
	}
	digest, err := ConnectionObservationDigest(observation)
	if err != nil || !bytes.Equal(digest, bundle.ExpectedObservationDigest) {
		return nil, errors.New("MCP session changed before effect")
	}
	index := sort.SearchStrings(bundle.AllowedTools, tool)
	if index >= len(bundle.AllowedTools) || bundle.AllowedTools[index] != tool || bundle.MaximumArgumentBytes == 0 || bundle.MaximumArgumentBytes > 1<<20 {
		return nil, errors.New("MCP tool is outside admitted capability scope")
	}
	if len(exactArguments) == 0 || !json.Valid(exactArguments) || uint64(len(exactArguments)) > bundle.MaximumArgumentBytes {
		return nil, errors.New("MCP tool arguments exceed admitted bound")
	}
	wantRequest, err := mcpToolEffectRequestDigestFromWire(server, observation, tool, exactArguments)
	if err != nil || !bytes.Equal(wantRequest, exactRequestDigest) {
		return nil, errors.New("MCP request digest does not match the immutable pipe bytes")
	}
	if tool != bundle.ExpectedEffectTool || !bytes.Equal(exactRequestDigest, bundle.ExpectedEffectRequestDigest) {
		return nil, errors.New("MCP tool or exact arguments differ from the signed one-shot effect closure")
	}
	wantAction, err := MCPEffectActionID(bundle, tool)
	if err != nil || !bytes.Equal(wantAction, bundle.ExpectedEffectActionID) {
		return nil, errors.New("MCP effect does not match the released executor.effect semantic identity")
	}
	// RevalidateUse is a current-authority check that cannot create a slot. Expiry,
	// revocation, publisher status and changed installed bytes all fail before
	// the already-started slot is recognized.
	if err := authorizer.Store.RevalidateUse(bundle.Start); err != nil {
		return nil, err
	}
	return append([]byte(nil), bundle.ExpectedEffectActionID...), nil
}

func computeOnlyMCPPermissions(value trusted.CapabilityPermissionManifestV1) bool {
	return len(value.ProcessCapabilities) == 0 && len(value.FilesystemCapabilities) == 0 &&
		len(value.NetworkCapabilities) == 0 && len(value.CredentialCapabilities) == 0 &&
		len(value.DataClassesRead) == 0 && len(value.DataClassesWrite) == 0 &&
		len(value.DisclosureCapabilities) == 0 && len(value.UploadCapabilities) == 0 &&
		len(value.DestructiveCapabilities) == 0 && len(value.Extensions) == 0
}

// HermeticMCPRuntimeBindings are the released observed-resource digests for
// the current local MCP implementation. They describe one fixed environment,
// no broker handles and the Linux bubblewrap profile implemented by
// isolation.StartHermetic; callers cannot substitute config-derived values.
func HermeticMCPRuntimeBindings() (runtimeAndSandbox, environment, credentials, filesystem, network []byte, err error) {
	digest := func(label string) []byte {
		value := sha256.Sum256([]byte("tos.openfox-hermetic-mcp.v1/" + label))
		return value[:]
	}
	runtimeAndSandbox, err = isolation.HermeticRuntimeAndSandboxDigest()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return runtimeAndSandbox, digest("fixed-empty-environment"), digest("no-credential-handles"),
		digest("no-filesystem-handles"), digest("no-network-broker"), nil
}

func (authorizer CapabilityAuthorizer) load(cfg config.MCPServerConfig) (CapabilityAuthorizationBundle, error) {
	if authorizer.Store == nil || !filepath.IsAbs(cfg.CapabilityAuthorizationFile) || filepath.Clean(cfg.CapabilityAuthorizationFile) != cfg.CapabilityAuthorizationFile {
		return CapabilityAuthorizationBundle{}, errors.New("MCP capability authorization file is required and must be absolute")
	}
	file, err := os.Open(cfg.CapabilityAuthorizationFile)
	if err != nil {
		return CapabilityAuthorizationBundle{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 8<<20))
	decoder.DisallowUnknownFields()
	var bundle CapabilityAuthorizationBundle
	if decoder.Decode(&bundle) != nil || decoder.Decode(&struct{}{}) != io.EOF || bundle.SchemaVersion != 1 ||
		len(bundle.ConfigurationDigest) != sha256.Size || len(bundle.ExpectedObservationDigest) != sha256.Size ||
		len(bundle.ExpectedEffectRequestDigest) != sha256.Size || len(bundle.ExpectedEffectActionID) != sha256.Size || bundle.ExpectedEffectTool == "" ||
		len(bundle.AllowedTools) == 0 || !sort.StringsAreSorted(bundle.AllowedTools) {
		return CapabilityAuthorizationBundle{}, errors.New("MCP capability authorization bundle is invalid")
	}
	for index, tool := range bundle.AllowedTools {
		if tool == "" || index > 0 && tool == bundle.AllowedTools[index-1] {
			return CapabilityAuthorizationBundle{}, errors.New("MCP allowed tool set is not canonical")
		}
	}
	toolIndex := sort.SearchStrings(bundle.AllowedTools, bundle.ExpectedEffectTool)
	if toolIndex == len(bundle.AllowedTools) || bundle.AllowedTools[toolIndex] != bundle.ExpectedEffectTool {
		return CapabilityAuthorizationBundle{}, errors.New("MCP released effect tool is outside the allowed tool set")
	}
	return bundle, nil
}

func MCPConfigurationDigest(name string, cfg config.MCPServerConfig) ([]byte, error) {
	copy := cfg
	copy.CapabilityAuthorizationFile = ""
	raw, err := json.Marshal(struct {
		Name   string                 `json:"name"`
		Config config.MCPServerConfig `json:"config"`
	}{name, copy})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.openfox-mcp-configuration.v1\x00"), raw...))
	return digest[:], nil
}

func ConnectionObservationDigest(observation ConnectionObservation) ([]byte, error) {
	raw, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.openfox-mcp-observation.v1\x00"), raw...))
	return digest[:], nil
}

func MCPInvocationDescriptorDigest(configuration, observation []byte, tools []string, maximumArgumentBytes uint64, effectTool string, effectRequestDigest, effectActionID []byte) ([]byte, error) {
	if len(configuration) != sha256.Size || len(observation) != sha256.Size || len(tools) == 0 ||
		!sort.StringsAreSorted(tools) || maximumArgumentBytes == 0 || maximumArgumentBytes > 1<<20 || effectTool == "" ||
		len(effectRequestDigest) != sha256.Size || len(effectActionID) != sha256.Size {
		return nil, errors.New("MCP invocation descriptor is invalid")
	}
	raw, err := json.Marshal(struct {
		Configuration        []byte   `json:"configuration_digest"`
		Observation          []byte   `json:"expected_observation_digest"`
		Tools                []string `json:"allowed_tools"`
		MaximumArgumentBytes uint64   `json:"maximum_argument_bytes"`
		EffectTool           string   `json:"expected_effect_tool"`
		EffectRequestDigest  []byte   `json:"expected_effect_request_digest"`
		EffectActionID       []byte   `json:"expected_effect_action_id"`
	}{configuration, observation, tools, maximumArgumentBytes, effectTool, effectRequestDigest, effectActionID})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.openfox-mcp-invocation-descriptor.v1\x00"), raw...))
	return digest[:], nil
}

// MCPEffectActionID derives the released executor.effect identity that a plan
// compiler must place in the signed one-shot invocation closure.
func MCPEffectActionID(bundle CapabilityAuthorizationBundle, tool string) ([]byte, error) {
	binding := bundle.Start.Binding
	target := sha256.Sum256(bytes.Join([][]byte{[]byte("tos.openfox-mcp-effect-target.v1"), bundle.ConfigurationDigest, bundle.ExpectedObservationDigest}, []byte{0}))
	profile := sha256.Sum256([]byte("tos.openfox-mcp-executor-effect-profile.v1"))
	action, _, err := commerce.DeriveStableActionID("executor.effect", map[string]commerce.SemanticValue{
		"owner_id": commerce.ID(hex.EncodeToString(binding.OwnerID)), "agent_id": commerce.ID(hex.EncodeToString(binding.AgentID)),
		"agreement_body_digest": commerce.Digest32("sha256:" + hex.EncodeToString(binding.AgreementDigest)),
		"obligation_id":         commerce.ID(hex.EncodeToString(binding.ObligationID)), "execution_id": commerce.Digest32("sha256:" + hex.EncodeToString(binding.ExecutionID)),
		"plan_effect_id": commerce.ID(hex.EncodeToString(binding.ActionID)), "effect_profile_digest": commerce.Digest32("sha256:" + hex.EncodeToString(profile[:])),
		"target_digest": commerce.Digest32("sha256:" + hex.EncodeToString(target[:])), "operation_kind": commerce.Kind(tool),
		"effect_semantic_key_digest": commerce.Digest32("sha256:" + hex.EncodeToString(bundle.ExpectedEffectRequestDigest)),
	})
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(action[len("sha256:"):])
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
