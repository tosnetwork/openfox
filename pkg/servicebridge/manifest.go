package servicebridge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// ManifestInput names what an OpenFox rail manifest binds.
type ManifestInput struct {
	ProviderAgentID string
	// Actor is the raw workchain-0 Service Actor address (manifest key 21).
	Actor string
	// ActorCodeHash is tvm-cell-sha256:<hex> of the pinned release.
	ActorCodeHash string
	// Attestor is mldsa44:<key id> of the attestor controller (keys 18, 21).
	Attestor         string
	Version          string
	RetentionSeconds uint64
}

func digestOf(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RailTransport is the OpenFox quoted transport binding: Agent Packets to
// the provider Agent with the advertised 1 MiB inline input.
func RailTransport(providerAgentID string) (nativecore.TransportBindingV1, string, error) {
	binding, err := nativecore.AgentPacketTransportBinding(providerAgentID, MaxInlineInputBytes)
	if err != nil {
		return nativecore.TransportBindingV1{}, "", err
	}
	_, digest, err := nativecore.BuildTransportBindingCellV1(binding)
	return binding, digest, err
}

// RailLimits are the tos-ai frozen limits with the output bounded to what
// one result message delivers inline.
func RailLimits() nativecore.SoftwareWorkLimitsV1 {
	limits := softwarework.FrozenV1Limits()
	return nativecore.SoftwareWorkLimitsV1{
		CPUMillis:       limits.CPUMillis,
		MemoryBytes:     limits.MemoryBytes,
		ScratchBytes:    limits.DiskBytes,
		OutputBytes:     1 << 20,
		WallClockMillis: uint64(limits.ExecutionTime.Milliseconds()),
	}
}

// BuildManifest returns the canonical manifest CBOR and its digest.
func BuildManifest(input ManifestInput) ([]byte, string, nativecore.SoftwareWorkManifestV1, error) {
	var none nativecore.SoftwareWorkManifestV1
	if !agentIDPattern.MatchString(input.ProviderAgentID) || !rawAddressPattern.MatchString(input.Actor) ||
		input.Version == "" || input.RetentionSeconds == 0 {
		return nil, "", none, errors.New("servicebridge: the manifest input is incomplete")
	}
	if _, err := mldsa44.ParseKeyIDText(input.Attestor); err != nil {
		return nil, "", none, errors.New("servicebridge: the attestor must be mldsa44:<key id>")
	}
	codeHash, err := hex.DecodeString(strings.TrimPrefix(input.ActorCodeHash, "tvm-cell-sha256:"))
	if err != nil || len(codeHash) != 32 || !strings.HasPrefix(input.ActorCodeHash, "tvm-cell-sha256:") {
		return nil, "", none, errors.New("servicebridge: the actor code hash must be tvm-cell-sha256:<hex>")
	}
	account, _ := hex.DecodeString(input.Actor[2:])
	_, transportDigest, err := RailTransport(input.ProviderAgentID)
	if err != nil {
		return nil, "", none, err
	}
	contract := softwarework.FrozenV1Contract()
	manifest := nativecore.SoftwareWorkManifestV1{
		Protocol:            nativecore.SoftwareWorkManifestProtocolV1,
		Version:             input.Version,
		Name:                "Deterministic Go test",
		Description:         "Run the committed Go test suite of an inline source archive without network access.",
		Operation:           "test",
		AcceptedSourceKinds: []string{"content-addressed-archive"},
		InputSchemaDigest:   digestOf(taskSchema),
		OutputSchemaDigest:  digestOf("tos.service.software-work-report.v1"),
		ToolchainDigest:     contract.ToolchainDigest,
		Invocation: nativecore.SoftwareWorkInvocationV1{
			Executable: contract.Executable, Arguments: contract.Arguments,
			WorkingDirectory: contract.WorkingDirectory,
		},
		NetworkPolicy: "none",
		Limits:        RailLimits(),
		ArtifactMediaTypes: []string{
			softwarework.ArtifactMediaType,
		},
		ReportMediaTypes:             []string{softwarework.ReportMediaType},
		SuccessCondition:             "exit-code-zero-and-valid-reports",
		RefundConditions:             []string{nativecore.NoAttestedResponseRefund},
		EndpointCommitment:           transportDigest,
		ExecutionSignerAuthorization: nativecore.SettlementAttestorAuthorization(input.Attestor),
		RetentionSeconds:             input.RetentionSeconds,
		SupportedAssets:              []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.NativeTOSAsset}},
		Settlement: nativecore.SoftwareWorkSettlementV1{
			Rail: nativecore.ServiceActorRail, ActorWorkchain: 0,
			ActorAccountID: account, ActorCodeHash: codeHash, AttestorKey: input.Attestor,
		},
	}
	encoded, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		return nil, "", none, err
	}
	return encoded, digest, manifest, nil
}

// RunnerContract is the tos-ai runner contract for a published manifest.
func RunnerContract(manifestDigest string) softwarework.Contract {
	contract := softwarework.FrozenV1Contract()
	contract.ManifestDigest, contract.SandboxDigest = manifestDigest, manifestDigest
	contract.Limits.OutputBytes = 1 << 20
	return contract
}

// MetadataHash is the NSM1 metadata hash the actor's policy must carry for
// the published Capability version.
func MetadataHash(
	network *nativev1.NetworkDomain,
	capabilityID, providerAgentID, version, manifestDigest string,
) (string, error) {
	hash, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{
		Network:           network,
		CapabilityID:      capabilityID,
		ProviderAgentID:   providerAgentID,
		CapabilityVersion: version,
		ManifestDigest:    manifestDigest,
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash[:]), nil
}
