package nativeimpl

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/opportunity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/gatewayfederation"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

type opportunityGatewayFake struct {
	search   *nativev1.SearchCapabilitiesResponse
	manifest *nativev1.GetSoftwareWorkManifestResponse
	err      error
}

func (f opportunityGatewayFake) SearchCapabilities(context.Context, *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return proto.Clone(f.search).(*nativev1.SearchCapabilitiesResponse), nil
}

func (f opportunityGatewayFake) GetSoftwareWorkManifest(context.Context, *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return proto.Clone(f.manifest).(*nativev1.GetSoftwareWorkManifestResponse), nil
}

type opportunityNativeFake struct{ state *nativev1.NativeStateV1 }

func (f opportunityNativeFake) ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(f.state).(*nativev1.NativeStateV1)}, nil
}

func opportunityCoordinatorFixture(t *testing.T) (*OpportunityCoordinator, opportunity.CandidateHint, *nativev1.NativeStateV1) {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: "sha256:" + strings.Repeat("a", 64),
		GenesisFileHash: "sha256:" + strings.Repeat("b", 64)}
	registry := "tvm-cell-sha256:" + strings.Repeat("c", 64)
	capabilityID := "cap_" + strings.Repeat("d", 64)
	provider := "agent_" + strings.Repeat("e", 64)
	manifest := nativecore.SoftwareWorkManifestV1{Protocol: nativecore.SoftwareWorkManifestProtocolV1,
		Version: "1.0.0", Name: "Deterministic test work", Description: "Run bounded tests", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive"}, InputSchemaDigest: "sha256:" + strings.Repeat("1", 64),
		OutputSchemaDigest: "sha256:" + strings.Repeat("2", 64), ToolchainDigest: "sha256:" + strings.Repeat("3", 64),
		Invocation:    nativecore.SoftwareWorkInvocationV1{Executable: "/usr/bin/test-runner", Arguments: []string{"--input", "${INPUT}", "--output", "${OUTPUT}"}, WorkingDirectory: "/workspace/source"},
		NetworkPolicy: "none", Limits: nativecore.SoftwareWorkLimitsV1{CPUMillis: 1000, MemoryBytes: 16 << 20,
			ScratchBytes: 1 << 20, OutputBytes: 1 << 20, WallClockMillis: 1000},
		ArtifactMediaTypes: []string{"application/octet-stream"}, ReportMediaTypes: []string{"application/json"},
		SuccessCondition: "exit-code-zero-and-valid-reports", RefundConditions: []string{"not-started-before-deadline"},
		EndpointCommitment: "sha256:" + strings.Repeat("4", 64), ExecutionSignerAuthorization: "sha256:" + strings.Repeat("5", 64),
		RetentionSeconds: 3600, SupportedAssets: []nativecore.SoftwareWorkAssetIdentityV1{{Workchain: 0,
			MasterAccount: strings.Repeat("6", 64), MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("7", 64),
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("8", 64), Decimals: 9}}}
	manifestRaw, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	state := &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("9", 64),
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: 42, ContractCodeHash: registry,
			TransactionHash: "sha256:" + strings.Repeat("a", 64)},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID,
			OwnerAgentId: provider, Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: manifestDigest}}}}}
	result := func(score uint32) *nativev1.CapabilitySearchResultV1 {
		return &nativev1.CapabilitySearchResultV1{Capability: proto.Clone(state).(*nativev1.NativeStateV1),
			CapabilityVersion: "1.0.0", ManifestDigest: manifestDigest,
			GatewayLocal: &nativev1.GatewayLocalCapabilityMetadataV1{Name: "display", Description: "hint", Operation: "test", MatchScore: score}}
	}
	gateways := []gatewayfederation.Gateway{{ID: "gateway-a", Client: opportunityGatewayFake{
		search:   &nativev1.SearchCapabilitiesResponse{Results: []*nativev1.CapabilitySearchResultV1{result(10)}},
		manifest: &nativev1.GetSoftwareWorkManifestResponse{ManifestDigest: manifestDigest, CanonicalCbor: manifestRaw}}},
		{ID: "gateway-b", Client: opportunityGatewayFake{
			search:   &nativev1.SearchCapabilitiesResponse{Results: []*nativev1.CapabilitySearchResultV1{result(90)}},
			manifest: &nativev1.GetSoftwareWorkManifestResponse{ManifestDigest: manifestDigest, CanonicalCbor: manifestRaw}}}}
	federation, err := gatewayfederation.New(gatewayfederation.Config{Network: network, RegistryCodeHash: registry,
		PerGatewayTimeout: time.Second, MaxGateways: 4, MaxResults: 20})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := buyersdk.NewCapabilityVerifier(buyersdk.CapabilityVerifierConfig{NativeClient: opportunityNativeFake{state},
		Network: network, RegistryCodeHash: registry, CallerID: "openfox-opportunity", Timeout: time.Second,
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewOpportunityCoordinator(OpportunityCoordinatorConfig{Federation: federation, Gateways: gateways,
		Verifier: verifier, Network: network, RegistryCodeHash: registry, CallerID: "openfox-opportunity",
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	hint := opportunity.CandidateHint{Key: opportunity.CandidateKey{Network: opportunity.Network{ID: network.NetworkId,
		GenesisRootHash: strings.TrimPrefix(network.GenesisRootHash, "sha256:"), GenesisFileHash: strings.TrimPrefix(network.GenesisFileHash, "sha256:")},
		CapabilityID: capabilityID, Version: "1.0.0", ManifestDigest: manifestDigest, ProviderAgentID: provider}}
	return coordinator, hint, state
}

func TestOpportunityCoordinatorAggregatesHintsThenReverifiesFinalizedState(t *testing.T) {
	coordinator, expected, _ := opportunityCoordinatorFixture(t)
	request := opportunity.SearchRequest{RequestID: "opp-request_" + strings.Repeat("a", 64), Query: "test",
		PageSize: 10, MaxCandidates: 10, DeadlineUnixMS: time.Unix(1_900_000_000, 0).Add(time.Minute).UnixMilli()}
	hints, err := coordinator.Search(context.Background(), request)
	if err != nil || len(hints) != 1 || hints[0].Key != expected.Key || len(hints[0].GatewayIDs) != 2 || hints[0].GatewayMatchScore != 90 {
		t.Fatalf("search: %+v err=%v", hints, err)
	}
	verified, err := coordinator.Verify(context.Background(), hints[0])
	if err != nil || verified.Key != expected.Key || verified.FinalizedCheckpoint != 42 || verified.Operation != "test" || verified.ManifestName != "Deterministic test work" {
		t.Fatalf("verify: %+v err=%v", verified, err)
	}
}

func TestOpportunityCoordinatorRejectsGatewayOwnerSubstitutionAtFinalizedBoundary(t *testing.T) {
	coordinator, hint, state := opportunityCoordinatorFixture(t)
	state.GetCapability().OwnerAgentId = "agent_" + strings.Repeat("f", 64)
	coordinator.verifier, _ = buyersdk.NewCapabilityVerifier(buyersdk.CapabilityVerifierConfig{NativeClient: opportunityNativeFake{state},
		Network: &nativev1.NetworkDomain{NetworkId: hint.Key.Network.ID, GenesisRootHash: "sha256:" + hint.Key.Network.GenesisRootHash,
			GenesisFileHash: "sha256:" + hint.Key.Network.GenesisFileHash}, RegistryCodeHash: state.Reference.ContractCodeHash,
		CallerID: "openfox-opportunity", Timeout: time.Second, Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	if _, err := coordinator.Verify(context.Background(), hint); !errors.Is(err, opportunity.ErrCoordinatorRejected) {
		t.Fatalf("owner substitution was not terminally rejected: %v", err)
	}
}
