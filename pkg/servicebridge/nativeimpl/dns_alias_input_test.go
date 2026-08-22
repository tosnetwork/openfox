package nativeimpl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/dnsalias"
)

type aliasClientFunc func(context.Context, *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error)

func (f aliasClientFunc) ResolveDNSAlias(
	ctx context.Context,
	request *nativev1.ResolveDNSAliasRequest,
) (*nativev1.ResolveDNSAliasResponse, error) {
	return f(ctx, request)
}

func TestResolveDNSNameInputReturnsDiscoveryEvidenceNotAuthority(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	network := testAliasNetwork()
	id := "cap_" + strings.Repeat("a", 64)
	client := aliasClientFunc(
		func(_ context.Context, request *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
			if request.Name != "compute.alice.tos" || request.Context.CallerId != "agent_buyer" ||
				request.Context.RequestId == "" || request.Context.DeadlineUnixMillis <= now.UnixMilli() {
				t.Fatalf("request = %+v", request)
			}
			return validAliasEvidence(id, request.Name, request.Kind, uint64(now.Unix())), nil
		},
	)
	result, err := ResolveDNSNameInput(t.Context(), client, network, "Compute.Alice.tos", "agent_buyer",
		nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY, now)
	if err != nil || result.NativeObjectId != id || result.NativeState.GetCapability().GetCapabilityId() != id {
		t.Fatalf("result = %+v, %v", result, err)
	}
}

func TestResolveDNSNameInputFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	network := testAliasNetwork()
	id := "agent_" + strings.Repeat("b", 64)
	base := validAliasEvidence(id, "alice.tos", nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, uint64(now.Unix()))
	tests := map[string]func(*nativev1.ResolveDNSAliasResponse){
		"not quorum":      func(v *nativev1.ResolveDNSAliasResponse) { v.Provenance = 0 },
		"object mismatch": func(v *nativev1.ResolveDNSAliasResponse) { v.NativeObjectId = "agent_" + strings.Repeat("c", 64) },
		"active auction":  func(v *nativev1.ResolveDNSAliasResponse) { v.Lifecycle.AuctionEndUnixSeconds = 1 },
		"expired": func(v *nativev1.ResolveDNSAliasResponse) {
			v.Lifecycle.RenewalDeadlineUnixSeconds = uint64(now.Unix() - 1)
		},
		"checkpoint drift": func(v *nativev1.ResolveDNSAliasResponse) { v.NativeState.Reference.FinalizedCheckpoint++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := cloneAlias(base)
			mutate(copy)
			client := aliasClientFunc(
				func(context.Context, *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
					return copy, nil
				},
			)
			if _, err := ResolveDNSNameInput(t.Context(), client, network, "alice.tos", "agent_buyer",
				nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, now); err == nil {
				t.Fatal("unsafe alias evidence accepted")
			}
		})
	}
}

func TestResolveDNSNameInputRejectsNoncanonicalLookupNamesLocally(t *testing.T) {
	client := aliasClientFunc(
		func(context.Context, *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
			t.Fatal("invalid name reached the Native gateway")
			return nil, nil
		},
	)
	for _, name := range []string{
		" alice.tos", "alice.tos ", "alice..tos", "alice/example.tos", "alice:port.tos",
		"älice.tos", strings.Repeat("a", 123) + ".tos",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ResolveDNSNameInput(t.Context(), client, testAliasNetwork(), name, "agent_buyer",
				nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, time.Unix(1_800_000_000, 0)); err == nil {
				t.Fatal("noncanonical alias input accepted")
			}
		})
	}
}

func validAliasEvidence(id, name string, kind nativev1.DNSAliasKindV1, now uint64) *nativev1.ResolveDNSAliasResponse {
	state := &nativev1.NativeStateV1{Network: testAliasNetwork(), Reference: &nativev1.ChainReference{
		Account: "0:" + strings.Repeat("0", 64), FinalizedCheckpoint: 42,
	}}
	if kind == nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT {
		state.State = &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: id}}
	} else {
		state.State = &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: id}}
	}
	return &nativev1.ResolveDNSAliasResponse{
		CanonicalName: name, Kind: kind, CategoryHash: aliasCategoryHash(kind), NativeObjectId: id, NativeState: state,
		ResolvedAccount: &nativev1.TOSAccountAddressV1{AccountId: make([]byte, 32)},
		Checkpoint: &nativev1.DNSCheckpointV1{
			Workchain: -1, Sequence: 42, RootHash: make([]byte, 32),
			FileHash: make([]byte, 32), GenerationUnixSeconds: now,
		},
		Lifecycle: &nativev1.DNSLifecycleV1{
			LastFillUpUnixSeconds:      now - 1_000,
			RenewalDeadlineUnixSeconds: now - 1_000 + dnsalias.LeaseSeconds,
		},
		Provenance: nativev1.DNSProvenanceV1_DNS_PROVENANCE_V1_QUORUM_AGREED,
		ResolverPath: []*nativev1.TOSAccountAddressV1{
			{Workchain: -1, AccountId: make([]byte, 32)},
			{Workchain: 0, AccountId: make([]byte, 32)},
			{Workchain: 0, AccountId: make([]byte, 32)},
		},
	}
}

func cloneAlias(value *nativev1.ResolveDNSAliasResponse) *nativev1.ResolveDNSAliasResponse {
	// Fixtures contain only the fields copied here; explicit construction keeps
	// mutation in one table row from leaking into another.
	state := &nativev1.NativeStateV1{Network: value.NativeState.Network, Reference: &nativev1.ChainReference{
		Account:             value.NativeState.Reference.Account,
		FinalizedCheckpoint: value.NativeState.Reference.FinalizedCheckpoint,
	}}
	if value.NativeState.GetAgent() != nil {
		state.State = &nativev1.NativeStateV1_Agent{
			Agent: &nativev1.AgentStateV1{AgentId: value.NativeState.GetAgent().AgentId},
		}
	}
	return &nativev1.ResolveDNSAliasResponse{
		CanonicalName: value.CanonicalName, Kind: value.Kind, CategoryHash: value.CategoryHash,
		NativeObjectId: value.NativeObjectId, NativeState: state, ResolvedAccount: value.ResolvedAccount,
		Checkpoint: &nativev1.DNSCheckpointV1{
			Workchain: value.Checkpoint.Workchain,
			Sequence:  value.Checkpoint.Sequence,
			RootHash: append(
				[]byte(nil),
				value.Checkpoint.RootHash...),
			FileHash:              append([]byte(nil), value.Checkpoint.FileHash...),
			GenerationUnixSeconds: value.Checkpoint.GenerationUnixSeconds,
		},
		Lifecycle: &nativev1.DNSLifecycleV1{
			AuctionEndUnixSeconds:      value.Lifecycle.AuctionEndUnixSeconds,
			LastFillUpUnixSeconds:      value.Lifecycle.LastFillUpUnixSeconds,
			RenewalDeadlineUnixSeconds: value.Lifecycle.RenewalDeadlineUnixSeconds,
		},
		Provenance: value.Provenance, ResolverPath: value.ResolverPath,
	}
}

func testAliasNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-test",
		GenesisRootHash: strings.Repeat("1", 64),
		GenesisFileHash: strings.Repeat("2", 64),
	}
}

func aliasCategoryHash(kind nativev1.DNSAliasKindV1) string {
	name := "agent"
	if kind == nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY {
		name = "capability"
	}
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:])
}
