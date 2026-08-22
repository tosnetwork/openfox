package nativeimpl

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/dnsalias"
	"google.golang.org/protobuf/proto"
)

type DNSAliasClient interface {
	ResolveDNSAlias(context.Context, *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error)
}

// ResolveDNSNameInput resolves discovery-only user input. Its return value is a
// Native object ID, never an authorization decision: the purchase path must
// still re-resolve and validate that object from finalized Registry state.
func ResolveDNSNameInput(
	ctx context.Context, client DNSAliasClient, expectedNetwork *nativev1.NetworkDomain, input, callerID string,
	kind nativev1.DNSAliasKindV1, now time.Time,
) (*nativev1.ResolveDNSAliasResponse, error) {
	if client == nil || ctx == nil || expectedNetwork == nil || expectedNetwork.NetworkId == "" ||
		expectedNetwork.GenesisRootHash == "" || expectedNetwork.GenesisFileHash == "" || callerID == "" || now.IsZero() {
		return nil, errors.New("nativeimpl: DNS alias input resolver is incomplete")
	}
	trimmed := strings.TrimSpace(input)
	name, err := dnsalias.CanonicalName(strings.ToLower(trimmed))
	if err != nil || trimmed != input {
		return nil, errors.New("nativeimpl: DNS alias input must be a canonical .tos name")
	}
	if kind != nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT &&
		kind != nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY {
		return nil, errors.New("nativeimpl: OpenFox accepts only Agent or Capability DNS aliases")
	}
	requestID, err := randomRequestID()
	if err != nil {
		return nil, err
	}
	response, err := client.ResolveDNSAlias(ctx, &nativev1.ResolveDNSAliasRequest{
		Context: &nativev1.RequestContext{
			RequestId: requestID, CallerId: callerID,
			DeadlineUnixMillis: now.Add(30 * time.Second).UnixMilli(),
		},
		Name: name, Kind: kind,
	})
	if err != nil {
		return nil, err
	}
	if err := validateDNSAliasEvidence(response, expectedNetwork, name, kind, uint64(now.Unix())); err != nil {
		return nil, err
	}
	return response, nil
}

func validateDNSAliasEvidence(
	response *nativev1.ResolveDNSAliasResponse,
	network *nativev1.NetworkDomain,
	name string,
	kind nativev1.DNSAliasKindV1,
	now uint64,
) error {
	if response == nil || response.CanonicalName != name || response.Kind != kind ||
		response.Provenance != nativev1.DNSProvenanceV1_DNS_PROVENANCE_V1_QUORUM_AGREED ||
		response.NativeState == nil || response.ResolvedAccount == nil {
		return errors.New("nativeimpl: DNS alias response is not quorum-bound Native evidence")
	}
	category := "agent"
	if kind == nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY {
		category = "capability"
	}
	digest := sha256.Sum256([]byte(category))
	if response.CategoryHash != hex.EncodeToString(digest[:]) || !proto.Equal(response.NativeState.Network, network) {
		return errors.New("nativeimpl: DNS alias category or network mismatch")
	}
	prefix, stateID := "agent_", ""
	if kind == nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT {
		if response.NativeState.GetAgent() != nil {
			stateID = response.NativeState.GetAgent().GetAgentId()
		}
	} else {
		prefix = "cap_"
		if response.NativeState.GetCapability() != nil {
			stateID = response.NativeState.GetCapability().GetCapabilityId()
		}
	}
	if !validNativeObjectID(response.NativeObjectId, prefix) || stateID != response.NativeObjectId {
		return errors.New("nativeimpl: DNS alias Native object identity mismatch")
	}
	if response.ResolvedAccount.Workchain != 0 || len(response.ResolvedAccount.AccountId) != 32 ||
		response.NativeState.Reference == nil || response.NativeState.Reference.Account !=
		fmt.Sprintf("0:%s", hex.EncodeToString(response.ResolvedAccount.AccountId)) {
		return errors.New("nativeimpl: DNS alias account provenance mismatch")
	}
	checkpoint := response.Checkpoint
	if checkpoint == nil || checkpoint.Workchain != -1 || checkpoint.Sequence == 0 ||
		len(checkpoint.RootHash) != 32 || len(checkpoint.FileHash) != 32 || checkpoint.GenerationUnixSeconds == 0 {
		return errors.New("nativeimpl: DNS alias checkpoint is incomplete")
	}
	lifecycle := response.Lifecycle
	if lifecycle == nil || lifecycle.AuctionEndUnixSeconds != 0 || lifecycle.LastFillUpUnixSeconds == 0 ||
		lifecycle.LastFillUpUnixSeconds > ^uint64(0)-dnsalias.LeaseSeconds ||
		lifecycle.RenewalDeadlineUnixSeconds != lifecycle.LastFillUpUnixSeconds+dnsalias.LeaseSeconds ||
		now > lifecycle.RenewalDeadlineUnixSeconds {
		return errors.New("nativeimpl: DNS alias lifecycle is unsafe")
	}
	if len(response.ResolverPath) < 3 || len(response.ResolverPath) > 8 ||
		response.NativeState.Reference.FinalizedCheckpoint != checkpoint.Sequence {
		return errors.New("nativeimpl: DNS alias provenance is incomplete")
	}
	for index, address := range response.ResolverPath {
		if address == nil || len(address.AccountId) != 32 || index == 0 && address.Workchain != -1 ||
			index > 0 && address.Workchain != 0 {
			return errors.New("nativeimpl: DNS alias resolver path address is invalid")
		}
	}
	return nil
}

func validNativeObjectID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && value == strings.ToLower(value)
}

func randomRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("nativeimpl: create DNS alias request ID")
	}
	return "dns_" + hex.EncodeToString(value[:]), nil
}
