package earning

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
)

type PinnedIntentAuthorities map[string]ed25519.PublicKey

func (authorities PinnedIntentAuthorities) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	expected, found := authorities[agentID]
	if !found || !expected.Equal(key) {
		return errors.New("Intent issuer key is not in the owner-pinned finalized authority snapshot")
	}
	return nil
}

// AuthorizeAgentOperationKey applies the same owner-pinned finalized Agent-key
// snapshot to the generic operation envelope. The profile and historical
// proof remain signed inputs; the local pin is the actual trust decision.
func (authorities PinnedIntentAuthorities) AuthorizeAgentOperationKey(agentID string, profile commerce.ProfileRefV1,
	key ed25519.PublicKey, at time.Time, historicalProof []byte) error {
	if commerce.ValidateProfileRefV1(profile) != nil || len(historicalProof) == 0 {
		return errors.New("Agent operation authorization evidence is incomplete")
	}
	return authorities.AuthorizeIntentKey(agentID, key, at)
}

// PinnedRelayAuthorities scopes an owner-pinned Agent authority snapshot to
// exact chain domains. The same display network ID, or even the same Agent
// key, is not implicitly authorized on a chain with different genesis state.
type PinnedRelayAuthorities struct {
	byNetworkDigest map[string]PinnedIntentAuthorities
}

func BindPinnedRelayAuthorities(authorities PinnedIntentAuthorities,
	networks []agentrelay.NetworkDomain) (PinnedRelayAuthorities, error) {
	if len(authorities) == 0 || len(networks) == 0 {
		return PinnedRelayAuthorities{}, errors.New("relay authority domain binding is empty")
	}
	bound := make(map[string]PinnedIntentAuthorities, len(networks))
	for _, network := range networks {
		digest, err := agentrelay.NetworkDomainDigest(network)
		if err != nil {
			return PinnedRelayAuthorities{}, err
		}
		if _, duplicate := bound[digest]; duplicate {
			return PinnedRelayAuthorities{}, errors.New("relay authority domain binding is duplicated")
		}
		frozen := make(PinnedIntentAuthorities, len(authorities))
		for agentID, key := range authorities {
			frozen[agentID] = append(ed25519.PublicKey(nil), key...)
		}
		bound[digest] = frozen
	}
	return PinnedRelayAuthorities{byNetworkDigest: bound}, nil
}

func (authorities PinnedRelayAuthorities) AuthorizeRelayKey(network agentrelay.NetworkDomain,
	agentID string, key ed25519.PublicKey, at time.Time) error {
	digest, err := agentrelay.NetworkDomainDigest(network)
	if err != nil {
		return err
	}
	pinned, found := authorities.byNetworkDigest[digest]
	if !found {
		return errors.New("relay Agent key is not authorized in the exact network domain")
	}
	return pinned.AuthorizeIntentKey(agentID, key, at)
}

func (authorities PinnedIntentAuthorities) AuthorizeHandoffKey(agentID string, key ed25519.PublicKey, at time.Time) error {
	return authorities.AuthorizeIntentKey(agentID, key, at)
}

func ParsePinnedIntentAuthorities(values map[string]string) (PinnedIntentAuthorities, error) {
	result := make(PinnedIntentAuthorities, len(values))
	for agentID, encoded := range values {
		raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "ed25519:"))
		if agentID == "" || err != nil || len(raw) != ed25519.PublicKeySize || len(encoded) != len("ed25519:")+ed25519.PublicKeySize*2 {
			return nil, errors.New("configured Intent authority is invalid")
		}
		result[agentID] = ed25519.PublicKey(append([]byte(nil), raw...))
	}
	return result, nil
}

type CurrentInventory struct{ SnapshotValue InventorySnapshot }

func (source CurrentInventory) Snapshot(ctx context.Context) (InventorySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return InventorySnapshot{}, err
	}
	return source.SnapshotValue, nil
}
