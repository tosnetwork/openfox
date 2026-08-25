package earning

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type PinnedIntentAuthorities map[string]ed25519.PublicKey

func (authorities PinnedIntentAuthorities) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	expected, found := authorities[agentID]
	if !found || !expected.Equal(key) {
		return errors.New("Intent issuer key is not in the owner-pinned finalized authority snapshot")
	}
	return nil
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
