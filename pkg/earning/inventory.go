// Package earning composes OpenFox's local autonomous earning control plane.
// Public protocol objects and digests come from tos-service-protocol; this
// package owns only private capability, cost, policy, and portfolio state.
package earning

import (
	"errors"
	"sort"
	"time"
)

type CapabilityState string

const (
	CapabilityReady   CapabilityState = "ready"
	CapabilityBusy    CapabilityState = "busy"
	CapabilityRevoked CapabilityState = "revoked"
)

type Capability struct {
	Namespace            string          `json:"namespace"`
	Identifier           string          `json:"identifier"`
	Version              string          `json:"version"`
	State                CapabilityState `json:"state"`
	Authority            string          `json:"authority"`
	EvidenceDigest       string          `json:"evidence_digest"`
	RevocationGeneration uint64          `json:"revocation_generation"`
	ExpiresAtUnix        uint64          `json:"expires_at_unix"`
}

type ResourceCapacity struct {
	CPUUnits        uint64 `json:"cpu_units"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	StorageBytes    uint64 `json:"storage_bytes"`
	ModelTokens     uint64 `json:"model_tokens"`
	APIAtomicBudget uint64 `json:"api_atomic_budget"`
	Concurrency     uint32 `json:"concurrency"`
}

type InventorySnapshot struct {
	OwnerID                     string           `json:"owner_id"`
	AgentID                     string           `json:"agent_id"`
	CreatedAtUnix               uint64           `json:"created_at_unix"`
	ExpiresAtUnix               uint64           `json:"expires_at_unix"`
	SourceGeneration            uint64           `json:"source_generation"`
	PortfolioRevision           uint64           `json:"portfolio_revision"`
	PolicyRevision              uint64           `json:"policy_revision"`
	ConsistencyToken            string           `json:"consistency_token"`
	Capabilities                []Capability     `json:"capabilities"`
	Available                   ResourceCapacity `json:"available"`
	SupportedSettlementAdapters []string         `json:"supported_settlement_adapters"`
}

func (snapshot InventorySnapshot) Validate(now time.Time) error {
	if snapshot.OwnerID == "" || snapshot.AgentID == "" || snapshot.CreatedAtUnix == 0 || snapshot.ExpiresAtUnix <= snapshot.CreatedAtUnix ||
		snapshot.SourceGeneration == 0 || snapshot.PortfolioRevision == 0 || snapshot.PolicyRevision == 0 || snapshot.ConsistencyToken == "" ||
		!now.UTC().Before(time.Unix(int64(snapshot.ExpiresAtUnix), 0).UTC()) || now.UTC().Before(time.Unix(int64(snapshot.CreatedAtUnix), 0).UTC().Add(-5*time.Minute)) {
		return errors.New("Inventory snapshot is stale or incomplete")
	}
	previous := ""
	for _, capability := range snapshot.Capabilities {
		key := capability.Namespace + "\x00" + capability.Identifier + "\x00" + capability.Version
		if capability.Namespace == "" || capability.Identifier == "" || capability.Version == "" || key <= previous || capability.Authority == "" ||
			capability.EvidenceDigest == "" || capability.RevocationGeneration == 0 || capability.ExpiresAtUnix == 0 ||
			capability.State != CapabilityReady && capability.State != CapabilityBusy && capability.State != CapabilityRevoked {
			return errors.New("Inventory capability is invalid, unsorted, or duplicated")
		}
		previous = key
	}
	if !sort.StringsAreSorted(snapshot.SupportedSettlementAdapters) {
		return errors.New("settlement adapters must be sorted")
	}
	for index, adapter := range snapshot.SupportedSettlementAdapters {
		if adapter == "" || index > 0 && adapter == snapshot.SupportedSettlementAdapters[index-1] {
			return errors.New("settlement adapters are invalid or duplicated")
		}
	}
	return nil
}

func (snapshot InventorySnapshot) HasCapability(namespace, identifier string, now time.Time) bool {
	if snapshot.Validate(now) != nil {
		return false
	}
	for _, capability := range snapshot.Capabilities {
		if capability.Namespace == namespace && capability.Identifier == identifier && capability.State == CapabilityReady &&
			now.UTC().Before(time.Unix(int64(capability.ExpiresAtUnix), 0).UTC()) {
			return true
		}
	}
	return false
}

func (snapshot InventorySnapshot) SupportsSettlement(adapter string) bool {
	index := sort.SearchStrings(snapshot.SupportedSettlementAdapters, adapter)
	return index < len(snapshot.SupportedSettlementAdapters) && snapshot.SupportedSettlementAdapters[index] == adapter
}
