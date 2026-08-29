package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/config"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func (h *Handler) registerCapabilityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/capabilities", h.handleCapabilities)
}

func (h *Handler) capabilityStore() (*capabilitycontrol.Store, error) {
	h.capabilityMu.Lock()
	defer h.capabilityMu.Unlock()
	if h.capabilityStoreInstance != nil {
		return h.capabilityStoreInstance, nil
	}
	cfg, err := config.LoadConfig(h.configPath)
	if err != nil {
		return nil, err
	}
	if cfg.Earning.OwnerID == "" || cfg.Earning.AgentID == "" {
		return nil, fmt.Errorf("earning.owner_id and earning.agent_id are required")
	}
	settings := cfg.Earning.TrustedCapability
	root := settings.ProjectionDirectory
	if root == "" {
		return nil, fmt.Errorf("earning.trusted_capability production directories are required")
	}
	controlAuthority, err := capabilitycontrol.OpenHTTPSControlAuthorityFromFile(settings.ControlAuthorityEndpoint, settings.ControlAuthorityTokenFile, settings.ControlAuthorityPublicKey)
	if err != nil {
		return nil, err
	}
	store, authority, err := capabilitycontrol.OpenProduction(capabilitycontrol.ProductionStoreOptions{ProjectionRoot: root,
		PublisherObservationDirectory: settings.PublisherObservationDirectory,
		DomainKind:                    trusted.DomainOwnerLocal, DomainID: []byte(cfg.Earning.OwnerID),
		OwnerID: []byte(cfg.Earning.OwnerID), AgentID: []byte(cfg.Earning.AgentID), Authority: controlAuthority})
	if err != nil {
		_ = controlAuthority.Close()
		return nil, err
	}
	h.capabilityStoreInstance, h.capabilityAuthority = store, authority
	return store, nil
}
func (h *Handler) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	store, err := h.capabilityStore()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	snapshot, err := store.Inventory(5 * time.Minute)
	if err != nil {
		http.Error(w, "inventory unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}
