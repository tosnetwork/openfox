package api

import (
	"net/http"
	"strings"
	"sync"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/web/backend/launcherconfig"
	ownercontrol "github.com/tosnetwork/tos-messenger/pkg/ownercontrol"
)

// Handler serves HTTP API requests.
type Handler struct {
	configPath                 string
	serverPort                 int
	serverPublic               bool
	serverPublicExplicit       bool
	serverHostInput            string
	serverHostExplicit         bool
	serverCIDRs                []string
	serverAllowLocalhostBypass bool
	serverTrustedProxyCIDRs    []string
	debug                      bool
	// Serializes model-related config writes. Other config endpoints still
	// coordinate their own load-modify-save cycles.
	configMu                   sync.Mutex
	oauthMu                    sync.Mutex
	oauthFlows                 map[string]*oauthFlow
	oauthState                 map[string]string
	weixinMu                   sync.Mutex
	weixinFlows                map[string]*weixinFlow
	wecomMu                    sync.Mutex
	wecomFlows                 map[string]*wecomFlow
	capabilityMu               sync.Mutex
	capabilityStoreInstance    *capabilitycontrol.Store
	capabilityAuthority        capabilitycontrol.ProductionAuthority
	capabilityAcquisitionFence capabilitycontrol.CapabilityAcquisitionFence
	ownerCommandService        *ownercontrol.Service
	ownerCommandJournal        *ownercontrol.FileJournal
}

// NewHandler creates an instance of the API handler.
func NewHandler(configPath string) *Handler {
	return &Handler{
		configPath:                 configPath,
		serverPort:                 launcherconfig.DefaultPort,
		serverAllowLocalhostBypass: launcherconfig.Default().AllowLocalhostBypass,
		oauthFlows:                 make(map[string]*oauthFlow),
		oauthState:                 make(map[string]string),
		weixinFlows:                make(map[string]*weixinFlow),
		wecomFlows:                 make(map[string]*wecomFlow),
	}
}

// SetServerOptions stores current backend listen options for fallback behavior.
func (h *Handler) SetServerOptions(port int, public bool, publicExplicit bool, allowedCIDRs []string) {
	h.serverPort = port
	h.serverPublic = public
	h.serverPublicExplicit = publicExplicit
	h.serverHostInput = ""
	h.serverHostExplicit = false
	h.serverCIDRs = append([]string(nil), allowedCIDRs...)
}

func (h *Handler) SetServerAccessOptions(allowLocalhostBypass bool, trustedProxyCIDRs []string) {
	h.serverAllowLocalhostBypass = allowLocalhostBypass
	h.serverTrustedProxyCIDRs = append([]string(nil), trustedProxyCIDRs...)
}

// SetServerBindHost stores the launcher's effective bind host.
// When explicit is true, hostInput is the normalized -host / OPENFOX_LAUNCHER_HOST value.
func (h *Handler) SetServerBindHost(hostInput string, explicit bool) {
	h.serverHostInput = strings.TrimSpace(hostInput)
	if !explicit {
		h.serverHostInput = ""
	}
	h.serverHostExplicit = explicit
}

func (h *Handler) SetDebug(debug bool) {
	h.debug = debug
}

// RegisterRoutes binds all API endpoint handlers to the ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Config CRUD
	h.registerConfigRoutes(mux)

	// Pico Channel (WebSocket chat)
	h.registerPicoRoutes(mux)

	// Gateway process lifecycle
	h.registerGatewayRoutes(mux)

	// Session history
	h.registerSessionRoutes(mux)

	// OAuth login and credential management
	h.registerOAuthRoutes(mux)

	// Model list management
	h.registerModelRoutes(mux)

	// Channel catalog (for frontend navigation/config pages)
	h.registerChannelRoutes(mux)

	// Skills and tools support/actions
	h.registerSkillRoutes(mux)
	h.registerCapabilityRoutes(mux)
	h.registerOwnerControlRoutes(mux)
	h.registerToolRoutes(mux)

	// OS startup / launch-at-login
	h.registerStartupRoutes(mux)

	// Launcher service parameters (port/public)
	h.registerLauncherConfigRoutes(mux)

	// Self-update endpoint (requires dashboard auth)
	h.registerUpdateRoutes(mux)

	// Runtime build/version metadata
	h.registerVersionRoutes(mux)

	// WeChat QR login flow
	h.registerWeixinRoutes(mux)

	// WeCom QR login flow
	h.registerWecomRoutes(mux)
}

// Shutdown gracefully shuts down the handler, stopping the gateway if it was started by this handler.
func (h *Handler) Shutdown() {
	h.StopGateway()
	h.capabilityMu.Lock()
	if h.capabilityStoreInstance != nil {
		_ = h.capabilityStoreInstance.Close()
	}
	if h.capabilityAuthority != nil {
		_ = h.capabilityAuthority.Close()
	}
	if h.ownerCommandJournal != nil {
		_ = h.ownerCommandJournal.Close()
	}
	h.capabilityStoreInstance = nil
	h.capabilityAuthority = nil
	h.ownerCommandService = nil
	h.ownerCommandJournal = nil
	h.capabilityMu.Unlock()
}
