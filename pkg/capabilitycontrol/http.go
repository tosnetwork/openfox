package capabilitycontrol

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// Handler exposes the shared Web/mobile-facing read API. Mutations are accepted
// only by the typed Owner Command sink, never by this projection endpoint.
func Handler(store *Store, authenticate func(*http.Request) error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/owner/capabilities", func(writer http.ResponseWriter, request *http.Request) {
		if authenticate == nil || authenticate(request) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		snapshot, err := store.Inventory(5 * time.Minute)
		if err != nil {
			http.Error(writer, "inventory unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, snapshot)
	})
	mux.HandleFunc("GET /v1/owner/capability-actions/{execution}", func(writer http.ResponseWriter, request *http.Request) {
		if authenticate == nil || authenticate(request) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		execution, err := hex.DecodeString(request.PathValue("execution"))
		if err != nil {
			http.Error(writer, "invalid execution", http.StatusBadRequest)
			return
		}
		state := store.Snapshot()
		slot, ok := state.UseSlots[hex.EncodeToString(execution)]
		if !ok {
			writeJSON(writer, http.StatusOK, map[string]string{"state": "unknown"})
			return
		}
		writeJSON(writer, http.StatusOK, slot)
	})
	return mux
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
