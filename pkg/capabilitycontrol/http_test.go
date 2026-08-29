package capabilitycontrol

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHTTPAuthenticatesBeforeInventoryDisclosure(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"), []byte("owner"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler(store, func(r *http.Request) error {
		if r.Header.Get("Authorization") == "ok" {
			return nil
		}
		return errDenied{}
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/v1/owner/capabilities", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	request := httptest.NewRequest("GET", "/v1/owner/capabilities", nil)
	request.Header.Set("Authorization", "ok")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.Code)
	}
}

type errDenied struct{}

func (errDenied) Error() string { return "denied" }
