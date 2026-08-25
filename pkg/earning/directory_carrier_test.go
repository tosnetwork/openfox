package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestDirectoryCarrierIsIndependentAndContentAddressed(t *testing.T) {
	directory := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intent := earningIntent(t, time.Unix(1_800_000_000, 0), privateKey)
	digest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(intent)
	path := filepath.Join(directory, digest[len("sha256:"):]+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	carrier := DirectoryCarrier{CarrierID: "carrier:directory", Directory: directory}
	results, err := carrier.Search(context.Background(), IntentQuery{MaximumResults: 10})
	// A bare content directory remains readable, but it deliberately returns no
	// resumable cursor: only the publication profile's durable sequence index
	// may claim monotonic incremental delivery.
	if err != nil || len(results) != 1 || results[0].Cursor != "" {
		t.Fatalf("results=%+v err=%v", results, err)
	}
	if err := os.Rename(path, filepath.Join(directory, strings.Repeat("0", 64)+".json")); err != nil {
		t.Fatal(err)
	}
	results, err = carrier.Search(context.Background(), IntentQuery{MaximumResults: 10})
	if err != nil || len(results) != 0 {
		t.Fatalf("substituted content address was accepted: results=%+v err=%v", results, err)
	}
}
