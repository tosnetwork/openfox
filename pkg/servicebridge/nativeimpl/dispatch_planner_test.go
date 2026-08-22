package nativeimpl

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/servicebridge"
)

func TestStaticDispatchPlannerPinsReviewedSourceAndTransport(t *testing.T) {
	source := []byte("reviewed deterministic source archive")
	digest := sha256.Sum256(source)
	path := filepath.Join(t.TempDir(), "source.tar")
	if err := os.WriteFile(path, source, 0o444); err != nil {
		t.Fatal(err)
	}
	config := StaticDispatchPlannerConfig{Transport: servicebridge.TransportA2A, SourceArchivePath: path,
		SourceDigest: "sha256:" + hex.EncodeToString(digest[:]), InputDigest: "sha256:" + strings.Repeat("1", 64),
		RequestTimeout: time.Minute}
	planner, err := NewStaticDispatchPlanner(config)
	if err != nil || planner == nil {
		t.Fatalf("planner: %v", err)
	}
	config.SourceDigest = "sha256:" + strings.Repeat("2", 64)
	if _, err := NewStaticDispatchPlanner(config); err == nil {
		t.Fatal("changed source digest was accepted")
	}
	config.SourceDigest = "sha256:" + hex.EncodeToString(digest[:])
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStaticDispatchPlanner(config); err == nil {
		t.Fatal("writable reviewed source was accepted")
	}
}
