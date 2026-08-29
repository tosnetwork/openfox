//go:build linux

package mcp

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSealExecutableIsIndependentOfMutableInstalledPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server")
	if err := os.WriteFile(path, []byte("original executable bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("original executable bytes"))
	sealed, err := sealExecutable(source, digest[:])
	_ = source.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	if err := os.WriteFile(path, []byte("attacker replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "original executable bytes" {
		t.Fatalf("sealed bytes changed through pathname replacement: %q", raw)
	}
}

func TestSealExecutableRejectsSameInodeContentMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server")
	if err := os.WriteFile(path, []byte("mutated bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	want := sha256.Sum256([]byte("original bytes"))
	if sealed, err := sealExecutable(source, want[:]); err == nil {
		_ = sealed.Close()
		t.Fatal("same-inode content mutation was sealed")
	}
}
