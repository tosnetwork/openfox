package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateNewIsOwnerOnlyAndNeverOverwrites(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "artifact.json")
	if err := writePrivateNew(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact info = %+v, err = %v", info, err)
	}
	if err := writePrivateNew(path, []byte("second\n")); err == nil {
		t.Fatal("writer overwrote a reviewed artifact")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "first\n" {
		t.Fatalf("artifact = %q, err = %v", raw, err)
	}
}

func TestPurchaseCommandRequiresExplicitStageAndInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"prepare"}, {"inspect"}, {"deploy-prepare"},
		{"deploy-broadcast"}, {"fund"}} {
		if err := run(args); err == nil {
			t.Fatalf("run(%v) succeeded without explicit reviewed inputs", args)
		}
	}
}

func TestReadPrivateFileRejectsPublicArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(path, 1024); err == nil {
		t.Fatal("reader accepted a public workflow artifact")
	}
}
