package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
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
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"prepare"},
		{"inspect"},
		{"deploy-prepare"},
		{"deploy-broadcast"},
		{"fund"},
		{"dispatch"},
	} {
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

func TestFundingAndTaskHandoffsBindPreparedPurchase(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	purchase := &buyersdk.PreparedPurchase{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("1", 64),
		Escrow: nativecore.EscrowIdentityV1{
			Address:  "0:" + strings.Repeat("2", 64),
			CodeHash: "tvm-cell-sha256:" + strings.Repeat("3", 64),
		}, AmountAtomic: "25",
	}
	funding := finalizedFundingDocument{
		Schema:  "tos.openfox.finalized-funding.v1",
		Verdict: "PASS_FINALIZED_EXACT_FUNDING", EscrowAddress: purchase.Escrow.Address,
		QuoteCommitment: purchase.QuoteCommitment, AmountAtomic: purchase.AmountAtomic,
		FinalizedCheckpoint: 42, ContractCodeHash: purchase.Escrow.CodeHash,
		FinalizedAt: time.Unix(1_900_000_000, 0).UTC().Format(time.RFC3339Nano),
	}
	fundingRaw, _ := json.Marshal(funding)
	fundingPath := filepath.Join(directory, "funding.json")
	if err := os.WriteFile(fundingPath, fundingRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFundingEvidence(fundingPath, purchase); err != nil {
		t.Fatal(err)
	}

	archive := []byte("reviewed source archive")
	archivePath := filepath.Join(directory, "source.tar")
	if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	task := dispatchTaskDocument{
		Schema:        "tos.service.local-funded-task.v1",
		EscrowAddress: purchase.Escrow.Address, QuoteCommitment: purchase.QuoteCommitment,
		ExecutionID: "exec_1", InputDigest: "sha256:" + strings.Repeat("4", 64),
		SourceDigest: "sha256:" + hex.EncodeToString(digest[:]), SourceArchive: archivePath,
	}
	taskRaw, _ := json.Marshal(task)
	taskPath := filepath.Join(directory, "task.json")
	if err := os.WriteFile(taskPath, taskRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, got, err := loadDispatchTask(taskPath, purchase); err != nil || string(got) != string(archive) {
		t.Fatalf("archive = %q, err = %v", got, err)
	}
	task.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("5", 64)
	taskRaw, _ = json.Marshal(task)
	if err := os.WriteFile(taskPath, taskRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDispatchTask(taskPath, purchase); err == nil {
		t.Fatal("task handoff accepted a different purchase")
	}
}

func TestPinnedHTTPClientRejectsRemotePlaintext(t *testing.T) {
	directory := t.TempDir()
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newPinnedHTTPClient("http://provider.example/task", "", token); err == nil {
		t.Fatal("client accepted remote plaintext")
	}
	if _, err := newPinnedHTTPClient("http://127.0.0.1:18080", "", token); err != nil {
		t.Fatal(err)
	}
}
