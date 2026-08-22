package main

import (
	"os"
	"path/filepath"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func TestParseKind(t *testing.T) {
	tests := map[string]nativev1.DNSAliasKindV1{
		"agent":      nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT,
		"capability": nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY,
	}
	for input, expected := range tests {
		actual, err := parseKind(input)
		if err != nil || actual != expected {
			t.Fatalf("parseKind(%q) = %v, %v", input, actual, err)
		}
	}
	if _, err := parseKind("wallet"); err == nil {
		t.Fatal("unsupported alias kind accepted")
	}
}

func TestReadPrivateTokenRequiresPrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private-token")
	if err := os.WriteFile(private, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := readPrivateToken(private); err != nil || value != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("private token = %q, %v", value, err)
	}

	public := filepath.Join(dir, "public-token")
	if err := os.WriteFile(public, []byte("0123456789abcdef0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateToken(public); err == nil {
		t.Fatal("group/world-readable token accepted")
	}

	symlink := filepath.Join(dir, "token-link")
	if err := os.Symlink(private, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateToken(symlink); err == nil {
		t.Fatal("token symlink accepted")
	}
}
