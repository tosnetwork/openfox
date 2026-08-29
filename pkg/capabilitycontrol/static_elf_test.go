//go:build linux

package capabilitycontrol

import (
	"os"
	"testing"
)

func TestHermeticLocalMCPRejectsScriptsAndDynamicELF(t *testing.T) {
	if err := validateHermeticStaticELF([]byte("#!/bin/sh\nexit 0\n")); err == nil {
		t.Fatal("script entrypoint could select an uncommitted host interpreter")
	}
	raw, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Skipf("host dynamic ELF fixture unavailable: %v", err)
	}
	if err := validateHermeticStaticELF(raw); err == nil {
		t.Fatal("dynamic host executable could select an uncommitted loader/library closure")
	}
}
