package nativeimpl

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func writeChainBuyerConfig(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	state := filepath.Join(directory, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "budget"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "purchases"), 0o700); err != nil {
		t.Fatal(err)
	}
	base := testChainBuyerStackConfig(t)
	writeCode := func(name string, value *cell.Cell) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(value.ToBOC())+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	registryRaw, err := base64.StdEncoding.DecodeString(base.RegistryCodeBOC)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := cell.FromBOC(registryRaw)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "tosctl")
	if err := os.WriteFile(binary, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	tosctlConfig := filepath.Join(directory, "tosctl.json")
	if err := os.WriteFile(tosctlConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := chainBuyerConfigDocument{
		Schema: "tos.openfox.chain-buyer-config.v1", StateDir: state,
		Network: base.Network, Endpoints: base.Endpoints, RegistryCodeBOCPath: writeCode("registry.boc", registry),
		RegistryCodeHash: base.RegistryCodeHash, EscrowCodeBOCPath: writeCode("escrow.boc", base.EscrowCode),
		EscrowCodeHash: base.EscrowCodeHash, AssetWalletCodeBOCPath: writeCode("wallet.boc", base.AssetWalletCode),
		BuyerAddress: base.BuyerAddress, BuyerAgentID: base.BuyerAgentID,
		Budget: chainBuyerBudget{
			WindowSeconds: 86400, MaxPurchases: 4,
			MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "300",
		},
		PollIntervalMilliseconds: 10, FinalityTimeoutSeconds: 2,
		TOSCTL: chainBuyerTOSCTL{
			BinaryPath: binary, ConfigPath: tosctlConfig, WalletName: "buyer",
			DeploymentAttachedNanoTOS: 100_000_000, FundingAttachedNanoTOS: 100_000_000,
			FundingForwardNanoTOS: 50_000_000, TimeoutSeconds: 2,
		},
	}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "buyer.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadChainBuyerStackBuildsReviewedCustodyGraph(t *testing.T) {
	stack, err := LoadChainBuyerStack(writeChainBuyerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if stack == nil || stack.SDK == nil || stack.Escrow == nil || stack.Deployer == nil ||
		stack.Capability != stack.SDK {
		t.Fatalf("stack = %+v", stack)
	}
}

func TestLoadChainBuyerStackRejectsPublicAndUnknownConfig(t *testing.T) {
	public := writeChainBuyerConfig(t)
	if err := os.Chmod(public, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadChainBuyerStack(public); err == nil {
		t.Fatal("loader accepted a public custody config")
	}

	unknown := writeChainBuyerConfig(t)
	raw, err := os.ReadFile(unknown)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-2], []byte(",\n  \"gateway_authority\": true\n}\n")...)
	if err := os.WriteFile(unknown, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadChainBuyerStack(unknown); err == nil {
		t.Fatal("loader accepted an unknown authority field")
	}
}
