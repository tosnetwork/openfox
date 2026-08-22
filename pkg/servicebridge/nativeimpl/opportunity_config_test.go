package nativeimpl

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func writeOpportunityCoordinatorConfig(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	state := filepath.Join(directory, "state")
	run := filepath.Join(directory, "run")
	for _, path := range []string{state, run} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	base := testChainBuyerStackConfig(t)
	registryRaw, _ := base64.StdEncoding.DecodeString(base.RegistryCodeBOC)
	registry, err := cell.FromBOC(registryRaw)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(directory, "registry.boc")
	if err := os.WriteFile(registryPath, []byte(base64.StdEncoding.EncodeToString(registry.ToBOC())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gateways := make([]opportunityGatewayConfig, 0, 2)
	for index, id := range []string{"gateway-a", "gateway-b"} {
		token := filepath.Join(directory, id+".token")
		if err := os.WriteFile(token, []byte("secret-"+id+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gateways = append(gateways, opportunityGatewayConfig{ID: id,
			BaseURL: "http://127.0.0.1:" + string(rune('1'+index)) + "8000", BearerTokenFile: token, InsecureLoopback: true})
	}
	document := opportunityCoordinatorDocument{Schema: opportunityCoordinatorConfigSchema, StateDir: state,
		SocketPath: filepath.Join(run, "opportunity.sock"), Network: base.Network, ChainEndpoints: base.Endpoints,
		ChainQuorum: 2, RegistryCodeBOCPath: registryPath, RegistryCodeHash: base.RegistryCodeHash,
		CallerID: "openfox-opportunity", RequestTimeoutSeconds: 5, MaxResults: 100,
		CredentialQuotaEnforced: true, Gateways: gateways}
	raw, _ := json.Marshal(document)
	path := filepath.Join(directory, "opportunity.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadOpportunityCoordinatorBuildsReadOnlyAuthorityGraph(t *testing.T) {
	resources, err := LoadOpportunityCoordinator(writeOpportunityCoordinatorConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if resources.Coordinator == nil || resources.SocketPath == "" {
		t.Fatalf("incomplete resources: %+v", resources)
	}
}

func TestLoadOpportunityCoordinatorRequiresPollingProtectionAndStrictConfig(t *testing.T) {
	path := writeOpportunityCoordinatorConfig(t)
	raw, _ := os.ReadFile(path)
	var document opportunityCoordinatorDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document.CredentialQuotaEnforced = false
	mutated, _ := json.Marshal(document)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpportunityCoordinator(path); err == nil {
		t.Fatal("recurring polling without quota or bounded cache was accepted")
	}

	path = writeOpportunityCoordinatorConfig(t)
	raw, _ = os.ReadFile(path)
	raw = append(raw[:len(raw)-1], []byte(`,"custody_key":"model"}`)...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpportunityCoordinator(path); err == nil {
		t.Fatal("unknown custody authority was accepted")
	}
}

func TestLoadOpportunityCoordinatorRejectsIncompletePolicyGatedAuthority(t *testing.T) {
	path := writeOpportunityCoordinatorConfig(t)
	raw, _ := os.ReadFile(path)
	var document opportunityCoordinatorDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document.Purchase = &opportunityPurchaseConfig{StateDir: document.StateDir, MandateID: "mandate",
		CapabilityClass: "software-work", RequestTimeoutSeconds: 5}
	mutated, _ := json.Marshal(document)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpportunityCoordinator(path); err == nil {
		t.Fatal("incomplete policy, custody, Messenger, and task authority was accepted")
	}
}
