package earning

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"

	"github.com/tosnetwork/openfox/pkg/config"
)

func paidDemandDeployerFor(t *testing.T, nonProduction bool) *buyersdk.TOSCTLPaidDemandEscrowDeployer {
	t.Helper()
	directory := t.TempDir()
	binary := filepath.Join(directory, "tosctl")
	configPath := filepath.Join(directory, "tosctl.json")
	if err := os.WriteFile(binary, []byte("#!/bin/false\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.EarningTOSEscrowSettings{
		Executable: binary, ConfigPath: configPath,
		DeploymentWallet: "deployer", RelayerAddress: "0:" + strings.Repeat("ab", 32),
		DeploymentNanoTOS: 100_000_000, NonProductionTestDeployment: nonProduction,
	}
	deployer, err := buyersdk.NewTOSCTLPaidDemandEscrowDeployer(paidDemandDeployerConfig(settings))
	if err != nil {
		t.Fatal(err)
	}
	return deployer
}

// Escrow v2 deployments require the operator's non-production
// acknowledgment, which is off unless configured.
func TestPaidDemandEscrowDeploymentRequiresTheNonProductionAcknowledgment(t *testing.T) {
	if !paidDemandDeployerConfig(
		config.EarningTOSEscrowSettings{NonProductionTestDeployment: true},
	).AcknowledgeNonProductionTestDeployment ||
		paidDemandDeployerConfig(config.EarningTOSEscrowSettings{}).AcknowledgeNonProductionTestDeployment {
		t.Fatal("the configured acknowledgment does not reach the deployer")
	}
	_, err := paidDemandDeployerFor(t, false).PreparePaidDemandDeployment(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "non-production") {
		t.Fatalf("a deployer without the acknowledgment did not refuse: %v", err)
	}
	_, err = paidDemandDeployerFor(t, true).PreparePaidDemandDeployment(context.Background(), nil)
	if err == nil || strings.Contains(err.Error(), "non-production") {
		t.Fatalf("positive control: an acknowledged deployer refused for the acknowledgment: %v", err)
	}
}
