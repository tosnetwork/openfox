package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativeimpl "github.com/tosnetwork/openfox/pkg/servicebridge/nativeimpl"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/chainactionpublisher"
)

func validConfig() config {
	return config{Schema: configSchema, LocalAgentID: "agent_" + strings.Repeat("a", 64), Network: &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: strings.Repeat("1", 64), GenesisFileHash: strings.Repeat("2", 64)}, GlobalID: 42, ChainEndpoints: []string{"https://a.test", "https://b.test", "https://c.test"}, ChainQuorum: 2,
		NativeGateway:   nativeGatewayConfig{BaseURL: "https://native.test", BearerToken: "secret"},
		TOSCTLCustody:   nativeimpl.TOSCTLGiftCustodyConfig{BinaryPath: "/usr/bin/tosctl", ConfigPath: "/private/tosctl.json", WalletName: "agent", OwnerWallet: "-1:" + strings.Repeat("1", 64), ControllerKeyID: "controller:main"},
		Publisher:       chainactionpublisher.TosctlBackendConfig{Network: "tos-test", Binary: "/usr/bin/tosctl", ConfigPath: "/private/tosctl.json", VaultURL: "unix:///private/vault.sock", RPCURL: "https://a.test", GenesisRootHash: strings.Repeat("1", 64), GenesisFileHash: strings.Repeat("2", 64), WalletName: "owner", Payer: "-1:" + strings.Repeat("1", 64)},
		MessengerSocket: "/private/messenger.sock", JournalDirectory: "/private/gifts", ModelSocket: "/private/model.sock", RuntimeSocket: "/private/runtime.sock", RecipientAddress: "0:" + strings.Repeat("2", 64), FeeReserveAtomic: 1_000_000, MinimumInclusionMargin: 60, ResponseLifetimeSecs: 3600}
}

func TestLoadConfigRequiresStrictOwnerPrivateCompleteDocument(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "gift.json")
	raw, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(path)
	if err != nil || loaded.Schema != configSchema || loaded.ModelSocket == loaded.RuntimeSocket {
		t.Fatalf("valid private config failed: %+v %v", loaded, err)
	}
	if err := os.WriteFile(path, append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("non-private configuration was accepted")
	}
}

func TestRunGiftComponentsCancelsAndWaitsForEveryRunner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	firstFailure := errors.New("component failed")
	stoppedA := make(chan struct{})
	stoppedB := make(chan struct{})
	err := runGiftComponents(ctx, cancel,
		func(context.Context) error { return firstFailure },
		func(ctx context.Context) error {
			<-ctx.Done()
			close(stoppedA)
			return nil
		},
		func(ctx context.Context) error {
			<-ctx.Done()
			close(stoppedB)
			return nil
		},
	)
	if !errors.Is(err, firstFailure) {
		t.Fatalf("component failure was lost: %v", err)
	}
	select {
	case <-stoppedA:
	default:
		t.Fatal("first dependent runner was not joined")
	}
	select {
	case <-stoppedB:
	default:
		t.Fatal("second dependent runner was not joined")
	}
}
