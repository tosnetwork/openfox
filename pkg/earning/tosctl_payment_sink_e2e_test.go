package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// TestTOSCTLPaymentSinkThreeNode is opt-in because it spends local test-chain
// funds and requires three live validator RPCs. It is intentionally kept next
// to the Adapter so the production path, rather than a parallel script-only
// implementation, is what the acceptance campaign exercises.
func TestTOSCTLPaymentSinkThreeNode(t *testing.T) {
	if os.Getenv("OPENFOX_TOS_THREE_NODE_E2E") != "1" {
		t.Skip("set OPENFOX_TOS_THREE_NODE_E2E=1 for the live three-node campaign")
	}
	executable := mustEnv(t, "OPENFOX_TOSCTL")
	primary := mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG")
	quorum2 := mustEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_2")
	quorum3 := mustEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_3")
	wallet := mustEnv(t, "OPENFOX_TOS_AGENT_WALLET")
	source := mustEnv(t, "OPENFOX_TOS_SOURCE_ACCOUNT")
	target := mustEnv(t, "OPENFOX_TOS_PAYMENT_TARGET")
	vaultURL := mustEnv(t, "OPENFOX_TOS_VAULT_URL")
	runID := mustEnv(t, "OPENFOX_TOS_E2E_RUN_ID")
	networkGlobalID64, err := strconv.ParseInt(mustEnv(t, "OPENFOX_TOS_NETWORK_GLOBAL_ID"), 10, 32)
	if err != nil || networkGlobalID64 == 0 {
		t.Fatal("OPENFOX_TOS_NETWORK_GLOBAL_ID must be a non-zero int32")
	}

	seed := sha256.Sum256([]byte("tos.openfox.three-node-payment-authority.v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	publicKey := key.Public().(ed25519.PublicKey)
	journalDirectory := filepath.Join(filepath.Dir(primary), ".tosctl-agent-controller-journal")
	if err := os.MkdirAll(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	bind := exec.Command(executable, "agent", "wallet", "bind-runtime", "--name", wallet,
		"--runner-id", "openfox-three-node-e2e", "--endpoint", "local://openfox/earning",
		"--economic-authority-id", "authority:openfox-three-node-e2e",
		"--economic-authority-public-key", hex.EncodeToString(publicKey),
		"--economic-custody-journal-directory", journalDirectory, "-c", primary, "--format", "json")
	bind.Env = append(os.Environ(), "VAULT_URL="+vaultURL)
	if output, err := bind.CombinedOutput(); err != nil {
		t.Fatalf("bind custody authority: %v: %s", err, output)
	}

	authorityDirectory := filepath.Join(filepath.Dir(primary), "openfox-economic-authority")
	if err := os.MkdirAll(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(authorityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(authorityDirectory, "owner:three-node-e2e", "agent:payer",
		"authority:openfox-three-node-e2e", key, PortfolioLimits{SpendAtomic: 10_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	fence, err := authority.AcquireWriter(context.Background(), "writer:three-node-e2e", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mandate := threeNodeDigest("mandate:" + runID)
	agreement := threeNodeDigest("agreement:" + runID)
	instance := threeNodeDigest("obligation-instance:" + runID)
	obligation := commerce.SettlementObligation{AgreementBodyDigest: agreement, AgreementObligationID: "payment:three-node-e2e",
		ObligationInstanceID: instance, Sequence: 1, PayerAgentID: "agent:payer", PayeeAgentID: "agent:provider",
		Amount:                 commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "100000000", Unit: "nanotos"},
		MaximumAggregateAmount: commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "100000000", Unit: "nanotos"},
		ExpiresAtUnix:          uint64(now.Add(5 * time.Minute).Unix()), SettlementAdapterURI: "tos.payment.direct.v1",
		SettlementParametersDigest: threeNodeDigest("settlement-parameters:" + runID), MandateDigest: mandate,
		StableActionID: threeNodeDigest("billing-action:" + runID)}
	request, err := commerce.BuildAgreementPaymentRequest("owner:three-node-e2e", "agent:payer", "tos:local-three-node",
		[]byte(target), obligation)
	if err != nil {
		t.Fatal(err)
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner:three-node-e2e", "agent:payer", "payment.direct", fields, canonical,
		fence, 1, mandate, "", "pending", request.ExpiresAtUnix)
	if err == nil {
		action, err = authority.SignAction(action, fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resolution, err := authority.Admit(action, fields, canonical, fence, nil); err != nil || resolution.State != commerce.ActionPrepared {
		t.Fatalf("admit payment action: resolution=%+v err=%v", resolution, err)
	}
	sink := &TOSCTLPaymentSink{Authority: authority, Executable: executable, ConfigPath: primary, Wallet: wallet,
		SourceAccount: source, NetworkGlobalID: int32(networkGlobalID64), FeeReserveNanoTOS: 50_000_000,
		QuorumConfigPaths: []string{quorum2, quorum3}, MaximumTransactions: 1000, VaultURL: vaultURL,
		EvidenceDirectory: filepath.Join(filepath.Dir(primary), "payment-evidence"), ResolveAttempts: 30, ResolveInterval: time.Second}
	evidence, err := sink.SubmitPayment(context.Background(), action, fence, fields, canonical, request)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ResolvedState != "finalized" || evidence.AdapterEvidenceProfile != tosQuorumEvidenceProfile || len(evidence.Evidence) == 0 {
		t.Fatalf("unexpected payment evidence: %+v", evidence)
	}
	if _, err := authority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionAccepted,
		evidence.ExactTransferReference, []string{evidence.FinalityReference}); err != nil {
		t.Fatal(err)
	}
	t.Logf("finalized Agreement-bound transfer %s with %s", evidence.ExactTransferReference, evidence.FinalityReference)
}

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func threeNodeDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
