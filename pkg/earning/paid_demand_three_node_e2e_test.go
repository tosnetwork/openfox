package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

type paidDemandThreeNodeFixture struct {
	Network         *nativev1.NetworkDomain `json:"network"`
	EscrowAddress   string                  `json:"escrow_address"`
	CodeHash        string                  `json:"code_hash"`
	QuoteCommitment string                  `json:"quote_commitment"`
	ProviderOffer   string                  `json:"provider_offer_digest"`
	AcceptBodyBOC   string                  `json:"accept_body_boc_base64"`
	AcceptBodyHash  string                  `json:"accept_body_hash"`
	AcceptByUnix    uint64                  `json:"accept_by_unix"`
}

// TestPaidDemandAcceptThreeNode is opt-in because it mutates a live local
// chain. It proves the production OpenFox authority -> tosctl custody -> Agent
// Account -> V2 escrow -> independent quorum resolver path, including stale
// writer rejection, exact preparation replay, and on-chain query replay.
func TestPaidDemandAcceptThreeNode(t *testing.T) {
	if os.Getenv("OPENFOX_PAID_DEMAND_THREE_NODE_E2E") != "1" {
		t.Skip("set OPENFOX_PAID_DEMAND_THREE_NODE_E2E=1 for the live campaign")
	}
	ctx := context.Background()
	fixturePath := mustEnv(t, "OPENFOX_PAID_DEMAND_FIXTURE")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture paidDemandThreeNodeFixture
	if json.Unmarshal(raw, &fixture) != nil || fixture.Network == nil || fixture.EscrowAddress == "" ||
		fixture.CodeHash == "" || fixture.QuoteCommitment == "" || fixture.AcceptBodyBOC == "" ||
		fixture.AcceptBodyHash == "" || fixture.AcceptByUnix <= uint64(time.Now().Unix()) {
		t.Fatal("Paid Demand fixture is incomplete or expired")
	}
	endpoints := []string{mustEnv(t, "OPENFOX_TOS_RPC_1"), mustEnv(t, "OPENFOX_TOS_RPC_2"), mustEnv(t, "OPENFOX_TOS_RPC_3")}
	chain, err := toschain.New(toschain.Config{Network: fixture.Network.NetworkId, Endpoints: endpoints, Quorum: 3})
	if err != nil {
		t.Fatal(err)
	}
	checkpointDirectory := t.TempDir()
	if err := os.Chmod(checkpointDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver, err := toschain.NewEscrowResolver(chain, fixture.Network, fixture.CodeHash,
		filepath.Join(checkpointDirectory, "escrow.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	pending, found, err := resolver.ResolveFinalizedV2(ctx, fixture.EscrowAddress)
	if err != nil || !found || pending.State.Status != nativecore.EscrowStatusPendingAcceptanceV2 ||
		pending.State.QuoteCommitment != fixture.QuoteCommitment {
		t.Fatalf("V2 deployment was not quorum-finalized: state=%+v found=%v err=%v", pending, found, err)
	}

	executable := mustEnv(t, "OPENFOX_TOSCTL")
	configPath := mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG")
	wallet := mustEnv(t, "OPENFOX_TOS_AGENT_WALLET")
	source := mustEnv(t, "OPENFOX_TOS_SOURCE_ACCOUNT")
	seed := sha256.Sum256([]byte("tos.openfox.three-node-payment-authority.v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	journalDirectory := filepath.Join(filepath.Dir(configPath), ".tosctl-agent-controller-journal")
	if err := os.MkdirAll(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	bind := exec.Command(executable, "agent", "wallet", "bind-runtime", "--name", wallet,
		"--runner-id", "openfox-paid-demand-three-node-e2e", "--endpoint", "local://openfox/earning",
		"--economic-authority-id", "authority:openfox-three-node-e2e", "--economic-authority-public-key",
		hex.EncodeToString(key.Public().(ed25519.PublicKey)), "--economic-custody-journal-directory", journalDirectory,
		"-c", configPath, "--format", "json")
	bind.Env = os.Environ()
	if output, bindErr := bind.CombinedOutput(); bindErr != nil {
		t.Fatalf("bind custody authority: %v: %s", bindErr, output)
	}
	authorityDirectory := os.Getenv("OPENFOX_ECONOMIC_AUTHORITY_DIRECTORY")
	if authorityDirectory == "" {
		authorityDirectory = filepath.Join(filepath.Dir(configPath), "openfox-economic-authority")
	}
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
	oldFence, err := authority.AcquireWriter(ctx, "writer:stale", []string{"escrow.transition"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := authority.AcquireWriter(ctx, "writer:current", []string{"escrow.transition"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{OwnerID: "owner:three-node-e2e", AgentID: "agent:payer", MandateDigest: threeNodeDigest("paid-demand-mandate"),
		Authority: authority, Gates: FeatureGates{Agreement: true, TOSEscrow: true}}
	agreement := threeNodeDigest("paid-demand-agreement")
	expected := threeNodeDigest("paid-demand-pending-acceptance")
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(engine.OwnerID), "agent_id": commerce.ID(engine.AgentID),
		"quote_commitment": commerce.Digest32("sha256:" + strings.TrimPrefix(fixture.QuoteCommitment, "tvm-cell-sha256:")), "escrow_account_id": commerce.ID(fixture.EscrowAddress),
		"transition_kind": commerce.Kind("accept"), "expected_state_digest": commerce.Digest32(expected)}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	canonical, err := codec.Marshal(struct {
		SchemaVersion   uint16 `json:"schema_version"`
		TransitionKind  string `json:"transition_kind"`
		AgreementDigest string `json:"agreement_digest"`
		ObligationID    string `json:"obligation_id"`
		EscrowAddress   string `json:"escrow_address"`
		QuoteCommitment string `json:"quote_commitment"`
		ExpectedStatus  uint8  `json:"expected_status"`
		BodyHash        string `json:"body_hash"`
		AmountNanoTOS   uint64 `json:"amount_nanotos"`
	}{1, "accept", agreement, "payment", fixture.EscrowAddress, fixture.QuoteCommitment,
		nativecore.EscrowStatusPendingAcceptanceV2, fixture.AcceptBodyHash, 100_000_000})
	if err != nil {
		t.Fatal(err)
	}
	request := buyersdk.CustodyEffectRequest{ActionKind: "escrow.accept", SemanticFields: fields, CanonicalRequest: canonical,
		AgreementDigest: agreement, ObligationID: "payment", SourceAccount: source, NetworkID: fixture.Network.NetworkId,
		NetworkGlobalID: 3, Destination: fixture.EscrowAddress, AmountNanoTOS: 100_000_000,
		BodyHash: fixture.AcceptBodyHash, StateInitHashOrZero: zeroDigest, ExpiresAtUnix: fixture.AcceptByUnix}
	networkDomain := &commerce.CustodyNetworkDomain{NetworkID: fixture.Network.NetworkId, GlobalID: 3,
		ZeroStateRootHash: fixture.Network.GenesisRootHash, ZeroStateFileHash: fixture.Network.GenesisFileHash, WorkchainID: 0}
	if _, err := (PaidDemandCustodyAuthorizer{Engine: engine, Fence: oldFence, PolicyRevision: 1,
		NetworkDomain: networkDomain}).AuthorizeCustodyEffect(ctx, request); err == nil {
		t.Fatal("superseded writer authorized a chain effect")
	}
	authorization, err := (PaidDemandCustodyAuthorizer{Engine: engine, Fence: fence, PolicyRevision: 1,
		NetworkDomain: networkDomain}).AuthorizeCustodyEffect(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := buyersdk.NewTOSCTLWalletActionSender(buyersdk.TOSCTLWalletActionSenderConfig{BinaryPath: executable,
		ConfigPath: configPath, WalletName: wallet, FeeReserveNanoTOS: 50_000_000, VaultURL: os.Getenv("VAULT_URL")})
	if err != nil {
		t.Fatal(err)
	}
	intent := buyersdk.WalletActionIntent{StableActionID: authorization.StableActionID, NetworkID: fixture.Network.NetworkId,
		TransitionKind: "escrow.accept", Destination: fixture.EscrowAddress, AmountNanoTOS: 100_000_000,
		BodyBOCBase64: fixture.AcceptBodyBOC, BodyHash: fixture.AcceptBodyHash,
		ValidUntilUnix: uint32(minUint64(fixture.AcceptByUnix, uint64(time.Now().Add(5*time.Minute).Unix()))), Authorization: authorization}
	prepared, err := sender.PrepareWalletAction(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := sender.PrepareWalletAction(ctx, intent)
	if err != nil || replayed.MessageHash != prepared.MessageHash || replayed.MessageBOCBase64 != prepared.MessageBOCBase64 {
		t.Fatalf("same action did not reproduce exact signed BOC: err=%v", err)
	}
	if err := sender.BroadcastWalletAction(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	accepted := waitPaidDemandStatus(t, ctx, resolver, fixture.EscrowAddress, nativecore.EscrowStatusAwaitingFundingV2)
	if accepted.State.ProviderOfferDigest != fixture.ProviderOffer || accepted.State.AcceptedAtUnix == 0 || accepted.Reference.FinalizedCheckpoint == 0 {
		t.Fatalf("finalized acceptance is incomplete: %+v", accepted)
	}
	// Re-broadcasting the exact controller message exercises both custody and
	// contract replay behavior. It may be rejected as already resolved locally;
	// if submitted, the state must remain the exact accepted Quote.
	_ = sender.BroadcastWalletAction(ctx, prepared)
	rechecked := waitPaidDemandStatus(t, ctx, resolver, fixture.EscrowAddress, nativecore.EscrowStatusAwaitingFundingV2)
	if rechecked.State.QuoteCommitment != fixture.QuoteCommitment || rechecked.State.AcceptedAtUnix != accepted.State.AcceptedAtUnix {
		t.Fatal("exact accept replay changed commercial state")
	}
	t.Logf("quorum-finalized V2 acceptance account=%s checkpoint=%d transaction=%s",
		fixture.EscrowAddress, accepted.Reference.FinalizedCheckpoint, accepted.Reference.TransactionHash)
}

func waitPaidDemandStatus(t *testing.T, ctx context.Context, resolver *toschain.EscrowResolver, address string,
	status uint8) *toschain.FinalizedEscrowV2 {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		state, found, err := resolver.ResolveFinalizedV2(ctx, address)
		if err == nil && found && state.State.Status == status {
			return state
		}
		time.Sleep(time.Second)
	}
	t.Fatal("Paid Demand state did not finalize before timeout")
	return nil
}
