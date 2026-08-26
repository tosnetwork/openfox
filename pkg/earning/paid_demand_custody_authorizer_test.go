package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
)

type custodyEffectPinnedKey struct{ key ed25519.PublicKey }

func (resolver custodyEffectPinnedKey) AuthorizeCustodyKey(authorityID, ownerID, agentID string,
	key ed25519.PublicKey, _ time.Time) error {
	if authorityID != "authority-1" || ownerID != "owner-1" || agentID != "agent-1" || !resolver.key.Equal(key) {
		return errors.New("unexpected custody authority")
	}
	return nil
}

func TestPaidDemandCustodyAuthorizerBindsExactEffectAndFencesTakeover(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_800_000_000, 0).UTC()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime-a", []string{"escrow.transition"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
		"quote_commitment":      commerce.Digest32("sha256:" + strings.Repeat("1", 64)),
		"escrow_account_id":     commerce.ID("0:" + strings.Repeat("2", 64)),
		"transition_kind":       commerce.Kind("accept"),
		"expected_state_digest": commerce.Digest32("sha256:" + strings.Repeat("3", 64)),
	}
	request := buyersdk.CustodyEffectRequest{ActionKind: "escrow.accept", SemanticFields: fields,
		CanonicalRequest: []byte{0xa1, 0x61, 0x76, 0x01}, AgreementDigest: "sha256:" + strings.Repeat("4", 64),
		ObligationID: "pay-1", SourceAccount: "0:" + strings.Repeat("5", 64), NetworkID: "tos:testnet",
		NetworkGlobalID: -3, Destination: "0:" + strings.Repeat("2", 64), AmountNanoTOS: 100_000_000,
		BodyHash: "tvm-cell-sha256:" + strings.Repeat("6", 64), StateInitHashOrZero: zeroDigest(),
		ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix())}
	networkDomain := &commerce.CustodyNetworkDomain{NetworkID: request.NetworkID, GlobalID: request.NetworkGlobalID,
		ZeroStateRootHash: "sha256:" + strings.Repeat("8", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("9", 64), WorkchainID: 0}
	adapter := PaidDemandCustodyAuthorizer{Engine: &Engine{OwnerID: "owner-1", AgentID: "agent-1",
		MandateDigest: testDigest, Authority: authority, Gates: FeatureGates{TOSEscrow: true}}, Fence: fence,
		PolicyRevision: 7, NetworkDomain: networkDomain}
	signed, err := adapter.AuthorizeCustodyEffect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if signed.ActionKind != "escrow.accept" || signed.AgreementBodyDigest != request.AgreementDigest ||
		signed.ObligationID != request.ObligationID || signed.BodyHash != request.BodyHash || signed.WriterGeneration != fence.Body.WriterGeneration {
		t.Fatalf("custody effect binding changed: %+v", signed)
	}
	if signed.SchemaVersion != 2 || signed.NetworkDomain == nil || *signed.NetworkDomain != *networkDomain {
		t.Fatalf("custody effect omitted its exact network domain: %+v", signed)
	}
	if err := commerce.VerifyRelayCustodyEffectAuthorization(signed,
		custodyEffectPinnedKey{key: key.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatalf("verify custody effect: %v", err)
	}
	mutated := signed
	mutated.Destination = "0:" + strings.Repeat("7", 64)
	if err := commerce.VerifyCustodyEffectAuthorization(mutated,
		custodyEffectPinnedKey{key: key.Public().(ed25519.PublicKey)}, now); err == nil {
		t.Fatal("destination substitution retained authorization")
	}
	mutated = signed
	changedDomain := *mutated.NetworkDomain
	changedDomain.WorkchainID = -1
	mutated.NetworkDomain = &changedDomain
	if err := commerce.VerifyRelayCustodyEffectAuthorization(mutated,
		custodyEffectPinnedKey{key: key.Public().(ed25519.PublicKey)}, now); err == nil {
		t.Fatal("target-workchain substitution retained authorization")
	}
	if _, err := authority.AcquireWriter(context.Background(), "runtime-b", []string{"escrow.transition"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	request.CanonicalRequest = []byte{0xa1, 0x61, 0x76, 0x02}
	if _, err := adapter.AuthorizeCustodyEffect(context.Background(), request); err == nil {
		t.Fatal("stale runtime authorized a custody effect after takeover")
	}
}
