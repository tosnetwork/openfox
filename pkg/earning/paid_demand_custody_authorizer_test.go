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
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type custodyEffectPinnedKey struct{ key ed25519.PublicKey }

func (resolver custodyEffectPinnedKey) AuthorizeCustodyKey(authorityID, ownerID, agentID string,
	key ed25519.PublicKey, _ time.Time) error {
	if authorityID != "authority-1" || ownerID != "owner-1" || agentID != "agent-1" || !resolver.key.Equal(key) {
		return errors.New("unexpected custody authority")
	}
	return nil
}

func TestLiveReservationForNewEscrowExposure(t *testing.T) {
	agreementDigest := "sha256:" + strings.Repeat("4", 64)
	record := EngagementRecord{AgreementDigest: agreementDigest, Agreement: commerce.AgentAgreement{
		Body: commerce.AgentAgreementBody{Obligations: []commerce.AgreementObligation{{
			ObligationID: "pay-1", ObligorAgentID: "agent-1", SettlementAdapterURI: paiddemand.SettlementAdapterURI,
			Amount: &commerce.AgreementAmount{AssetNamespace: "tos.contract",
				AssetIdentifier: "0:" + strings.Repeat("a", 64), Unit: "atomic", AmountAtomic: "100"},
		}}},
	}}
	expected, err := paidDemandBuyerReservation(record, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	record.ReservationID = expected.ReservationID
	document := authorityDocument{Reservations: map[string]ExposureReservation{
		expected.ReservationID: expected,
	}}
	if !exactLivePaidDemandReservation(document, record, "agent-1", agreementDigest, "pay-1") {
		t.Fatal("exact live reservation was not recognized")
	}
	if exactLivePaidDemandReservation(document, record, "agent-1", agreementDigest, "missing-payment") {
		t.Fatal("unknown Agreement obligation retained new escrow exposure authority")
	}

	mutations := []struct {
		name   string
		mutate func(*authorityDocument)
	}{
		{name: "missing", mutate: func(document *authorityDocument) { delete(document.Reservations, expected.ReservationID) }},
		{name: "released", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.Released = true
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "map identity mismatch", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.ReservationID = "reservation:other"
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "agreement mismatch", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.AgreementDigest = "sha256:" + strings.Repeat("7", 64)
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "zero exposure", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.SpendAtomic = 0
			reservation.LockedCapitalAtomic = 0
			reservation.MaximumLossAtomic = 0
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "undersized spend", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.SpendAtomic--
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "undersized locked capital", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.LockedCapitalAtomic--
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "undersized maximum loss", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			reservation.MaximumLossAtomic--
			document.Reservations[expected.ReservationID] = reservation
		}},
		{name: "wrong asset", mutate: func(document *authorityDocument) {
			reservation := document.Reservations[expected.ReservationID]
			asset := *reservation.Asset
			asset.AssetIdentifier = "0:" + strings.Repeat("b", 64)
			reservation.Asset = &asset
			document.Reservations[expected.ReservationID] = reservation
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := cloneAuthorityDocument(document)
			mutation.mutate(&candidate)
			if exactLivePaidDemandReservation(candidate, record, "agent-1", agreementDigest, "pay-1") {
				t.Fatal("invalid reservation retained new escrow exposure authority")
			}
		})
	}
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
	record := EngagementRecord{AgreementDigest: request.AgreementDigest, Agreement: commerce.AgentAgreement{
		Body: commerce.AgentAgreementBody{Obligations: []commerce.AgreementObligation{{
			ObligationID: request.ObligationID, ObligorAgentID: "agent-1", SettlementAdapterURI: paiddemand.SettlementAdapterURI,
			Amount: &commerce.AgreementAmount{AssetNamespace: "tos.contract",
				AssetIdentifier: "0:" + strings.Repeat("a", 64), Unit: "atomic", AmountAtomic: "100000000"},
		}}},
	}}
	reservation, err := paidDemandBuyerReservation(record, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	record.ReservationID = reservation.ReservationID
	authority.mu.Lock()
	authority.doc.Engagements[request.AgreementDigest] = record
	authority.doc.Reservations[reservation.ReservationID] = reservation
	authority.mu.Unlock()
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
	authority.mu.Lock()
	forked := authority.doc.Engagements[request.AgreementDigest]
	forked.NegotiationAmbiguous = true
	authority.doc.Engagements[request.AgreementDigest] = forked
	authority.mu.Unlock()
	request.CanonicalRequest = []byte{0xa1, 0x61, 0x76, 0x03}
	if _, err := adapter.AuthorizeCustodyEffect(context.Background(), request); err == nil {
		t.Fatal("ambiguous Agreement lineage authorized another escrow effect")
	}
	authority.mu.Lock()
	forked.NegotiationAmbiguous = false
	authority.doc.Engagements[request.AgreementDigest] = forked
	released := authority.doc.Reservations[forked.ReservationID]
	released.Released = true
	authority.doc.Reservations[forked.ReservationID] = released
	authority.mu.Unlock()
	request.CanonicalRequest = []byte{0xa1, 0x61, 0x76, 0x04}
	if _, err := adapter.AuthorizeCustodyEffect(context.Background(), request); err == nil {
		t.Fatal("released Portfolio reservation authorized another escrow effect")
	}
	authority.mu.Lock()
	released.Released = false
	authority.doc.Reservations[forked.ReservationID] = released
	authority.mu.Unlock()
	if _, err := authority.AcquireWriter(context.Background(), "runtime-b", []string{"escrow.transition"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	request.CanonicalRequest = []byte{0xa1, 0x61, 0x76, 0x02}
	if _, err := adapter.AuthorizeCustodyEffect(context.Background(), request); err == nil {
		t.Fatal("stale runtime authorized a custody effect after takeover")
	}
}
