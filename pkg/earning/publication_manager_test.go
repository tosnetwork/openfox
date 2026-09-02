package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestPublicationManagerEnforcesPricingRevisionAndWithdrawal(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	intent.Body.Payload.DiscoveryCard.IntentModes = []commerce.IntentMode{commerce.IntentOffer}
	intent.Body.Payload.DiscoveryCard.ValueHints[0].MinimumDecimal = "150"
	intent.Body.Payload.DiscoveryCard.ValueHints[0].MaximumDecimal = "150"
	intent.Body.Payload.DiscoveryCard.ValueHints[0].Unit = "atomic"
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:test", intent.Body.IssuerAgentID, "authority:test", authorityKey,
		PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "publisher", []string{"publication.publish", "publication.withdraw"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	carrierDirectory := privateTempDir(t)
	sink, err := OpenDirectoryPublicationSink(carrierDirectory, "carrier:directory", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	inventory := InventorySnapshot{OwnerID: "owner:test", AgentID: intent.Body.IssuerAgentID, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1,
		ConsistencyToken: "inventory:publication", SupportedSettlementAdapters: []string{}}
	engine := &Engine{OwnerID: "owner:test", AgentID: intent.Body.IssuerAgentID, Authority: authority,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), Gates: FeatureGates{Publication: true},
		Collector:        Collector{Authority: PinnedIntentAuthorities{intent.Body.IssuerAgentID: issuerPublic}},
		PublicationSinks: map[string]PublicationSink{"carrier:directory": sink}, Now: func() time.Time { return now }}
	publicationDirectory := privateTempDir(t)
	manager, err := OpenPublicationManager(publicationDirectory, engine, staticInventory{value: inventory}, issuerKey, PublicationPolicy{
		MinimumTTL: time.Minute, MaximumTTL: 24 * time.Hour, MinimumMarginPPM: 200_000, MaximumPriceChangePPM: 250_000,
		MaximumActive: 2, MaximumRevisionsPerObject: 3, MaximumPublicationsPerPeriod: 4, Period: time.Hour,
		AllowedAudiences: []string{"public:indexable"}, AllowDemand: true})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	manager.now = func() time.Time { return now }
	draft := PublicationDraft{Body: intent.Body, Economics: PublicationEconomics{RevenueAtomic: "150", UnitCostAtomic: "100",
		AssetNamespace: "tos.asset", AssetIdentifier: "native", ValueHintRole: "budget", Unit: "atomic",
		EvidenceDigest: "sha256:" + strings.Repeat("5", 64), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}
	record, err := manager.Publish(context.Background(), draft, []string{"carrier:directory"}, 1, fence)
	if err != nil || record.Status != "active" || record.RevisionCount != 1 {
		t.Fatalf("publish=%+v err=%v", record, err)
	}
	readOnly, err := ReadPublicationRecords(publicationDirectory)
	if err != nil || len(readOnly) != 1 || readOnly[0].LatestDigest != record.LatestDigest {
		t.Fatalf("read-only publication snapshot=%+v err=%v", readOnly, err)
	}
	retry, err := manager.Publish(context.Background(), draft, []string{"carrier:directory"}, 1, fence)
	if err != nil || retry.LatestDigest != record.LatestDigest || retry.RevisionCount != 1 {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	revision := draft
	revision.Body.Revision = 2
	revision.Body.PredecessorDigest = record.LatestDigest
	revision.Economics.RevenueAtomic = "250"
	revision.Body.Payload.DiscoveryCard.ValueHints[0].MinimumDecimal = "250"
	revision.Body.Payload.DiscoveryCard.ValueHints[0].MaximumDecimal = "250"
	if _, err := manager.Revise(context.Background(), revision, []string{"carrier:directory"}, 1, fence); err == nil {
		t.Fatal("excessive price change was published")
	}
	revision.Economics.RevenueAtomic = "180"
	revision.Body.Payload.DiscoveryCard.ValueHints[0].MinimumDecimal = "180"
	revision.Body.Payload.DiscoveryCard.ValueHints[0].MaximumDecimal = "180"
	revised, err := manager.Revise(context.Background(), revision, []string{"carrier:directory"}, 1, fence)
	if err != nil || revised.RevisionCount != 2 {
		t.Fatalf("revise=%+v err=%v", revised, err)
	}
	withdrawn, err := manager.Withdraw(context.Background(), revision.Body.ObjectID, "capacity-unavailable", 1, fence)
	if err != nil || withdrawn.Status != "withdrawn" {
		t.Fatalf("withdraw=%+v err=%v", withdrawn, err)
	}
	originalWithdrawalDigest, err := commerce.IntentWithdrawalDigest(withdrawn.PendingWithdrawal.Body)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the legacy crash window: the Carrier retained the exact signed
	// tombstone but the local journal retained neither it nor its resolution.
	legacy := withdrawn
	legacy.Status = "withdrawing"
	legacy.PendingWithdrawal = nil
	legacy.WithdrawalActions = nil
	if err := manager.storeRecord(legacy, false); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager, err = OpenPublicationManager(publicationDirectory, engine, staticInventory{value: inventory}, issuerKey, PublicationPolicy{
		MinimumTTL: time.Minute, MaximumTTL: 24 * time.Hour, MinimumMarginPPM: 200_000, MaximumPriceChangePPM: 250_000,
		MaximumActive: 2, MaximumRevisionsPerObject: 3, MaximumPublicationsPerPeriod: 4, Period: time.Hour,
		AllowedAudiences: []string{"public:indexable"}, AllowDemand: true})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	manager.now = func() time.Time { return now }
	recovered, err := manager.Withdraw(context.Background(), revision.Body.ObjectID, "capacity-unavailable", 1, fence)
	if err != nil || recovered.Status != "withdrawn" || recovered.PendingWithdrawal == nil || len(recovered.WithdrawalActions) != 1 {
		t.Fatalf("recovered withdrawal=%+v err=%v", recovered, err)
	}
	recoveredDigest, err := commerce.IntentWithdrawalDigest(recovered.PendingWithdrawal.Body)
	if err != nil || recoveredDigest != originalWithdrawalDigest {
		t.Fatalf("recovered a different signed withdrawal: got %q want %q err=%v", recoveredDigest, originalWithdrawalDigest, err)
	}
	page, err := (DirectoryCarrier{CarrierID: "carrier:directory", Directory: carrierDirectory}).Search(context.Background(), IntentQuery{MaximumResults: 10})
	if err != nil || len(page) != 3 || page[0].Intent.Body.Revision != 1 || page[1].Intent.Body.Revision != 2 || page[2].Withdrawal == nil ||
		page[2].Withdrawal.Body.IntentDigest != revised.LatestDigest { // Consumers, not the Carrier, apply the signed tombstone.
		t.Fatalf("post-withdraw discovery=%+v err=%v", page, err)
	}
	demand := intent.Body
	demand.ObjectID = "intent:" + strings.Repeat("9", 64)
	demand.Revision, demand.PredecessorDigest = 1, ""
	demand.Payload.DiscoveryCard.IntentModes = []commerce.IntentMode{commerce.IntentRequest}
	demandRecord, err := manager.Publish(context.Background(), PublicationDraft{Body: demand}, []string{"carrier:directory"}, 1, fence)
	if err != nil || demandRecord.Status != "active" {
		t.Fatalf("generic demand publication=%+v err=%v", demandRecord, err)
	}
}

func TestPublicationManagerBindsNonDegeneratePriceRange(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	intent.Body.Payload.DiscoveryCard.IntentModes = []commerce.IntentMode{commerce.IntentOffer}
	intent.Body.Payload.DiscoveryCard.ValueHints[0].AmountKind = "range"
	intent.Body.Payload.DiscoveryCard.ValueHints[0].MinimumDecimal = "100"
	intent.Body.Payload.DiscoveryCard.ValueHints[0].MaximumDecimal = "180"
	intent.Body.Payload.DiscoveryCard.ValueHints[0].Unit = "atomic"
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:range", intent.Body.IssuerAgentID,
		"authority:range", authorityKey, PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "range-publisher",
		[]string{"publication.publish"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	carrierDirectory := privateTempDir(t)
	sink, err := OpenDirectoryPublicationSink(carrierDirectory, "carrier:range", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	inventory := InventorySnapshot{OwnerID: "owner:range", AgentID: intent.Body.IssuerAgentID,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		SourceGeneration: 1, PortfolioRevision: 1, PolicyRevision: 1, ConsistencyToken: "inventory:range"}
	engine := &Engine{OwnerID: "owner:range", AgentID: intent.Body.IssuerAgentID, Authority: authority,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), Gates: FeatureGates{Publication: true},
		Collector:        Collector{Authority: PinnedIntentAuthorities{intent.Body.IssuerAgentID: issuerPublic}},
		PublicationSinks: map[string]PublicationSink{"carrier:range": sink}, Now: func() time.Time { return now }}
	manager, err := OpenPublicationManager(privateTempDir(t), engine, staticInventory{value: inventory}, issuerKey,
		PublicationPolicy{MinimumTTL: time.Minute, MaximumTTL: 24 * time.Hour, MinimumMarginPPM: 100_000,
			MaximumPriceChangePPM: 250_000, MaximumActive: 2, MaximumRevisionsPerObject: 3,
			MaximumPublicationsPerPeriod: 4, Period: time.Hour, AllowedAudiences: []string{"public:indexable"}, AllowDemand: true})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	manager.now = func() time.Time { return now }
	draft := PublicationDraft{Body: intent.Body, Economics: PublicationEconomics{RevenueAtomic: "100",
		MaximumRevenueAtomic: "180", UnitCostAtomic: "50", AssetNamespace: "tos.asset",
		AssetIdentifier: "native", ValueHintRole: "budget", Unit: "atomic",
		EvidenceDigest: "sha256:" + strings.Repeat("5", 64), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}
	record, err := manager.Publish(context.Background(), draft, []string{"carrier:range"}, 1, fence)
	if err != nil || record.Status != "active" || record.Economics.MaximumRevenueAtomic != "180" {
		t.Fatalf("range publish=%+v err=%v", record, err)
	}
	invalid := draft
	invalid.Body.ObjectID += ":invalid"
	invalid.Economics.MaximumRevenueAtomic = "99"
	if _, err := manager.Publish(context.Background(), invalid, []string{"carrier:range"}, 1, fence); err == nil {
		t.Fatal("inverted economic range was published")
	}
	mismatch := draft
	mismatch.Body.ObjectID += ":mismatch"
	mismatch.Economics.MaximumRevenueAtomic = "179"
	if _, err := manager.Publish(context.Background(), mismatch, []string{"carrier:range"}, 1, fence); err == nil {
		t.Fatal("range evidence not equal to the signed value hint was published")
	}
}
