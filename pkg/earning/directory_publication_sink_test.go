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

func TestDirectoryPublicationIsWriterFencedAndDiscoverable(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	intent := earningIntent(t, now, issuerKey)
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:test", intent.Body.IssuerAgentID, "authority:test", authorityKey,
		PortfolioLimits{ComputeUnits: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "publisher", []string{"publication.publish"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTempDir(t)
	sink, err := OpenDirectoryPublicationSink(directory, "carrier:directory", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	engine := Engine{OwnerID: "owner:test", AgentID: intent.Body.IssuerAgentID, Authority: authority,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), Gates: FeatureGates{Publication: true},
		Collector:        Collector{Authority: PinnedIntentAuthorities{intent.Body.IssuerAgentID: issuerPublic}},
		PublicationSinks: map[string]PublicationSink{"carrier:directory": sink}, Now: func() time.Time { return now }}
	first, err := engine.PublishIntent(context.Background(), "carrier:directory", intent, 1, fence)
	if err != nil || first.State != commerce.ActionTerminal {
		t.Fatalf("publish=%+v err=%v", first, err)
	}
	retry, err := engine.PublishIntent(context.Background(), "carrier:directory", intent, 1, fence)
	if err != nil || retry.StableActionID != first.StableActionID {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	results, err := (DirectoryCarrier{CarrierID: "carrier:directory", Directory: directory}).Search(context.Background(), IntentQuery{MaximumResults: 10})
	if err != nil || len(results) != 1 {
		t.Fatalf("discover=%+v err=%v", results, err)
	}
	newFence, err := authority.AcquireWriter(context.Background(), "publisher-2", []string{"publication.publish"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intent.Body.Revision = 2
	intent.Body.PredecessorDigest = first.SinkReference
	intent, err = commerce.SignIntent(intent.Body, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.PublishIntent(context.Background(), "carrier:directory", intent, 1, fence); err == nil {
		t.Fatal("stale writer published a new revision")
	}
	if _, err := engine.PublishIntent(context.Background(), "carrier:directory", intent, 1, newFence); err != nil {
		t.Fatal(err)
	}
}
