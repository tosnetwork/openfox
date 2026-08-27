package earning

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
)

func TestGuarantorJournalPersistsOfferAndRejectsSplitWriter(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor"); err == nil {
		t.Fatal("second Guarantor writer acquired the same economic domain")
	}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	position := GuarantorOfferPosition{QuoteRequestDigest: digest("1"), CoveredPartyAgentID: "agent:covered",
		CoverageAsset: commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"},
		GrossExposureAtomic: "1000", NetExposureAtomic: "600", AcceptByUnix: 2_000_000_100,
		ReservationExpiresAt: 2_000_000_200, Record: guarantor.OfferRecord{OfferID: digest("2"),
			ReservationID: digest("3"), AgreementDigest: digest("4"), Status: guarantor.OfferReservedUnsigned,
			StateRevision: 3, LastEvidenceDigest: digest("5")}}
	if err := journal.ReserveUnsignedOffer(position); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	_, offers, _ := reopened.Snapshot()
	if len(offers) != 1 || offers[0].Record.Status != guarantor.OfferReservedUnsigned || offers[0].OfferEnvelopeDigest != "" {
		t.Fatalf("unexpected recovered Guarantor offer: %#v", offers)
	}
	conflict := position
	conflict.NetExposureAtomic = "601"
	if err := reopened.ReserveUnsignedOffer(conflict); err == nil {
		t.Fatal("same Guarantor offer identity accepted different exposure")
	}
}

func TestGuarantorAdmissionCutBlocksPreparedAndSurvivesRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	domainID, actionID, requestDigest := digest("a"), digest("b"), digest("c")
	journal, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	receivedAt := time.Unix(2_000_000_000, 0).UTC()
	entry, err := journal.BeginAdmission(domainID, actionID, requestDigest, receivedAt)
	if err != nil || entry.Sequence != 1 {
		t.Fatalf("begin admission: %#v %v", entry, err)
	}
	if _, err := journal.FreezeAdmissionCut(domainID, uint64(receivedAt.Unix())); err == nil {
		t.Fatal("prepared admission did not block the cut")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenGuarantorJournal(directory, "owner:test", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	resolution := commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest,
		State: commerce.ActionRejected, StateRevision: 2, EvidenceRefs: []string{digest("d")}}
	if _, err := journal.ResolveAdmission(domainID, resolution); err != nil {
		t.Fatal(err)
	}
	cut, err := journal.FreezeAdmissionCut(domainID, uint64(receivedAt.Unix()))
	if err != nil || cut.HighWater != 1 || cut.Entries[0].Resolution.State != commerce.ActionRejected ||
		!canonicalSHA256(cut.LogRoot) {
		t.Fatalf("unexpected recovered cut: %#v %v", cut, err)
	}
	if _, err := journal.BeginAdmission(domainID, actionID, digest("e"), receivedAt); err == nil {
		t.Fatal("same semantic admission identity accepted different request bytes")
	}
	if _, err := journal.BeginAdmission(domainID, digest("f"), digest("1"), receivedAt.Add(-time.Second)); err == nil {
		t.Fatal("admission log accepted a clock rollback")
	}
}

func TestGuarantorJournalRejectsTamperedAdmissionRoot(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "guarantor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	journal, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.BeginAdmission(digest("a"), digest("b"), digest("c"), time.Unix(2_000_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, guarantorJournalFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	logs := document["admission_logs"].(map[string]any)
	logs[digest("a")].(map[string]any)["current_root"] = digest("d")
	tampered, _ := json.Marshal(document)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenGuarantorJournal(directory, "owner:test", "agent:guarantor"); err == nil {
		_ = reopened.Close()
		t.Fatal("tampered admission root was accepted")
	}
}
