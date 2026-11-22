package earning

import (
	"os"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// TestGuarantorPortfolioFailsOnAnAmountItCannotRead: a coverage whose released
// reservation consumed a paid or defaulted amount that does not parse holds an
// unknown exposure. The portfolio fails instead of counting it as zero, and
// counts the amounts it can read.
func TestGuarantorPortfolioFailsOnAnAmountItCannotRead(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	asset := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	agreement, claimID, reservation := digest("c"), digest("b"), digest("2")
	for name, test := range map[string]struct {
		paid, defaulted string
		want            string
	}{
		"both read":            {paid: "30", defaulted: "12", want: "42"},
		"paid unreadable":      {paid: "thirty", defaulted: "12"},
		"paid negative":        {paid: "-1", defaulted: "12"},
		"defaulted unreadable": {paid: "30", defaulted: "1e3"},
		"defaulted empty":      {paid: "30", defaulted: ""},
	} {
		t.Run(name, func(t *testing.T) {
			journal, _ := openTestGuarantorJournal(t)
			position := testCoverageWithClaim(claimID)
			position.Record.CoverageAgreementBodyDigest, position.Record.ReservationID = agreement, reservation
			position.Record.CoverageStatus = guarantor.CoverageClosed
			position.Terms.CoverageAsset = asset
			position.PaidAtomic, position.DefaultedAtomic = test.paid, test.defaulted
			journal.mu.Lock()
			journal.doc.Coverages[agreement] = position
			journal.mu.Unlock()
			authority := guarantorSnapshotAuthority{reservations: []ExposureReservation{
				{ReservationID: reservation, MaximumLossAtomic: 100, Released: true},
			}}
			coordinator := GuarantorProviderCoordinator{Journal: journal, Authority: authority}
			snapshot, err := coordinator.portfolioFor("agent:party", asset)
			if test.want == "" {
				if err == nil {
					t.Fatalf("a portfolio was summed over an amount that cannot be read: %#v", snapshot)
				}
				return
			}
			if err != nil || snapshot.AggregateReservedAtomic != test.want {
				t.Fatalf("portfolio: %#v err=%v, want an aggregate of %s", snapshot, err, test.want)
			}
		})
	}
}

// TestGuarantorJournalRefusesACoverageStoredUnderAnotherIdentity: a coverage
// is found by its key and summed by its record, so a document whose key and
// record name different coverage Agreements, or whose record names none, is
// refused at load.
func TestGuarantorJournalRefusesACoverageStoredUnderAnotherIdentity(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	key, claimID := digest("c"), digest("b")
	for name, test := range map[string]struct {
		record string
		loads  bool
	}{
		"the record names the key":          {record: key, loads: true},
		"the record names another coverage": {record: digest("d")},
		"the record names no coverage":      {record: ""},
	} {
		t.Run(name, func(t *testing.T) {
			journal, directory := openTestGuarantorJournal(t)
			rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) {
				position := testCoverageWithClaim(claimID)
				position.RevisionEpochs = map[string]GuarantorRevisionEpochState{claimID: testFrozenEpoch()}
				position.Record.CoverageAgreementBodyDigest = test.record
				doc.Coverages[key] = position
			})
			err := openTestGuarantorJournalErr(t, directory)
			if test.loads {
				if err != nil {
					t.Fatalf("a coverage stored under its own identity was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "stored under another identity") {
				t.Fatalf("a coverage stored under another identity: got %v", err)
			}
		})
	}
}

// TestGuarantorJournalReportsADetachedJournalAsThat: resolving an admission
// and saving a firm-offer issuance plan on a journal that is closed, or whose
// directory was replaced, fail with that reason and not as an invalid
// argument, which a caller would not retry.
func TestGuarantorJournalReportsADetachedJournalAsThat(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	resolution := commerce.ActionResolution{
		StableActionID: digest("1"), ExactRequestDigest: digest("2"),
		State: commerce.ActionTerminal, StateRevision: 2,
	}
	calls := map[string]func(journal *GuarantorJournal) error{
		"resolve an admission": func(journal *GuarantorJournal) error {
			_, err := journal.ResolveAdmission(digest("8"), resolution)
			return err
		},
		"save a firm-offer issuance plan": func(journal *GuarantorJournal) error {
			return journal.SaveFirmOfferIssuancePlan(GuarantorFirmOfferIssuancePlan{})
		},
	}
	for name, call := range calls {
		t.Run(name+" on a closed journal", func(t *testing.T) {
			journal, _ := openTestGuarantorJournal(t)
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			if err := call(journal); err == nil || !strings.Contains(err.Error(), "journal is closed") {
				t.Fatalf("got %v, want the closed journal reported", err)
			}
		})
		t.Run(name+" on a replaced directory", func(t *testing.T) {
			journal, directory := openTestGuarantorJournal(t)
			if _, err := journal.BeginAdmission(digest("8"), resolution.StableActionID,
				resolution.ExactRequestDigest, time.Unix(2_000_000_000, 0)); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(directory, directory+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := call(journal); err == nil || !strings.Contains(err.Error(), "directory was replaced") {
				t.Fatalf("got %v, want the replaced directory reported", err)
			}
		})
	}
}
