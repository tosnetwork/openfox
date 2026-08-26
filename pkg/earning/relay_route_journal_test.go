package earning

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestRelayPermanentReplayCapacityReservesEntryCounts(t *testing.T) {
	sponsorshipRecord := RelayRouteRecord{Hops: []RelayRouteHop{{Attempt: RelayAttempt{
		Execution: agentrelay.RelayExecutionRequest{QuoteRequest: agentrelay.SignedRelayQuoteRequest{
			Body: agentrelay.RelayQuoteRequestBody{Mode: agentrelay.ModeSponsorOnly}}}}}}}
	relayRecord := RelayRouteRecord{Hops: []RelayRouteHop{{Attempt: RelayAttempt{
		Execution: agentrelay.RelayExecutionRequest{QuoteRequest: agentrelay.SignedRelayQuoteRequest{
			Body: agentrelay.RelayQuoteRequestBody{Mode: agentrelay.ModeRelayExact}}}}}}}

	for _, test := range []struct {
		name                   string
		records                map[string]RelayRouteRecord
		terminalTombstoneCount int
		sponsorshipEffectCount int
		newMode                agentrelay.Mode
		wantRejected           bool
	}{
		{name: "terminal-count-already-full", terminalTombstoneCount: maximumRelayTerminalTombstones,
			newMode: agentrelay.ModeRelayExact, wantRejected: true},
		{name: "active-and-new-terminal-count-overflow",
			records:                map[string]RelayRouteRecord{"active": relayRecord},
			terminalTombstoneCount: maximumRelayTerminalTombstones - 1,
			newMode:                agentrelay.ModeRelayExact, wantRejected: true},
		{name: "sponsorship-count-already-full", sponsorshipEffectCount: maximumRelaySponsorshipEffects,
			newMode: agentrelay.ModeSponsorOnly, wantRejected: true},
		{name: "active-and-new-sponsorship-count-overflow",
			records:                map[string]RelayRouteRecord{"active": sponsorshipRecord},
			sponsorshipEffectCount: maximumRelaySponsorshipEffects - 1,
			newMode:                agentrelay.ModeSponsorOnly, wantRejected: true},
		{name: "exact-count-boundary", records: map[string]RelayRouteRecord{"active": sponsorshipRecord},
			terminalTombstoneCount: maximumRelayTerminalTombstones - 2,
			sponsorshipEffectCount: maximumRelaySponsorshipEffects - 2,
			newMode:                agentrelay.ModeSponsorOnly},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := DurableRelayRouteJournal{records: test.records,
				terminalTombstoneCount: test.terminalTombstoneCount,
				sponsorshipEffectCount: test.sponsorshipEffectCount}
			// Bytes deliberately remain zero: these cases prove that entry-count
			// exhaustion is enforced independently of aggregate byte capacity.
			err := journal.reservePermanentReplayCapacity(test.newMode)
			if test.wantRejected && err == nil {
				t.Fatal("count-saturated permanent replay registry admitted another route")
			}
			if !test.wantRejected && err != nil {
				t.Fatalf("exact permanent replay count boundary was rejected: %v", err)
			}
		})
	}
}

func TestDurableRelayRouteJournalFailsClosedAfterDirectoryReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit renaming this open directory")
	}
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	directory := filepath.Join(t.TempDir(), "owner-relay-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	moved := directory + "-moved"
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if replacement, err := OpenDurableRelayRouteJournal(directory); err == nil {
		_ = replacement.Close()
		t.Fatal("replacement directory created a concurrent logical route authority")
	}
	attempt := fixture.attempt(t)
	profileDigest, err := agentrelay.RelayServiceProfileDigest(fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	provider := RelayProviderProvenance{ProviderAgentID: fixture.profile.ProviderAgentID,
		IntentDigest: fixture.verified.IntentDigest(), ProfileDigest: profileDigest,
		OperatorDomain: "operator", FailureDomain: "failure", EndpointOrigin: "https://relay.example",
		CertificatePinDigest: relayTestDigest("1"), ImplementationEvidenceHash: relayTestDigest("2")}
	if _, _, err := journal.Bind(fixture.prepared, []RelayProviderProvenance{provider}, provider,
		attempt, 1, fixture.now); err == nil {
		t.Fatal("replaced relay journal directory did not fail closed")
	}
	if _, err := os.Lstat(filepath.Join(directory, relayRouteJournalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received route state: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableRelayRouteJournalPinsProtectedChildDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit renaming this open directory")
	}
	directory := filepath.Join(t.TempDir(), "owner-relay-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	original := journal.effectDirectory
	moved := original + "-moved"
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.sponsorshipChainEffectPath(relayTestDigest("a"), true); err == nil {
		t.Fatal("replaced sponsorship registry did not fail closed")
	}
	entries, err := os.ReadDir(original)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement sponsorship registry received state: entries=%d err=%v", len(entries), err)
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, original); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.sponsorshipChainEffectPath(relayTestDigest("a"), true); err == nil {
		t.Fatal("restoring a detached sponsorship registry cleared its permanent poison")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRelayPermanentRegistryCountIsBounded(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "registry")
	shard := filepath.Join(directory, "aa")
	if err := os.MkdirAll(shard, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.json", "two.json"} {
		if err := os.WriteFile(filepath.Join(shard, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pinned, err := openRelayPinnedDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	if count, bytes, err := countRelayPermanentRegistryPinned(pinned, ".", ".json", 2, 2, 4); err != nil || count != 2 || bytes != 4 {
		t.Fatalf("bounded registry count=%d bytes=%d err=%v", count, bytes, err)
	}
	if _, _, err := countRelayPermanentRegistryPinned(pinned, ".", ".json", 1, 2, 4); err == nil {
		t.Fatal("permanent registry above its cap was accepted")
	}
	if _, _, err := countRelayPermanentRegistryPinned(pinned, ".", ".json", 2, 2, 3); err == nil {
		t.Fatal("permanent registry above its aggregate byte cap was accepted")
	}
}

func TestRelayRouteOwnerDomainCannotSplitAcrossDirectories(t *testing.T) {
	first := &DurableRelayRouteJournal{}
	second := &DurableRelayRouteJournal{}
	if err := first.bindOwnerDomain("owner:test", "agent:test"); err != nil {
		t.Fatal(err)
	}
	defer first.closeOwnerDomain()
	if err := second.bindOwnerDomain("owner:test", "agent:test"); err == nil {
		second.closeOwnerDomain()
		t.Fatal("same owner and Agent acquired two route authority domains")
	}
	if err := second.bindOwnerDomain("owner:test", "agent:other"); err != nil {
		t.Fatalf("independent owner/Agent route domain was rejected: %v", err)
	}
	second.closeOwnerDomain()
}

func TestDurableRelayRouteJournalPinsSelectionBeforeSubmitAndAcrossRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	attempt := fixture.attempt(t)
	profileDigest, err := agentrelay.RelayServiceProfileDigest(fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	first := RelayProviderProvenance{ProviderAgentID: fixture.profile.ProviderAgentID,
		IntentDigest: fixture.verified.IntentDigest(), ProfileDigest: profileDigest,
		OperatorDomain: "operator:first", FailureDomain: "failure:first", EndpointOrigin: "https://relay.example",
		CertificatePinDigest: relayTestDigest("1"), ImplementationEvidenceHash: relayTestDigest("a")}
	second := RelayProviderProvenance{ProviderAgentID: "agent:provider-two",
		IntentDigest: relayTestDigest("2"), ProfileDigest: relayTestDigest("3"),
		OperatorDomain: "operator:second", FailureDomain: "failure:second", EndpointOrigin: "https://two.example",
		CertificatePinDigest: relayTestDigest("4"), ImplementationEvidenceHash: relayTestDigest("b")}
	directory := filepath.Join(t.TempDir(), "owner-relay-routes")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableRelayRouteJournal(directory); err == nil {
		t.Fatal("second process opened owner relay route journal")
	}
	record, created, err := journal.Bind(fixture.prepared, []RelayProviderProvenance{second, first}, first,
		attempt, 1, fixture.now)
	current, found := record.Current()
	if err != nil || !created || !found || current.Provider != first || current.Generation != 1 || current.SubmitStarted {
		t.Fatalf("initial relay route was not frozen: record=%+v created=%v err=%v", record, created, err)
	}
	executionDigest, _ := agentrelay.RelayExecutionRequestDigest(attempt.Execution)
	record, err = journal.MarkSubmitStarted(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, fixture.now.Add(time.Second))
	current, _ = record.Current()
	if err != nil || !current.SubmitStarted {
		t.Fatalf("relay submit ambiguity was not durably marked: record=%+v err=%v", record, err)
	}
	resolution, evidence := relayTerminalAbsent(t, fixture, attempt.Execution)
	result := RelayExecutionResult{Resolution: resolution, Evidence: &evidence}
	mismatched := result
	mismatched.Resolution.Body.EvidenceSetDigest = relayTestDigest("f")
	if _, err := journal.RecordTerminal(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, mismatched, fixture.now.Add(2*time.Second)); !errors.Is(err, agentrelay.ErrRelayInvalidState) {
		t.Fatalf("terminal resolution accepted a different evidence set: %v", err)
	}
	mismatched = result
	mismatched.Resolution.Body.Network.ZeroStateRootHash = relayTestDigest("f")
	if _, err := journal.RecordTerminal(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, mismatched, fixture.now.Add(2*time.Second)); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("terminal resolution accepted another genesis domain: %v", err)
	}
	record, err = journal.RecordTerminal(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, result, fixture.now.Add(2*time.Second))
	current, _ = record.Current()
	if err != nil || current.TerminalResolution == nil || current.TerminalFinalityEvidence == nil {
		t.Fatalf("relay terminal evidence was not durably recorded: record=%+v err=%v", record, err)
	}
	if len(journal.records) != 0 {
		t.Fatalf("terminal route still consumes a bounded hot slot: records=%d", len(journal.records))
	}
	if tombstone, found, err := journal.readTerminalRoute(record.StableActionID); err != nil || !found ||
		!reflect.DeepEqual(tombstone, record) {
		t.Fatalf("terminal route lifetime tombstone is missing: found=%v tombstone=%+v err=%v",
			found, tombstone, err)
	}
	if _, err := journal.RecordTerminal(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, result, fixture.now.Add(3*time.Second)); err != nil {
		t.Fatalf("exact terminal evidence replay was not idempotent: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	terminalPath, err := journal.terminalRoutePath(record.StableActionID, false)
	if err != nil {
		t.Fatal(err)
	}
	tombstoneRaw, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatal(err)
	}
	var tombstone relayTerminalRouteTombstone
	if err := json.Unmarshal(tombstoneRaw, &tombstone); err != nil {
		t.Fatal(err)
	}
	artifactPath, err := journal.terminalArtifactPath(tombstone.ProtectedArtifactDigest, false)
	if err != nil {
		t.Fatal(err)
	}
	untampered, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	var tampered relayTerminalRouteArtifact
	if err := json.Unmarshal(untampered, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Record.MaximumCumulativeServiceFeeAtomic = "999"
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if compromised, openErr := OpenDurableRelayRouteJournal(directory); openErr == nil {
		_, resolveErr := compromised.Resolve(record.StableActionID, record.ExactRequestDigest)
		_ = compromised.Close()
		if resolveErr == nil {
			t.Fatal("journal recovery accepted a cumulative fee cap above hop0 signed MaximumServiceFee")
		}
	}
	if err := os.WriteFile(artifactPath, untampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(untampered, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Record.CumulativeServiceFeeAtomic = "4"
	raw, err = json.Marshal(tampered)
	if err != nil || os.WriteFile(artifactPath, raw, 0o600) != nil {
		t.Fatalf("write cumulative-fee tamper: %v", err)
	}
	if compromised, openErr := OpenDurableRelayRouteJournal(directory); openErr == nil {
		_, resolveErr := compromised.Resolve(record.StableActionID, record.ExactRequestDigest)
		_ = compromised.Close()
		if resolveErr == nil {
			t.Fatal("journal recovery accepted cumulative fees inconsistent with its signed hops")
		}
	}
	if err := os.WriteFile(artifactPath, untampered, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Resolve(record.StableActionID, record.ExactRequestDigest)
	recoveredCurrent, _ := recovered.Current()
	if err != nil || !recoveredCurrent.SubmitStarted || recoveredCurrent.Provider != first ||
		!reflect.DeepEqual(recoveredCurrent.Attempt, attempt) ||
		!reflect.DeepEqual(recoveredCurrent.TerminalResolution, &resolution) ||
		!reflect.DeepEqual(recoveredCurrent.TerminalFinalityEvidence, &evidence) {
		t.Fatalf("selected provider/attempt did not survive restart: record=%+v err=%v", recovered, err)
	}
	// A fresh owner selection cannot replace a route whose selected provider
	// may already have observed the executable request.
	rebound, created, err := reopened.Bind(fixture.prepared, []RelayProviderProvenance{first, second}, first,
		attempt, 2, fixture.now.Add(4*time.Second))
	reboundCurrent, _ := rebound.Current()
	if err != nil || created || reboundCurrent.Provider != first {
		t.Fatalf("restart replaced the durably selected provider: record=%+v created=%v err=%v", rebound, created, err)
	}
	if _, err := reopened.Resolve(record.StableActionID, relayTestDigest("f")); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("same stable ID with another request was not fenced: %v", err)
	}
	// Crash-before-accounting recovery keeps the full artifact even under
	// storage pressure. Only an exact receipt from the independent accounting
	// handoff may make it archive-eligible; the small semantic tombstone remains
	// forever and continues to fence rebinding.
	if err := os.Chtimes(artifactPath, fixture.now.Add(-time.Hour), fixture.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= maximumRelayTerminalArtifacts; index++ {
		digest := "sha256:" + fmt.Sprintf("%064x", index)
		path, pathErr := reopened.terminalArtifactPath(digest, true)
		if pathErr != nil {
			t.Fatal(pathErr)
		}
		if writeErr := writeRelayJournalAtomic(filepath.Dir(path), path, []byte("{}")); writeErr != nil {
			t.Fatal(writeErr)
		}
		stamp := fixture.now.Add(time.Duration(index) * time.Second)
		if timeErr := os.Chtimes(path, stamp, stamp); timeErr != nil {
			t.Fatal(timeErr)
		}
	}
	if err := reopened.compactTerminalArtifacts(""); err == nil {
		t.Fatal("unacknowledged terminal artifacts were evicted under capacity pressure")
	}
	if _, err := os.Lstat(artifactPath); err != nil {
		t.Fatalf("crash-before-accounting terminal artifact was not preserved: %v", err)
	}
	reference, err := RelayTerminalHandoffReferenceForRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	accountingDirectory := filepath.Join(t.TempDir(), "terminal-accounting")
	if err := os.Mkdir(accountingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	accounting, err := OpenDurableRelayTerminalAccountingJournal(accountingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer accounting.Close()
	receipt, err := accounting.CommitRelayTerminalHandoff(t.Context(), reference,
		attempt, result, fixture.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcknowledgeTerminalHandoff(RelayTerminalHandoffAcknowledgement{
		Reference: reference, AccountingReceiptDigest: receipt.ReceiptDigest, AccountingRevision: receipt.Revision,
		AcknowledgedAt: time.Unix(int64(receipt.RecordedAtUnix), 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(artifactPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("accounting-acknowledged relay artifact was not archived at the bounded cache limit: %v", err)
	}
	if _, err := reopened.Resolve(record.StableActionID, record.ExactRequestDigest); !errors.Is(err, errRelayTerminalArtifactArchived) {
		t.Fatalf("archived route lost its explicit terminal fence: %v", err)
	}
	if _, created, err := reopened.Bind(fixture.prepared, []RelayProviderProvenance{first, second}, first,
		attempt, 1, fixture.now.Add(5*time.Second)); created || !errors.Is(err, errRelayTerminalArtifactArchived) {
		t.Fatalf("archived terminal route was rebound: created=%v err=%v", created, err)
	}
}

func TestDurableRelayRouteJournalReconcilesTerminalStorageCrashBoundaries(t *testing.T) {
	for _, test := range []struct {
		name           string
		writeTombstone bool
	}{{name: "artifact-before-tombstone"}, {name: "tombstone-before-hot-delete", writeTombstone: true}} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
			fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
			attempt := fixture.attempt(t)
			profileDigest, err := agentrelay.RelayServiceProfileDigest(fixture.profile)
			if err != nil {
				t.Fatal(err)
			}
			provenance := RelayProviderProvenance{ProviderAgentID: fixture.profile.ProviderAgentID,
				IntentDigest: fixture.verified.IntentDigest(), ProfileDigest: profileDigest,
				OperatorDomain: "operator:test", FailureDomain: "failure:test", EndpointOrigin: "https://relay.example",
				CertificatePinDigest: relayTestDigest("1"), ImplementationEvidenceHash: relayTestDigest("2")}
			directory := filepath.Join(t.TempDir(), "routes")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			journal, err := OpenDurableRelayRouteJournal(directory)
			if err != nil {
				t.Fatal(err)
			}
			active, _, err := journal.BindSingle(fixture.prepared, provenance, attempt, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			executionDigest, _ := agentrelay.RelayExecutionRequestDigest(attempt.Execution)
			active, err = journal.MarkSubmitStarted(active.StableActionID, active.ExactRequestDigest, 1,
				executionDigest, fixture.now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			resolution, evidence := relayTerminalAbsent(t, fixture, attempt.Execution)
			resolutionDigest, _ := agentrelay.RelayResolutionDigest(resolution.Body)
			evidenceDigest, _ := agentrelay.RelayFinalityEvidenceDigest(evidence.Body)
			terminal := cloneRelayRouteRecord(active)
			current := &terminal.Hops[len(terminal.Hops)-1]
			current.TerminalResolutionDigest, current.TerminalResolution = resolutionDigest, &resolution
			current.TerminalFinalityEvidenceDigest, current.TerminalFinalityEvidence = evidenceDigest, &evidence
			terminal.UpdatedAtUnix = uint64(fixture.now.Add(2 * time.Second).Unix())
			if !relayTerminalRecordIsMonotonicSuccessor(active, terminal) {
				t.Fatal("test terminal record is not a valid monotonic successor")
			}
			if test.writeTombstone {
				if err := journal.writeTerminalRoute(terminal); err != nil {
					t.Fatal(err)
				}
			} else {
				artifactDigest, err := codec.Digest(relayTerminalRouteArtifactDomain, terminal)
				if err != nil {
					t.Fatal(err)
				}
				path, err := journal.terminalArtifactPath(artifactDigest, true)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(relayTerminalRouteArtifact{
					Schema: relayTerminalRouteArtifactSchema, Record: terminal})
				if err != nil || writeRelayJournalAtomic(filepath.Dir(path), path, raw) != nil {
					t.Fatalf("write terminal artifact crash fixture: %v", err)
				}
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenDurableRelayRouteJournal(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			recovered, err := reopened.Resolve(active.StableActionID, active.ExactRequestDigest)
			if err != nil || !reflect.DeepEqual(recovered, terminal) || len(reopened.records) != 0 {
				t.Fatalf("terminal crash boundary did not reconcile: recovered=%+v hot=%d err=%v",
					recovered, len(reopened.records), err)
			}
		})
	}
}

func TestRelayProviderProvenanceRejectsSybilAndSharedFailureDomain(t *testing.T) {
	first := RelayProviderProvenance{ProviderAgentID: "agent:first", IntentDigest: relayTestDigest("1"),
		ProfileDigest: relayTestDigest("2"), OperatorDomain: "operator:shared", FailureDomain: "failure:first",
		EndpointOrigin: "https://shared.example", CertificatePinDigest: relayTestDigest("3"),
		ImplementationEvidenceHash: relayTestDigest("8")}
	second := RelayProviderProvenance{ProviderAgentID: "agent:second", IntentDigest: relayTestDigest("5"),
		ProfileDigest: relayTestDigest("6"), OperatorDomain: "operator:shared", FailureDomain: "failure:second",
		EndpointOrigin: "https://shared.example", CertificatePinDigest: relayTestDigest("7"),
		ImplementationEvidenceHash: relayTestDigest("4")}
	values := []RelayProviderProvenance{first, second}
	if relayProvenanceKey(values[0]) > relayProvenanceKey(values[1]) {
		values[0], values[1] = values[1], values[0]
	}
	if validIndependentRelayProvenance(values) {
		t.Fatal("two provider identities under one operator/origin were treated as decentralized")
	}
	second.OperatorDomain, second.EndpointOrigin = "operator:second", "https://second.example"
	values = []RelayProviderProvenance{first, second}
	if relayProvenanceKey(values[0]) > relayProvenanceKey(values[1]) {
		values[0], values[1] = values[1], values[0]
	}
	if !validIndependentRelayProvenance(values) {
		t.Fatal("distinct owner-attested operator/failure/origin/certificate domains were rejected")
	}
}

func TestRelayRouteTerminalSupersedesUnstartedQuerySuccessorAcrossRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider-one", nil, "https://one.example")
	attempt := fixture.attempt(t)
	profileDigest, _ := agentrelay.RelayServiceProfileDigest(fixture.profile)
	first := RelayProviderProvenance{ProviderAgentID: fixture.profile.ProviderAgentID,
		IntentDigest: fixture.verified.IntentDigest(), ProfileDigest: profileDigest,
		OperatorDomain: "operator:first", FailureDomain: "failure:first", EndpointOrigin: "https://one.example",
		CertificatePinDigest: relayTestDigest("1"), ImplementationEvidenceHash: relayTestDigest("a")}
	second := RelayProviderProvenance{ProviderAgentID: "agent:provider-two", IntentDigest: relayTestDigest("2"),
		ProfileDigest: relayTestDigest("3"), OperatorDomain: "operator:second", FailureDomain: "failure:second",
		EndpointOrigin: "https://two.example", CertificatePinDigest: relayTestDigest("4"),
		ImplementationEvidenceHash: relayTestDigest("b")}
	directory := filepath.Join(t.TempDir(), "terminal-cancels-query-draft")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := journal.Bind(fixture.prepared, []RelayProviderProvenance{first, second}, first,
		attempt, 2, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, _ := agentrelay.RelayExecutionRequestDigest(attempt.Execution)
	record, err = journal.MarkSubmitStarted(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, fixture.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	current, _ := record.Current()
	principal := current.Attempt.Execution.AdmissionReceipt.Body.AuthenticatedPrincipal
	authDigest, _ := relayTransportAuthenticationDigest(first, principal)
	networkDigest, _ := agentrelay.NetworkDomainDigest(current.Attempt.Execution.QuoteRequest.Body.Network)
	transactionDigest, _ := agentrelay.RelayTransactionIdentityDigest(current.Attempt.Execution.QuoteRequest.Body)
	query := relayRouteResolveQueryAttempt{SchemaVersion: 1, RouteGeneration: 1,
		ProviderAgentID: first.ProviderAgentID, ProviderProfileDigest: first.ProfileDigest,
		AuthenticatedPrincipal: principal, TransportAuthenticationDigest: authDigest, NetworkDigest: networkDigest,
		TransactionIdentityDigest: transactionDigest, StableActionID: record.StableActionID,
		ExactRequestDigest: record.ExactRequestDigest, RelayExecutionDigest: executionDigest,
		Outcome: relayResolveUnavailable, StartedAtUnix: uint64(fixture.now.Add(2 * time.Second).Unix()),
		CompletedAtUnix: uint64(fixture.now.Add(3 * time.Second).Unix())}
	record, err = journal.recordResolveQuery(record.StableActionID, record.ExactRequestDigest, 1, query)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := journal.recordResolveQuery(record.StableActionID, record.ExactRequestDigest, 1, query); err != nil ||
		!reflect.DeepEqual(replay, record) {
		t.Fatalf("exact Resolve query replay changed the durable gate: replay=%+v err=%v", replay, err)
	}
	conflict := query
	conflict.Outcome = relayResolveRemoteUnknown
	if _, err := journal.recordResolveQuery(record.StableActionID, record.ExactRequestDigest, 1, conflict); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("different Resolve outcome replaced the durable gate: %v", err)
	}
	draft := cloneRelayAttempt(attempt)
	draft.Execution.AdmissionReceipt = agentrelay.SignedRelaySideEffectAdmissionReceipt{}
	draft.Execution.QuoteRequest.Body.ProviderAgentID = second.ProviderAgentID
	draft.Execution.QuoteRequest.Body.RequestID = "request:provider-two"
	draft.Execution.ProviderQuote.Body.ProviderAgentID = second.ProviderAgentID
	record, err = journal.PrepareSwitch(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, second, draft, fixture.now.Add(4*time.Second))
	if err != nil || record.PendingSwitch == nil || record.PendingSwitch.AdmissionStarted {
		t.Fatalf("side-effect-free successor draft was not persisted: record=%+v err=%v", record, err)
	}
	pendingRaw, err := os.ReadFile(filepath.Join(directory, relayRouteJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	var pendingTamper relayRouteJournalDocument
	if err := json.Unmarshal(pendingRaw, &pendingTamper); err != nil {
		t.Fatal(err)
	}
	pendingTamper.Records[0].PendingSwitch.CumulativeServiceFeeAtomicAfter = "7"
	tamperedRaw, err := json.Marshal(pendingTamper)
	if err != nil {
		t.Fatal(err)
	}
	tamperedDirectory := filepath.Join(t.TempDir(), "pending-fee-tamper")
	if err := os.Mkdir(tamperedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tamperedDirectory, relayRouteJournalFile), tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if compromised, err := OpenDurableRelayRouteJournal(tamperedDirectory); err == nil {
		_ = compromised.Close()
		t.Fatal("journal recovery accepted a pending fee reservation inconsistent with its successor quote")
	}
	resolution, evidence := relayTerminalAbsent(t, fixture, attempt.Execution)
	record, err = journal.RecordTerminal(record.StableActionID, record.ExactRequestDigest, 1,
		executionDigest, RelayExecutionResult{Resolution: resolution, Evidence: &evidence},
		fixture.now.Add(5*time.Second))
	current, _ = record.Current()
	if err != nil || record.PendingSwitch != nil || current.FailoverQueryAttempt != nil ||
		current.TerminalResolution == nil || current.TerminalFinalityEvidence == nil {
		t.Fatalf("verified prior terminal result did not atomically cancel the unstarted draft: record=%+v err=%v", record, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayRouteJournal(directory)
	if err != nil {
		t.Fatalf("terminal-over-query transition did not survive restart: %v", err)
	}
	defer reopened.Close()
}
