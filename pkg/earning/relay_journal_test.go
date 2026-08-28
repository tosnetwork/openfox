package earning

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestDurableRelayJournalFailsClosedAfterDirectoryReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit renaming this open directory")
	}
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	directory := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.BindRelayProviderAuthority(fixture.profile.ProviderAgentID); err != nil {
		t.Fatal(err)
	}
	if !journal.HasLinearizableRelayProviderJournal() {
		t.Fatal("healthy provider journal did not advertise linearizable admission")
	}
	attempt := fixture.attempt(t)
	if _, created, err := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, fixture.now); err != nil || !created {
		t.Fatalf("seed quote reservation: created=%v err=%v", created, err)
	}
	record, created, err := journal.Admit(attempt.Execution, fixture.now)
	if err != nil || !created {
		t.Fatalf("seed execution admission: created=%v err=%v", created, err)
	}
	moved := directory + "-moved"
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if replacement, err := OpenDurableRelayJournal(directory); err == nil {
		_ = replacement.Close()
		t.Fatal("replacement directory acquired the same live provider journal domain")
	}
	if _, _, err := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, fixture.now); err == nil {
		t.Fatal("detached provider journal returned an existing quote")
	}
	if _, err := journal.Resolve(record.StableActionID, record.ExactRequestDigest); err == nil {
		t.Fatal("detached provider journal returned an authoritative execution record")
	}
	if journal.HasLinearizableRelayProviderJournal() {
		t.Fatal("detached provider journal continued advertising linearizable admission")
	}
	if _, err := os.Lstat(filepath.Join(directory, relayJournalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received provider state: %v", err)
	}
	replacementDirectory := directory + "-replacement"
	if err := os.Rename(directory, replacementDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, directory); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, fixture.now); err == nil {
		t.Fatal("poisoned provider journal resumed after its pathname was restored")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if journal.HasLinearizableRelayProviderJournal() {
		t.Fatal("closed provider journal continued advertising linearizable admission")
	}
	replacement, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatalf("replacement provider journal did not become available after clean close: %v", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableRelayJournalRejectsDuplicateJSONKeys(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, relayJournalFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"schema":`),
		[]byte(`"schema":"tos.openfox.agent-relay-journal.v2","schema":`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableRelayJournal(directory); err == nil {
		t.Fatal("provider journal accepted duplicate JSON keys")
	}
}

func TestDurableRelayJournalProviderDomainIsUniqueAcrossDirectories(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	open := func(name string) *DurableRelayJournal {
		directory := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		journal, err := OpenDurableRelayJournal(directory)
		if err != nil {
			t.Fatal(err)
		}
		return journal
	}
	first, second := open("first"), open("second")
	if err := first.BindRelayProviderAuthority(fixture.profile.ProviderAgentID); err != nil {
		t.Fatal(err)
	}
	if err := second.BindRelayProviderAuthority(fixture.profile.ProviderAgentID); err == nil {
		t.Fatal("one provider identity acquired two live journal domains")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.BindRelayProviderAuthority(fixture.profile.ProviderAgentID); err != nil {
		t.Fatalf("provider domain did not become available after clean close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableRelayJournalFreezesBytesCASAndRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	attempt := fixture.attempt(t)
	directory := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableRelayJournal(directory); err == nil {
		t.Fatal("second relay journal process lock was admitted")
	}
	if _, created, err := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, fixture.now); err != nil || !created {
		t.Fatalf("durable quote reservation: created=%v err=%v", created, err)
	}
	first, created, err := journal.Admit(attempt.Execution, fixture.now)
	if err != nil || !created || first.State != commerce.ActionPrepared {
		t.Fatalf("first admission: created=%v record=%+v err=%v", created, first.Snapshot(), err)
	}
	retry, created, err := journal.Admit(attempt.Execution, fixture.now)
	if err != nil || created || !reflect.DeepEqual(retry.Snapshot(), first.Snapshot()) {
		t.Fatalf("exact retry changed frozen record: created=%v err=%v", created, err)
	}

	mutated := attempt.Execution
	mutated.SignedTransactionBytes = append([]byte(nil), mutated.SignedTransactionBytes...)
	mutated.SignedTransactionBytes[0] ^= 0xff
	mutatedDigest, _ := agentrelay.SignedTransactionDigest(mutated.SignedTransactionBytes)
	mutated.QuoteRequest.Body.SignedTransactionDigest = mutatedDigest
	mutated.QuoteRequest, err = agentrelay.SignRelayQuoteRequest(mutated.QuoteRequest.Body, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	mutated.ProviderQuote.Body.QuoteRequestDigest, _ = agentrelay.RelayQuoteRequestDigest(mutated.QuoteRequest.Body)
	mutated.ProviderQuote.Body.QuoteID = "quote:mutated-bytes"
	mutated.ProviderQuote, err = agentrelay.SignProviderRelayQuote(mutated.ProviderQuote.Body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Admit(mutated, fixture.now); err == nil {
		t.Fatal("same semantic action with different signed bytes bypassed its admission receipt")
	}
	crossNetwork := attempt.Execution
	crossNetwork.QuoteRequest.Body.Network.NetworkID = "tos:othernet"
	crossNetwork.QuoteRequest.Body.Network.GlobalID++
	crossNetwork.QuoteRequest, err = agentrelay.SignRelayQuoteRequest(crossNetwork.QuoteRequest.Body, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Admit(crossNetwork, fixture.now); err == nil {
		t.Fatal("provider-wide stable action was admitted on a second network without a matching receipt")
	}

	submitted, err := journal.Transition(first.StableActionID, first.ExactRequestDigest, first.StateRevision,
		commerce.ActionSubmitted, "", nil, "", fixture.now.Add(time.Second))
	if err != nil || submitted.State != commerce.ActionSubmitted {
		t.Fatalf("submitted transition: record=%+v err=%v", submitted.Snapshot(), err)
	}
	if _, err := journal.Transition(first.StableActionID, first.ExactRequestDigest, first.StateRevision,
		commerce.ActionAccepted, "tx:stale", nil, "", fixture.now.Add(2*time.Second)); !errors.Is(err, agentrelay.ErrRelayInvalidState) {
		t.Fatalf("stale CAS revision was accepted: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(filepath.Join(directory, relayJournalFile))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("relay journal file is not owner-only: info=%v err=%v", info, err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Resolve(first.StableActionID, first.ExactRequestDigest)
	if err != nil || recovered.State != commerce.ActionSubmitted ||
		!reflect.DeepEqual(recovered.ExecutionRequest().SignedTransactionBytes,
			attempt.Execution.SignedTransactionBytes) {
		t.Fatalf("relay restart did not recover exact submitted bytes: state=%s err=%v", recovered.State, err)
	}
}

func TestDurableRelayJournalPersistsReceiptAndAllowsPreTakeoverDrain(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	preTakeover := fixture.attempt(t)
	takeoverFence := fixture.takeoverFence(t)
	fixture.resolver.setCurrentWriter(takeoverFence)
	postTakeoverPrepared, err := clonePreparedRelayTransaction(fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	postTakeoverPrepared.WriterFence = takeoverFence
	postTakeoverPrepared.UnderlyingActionRequest = []byte{0xa1, 0x01, 0x03}
	postTakeoverPrepared.SemanticFields["obligation_instance_id"] = commerce.Digest32(relayTestDigest("7"))
	priorAction := fixture.prepared.UnderlyingAction
	postTakeoverAction, err := commerce.BuildAuthorizedAction(priorAction.OwnerID, priorAction.AgentID,
		priorAction.ActionKind, postTakeoverPrepared.SemanticFields, postTakeoverPrepared.UnderlyingActionRequest,
		takeoverFence, priorAction.PolicyRevision, priorAction.MandateDigest, priorAction.ApprovalDigest,
		priorAction.ExpectedPriorState, priorAction.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	postTakeoverAction, err = commerce.SignAuthorizedAction(postTakeoverAction, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	postTakeoverPrepared.UnderlyingAction = postTakeoverAction
	postTakeoverPrepared.QuoteBody.RequestID = "request:post-takeover"
	postTakeoverPrepared.QuoteBody.StableActionID = postTakeoverAction.StableActionID
	postTakeoverPrepared.QuoteBody.ExactRequestDigest = postTakeoverAction.ExactRequestDigest
	fixture.prepared = postTakeoverPrepared
	postTakeover := fixture.attempt(t)
	directory := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := journal.ReserveQuote(fixture.profile, preTakeover.Execution.QuoteRequest,
		preTakeover.Execution.ProviderQuote, fixture.now); err != nil || !created {
		t.Fatalf("pre-takeover quote reservation: created=%v err=%v", created, err)
	}
	if _, created, err := journal.ReserveQuote(fixture.profile, postTakeover.Execution.QuoteRequest,
		postTakeover.Execution.ProviderQuote, fixture.now); err != nil || !created {
		t.Fatalf("post-takeover quote reservation: created=%v err=%v", created, err)
	}
	newer, created, err := journal.Admit(postTakeover.Execution, fixture.now)
	if err != nil || !created {
		t.Fatalf("post-takeover admission: created=%v err=%v", created, err)
	}
	older, created, err := journal.Admit(preTakeover.Execution, fixture.now.Add(time.Second))
	if err != nil || !created {
		t.Fatalf("receipt issued before takeover did not drain after higher generation: created=%v err=%v", created, err)
	}
	alternateReceipt := preTakeover.Execution
	alternateBody := alternateReceipt.AdmissionReceipt.Body
	alternateBody.AdmissionSequence += 100
	alternateReceipt.AdmissionReceipt, err = agentrelay.SignRelaySideEffectAdmissionReceipt(alternateBody, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Admit(alternateReceipt, fixture.now.Add(2*time.Second)); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("same action with a different admission receipt was not conflict: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if retry, created, err := reopened.Admit(preTakeover.Execution, fixture.now.Add(3*time.Second)); err != nil || created || retry.AdmissionReceiptDigest != older.AdmissionReceiptDigest {
		t.Fatalf("restart did not preserve the exact pre-takeover receipt: created=%v digest=%q err=%v",
			created, retry.AdmissionReceiptDigest, err)
	}
	ownerKey := preTakeover.Execution.AuthorizedAction.OwnerID + "\x00" + preTakeover.Execution.AuthorizedAction.AgentID
	if reopened.writerHighWater[ownerKey] != 2 {
		t.Fatalf("writer high-water audit metadata did not survive restart: %d", reopened.writerHighWater[ownerKey])
	}
	if recovered, err := reopened.Resolve(newer.StableActionID, newer.ExactRequestDigest); err != nil ||
		recovered.ExecutionRequest().AuthorizedAction.WriterGeneration != 2 {
		t.Fatalf("post-takeover receipt was not recovered: record=%+v err=%v", recovered.Snapshot(), err)
	}
}

func TestDurableRelayJournalRejectsSymlinkAndPublicDirectory(t *testing.T) {
	publicDirectory := filepath.Join(t.TempDir(), "public-relay")
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableRelayJournal(publicDirectory); err == nil {
		t.Fatal("public relay journal directory was accepted")
	}
	privateDirectory := filepath.Join(t.TempDir(), "private-relay")
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("not a journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(privateDirectory, relayJournalFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableRelayJournal(privateDirectory); err == nil {
		t.Fatal("symlink relay journal was accepted")
	}
}

func TestDurableRelayJournalReservesAggregateSponsorshipAcrossRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	profile := fixture.profile
	profile.SupportedModes = []agentrelay.Mode{agentrelay.ModeRelayExact, agentrelay.ModeSponsorOnly}
	profile.ExposureLimits[0].MaximumPerRequestAtomic = "6000"
	profile.ExposureLimits[0].MaximumOutstandingAtomic = "10000"
	requestOne, quoteOne := relaySponsorReservation(t, fixture, profile, "request:sponsor-one", "6000")
	directory := filepath.Join(t.TempDir(), "relay-exposure")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if reserved, created, err := journal.ReserveQuote(profile, requestOne, quoteOne, fixture.now); err != nil || !created || !reflect.DeepEqual(reserved, quoteOne) {
		t.Fatalf("first sponsorship reservation: created=%v err=%v", created, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reserved, created, err := reopened.ReserveQuote(profile, requestOne, quoteOne, fixture.now.Add(time.Second)); err != nil || created || !reflect.DeepEqual(reserved, quoteOne) {
		t.Fatalf("restart did not return the exact reserved quote: created=%v err=%v", created, err)
	}
	requestTwo, quoteTwo := relaySponsorReservation(t, fixture, profile, "request:sponsor-two", "6000")
	if _, _, err := reopened.ReserveQuote(profile, requestTwo, quoteTwo, fixture.now.Add(time.Second)); !errors.Is(err, agentrelay.ErrRelayExposure) {
		t.Fatalf("aggregate outstanding sponsorship was not enforced after restart: %v", err)
	}
}

func TestDurableRelayJournalCheckpointsSponsorshipBeforeBroadcast(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = relayTestDigest("6")
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	directory := filepath.Join(t.TempDir(), "relay-sponsorship")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.ReserveQuote(fixture.profile, execution.QuoteRequest, execution.ProviderQuote, fixture.now); err != nil {
		t.Fatal(err)
	}
	record, _, err := journal.Admit(execution, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	recoveryToken := []byte("protected exact payment recovery identity")
	recovery, transactionEvidence := relayJournalSponsorshipEvidence(t, fixture, execution, agreement,
		obligation, recoveryToken)
	attempted, err := journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, recovery, fixture.now.Add(time.Second))
	if err != nil || !attempted.SponsorshipAttempted || !bytes.Equal(attempted.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("sponsorship attempt checkpoint failed: record=%+v err=%v", attempted.Snapshot(), err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	attempted, err = journal.Resolve(record.StableActionID, record.ExactRequestDigest)
	if err != nil || !attempted.SponsorshipAttempted || !bytes.Equal(attempted.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("sponsorship recovery identity did not survive restart: record=%+v err=%v", attempted.Snapshot(), err)
	}
	observation := relayJournalSponsorshipObservation(transactionEvidence, fixture.now)
	observed, err := journal.RecordSponsorshipObservation(attempted.StableActionID, attempted.ExactRequestDigest,
		attempted.StateRevision, observation, fixture.now.Add(2*time.Second))
	if err != nil || observed.SponsorshipCreditObservation == nil || !observed.SponsorshipAttempted ||
		!bytes.Equal(observed.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("nonterminal sponsorship observation was not durably fenced: record=%+v err=%v", observed.Snapshot(), err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	attempted, err = journal.Resolve(record.StableActionID, record.ExactRequestDigest)
	if err != nil || attempted.SponsorshipCreditObservation == nil || !attempted.SponsorshipAttempted ||
		!bytes.Equal(attempted.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("observed-unproven sponsorship did not survive restart: record=%+v err=%v", attempted.Snapshot(), err)
	}
	checkpointed, err := journal.RecordSponsorship(attempted.StableActionID, attempted.ExactRequestDigest,
		attempted.StateRevision, transactionEvidence, fixture.now.Add(3*time.Second))
	if err != nil || checkpointed.State != commerce.ActionPrepared || checkpointed.SponsorshipTransferReference != "tx:sponsorship" ||
		!checkpointed.SponsorshipAttempted || !bytes.Equal(checkpointed.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("sponsorship checkpoint failed: record=%+v err=%v", checkpointed.Snapshot(), err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Resolve(record.StableActionID, record.ExactRequestDigest)
	if err != nil || recovered.SponsorshipTransferReference != "tx:sponsorship" ||
		!reflect.DeepEqual(recovered.EvidenceRefs, transactionEvidence.ObservationDigests) ||
		!recovered.SponsorshipAttempted || !bytes.Equal(recovered.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("sponsorship checkpoint did not survive restart: record=%+v err=%v", recovered.Snapshot(), err)
	}
	if _, err := reopened.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, transactionEvidence, fixture.now.Add(3*time.Second)); err != nil {
		t.Fatalf("exact sponsorship retry was not idempotent: %v", err)
	}
	second := transactionEvidence
	second.SubmittedTransactionHash = "tx:second-top-up"
	if _, err := reopened.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
		recovered.StateRevision, second, fixture.now.Add(3*time.Second)); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("second sponsorship transfer did not conflict: %v", err)
	}
}

func TestDurableRelayJournalSponsorshipSuccessTransactionAbsenceRetainsExposureAcrossRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = relayTestDigest("6")
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	directory := filepath.Join(t.TempDir(), "relay-sponsorship-transaction-absence")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, reserveErr := journal.ReserveQuote(fixture.profile, execution.QuoteRequest,
		execution.ProviderQuote, fixture.now); reserveErr != nil || !created {
		t.Fatalf("reserve combined quote: created=%v err=%v", created, reserveErr)
	}
	record, created, err := journal.Admit(execution, fixture.now)
	if err != nil || !created {
		t.Fatalf("admit combined action: created=%v err=%v", created, err)
	}
	recoveryToken := []byte("protected exact combined sponsorship recovery")
	recovery, evidence := relayJournalSponsorshipEvidence(t, fixture, execution, agreement, obligation, recoveryToken)
	evidence = relayJournalClientCorroboratedEvidence(t, evidence)
	attempted, err := journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, recovery, fixture.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sponsored, err := journal.RecordSponsorship(attempted.StableActionID, attempted.ExactRequestDigest,
		attempted.StateRevision, evidence, fixture.now.Add(2*time.Second))
	if err != nil || !sponsored.SponsorshipAttempted || !bytes.Equal(sponsored.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("combined sponsorship did not retain protected recovery material: record=%+v err=%v",
			sponsored.Snapshot(), err)
	}
	observedAt := maxUint64(execution.QuoteRequest.Body.TransactionValidUntilUnix+
		uint64(execution.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds)+1,
		uint64(fixture.now.Add(3*time.Second).Unix()))
	transactionRefs, bundleDigest, bundle := relayJournalTransactionAbsenceProof(t, execution, recovery, observedAt)
	terminalAt := time.Unix(int64(observedAt), 0).UTC()
	terminal, err := journal.RecordSponsorshipAbsence(sponsored.StableActionID, sponsored.ExactRequestDigest,
		sponsored.StateRevision, agentrelay.OutcomeCorroboratedSponsorshipOnly, nil, transactionRefs,
		bundleDigest, bundle, terminalAt)
	if err != nil || terminal.State != commerce.ActionTerminal || terminal.TransactionReference != "tx:sponsorship" ||
		terminal.SponsorshipAttempted || len(terminal.SponsorshipRecoveryToken()) != 0 ||
		len(terminal.TransactionAbsenceObservations) != len(transactionRefs) {
		t.Fatalf("S+/R- terminal transition was not durable and exact: record=%+v err=%v", terminal.Snapshot(), err)
	}
	assertDurableRelaySponsorshipExposureReserved(t, journal, record.StableActionID)
	transactionDigests, digestErr := relayAbsenceReferenceDigests(transactionRefs)
	if digestErr != nil || terminal.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		!reflect.DeepEqual(terminal.TransactionAbsenceObservationDigests, transactionDigests) ||
		terminal.AbsenceProofBundleDigest != bundleDigest || !bytes.Equal(terminal.AbsenceProofBundle, bundle) {
		t.Fatalf("stored S+/R- terminal material cannot be replayed exactly: digests=%v err=%v", transactionDigests, digestErr)
	}
	if replay, replayErr := journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
		terminal.StateRevision, agentrelay.OutcomeCorroboratedSponsorshipOnly, nil, transactionRefs,
		bundleDigest, bundle, terminalAt); replayErr != nil || replay.StateRevision != terminal.StateRevision {
		t.Fatalf("exact S+/R- replay was not idempotent: record=%+v err=%v", replay.Snapshot(), replayErr)
	}
	var substitutedBundle agentrelay.RelayAbsenceProofBundleV1
	if err := codec.Unmarshal(bundle, &substitutedBundle); err != nil {
		t.Fatal(err)
	}
	substitutedBundle.ProofPayload, err = codec.Marshal(map[string]string{"fixture": "substituted S+/R- proof"})
	if err != nil {
		t.Fatal(err)
	}
	substitutedBundle.ProofPayloadDigest, err = codec.DigestCanonical(agentrelay.RelayAbsenceProofPayloadDomainV1,
		substitutedBundle.ProofPayload)
	if err != nil {
		t.Fatal(err)
	}
	substitutedBytes, err := codec.Marshal(substitutedBundle)
	if err != nil {
		t.Fatal(err)
	}
	substitutedDigest, err := agentrelay.RelayAbsenceProofBundleDigest(substitutedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, conflictErr := journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
		terminal.StateRevision, agentrelay.OutcomeCorroboratedSponsorshipOnly, nil, transactionRefs,
		substitutedDigest, substitutedBytes, terminalAt); !errors.Is(conflictErr, agentrelay.ErrRelayConflict) {
		t.Fatalf("substituted S+/R- proof did not conflict: %v", conflictErr)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Resolve(record.StableActionID, record.ExactRequestDigest)
	if err != nil || recovered.State != commerce.ActionTerminal ||
		recovered.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		recovered.TransactionReference != recovered.SponsorshipTransferReference ||
		recovered.SponsorshipAttempted || len(recovered.SponsorshipRecoveryToken()) != 0 ||
		!reflect.DeepEqual(recovered.TransactionAbsenceObservations, transactionRefs) ||
		recovered.AbsenceProofBundleDigest != bundleDigest || !bytes.Equal(recovered.AbsenceProofBundle, bundle) {
		t.Fatalf("S+/R- terminal record did not survive restart: record=%+v err=%v", recovered.Snapshot(), err)
	}
	assertDurableRelaySponsorshipExposureReserved(t, reopened, record.StableActionID)
}

func relayJournalTransactionAbsenceProof(t *testing.T, execution agentrelay.RelayExecutionRequest,
	recovery agentrelay.SponsorshipRecoveryHandle, observedAt uint64) (
	[]agentrelay.RelayAbsenceObservationReference, string, []byte) {
	t.Helper()
	networkDigest, err := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	profile := *execution.ProviderQuote.Body.RelayFinalityProfile
	release := execution.QuoteRequest.Body.SelectedSponsorshipReleaseProfile()
	references := make([]agentrelay.RelayAbsenceObservationReference, profile.MinimumObservers)
	for index := range references {
		references[index] = agentrelay.RelayAbsenceObservationReference{SchemaVersion: 1,
			ObservationKind: agentrelay.AbsenceObservationClientTransaction,
			Conclusion:      agentrelay.AbsenceConclusionExpiredWithoutInclusion,
			ProviderAgentID: execution.ProviderQuote.Body.ProviderAgentID, NetworkDigest: networkDigest,
			RelayStableActionID:     execution.AuthorizedAction.StableActionID,
			RelayExactRequestDigest: execution.AuthorizedAction.ExactRequestDigest,
			RelayExecutionDigest:    executionDigest, SponsorshipStableActionID: recovery.StableActionID,
			SponsorshipExactRequestDigest: recovery.ExactRequestDigest,
			SponsorshipValidUntilUnix:     recovery.ValidUntilUnix,
			SignedTransactionDigest:       execution.QuoteRequest.Body.SignedTransactionDigest,
			SignedTransactionCellHash:     execution.QuoteRequest.Body.SignedTransactionCellHash,
			TerminalProfileURI:            profile.ProfileURI, TerminalProfileDigest: profile.ProfileDigest,
			TerminalEvidenceClass: profile.TerminalEvidenceClass,
			FinalizedCheckpointID: "checkpoint:transaction-absence", FinalizedCheckpointSequence: 501,
			FinalizedCheckpointUnix: observedAt, ObserverID: fmt.Sprintf("observer:%d", index),
			OperatorDomainID:                 fmt.Sprintf("operator:%d", index),
			ObservationEvidenceProfileURI:    release.ProfileURI,
			ObservationEvidenceProfileDigest: release.ProfileDigest,
			ObservationDigest:                relayTestDigest(fmt.Sprintf("%x", index+1)), ObservedAtUnix: observedAt}
	}
	sort.Slice(references, func(left, right int) bool {
		leftDigest, _ := agentrelay.RelayAbsenceObservationReferenceDigest(references[left])
		rightDigest, _ := agentrelay.RelayAbsenceObservationReferenceDigest(references[right])
		return leftDigest < rightDigest
	})
	payload, err := codec.Marshal(map[string]string{"fixture": "durable S+/R- transaction absence"})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := codec.DigestCanonical(agentrelay.RelayAbsenceProofPayloadDomainV1, payload)
	profileDigest, profileErr := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if err != nil || profileErr != nil {
		t.Fatal(errors.Join(err, profileErr))
	}
	wrapper := agentrelay.RelayAbsenceProofBundleV1{SchemaVersion: 1,
		ProofScope:      agentrelay.RelayAbsenceProofTransactionOnly,
		ProofProfileURI: agentrelay.RelayAbsenceTOSRPCProofProfileURI, ProofProfileDigest: profileDigest,
		ProofPayloadDigest: payloadDigest, ProofPayload: payload,
		TransactionAbsenceObservations: references}
	bundle, err := codec.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := agentrelay.RelayAbsenceProofBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return references, bundleDigest, bundle
}

func assertDurableRelaySponsorshipExposureReserved(t *testing.T, journal *DurableRelayJournal,
	stableActionID string) {
	t.Helper()
	journal.mu.Lock()
	defer journal.mu.Unlock()
	for _, reservation := range journal.quoteReservations {
		if reservation.StableActionID == stableActionID {
			if reservation.ExposureReleased {
				t.Fatal("S+/R- terminal incorrectly released unreimbursed sponsorship exposure")
			}
			return
		}
	}
	t.Fatal("S+/R- terminal lost its sponsorship exposure reservation")
}

func relayJournalSponsorshipObservation(evidence agentrelay.RelaySponsorshipTransactionEvidence,
	now time.Time) agentrelay.RelaySponsorshipCreditObservation {
	return agentrelay.RelaySponsorshipCreditObservation{SchemaVersion: 1,
		NetworkDigest: evidence.NetworkDigest, AgreementPaymentRequest: evidence.AgreementPaymentRequest,
		AgreementPaymentRequestDigest:        evidence.AgreementPaymentRequestDigest,
		SponsorshipStableActionID:            evidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:        evidence.SponsorshipExactRequestDigest,
		ProviderSponsorSourceAccount:         evidence.ProviderSponsorSourceAccount,
		ProviderSponsorSourceSequence:        evidence.ProviderSponsorSourceSequence,
		ProviderSponsorValidUntilUnix:        evidence.ProviderSponsorValidUntilUnix,
		SignedTopUpTransactionDigest:         evidence.SignedTopUpTransactionDigest,
		SignedTopUpTransactionCellHash:       evidence.SignedTopUpTransactionCellHash,
		SponsorshipPaymentCommitmentCellHash: evidence.SponsorshipPaymentCommitmentCellHash,
		DestinationSourceAccount:             evidence.DestinationSourceAccount, Amount: evidence.Amount,
		SubmittedTransactionHash:    evidence.SubmittedTransactionHash,
		SourceExecutionReference:    evidence.SourceExecutionReference,
		DestinationCreditReferences: append([]string(nil), evidence.DestinationCreditReferences...),
		EvidenceProfileURI:          agentrelay.RPCCorroborationEvidenceProfileURI,
		EvidenceProfileDigest:       relayTestDigest("6"), ObservedCheckpointID: "checkpoint:observed",
		ObservedCheckpointSequence: 100, ObservedCheckpointUnix: uint64(now.Unix()),
		ObservationDigests: append([]string(nil), evidence.ObservationDigests...), ObservedAtUnix: uint64(now.Unix())}
}

func relayJournalSponsorshipEvidence(t *testing.T, fixture *relayTestFixture,
	execution agentrelay.RelayExecutionRequest, agreement commerce.AgentAgreement,
	obligation commerce.AgreementObligation, recoveryToken []byte) (agentrelay.SponsorshipRecoveryHandle,
	agentrelay.RelaySponsorshipTransactionEvidence) {
	t.Helper()
	agreementDigest, err := commerce.AgreementBodyDigest(agreement.Body)
	if err != nil {
		t.Fatal(err)
	}
	materialized := obligation
	materialized.ExpiresAtUnix = relaySponsorshipExpiry(obligation.ExpiresAtUnix,
		agreement.Body.ExpiresAtUnix, execution.ExpiresAtUnix)
	instances, err := commerce.MaterializeSettlementObligations("owner:provider", fixture.profile.ProviderAgentID,
		agreementDigest, obligation.ObligationID, relayTestDigest("a"), materialized)
	if err != nil || len(instances) != 1 {
		t.Fatalf("materialize sponsorship payment: instances=%d err=%v", len(instances), err)
	}
	networkDigest, err := agentrelay.NetworkDomainDigest(execution.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	payment, err := commerce.BuildDomainBoundAgreementPaymentRequest("owner:provider", fixture.profile.ProviderAgentID,
		execution.QuoteRequest.Body.Network.NetworkID, networkDigest,
		[]byte(execution.QuoteRequest.Body.SourceAccount), instances[0])
	if err != nil {
		t.Fatal(err)
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(payment)
	canonical, _, materialErr := commerce.PaymentAuthorizationMaterial(payment)
	exactDigest, exactErr := commerce.ExactRequestDigest(canonical)
	if err != nil || materialErr != nil || exactErr != nil {
		t.Fatal(errors.Join(err, materialErr, exactErr))
	}
	recovery := agentrelay.SponsorshipRecoveryHandle{AgreementPaymentRequestDigest: paymentDigest,
		StableActionID: payment.StableActionID, ExactRequestDigest: exactDigest,
		ValidUntilUnix: payment.ExpiresAtUnix, OpaqueToken: append([]byte(nil), recoveryToken...)}
	reserved := *execution.ProviderQuote.Body.ReservedSponsorship
	if execution.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		t.Fatal("sponsorship terminal profile is missing")
	}
	terminalProfile := *execution.ProviderQuote.Body.SponsorshipTerminalProfile
	evidence := agentrelay.RelaySponsorshipTransactionEvidence{SchemaVersion: 1,
		TerminalEvidenceClass:               agentrelay.SponsorshipTerminalValidatorFinality,
		ValidatorAuthenticatedPortableProof: true, NetworkDigest: networkDigest,
		AgreementPaymentRequest: payment, AgreementPaymentRequestDigest: paymentDigest,
		SponsorshipStableActionID: payment.StableActionID, SponsorshipExactRequestDigest: exactDigest,
		ProviderSponsorSourceAccount: "0:sponsor", ProviderSponsorSourceSequence: 7,
		ProviderSponsorValidUntilUnix:        payment.ExpiresAtUnix,
		SignedTopUpTransactionDigest:         relayTestDigest("d"),
		SignedTopUpTransactionCellHash:       "tvm-cell-sha256:" + strings.Repeat("e", 64),
		SponsorshipPaymentCommitmentCellHash: "tvm-cell-sha256:" + strings.Repeat("f", 64),
		DestinationSourceAccount:             execution.QuoteRequest.Body.SourceAccount, Amount: reserved,
		SubmittedTransactionHash: "tx:sponsorship", SourceExecutionReference: "source:execution",
		DestinationCreditReferences: []string{relayTestDigest("4")}, FinalizedCheckpointID: "checkpoint:sponsor",
		FinalizedCheckpointSequence: 101, FinalizedCheckpointUnix: uint64(fixture.now.Unix()),
		ConfirmationDepth:                terminalProfile.MinimumConfirmationDepth,
		SponsorshipTerminalProfileDigest: terminalProfile.ProfileDigest,
		ObservationDigests:               []string{relayTestDigest("4")}, ProofBundleDigest: relayTestDigest("5"),
		PortableProofLocator: "proof:sponsor", ObservedAtUnix: uint64(fixture.now.Unix())}
	return recovery, evidence
}

func relayJournalClientCorroboratedEvidence(t *testing.T,
	evidence agentrelay.RelaySponsorshipTransactionEvidence) agentrelay.RelaySponsorshipTransactionEvidence {
	t.Helper()
	bundle, err := codec.Marshal(map[string]string{"fixture": "durable client-corroborated sponsorship"})
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	evidence.TerminalEvidenceClass = agentrelay.SponsorshipTerminalClientCorroborated
	evidence.ValidatorAuthenticatedPortableProof = false
	evidence.PortableProofLocator = ""
	evidence.ProofBundle = bundle
	evidence.ProofBundleDigest = bundleDigest
	return evidence
}

func TestDurableRelayJournalCorroboratedTerminalBindingSurvivesRestartAndTombstone(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = relayTestDigest("6")
	fixture.enableSponsorship(t, agentrelay.ModeSponsorOnly)
	attempt := fixture.attempt(t)
	var sponsorshipObligation commerce.AgreementObligation
	for _, candidate := range attempt.Agreement.Body.Obligations {
		if candidate.ObligationID == attempt.Execution.SponsorshipObligationID {
			sponsorshipObligation = candidate
			break
		}
	}
	if sponsorshipObligation.ObligationID == "" {
		t.Fatal("sponsor-only fixture lacks its payment obligation")
	}

	directory := filepath.Join(t.TempDir(), "relay-corroborated-terminal")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{TerminalRetention: time.Second, MaximumProtectedRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, reserveErr := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
		attempt.Execution.ProviderQuote, fixture.now); reserveErr != nil || !created {
		t.Fatalf("reserve sponsor-only quote: created=%v err=%v", created, reserveErr)
	}
	record, created, err := journal.Admit(attempt.Execution, fixture.now)
	if err != nil || !created {
		t.Fatalf("admit sponsor-only action: created=%v err=%v", created, err)
	}
	recovery, evidence := relayJournalSponsorshipEvidence(t, fixture, attempt.Execution,
		attempt.Agreement, sponsorshipObligation, []byte("corroborated recovery token"))
	evidence = relayJournalClientCorroboratedEvidence(t, evidence)
	attempted, err := journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, recovery, fixture.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := journal.RecordSponsorshipObservation(attempted.StableActionID,
		attempted.ExactRequestDigest, attempted.StateRevision,
		relayJournalSponsorshipObservation(evidence, fixture.now.Add(2*time.Second)),
		fixture.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	checkpointed, err := journal.RecordSponsorship(observed.StableActionID, observed.ExactRequestDigest,
		observed.StateRevision, evidence, fixture.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Transition(checkpointed.StableActionID, checkpointed.ExactRequestDigest,
		checkpointed.StateRevision, commerce.ActionTerminal, "relay:wrong-mode",
		evidence.ObservationDigests,
		agentrelay.OutcomeCorroboratedSuccess,
		fixture.now.Add(4*time.Second)); !errors.Is(err, agentrelay.ErrRelayInvalidState) {
		t.Fatalf("sponsor-only record accepted the mixed corroborated outcome: %v", err)
	}
	terminal, err := journal.Transition(checkpointed.StableActionID, checkpointed.ExactRequestDigest,
		checkpointed.StateRevision, commerce.ActionTerminal, checkpointed.SponsorshipTransferReference,
		evidence.ObservationDigests, agentrelay.OutcomeCorroboratedSponsorshipOnly,
		fixture.now.Add(4*time.Second))
	if err != nil || terminal.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		terminal.TransactionReference != terminal.SponsorshipTransferReference {
		t.Fatalf("corroborated terminal transition failed: record=%+v err=%v", terminal.Snapshot(), err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, err = OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{TerminalRetention: time.Second, MaximumProtectedRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := journal.Resolve(terminal.StableActionID, terminal.ExactRequestDigest)
	if err != nil || restored.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		restored.SponsorshipTransactionEvidence == nil ||
		restored.SponsorshipTransactionEvidence.TerminalEvidenceClass != agentrelay.SponsorshipTerminalClientCorroborated {
		t.Fatalf("corroborated terminal restore lost its evidence predicate: record=%+v err=%v", restored.Snapshot(), err)
	}
	released, err := journal.ReleaseSponsorshipExposure(restored.StableActionID, restored.ExactRequestDigest,
		restored.StateRevision, []string{relayTestDigest("e")}, fixture.now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	second := relayDistinctAttempt(t, fixture, "force-corroborated-compaction")
	if _, _, err := journal.ReserveQuote(fixture.profile, second.Execution.QuoteRequest,
		second.Execution.ProviderQuote, fixture.now.Add(7*time.Second)); err != nil {
		t.Fatalf("trigger corroborated terminal compaction: %v", err)
	}
	tombstone, found := journal.tombstones[relayDurableRecordKey(released.StableActionID)]
	if !found || !validRelayTombstone(fixture.profile.ProviderAgentID, tombstone) {
		t.Fatalf("corroborated terminal was not retained as a valid tombstone: found=%v tombstone=%+v", found, tombstone)
	}
	mutated := tombstone
	mutated.AssuranceLevel = agentrelay.AssuranceAutonomousDecentralized
	if validRelayTombstone(fixture.profile.ProviderAgentID, mutated) {
		t.Fatal("corroborated tombstone was restorable as autonomous-decentralized")
	}
	mutated = tombstone
	mutated.SponsorshipTerminalEvidenceClass = agentrelay.SponsorshipTerminalValidatorFinality
	if validRelayTombstone(fixture.profile.ProviderAgentID, mutated) {
		t.Fatal("corroborated tombstone accepted a substituted terminal evidence class")
	}
	mutated = tombstone
	mutated.SponsorshipTerminalProfileURI = "tos.depth-quorum.v1"
	if validRelayTombstone(fixture.profile.ProviderAgentID, mutated) {
		t.Fatal("corroborated tombstone accepted a substituted terminal profile")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{TerminalRetention: time.Second, MaximumProtectedRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Resolve(released.StableActionID, released.ExactRequestDigest); !errors.Is(err, ErrRelayRetired) {
		t.Fatalf("corroborated tombstone did not survive restart: %v", err)
	}
}

func TestDurableRelayJournalCombinedCorroboratedPartialTerminalSurvivesRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	fixture.enableClientCorroboratedTerminalProfile()
	fixture.prepared.QuoteBody.AssuranceLevel = agentrelay.AssuranceAuthorizedSingleProvider
	fixture.prepared.QuoteBody.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	fixture.prepared.QuoteBody.SponsorshipReleaseProfileDigest = relayTestDigest("6")
	execution, agreement, obligation := relaySponsorshipFixture(t, fixture)
	if execution.QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay {
		t.Fatal("fixture did not select the combined mode")
	}
	directory := filepath.Join(t.TempDir(), "relay-combined-corroborated-partial")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, reserveErr := journal.ReserveQuote(fixture.profile, execution.QuoteRequest,
		execution.ProviderQuote, fixture.now); reserveErr != nil || !created {
		t.Fatalf("reserve combined quote: created=%v err=%v", created, reserveErr)
	}
	record, created, err := journal.Admit(execution, fixture.now)
	if err != nil || !created {
		t.Fatalf("admit combined action: created=%v err=%v", created, err)
	}
	recovery, evidence := relayJournalSponsorshipEvidence(t, fixture, execution, agreement,
		obligation, []byte("combined partial recovery token"))
	evidence = relayJournalClientCorroboratedEvidence(t, evidence)
	attempted, err := journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, recovery, fixture.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := journal.RecordSponsorshipObservation(attempted.StableActionID,
		attempted.ExactRequestDigest, attempted.StateRevision,
		relayJournalSponsorshipObservation(evidence, fixture.now.Add(2*time.Second)),
		fixture.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	checkpointed, err := journal.RecordSponsorship(observed.StableActionID, observed.ExactRequestDigest,
		observed.StateRevision, evidence, fixture.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// A fresh balance/sequence/expiry recheck may reject the client BOC after
	// the exact top-up has already met the signed corroboration predicate. The
	// truthful combined-mode partial outcome retains the sponsorship reference;
	// it must not be mislabeled as a completed relay.
	terminal, err := journal.Transition(checkpointed.StableActionID, checkpointed.ExactRequestDigest,
		checkpointed.StateRevision, commerce.ActionTerminal, checkpointed.SponsorshipTransferReference,
		evidence.ObservationDigests, agentrelay.OutcomeCorroboratedSponsorshipOnly,
		fixture.now.Add(4*time.Second))
	if err != nil || terminal.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		terminal.TransactionReference != terminal.SponsorshipTransferReference {
		t.Fatalf("combined corroborated partial terminal failed: record=%+v err=%v", terminal.Snapshot(), err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.Resolve(terminal.StableActionID, terminal.ExactRequestDigest)
	if err != nil || restored.TerminalOutcome != agentrelay.OutcomeCorroboratedSponsorshipOnly ||
		restored.ExecutionRequest().QuoteRequest.Body.Mode != agentrelay.ModeSponsorAndRelay ||
		restored.TransactionReference != restored.SponsorshipTransferReference {
		t.Fatalf("combined partial terminal did not survive restart: record=%+v err=%v", restored.Snapshot(), err)
	}
}

func TestDurableRelayJournalEnforcesOwnerStricterAdmissionLimits(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	limits := fixture.profile.AdmissionLimits
	limits.MaximumQuoteReservations = 1
	limits.MaximumActiveExecutions = 1
	limits.MaximumActivePerRequester = 1
	limits.MaximumQuoteRequestsPerWindow = 2
	limits.MaximumQuoteRequestsPerRequesterWindow = 1
	directory := filepath.Join(t.TempDir(), "relay-admission")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{AdmissionLimits: &limits})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	first := relayDistinctAttempt(t, fixture, "admission-one")
	second := relayDistinctAttempt(t, fixture, "admission-two")
	if _, created, err := journal.ReserveQuote(fixture.profile, first.Execution.QuoteRequest,
		first.Execution.ProviderQuote, fixture.now); err != nil || !created {
		t.Fatalf("first bounded quote: created=%v err=%v", created, err)
	}
	if _, _, err := journal.ReserveQuote(fixture.profile, second.Execution.QuoteRequest,
		second.Execution.ProviderQuote, fixture.now); !errors.Is(err, agentrelay.ErrRelayAdmissionLimit) {
		t.Fatalf("owner quote-reservation ceiling was not atomic: %v", err)
	}
	if _, _, err := journal.Admit(first.Execution, fixture.now); err != nil {
		t.Fatal(err)
	}
	// Consuming the first quote frees reservation capacity, but the persisted
	// per-requester window remains exhausted across restart.
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{AdmissionLimits: &limits})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, _, err := journal.ReserveQuote(fixture.profile, second.Execution.QuoteRequest,
		second.Execution.ProviderQuote, fixture.now.Add(time.Second)); !errors.Is(err, agentrelay.ErrRelayAdmissionLimit) {
		t.Fatalf("durable requester rate ceiling was not enforced: %v", err)
	}
}

func TestDurableRelayJournalAppliesTightenedOwnerWorkLimitToReservedQuotesAfterRestart(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	directory := filepath.Join(t.TempDir(), "relay-tightened-work")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	first := relayDistinctAttempt(t, fixture, "tightened-one")
	second := relayDistinctAttempt(t, fixture, "tightened-two")
	for _, attempt := range []RelayAttempt{first, second} {
		if _, created, reserveErr := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
			attempt.Execution.ProviderQuote, fixture.now); reserveErr != nil || !created {
			t.Fatalf("reserve quote before owner tightening: created=%v err=%v", created, reserveErr)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	limits := fixture.profile.AdmissionLimits
	limits.MaximumActiveExecutions = 1
	limits.MaximumActivePerRequester = 1
	journal, err = OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{AdmissionLimits: &limits})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, created, err := journal.Admit(first.Execution, fixture.now); err != nil || !created {
		t.Fatalf("first previously reserved execution: created=%v err=%v", created, err)
	}
	if _, _, err := journal.Admit(second.Execution, fixture.now); !errors.Is(err, agentrelay.ErrRelayAdmissionLimit) {
		t.Fatalf("reserved quote bypassed tightened owner active-work limit: %v", err)
	}
}

func TestDurableRelayJournalCompactsBeyondActiveCapacityWithoutIdentityReuse(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	directory := filepath.Join(t.TempDir(), "relay-compaction")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{TerminalRetention: time.Second, MaximumProtectedRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	var first RelayAttempt
	for index := 0; index < 6; index++ {
		attempt := relayDistinctAttempt(t, fixture, fmt.Sprintf("retired-%d", index+1))
		if index == 0 {
			first = attempt
		}
		at := fixture.now.Add(10*time.Second + time.Duration(index)*3*time.Second)
		if _, created, reserveErr := journal.ReserveQuote(fixture.profile, attempt.Execution.QuoteRequest,
			attempt.Execution.ProviderQuote, at); reserveErr != nil || !created {
			t.Fatalf("reserve action %d beyond active capacity: created=%v err=%v", index, created, reserveErr)
		}
		record, created, admitErr := journal.Admit(attempt.Execution, at)
		if admitErr != nil || !created {
			t.Fatalf("admit action %d beyond active capacity: created=%v err=%v", index, created, admitErr)
		}
		if _, transitionErr := journal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, commerce.ActionTerminal, "", []string{relayTestDigest("f")},
			agentrelay.OutcomeFinalizedAbsent, at.Add(time.Second)); transitionErr != nil {
			t.Fatalf("terminal action %d: %v", index, transitionErr)
		}
	}
	if len(journal.tombstones) <= 4 {
		t.Fatalf("terminal compaction did not sustain more than active capacity: tombstones=%d", len(journal.tombstones))
	}
	if _, err := journal.Resolve(first.Execution.AuthorizedAction.StableActionID,
		first.Execution.AuthorizedAction.ExactRequestDigest); !errors.Is(err, ErrRelayRetired) {
		t.Fatalf("exact retired action did not return explicit retired status: %v", err)
	}
	if _, err := journal.Resolve(first.Execution.AuthorizedAction.StableActionID,
		relayTestDigest("0")); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("retired stable ID accepted a different request: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDurableRelayJournalWithOptions(directory,
		DurableRelayJournalOptions{TerminalRetention: time.Second, MaximumProtectedRecords: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Resolve(first.Execution.AuthorizedAction.StableActionID,
		first.Execution.AuthorizedAction.ExactRequestDigest); !errors.Is(err, ErrRelayRetired) {
		t.Fatalf("retired identity did not survive restart: %v", err)
	}
	if _, _, err := reopened.Admit(first.Execution, fixture.now.Add(20*time.Second)); !errors.Is(err, ErrRelayRetired) {
		t.Fatalf("retired exact execution was reusable after restart: %v", err)
	}
}

func relayDistinctAttempt(t *testing.T, fixture *relayTestFixture, label string) RelayAttempt {
	t.Helper()
	attempt := fixture.attempt(t)
	obligationDigest, err := commerce.ExactRequestDigest([]byte("obligation:" + label))
	if err != nil {
		t.Fatal(err)
	}
	fields := make(map[string]commerce.SemanticValue, len(fixture.prepared.SemanticFields))
	for key, value := range fixture.prepared.SemanticFields {
		fields[key] = value
	}
	fields["obligation_instance_id"] = commerce.Digest32(obligationDigest)
	underlyingRequest := []byte("underlying:" + label)
	prior := attempt.Execution.AuthorizedAction
	action, err := commerce.BuildAuthorizedAction(prior.OwnerID, prior.AgentID, prior.ActionKind, fields,
		underlyingRequest, attempt.Execution.WriterFence, prior.PolicyRevision, prior.MandateDigest,
		prior.ApprovalDigest, prior.ExpectedPriorState, prior.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(action, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	wireFields, err := commerce.ExportSemanticFields(action.ActionKind, fields)
	if err != nil {
		t.Fatal(err)
	}
	attempt.Execution.AuthorizedAction = action
	attempt.Execution.UnderlyingActionRequest = underlyingRequest
	attempt.Execution.SemanticFields = wireFields
	attempt.Execution.QuoteRequest.Body.StableActionID = action.StableActionID
	attempt.Execution.QuoteRequest.Body.ExactRequestDigest = action.ExactRequestDigest
	attempt.Execution.QuoteRequest.Body.RequestID = "request:" + label
	attempt.Execution.QuoteRequest, err = agentrelay.SignRelayQuoteRequest(
		attempt.Execution.QuoteRequest.Body, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	attempt.Execution.ProviderQuote.Body.QuoteID = "quote:" + label
	attempt.Execution.ProviderQuote.Body.QuoteRequestDigest, err =
		agentrelay.RelayQuoteRequestDigest(attempt.Execution.QuoteRequest.Body)
	if err != nil {
		t.Fatal(err)
	}
	attempt.Execution.ProviderQuote, err = agentrelay.SignProviderRelayQuote(
		attempt.Execution.ProviderQuote.Body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	relayTestRefreshAdmission(t, fixture, &attempt.Execution)
	return attempt
}

func relaySponsorReservation(t *testing.T, fixture *relayTestFixture, profile agentrelay.RelayServiceProfile,
	requestID, amountAtomic string) (agentrelay.SignedRelayQuoteRequest, agentrelay.SignedProviderRelayQuote) {
	t.Helper()
	body := fixture.prepared.QuoteBody
	body.RequestID, body.Mode = requestID, agentrelay.ModeSponsorOnly
	body.RelayTerminalEvidenceClass = ""
	body.RelayFinalityProfileURI = ""
	body.RelayFinalityProfileDigest = ""
	sponsorship := agentrelay.AssetAmount{Asset: fixture.asset, AmountAtomic: amountAtomic}
	body.RequestedSponsorship = &sponsorship
	body.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseValidatorFinality
	body.SponsorshipReleaseProfileURI = fixture.finality.ProfileURI
	body.SponsorshipReleaseProfileDigest = fixture.finality.ProfileDigest
	body.SponsorshipTerminalEvidenceClass = fixture.finality.TerminalEvidenceClass
	body.SponsorshipTerminalProfileURI = fixture.finality.ProfileURI
	body.SponsorshipTerminalProfileDigest = fixture.finality.ProfileDigest
	request, err := agentrelay.SignRelayQuoteRequest(body, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	quoteBody, err := (relayTestQuotePolicy{fee: "1", intent: fixture.verified.IntentDigest()}).Quote(
		context.Background(), profile, request, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	quoteBody.FeeLines[0].Kind = agentrelay.ObligationSponsorshipFee
	quoteBody.ReservedSponsorship = &sponsorship
	quote, err := agentrelay.SignProviderRelayQuote(quoteBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	return request, quote
}
