package prediction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type relayTestBroadcaster struct {
	calls [][]byte
	err   error
}

type relayBlockingBroadcaster struct {
	entered chan struct{}
	release chan struct{}
}

func (broadcaster *relayBlockingBroadcaster) BroadcastExactPredictionBOC(ctx context.Context, _ []byte) error {
	close(broadcaster.entered)
	select {
	case <-broadcaster.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (broadcaster *relayTestBroadcaster) BroadcastExactPredictionBOC(_ context.Context, boc []byte) error {
	broadcaster.calls = append(broadcaster.calls, append([]byte(nil), boc...))
	return broadcaster.err
}

type relayTestVerifier struct {
	sourceCalls      int
	destinationCalls int
	bounceCalls      int
	err              error
}

func (*relayTestVerifier) predictionRelayEvidenceVerifier() {}

func (verifier *relayTestVerifier) VerifyPredictionSource(_ context.Context, _ PredictionRelayRecord,
	_ SourceTransactionEvidence,
) error {
	verifier.sourceCalls++
	return verifier.err
}

func (verifier *relayTestVerifier) VerifyPredictionDestination(_ context.Context, _ PredictionRelayRecord,
	_ DestinationTransactionEvidence,
) error {
	verifier.destinationCalls++
	return verifier.err
}

func (verifier *relayTestVerifier) VerifyPredictionBounceCredit(_ context.Context, _ PredictionRelayRecord,
	_ BounceCreditEvidence,
) error {
	verifier.bounceCalls++
	return verifier.err
}

type relayFixture struct {
	profile     PredictionRelayProfile
	actionID    string
	signedBOC   []byte
	expected    ExpectedContractCall
	cursor      AccountCursor
	checkpoint  BlockIdentity
	source      SourceTransactionEvidence
	destination DestinationTransactionEvidence
}

func newRelayFixture(t *testing.T) relayFixture {
	t.Helper()
	digest := func(prefix, value string) string { return prefix + strings.Repeat(value, 64) }
	sourceAddress := "0:" + strings.Repeat("1", 64)
	marketAddress := "0:" + strings.Repeat("2", 64)
	body := cell.BeginCell().MustStoreUInt(0x504d0001, 32).MustStoreUInt(7, 64).EndCell()
	signed := cell.BeginCell().MustStoreUInt(0xeeee, 16).MustStoreRef(body).EndCell()
	profile := PredictionRelayProfile{
		NetworkDomainHash: digest("sha256:", "a"), SourceAgentAccount: sourceAddress,
		SourceAgentAccountCodeHash: digest("tvm-cell-sha256:", "7"),
		MarketAddress:              marketAddress, MarketID: digest("sha256:", "8"),
		MarketCodeHash:   digest("tvm-cell-sha256:", "b"),
		MarketConfigHash: digest("tvm-cell-sha256:", "c"),
		ObserverIDs:      []string{digest("sha256:", "1"), digest("sha256:", "2"), digest("sha256:", "3")},
		QuorumThreshold:  2, MaximumOutstanding: 16, MaximumSignedBOCBytes: 8192,
		MinimumNoBounceMCBlocks: 8,
	}
	actionID := digest("sha256:", "e")
	expected, err := NewExpectedContractCall(
		"prediction.match.submit", actionID, marketAddress, 10_000_000, body.ToBOCWithFlags(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := BlockIdentity{
		WorkchainID: -1, Shard: -1, SequenceNumber: 100,
		RootHash: digest("sha256:", "4"), FileHash: digest("sha256:", "5"), MasterchainSequence: 100,
	}
	cursor := AccountCursor{
		AccountAddress: sourceAddress, LastLogicalTime: 90,
		LastTransactionHash: digest("sha256:", "6"),
	}
	finality := func(view string, mc uint32) QuorumFinality {
		return QuorumFinality{
			NetworkDomainHash: profile.NetworkDomainHash,
			FinalityViewID:    digest("sha256:", view), ObserverIDs: append([]string(nil), profile.ObserverIDs...),
			AgreeingIDs: append([]string(nil), profile.ObserverIDs[:2]...), Threshold: 2, MasterchainSeqno: mc,
		}
	}
	transactionCell := cell.BeginCell().MustStoreUInt(0x701, 12).EndCell()
	outboundCell := cell.BeginCell().MustStoreUInt(0x702, 12).MustStoreRef(body).EndCell()
	outbound := ChainObservedMessage{
		MessageHash:     cellDigest(outboundCell),
		ExactMessageBOC: base64.StdEncoding.EncodeToString(outboundCell.ToBOCWithFlags(false)),
		SourceAddress:   sourceAddress, DestinationAddress: marketAddress, ValueNanoTOS: expected.ValueNanoTOS,
		BodyBOCBase64: expected.BodyBOCBase64, BodyHash: expected.BodyHash,
		StateInitBOCBase64: expected.StateInitBOCBase64, StateInitHash: expected.StateInitHash,
		Bounce: true, ExtraFlags: 3,
	}
	source := SourceTransactionEvidence{
		SubmittedExternalMessageHash: cellDigest(signed),
		TransactionHash:              "sha256:" + hex.EncodeToString(transactionCell.Hash()),
		TransactionBOCBase64:         base64.StdEncoding.EncodeToString(transactionCell.ToBOCWithFlags(false)),
		Block: BlockIdentity{
			WorkchainID: 0, Shard: 1, SequenceNumber: 50,
			RootHash: digest("sha256:", "7"), FileHash: digest("sha256:", "8"), MasterchainSequence: 101,
		},
		Finality: finality("9", 110), NextSourceCursor: AccountCursor{
			AccountAddress:  sourceAddress,
			LastLogicalTime: 110, LastTransactionHash: digest("sha256:", "7"),
		},
		OutboundMessages: []ChainObservedMessage{outbound},
	}
	destinationCell := cell.BeginCell().MustStoreUInt(0x703, 12).EndCell()
	destination := DestinationTransactionEvidence{
		InboundMessageHash:   outbound.MessageHash,
		TransactionHash:      "sha256:" + hex.EncodeToString(destinationCell.Hash()),
		TransactionBOCBase64: base64.StdEncoding.EncodeToString(destinationCell.ToBOCWithFlags(false)),
		Block: BlockIdentity{
			WorkchainID: 0, Shard: 1, SequenceNumber: 51,
			RootHash: digest("sha256:", "8"), FileHash: digest("sha256:", "9"), MasterchainSequence: 102,
		},
		Finality: finality("a", 111), NextDestinationCursor: AccountCursor{
			AccountAddress:  marketAddress,
			LastLogicalTime: 120, LastTransactionHash: digest("sha256:", "8"),
		},
		Ordinary: true, ComputeSuccess: true, ActionSuccess: true, OpcodeSuccess: true,
		MarketCodeHash: profile.MarketCodeHash, MarketConfigHash: profile.MarketConfigHash,
		SuccessPredicateDigest: expected.SuccessPredicateDigest,
	}
	return relayFixture{
		profile: profile, actionID: actionID, signedBOC: signed.ToBOCWithFlags(false),
		expected: expected, cursor: cursor, checkpoint: checkpoint, source: source, destination: destination,
	}
}

func openRelayFixture(t *testing.T, fixture relayFixture, directory string) *PredictionRelayJournal {
	t.Helper()
	journal, err := OpenPredictionRelayJournal(directory, fixture.profile)
	if err != nil {
		t.Fatalf("open relay journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func TestPredictionRelayProfileCapsObserverMemory(t *testing.T) {
	fixture := newRelayFixture(t)
	fixture.profile.ObserverIDs = make([]string, 65)
	for index := range fixture.profile.ObserverIDs {
		value := sha256.Sum256([]byte{byte(index)})
		fixture.profile.ObserverIDs[index] = "sha256:" + hex.EncodeToString(value[:])
	}
	// Sorting would make every identity canonical, but the explicit count cap
	// must reject the profile before it can amplify every durable record.
	if _, err := OpenPredictionRelayJournal(filepath.Join(t.TempDir(), "relay"), fixture.profile); err == nil {
		t.Fatal("Prediction relay accepted more than 64 observer identities")
	}
}

func prepareAndResolveSource(
	t *testing.T,
	journal *PredictionRelayJournal,
	fixture relayFixture,
) PredictionRelayRecord {
	t.Helper()
	if _, err := journal.Prepare(
		fixture.actionID,
		fixture.signedBOC,
		fixture.expected,
		fixture.cursor,
		fixture.checkpoint,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.BeginOrResumeExactBroadcast(
		t.Context(), fixture.actionID, &relayTestBroadcaster{},
	); err != nil {
		t.Fatal(err)
	}
	record, err := journal.ResolveSource(t.Context(), fixture.actionID, fixture.source, &relayTestVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPredictionRelayBroadcastCrashWindowAndSourceFinalBoundary(t *testing.T) {
	fixture := newRelayFixture(t)
	directory := filepath.Join(t.TempDir(), "relay")
	journal := openRelayFixture(t, fixture, directory)
	prepared, err := journal.Prepare(
		fixture.actionID,
		fixture.signedBOC,
		fixture.expected,
		fixture.cursor,
		fixture.checkpoint,
	)
	if err != nil || prepared.State != RelaySigned {
		t.Fatalf("prepare: state=%s err=%v", prepared.State, err)
	}
	rawDigest := sha256.Sum256(fixture.signedBOC)
	if prepared.ExactSignedBOCDigest != "sha256:"+hex.EncodeToString(rawDigest[:]) ||
		prepared.SubmittedExternalMessageHash != fixture.source.SubmittedExternalMessageHash ||
		prepared.ExactSignedBOCDigest == prepared.SubmittedExternalMessageHash {
		t.Fatalf("relay conflated exact BOC bytes with the submitted TVM message: %#v", prepared)
	}

	failed := &relayTestBroadcaster{err: errors.New("socket failed")}
	broadcasting, err := journal.BeginOrResumeExactBroadcast(t.Context(), fixture.actionID, failed)
	if err == nil || broadcasting.State != RelayBroadcasting || broadcasting.BroadcastAttempts != 1 ||
		len(failed.calls) != 1 || !bytes.Equal(failed.calls[0], fixture.signedBOC) {
		t.Fatalf("first ambiguous broadcast was not durably bounded: %#v %v", broadcasting, err)
	}
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	restarted, err := OpenPredictionRelayJournal(directory, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	journal = restarted

	resumed := &relayTestBroadcaster{}
	broadcasting, err = journal.BeginOrResumeExactBroadcast(t.Context(), fixture.actionID, resumed)
	if err != nil || broadcasting.BroadcastAttempts != 2 || len(resumed.calls) != 1 ||
		!bytes.Equal(resumed.calls[0], fixture.signedBOC) {
		t.Fatalf("restart did not resend exact durable bytes: %#v %v", broadcasting, err)
	}
	fixture.source.OutboundMessages = nil
	resolved, err := journal.ResolveSource(t.Context(), fixture.actionID, fixture.source, &relayTestVerifier{})
	if err != nil || resolved.State != RelaySourceActionSkipped {
		t.Fatalf("resolve skipped source: %#v %v", resolved, err)
	}
	if disposition := resolved.ReservationDisposition(); !disposition.ReleaseMarketExposure ||
		!disposition.ReleaseSourceLiquidity ||
		disposition.RealizeSourceLoss {
		t.Fatalf("wrong skipped-action reservation disposition: %#v", disposition)
	}
	if _, err := journal.BeginOrResumeExactBroadcast(t.Context(), fixture.actionID, resumed); err == nil ||
		len(resumed.calls) != 1 {
		t.Fatal("source-final exact BOC was rebroadcast")
	}
}

func TestPredictionRelayDestinationSuccessPersistsAcrossRestart(t *testing.T) {
	fixture := newRelayFixture(t)
	directory := filepath.Join(t.TempDir(), "relay")
	journal := openRelayFixture(t, fixture, directory)
	record := prepareAndResolveSource(t, journal, fixture)
	if record.State != RelaySourceFinalized || record.ActualOutbound == nil {
		t.Fatalf("source not finalized: %#v", record)
	}
	verifier := &relayTestVerifier{}
	committed, err := journal.ResolveDestination(t.Context(), fixture.actionID, fixture.destination, verifier)
	if err != nil || committed.State != RelayDestinationCommitted || verifier.destinationCalls != 1 {
		t.Fatalf("commit: %#v %v", committed, err)
	}
	if disposition := committed.ReservationDisposition(); !disposition.ReleaseMarketExposure ||
		!disposition.ReleaseSourceLiquidity ||
		disposition.RealizeSourceLoss {
		t.Fatalf("wrong success disposition: %#v", disposition)
	}
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	restarted, err := OpenPredictionRelayJournal(directory, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	recovered, ok := restarted.Get(fixture.actionID)
	if !ok || recovered.State != RelayDestinationCommitted || recovered.DestinationEvidence == nil ||
		recovered.DestinationEvidence.TransactionHash != fixture.destination.TransactionHash {
		t.Fatalf("terminal destination evidence was not recovered: %#v", recovered)
	}
}

func TestPredictionRelayDoesNotFinalizeDuringInFlightBroadcast(t *testing.T) {
	fixture := newRelayFixture(t)
	journal := openRelayFixture(t, fixture, filepath.Join(t.TempDir(), "relay"))
	if _, err := journal.Prepare(
		fixture.actionID,
		fixture.signedBOC,
		fixture.expected,
		fixture.cursor,
		fixture.checkpoint,
	); err != nil {
		t.Fatal(err)
	}
	broadcaster := &relayBlockingBroadcaster{entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := journal.BeginOrResumeExactBroadcast(context.Background(), fixture.actionID, broadcaster)
		result <- err
	}()
	<-broadcaster.entered
	verifier := &relayTestVerifier{}
	if _, err := journal.ResolveSource(t.Context(), fixture.actionID, fixture.source, verifier); err == nil ||
		verifier.sourceCalls != 0 {
		t.Fatal("source finality raced an in-flight socket write")
	}
	close(broadcaster.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	resolved, err := journal.ResolveSource(t.Context(), fixture.actionID, fixture.source, verifier)
	if err != nil || resolved.State != RelaySourceFinalized || verifier.sourceCalls != 1 {
		t.Fatalf("source did not resolve after broadcast returned: %#v %v", resolved, err)
	}
}

func TestPredictionRelayRichBounceRequiresExactAgentCredit(t *testing.T) {
	fixture := newRelayFixture(t)
	journal := openRelayFixture(t, fixture, filepath.Join(t.TempDir(), "relay"))
	prepareAndResolveSource(t, journal, fixture)
	richBody := cell.BeginCell().MustStoreUInt(0xfffffffe, 32).MustStoreUInt(0x504d0001, 32).EndCell()
	bounceCell := cell.BeginCell().MustStoreUInt(0x704, 12).MustStoreRef(richBody).EndCell()
	bounce := ChainObservedMessage{
		MessageHash: cellDigest(
			bounceCell,
		), ExactMessageBOC: base64.StdEncoding.EncodeToString(bounceCell.ToBOCWithFlags(false)),
		SourceAddress: fixture.profile.MarketAddress, DestinationAddress: fixture.profile.SourceAgentAccount,
		ValueNanoTOS:  fixture.expected.ValueNanoTOS - 1000,
		BodyBOCBase64: base64.StdEncoding.EncodeToString(richBody.ToBOCWithFlags(false)),
		BodyHash:      cellDigest(richBody), Bounced: true,
	}
	failure := fixture.destination
	failure.Aborted, failure.ComputeSuccess, failure.ActionSuccess, failure.OpcodeSuccess = true, false, false, false
	failure.SuccessPredicateDigest = ""
	failure.BounceMessage = &bounce
	failure.RichBounceEnvelopeHash = bounce.BodyHash
	failure.RichBounceOriginalBodyHash = fixture.expected.BodyHash
	created, err := journal.ResolveDestination(t.Context(), fixture.actionID, failure, &relayTestVerifier{})
	if err != nil || created.State != RelayDestinationFailedBounceCreated {
		t.Fatalf("bounce creation: %#v %v", created, err)
	}
	if disposition := created.ReservationDisposition(); !disposition.ReleaseMarketExposure ||
		disposition.ReleaseSourceLiquidity {
		t.Fatalf("bounce creation released source funds early: %#v", disposition)
	}
	// A crash after the destination has created the rich bounce but before the
	// source account has credited it is the economically sensitive window: the
	// market exposure is gone, but the source funds are not yet reusable.
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	restarted, err := OpenPredictionRelayJournal(journal.directory, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	journal = restarted
	recovered, ok := journal.Get(fixture.actionID)
	if !ok || recovered.State != RelayDestinationFailedBounceCreated || recovered.DestinationEvidence == nil ||
		recovered.DestinationEvidence.BounceMessage == nil ||
		recovered.ReservationDisposition().ReleaseSourceLiquidity {
		t.Fatalf("restart lost the unresolved rich-bounce boundary: %#v", recovered)
	}
	if _, err := journal.BeginOrResumeExactBroadcast(t.Context(), fixture.actionID, &relayTestBroadcaster{}); err == nil {
		t.Fatal("restart rebroadcast an action whose destination already created a rich bounce")
	}
	creditCell := cell.BeginCell().MustStoreUInt(0x705, 12).EndCell()
	credit := BounceCreditEvidence{
		InboundBounceMessageHash: bounce.MessageHash,
		TransactionHash:          "sha256:" + hex.EncodeToString(creditCell.Hash()),
		TransactionBOCBase64:     base64.StdEncoding.EncodeToString(creditCell.ToBOCWithFlags(false)),
		Block: BlockIdentity{
			WorkchainID: 0, Shard: 1, SequenceNumber: 53,
			RootHash: "sha256:" + strings.Repeat(
				"a",
				64,
			), FileHash: "sha256:" + strings.Repeat("b", 64), MasterchainSequence: 104,
		},
		Finality: fixture.destination.Finality, NextSourceCursor: AccountCursor{
			AccountAddress:  fixture.profile.SourceAgentAccount,
			LastLogicalTime: 140, LastTransactionHash: "sha256:" + strings.Repeat("c", 64),
		},
		CreditedValueNanoTOS: bounce.ValueNanoTOS,
	}
	credited, err := journal.ResolveBounceCredit(t.Context(), fixture.actionID, credit, &relayTestVerifier{})
	if err != nil || credited.State != RelayBounceCreditedAtAgent {
		t.Fatalf("bounce credit: %#v %v", credited, err)
	}
	if disposition := credited.ReservationDisposition(); !disposition.ReleaseSourceLiquidity ||
		disposition.RealizeSourceLoss {
		t.Fatalf("credited bounce did not release source funds: %#v", disposition)
	}
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	restarted, err = OpenPredictionRelayJournal(journal.directory, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	recovered, ok = restarted.Get(fixture.actionID)
	if !ok || recovered.State != RelayBounceCreditedAtAgent || recovered.BounceCreditEvidence == nil ||
		!recovered.ReservationDisposition().ReleaseSourceLiquidity {
		t.Fatalf("restart lost terminal rich-bounce credit: %#v", recovered)
	}
}

func TestPredictionRelayRecoversAcrossSourceAndBounceResolutionCrashes(t *testing.T) {
	fixture := newRelayFixture(t)
	directory := filepath.Join(t.TempDir(), "relay")
	journal := openRelayFixture(t, fixture, directory)
	if record := prepareAndResolveSource(t, journal, fixture); record.State != RelaySourceFinalized {
		t.Fatalf("source was not finalized before simulated crash: %#v", record)
	}
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	restarted, err := OpenPredictionRelayJournal(directory, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	journal = restarted
	recovered, found := journal.Get(fixture.actionID)
	if !found || recovered.State != RelaySourceFinalized || recovered.ActualOutbound == nil {
		t.Fatalf("source-finalized recovery lost the destination resolution boundary: %#v", recovered)
	}

	richBody := cell.BeginCell().MustStoreUInt(0xfffffffe, 32).MustStoreUInt(0x504d0001, 32).EndCell()
	bounceCell := cell.BeginCell().MustStoreUInt(0x704, 12).MustStoreRef(richBody).EndCell()
	bounce := ChainObservedMessage{
		MessageHash:     cellDigest(bounceCell),
		ExactMessageBOC: base64.StdEncoding.EncodeToString(bounceCell.ToBOCWithFlags(false)),
		SourceAddress:   fixture.profile.MarketAddress, DestinationAddress: fixture.profile.SourceAgentAccount,
		ValueNanoTOS:  fixture.expected.ValueNanoTOS - 1000,
		BodyBOCBase64: base64.StdEncoding.EncodeToString(richBody.ToBOCWithFlags(false)),
		BodyHash:      cellDigest(richBody), Bounced: true,
	}
	failure := fixture.destination
	failure.Aborted, failure.ComputeSuccess, failure.ActionSuccess, failure.OpcodeSuccess = true, false, false, false
	failure.SuccessPredicateDigest = ""
	failure.BounceMessage = &bounce
	failure.RichBounceEnvelopeHash = bounce.BodyHash
	failure.RichBounceOriginalBodyHash = fixture.expected.BodyHash
	created, err := journal.ResolveDestination(t.Context(), fixture.actionID, failure, &relayTestVerifier{})
	if err != nil || created.State != RelayDestinationFailedBounceCreated {
		t.Fatalf("bounce creation: %#v %v", created, err)
	}
	if closeErr := journal.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	journal, err = OpenPredictionRelayJournal(directory, fixture.profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	recovered, found = journal.Get(fixture.actionID)
	if !found || recovered.State != RelayDestinationFailedBounceCreated || recovered.DestinationEvidence == nil {
		t.Fatalf("bounce-resolving recovery lost exact destination evidence: %#v", recovered)
	}

	creditCell := cell.BeginCell().MustStoreUInt(0x705, 12).EndCell()
	credit := BounceCreditEvidence{
		InboundBounceMessageHash: bounce.MessageHash,
		TransactionHash:          "sha256:" + hex.EncodeToString(creditCell.Hash()),
		TransactionBOCBase64:     base64.StdEncoding.EncodeToString(creditCell.ToBOCWithFlags(false)),
		Block: BlockIdentity{
			WorkchainID: -1, Shard: -1, SequenceNumber: 53,
			RootHash:            "sha256:" + strings.Repeat("a", 64),
			FileHash:            "sha256:" + strings.Repeat("b", 64),
			MasterchainSequence: 104,
		},
		Finality: fixture.destination.Finality,
		NextSourceCursor: AccountCursor{
			AccountAddress: fixture.profile.SourceAgentAccount, LastLogicalTime: 140,
			LastTransactionHash: "sha256:" + strings.Repeat("c", 64),
		},
		CreditedValueNanoTOS: bounce.ValueNanoTOS,
	}
	credited, err := journal.ResolveBounceCredit(t.Context(), fixture.actionID, credit, &relayTestVerifier{})
	if err != nil || credited.State != RelayBounceCreditedAtAgent {
		t.Fatalf("bounce credit after recovery: %#v %v", credited, err)
	}
}

func TestPredictionRelayNoBounceNeedsBoundedFinalProof(t *testing.T) {
	fixture := newRelayFixture(t)
	journal := openRelayFixture(t, fixture, filepath.Join(t.TempDir(), "relay"))
	prepareAndResolveSource(t, journal, fixture)
	failure := fixture.destination
	failure.Aborted, failure.ComputeSuccess, failure.ActionSuccess, failure.OpcodeSuccess = true, false, false, false
	failure.SuccessPredicateDigest = ""
	failure.Finality.MasterchainSeqno = 120
	failure.NoBounceProof = &BoundedAbsenceEvidence{
		ScanStartMasterchainSeqno: 102, ScanEndMasterchainSeqno: 110,
		ObservationDigests: []string{"sha256:" + strings.Repeat("1", 64), "sha256:" + strings.Repeat("2", 64)},
		EvidenceSetDigest:  "sha256:" + strings.Repeat("3", 64),
	}
	terminal, err := journal.ResolveDestination(t.Context(), fixture.actionID, failure, &relayTestVerifier{})
	if err != nil || terminal.State != RelayDestinationFailedNoBounce {
		t.Fatalf("no-bounce terminal: %#v %v", terminal, err)
	}
	if disposition := terminal.ReservationDisposition(); !disposition.ReleaseMarketExposure ||
		disposition.ReleaseSourceLiquidity ||
		!disposition.RealizeSourceLoss {
		t.Fatalf("no-bounce value was treated as reusable: %#v", disposition)
	}
}

func TestPredictionRelayRejectsMutatedOrWeakEvidenceBeforeVerifier(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*relayFixture)
	}{
		{"wrong external message", func(f *relayFixture) {
			f.source.SubmittedExternalMessageHash = "tvm-cell-sha256:" + strings.Repeat("0", 64)
		}},
		{"multiple outbound", func(f *relayFixture) {
			f.source.OutboundMessages = append(f.source.OutboundMessages, f.source.OutboundMessages[0])
		}},
		{"wrong body", func(f *relayFixture) {
			f.source.OutboundMessages[0].BodyHash = "tvm-cell-sha256:" + strings.Repeat("0", 64)
		}},
		{"wrong state init", func(f *relayFixture) {
			stateInit := cell.BeginCell().MustStoreUInt(0x51, 8).EndCell()
			f.source.OutboundMessages[0].StateInitBOCBase64 = base64.StdEncoding.EncodeToString(
				stateInit.ToBOCWithFlags(false),
			)
			f.source.OutboundMessages[0].StateInitHash = cellDigest(stateInit)
		}},
		{"wrong extra flags", func(f *relayFixture) { f.source.OutboundMessages[0].ExtraFlags = 0 }},
		{"unadmitted quorum member", func(f *relayFixture) {
			f.source.Finality.AgreeingIDs[0] = "sha256:" + strings.Repeat("0", 64)
			sortStrings(f.source.Finality.AgreeingIDs)
		}},
		{"pre-checkpoint block", func(f *relayFixture) { f.source.Block.MasterchainSequence = 99 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayFixture(t)
			journal := openRelayFixture(t, fixture, filepath.Join(t.TempDir(), "relay"))
			if _, err := journal.Prepare(
				fixture.actionID,
				fixture.signedBOC,
				fixture.expected,
				fixture.cursor,
				fixture.checkpoint,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.BeginOrResumeExactBroadcast(
				t.Context(), fixture.actionID, &relayTestBroadcaster{},
			); err != nil {
				t.Fatal(err)
			}
			test.mutate(&fixture)
			verifier := &relayTestVerifier{}
			if _, err := journal.ResolveSource(t.Context(), fixture.actionID, fixture.source, verifier); err == nil ||
				verifier.sourceCalls != 0 {
				t.Fatalf("weak evidence reached verifier: calls=%d err=%v", verifier.sourceCalls, err)
			}
		})
	}
}

func TestPredictionRelayVerifierFailureLeavesStateAmbiguous(t *testing.T) {
	fixture := newRelayFixture(t)
	journal := openRelayFixture(t, fixture, filepath.Join(t.TempDir(), "relay"))
	if _, err := journal.Prepare(
		fixture.actionID,
		fixture.signedBOC,
		fixture.expected,
		fixture.cursor,
		fixture.checkpoint,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.BeginOrResumeExactBroadcast(
		t.Context(), fixture.actionID, &relayTestBroadcaster{},
	); err != nil {
		t.Fatal(err)
	}
	verifier := &relayTestVerifier{err: errors.New("quorum signatures invalid")}
	if _, err := journal.ResolveSource(t.Context(), fixture.actionID, fixture.source, verifier); err == nil {
		t.Fatal("invalid proof was accepted")
	}
	record, _ := journal.Get(fixture.actionID)
	if record.State != RelayBroadcasting || record.ReservationDisposition() != (PredictionReservationDisposition{}) {
		t.Fatalf("ambiguous proof released capacity: %#v", record)
	}
}

func sortStrings(values []string) {
	for i := range values {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}
