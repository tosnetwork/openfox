package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type outcomeOperationResolver struct{ key ed25519.PublicKey }

func (resolver outcomeOperationResolver) AuthorizeAgentOperationKey(agentID string, profile commerce.ProfileRefV1,
	key ed25519.PublicKey, _ time.Time, proof []byte) error {
	if agentID != "agent:outcome" || profile.ProfileURI != "tos.identity.agent-key.v1" || !key.Equal(resolver.key) || string(proof) != "historical-proof" {
		return errors.New("unexpected outcome operation authority")
	}
	return nil
}

func TestOutcomeJournalCrashGapReplayAndWriterTakeover(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:outcome", "agent:outcome", "authority:outcome", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence1, err := authority.AcquireWriter(context.Background(), "runtime:one", []string{outcomeJournalScope}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTempDir(t)
	cohort := zeroSHA256Digest()
	journal, err := OpenOutcomeJournal(directory, "owner:outcome", "agent:outcome", "authority:outcome", "economic_attempts", cohort, fence1, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := journal.Reserve(fence1, authority, now)
	if err != nil || reserved != 1 {
		t.Fatalf("reserve=%d err=%v", reserved, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, err = OpenOutcomeJournal(directory, "owner:outcome", "agent:outcome", "authority:outcome", "economic_attempts", cohort, fence1, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	head := journal.Head()
	if len(head.GapSequences) != 1 || head.GapSequences[0] != 1 || head.PendingSequence != 0 {
		t.Fatalf("crash gap not recovered: %+v", head)
	}
	sequence, err := journal.Reserve(fence1, authority, now)
	if err != nil || sequence != 2 {
		t.Fatalf("post-gap reserve=%d err=%v", sequence, err)
	}

	assertion, _ := codec.Marshal(commerce.ActionResolutionReferencePayloadV1{StableActionID: testDigest,
		ExactRequestDigest: zeroSHA256Digest(), AuthorizedActionDigest: testDigest, ActionResolutionDigest: zeroSHA256Digest(),
		ResolutionState: commerce.ActionTerminal, ResolutionStateRevision: 1})
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: testDigest}, nil,
		commerce.OutcomeProfileActionResolutionReference, assertion, commerce.EmptyOutcomeEvidenceManifestV1("local_projection"), commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, payload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}
	_, operationKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: "agent:outcome", AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1, ProfileDigest: testDigest},
		AudienceDescriptor: "local-private", ObjectID: contentID, OrderingDomain: head.OrderingDomain, Sequence: sequence, Epoch: fence1.Body.WriterGeneration,
		CreatedAtUnix: uint64(now.Unix()), PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(payload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commerce.SignAgentOperationV1(body, body.ActorAgentID, operationKey, []byte("historical-proof"))
	if err != nil {
		t.Fatal(err)
	}
	artifacts := commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertion,
		EvidenceManifest: commerce.EmptyOutcomeEvidenceManifestV1("local_projection"),
		ExtensionSet:     commerce.EmptyOutcomeExtensionSetV1(), AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{}}
	envelopeDigest, err := commerce.AgentOperationEnvelopeDigestV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	gapDigest, err := codec.Digest("tos.openfox.outcome-journal-gap-set.v1", head.GapSequences)
	if err != nil {
		t.Fatal(err)
	}
	appendRequest := commerce.OperationJournalAppendAdmissionRequestV1{OrderingDomain: head.OrderingDomain, Epoch: head.WriterGeneration,
		Sequence: sequence, EventContentID: contentID, OperationEnvelopeDigest: envelopeDigest, GapSetDigest: gapDigest}
	appendBytes, _ := codec.Marshal(appendRequest)
	appendFields, err := commerce.OperationJournalAppendSemanticFieldsV1("owner:outcome", "agent:outcome", head.OrderingDomain,
		head.WriterGeneration, sequence, contentID)
	if err != nil {
		t.Fatal(err)
	}
	appendAction, err := commerce.BuildAuthorizedAction("owner:outcome", "agent:outcome", outcomeJournalScope, appendFields, appendBytes,
		fence1, 1, testDigest, "", "journal-head", fence1.Body.ExpiresAtUnix)
	if err == nil {
		appendAction, err = authority.SignAction(appendAction, fence1)
	}
	if err == nil {
		_, err = authority.Admit(appendAction, appendFields, appendBytes, fence1, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	appendAdmission := &OutcomeJournalAppendAdmission{Request: appendRequest, Action: appendAction, Fence: fence1}
	durableRecord, err := journal.Commit(sequence, envelope, payload, artifacts,
		outcomeOperationResolver{key: operationKey.Public().(ed25519.PublicKey)}, now, appendAdmission, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate power loss after the immutable record and its directory entry
	// were synced, but before the atomic head replacement. Startup must promote
	// this exact admitted record, not quarantine it and append a duplicate under
	// a new semantic Action.
	crashHead := head
	crashHead.PendingSequence = sequence
	crashRaw, err := json.Marshal(crashHead)
	if err != nil {
		t.Fatal(err)
	}
	journal.mu.Lock()
	err = fileutil.WriteFileAtomicRoot(journal.root, outcomeJournalHead, crashRaw, 0o600)
	journal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenOutcomeJournal(directory, "owner:outcome", "agent:outcome", "authority:outcome", "economic_attempts", cohort, fence1, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	recoveredHead := journal.Head()
	if recoveredHead.PendingSequence != 0 || recoveredHead.LastSequence != sequence ||
		recoveredHead.LastRecordChecksum != durableRecord.RecordChecksum || recoveredHead.LastEnvelopeDigest != durableRecord.OperationEnvelopeDigest {
		t.Fatalf("durable pre-head record was not recovered exactly: %+v", recoveredHead)
	}
	records, err := journal.Records(10)
	if err != nil || len(records) != 1 || records[0].Sequence != 2 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	checkpoint, checkpointDigest, err := journal.CreateCheckpoint(operationKey, body.AuthorizationRef, []byte("historical-proof"),
		outcomeOperationResolver{key: operationKey.Public().(ed25519.PublicKey)}, now)
	if err != nil || !canonicalSHA256(checkpointDigest) || VerifyOutcomeJournalCheckpointV1(checkpoint,
		outcomeOperationResolver{key: operationKey.Public().(ed25519.PublicKey)}, now) != nil {
		t.Fatalf("checkpoint digest=%s err=%v", checkpointDigest, err)
	}
	checkpoint.Body.LastRecordChecksum = zeroSHA256Digest()
	if VerifyOutcomeJournalCheckpointV1(checkpoint, outcomeOperationResolver{key: operationKey.Public().(ed25519.PublicKey)}, now) == nil {
		t.Fatal("mutated journal checkpoint verified")
	}
	archive, err := journal.ExportArchive()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the durable import intent and first record, but
	// before head promotion. Reopen must finish that exact archive without a
	// replacement branch or operator-side truncation.
	crashImportDirectory := privateTempDir(t)
	crashImport, err := OpenOutcomeJournal(crashImportDirectory, "owner:outcome", "agent:outcome", "authority:outcome",
		"economic_attempts", cohort, fence1, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	rawArchive, _ := json.Marshal(archive)
	if err = fileutil.WriteFileAtomicRoot(crashImport.root, outcomeJournalImportIntent, rawArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	rawRecord, _ := json.Marshal(archive.Records[0])
	if err = writeOutcomeRootExclusive(crashImport.root,
		outcomeRecordName(archive.Records[0].Epoch, archive.Records[0].Sequence), rawRecord); err != nil {
		t.Fatal(err)
	}
	if err = crashImport.Close(); err != nil {
		t.Fatal(err)
	}
	crashImport, err = OpenOutcomeJournal(crashImportDirectory, "owner:outcome", "agent:outcome", "authority:outcome",
		"economic_attempts", cohort, fence1, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, recoverErr := crashImport.Records(10); recoverErr != nil || len(recovered) != len(archive.Records) ||
		recovered[len(recovered)-1].RecordChecksum != archive.Head.LastRecordChecksum {
		_ = crashImport.Close()
		t.Fatalf("crashed archive import did not recover exactly: records=%+v err=%v", recovered, recoverErr)
	}
	if _, statErr := crashImport.root.Stat(outcomeJournalImportIntent); !errors.Is(statErr, os.ErrNotExist) {
		_ = crashImport.Close()
		t.Fatalf("completed archive import retained its recovery intent: %v", statErr)
	}
	if err = crashImport.Close(); err != nil {
		t.Fatal(err)
	}
	imported, err := OpenOutcomeJournal(privateTempDir(t), "owner:outcome", "agent:outcome", "authority:outcome",
		"economic_attempts", cohort, fence1, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := imported.ImportArchive(archive, outcomeOperationResolver{key: operationKey.Public().(ed25519.PublicKey)}, now); err != nil {
		_ = imported.Close()
		t.Fatal(err)
	}
	if importedRecords, importErr := imported.Records(10); importErr != nil || len(importedRecords) != 1 ||
		importedRecords[0].RecordChecksum != records[0].RecordChecksum {
		_ = imported.Close()
		t.Fatalf("archive did not round-trip: records=%+v err=%v", importedRecords, importErr)
	}
	if err := imported.ImportArchive(archive, outcomeOperationResolver{key: operationKey.Public().(ed25519.PublicKey)}, now); err == nil {
		_ = imported.Close()
		t.Fatal("archive overwrote a non-empty journal")
	}
	if err := imported.Close(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	fence2, err := authority.AcquireWriter(context.Background(), "runtime:two", []string{outcomeJournalScope}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	journal, err = OpenOutcomeJournal(directory, "owner:outcome", "agent:outcome", "authority:outcome", "economic_attempts", cohort, fence2, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, err := journal.Reserve(fence1, authority, now); err == nil {
		t.Fatal("stale writer appended after takeover")
	}
	if sequence, err := journal.Reserve(fence2, authority, now); err != nil || sequence != 3 {
		t.Fatalf("takeover sequence=%d err=%v", sequence, err)
	}
}
