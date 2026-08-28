package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type outcomeTransitionErrorAuthority struct {
	EconomicAuthority
	now        time.Time
	resolution commerce.ActionResolution
}

func (authority outcomeTransitionErrorAuthority) AuthorityNow() time.Time { return authority.now }

func (authority outcomeTransitionErrorAuthority) Transition(string, string, commerce.ActionResolutionState,
	string, []string) (commerce.ActionResolution, error) {
	return authority.resolution, errors.New("sink returned a terminal rejection")
}

type collectingActionOutcomeRecorder struct {
	resolutions []commerce.ActionResolution
}

func (recorder *collectingActionOutcomeRecorder) RecordActionResolution(_ commerce.AuthorizedAction,
	resolution commerce.ActionResolution, _ time.Time) error {
	recorder.resolutions = append(recorder.resolutions, resolution)
	return nil
}

func TestOutcomeRecordingAuthorityRetainsTransitionResolutionReturnedWithError(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	action := commerce.AuthorizedAction{StableActionID: testDigest, ExactRequestDigest: zeroSHA256Digest()}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionRejected, SinkReference: "sink:policy", StateRevision: 1}
	recorder := &collectingActionOutcomeRecorder{}
	authority := NewOutcomeRecordingAuthority(outcomeTransitionErrorAuthority{now: now, resolution: resolution}, recorder)
	authority.remember(action)
	observed, err := authority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionRejected, "sink:policy", nil)
	if err == nil || observed.State != commerce.ActionRejected || len(recorder.resolutions) != 1 || recorder.resolutions[0].State != commerce.ActionRejected {
		t.Fatalf("negative transition resolution was dropped: observed=%+v captured=%+v err=%v", observed, recorder.resolutions, err)
	}
}

func TestJournalOutcomeRecorderCapturesNegativeResolution(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:recorder", "agent:recorder", "authority:recorder", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime:recorder", []string{"accounting.record", outcomeJournalScope}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenOutcomeJournal(privateTempDir(t), "owner:recorder", "agent:recorder", "authority:recorder", "economic_attempts", zeroSHA256Digest(), fence, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	_, operationKey, _ := ed25519.GenerateKey(rand.Reader)
	recorder := &JournalOutcomeRecorder{Journal: journal, NetworkID: "tos:test", AudienceDescriptor: "local-private",
		AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1, ProfileDigest: testDigest},
		OperationKey:     operationKey, HistoricalProof: []byte("proof"), Fence: fence, FenceResolver: authority}
	recorder.AppendAuthority = authority
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:recorder"), "agent_id": commerce.ID("agent:recorder"),
		"entry_id": commerce.Digest32(testDigest), "classification": commerce.Kind("failed_cost"), "evidence_set_digest": commerce.Digest32(zeroSHA256Digest())}
	action, err := commerce.BuildAuthorizedAction("owner:recorder", "agent:recorder", "accounting.record", fields, []byte("exact request"), fence, 1,
		testDigest, "", "empty", uint64(now.Add(time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = authority.SignAction(action, fence)
	if err != nil {
		t.Fatal(err)
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionRejected, SinkReference: "sink:policy", StateRevision: 1}
	if err := recorder.RecordActionResolution(action, resolution, now); err != nil {
		t.Fatal(err)
	}
	records, err := journal.Records(10)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if records[0].Envelope.Body.ObjectID == "" || records[0].Sequence != 1 {
		t.Fatalf("invalid recorded outcome: %+v", records[0])
	}
	if records[0].JournalAppendRequest == nil || records[0].JournalAppendAction == nil || records[0].JournalAppendWriterFence == nil ||
		records[0].JournalAppendAction.StableActionID != records[0].JournalAppendActionID ||
		records[0].JournalAppendAction.ExactRequestDigest != records[0].JournalAppendRequestDigest {
		t.Fatal("durable record omitted its exact append admission evidence")
	}
	if records[0].SourceAuthorizedAction == nil || records[0].SourceActionResolution == nil ||
		!reflect.DeepEqual(*records[0].SourceAuthorizedAction, action) || !reflect.DeepEqual(*records[0].SourceActionResolution, resolution) {
		t.Fatal("durable record omitted the exact source Action or sink resolution")
	}
	// Simulate the crash window after the Operation record became durable but
	// before its append Action reached TERMINAL. A retry must finish that exact
	// Action and must not append another outcome record.
	authority.mu.Lock()
	appendResolution := authority.doc.Actions[records[0].JournalAppendActionID]
	appendResolution.State = commerce.ActionPrepared
	appendResolution.StateRevision = 1
	appendResolution.SinkReference = ""
	appendResolution.EvidenceRefs = nil
	authority.doc.Actions[records[0].JournalAppendActionID] = appendResolution
	if err := authority.persist(authority.doc); err != nil {
		authority.mu.Unlock()
		t.Fatal(err)
	}
	authority.mu.Unlock()
	if err := recorder.RecordActionResolution(action, resolution, now); err != nil {
		t.Fatal(err)
	}
	if recovered := authority.Resolve(records[0].JournalAppendActionID, records[0].JournalAppendRequestDigest); recovered.State != commerce.ActionTerminal {
		t.Fatalf("append Action was not recovered: %+v", recovered)
	}
	if records, err = journal.Records(10); err != nil || len(records) != 1 {
		t.Fatalf("recovery duplicated the durable outcome: records=%d err=%v", len(records), err)
	}
	// The event commits the exact source resolution digest. Recomputing the
	// non-secret record checksum after changing the retained sink result must
	// therefore still fail validation.
	sourceTampered := records[0]
	mutatedResolution := *sourceTampered.SourceActionResolution
	mutatedResolution.SinkReference = "sink:substituted"
	sourceTampered.SourceActionResolution = &mutatedResolution
	sourceTampered.RecordChecksum = ""
	sourceTampered.RecordChecksum, err = outcomeRecordChecksum(sourceTampered)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sourceTampered)
	path := filepath.Join(journal.directory, outcomeRecordName(sourceTampered.Epoch, sourceTampered.Sequence))
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Records(10); err == nil {
		t.Fatal("journal accepted a substituted source resolution with a recomputed checksum")
	}
	originalRaw, _ := json.Marshal(records[0])
	if err = os.WriteFile(path, originalRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	// A local attacker can recompute the non-secret record checksum, so archive
	// validation must independently verify the retained authority signature.
	tampered := records[0]
	tampered.JournalAppendAction.AuthorizationProof = "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tampered.RecordChecksum = ""
	tampered.RecordChecksum, err = outcomeRecordChecksum(tampered)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(tampered)
	if err = os.WriteFile(filepath.Join(journal.directory, outcomeRecordName(tampered.Epoch, tampered.Sequence)), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Records(10); err == nil {
		t.Fatal("journal accepted a forged append Action with a recomputed checksum")
	}
}

func TestOutcomeRecordingAuthorityCapturesEveryRevisionExactlyOnce(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	base, err := OpenPersonalAuthority(privateTempDir(t), "owner:managed", "agent:managed", "authority:managed", authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	base.now = func() time.Time { return now }
	fence, err := base.AcquireWriter(context.Background(), "runtime:managed", []string{"accounting.record", outcomeJournalScope}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, operationKey, _ := ed25519.GenerateKey(rand.Reader)
	operationAuthority, err := commerce.NewPinnedAgentOperationAuthorityV1("agent:managed", operationKey.Public().(ed25519.PublicKey),
		time.Unix(1, 0).UTC(), time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC), testDigest)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTempDir(t)
	recorder := &ManagedOutcomeRecorder{Directory: directory, OwnerID: "owner:managed", AgentID: "agent:managed",
		AuthorityID: "authority:managed", Purpose: "economic-side-effects", CohortScopeDigest: zeroSHA256Digest(),
		NetworkID: "tos:test", AudienceDescriptor: "local-private", OperationAuthority: operationAuthority,
		OperationKey: operationKey, FenceSource: func(context.Context) (commerce.WriterFence, error) { return fence, nil }, FenceResolver: base,
		AppendAuthority: base}
	defer recorder.Close()
	authority := NewOutcomeRecordingAuthority(base, recorder)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:managed"), "agent_id": commerce.ID("agent:managed"),
		"entry_id": commerce.Digest32(testDigest), "classification": commerce.Kind("cost"), "evidence_set_digest": commerce.Digest32(zeroSHA256Digest())}
	action, err := commerce.BuildAuthorizedAction("owner:managed", "agent:managed", "accounting.record", fields, []byte("request"), fence,
		1, testDigest, "", "empty", uint64(now.Add(time.Minute).Unix()))
	if err == nil {
		action, err = base.SignAction(action, fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := authority.Admit(action, fields, []byte("request"), fence, nil)
	if err != nil || prepared.State != commerce.ActionPrepared {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	// Simulate a process takeover: the decorator's memory is empty, so the
	// terminal capture must recover the exact signed Action from the durable
	// economic authority rather than reconstructing it from current policy.
	authority = NewOutcomeRecordingAuthority(base, recorder)
	terminal, err := authority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionTerminal, "sink:done", []string{testDigest})
	if err != nil || terminal.StateRevision != 2 {
		t.Fatalf("terminal=%+v err=%v", terminal, err)
	}
	if _, err := authority.Admit(action, fields, []byte("request"), fence, nil); err != nil {
		t.Fatal(err)
	}
	records, err := recorder.journal.Records(10)
	if err != nil || len(records) != 2 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	for index, record := range records {
		var assertion commerce.ActionResolutionReferencePayloadV1
		if err := codec.Unmarshal(record.Artifacts.AssertionPayload, &assertion); err != nil || assertion.ResolutionStateRevision != uint64(index+1) {
			t.Fatalf("record %d did not bind its Action revision: %+v err=%v", index, assertion, err)
		}
	}
	conflicting, err := commerce.BuildAuthorizedAction("owner:managed", "agent:managed", "accounting.record", fields,
		[]byte("different request"), fence, 1, testDigest, "", "empty", uint64(now.Add(time.Minute).Unix()))
	if err == nil {
		conflicting, err = base.SignAction(conflicting, fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	conflict, conflictErr := authority.Admit(conflicting, fields, []byte("different request"), fence, nil)
	if conflictErr == nil || conflict.State != commerce.ActionConflict {
		t.Fatalf("conflict=%+v err=%v", conflict, conflictErr)
	}
	records, err = recorder.journal.Records(10)
	if err != nil || len(records) != 3 {
		t.Fatalf("negative resolution was omitted: records=%d err=%v", len(records), err)
	}
	var negative commerce.ActionResolutionReferencePayloadV1
	if codec.Unmarshal(records[2].Artifacts.AssertionPayload, &negative) != nil || negative.ResolutionState != commerce.ActionConflict {
		t.Fatalf("negative resolution evidence is invalid: %+v", negative)
	}
}

func TestOutcomeJournalAppendAuthorityRejectsCrossHostFork(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:fork", "agent:fork", "authority:fork", key, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime:fork", []string{outcomeJournalScope}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := OutcomeOrderingDomainV1("owner:fork", "agent:fork", "authority:fork", "economic-side-effects", zeroSHA256Digest())
	if err != nil {
		t.Fatal(err)
	}
	eventA := testDigest
	eventB, err := codec.Digest("tos.test.outcome.event-b.v1", "event-b")
	if err != nil {
		t.Fatal(err)
	}
	admit := func(eventID string) (commerce.AuthorizedAction, commerce.ActionResolution, error) {
		request := commerce.OperationJournalAppendAdmissionRequestV1{OrderingDomain: domain, Epoch: fence.Body.WriterGeneration,
			Sequence: 1, EventContentID: eventID, OperationEnvelopeDigest: testDigest, GapSetDigest: zeroSHA256Digest()}
		canonical, marshalErr := codec.Marshal(request)
		if marshalErr != nil {
			return commerce.AuthorizedAction{}, commerce.ActionResolution{}, marshalErr
		}
		fields, fieldsErr := commerce.OperationJournalAppendSemanticFieldsV1("owner:fork", "agent:fork", domain,
			fence.Body.WriterGeneration, 1, eventID)
		if fieldsErr != nil {
			return commerce.AuthorizedAction{}, commerce.ActionResolution{}, fieldsErr
		}
		action, buildErr := commerce.BuildAuthorizedAction("owner:fork", "agent:fork", outcomeJournalScope, fields, canonical,
			fence, 1, testDigest, "", "journal-head", uint64(now.Add(time.Minute).Unix()))
		if buildErr == nil {
			action, buildErr = authority.SignAction(action, fence)
		}
		if buildErr != nil {
			return commerce.AuthorizedAction{}, commerce.ActionResolution{}, buildErr
		}
		resolution, admitErr := authority.Admit(action, fields, canonical, fence, nil)
		return action, resolution, admitErr
	}
	actionA, first, err := admit(eventA)
	if err != nil || first.State != commerce.ActionPrepared {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	// An exact crash retry is idempotent.
	fieldsA, _ := commerce.OperationJournalAppendSemanticFieldsV1("owner:fork", "agent:fork", domain, fence.Body.WriterGeneration, 1, eventA)
	requestA := commerce.OperationJournalAppendAdmissionRequestV1{OrderingDomain: domain, Epoch: fence.Body.WriterGeneration,
		Sequence: 1, EventContentID: eventA, OperationEnvelopeDigest: testDigest, GapSetDigest: zeroSHA256Digest()}
	canonicalA, _ := codec.Marshal(requestA)
	if retried, retryErr := authority.Admit(actionA, fieldsA, canonicalA, fence, nil); retryErr != nil || !reflect.DeepEqual(retried, first) {
		t.Fatalf("exact retry was not idempotent: %+v err=%v", retried, retryErr)
	}
	if _, _, err := admit(eventB); err == nil {
		t.Fatal("a second host admitted a conflicting event at the same sequence")
	}
}
