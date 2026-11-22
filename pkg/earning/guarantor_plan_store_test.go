package earning

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// testExpiredGuarantorOffer is an expired offer position holding the
// non-acceptance evidence its release plan is for.
func testExpiredGuarantorOffer(offerID string) GuarantorOfferPosition {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	evidence := guarantor.AuthorizedOfferNonAcceptanceEvidenceV1{
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{{AuthoritySubject: "agent:guarantor"}}}
	evidence.Body.SchemaVersion, evidence.Body.AuthorityInstanceID = 1, offerID
	evidence.Body.AuthorizedFirmOfferEnvelopeDigest, evidence.Body.AcceptanceAdmissionLogRoot = digest("1"), digest("2")
	evidence.Body.AuthorizedActionDigest, evidence.Body.StableActionID = digest("3"), digest("4")
	evidence.Body.ExactRequestDigest, evidence.Body.WriterFenceDigest = digest("5"), digest("6")
	evidence.Body.PriorOfferStateRevision, evidence.Body.ResolvedOfferStateRevision = 3, 4
	return GuarantorOfferPosition{QuoteRequestDigest: digest("3"), NonAcceptanceEvidence: &evidence,
		Record: guarantor.OfferRecord{OfferID: offerID, ReservationID: digest("a"), Status: guarantor.OfferExpired,
			StateRevision: 4}}
}

// testGuarantorOfferReleasePlan is the release plan a coordinator prepares for
// an expired offer: its semantic fields derive its stable action identity and
// name the offer's reservation and stored non-acceptance evidence.
func testGuarantorOfferReleasePlan(t *testing.T, position GuarantorOfferPosition,
	basePortfolioRevision uint64) GuarantorPreAcceptanceReleasePlan {
	t.Helper()
	evidenceDigest, err := guarantor.Digest(guarantor.OfferNonAcceptanceDomain, *position.NonAcceptanceEvidence)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:guarantor"),
		"agent_id": commerce.ID("agent:guarantor"), "reservation_id": commerce.Digest32(position.Record.ReservationID),
		"target_revision":              commerce.U64(basePortfolioRevision + 1),
		"terminal_evidence_set_digest": commerce.Digest32(evidenceDigest)}
	body := guarantor.PreAcceptanceExposureReleaseActionBodyV1{SchemaVersion: 1, ReleaseVariant: "pre_acceptance",
		AuthorizedNonAcceptanceEvidence: *position.NonAcceptanceEvidence,
		ExpectedPortfolioRevision:       basePortfolioRevision, TargetPortfolioRevision: basePortfolioRevision + 1}
	request, err := guarantor.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	stableActionID, _, err := commerce.DeriveStableActionID("portfolio.release", fields)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := commerce.ExactRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return GuarantorPreAcceptanceReleasePlan{Action: commerce.AuthorizedAction{SchemaVersion: 1,
		OwnerID: "owner:guarantor", AgentID: "agent:guarantor", ActionKind: "portfolio.release",
		StableActionID: stableActionID, ExactRequestDigest: requestDigest, WriterGeneration: 1}, Fields: fields,
		CanonicalRequest: request, RequestBody: body, BasePortfolioRevision: basePortfolioRevision,
		TargetPortfolioRevision: basePortfolioRevision + 1, ReleasedAtUnix: 2_000_000_000}
}

// reopenTestGuarantorJournal closes journal and opens its directory again, as
// a restart does: the new journal holds nothing but what it loads from disk.
func reopenTestGuarantorJournal(t *testing.T, journal *GuarantorJournal, directory string) *GuarantorJournal {
	t.Helper()
	return restartTestGuarantorJournal(t, journal, directory, "", nil)
}

// storedTestOfferReleasePlan returns the only offer's release plan.
func storedTestOfferReleasePlan(t *testing.T, journal *GuarantorJournal) GuarantorPreAcceptanceReleasePlan {
	t.Helper()
	_, offers, _ := journal.Snapshot()
	if len(offers) != 1 || offers[0].PreAcceptanceReleasePlan == nil {
		t.Fatalf("the journal does not hold the release plan: %#v", offers)
	}
	return *offers[0].PreAcceptanceReleasePlan
}

// resumeTestOfferReleasePlan does with a stored release plan what a
// coordinator resuming it does: it derives the stable action identity from the
// plan's semantic fields, which the authority checks on admission, and
// reauthorizes the plan under the next writer generation. It returns the
// identity and the plan as stored afterwards.
func resumeTestOfferReleasePlan(t *testing.T, journal *GuarantorJournal, offerID string,
	writerGeneration uint64) (string, GuarantorPreAcceptanceReleasePlan) {
	t.Helper()
	plan := storedTestOfferReleasePlan(t, journal)
	stableActionID, _, err := commerce.DeriveStableActionID(plan.Action.ActionKind, plan.Fields)
	if err != nil {
		t.Fatalf("resume the stored release plan: its semantic fields derive no stable action identity: %v", err)
	}
	if stableActionID != plan.Action.StableActionID {
		t.Fatalf("resume the stored release plan: its semantic fields derive %s, its action is %s",
			stableActionID, plan.Action.StableActionID)
	}
	reauthorized := plan.Action
	reauthorized.WriterGeneration = writerGeneration
	if _, err := journal.RefreshOfferReleasePlanAction(offerID, reauthorized); err != nil {
		t.Fatalf("reauthorize the stored release plan: %v", err)
	}
	return stableActionID, storedTestOfferReleasePlan(t, journal)
}

// TestGuarantorJournalPlanResumesAfterARestart: a stored plan is resumed after
// a restart exactly as it is resumed without one. Its semantic fields are
// written with the commit that stores the plan, so a journal opened from disk,
// holding nothing of the journal that stored it, resumes the plan to the same
// stable action identity and the same stored plan.
func TestGuarantorJournalPlanResumesAfterARestart(t *testing.T) {
	offerID := "sha256:" + strings.Repeat("7", 64)
	build := func() (*GuarantorJournal, string, GuarantorPreAcceptanceReleasePlan) {
		journal, directory := openTestGuarantorJournal(t)
		position := testExpiredGuarantorOffer(offerID)
		rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) { doc.Offers[offerID] = position })
		journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
		if err != nil {
			t.Fatal(err)
		}
		closeGuarantorJournalOnCleanup(t, journal)
		plan := testGuarantorOfferReleasePlan(t, position, 6)
		if _, err := journal.StoreOfferReleasePlan(offerID, plan); err != nil {
			t.Fatalf("store the release plan: %v", err)
		}
		return journal, directory, plan
	}

	// Without a restart.
	journal, _, plan := build()
	wantIdentity, wantPlan := resumeTestOfferReleasePlan(t, journal, offerID, 2)
	if wantIdentity != plan.Action.StableActionID {
		t.Fatalf("the plan resumed without a restart has identity %s, want %s", wantIdentity, plan.Action.StableActionID)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	// With a restart between the commit and the resume.
	journal, directory, plan := build()
	journal = reopenTestGuarantorJournal(t, journal, directory)
	loaded := storedTestOfferReleasePlan(t, journal)
	if !reflect.DeepEqual(loaded.Fields, plan.Fields) {
		t.Fatalf("the plan loaded from disk has semantic fields %#v, want %#v", loaded.Fields, plan.Fields)
	}
	gotIdentity, gotPlan := resumeTestOfferReleasePlan(t, journal, offerID, 2)
	if gotIdentity != wantIdentity || !reflect.DeepEqual(gotPlan, wantPlan) {
		t.Fatalf("the plan resumed after a restart differs from the plan resumed without one:\n got %s %#v\nwant %s %#v",
			gotIdentity, gotPlan, wantIdentity, wantPlan)
	}
	// And once more across a second restart.
	journal = reopenTestGuarantorJournal(t, journal, directory)
	if again := storedTestOfferReleasePlan(t, journal); !reflect.DeepEqual(again, wantPlan) {
		t.Fatalf("the reauthorized plan loaded from disk is %#v, want %#v", again, wantPlan)
	}
}

// TestGuarantorJournalKeepsPlanSemanticFieldsAcrossCopies: a stored plan keeps
// its semantic fields through later commits, and the maps handed in and handed
// back are not the journal's.
func TestGuarantorJournalKeepsPlanSemanticFieldsAcrossCopies(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	offerID := digest("7")
	journal, directory := openTestGuarantorJournal(t)
	position := testExpiredGuarantorOffer(offerID)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) { doc.Offers[offerID] = position })
	journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, journal)
	want := testGuarantorOfferReleasePlan(t, position, 1).Fields
	handedIn := testGuarantorOfferReleasePlan(t, position, 1)
	if _, err := journal.StoreOfferReleasePlan(offerID, handedIn); err != nil {
		t.Fatal(err)
	}
	handedIn.Fields["owner_id"] = commerce.ID("owner:changed-by-the-caller")
	if got := storedTestOfferReleasePlan(t, journal).Fields; !reflect.DeepEqual(got, want) {
		t.Fatalf("the stored plan's semantic fields are %#v, want %#v", got, want)
	}
	// Later commits copy the document again.
	for index, action := range []string{digest("1"), digest("2")} {
		if _, err := journal.BeginAdmission(digest("8"), action, digest("9"),
			time.Unix(2_000_000_000+int64(index), 0).UTC()); err != nil {
			t.Fatal(err)
		}
	}
	handedBack := storedTestOfferReleasePlan(t, journal).Fields
	if !reflect.DeepEqual(handedBack, want) {
		t.Fatalf("the plan's semantic fields after later commits are %#v, want %#v", handedBack, want)
	}
	handedBack["owner_id"] = commerce.ID("owner:changed-in-a-snapshot")
	if got := storedTestOfferReleasePlan(t, journal).Fields; !reflect.DeepEqual(got, want) {
		t.Fatalf("the plan's semantic fields were changed through a map the journal handed out: %#v", got)
	}
}

// editTestGuarantorJournalFile rewrites the journal document on disk through
// change, which edits the decoded document in place. Numbers keep their exact
// digits.
func editTestGuarantorJournalFile(t *testing.T, directory string, original []byte, change func(doc map[string]any)) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(original))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	change(doc)
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, guarantorJournalFile), edited, 0o600); err != nil {
		t.Fatal(err)
	}
}

// restartTestGuarantorJournal closes journal and opens its directory again, as
// a restart does. Before it reopens the real document it writes each tampered
// variant of it in turn, changed in the coverage position of agreementDigest,
// and requires the journal to refuse every one of them.
func restartTestGuarantorJournal(t *testing.T, journal *GuarantorJournal, directory, agreementDigest string,
	tampered map[string]func(coverage map[string]any)) *GuarantorJournal {
	t.Helper()
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, guarantorJournalFile)
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range tampered {
		editTestGuarantorJournalFile(t, directory, original, func(doc map[string]any) {
			coverage, found := doc["coverages"].(map[string]any)[agreementDigest].(map[string]any)
			if !found {
				t.Fatalf("the document has no coverage %s", agreementDigest)
			}
			change(coverage)
		})
		opened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
		if err == nil {
			_ = opened.Close()
			t.Errorf("a journal whose plan was tampered with (%s) was loaded", name)
		}
	}
	if err := os.WriteFile(file, original, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("reopen the Guarantor journal from disk: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	return reopened
}

// tamperedTestPlanFields are changes to a stored coverage plan's semantic
// fields that a load must refuse: one value changed, the fields removed, and
// the fields emptied of their values.
func tamperedTestPlanFields(t *testing.T, planMember, numberField string) map[string]func(coverage map[string]any) {
	t.Helper()
	planOf := func(coverage map[string]any) map[string]any {
		plan, found := coverage[planMember].(map[string]any)
		if !found {
			t.Fatalf("the coverage has no %s", planMember)
		}
		return plan
	}
	return map[string]func(coverage map[string]any){
		"a semantic field value changed": func(coverage map[string]any) {
			fields, stored := planOf(coverage)["semantic_fields"].([]any)
			if !stored {
				t.Fatalf("the plan's semantic field values are not in the document: %v", planOf(coverage)["semantic_fields"])
			}
			for _, field := range fields {
				if value := field.(map[string]any); value["name"] == numberField {
					value["number"] = json.Number("4611686018427387904")
					return
				}
			}
			t.Fatalf("the plan has no semantic field %s", numberField)
		},
		"the semantic fields removed": func(coverage map[string]any) { delete(planOf(coverage), "semantic_fields") },
		"the semantic fields emptied": func(coverage map[string]any) {
			emptied := map[string]any{}
			switch fields := planOf(coverage)["semantic_fields"].(type) {
			case []any:
				for _, field := range fields {
					emptied[field.(map[string]any)["name"].(string)] = map[string]any{}
				}
			case map[string]any:
				for name := range fields {
					emptied[name] = map[string]any{}
				}
			}
			planOf(coverage)["semantic_fields"] = emptied
		},
		"the writer fence given another generation": func(coverage map[string]any) {
			planOf(coverage)["writer_fence"].(map[string]any)["body"].(map[string]any)["writer_generation"] = json.Number("4611686018427387904")
		},
		"the canonical request changed": func(coverage map[string]any) {
			planOf(coverage)["canonical_request"] = "cmVsZWFzZS1zb21ldGhpbmctZWxzZQ=="
		},
	}
}

// tamperedTestExposureReleasePlan are the changes to a coverage holding an
// exposure-release plan that a load must refuse: the plan itself changed, or
// the terminal claim set or reservation it releases for.
func tamperedTestExposureReleasePlan(t *testing.T) map[string]func(coverage map[string]any) {
	t.Helper()
	tampered := tamperedTestPlanFields(t, "exposure_release_plan", "target_revision")
	tampered["the planned target revision changed"] = func(coverage map[string]any) {
		coverage["exposure_release_plan"].(map[string]any)["request_body"].(map[string]any)["target_portfolio_revision"] = json.Number("4611686018427387904")
	}
	tampered["the stored terminal claim set changed"] = func(coverage map[string]any) {
		coverage["terminal_claim_set"].(map[string]any)["body"].(map[string]any)["created_at_unix"] = json.Number("1")
	}
	tampered["the stored terminal claim set removed"] = func(coverage map[string]any) {
		delete(coverage, "terminal_claim_set")
	}
	tampered["the coverage's reservation changed"] = func(coverage map[string]any) {
		coverage["record"].(map[string]any)["reservation_id"] = "sha256:" + strings.Repeat("9", 64)
	}
	return tampered
}

// tamperedTestCoverageResolutionPlan are the changes to a coverage holding a
// coverage-resolution plan that a load must refuse: the plan itself changed,
// or the exposure release it resolves from.
func tamperedTestCoverageResolutionPlan(t *testing.T, otherTargetState string) map[string]func(coverage map[string]any) {
	t.Helper()
	tampered := tamperedTestPlanFields(t, "coverage_resolution_plan", "expected_state_revision")
	tampered["the planned target state changed"] = func(coverage map[string]any) {
		coverage["coverage_resolution_plan"].(map[string]any)["target_state"] = otherTargetState
	}
	tampered["the planned expected revision changed"] = func(coverage map[string]any) {
		coverage["coverage_resolution_plan"].(map[string]any)["request_body"].(map[string]any)["expected_coverage_revision"] = json.Number("4611686018427387904")
	}
	tampered["the stored exposure release changed"] = func(coverage map[string]any) {
		coverage["exposure_release_receipt"].(map[string]any)["body"].(map[string]any)["released_at_unix"] = json.Number("1")
	}
	tampered["the stored exposure release removed"] = func(coverage map[string]any) {
		delete(coverage, "exposure_release_receipt")
	}
	return tampered
}

// TestGuarantorJournalRefusesATamperedPlan: a journal whose stored plan was
// changed on disk, or no longer belongs to the receipts stored beside it, does
// not load. The same file written back unchanged loads.
func TestGuarantorJournalRefusesATamperedPlan(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	offerID := digest("7")
	journal, directory := openTestGuarantorJournal(t)
	position := testExpiredGuarantorOffer(offerID)
	rewriteTestGuarantorJournal(t, journal, func(doc *guarantorJournalDocument) { doc.Offers[offerID] = position })
	journal, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatal(err)
	}
	closeGuarantorJournalOnCleanup(t, journal)
	if _, err := journal.StoreOfferReleasePlan(offerID, testGuarantorOfferReleasePlan(t, position, 6)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	offerOf := func(t *testing.T, doc map[string]any) map[string]any {
		t.Helper()
		offer, found := doc["offers"].(map[string]any)[offerID].(map[string]any)
		if !found {
			t.Fatalf("the document has no offer %s", offerID)
		}
		return offer
	}
	planOf := func(t *testing.T, doc map[string]any) map[string]any {
		t.Helper()
		plan, found := offerOf(t, doc)["pre_acceptance_release_plan"].(map[string]any)
		if !found {
			t.Fatal("the document has no release plan")
		}
		return plan
	}
	// fieldsOf returns the plan's stored semantic fields, in their order.
	fieldsOf := func(t *testing.T, doc map[string]any) []any {
		t.Helper()
		fields, stored := planOf(t, doc)["semantic_fields"].([]any)
		if !stored || len(fields) != 5 {
			t.Fatalf("the plan's semantic field values are not in the document: %v", planOf(t, doc)["semantic_fields"])
		}
		return fields
	}
	for name, change := range map[string]func(t *testing.T, doc map[string]any){
		"a semantic field value changed": func(t *testing.T, doc map[string]any) {
			fieldsOf(t, doc)[3].(map[string]any)["number"] = json.Number("8")
		},
		"a semantic field's digest changed": func(t *testing.T, doc map[string]any) {
			fieldsOf(t, doc)[2].(map[string]any)["text"] = digest("b")
		},
		"a semantic field removed": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["semantic_fields"] = fieldsOf(t, doc)[:4]
		},
		"two semantic fields exchanged": func(t *testing.T, doc map[string]any) {
			fields := fieldsOf(t, doc)
			fields[0], fields[1] = fields[1], fields[0]
		},
		"a semantic field given another type": func(t *testing.T, doc map[string]any) {
			fieldsOf(t, doc)[0].(map[string]any)["type"] = "kind"
		},
		"the semantic fields removed": func(t *testing.T, doc map[string]any) {
			delete(planOf(t, doc), "semantic_fields")
		},
		"the semantic fields emptied": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["semantic_fields"] = map[string]any{"owner_id": map[string]any{}, "agent_id": map[string]any{},
				"reservation_id": map[string]any{}, "target_revision": map[string]any{},
				"terminal_evidence_set_digest": map[string]any{}}
		},
		"the stable action identity changed": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["authorized_action"].(map[string]any)["stable_action_id"] = digest("c")
		},
		"the action kind changed": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["authorized_action"].(map[string]any)["action_kind"] = "commercial.quote.close"
		},
		"the action given to another Agent": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["authorized_action"].(map[string]any)["agent_id"] = "agent:another"
		},
		"the canonical request changed": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["canonical_request"] = "cmVsZWFzZS1zb21ldGhpbmctZWxzZQ=="
		},
		"the base portfolio revision changed": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["base_portfolio_revision"] = json.Number("5")
		},
		"an unknown member added": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["released_exposure_atomic"] = "1"
		},
		"the stored non-acceptance evidence changed": func(t *testing.T, doc map[string]any) {
			body := offerOf(t, doc)["non_acceptance_evidence"].(map[string]any)["body"].(map[string]any)
			body["acceptance_admission_log_root"] = digest("d")
		},
		"the stored non-acceptance evidence removed": func(t *testing.T, doc map[string]any) {
			delete(offerOf(t, doc), "non_acceptance_evidence")
		},
		"the offer's reservation changed": func(t *testing.T, doc map[string]any) {
			offerOf(t, doc)["record"].(map[string]any)["reservation_id"] = digest("e")
		},
		"the offer no longer expired": func(t *testing.T, doc map[string]any) {
			offerOf(t, doc)["record"].(map[string]any)["status"] = string(guarantor.OfferIssued)
		},
	} {
		t.Run(name, func(t *testing.T) {
			editTestGuarantorJournalFile(t, directory, original, func(doc map[string]any) { change(t, doc) })
			if err := openTestGuarantorJournalErr(t, directory); err == nil {
				// The journal opened holds the process-wide domain lock.
				t.Error("a journal with a tampered plan was loaded")
			}
		})
	}
	editTestGuarantorJournalFile(t, directory, original, func(map[string]any) {})
	reopened, err := OpenGuarantorJournal(directory, "owner:guarantor", "agent:guarantor")
	if err != nil {
		t.Fatalf("the unchanged journal, written back the same way, was refused: %v", err)
	}
	closeGuarantorJournalOnCleanup(t, reopened)
	if got := storedTestOfferReleasePlan(t, reopened); !reflect.DeepEqual(got.Fields,
		testGuarantorOfferReleasePlan(t, position, 6).Fields) {
		t.Fatalf("the unchanged journal loaded other semantic fields: %#v", got.Fields)
	}
}
