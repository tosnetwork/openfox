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

// TestSameJSONFailsClosed: two values that cannot be encoded are not the same,
// and neither is such a value and one that can be.
func TestSameJSONFailsClosed(t *testing.T) {
	unencodable := func() {}
	if sameJSON(unencodable, unencodable) {
		t.Fatal("two values that cannot be encoded compared as the same")
	}
	if sameJSON(unencodable, nil) || sameJSON(nil, unencodable) {
		t.Fatal("a value that cannot be encoded compared as the same as one that can")
	}
	if !sameJSON(map[string]uint64{"a": 1}, map[string]uint64{"a": 1}) || sameJSON(uint64(1), uint64(2)) {
		t.Fatal("sameJSON does not compare encodings")
	}
}

// nextTestWriterGeneration is action and fence moved to the next writer
// generation, as a takeover reauthorizes them.
func nextTestWriterGeneration(action commerce.AuthorizedAction, fence commerce.WriterFence) (commerce.AuthorizedAction,
	commerce.WriterFence) {
	action.WriterGeneration++
	fence.Body.WriterGeneration = action.WriterGeneration
	return action, fence
}

// requireExposureReleaseReauthorizationRefusesAChangedPlan reauthorizes the
// stored exposure-release plan of agreementDigest with a semantic field
// changed and with the request changed. Both name the stored action under a
// newer writer generation, as a takeover does; neither may be stored.
func requireExposureReleaseReauthorizationRefusesAChangedPlan(t *testing.T, journal *GuarantorJournal,
	agreementDigest string) {
	t.Helper()
	revision, stored := storedTestCoveragePosition(t, journal, agreementDigest)
	if stored.ExposureReleasePlan == nil {
		t.Fatal("the coverage holds no exposure-release plan")
	}
	// Each changed plan is made from its own private copy of the position.
	_, first := storedTestCoveragePosition(t, journal, agreementDigest)
	changedField := *first.ExposureReleasePlan
	changedField.Action, changedField.WriterFence = nextTestWriterGeneration(changedField.Action, changedField.WriterFence)
	changedField.Fields["target_revision"] = commerce.U64(changedField.RequestBody.TargetPortfolioRevision + 1)
	if _, err := journal.ReauthorizeExposureReleasePlan(agreementDigest, changedField); err == nil {
		t.Error("an exposure-release plan was reauthorized with a changed semantic field")
	}
	_, again := storedTestCoveragePosition(t, journal, agreementDigest)
	changedRequest := *again.ExposureReleasePlan
	changedRequest.Action, changedRequest.WriterFence = nextTestWriterGeneration(changedRequest.Action, changedRequest.WriterFence)
	changedRequest.RequestBody.TargetPortfolioRevision++
	request, err := guarantor.Canonical(changedRequest.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	changedRequest.CanonicalRequest = request
	if _, err := journal.ReauthorizeExposureReleasePlan(agreementDigest, changedRequest); err == nil {
		t.Error("an exposure-release plan was reauthorized with a changed request")
	}
	requireTestCoveragePositionUnchanged(t, journal, agreementDigest, revision, stored)
}

// requireCoverageResolutionReauthorizationRefusesAChangedPlan is the same for
// the stored coverage-resolution plan of agreementDigest.
func requireCoverageResolutionReauthorizationRefusesAChangedPlan(t *testing.T, journal *GuarantorJournal,
	agreementDigest string) {
	t.Helper()
	revision, stored := storedTestCoveragePosition(t, journal, agreementDigest)
	if stored.CoverageResolutionPlan == nil {
		t.Fatal("the coverage holds no coverage-resolution plan")
	}
	// Each changed plan is made from its own private copy of the position.
	_, first := storedTestCoveragePosition(t, journal, agreementDigest)
	changedField := *first.CoverageResolutionPlan
	changedField.Action, changedField.WriterFence = nextTestWriterGeneration(changedField.Action, changedField.WriterFence)
	changedField.Fields["expected_state_revision"] = commerce.U64(changedField.RequestBody.ExpectedRevision + 1)
	if _, err := journal.ReauthorizeCoverageResolutionPlan(agreementDigest, changedField); err == nil {
		t.Error("a coverage-resolution plan was reauthorized with a changed semantic field")
	}
	_, again := storedTestCoveragePosition(t, journal, agreementDigest)
	changedRequest := *again.CoverageResolutionPlan
	changedRequest.Action, changedRequest.WriterFence = nextTestWriterGeneration(changedRequest.Action, changedRequest.WriterFence)
	changedRequest.RequestBody.ExpectedRevision++
	changedRequest.RequestBody.TargetRevision++
	request, err := guarantor.Canonical(changedRequest.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	changedRequest.CanonicalRequest = request
	if _, err := journal.ReauthorizeCoverageResolutionPlan(agreementDigest, changedRequest); err == nil {
		t.Error("a coverage-resolution plan was reauthorized with a changed request")
	}
	requireTestCoveragePositionUnchanged(t, journal, agreementDigest, revision, stored)
}

// storedTestCoveragePosition returns the journal's revision and a private copy
// of the coverage position of agreementDigest.
func storedTestCoveragePosition(t *testing.T, journal *GuarantorJournal, agreementDigest string) (uint64,
	GuarantorCoveragePosition) {
	t.Helper()
	revision, _, coverages := journal.Snapshot()
	for _, coverage := range coverages {
		if coverage.Record.CoverageAgreementBodyDigest == agreementDigest {
			return revision, coverage
		}
	}
	t.Fatalf("the journal holds no coverage %s", agreementDigest)
	return 0, GuarantorCoveragePosition{}
}

// requireTestCoveragePositionUnchanged fails unless the journal is still at
// revision and holds want for agreementDigest.
func requireTestCoveragePositionUnchanged(t *testing.T, journal *GuarantorJournal, agreementDigest string,
	revision uint64, want GuarantorCoveragePosition) {
	t.Helper()
	gotRevision, got := storedTestCoveragePosition(t, journal, agreementDigest)
	if gotRevision != revision || !sameJSON(got, want) {
		t.Errorf("a refused reauthorization changed the journal: revision %d, want %d", gotRevision, revision)
	}
}

// tamperedTestFirmOfferIssuancePlan are the changes to a document holding one
// firm-offer issuance plan that a load must refuse: each changes what a resume
// would reserve or record, and each differs from what the plan's own offer
// derives.
func tamperedTestFirmOfferIssuancePlan(t *testing.T) map[string]func(doc map[string]any) {
	t.Helper()
	planOf := func(doc map[string]any) map[string]any {
		plans, found := doc["firm_offer_issuance_plans"].(map[string]any)
		if !found || len(plans) != 1 {
			t.Fatalf("the document does not hold exactly one firm-offer issuance plan: %v", doc["firm_offer_issuance_plans"])
		}
		for _, plan := range plans {
			return plan.(map[string]any)
		}
		return nil
	}
	member := func(name string) func(doc map[string]any) map[string]any {
		return func(doc map[string]any) map[string]any {
			value, found := planOf(doc)[name].(map[string]any)
			if !found {
				t.Fatalf("the firm-offer issuance plan has no %s", name)
			}
			return value
		}
	}
	position, reservation, action := member("position"), member("reservation"), member("authorized_action")
	other := "sha256:" + strings.Repeat("9", 64)
	return map[string]func(doc map[string]any){
		"the position's gross exposure changed": func(doc map[string]any) { position(doc)["gross_exposure_atomic"] = "1" },
		"the position's net exposure changed":   func(doc map[string]any) { position(doc)["net_exposure_atomic"] = "1" },
		"the position's accept-by changed": func(doc map[string]any) {
			position(doc)["accept_by_unix"] = json.Number("4000000000")
		},
		"the position's reservation expiry changed": func(doc map[string]any) {
			position(doc)["reservation_expires_at_unix"] = json.Number("4000000001")
		},
		"the position's covered party changed": func(doc map[string]any) {
			position(doc)["covered_party_agent_id"] = "agent:another"
		},
		"the position's quote request changed": func(doc map[string]any) { position(doc)["quote_request_digest"] = other },
		"the position's coverage asset changed": func(doc map[string]any) {
			position(doc)["coverage_asset"].(map[string]any)["asset_identifier"] = "another-asset"
		},
		"the position's record given another evidence digest": func(doc map[string]any) {
			position(doc)["record"].(map[string]any)["last_evidence_digest"] = other
		},
		"the position's record given another agreement": func(doc map[string]any) {
			position(doc)["record"].(map[string]any)["agreement_digest"] = other
		},
		"the position's record already issued": func(doc map[string]any) {
			position(doc)["record"].(map[string]any)["status"] = string(guarantor.OfferIssued)
		},
		"the reservation's maximum loss changed": func(doc map[string]any) {
			reservation(doc)["maximum_loss_atomic"] = json.Number("1")
		},
		"the reservation's agreement changed": func(doc map[string]any) { reservation(doc)["agreement_digest"] = other },
		"the reservation already released":    func(doc map[string]any) { reservation(doc)["released"] = true },
		"the reservation's asset removed":     func(doc map[string]any) { delete(reservation(doc), "asset") },
		"the admission domain changed":        func(doc map[string]any) { planOf(doc)["admission_domain_id"] = other },
		"the action's policy revision changed": func(doc map[string]any) {
			action(doc)["policy_revision"] = json.Number("99")
		},
		"the action's expiry changed": func(doc map[string]any) {
			action(doc)["expires_at_unix"] = json.Number("4000000002")
		},
	}
}

// restartTestGuarantorJournalHoldingAFirmOfferPlan restarts journal while it
// holds exactly one firm-offer issuance plan: every tampered document is
// refused, and the journal opened from disk holds the plan as it was stored.
func restartTestGuarantorJournalHoldingAFirmOfferPlan(t *testing.T, journal *GuarantorJournal,
	directory string) *GuarantorJournal {
	t.Helper()
	journal.mu.Lock()
	identities := make([]string, 0, len(journal.doc.FirmOfferIssuancePlans))
	for identity := range journal.doc.FirmOfferIssuancePlans {
		identities = append(identities, identity)
	}
	journal.mu.Unlock()
	if len(identities) != 1 {
		t.Fatalf("the journal holds %d firm-offer issuance plans, want one", len(identities))
	}
	stored, found := journal.FirmOfferIssuancePlan(identities[0])
	if !found {
		t.Fatal("the journal does not return its firm-offer issuance plan")
	}
	journal = restartTestGuarantorJournalDocuments(t, journal, directory, tamperedTestFirmOfferIssuancePlan(t))
	loaded, found := journal.FirmOfferIssuancePlan(identities[0])
	if !found {
		t.Fatal("the journal opened from disk holds no firm-offer issuance plan")
	}
	if !reflect.DeepEqual(loaded.Fields, stored.Fields) || !sameJSON(loaded, stored) {
		t.Fatalf("the firm-offer issuance plan loaded from disk is %#v, want %#v", loaded, stored)
	}
	return journal
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

// TestGuarantorJournalStoresOnlyAPlanItWouldLoad: a plan is checked when it is
// stored exactly as it is when the journal loads, so a plan a restart would
// refuse never reaches the document.
func TestGuarantorJournalStoresOnlyAPlanItWouldLoad(t *testing.T) {
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
	before, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(plan *GuarantorPreAcceptanceReleasePlan){
		"a semantic field that does not derive the stable action identity": func(plan *GuarantorPreAcceptanceReleasePlan) {
			plan.Fields["target_revision"] = commerce.U64(9)
		},
		"a semantic field missing": func(plan *GuarantorPreAcceptanceReleasePlan) {
			delete(plan.Fields, "reservation_id")
		},
		"no semantic fields": func(plan *GuarantorPreAcceptanceReleasePlan) { plan.Fields = nil },
		"another offer's reservation": func(plan *GuarantorPreAcceptanceReleasePlan) {
			other := testExpiredGuarantorOffer(offerID)
			other.Record.ReservationID = digest("b")
			*plan = testGuarantorOfferReleasePlan(t, other, 6)
		},
		"other non-acceptance evidence": func(plan *GuarantorPreAcceptanceReleasePlan) {
			other := testExpiredGuarantorOffer(offerID)
			other.NonAcceptanceEvidence.Body.AcceptanceAdmissionLogRoot = digest("c")
			*plan = testGuarantorOfferReleasePlan(t, other, 6)
		},
		"a request of another digest": func(plan *GuarantorPreAcceptanceReleasePlan) {
			plan.CanonicalRequest = []byte("another-request")
		},
		"an overflowing target revision": func(plan *GuarantorPreAcceptanceReleasePlan) {
			*plan = testGuarantorOfferReleasePlan(t, position, ^uint64(0))
		},
		"another owner's action": func(plan *GuarantorPreAcceptanceReleasePlan) { plan.Action.OwnerID = "owner:another" },
		"a request body that is not its canonical request": func(plan *GuarantorPreAcceptanceReleasePlan) {
			plan.RequestBody.ReleaseVariant = "post_acceptance"
		},
	} {
		plan := testGuarantorOfferReleasePlan(t, position, 6)
		change(&plan)
		if _, err := journal.StoreOfferReleasePlan(offerID, plan); err == nil {
			t.Fatalf("a release plan with %s was stored", name)
		}
	}
	after, err := os.ReadFile(filepath.Join(directory, guarantorJournalFile))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("a refused plan changed the document: %v", err)
	}
	stored := testGuarantorOfferReleasePlan(t, position, 6)
	if _, err := journal.StoreOfferReleasePlan(offerID, stored); err != nil {
		t.Fatalf("store the valid release plan: %v", err)
	}
	// A reauthorized action must keep the plan one the journal would load.
	otherOwner := stored.Action
	otherOwner.WriterGeneration, otherOwner.OwnerID = 2, "owner:another"
	if _, err := journal.RefreshOfferReleasePlanAction(offerID, otherOwner); err == nil {
		t.Fatal("a release plan was reauthorized with another owner's action")
	}
	journal = reopenTestGuarantorJournal(t, journal, directory)
	if got := storedTestOfferReleasePlan(t, journal); !reflect.DeepEqual(got.Fields, stored.Fields) ||
		got.Action.OwnerID != "owner:guarantor" {
		t.Fatalf("the journal loaded another plan than the one stored: %#v", got)
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
	documents := make(map[string]func(doc map[string]any), len(tampered))
	for name, change := range tampered {
		documents[name] = func(doc map[string]any) {
			coverage, found := doc["coverages"].(map[string]any)[agreementDigest].(map[string]any)
			if !found {
				t.Fatalf("the document has no coverage %s", agreementDigest)
			}
			change(coverage)
		}
	}
	return restartTestGuarantorJournalDocuments(t, journal, directory, documents)
}

// restartTestGuarantorJournalDocuments is restartTestGuarantorJournal for
// changes made anywhere in the document.
func restartTestGuarantorJournalDocuments(t *testing.T, journal *GuarantorJournal, directory string,
	tampered map[string]func(doc map[string]any)) *GuarantorJournal {
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
		editTestGuarantorJournalFile(t, directory, original, change)
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
		// The request body is what a resume reads; it must be the request the
		// action's digest covers.
		"the request body's release variant changed": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["request_body"].(map[string]any)["release_variant"] = "post_acceptance"
		},
		"the offer released with no release receipt": func(t *testing.T, doc map[string]any) {
			offerOf(t, doc)["record"].(map[string]any)["status"] = string(guarantor.OfferReleased)
		},
		"the offer stored under another key": func(t *testing.T, doc map[string]any) {
			offers := doc["offers"].(map[string]any)
			offers[digest("f")] = offerOf(t, doc)
			delete(offers, offerID)
		},
		// Decoding matches a member name in any letter case, so each of these
		// would otherwise decode as the member it resembles.
		"a plan member renamed to another letter case": func(t *testing.T, doc map[string]any) {
			plan := planOf(t, doc)
			plan["Released_At_Unix"] = plan["released_at_unix"]
			delete(plan, "released_at_unix")
		},
		"a plan member added whose name differs only in case": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["Released_At_Unix"] = json.Number("1")
		},
		"a second semantic-fields member differing in case": func(t *testing.T, doc map[string]any) {
			planOf(t, doc)["Semantic_Fields"] = map[string]any{}
		},
		"an offer member renamed to another letter case": func(t *testing.T, doc map[string]any) {
			offer := offerOf(t, doc)
			offer["Accept_By_Unix"] = offer["accept_by_unix"]
			delete(offer, "accept_by_unix")
		},
		"a document member renamed to another letter case": func(t *testing.T, doc map[string]any) {
			doc["Revision"] = doc["revision"]
			delete(doc, "revision")
		},
		"a record member renamed to another letter case": func(t *testing.T, doc map[string]any) {
			record := offerOf(t, doc)["record"].(map[string]any)
			record["State_Revision"] = record["state_revision"]
			delete(record, "state_revision")
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
	// A member written twice cannot be expressed through a decoded document, so
	// these are made in the bytes. Decoding keeps the last of the two; the
	// first is the changed one, so each of these documents decodes to exactly
	// the original.
	insertBefore := func(t *testing.T, member, duplicate string) []byte {
		t.Helper()
		if bytes.Count(original, []byte(member)) != 1 {
			t.Fatalf("the document does not hold %s exactly once", member)
		}
		return bytes.Replace(original, []byte(member), []byte(duplicate+member), 1)
	}
	for name, edited := range map[string][]byte{
		"two offers members in the document":       insertBefore(t, `"offers":`, `"offers":{},`),
		"two revision members in the document":     insertBefore(t, `"revision":`, `"revision":1,`),
		"two release plans in one offer":           insertBefore(t, `"pre_acceptance_release_plan":`, `"pre_acceptance_release_plan":null,`),
		"two records in one offer":                 insertBefore(t, `"record":`, `"record":{"offer_id":"`+offerID+`","status":"issued","state_revision":1},`),
		"two release times in one plan":            insertBefore(t, `"released_at_unix":`, `"released_at_unix":1,`),
		"two offers of one identity in the offers": insertBefore(t, `"`+offerID+`":{`, `"`+offerID+`":null,`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(directory, guarantorJournalFile), edited, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := openTestGuarantorJournalErr(t, directory); err == nil {
				t.Error("a journal with a member written twice was loaded")
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
