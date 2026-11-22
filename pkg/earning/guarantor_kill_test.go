package earning

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

// The kill test runs the provider coordinator in processes of this test
// binary and kills one of them, with SIGKILL, at a chosen point of a
// coordinator call. A fresh process then opens what the killed one left and
// repeats the call. Nothing in the coordinator is replaced by a double that
// returns an error where a crash would have happened: the process is gone,
// with whatever it had written, and the next one has only the disk.
//
// A process is this binary run with -test.run=TestGuarantorKillProcess and
// the variables below. The kill points are reached through two things a test
// already controls, neither of them a seam of the shipped code: the
// coordinator's Authority is an interface, wrapped here to stop around a
// terminal transition, and the journal's file writer is the field its own
// tests replace, wrapped here to stop inside or after a document write.
const (
	guarantorKillDirectoryEnv = "OPENFOX_GUARANTOR_KILL_DIRECTORY"
	guarantorKillNowEnv       = "OPENFOX_GUARANTOR_KILL_NOW"
	guarantorKillOrdinalEnv   = "OPENFOX_GUARANTOR_KILL_ORDINAL"
	guarantorKillStepsEnv     = "OPENFOX_GUARANTOR_KILL_STEPS"
	guarantorKillPointEnv     = "OPENFOX_GUARANTOR_KILL_POINT"
	// guarantorKillReached is the line a process prints when it has reached
	// its kill point and waits to be killed.
	guarantorKillReached = "guarantor kill point reached"
	// guarantorKillResultsFile holds what a process that ran to its end
	// returned from each step.
	guarantorKillResultsFile = "kill-test-results.json"
)

// guarantorKillSteps are the coordinator calls a process makes, in order. A
// process runs the first n of them; the ones an earlier process completed are
// repeated and must return what that process committed.
var guarantorKillSteps = []string{"issue", "accept", "activate", "claim"}

// guarantorKillEntropy is a deterministic entropy source: SHA-256 in counter
// mode over a seed. A process of the kill test reads from it wherever the
// coordinator reads crypto/rand, so that two processes with the same history
// produce the same bytes: the same keys, and the same lease in the writer
// fence the authority issues, which every receipt carries.
type guarantorKillEntropy struct {
	mu      sync.Mutex
	seed    [sha256.Size]byte
	counter uint64
	buffer  []byte
}

func newGuarantorKillEntropy(label string) *guarantorKillEntropy {
	return &guarantorKillEntropy{seed: sha256.Sum256([]byte("openfox guarantor kill test entropy: " + label))}
}

func (entropy *guarantorKillEntropy) Read(output []byte) (int, error) {
	entropy.mu.Lock()
	defer entropy.mu.Unlock()
	for index := range output {
		if len(entropy.buffer) == 0 {
			var block [sha256.Size + 8]byte
			copy(block[:], entropy.seed[:])
			binary.BigEndian.PutUint64(block[sha256.Size:], entropy.counter)
			entropy.counter++
			sum := sha256.Sum256(block[:])
			entropy.buffer = sum[:]
		}
		output[index] = entropy.buffer[0]
		entropy.buffer = entropy.buffer[1:]
	}
	return len(output), nil
}

// guarantorKillProcess is one process of the kill test.
type guarantorKillProcess struct {
	// directory holds the authority and the journal, as earlier processes
	// left them.
	directory string
	// now is the test's logical time; every process of one test shares it.
	now time.Time
	// ordinal counts the processes started on directory, from 1.
	ordinal int
	// steps is how many of guarantorKillSteps the process runs.
	steps int
	// point is where the process stops and waits to be killed, inside its
	// last step: empty to run to the end, or "kind:n" for the n-th event of a
	// kind. The kinds are before-terminal and after-terminal, around the
	// authority's transition of an action to terminal, and during-write and
	// after-write, inside and after a write of the journal document.
	point string
}

// keysGenerated switches the process from the entropy all processes share to
// its own, named by its ordinal.
func (process *guarantorKillProcess) keysGenerated() {
	rand.Reader = newGuarantorKillEntropy("process " + strconv.Itoa(process.ordinal))
}

// guarantorKillFixture is what the provider lifecycle built for a process.
type guarantorKillFixture struct {
	now                time.Time
	coordinator        *GuarantorProviderCoordinator
	authority          *PersonalAuthority
	fence              commerce.WriterFence
	issueInput         GuarantorIssueOfferInput
	agreement          commerce.AgentAgreementBody
	agreementDigest    string
	underlying         commerce.AgentAgreementBody
	underlyingDigest   string
	underlyingResolver guarantor.UnderlyingAgreementResolver
	agreementVerifier  commerce.AgreementEvidenceVerifier
	coveredKey         ed25519.PrivateKey
	guarantorKey       ed25519.PrivateKey
	terms              guarantor.CoverageTermsV1
	asset              commerce.AssetIdentityV1
	destinationDigest  string
	evidenceProfile    commerce.ProfileRefV1
}

// guarantorKillHooks stops the process at its kill point.
type guarantorKillHooks struct {
	kind  string
	count int
	// armed is set while the process runs the step its point belongs to.
	armed bool
	seen  int
}

// due counts one event of kind and reports whether it is the kill point.
func (hooks *guarantorKillHooks) due(kind string) bool {
	if !hooks.armed || hooks.kind != kind {
		return false
	}
	hooks.seen++
	return hooks.seen == hooks.count
}

// stop reports the kill point to the parent and waits to be killed. It never
// returns: the parent kills the process, and a process nobody kills is ended
// by its own test timeout.
func (hooks *guarantorKillHooks) stop() {
	fmt.Fprintln(os.Stdout, guarantorKillReached)
	_ = os.Stdout.Sync()
	for {
		time.Sleep(time.Hour)
	}
}

// guarantorKillAuthority is the real authority with a stop before and after
// it makes an action terminal.
type guarantorKillAuthority struct {
	EconomicAuthority
	hooks *guarantorKillHooks
}

func (authority *guarantorKillAuthority) Transition(
	stableActionID, exactRequestDigest string, state commerce.ActionResolutionState, sinkReference string,
	evidenceRefs []string,
) (commerce.ActionResolution, error) {
	if state == commerce.ActionTerminal && authority.hooks.due("before-terminal") {
		authority.hooks.stop()
	}
	resolution, err := authority.EconomicAuthority.Transition(stableActionID, exactRequestDigest, state, sinkReference,
		evidenceRefs)
	if err == nil && state == commerce.ActionTerminal && authority.hooks.due("after-terminal") {
		authority.hooks.stop()
	}
	return resolution, err
}

// install puts the stops inside and after a document write in front of the
// journal's file writer. The stop inside a write does what an atomic write
// does before its rename, with the same temporary name, and goes no further:
// the temporary file is complete on disk and the document is the old one.
func (hooks *guarantorKillHooks) install(journal *GuarantorJournal) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	underneath := journal.writeFile
	journal.writeFile = func(root *os.Root, name string, data []byte, perm os.FileMode) error {
		if name != guarantorJournalFile {
			return underneath(root, name, data, perm)
		}
		if hooks.due("during-write") {
			file, _, err := fileutil.CreateTemporaryFileRoot(root, ".", perm)
			if err == nil {
				_, err = file.Write(data)
			}
			if err == nil {
				err = file.Sync()
			}
			if err != nil {
				return fmt.Errorf("write the temporary file of the kill point: %w", err)
			}
			hooks.stop()
		}
		err := underneath(root, name, data, perm)
		if err == nil && hooks.due("after-write") {
			hooks.stop()
		}
		return err
	}
}

// TestGuarantorKillProcess is one process of
// TestGuarantorCoordinatorResumesAfterBeingKilled. Run by itself it does
// nothing.
func TestGuarantorKillProcess(t *testing.T) {
	directory := os.Getenv(guarantorKillDirectoryEnv)
	if directory == "" {
		t.Skip("a process of TestGuarantorCoordinatorResumesAfterBeingKilled; it does nothing by itself")
	}
	nowUnix, nowErr := strconv.ParseInt(os.Getenv(guarantorKillNowEnv), 10, 64)
	ordinal, ordinalErr := strconv.Atoi(os.Getenv(guarantorKillOrdinalEnv))
	steps, stepsErr := strconv.Atoi(os.Getenv(guarantorKillStepsEnv))
	if nowErr != nil || ordinalErr != nil || stepsErr != nil || nowUnix <= 0 || ordinal <= 0 || steps < 0 ||
		steps > len(guarantorKillSteps) {
		t.Fatalf("the kill test process is misconfigured: now=%v ordinal=%v steps=%v", nowErr, ordinalErr, stepsErr)
	}
	// Every process generates the same keys.
	rand.Reader = newGuarantorKillEntropy("keys")
	runGuarantorProviderLifecycleIn(t, guarantorNoFallback, &guarantorKillProcess{
		directory: directory, now: time.Unix(nowUnix, 0).UTC(), ordinal: ordinal, steps: steps,
		point: os.Getenv(guarantorKillPointEnv),
	})
}

// drive makes the process's coordinator calls on the fixture, stops at its
// kill point if it has one, and otherwise writes what each call returned.
func (process *guarantorKillProcess) drive(t *testing.T, fixture guarantorKillFixture) {
	t.Helper()
	hooks := &guarantorKillHooks{}
	if process.point != "" {
		kind, count, found := strings.Cut(process.point, ":")
		number, err := strconv.Atoi(count)
		if !found || err != nil || number <= 0 || process.steps == 0 {
			t.Fatalf("the kill point %q is not kind:n inside a step", process.point)
		}
		hooks.kind, hooks.count = kind, number
	}
	coordinator, authority, fence := fixture.coordinator, fixture.authority, fixture.fence
	coordinator.Authority = &guarantorKillAuthority{EconomicAuthority: coordinator.Authority, hooks: hooks}
	hooks.install(coordinator.Journal)
	ctx := context.Background()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	// at moves the authority's clock to the logical time of a step.
	at := func(offset time.Duration) time.Time {
		instant := fixture.now.Add(offset)
		authority.now = func() time.Time { return instant }
		return instant
	}
	results := map[string]string{}
	var offer guarantor.AuthorizedFirmCoverageOfferV1
	var acceptance guarantor.AuthorizedCoverageAcceptanceReceiptV1
	steps := map[string]func(){
		"issue": func() {
			at(0)
			issued, resolution, err := coordinator.IssueFirmOffer(ctx, fixture.issueInput, fence)
			if err != nil || resolution.State != commerce.ActionTerminal {
				t.Fatalf("issue the firm offer: state=%s err=%v", resolution.State, err)
			}
			offer = issued
			results["offer"], _ = guarantor.FirmOfferDigest(issued)
			results["offer writer generation"] = strconv.FormatUint(
				issued.ExposureAdmissionReceipt.Body.WriterGeneration, 10)
		},
		"accept": func() {
			receivedAt := at(time.Minute)
			keys := map[string]ed25519.PrivateKey{
				"agent:covered": fixture.coveredKey, "agent:guarantor": fixture.guarantorKey,
			}
			profile := commerce.ProfileRefV1{
				ProfileURI: commerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
				ProfileDigest: commerce.AgentSignatureProfileDigest(),
			}
			request := signGuarantorTestAcceptance(t, fixture.agreement, offer, "agent:covered", keys, profile,
				fixture.underlyingResolver, fixture.agreementVerifier, receivedAt, fixture.now.Add(4*time.Minute))
			receipt, resolution, err := coordinator.AcceptCoverage(ctx, GuarantorAcceptCoverageInput{
				Offer: offer, Request: request, CoverageObligationID: "obligation:coverage",
				ReceivedAtUnix: uint64(receivedAt.Unix()),
			}, fence)
			if err != nil || resolution.State != commerce.ActionTerminal {
				t.Fatalf("accept the coverage: state=%s err=%v", resolution.State, err)
			}
			acceptance = receipt
			results["acceptance"], _ = guarantor.CoverageAcceptanceReceiptDigestV1(receipt)
			results["acceptance writer generation"] = strconv.FormatUint(receipt.Body.WriterGeneration, 10)
		},
		"activate": func() {
			activatedAt := at(2 * time.Minute)
			underlying := fixture.underlying
			predicate := underlying.AuthorizationPredicates[0]
			accepted, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
				AgreementID: underlying.AgreementID, AgreementVersion: underlying.Version,
				AgreementBodyDigest: fixture.underlyingDigest, AcceptingSubject: predicate.AuthoritySubject,
				PredicateIDs:                    []string{predicate.PredicateID},
				EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
				ExpiresAtUnix:                   underlying.ExpiresAtUnix,
			}, fixture.coveredKey)
			if err != nil {
				t.Fatal(err)
			}
			underlyingEvidence, err := commerce.AgentSignatureEvidence(underlying, accepted)
			if err != nil {
				t.Fatal(err)
			}
			prerequisites := guarantor.CanonicalGuarantorEvidenceSetV1{
				SchemaVersion: 1, Purpose: "coverage-activation", ContextDigest: fixture.agreementDigest,
				Items: []guarantor.CanonicalGuarantorEvidenceItemV1{{
					ContentType: "application/cbor", EvidenceProfileDigest: digest("6"),
					EvidenceEnvelopeDigest: digest("7"), Representation: "inline",
					CanonicalEnvelopeBytes: []byte("finalized-premium-payment-evidence"),
				}},
			}
			activation, resolution, err := coordinator.ActivateCoverage(ctx, GuarantorActivateCoverageInput{
				Offer: offer, AcceptanceReceipt: acceptance, UnderlyingAgreement: underlying,
				UnderlyingAuthorizationEvidence: guarantor.GuarantorAgreementAuthorizationEvidenceSetV1{
					SchemaVersion: 1, AgreementID: underlying.AgreementID, AgreementVersion: underlying.Version,
					AgreementBodyDigest: fixture.underlyingDigest,
					Evidence:            []commerce.AgreementAuthorizationEvidence{underlyingEvidence},
				},
				PrerequisiteEvidenceSet: &prerequisites, ActivatedAtUnix: uint64(activatedAt.Unix()),
			}, fence)
			if err != nil || resolution.State != commerce.ActionTerminal {
				t.Fatalf("activate the coverage: state=%s err=%v", resolution.State, err)
			}
			results["activation"], _ = guarantor.CoverageActivationEvidenceDigestV1(activation)
			results["activation writer generation"] = strconv.FormatUint(activation.Body.WriterGeneration, 10)
		},
		"claim": func() {
			at(4 * time.Minute)
			claim := signGuarantorKillTestClaim(t, fixture, digest)
			admitted, err := coordinator.AdmitClaim(ctx, fixture.agreementDigest, claim, fence)
			if err != nil || admitted.IngressResolution.State != commerce.ActionTerminal ||
				admitted.AdmissionResolution.State != commerce.ActionTerminal {
				t.Fatalf("admit the claim: ingress=%s admission=%s err=%v", admitted.IngressResolution.State,
					admitted.AdmissionResolution.State, err)
			}
			results["claim ingress"], _ = guarantor.ClaimIngressReceiptDigestV1(admitted.IngressReceipt)
			results["claim admission"], _ = guarantor.ClaimAdmissionReceiptDigestV1(admitted.AdmissionReceipt)
			results["claim ingress writer generation"] = strconv.FormatUint(
				admitted.IngressReceipt.Body.WriterGeneration, 10)
			results["claim admission writer generation"] = strconv.FormatUint(
				admitted.AdmissionReceipt.Body.WriterGeneration, 10)
		},
	}
	for index := 0; index < process.steps; index++ {
		hooks.armed, hooks.seen = hooks.kind != "" && index == process.steps-1, 0
		steps[guarantorKillSteps[index]]()
	}
	if process.point != "" {
		t.Fatalf("the process ran %d steps to the end without reaching its kill point %s", process.steps,
			process.point)
	}
	for name, value := range results {
		if value == "" {
			t.Fatalf("the result %q of the process is empty", name)
		}
	}
	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(process.directory, guarantorKillResultsFile), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// signGuarantorKillTestClaim is the lifecycle's first claim, signed by the
// covered party at the fixture's logical time.
func signGuarantorKillTestClaim(t *testing.T, fixture guarantorKillFixture, digest func(string) string,
) guarantor.AuthorizedCoverageClaimV1 {
	t.Helper()
	now, terms := fixture.now, fixture.terms
	manifest := guarantor.ClaimEvidenceManifestV1{
		SchemaVersion: 1, TotalDeclaredBytes: 64,
		Items: []guarantor.ClaimEvidenceDescriptorV1{{
			PredicateID: "evidence:failure", EvidenceProfile: fixture.evidenceProfile, ContentType: "application/json",
			ContentDigest: digest("a"), ContentSize: 64, DisclosurePolicyDigest: digest("b"),
		}},
	}
	manifestDigest, err := guarantor.ValidateClaimEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	incidentDigest := digest("c")
	recovery := guarantor.OtherRecoveryDeclarationV1{
		SchemaVersion: 1, CoverageAgreementBodyDigest: fixture.agreementDigest,
		CoverageObligationID: "obligation:coverage", UnderlyingAgreementBodyDigest: fixture.underlyingDigest,
		ClaimRevision: 1, BeneficiaryAgentID: "agent:covered", IncidentKeyDigest: incidentDigest,
		CoverageAsset: fixture.asset, DeclaredAtUnix: uint64(now.Add(3 * time.Minute).Unix()),
	}
	recoveryDigest, err := guarantor.ValidateOtherRecoveryDeclaration(recovery, manifest)
	if err != nil {
		t.Fatal(err)
	}
	triggered := guarantor.TriggeredObligationSetV1{
		SchemaVersion: 1, UnderlyingAgreementBodyDigest: fixture.underlyingDigest,
		ObligationIDs: []string{"obligation:work"},
	}
	triggeredDigest, err := guarantor.TriggeredObligationSetDigestV1(triggered)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := guarantor.ClaimID(fixture.agreementDigest, "obligation:coverage", incidentDigest, "agent:covered",
		triggeredDigest)
	if err != nil {
		t.Fatal(err)
	}
	profile := terms.ClaimantAuthorizationProfiles[0]
	body := guarantor.CoverageClaimBodyV1{
		SchemaVersion: 1, ClaimID: claimID, ClaimRevision: 1,
		CoverageAgreementBodyDigest: fixture.agreementDigest, CoverageObligationID: "obligation:coverage",
		UnderlyingAgreementBodyDigest: fixture.underlyingDigest, TriggeredObligationSet: triggered,
		ClaimantSubject: "agent:covered", ClaimantAuthorizationProfile: profile,
		BeneficiaryAgentID: "agent:covered", IncidentKeyDigest: incidentDigest,
		OccurredAtUnix:         uint64(now.Add(2 * time.Minute).Unix()),
		ClaimedAmount:          commerce.AtomicAmountV1{Asset: fixture.asset, AmountAtomic: "400"},
		EvidenceManifestDigest: manifestDigest, OtherRecoveryDeclarationDigest: recoveryDigest,
		PayoutDestinationDigest: fixture.destinationDigest,
		CreatedAtUnix:           uint64(now.Add(3 * time.Minute).Unix()),
		ExpiresAtUnix:           uint64(now.Add(10 * time.Minute).Unix()),
	}
	bodyDigest, err := guarantor.ClaimBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := guarantor.SignObjectAuthorization(context.Background(), guarantor.AuthorizationStatementV1{
		SchemaVersion: 1, AuthoritySubject: "agent:covered", ProfileURI: profile.ProfileURI,
		ProfileVersion: profile.ProfileVersion, ProfileDigest: profile.ProfileDigest,
		AuthorizedObjectKind: "coverage-claim", AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix: uint64(now.Add(3 * time.Minute).Unix()),
	}, "tos.service.agent-guarantor-claim-signature.v1", testAuthorityCustody,
		testGuarantorController(fixture.coveredKey.Public().(ed25519.PublicKey)), []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	return guarantor.AuthorizedCoverageClaimV1{
		Body: body, EvidenceManifest: manifest, OtherRecoveryDeclaration: recovery,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization},
	}
}

// guarantorKillPoint is one place a process is killed, and what the process
// that resumes must return for the step it was killed in.
type guarantorKillPoint struct {
	name string
	// step is the index in guarantorKillSteps of the call the process is
	// killed in.
	step int
	// point is the process's kill point.
	point string
	// generation is the writer generation the step's receipts must carry: 2,
	// the killed process's, when that process had fixed the action in a plan
	// whose action is terminal, or in the committed receipt; 3, the resuming
	// process's, when the killed one had fixed nothing the authority holds
	// as terminal, so the resuming one authorizes the action itself.
	generation int
	// leavesTemporary is set when the kill leaves the temporary file of an
	// interrupted document write in the journal directory.
	leavesTemporary bool
}

// guarantorKillPoints are the crash points of the coordinator this test
// kills a process at. The document writes of each call are numbered in the
// order the call makes them:
//
//	issue:    1 admission, 2 plan, 3 reservation, 4 issued offer, 5 terminal result, 6 plan removed
//	accept:   1 admission, 2 plan, 3 acceptance, 4 terminal result
//	activate: 1 admission, 2 plan, 3 terminal result, 4 activation
//	claim:    1 ingress admission, 2 ingress plan, 3 ingress result, 4 admission plan, 5 claim admission
var guarantorKillPoints = []guarantorKillPoint{
	{"issue: inside its first document write", 0, "during-write:1", 3, true},
	{"issue: plan stored, authority not asked", 0, "after-write:2", 3, false},
	{"issue: offer issued in the journal, before the terminal transition", 0, "before-terminal:1", 2, false},
	{"issue: authority terminal, before the journal records it", 0, "after-terminal:1", 2, false},
	{"issue: last commit made, before the offer is returned", 0, "after-write:6", 2, false},
	{"accept: plan stored, authority not asked", 1, "after-write:2", 3, false},
	{"accept: action prepared, before the terminal transition", 1, "before-terminal:1", 3, false},
	{"accept: authority terminal, before the journal commit", 1, "after-terminal:1", 2, false},
	{"accept: authority terminal, inside the commit's document write", 1, "during-write:3", 2, true},
	{"accept: journal commit made, before the receipt is returned", 1, "after-write:3", 2, false},
	{"activate: authority terminal, before the journal commit", 2, "after-terminal:1", 2, false},
	{"activate: journal commit made, before the evidence is returned", 2, "after-write:4", 2, false},
	{"claim: both actions terminal, before the journal commit", 3, "after-terminal:2", 2, false},
	{"claim: journal commit made, before the receipts are returned", 3, "after-write:5", 2, false},
}

// TestGuarantorCoordinatorResumesAfterBeingKilled kills a process running the
// coordinator at each of guarantorKillPoints and requires the process that
// opens its journal next to return, for the call that was interrupted,
// exactly the receipts an uninterrupted process returns.
//
// "Exactly" is byte for byte, by envelope digest. An uninterrupted run and a
// killed one are comparable because every process runs on the test's logical
// clock and reads its entropy from a seeded source, so the writer fence the
// authority issues to the n-th process on a directory is the same in both.
// The reference for a kill point is therefore a run in which the same number
// of processes took the writer and none was killed: the call is made by the
// second process where the killed process had fixed the action, and by the
// third, after a second that did nothing new, where the resuming process
// authorizes it.
func TestGuarantorCoordinatorResumesAfterBeingKilled(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skipf("a process cannot be killed with SIGKILL on %s", runtime.GOOS)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	base := t.TempDir()
	// run starts the ordinal-th process on directory to run steps calls, with
	// a kill point or none. It kills a process that reports its kill point
	// and returns whether it did, with the process's output.
	run := func(directory string, ordinal, steps int, point string) (bool, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, "-test.run=^TestGuarantorKillProcess$", "-test.count=1",
			"-test.timeout=80s", "-test.v")
		command.Env = append(os.Environ(), guarantorKillDirectoryEnv+"="+directory,
			guarantorKillNowEnv+"="+strconv.FormatInt(now.Unix(), 10),
			guarantorKillOrdinalEnv+"="+strconv.Itoa(ordinal), guarantorKillStepsEnv+"="+strconv.Itoa(steps),
			guarantorKillPointEnv+"="+point)
		stdout, pipeErr := command.StdoutPipe()
		if pipeErr != nil {
			t.Fatal(pipeErr)
		}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if startErr := command.Start(); startErr != nil {
			t.Fatal(startErr)
		}
		var output strings.Builder
		reached := false
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line + "\n")
			if line == guarantorKillReached && !reached {
				reached = true
				// os.Process.Kill sends SIGKILL: the process gets no chance to
				// run anything more.
				if killErr := command.Process.Kill(); killErr != nil {
					t.Fatalf("kill the process at %s: %v", point, killErr)
				}
			}
		}
		waitErr := command.Wait()
		output.WriteString(stderr.String())
		status, isStatus := command.ProcessState.Sys().(syscall.WaitStatus)
		killed := isStatus && status.Signaled() && status.Signal() == syscall.SIGKILL
		switch {
		case point == "" && waitErr != nil:
			t.Fatalf("process %d on %s, running %d steps: %v\n%s", ordinal, filepath.Base(directory), steps, waitErr,
				output.String())
		case point != "" && (!reached || !killed):
			t.Fatalf("process %d on %s was to be killed at %s: reached=%v killed by SIGKILL=%v wait=%v\n%s", ordinal,
				filepath.Base(directory), point, reached, killed, waitErr, output.String())
		}
		return killed, output.String()
	}
	results := func(directory string) map[string]string {
		t.Helper()
		raw, readErr := os.ReadFile(filepath.Join(directory, guarantorKillResultsFile))
		if readErr != nil {
			t.Fatalf("read the results of the last process on %s: %v", filepath.Base(directory), readErr)
		}
		var decoded map[string]string
		if decodeErr := json.Unmarshal(raw, &decoded); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return decoded
	}
	// prefixes[n] holds the stores after one process made the first n calls.
	prefixes := make([]string, len(guarantorKillSteps))
	for steps := range guarantorKillSteps {
		prefixes[steps] = filepath.Join(base, "prefix-"+strconv.Itoa(steps))
		if mkdirErr := os.Mkdir(prefixes[steps], 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		run(prefixes[steps], 1, steps, "")
	}
	// reference returns what an uninterrupted run returns when the call of
	// step is made by the process that takes writer generation generation.
	references := map[string]map[string]string{}
	reference := func(step, generation int) map[string]string {
		t.Helper()
		key := strconv.Itoa(step) + "/" + strconv.Itoa(generation)
		if cached, found := references[key]; found {
			return cached
		}
		directory := filepath.Join(base, "reference-"+strconv.Itoa(step)+"-"+strconv.Itoa(generation))
		copyGuarantorKillTestTree(t, prefixes[step], directory)
		for ordinal := 2; ordinal < generation; ordinal++ {
			run(directory, ordinal, step, "")
		}
		run(directory, generation, step+1, "")
		references[key] = results(directory)
		wantGeneration := strconv.Itoa(generation)
		for name, value := range references[key] {
			if strings.HasPrefix(name, guarantorKillStepResult[step]) && strings.HasSuffix(name, "writer generation") &&
				value != wantGeneration {
				t.Fatalf("the reference for step %s by process %d carries %s = %s", guarantorKillSteps[step],
					generation, name, value)
			}
		}
		return references[key]
	}
	for index, point := range guarantorKillPoints {
		t.Run(point.name, func(t *testing.T) {
			directory := filepath.Join(base, "killed-"+strconv.Itoa(index))
			copyGuarantorKillTestTree(t, prefixes[point.step], directory)
			run(directory, 2, point.step+1, point.point)
			journalDirectory := filepath.Join(directory, "guarantor")
			if left := guarantorKillTestTemporaries(t, journalDirectory); (len(left) != 0) != point.leavesTemporary {
				t.Fatalf("the killed process left the temporary files %v, want some: %v", left, point.leavesTemporary)
			}
			if _, statErr := os.Stat(filepath.Join(directory, guarantorKillResultsFile)); statErr == nil {
				t.Fatal("the killed process wrote its results")
			}
			// A fresh process opens what the killed one left and makes the
			// same calls.
			run(directory, 3, point.step+1, "")
			resumed := results(directory)
			want := reference(point.step, point.generation)
			if !reflect.DeepEqual(resumed, want) {
				t.Fatalf("the process resumed after the kill returned\n%v\nan uninterrupted run returns\n%v", resumed,
					want)
			}
			if left := guarantorKillTestTemporaries(t, journalDirectory); len(left) != 0 {
				t.Fatalf("the resumed process left the temporary files %v", left)
			}
			// Making the calls once more returns the same receipts again.
			run(directory, 4, point.step+1, "")
			if again := results(directory); !reflect.DeepEqual(again, want) {
				t.Fatalf("a further process returned\n%v\nwant\n%v", again, want)
			}
		})
	}
}

// guarantorKillStepResult is, per step, the prefix of the names of its
// results.
var guarantorKillStepResult = []string{"offer", "acceptance", "activation", "claim"}

// guarantorKillTestTemporaries lists the temporary files of atomic writes in
// directory.
func guarantorKillTestTemporaries(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var temporaries []string
	for _, entry := range entries {
		if fileutil.IsAtomicWriteTemporaryName(entry.Name()) {
			temporaries = append(temporaries, entry.Name())
		}
	}
	return temporaries
}

// copyGuarantorKillTestTree copies the directory source, which must not be in
// use, to the new directory target, with every file's and directory's mode.
// The results of the process that wrote source are not copied.
func copyGuarantorKillTestTree(t *testing.T, source, target string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.Mkdir(destination, info.Mode().Perm())
		}
		if relative == guarantorKillResultsFile || !info.Mode().IsRegular() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err = io.Copy(output, input); err != nil {
			_ = output.Close()
			return err
		}
		return output.Close()
	})
	if err != nil {
		t.Fatalf("copy %s: %v", filepath.Base(source), err)
	}
}
