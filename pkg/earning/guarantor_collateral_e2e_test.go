package earning

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
	"github.com/tosnetwork/ai/protocol/pkg/codec"
)

const (
	testCollateralObligationID = "obligation:collateral"
	testCollateralCustodian    = "agent:custodian"
	testCollateralReorgSeconds = 60
)

// TestGuarantorCollateralAttestedCoverageVerifiesFromTheJournal runs a
// collateral-attested coverage with a really admitted and signed collateral
// lock and really signed collateral-control evidence. Activation stores both
// in the journal; claim admission, cancellation and closure then verify
// through the journal resolver, and each is refused once a stored prerequisite
// file is gone or the resolver does not expose the finality verifier.
//
// A coverage is cancelled only from its activation, before any claim, so the
// cancellation runs on a second collateralized coverage with its own lock.
//
// The finality verifier is a test double pinned to those locks. No
// chain-side verification of a collateral lock exists yet, and nothing in the
// production code can construct this double.
func TestGuarantorCollateralAttestedCoverageVerifiesFromTheJournal(t *testing.T) {
	runGuarantorProviderLifecycle(t, guarantorCollateralAttested)
}

// finalizedCollateralTransition is one collateral transition the test treats
// as finalized: its exact adapter request, adapter evidence, resulting state,
// finality reference and time.
type finalizedCollateralTransition struct {
	request     guarantor.CollateralAdapterRequestV1
	evidence    guarantor.CollateralAdapterEvidenceV1
	result      guarantor.CollateralPositionStateV1
	reference   string
	finalizedAt time.Time
}

// pinnedCollateralFinality is a test-only finality verifier. It accepts
// exactly the transitions it was pinned to, one lock per coverage in this
// test, and refuses everything else.
type pinnedCollateralFinality struct {
	finalized []finalizedCollateralTransition
}

func (pinned *pinnedCollateralFinality) VerifyCollateralAdapterFinalityV1(request guarantor.CollateralAdapterRequestV1,
	evidence guarantor.CollateralAdapterEvidenceV1, result guarantor.CollateralPositionStateV1, reference string,
	finalizedAt time.Time, _ guarantor.CollateralTermsV1) error {
	if pinned != nil {
		for _, known := range pinned.finalized {
			if known.reference != "" && sameJSON(request, known.request) && sameJSON(evidence, known.evidence) &&
				sameJSON(result, known.result) && reference == known.reference && finalizedAt.Equal(known.finalizedAt) {
				return nil
			}
		}
	}
	return errors.New("collateral transition is not a pinned finalized lock")
}

// testControlResolution is a test-only control-resolution verifier that
// records that it was asked.
type testControlResolution struct{ asked *bool }

func (control testControlResolution) VerifyGuarantorAuthorityControlResolution(commerce.ProfileRefV1, string,
	guarantor.GuarantorStageActionAuthorityV1, commerce.ProfileRefV1, []string, string, uint64, time.Time,
	[]byte) (guarantor.AuthorityControlResolutionResultV1, error) {
	*control.asked = true
	return guarantor.AuthorityControlResolutionResultV1{}, errors.New("no control resolution in this test")
}

// Operator resolvers that are themselves one or both verifiers, and one that
// serves immutable evidence itself.
type (
	operatorWithFinality struct {
		guarantorPinnedResolver
		*pinnedCollateralFinality
	}
	operatorWithControl struct {
		guarantorPinnedResolver
		testControlResolution
	}
	operatorWithBoth struct {
		guarantorPinnedResolver
		*pinnedCollateralFinality
		testControlResolution
	}
	operatorServingEvidence struct{ guarantorPinnedResolver }
)

func (operatorServingEvidence) ResolveImmutableGuarantorEvidence(guarantor.ImmutableEvidenceDescriptorV1) ([]byte, error) {
	return nil, errors.New("no evidence in this test")
}

// TestJournalResolverForwardsExactlyTheVerifiersTheOperatorProvides: the
// protocol finds the collateral finality verifier and the control-resolution
// verifier by asking its resolver whether it is one. The journal resolver and
// the pending resolver expose each of them when the operator provides it, the
// very one the operator provides, and neither when the operator provides none.
func TestJournalResolverForwardsExactlyTheVerifiersTheOperatorProvides(t *testing.T) {
	journal, _ := openTestGuarantorJournal(t)
	agreement := "sha256:" + strings.Repeat("c", 64)
	base := newGuarantorPinnedResolver(nil)
	reference := "sha256:" + strings.Repeat("d", 64)
	finality := &pinnedCollateralFinality{finalized: []finalizedCollateralTransition{{reference: reference}}}
	var asked bool
	control := testControlResolution{asked: &asked}
	for name, test := range map[string]struct {
		operator                  guarantor.AuthorityKeyResolver
		configured                guarantor.CollateralAdapterFinalityVerifier
		wantFinality, wantControl bool
	}{
		"the operator provides neither":                  {base, nil, false, false},
		"the coordinator is configured with finality":    {base, finality, true, false},
		"the operator's resolver is the finality":        {operatorWithFinality{base, finality}, nil, true, false},
		"the operator's resolver is the control":         {operatorWithControl{base, control}, nil, false, true},
		"the operator's resolver is both":                {operatorWithBoth{base, finality, control}, nil, true, true},
		"configured finality and the resolver's control": {operatorWithControl{base, control}, finality, true, true},
		"an evidence-serving operator, neither":          {operatorServingEvidence{base}, nil, false, false},
		"an evidence-serving operator, configured":       {operatorServingEvidence{base}, finality, true, false},
	} {
		coordinator := GuarantorProviderCoordinator{Resolver: test.operator, Journal: journal,
			CollateralFinalityVerifier: test.configured}
		for kind, resolver := range map[string]guarantor.AuthorityKeyResolver{
			"journal resolver": coordinator.resolverFor(agreement),
			"pending resolver": coordinator.pendingResolverFor(agreement, map[string]GuarantorStoredEvidence{}),
		} {
			if _, serves := resolver.(guarantor.ImmutableEvidenceResolver); !serves {
				t.Errorf("%s, %s: the resolver does not serve immutable evidence", name, kind)
			}
			gotFinality, isFinality := resolver.(guarantor.CollateralAdapterFinalityVerifier)
			gotControl, isControl := resolver.(guarantor.AuthorityControlResolutionVerifier)
			if isFinality != test.wantFinality || isControl != test.wantControl {
				t.Errorf("%s, %s: exposes finality=%v control=%v, want finality=%v control=%v", name, kind,
					isFinality, isControl, test.wantFinality, test.wantControl)
				continue
			}
			// What is exposed is the operator's own verifier.
			if isFinality {
				if err := gotFinality.VerifyCollateralAdapterFinalityV1(guarantor.CollateralAdapterRequestV1{},
					guarantor.CollateralAdapterEvidenceV1{}, guarantor.CollateralPositionStateV1{}, reference, time.Time{},
					guarantor.CollateralTermsV1{}); err != nil {
					t.Errorf("%s, %s: the exposed finality verifier is not the operator's: %v", name, kind, err)
				}
			}
			if isControl {
				asked = false
				_, _ = gotControl.VerifyGuarantorAuthorityControlResolution(commerce.ProfileRefV1{}, "",
					guarantor.GuarantorStageActionAuthorityV1{}, commerce.ProfileRefV1{}, nil, "", 0, time.Time{}, nil)
				if !asked {
					t.Errorf("%s, %s: the exposed control-resolution verifier is not the operator's", name, kind)
				}
			}
		}
	}
}

// operatorServingEvidenceWithFinality is an operator resolver that serves
// immutable evidence and is itself a finality verifier.
type operatorServingEvidenceWithFinality struct {
	operatorServingEvidence
	*pinnedCollateralFinality
}

// TestTheConfiguredFinalityVerifierAnswersAheadOfTheResolversOwn: the protocol
// asks the resolver it is given for the collateral finality verifier, and the
// coordinator verifies every activation with the verifier it is configured
// with. So that one answers on every resolver the coordinator builds, ahead
// of a verifier the operator's resolver itself is, whichever resolver serves
// the evidence; the resolver's own answers only when none is configured.
func TestTheConfiguredFinalityVerifierAnswersAheadOfTheResolversOwn(t *testing.T) {
	journal, _ := openTestGuarantorJournal(t)
	agreement := "sha256:" + strings.Repeat("c", 64)
	base := newGuarantorPinnedResolver(nil)
	configuredReference, ownReference := "sha256:"+strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)
	configured := &pinnedCollateralFinality{
		finalized: []finalizedCollateralTransition{{reference: configuredReference}},
	}
	own := &pinnedCollateralFinality{finalized: []finalizedCollateralTransition{{reference: ownReference}}}
	accepts := func(verifier guarantor.CollateralAdapterFinalityVerifier, reference string) bool {
		return verifier.VerifyCollateralAdapterFinalityV1(guarantor.CollateralAdapterRequestV1{},
			guarantor.CollateralAdapterEvidenceV1{}, guarantor.CollateralPositionStateV1{}, reference, time.Time{},
			guarantor.CollateralTermsV1{}) == nil
	}
	for name, test := range map[string]struct {
		operator   guarantor.AuthorityKeyResolver
		configured guarantor.CollateralAdapterFinalityVerifier
		answers    string
	}{
		"a resolver that is a finality verifier, another one configured": {
			operatorWithFinality{base, own}, configured, configuredReference,
		},
		"a resolver that is a finality verifier, none configured": {
			operatorWithFinality{base, own}, nil, ownReference,
		},
		"an evidence-serving resolver that is a finality verifier, another one configured": {
			operatorServingEvidenceWithFinality{operatorServingEvidence{base}, own}, configured, configuredReference,
		},
		"an evidence-serving resolver that is a finality verifier, none configured": {
			operatorServingEvidenceWithFinality{operatorServingEvidence{base}, own}, nil, ownReference,
		},
		"an evidence-serving resolver, one configured": {
			operatorServingEvidence{base}, configured, configuredReference,
		},
	} {
		coordinator := GuarantorProviderCoordinator{Resolver: test.operator, Journal: journal}
		if test.configured != nil {
			coordinator.CollateralFinalityVerifier = test.configured
		}
		for kind, resolver := range map[string]guarantor.AuthorityKeyResolver{
			"journal resolver": coordinator.resolverFor(agreement),
			"pending resolver": coordinator.pendingResolverFor(agreement, map[string]GuarantorStoredEvidence{}),
		} {
			if _, serves := resolver.(guarantor.ImmutableEvidenceResolver); !serves {
				t.Errorf("%s, %s: the resolver does not serve immutable evidence", name, kind)
			}
			exposed, isFinality := resolver.(guarantor.CollateralAdapterFinalityVerifier)
			if !isFinality {
				t.Errorf("%s, %s: no finality verifier is exposed", name, kind)
				continue
			}
			for _, reference := range []string{configuredReference, ownReference} {
				if got, want := accepts(exposed, reference), reference == test.answers; got != want {
					t.Errorf("%s, %s: the exposed finality verifier accepts %s: %v, want %v",
						name, kind, reference, got, want)
				}
			}
		}
	}
}

// guarantorCollateralFixture is one collateral-attested profile with a
// custodian-authorized lock transition and Guarantor-controlled custody.
type guarantorCollateralFixture struct {
	profile       guarantor.CollateralProfileV1
	profileDigest string
	lock          guarantor.CollateralTransitionProfileV1
}

func newGuarantorCollateralFixture(t *testing.T, asset commerce.AssetIdentityV1, claimProfileDigest string,
	ref func(ch, name string) commerce.ProfileRefV1) guarantorCollateralFixture {
	t.Helper()
	custody := ref("7", "collateral-custody")
	lock := guarantor.CollateralTransitionProfileV1{TransitionKind: "lock",
		SuccessorDerivationProfile: ref("1", "collateral-successor"), AdapterProfile: custody,
		AdapterRequestContentType: "application/cbor", AdapterRequestProfile: ref("2", "collateral-request"),
		MaximumAdapterRequestBytes: 64 << 10, AdapterEvidenceContentType: "application/cbor",
		AdapterEvidenceProfile: ref("3", "collateral-adapter-evidence"), AuthorizationSubjectSource: "custodian",
		CustodianAuthorizationBinding: &guarantor.CollateralAuthorizationBindingV1{
			AuthorizationProfile: ref("4", "custodian-authority"), AuthorizationSubjects: []string{testCollateralCustodian},
			AuthorizationQuorumRule: "all"},
		PermittedPriorStates: []string{"lock_pending", "unproven"}, PermittedResultingStates: []string{"locked"},
		AuthorizedClaimDecisionBinding: "forbidden", PayoutDestinationBinding: "forbidden"}
	profile := guarantor.CollateralProfileV1{ProfileID: "collateral:attested", ProfileVersion: 1,
		AssuranceLevel: guarantor.AssuranceCollateralAttested, Asset: asset, CustodyAdapterProfile: custody,
		CollateralControlDisclosure: guarantor.CollateralControlDisclosureV1{SchemaVersion: 1, CustodyAdapterProfile: custody,
			AdapterOperatorSubjects: []string{testCollateralCustodian}, CustodianControllerRootSubjects: []string{testCollateralCustodian},
			DeclaredGuarantorControlRelationship: "guarantor_controlled"},
		TransitionProfiles: []guarantor.CollateralTransitionProfileV1{lock}, CompatibleClaimProfileDigests: []string{claimProfileDigest},
		ExclusiveAllocationRequired: true, MinimumCollateralizationPPM: 1_000_000, MaximumEvidenceAgeSeconds: 3600}
	digest, err := codec.Digest("tos.service.agent-guarantor-collateral-profile.v1", profile)
	if err != nil {
		t.Fatal(err)
	}
	return guarantorCollateralFixture{profile: profile, profileDigest: digest, lock: lock}
}

// terms are collateral terms under the fixture's profile. The collateral is
// locked by lockBy and until lockUntil, and may be released only at
// lockUntil, which the caller sets one reorg window after the coverage
// terms' final deadline.
func (fixture guarantorCollateralFixture) terms(t *testing.T, amount commerce.AtomicAmountV1, lockBy, lockUntil uint64,
	ref func(ch, name string) commerce.ProfileRefV1) *guarantor.CollateralTermsV1 {
	t.Helper()
	lockDigest, err := guarantor.CollateralTransitionProfileDigestV1(fixture.lock)
	if err != nil {
		t.Fatal(err)
	}
	terms := &guarantor.CollateralTermsV1{PositionID: "position:collateral", SelectedCollateralProfileDigest: fixture.profileDigest,
		AssuranceLevel: guarantor.AssuranceCollateralAttested, Asset: amount.Asset, Amount: amount,
		CollateralPrincipalSubject: "agent:guarantor", CustodyAdapterProfile: fixture.profile.CustodyAdapterProfile,
		CollateralControlDisclosure: fixture.profile.CollateralControlDisclosure,
		PositionIdentityProfile:     ref("5", "collateral-position"),
		TransitionBindings: []guarantor.CollateralTransitionBindingV1{{TransitionProfileDigest: lockDigest,
			TransitionProfile: fixture.lock, AuthorizationBinding: *fixture.lock.CustodianAuthorizationBinding}},
		ContractOrAccountDigest: "sha256:" + strings.Repeat("a", 64), ExclusiveAllocationRequired: true,
		LockByUnix: lockBy, LockUntilUnix: lockUntil, ReleaseNotBeforeUnix: lockUntil,
		FinalityProfile: ref("6", "collateral-finality"), MaximumEvidenceAgeSeconds: 3600,
		ReorgWindowSeconds: testCollateralReorgSeconds}
	if err := guarantor.ValidateCollateralTermsV1(*terms); err != nil {
		t.Fatalf("the collateral terms are invalid: %v", err)
	}
	return terms
}

// signedCollateralLock locks the coverage's collateral position: the
// collateral-transition action is admitted by the economic authority and made
// terminal, its stage evidence is signed by the Action Authority, and the
// evidence body is signed by the custodian the transition binding names. It
// returns the evidence and the one finalized transition the finality double
// accepts.
func signedCollateralLock(t *testing.T, coordinator *GuarantorProviderCoordinator, fence commerce.WriterFence,
	coverageTerms guarantor.CoverageTermsV1, agreementDigest, predecessorDigest string,
	at time.Time) (guarantor.AuthorizedCollateralEvidenceV1, finalizedCollateralTransition) {
	t.Helper()
	fail := func(step string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("collateral lock, %s: %v", step, err)
		}
	}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	terms := *coverageTerms.CollateralTerms
	binding := terms.TransitionBindings[0]
	profile := binding.TransitionProfile
	bindingDigest, err := guarantor.CollateralTransitionBindingDigestV1(binding)
	fail("transition binding", err)
	zero := commerce.AtomicAmountV1{Asset: terms.Asset, AmountAtomic: "0"}
	expected := guarantor.CollateralPositionStateV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CollateralObligationID: coverageTerms.CollateralObligationID, PositionID: terms.PositionID, PositionDigest: digest("b"),
		CoverageBindingDigest: digest("c"), StateRevision: 1, Status: guarantor.CollateralLockPending, Asset: terms.Asset,
		AllocatedAmount: terms.Amount, CumulativeConsumed: zero, CumulativeReleased: zero, CumulativeImpaired: zero,
		RemainingAmount: terms.Amount}
	expectedDigest, err := guarantor.CollateralPositionStateDigestV1(expected)
	fail("expected position state", err)
	prerequisites := guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "collateral-lock",
		ContextDigest: agreementDigest, Items: []guarantor.CanonicalGuarantorEvidenceItemV1{{ContentType: "application/cbor",
			EvidenceProfileDigest: digest("6"), EvidenceEnvelopeDigest: digest("7"), Representation: "inline",
			CanonicalEnvelopeBytes: []byte("custody-account-statement")}}}
	prerequisitesDigest, err := guarantor.CanonicalGuarantorEvidenceSetDigestV1(prerequisites)
	fail("lock prerequisites", err)
	request := guarantor.CollateralAdapterRequestV1{SchemaVersion: 1, AdapterProfile: profile.AdapterProfile,
		AdapterRequestProfile: profile.AdapterRequestProfile, CoverageAgreementBodyDigest: agreementDigest,
		CollateralObligationID: coverageTerms.CollateralObligationID, CollateralPositionID: terms.PositionID,
		TransitionBindingDigest: bindingDigest, TransitionKind: "lock", ExpectedPositionState: expected,
		ExpectedStateDigest: expectedDigest, Asset: terms.Asset, Amount: terms.Amount,
		PrerequisiteEvidenceSetDigest: prerequisitesDigest, AdapterOperationParameters: []byte{0xa0}}
	requestDigest, err := guarantor.CollateralAdapterRequestDigestV1(request, binding, terms)
	fail("adapter request", err)
	actionBody := guarantor.CollateralTransitionActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		ObligationID: coverageTerms.CollateralObligationID, CollateralPositionID: terms.PositionID, TransitionBinding: binding,
		TransitionKind: "lock", ExpectedStateRevision: expected.StateRevision, ExpectedStateDigest: expectedDigest,
		Asset: terms.Asset, Amount: terms.Amount, PrerequisiteEvidenceSet: prerequisites, AdapterRequest: request}
	fail("transition action body", guarantor.ValidateCollateralTransitionActionBodyV1(actionBody, terms, false))
	canonical, err := guarantor.Canonical(actionBody)
	fail("encode the action", err)
	actionBodyDigest, err := guarantor.Digest("tos.service.agent-guarantor-collateral-transition-action-body.v1", actionBody)
	fail("action body digest", err)

	// The action is admitted and resolved by the economic authority.
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(coordinator.OwnerID),
		"agent_id": commerce.ID(coordinator.AgentID), "agreement_body_digest": commerce.Digest32(agreementDigest),
		"obligation_id":             commerce.ID(coverageTerms.CollateralObligationID),
		"collateral_position_id":    commerce.ID(terms.PositionID),
		"transition_binding_digest": commerce.Digest32(bindingDigest),
		"expected_state_revision":   commerce.U64(expected.StateRevision), "transition_kind": commerce.Kind("lock")}
	action, err := commerce.BuildAuthorizedAction(coordinator.OwnerID, coordinator.AgentID, "collateral.transition", fields,
		canonical, fence, coordinator.PolicyRevision, coordinator.MandateDigest, "", predecessorDigest, terms.LockByUnix)
	fail("build the action", err)
	action, err = coordinator.Authority.SignAction(action, fence)
	fail("sign the action", err)
	resolution, err := coordinator.Authority.Admit(action, fields, canonical, fence, nil)
	if err != nil || resolution.State != commerce.ActionPrepared {
		t.Fatalf("collateral lock, admit the action: state=%s err=%v", resolution.State, err)
	}
	actionDigest, err := commerce.AuthorizedActionDigest(action)
	fail("action digest", err)
	resolution, err = coordinator.Authority.Transition(action.StableActionID, action.ExactRequestDigest,
		commerce.ActionTerminal, actionDigest, []string{actionDigest})
	fail("resolve the action", err)
	stage, err := coordinator.buildGuarantorStage(coverageTerms, "collateral_transition",
		"application/vnd.tos.service.agent-guarantor-collateral-transition-action.v1+cbor", canonical, action, resolution,
		fence, at)
	fail("stage evidence", err)

	result, err := guarantor.ApplyCollateralAdapterTransitionV1(request, binding, terms)
	fail("resulting position state", err)
	resultDigest, err := guarantor.CollateralPositionStateDigestV1(result)
	fail("resulting state digest", err)
	adapterEvidence := guarantor.CollateralAdapterEvidenceV1{ContentType: profile.AdapterEvidenceContentType,
		EvidenceProfile: profile.AdapterEvidenceProfile, TransitionBindingDigest: bindingDigest,
		AdapterProfileDigest: profile.AdapterProfile.ProfileDigest, TransitionKind: "lock", AdapterRequestDigest: requestDigest,
		PriorStateRevision: expected.StateRevision, ResultingStateRevision: result.StateRevision,
		ExpectedStateDigest: expectedDigest, ResultingStateDigest: resultDigest, Representation: "inline",
		CanonicalEvidenceBytes: []byte("finalized-collateral-lock")}
	adapterEvidenceDigest, err := guarantor.CollateralAdapterEvidenceDigestV1(adapterEvidence)
	fail("adapter evidence", err)
	rawEligibility, err := coordinator.Eligibility.FreshEligibilityProofSet(context.Background(), "collateral-transition",
		binding.AuthorizationBinding.AuthorizationSubjects, at)
	fail("eligibility proof", err)
	eligibility, err := buildGuarantorEligibilityProofSet(rawEligibility, action, requestDigest,
		binding.AuthorizationBinding.AuthorizationSubjects, "collateral-evidence", actionBodyDigest, bindingDigest,
		binding.AuthorizationBinding.AuthorizationProfile, expected.CoverageBindingDigest, expected.StateRevision,
		uint64(at.Unix()))
	fail("eligibility proof set", err)
	eligibilityDigest, err := guarantor.AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	fail("eligibility digest", err)

	pinned := finalizedCollateralTransition{request: request, evidence: adapterEvidence, result: result,
		reference: digest("d"), finalizedAt: at}
	body := guarantor.CollateralEvidenceBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CollateralObligationID: coverageTerms.CollateralObligationID, PositionID: terms.PositionID,
		PositionDigest: result.PositionDigest, TransitionBindingDigest: bindingDigest,
		CollateralTransitionActionBodyDigest: actionBodyDigest, AdapterProfile: profile.AdapterProfile,
		EvidenceProfile: profile.AdapterEvidenceProfile, EvidenceContentType: profile.AdapterEvidenceContentType,
		TransitionKind: "lock", Amount: terms.Amount, CumulativeConsumed: result.CumulativeConsumed,
		PriorStateRevision: expected.StateRevision, ResultingStateRevision: result.StateRevision,
		ExpectedStateDigest: expectedDigest, ResultingStateDigest: resultDigest,
		CoverageBindingDigest: result.CoverageBindingDigest, FinalityReference: pinned.reference,
		FinalizedAtUnix: uint64(at.Unix()), AdapterRequestDigest: requestDigest, AdapterEvidenceDigest: adapterEvidenceDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration,
		WriterFenceDigest: action.WriterFenceDigest, AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := guarantor.Digest("tos.service.agent-guarantor-collateral-evidence-body.v1", body)
	fail("evidence body digest", err)
	custodian := binding.AuthorizationBinding.AuthorizationProfile
	authorization, err := guarantor.SignObjectAuthorization(context.Background(), guarantor.AuthorizationStatementV1{
		SchemaVersion: 1, AuthoritySubject: testCollateralCustodian, ProfileURI: custodian.ProfileURI,
		ProfileVersion: custodian.ProfileVersion, ProfileDigest: custodian.ProfileDigest,
		AuthorizedObjectKind: "collateral-evidence", AuthorizedBodyDigest: bodyDigest, ValidationTimeUnix: uint64(at.Unix())},
		"tos.service.agent-guarantor-collateral-evidence-signature.v1", testAuthorityCustody,
		testCollateralCustodianController, []byte("custodian-history"))
	fail("custodian signature", err)
	return guarantor.AuthorizedCollateralEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		CollateralTransitionActionBody: actionBody, AdapterEvidence: adapterEvidence, ResultingPositionState: result,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations:                        []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}, pinned
}

// testCollateralCustodianController is the fake custody controller the
// custodian signs with.
const testCollateralCustodianController = "collateral-custodian"

// signedCollateralControl is the Guarantor's signed statement of who controls
// the custody, exactly as the collateral terms disclose it.
func signedCollateralControl(t *testing.T, signer GuarantorObjectSigner, coverageTerms guarantor.CoverageTermsV1,
	agreementDigest string, at time.Time, expiresAtUnix uint64) guarantor.AuthorizedCollateralControlEvidenceV1 {
	t.Helper()
	disclosure := coverageTerms.CollateralTerms.CollateralControlDisclosure
	disclosureDigest, err := guarantor.CollateralControlDisclosureDigestV1(disclosure)
	if err != nil {
		t.Fatal(err)
	}
	body := guarantor.CollateralControlEvidenceBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CollateralObligationID:            coverageTerms.CollateralObligationID,
		SelectedCollateralProfileDigest:   coverageTerms.SelectedCollateralProfileDigest,
		CollateralControlDisclosureDigest: disclosureDigest, CustodyAdapterProfile: disclosure.CustodyAdapterProfile,
		AdapterOperatorSubjects:              disclosure.AdapterOperatorSubjects,
		CustodianControllerRootSubjects:      disclosure.CustodianControllerRootSubjects,
		DeclaredGuarantorControlRelationship: disclosure.DeclaredGuarantorControlRelationship,
		ObservedAtUnix:                       uint64(at.Unix()), ExpiresAtUnix: expiresAtUnix}
	bodyDigest, err := guarantor.Digest("tos.service.agent-guarantor-collateral-control-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := signer.SignObject("collateral-control-evidence", bodyDigest,
		"tos.service.agent-guarantor-collateral-control-evidence-signature.v1", at)
	if err != nil {
		t.Fatalf("sign the collateral control evidence: %v", err)
	}
	return guarantor.AuthorizedCollateralControlEvidenceV1{Body: body,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
}

// collateralActivationPrerequisites is the activation prerequisite set of a
// collateralized coverage: the lock and the control evidence by descriptor
// under the selected collateral profile, with any other items the activation
// needs. It returns the set and the two envelope digests.
func collateralActivationPrerequisites(t *testing.T, coverageTerms guarantor.CoverageTermsV1, agreementDigest string,
	lock guarantor.AuthorizedCollateralEvidenceV1, control guarantor.AuthorizedCollateralControlEvidenceV1,
	others ...guarantor.CanonicalGuarantorEvidenceItemV1) (guarantor.CanonicalGuarantorEvidenceSetV1, string, string) {
	t.Helper()
	policy := coverageTerms.SelectedCollateralProfileDigest
	item := func(contentType string, value any, digest string, digestErr error) guarantor.CanonicalGuarantorEvidenceItemV1 {
		t.Helper()
		wire, err := guarantor.Canonical(value)
		if err != nil || digestErr != nil {
			t.Fatalf("encode the %s prerequisite: %v %v", contentType, err, digestErr)
		}
		return guarantor.CanonicalGuarantorEvidenceItemV1{ContentType: contentType, EvidenceProfileDigest: policy,
			EvidenceEnvelopeDigest: digest, Representation: "content_addressed",
			ImmutableDescriptor: &guarantor.ImmutableEvidenceDescriptorV1{ContentType: contentType, ContentDigest: digest,
				ContentSize: uint64(len(wire)), RetrievalPolicyDigest: policy}}
	}
	lockDigest, lockErr := guarantor.CollateralEvidenceDigestV1(lock)
	controlDigest, controlErr := guarantor.CollateralControlEvidenceDigestV1(control)
	items := append([]guarantor.CanonicalGuarantorEvidenceItemV1{
		item(guarantor.CollateralEvidenceContentTypeV1, lock, lockDigest, lockErr),
		item(guarantor.CollateralControlEvidenceContentTypeV1, control, controlDigest, controlErr)}, others...)
	sort.Slice(items, func(i, j int) bool {
		left, _ := guarantor.Canonical(items[i])
		right, _ := guarantor.Canonical(items[j])
		return string(left) < string(right)
	})
	set := guarantor.CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "coverage-activation-collateral",
		ContextDigest: agreementDigest, Items: items}
	if err := guarantor.ValidateCanonicalGuarantorEvidenceSetV1(set); err != nil {
		t.Fatalf("the collateral activation prerequisite set is invalid: %v", err)
	}
	return set, lockDigest, controlDigest
}

// signedTestCancellationRequest is the covered party's signed request to
// cancel a coverage under its Agreement's covered-party branch at created.
func signedTestCancellationRequest(t *testing.T, agreement commerce.AgentAgreementBody, agreementDigest string,
	policy guarantor.CoverageCancellationPolicyV1, coveredController string,
	created time.Time) guarantor.AuthorizedCoverageCancellationRequestV1 {
	t.Helper()
	policyDigest, err := guarantor.CoverageCancellationPolicyDigestV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	profile := policy.Branches[0].RequestAuthorizationProfile
	body := guarantor.CoverageCancellationRequestBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: "obligation:coverage", CancellationPolicyDigest: policyDigest,
		CancellationBranch: policy.Branches[0].CancellationBranch, RequesterSubject: "agent:covered",
		EffectiveNotBeforeUnix: uint64(created.Unix()), EffectiveNotAfterUnix: uint64(created.Add(30 * time.Second).Unix()),
		CreatedAtUnix: uint64(created.Unix()), ExpiresAtUnix: uint64(created.Add(45 * time.Second).Unix())}
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-cancellation-request-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := guarantor.SignObjectAuthorization(context.Background(), guarantor.AuthorizationStatementV1{
		SchemaVersion: 1, AuthoritySubject: "agent:covered", ProfileURI: profile.ProfileURI,
		ProfileVersion: profile.ProfileVersion, ProfileDigest: profile.ProfileDigest,
		AuthorizedObjectKind: "coverage-cancellation-request", AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix: uint64(created.Unix())}, "tos.service.agent-guarantor-cancellation-request-signature.v1",
		testAuthorityCustody, coveredController, []byte("covered-history"))
	if err != nil {
		t.Fatal(err)
	}
	return guarantor.AuthorizedCoverageCancellationRequestV1{Body: body, CoverageAgreementBody: agreement,
		Authorizations: []guarantor.ProfileQualifiedObjectAuthorizationV1{authorization}}
}

// collateralVerificationCheck checks one verification of a collateralized
// coverage three ways: it passes through the coordinator's journal resolver;
// it is refused through a journal resolver that does not expose the finality
// verifier; and it is refused through the coordinator's resolver once either
// stored prerequisite file is gone.
type collateralVerificationCheck struct {
	coordinator     *GuarantorProviderCoordinator
	journalDir      string
	agreementDigest string
	prerequisites   []string
}

func (check collateralVerificationCheck) run(t *testing.T, name string, verify func(guarantor.AuthorityKeyResolver) error) {
	t.Helper()
	const refusal = "collateral activation lacks exact allocation, control, or operational-independence proof"
	if err := verify(check.coordinator.resolverFor(check.agreementDigest)); err != nil {
		t.Fatalf("%s does not verify through the journal resolver: %v", name, err)
	}
	withoutFinality := GuarantorJournalEvidenceResolver{AuthorityKeyResolver: check.coordinator.Resolver,
		Journal: check.coordinator.Journal, AgreementDigest: check.agreementDigest}
	if err := verify(withoutFinality); err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatalf("%s verified through a resolver that does not expose the finality verifier: %v", name, err)
	}
	for _, digest := range check.prerequisites {
		file := filepath.Join(check.journalDir, guarantorEvidenceDirectory, strings.TrimPrefix(digest, "sha256:"))
		if err := os.Rename(file, file+".moved"); err != nil {
			t.Fatal(err)
		}
		err := verify(check.coordinator.resolverFor(check.agreementDigest))
		if restoreErr := os.Rename(file+".moved", file); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if err == nil {
			t.Fatalf("%s verified although the stored prerequisite %s is gone", name, digest)
		}
	}
	if err := verify(check.coordinator.resolverFor(check.agreementDigest)); err != nil {
		t.Fatalf("%s does not verify after its prerequisites were put back: %v", name, err)
	}
}
