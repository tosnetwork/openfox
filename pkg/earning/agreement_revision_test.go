package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	revisionBuyer    = "agent:revision-buyer"
	revisionProvider = "agent:revision-provider"
)

type blockingProposalSink struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (sink *blockingProposalSink) Submit(_ context.Context, action commerce.AuthorizedAction, _ commerce.WriterFence,
	_ map[string]commerce.SemanticValue, _ []byte, _ OutboundMessage) (commerce.ActionResolution, error) {
	sink.calls.Add(1)
	sink.entered <- struct{}{}
	<-sink.release
	return commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, StateRevision: 1, SinkReference: "event:proposal"}, nil
}

func (sink *blockingProposalSink) ResolveAction(_ context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest,
		State: commerce.ActionUnknown, StateRevision: 1}, nil
}

func revisionAgreement(t *testing.T, now time.Time, agreementID string) commerce.AgentAgreementBody {
	t.Helper()
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: agreementID, Version: 1,
		NetworkContext: "tos:revision-test",
		Participants: []commerce.AgreementParticipant{{AgentID: revisionBuyer, Roles: []string{"buyer"}},
			{AgentID: revisionProvider, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("complete repository review"),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "payment", Kind: "payment", ObligorAgentID: revisionBuyer, BeneficiaryAgentID: revisionProvider,
				DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("payment after delivery"),
				Amount:                &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "evidence",
				SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte("tos1provider"),
				AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: revisionProvider, BeneficiaryAgentID: revisionBuyer,
				SubjectContentType: "text/plain", Subject: []byte("review every package and deliver one report"),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-start", DisputePolicy: "evidence",
				AuthorizationPredicateIDs: []string{"predicate:provider"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: revisionBuyer},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"payment"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: revisionProvider},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	prepared, err := commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func revisionAuthority(t *testing.T, now time.Time) (*PersonalAuthority, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityID := "authority:" + hex.EncodeToString(publicKey[:8])
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner:revision", revisionProvider, authorityID,
		privateKey, PortfolioLimits{ComputeUnits: 10, SpendAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return now }
	t.Cleanup(func() { _ = authority.Close() })
	return authority, privateKey
}

func TestBuildAgreementRevisionRebindsPriceAndScope(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	predecessor := revisionAgreement(t, now, "agreement:revision-builder")
	predecessorDigest, _ := commerce.AgreementBodyDigest(predecessor)
	originalTarget := predecessor.AuthorizationPredicates[0].EvidenceTargetProjectionDigest
	successor, err := BuildAgreementRevision(predecessor, func(body *commerce.AgentAgreementBody) error {
		body.Terms = []byte("review only the authentication package")
		body.Obligations[0].Amount.AmountAtomic = "35"
		body.Obligations[1].Subject = []byte("review only the authentication package and deliver one report")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if successor.Version != 2 || successor.PredecessorAgreementDigest != predecessorDigest ||
		successor.Obligations[0].Amount.AmountAtomic != "35" ||
		string(successor.Obligations[1].Subject) != "review only the authentication package and deliver one report" ||
		successor.AuthorizationPredicates[0].EvidenceTargetProjectionDigest == originalTarget {
		t.Fatalf("successor did not bind the exact price/scope revision: %+v", successor)
	}
	if predecessor.Obligations[0].Amount.AmountAtomic != "50" ||
		string(predecessor.Obligations[1].Subject) != "review every package and deliver one report" {
		t.Fatal("revision builder mutated its predecessor")
	}
}

func TestUniqueUnforkedAgreementLeafTopology(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	root := revisionAgreement(t, now, "agreement:topology")
	rootDigest, _ := commerce.AgreementBodyDigest(root)
	first, err := BuildAgreementRevision(root, func(body *commerce.AgentAgreementBody) error {
		body.Obligations[0].Amount.AmountAtomic = "45"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildAgreementRevision(root, func(body *commerce.AgentAgreementBody) error {
		body.Obligations[0].Amount.AmountAtomic = "40"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := commerce.AgreementBodyDigest(first)
	secondDigest, _ := commerce.AgreementBodyDigest(second)
	rootRecord := EngagementRecord{Agreement: commerce.AgentAgreement{Body: root}, AgreementDigest: rootDigest}
	firstRecord := EngagementRecord{Agreement: commerce.AgentAgreement{Body: first}, AgreementDigest: firstDigest}
	secondRecord := EngagementRecord{Agreement: commerce.AgentAgreement{Body: second}, AgreementDigest: secondDigest}
	chain := []EngagementRecord{rootRecord, firstRecord}
	if uniqueUnforkedAgreementLeaf(rootRecord, chain) || !uniqueUnforkedAgreementLeaf(firstRecord, chain) {
		t.Fatal("linear Agreement chain did not expose only its successor leaf")
	}
	fork := append(chain, secondRecord)
	if uniqueUnforkedAgreementLeaf(rootRecord, fork) || uniqueUnforkedAgreementLeaf(firstRecord, fork) ||
		uniqueUnforkedAgreementLeaf(secondRecord, fork) {
		t.Fatal("forked Agreement graph exposed an automatic authorization leaf")
	}
}

func TestForkedAgreementCannotEnterPaidDemandEconomicPaths(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body, _ := paidProviderAgreement(t, now)
	digest, err := commerce.AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	record := EngagementRecord{Agreement: commerce.AgentAgreement{Body: body}, AgreementDigest: digest,
		State: EngagementAgreed, NegotiationAmbiguous: true,
		NegotiationConflictCodes:   []string{"agreement_body_fork"},
		NegotiationConflictDigests: []string{digest}}
	if engagementEligibleForReservation(record, revisionProvider) {
		t.Fatal("forked Agreement remained eligible for Portfolio reservation")
	}
	record.State = EngagementProposed
	if paidDemandBuyerCandidate(record, revisionBuyer) {
		t.Fatal("forked Agreement remained eligible for Paid Demand buyer funding")
	}
}

func TestAgreementProposalPreflightChecksTimeAndParticipants(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	engine := &Engine{AgentID: revisionProvider, Now: func() time.Time { return now }}
	body := revisionAgreement(t, now, "agreement:preflight")
	if err := engine.preflightAgreementProposal(body, []string{revisionBuyer}); err != nil {
		t.Fatal(err)
	}
	if err := engine.preflightAgreementProposal(body, []string{"agent:unrelated"}); err == nil {
		t.Fatal("Agreement recipient outside the participant set passed preflight")
	}
	expired := body
	expired.ValidFromUnix = uint64(now.Add(-2 * time.Hour).Unix())
	expired.ExpiresAtUnix = uint64(now.Add(-time.Hour).Unix())
	for index := range expired.AuthorizationPredicates {
		expired.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	expired, err := commerce.PrepareAgreementTargets(expired)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.preflightAgreementProposal(expired, []string{revisionBuyer}); err == nil {
		t.Fatal("expired Agreement passed proposal preflight")
	}
}

func TestAgreementLedgerRejectsWrongAndSkippedPredecessors(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, _ := revisionAuthority(t, now)
	root := revisionAgreement(t, now, "agreement:lineage-root")
	other := revisionAgreement(t, now, "agreement:lineage-other")
	rootDigest, _ := commerce.AgreementBodyDigest(root)
	otherDigest, _ := commerce.AgreementBodyDigest(other)
	if _, err := authority.RecordAgreementProposal(root, revisionBuyer, "event:root", "sha256:"+strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementProposal(other, revisionBuyer, "event:other", "sha256:"+strings.Repeat("2", 64)); err != nil {
		t.Fatal(err)
	}
	successor, err := BuildAgreementRevision(root, func(body *commerce.AgentAgreementBody) error {
		body.Obligations[0].Amount.AmountAtomic = "45"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*commerce.AgentAgreementBody){
		"known unrelated predecessor": func(body *commerce.AgentAgreementBody) { body.PredecessorAgreementDigest = otherDigest },
		"unknown predecessor": func(body *commerce.AgentAgreementBody) {
			body.PredecessorAgreementDigest = "sha256:" + strings.Repeat("9", 64)
		},
		"skipped version": func(body *commerce.AgentAgreementBody) {
			body.Version = 3
			body.PredecessorAgreementDigest = rootDigest
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := successor
			mutate(&candidate)
			candidate.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), candidate.AuthorizationPredicates...)
			for index := range candidate.AuthorizationPredicates {
				candidate.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
			}
			candidate, err = commerce.PrepareAgreementTargets(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.RecordAgreementProposal(candidate, revisionProvider, "event:"+name,
				"sha256:"+strings.Repeat("3", 64)); err == nil {
				t.Fatal("invalid Agreement lineage was recorded")
			}
		})
	}
}

func TestAgreementLedgerRejectsForkAndMakesUnfinishedPredecessorStale(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, authorityKey := revisionAuthority(t, now)
	root := revisionAgreement(t, now, "agreement:fork")
	rootRecord, err := authority.RecordAgreementProposal(root, revisionBuyer, "event:root", "sha256:"+strings.Repeat("4", 64))
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildAgreementRevision(root, func(body *commerce.AgentAgreementBody) error {
		body.Obligations[0].Amount.AmountAtomic = "45"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildAgreementRevision(root, func(body *commerce.AgentAgreementBody) error {
		body.Obligations[0].Amount.AmountAtomic = "40"
		body.Obligations[1].Subject = []byte("review only one named package")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	firstRecord, err := authority.RecordAgreementProposal(first, revisionBuyer, "event:first", "sha256:"+strings.Repeat("5", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementProposal(second, revisionBuyer, "event:second", "sha256:"+strings.Repeat("6", 64)); err == nil {
		t.Fatal("conflicting bytes for one Agreement ID and version were recorded as a fork")
	}
	records := authority.EngagementSnapshot()
	if len(records) != 2 || uniqueUnforkedAgreementLeaf(firstRecord, records) || uniqueUnforkedAgreementLeaf(rootRecord, records) {
		t.Fatalf("retained fork did not stop automatic authorization: %+v", records)
	}
	for _, record := range records {
		if !record.NegotiationAmbiguous || !containsString(record.NegotiationConflictCodes, "agreement_body_fork") {
			t.Fatalf("fork conflict was not persisted on the Agreement lineage: %+v", record)
		}
	}

	providerPublic, providerKey, _ := ed25519.GenerateKey(rand.Reader)
	acceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
		AgreementID: root.AgreementID, AgreementVersion: root.Version, AgreementBodyDigest: rootRecord.AgreementDigest,
		AcceptingSubject: root.AuthorizationPredicates[1].AuthoritySubject, AcceptedRoles: []string{"provider"},
		PredicateIDs: []string{"predicate:provider"}, EvidenceTargetProjectionDigests: []string{root.AuthorizationPredicates[1].EvidenceTargetProjectionDigest},
		ExpiresAtUnix: root.ExpiresAtUnix,
	}, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := commerce.AgentSignatureEvidence(root, acceptance)
	if err != nil {
		t.Fatal(err)
	}
	verifier := AgreementEvidenceRouter{AgentAuthority: agreementKeyResolver{revisionProvider: providerPublic}}
	if _, err := authority.RecordAgreementEvidence(rootRecord.AgreementDigest, evidence, verifier); err == nil {
		t.Fatal("superseded predecessor accepted new authorization evidence")
	}

	fence, err := authority.AcquireWriter(context.Background(), "fork-runtime", []string{"agreement.propose"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now, resolutions: map[string]commerce.ActionResolution{}}
	engine := &Engine{OwnerID: "owner:revision", AgentID: revisionProvider, MandateDigest: testDigest,
		Gates: FeatureGates{Agreement: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	if _, err := engine.ProposeAgreement(context.Background(), second, []string{revisionBuyer}, 1, fence); err == nil {
		t.Fatal("conflicting Agreement fork passed proposal preflight")
	}
	if sink.calls != 0 {
		t.Fatalf("rejected Agreement fork performed %d Messenger side effects", sink.calls)
	}
}

func TestAgreementProposalReplayRequiresExactProposerAndActionIdentity(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, _ := revisionAuthority(t, now)
	body := revisionAgreement(t, now, "agreement:proposal-identity")
	digest, err := commerce.AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	actionID := "sha256:" + strings.Repeat("c", 64)
	if _, err := authority.RecordAgreementProposal(body, revisionBuyer, "event:first", actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementProposal(body, revisionBuyer, "event:replay", actionID); err != nil {
		t.Fatalf("exact semantic proposal replay was rejected: %v", err)
	}
	if _, err := authority.RecordAgreementProposal(body, revisionProvider, "event:other",
		"sha256:"+strings.Repeat("d", 64)); err == nil {
		t.Fatal("same body under a different proposer/action identity was accepted")
	}
	record, found := authority.Engagement(digest)
	if !found || !record.NegotiationAmbiguous || !containsString(record.NegotiationConflictCodes, "proposal_identity_conflict") {
		t.Fatalf("proposal identity conflict was not retained: %+v", record)
	}
}

func TestAgreementEvidenceReplayCannotBypassDurableFork(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, _ := revisionAuthority(t, now)
	body := revisionAgreement(t, now, "agreement:evidence-replay-fork")
	record, err := authority.RecordAgreementProposal(body, revisionBuyer, "event:proposal",
		"sha256:"+strings.Repeat("7", 64))
	if err != nil {
		t.Fatal(err)
	}
	providerPublic, providerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	predicate := body.AuthorizationPredicates[1]
	acceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
		AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: record.AgreementDigest,
		AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
		PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
		ExpiresAtUnix: body.ExpiresAtUnix,
	}, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := commerce.AgentSignatureEvidence(body, acceptance)
	if err != nil {
		t.Fatal(err)
	}
	verifier := AgreementEvidenceRouter{AgentAuthority: agreementKeyResolver{revisionProvider: providerPublic}}
	if _, err := authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err != nil {
		t.Fatal(err)
	}
	fork := body
	fork.Terms = []byte("conflicting complete terms")
	fork.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), fork.AuthorizationPredicates...)
	for index := range fork.AuthorizationPredicates {
		fork.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	fork, err = commerce.PrepareAgreementTargets(fork)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementProposal(fork, revisionBuyer, "event:fork",
		"sha256:"+strings.Repeat("8", 64)); err == nil {
		t.Fatal("conflicting Agreement body did not create a durable fork")
	}
	if _, err := authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier); err == nil {
		t.Fatal("exact evidence replay bypassed the durable fork marker")
	}
}

func TestConcurrentAgreementForkIsRejectedBeforeSecondMessengerSideEffect(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, _ := revisionAuthority(t, now)
	fence, err := authority.AcquireWriter(context.Background(), "concurrent-proposal",
		[]string{"agreement.propose"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first := revisionAgreement(t, now, "agreement:concurrent-fork")
	second := first
	second.Terms = []byte("conflicting complete terms")
	second.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), second.AuthorizationPredicates...)
	for index := range second.AuthorizationPredicates {
		second.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	second, err = commerce.PrepareAgreementTargets(second)
	if err != nil {
		t.Fatal(err)
	}
	sink := &blockingProposalSink{entered: make(chan struct{}, 2), release: make(chan struct{})}
	engine := &Engine{OwnerID: "owner:revision", AgentID: revisionProvider, MandateDigest: testDigest,
		Gates: FeatureGates{Agreement: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	type proposalResult struct {
		resolution commerce.ActionResolution
		err        error
	}
	firstDone := make(chan proposalResult, 1)
	go func() {
		resolution, proposeErr := engine.ProposeAgreement(context.Background(), first, []string{revisionBuyer}, 1, fence)
		firstDone <- proposalResult{resolution: resolution, err: proposeErr}
	}()
	<-sink.entered // The first side effect is blocked; its proposal must already be durable.
	secondDone := make(chan proposalResult, 1)
	go func() {
		resolution, proposeErr := engine.ProposeAgreement(context.Background(), second, []string{revisionBuyer}, 1, fence)
		secondDone <- proposalResult{resolution: resolution, err: proposeErr}
	}()
	var secondResult proposalResult
	select {
	case secondResult = <-secondDone:
	case <-sink.entered:
		// Reaching this branch is the old TOCTOU bug: both forks escaped to
		// Messenger before either body was durably reconciled.
	}
	close(sink.release)
	firstResult := <-firstDone
	if secondResult.err == nil {
		secondResult = <-secondDone
	}
	if firstResult.err != nil || firstResult.resolution.State != commerce.ActionTerminal || secondResult.err == nil || sink.calls.Load() != 1 {
		t.Fatalf("concurrent fork crossed the side-effect boundary: first=%+v second=%+v calls=%d",
			firstResult, secondResult, sink.calls.Load())
	}
}

func TestAgreementProposalPreflightRejectsExpiredAndUnknownLineageBeforeSend(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, authorityKey := revisionAuthority(t, now)
	fence, err := authority.AcquireWriter(context.Background(), "proposal-runtime", []string{"agreement.propose"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sink := &exactSink{key: authorityKey.Public().(ed25519.PublicKey), now: now, resolutions: map[string]commerce.ActionResolution{}}
	engine := &Engine{OwnerID: "owner:revision", AgentID: revisionProvider, MandateDigest: testDigest,
		Gates: FeatureGates{Agreement: true}, Authority: authority, Sink: sink, Now: func() time.Time { return now }}
	expired := revisionAgreement(t, now, "agreement:expired")
	expired.ValidFromUnix = uint64(now.Add(-2 * time.Hour).Unix())
	expired.ExpiresAtUnix = uint64(now.Add(-time.Hour).Unix())
	for index := range expired.AuthorizationPredicates {
		expired.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	expired, err = commerce.PrepareAgreementTargets(expired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ProposeAgreement(context.Background(), expired, []string{revisionBuyer}, 1, fence); err == nil {
		t.Fatal("expired Agreement proposal reached the send path")
	}

	root := revisionAgreement(t, now, "agreement:unknown-lineage")
	successor, err := BuildAgreementRevision(root, func(body *commerce.AgentAgreementBody) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	successor.PredecessorAgreementDigest = "sha256:" + strings.Repeat("8", 64)
	for index := range successor.AuthorizationPredicates {
		successor.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	successor, err = commerce.PrepareAgreementTargets(successor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ProposeAgreement(context.Background(), successor, []string{revisionBuyer}, 1, fence); err == nil {
		t.Fatal("proposal with an unknown predecessor reached the send path")
	}
	if sink.calls != 0 {
		t.Fatalf("invalid proposal performed %d Messenger side effects", sink.calls)
	}
}

func TestAgreementEvidenceEnforcesBodyPredicateAndAcceptanceValidityWithReleasedDependency(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, _ := revisionAuthority(t, now)
	providerPublic, providerKey, _ := ed25519.GenerateKey(rand.Reader)
	verifier := AgreementEvidenceRouter{AgentAuthority: agreementKeyResolver{revisionProvider: providerPublic}}

	signProviderEvidence := func(body commerce.AgentAgreementBody, record EngagementRecord,
		expiresAt uint64) commerce.AgreementAuthorizationEvidence {
		t.Helper()
		predicate := body.AuthorizationPredicates[1]
		acceptance, err := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: record.AgreementDigest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs:                    []string{predicate.PredicateID},
			EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest}, ExpiresAtUnix: expiresAt,
		}, providerKey)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := commerce.AgentSignatureEvidence(body, acceptance)
		if err != nil {
			t.Fatal(err)
		}
		return evidence
	}

	expiredBody := revisionAgreement(t, now, "agreement:evidence-expired")
	expiredRecord, err := authority.RecordAgreementProposal(expiredBody, revisionBuyer, "event:expired",
		"sha256:"+strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return time.Unix(int64(expiredBody.ExpiresAtUnix), 0).UTC() }
	if _, err := authority.RecordAgreementEvidence(expiredRecord.AgreementDigest,
		signProviderEvidence(expiredBody, expiredRecord, expiredBody.ExpiresAtUnix), verifier); err == nil {
		t.Fatal("expired Agreement accepted new evidence under the pinned released protocol dependency")
	}
	authority.now = func() time.Time { return now }

	futurePredicate := revisionAgreement(t, now, "agreement:evidence-future-predicate")
	futurePredicate.AuthorizationPredicates = append([]commerce.AgreementAuthorizationPredicate(nil), futurePredicate.AuthorizationPredicates...)
	for index := range futurePredicate.AuthorizationPredicates {
		futurePredicate.AuthorizationPredicates[index].ValidFromUnix = uint64(now.Add(time.Minute).Unix())
		futurePredicate.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	futurePredicate, err = commerce.PrepareAgreementTargets(futurePredicate)
	if err != nil {
		t.Fatal(err)
	}
	futureRecord, err := authority.RecordAgreementProposal(futurePredicate, revisionBuyer, "event:future",
		"sha256:"+strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementEvidence(futureRecord.AgreementDigest,
		signProviderEvidence(futurePredicate, futureRecord, futurePredicate.ExpiresAtUnix), verifier); err == nil {
		t.Fatal("not-yet-valid predicate accepted evidence")
	}

	outlivedBody := revisionAgreement(t, now, "agreement:evidence-outlives")
	outlivedRecord, err := authority.RecordAgreementProposal(outlivedBody, revisionBuyer, "event:outlives",
		"sha256:"+strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementEvidence(outlivedRecord.AgreementDigest,
		signProviderEvidence(outlivedBody, outlivedRecord, uint64(now.Add(2*time.Hour).Unix())), verifier); err == nil {
		t.Fatal("acceptance outliving its Agreement/predicate was accepted")
	}
}

func TestAgreedPredecessorEvidenceReplayIsIdempotentAndWithdrawalCannotCancel(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authority, _ := revisionAuthority(t, now)
	body := revisionAgreement(t, now, "agreement:withdraw-agreed")
	proposalActionID := "sha256:" + strings.Repeat("a", 64)
	record, err := authority.RecordAgreementProposal(body, revisionBuyer, "event:proposal", proposalActionID)
	if err != nil {
		t.Fatal(err)
	}
	resolver := agreementKeyResolver{}
	keys := map[string]ed25519.PrivateKey{}
	for _, participant := range []string{revisionBuyer, revisionProvider} {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		resolver[participant], keys[participant] = publicKey, privateKey
	}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	var recordedEvidence []commerce.AgreementAuthorizationEvidence
	for _, predicate := range body.AuthorizationPredicates {
		acceptance, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: record.AgreementDigest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: body.ExpiresAtUnix,
		}, keys[predicate.AuthoritySubject.SubjectIdentifier])
		if signErr != nil {
			t.Fatal(signErr)
		}
		evidence, evidenceErr := commerce.AgentSignatureEvidence(body, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		recordedEvidence = append(recordedEvidence, evidence)
		record, err = authority.RecordAgreementEvidence(record.AgreementDigest, evidence, verifier)
		if err != nil {
			t.Fatal(err)
		}
	}
	if record.State != EngagementAgreed {
		t.Fatalf("Agreement did not reach agreed state: %s", record.State)
	}
	successor, err := BuildAgreementRevision(body, func(revision *commerce.AgentAgreementBody) error {
		revision.Obligations[0].Amount.AmountAtomic = "45"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordAgreementProposal(successor, revisionBuyer, "event:successor", "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	replayed, err := authority.RecordAgreementEvidence(record.AgreementDigest, recordedEvidence[0], verifier)
	if err != nil || replayed.State != EngagementAgreed || len(replayed.Agreement.AuthorizationEvidence) != len(recordedEvidence) {
		t.Fatalf("exact evidence replay on agreed predecessor was not idempotent: record=%+v err=%v", replayed, err)
	}
	if _, err := authority.ObserveAgreementWithdrawal(record.AgreementDigest, proposalActionID, revisionBuyer, "event:withdraw"); err == nil {
		t.Fatal("proposal withdrawal cancelled a completely accepted Agreement")
	}
	stored, found := authority.Engagement(record.AgreementDigest)
	if !found || stored.State != EngagementAgreed {
		t.Fatalf("agreed Agreement changed after withdrawal: %+v", stored)
	}
}
