package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestPersonalAuthorityFailsClosedAcrossPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit renaming this open directory")
	}
	directory := privateTempDir(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	fence, err := authority.AcquireWriter(t.Context(), "runtime-initial", []string{"publication.reply"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := authority.BindRelaySideEffectAuthority(fence)
	if err != nil || !bound.HasLinearizableRelayAdmission() {
		t.Fatalf("healthy authority did not expose its local admission capability: %v", err)
	}
	moved := directory + "-moved"
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if replacement, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, PortfolioLimits{}); err == nil {
		_ = replacement.Close()
		t.Fatal("replacement directory acquired the same live logical authority")
	}
	if _, err := authority.AcquireWriter(t.Context(), "runtime", []string{"publication.reply"}, time.Minute); err == nil {
		t.Fatal("detached authority issued a new writer fence")
	}
	if resolution := authority.Resolve(testDigest, testDigest); resolution.State != commerce.ActionConflict {
		t.Fatalf("detached authority translated storage failure into authoritative absence: %+v", resolution)
	}
	if bound.HasLinearizableRelayAdmission() {
		t.Fatal("detached authority continued advertising linearizable admission")
	}
	if _, err := os.Lstat(filepath.Join(directory, authorityFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received authority state: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(moved, authorityFile)); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("original authority journal disappeared: info=%v err=%v", info, err)
	}
	replacementDirectory := directory + "-replacement"
	if err := os.Rename(directory, replacementDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, directory); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AcquireWriter(t.Context(), "runtime-restored", []string{"publication.reply"}, time.Minute); err == nil {
		t.Fatal("poisoned authority resumed after its pathname was restored")
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	if bound.HasLinearizableRelayAdmission() {
		t.Fatal("closed authority continued advertising linearizable admission")
	}
	replacement, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, PortfolioLimits{})
	if err != nil {
		t.Fatalf("replacement authority did not become available after clean close: %v", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPersonalAuthorityRejectsRelayAdmissionLedgerAbovePermanentCapacity(t *testing.T) {
	directory := privateTempDir(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, authorityFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document authorityDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maximumRelayAdmissions; index++ {
		document.RelayAdmissions[fmt.Sprintf("entry-%05d", index)] = agentrelay.SignedRelaySideEffectAdmissionReceipt{}
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, PortfolioLimits{}); err == nil {
		_ = reopened.Close()
		t.Fatal("oversized permanent relay admission ledger was accepted")
	}
}

func TestPersonalAuthorityFencesActionsAndPortfolio(t *testing.T) {
	directory := privateTempDir(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := PortfolioLimits{ComputeUnits: 10, SpendAtomic: 100, LockedCapitalAtomic: 100, ReceivableAtomic: 200, MaximumLossAtomic: 50}
	authority, err := OpenPersonalAuthority(directory, "owner-1", "agent-1", "authority-1", key, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	fixed := time.Unix(1_800_000_000, 0).UTC()
	authority.now = func() time.Time { return fixed }
	fence1, err := authority.AcquireWriter(context.Background(), "runtime-a", []string{"portfolio.reserve"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("reserve exact bytes")
	fields := reserveFields(1)
	action, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "portfolio.reserve", fields, request, fence1, 1,
		testDigest, "", "empty", uint64(fixed.Add(30*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = authority.SignAction(action, fence1)
	if err != nil {
		t.Fatal(err)
	}
	reservation := &ExposureReservation{ReservationID: action.StableActionID, AgreementDigest: testDigest, ComputeUnits: 4, SpendAtomic: 25, MaximumLossAtomic: 10}
	resolution, err := authority.Admit(action, fields, request, fence1, reservation)
	if err != nil || resolution.State != commerce.ActionPrepared {
		t.Fatalf("admit: resolution=%+v err=%v", resolution, err)
	}
	if retry, err := authority.Admit(action, fields, request, fence1, reservation); err != nil || !reflect.DeepEqual(retry, resolution) {
		t.Fatalf("exact retry was not idempotent: resolution=%+v err=%v", retry, err)
	}
	mutated := append([]byte(nil), request...)
	mutated[0] ^= 1
	if _, err := authority.Admit(action, fields, mutated, fence1, reservation); err == nil {
		t.Fatal("request mutation was accepted")
	}
	fence2, err := authority.AcquireWriter(context.Background(), "runtime-b", []string{"portfolio.release", "portfolio.reserve"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Admit(action, fields, request, fence1, nil); err == nil {
		t.Fatal("stale writer action was accepted after takeover")
	}
	action2, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "portfolio.reserve", reserveFields(2), []byte("second"), fence2, 2,
		testDigest, "", "empty", uint64(fixed.Add(30*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action2, err = authority.SignAction(action2, fence2)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge := &ExposureReservation{ReservationID: action2.StableActionID, AgreementDigest: testDigest, ComputeUnits: 7, SpendAtomic: 76}
	if _, err := authority.Admit(action2, reserveFields(2), []byte("second"), fence2, tooLarge); err == nil {
		t.Fatal("aggregate portfolio overcommit was accepted")
	}
	release := PortfolioReleaseRequest{ReservationID: reservation.ReservationID, AgreementDigest: testDigest,
		TargetPortfolioRevision: 3, TerminalEvidenceSetDigest: testDigest}
	releaseRequest, err := codec.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	releaseFields := map[string]commerce.SemanticValue{
		"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
		"reservation_id": commerce.Digest32(reservation.ReservationID), "target_revision": commerce.U64(3),
		"terminal_evidence_set_digest": commerce.Digest32(testDigest),
	}
	releaseAction, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "portfolio.release", releaseFields, releaseRequest,
		fence2, 2, testDigest, "", "reserved", uint64(fixed.Add(30*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	releaseAction, err = authority.SignAction(releaseAction, fence2)
	if err != nil {
		t.Fatal(err)
	}
	if resolution, err := authority.ReleaseReservation(releaseAction, releaseFields, releaseRequest, fence2); err != nil || resolution.State != commerce.ActionTerminal {
		t.Fatalf("authorized release: resolution=%+v err=%v", resolution, err)
	}
	if _, err := authority.Admit(action2, reserveFields(2), []byte("second"), fence2, tooLarge); err != nil {
		t.Fatalf("capacity was not released: %v", err)
	}
}

func TestPersonalAuthoritySeparatesMaximumLossByExactAsset(t *testing.T) {
	directory := privateTempDir(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(directory, "owner-1", "agent-1", "authority-asset", key,
		PortfolioLimits{MaximumLossAtomic: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_800_000_000, 0).UTC()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "asset-runtime", []string{"portfolio.reserve"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	native := commerce.AssetIdentityV1{AssetNamespace: "tos.asset", AssetIdentifier: "native", Unit: "nano"}
	token := commerce.AssetIdentityV1{AssetNamespace: "tos.jetton", AssetIdentifier: testDigest, Unit: "micro"}
	admit := func(sequence uint64, asset commerce.AssetIdentityV1, maximum uint64) error {
		request := []byte(fmt.Sprintf("asset-reservation-%d", sequence))
		fields := reserveFields(sequence)
		action, buildErr := commerce.BuildAuthorizedAction("owner-1", "agent-1", "portfolio.reserve", fields,
			request, fence, 1, testDigest, "", "empty", uint64(now.Add(30*time.Minute).Unix()))
		if buildErr != nil {
			return buildErr
		}
		action, buildErr = authority.SignAction(action, fence)
		if buildErr != nil {
			return buildErr
		}
		_, buildErr = authority.Admit(action, fields, request, fence, &ExposureReservation{ReservationID: action.StableActionID,
			AgreementDigest: testDigest, Asset: &asset, MaximumLossAtomic: maximum})
		return buildErr
	}
	if err := admit(1, native, 80); err != nil {
		t.Fatal(err)
	}
	if err := admit(2, token, 80); err != nil {
		t.Fatalf("different asset units were incorrectly summed: %v", err)
	}
	if err := admit(3, native, 30); err == nil {
		t.Fatal("same-asset maximum loss overcommit was accepted")
	}
}

func TestPersonalAuthorityProcessLockAndRecovery(t *testing.T) {
	directory := privateTempDir(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := PortfolioLimits{ComputeUnits: 1}
	first, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, limits); err == nil {
		t.Fatal("second process authority lock was admitted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", key, limits)
	if err != nil {
		t.Fatalf("recover authority: %v", err)
	}
	defer recovered.Close()
	fixed := time.Unix(1_800_000_000, 0).UTC()
	recovered.now = func() time.Time { return fixed }
	fence, err := recovered.AcquireWriter(context.Background(), "runtime", []string{"publication.reply"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := commerce.AuthorityInstanceAllocationRequest{OwnerID: "owner", AgentID: "agent", PurposeKind: "reply",
		MandateDigest: testDigest, ApprovalDigestOrZero: zeroDigest(), DownstreamEffectDescriptorDigest: testDigest,
		PredecessorAuthorityInstanceID: zeroDigest()}
	allocated, err := recovered.AllocateInstance(request, fence)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := recovered.AllocateInstance(request, fence)
	if err != nil || retry != allocated {
		t.Fatalf("allocation retry changed identity: first=%+v retry=%+v err=%v", allocated, retry, err)
	}
}

func TestPersonalAuthorityRecoversRelayAdmissionAcrossRestartAndTakeover(t *testing.T) {
	fixture := newRelayTestFixture(t, "agent:provider", nil, "https://relay.example")
	directory := privateTempDir(t)
	authority, err := OpenPersonalAuthority(directory, "owner:client", "agent:client", "authority:client",
		fixture.authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return fixture.now }
	fence, err := authority.AcquireWriter(t.Context(), "runtime:relay-one", []string{"payment.direct"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := clonePreparedRelayTransaction(fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	prepared.WriterFence = fence
	priorAction := prepared.UnderlyingAction
	prepared.UnderlyingAction, err = commerce.BuildAuthorizedAction(priorAction.OwnerID, priorAction.AgentID,
		priorAction.ActionKind, prepared.SemanticFields, prepared.UnderlyingActionRequest, fence,
		priorAction.PolicyRevision, priorAction.MandateDigest, priorAction.ApprovalDigest,
		priorAction.ExpectedPriorState, priorAction.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	prepared.UnderlyingAction, err = authority.SignAction(prepared.UnderlyingAction, fence)
	if err != nil {
		t.Fatal(err)
	}
	prepared.QuoteBody.StableActionID = prepared.UnderlyingAction.StableActionID
	prepared.QuoteBody.ExactRequestDigest = prepared.UnderlyingAction.ExactRequestDigest
	fixture.prepared = prepared
	fixture.resolver.setCurrentWriter(fence)
	provider := fixture.service(agentrelay.NewMemoryJournal(), &relayTestBroadcaster{})
	transport := relayFunctionTransport{quote: provider.Quote,
		submit: func(context.Context, agentrelay.RelayExecutionRequest,
			commerce.AgentAgreement) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, errors.New("not used")
		},
		resolve: func(context.Context, agentrelay.ResolveCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayResolution, error) {
			return agentrelay.SignedRelayResolution{}, ErrRelayRemoteUnknown
		},
		evidence: func(context.Context, agentrelay.EvidenceCall,
			agentrelay.RelayExecutionRequest) (agentrelay.SignedRelayFinalityEvidence, error) {
			return agentrelay.SignedRelayFinalityEvidence{}, errors.New("not used")
		}}
	coordinator := relayTestCoordinator(t, fixture, transport)
	admission, err := authority.BindRelaySideEffectAuthority(fence)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.SideEffectAdmission = admission
	attempt, err := coordinator.Prepare(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptor(attempt.Execution)
	if err != nil {
		t.Fatal(err)
	}
	want := attempt.Execution.AdmissionReceipt
	if want.Body.AdmissionSequence != 1 {
		t.Fatalf("first durable relay admission sequence=%d", want.Body.AdmissionSequence)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenPersonalAuthority(directory, "owner:client", "agent:client", "authority:client",
		fixture.authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return fixture.now }
	reopenedAdmission, err := reopened.BindRelaySideEffectAuthority(fence)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := reopenedAdmission.AdmitRelaySideEffects(t.Context(), descriptor); err != nil || !reflect.DeepEqual(retry, want) {
		t.Fatalf("restart did not return the exact admission receipt: retry=%+v err=%v", retry.Body, err)
	}
	if resolved, err := reopenedAdmission.ResolveRelaySideEffectAdmission(t.Context(), descriptor.Lookup()); err != nil || !reflect.DeepEqual(resolved, want) {
		t.Fatalf("restart resolution did not recover the exact admission: resolved=%+v err=%v", resolved.Body, err)
	}
	predecessorDigest, err := agentrelay.RelaySideEffectAdmissionReceiptBodyDigest(want.Body)
	if err != nil {
		t.Fatal(err)
	}
	successorDescriptor := descriptor
	successorDescriptor.ProviderAgentID = "agent:relay-successor"
	successorDescriptor.ServiceProfileDigest = "sha256:" + strings.Repeat("6", 64)
	successorDescriptor.ProviderQuoteDigest = "sha256:" + strings.Repeat("7", 64)
	successorDescriptor.RelayExecutionDigest = "sha256:" + strings.Repeat("8", 64)
	successorDescriptor.RouteAttempt = 2
	successorDescriptor.PredecessorReceiptDigest = predecessorDigest
	wrongTransaction := successorDescriptor
	wrongTransaction.TransactionIdentityDigest = "sha256:" + strings.Repeat("9", 64)
	if _, err := reopenedAdmission.AdmitRelaySideEffects(t.Context(), wrongTransaction); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("successor changed the exact signed-transaction identity: %v", err)
	}
	successor, err := reopenedAdmission.AdmitRelaySideEffects(t.Context(), successorDescriptor)
	if err != nil || successor.Body.RouteAttempt != 2 || successor.Body.PredecessorReceiptDigest != predecessorDigest ||
		successor.Body.TransactionIdentityDigest != want.Body.TransactionIdentityDigest {
		t.Fatalf("durable authority did not issue the exact receipt-chained successor: %+v err=%v", successor.Body, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	authorityPath := filepath.Join(directory, authorityFile)
	untampered, err := os.ReadFile(authorityPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentrelay.RelaySideEffectAdmissionReceiptBody){
		"policy revision": func(body *agentrelay.RelaySideEffectAdmissionReceiptBody) { body.PolicyRevision++ },
		"mandate": func(body *agentrelay.RelaySideEffectAdmissionReceiptBody) {
			body.MandateDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"approval": func(body *agentrelay.RelaySideEffectAdmissionReceiptBody) {
			body.ApprovalDigest = "sha256:" + strings.Repeat("c", 64)
		},
	} {
		t.Run("reject persisted successor "+name+" substitution", func(t *testing.T) {
			var document authorityDocument
			if err := json.Unmarshal(untampered, &document); err != nil {
				t.Fatal(err)
			}
			for lookup, receipt := range document.RelayAdmissions {
				if receipt.Body.RouteAttempt != 2 {
					continue
				}
				mutate(&receipt.Body)
				resigned, signErr := agentrelay.SignRelaySideEffectAdmissionReceipt(receipt.Body,
					fixture.authorityKey)
				if signErr != nil {
					t.Fatal(signErr)
				}
				document.RelayAdmissions[lookup] = resigned
			}
			raw, err := json.Marshal(document)
			if err != nil || os.WriteFile(authorityPath, raw, 0o600) != nil {
				t.Fatalf("write tampered authority journal: %v", err)
			}
			if recovered, err := OpenPersonalAuthority(directory, "owner:client", "agent:client", "authority:client",
				fixture.authorityKey, PortfolioLimits{}); err == nil {
				_ = recovered.Close()
				t.Fatal("persisted receipt authorization-context substitution survived recovery")
			}
			if err := os.WriteFile(authorityPath, untampered, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	reopened, err = OpenPersonalAuthority(directory, "owner:client", "agent:client", "authority:client",
		fixture.authorityKey, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return fixture.now }
	reopenedAdmission, err = reopened.BindRelaySideEffectAuthority(fence)
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := reopenedAdmission.ResolveRelaySideEffectAdmission(t.Context(), successorDescriptor.Lookup()); err != nil ||
		!reflect.DeepEqual(resolved, successor) {
		t.Fatalf("restart lost the current relay successor receipt: resolved=%+v err=%v", resolved.Body, err)
	}
	differentRoute := descriptor
	differentRoute.ProviderAgentID = "agent:different-provider"
	if _, err := reopenedAdmission.AdmitRelaySideEffects(t.Context(), differentRoute); !errors.Is(err, agentrelay.ErrRelayConflict) {
		t.Fatalf("same semantic action minted a second provider-route receipt: %v", err)
	}
	if _, err := reopened.AcquireWriter(t.Context(), "runtime:relay-two", []string{"payment.direct"}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := reopenedAdmission.AdmitRelaySideEffects(t.Context(), descriptor); err == nil {
		t.Fatal("superseded writer minted or directly retried an admission instead of resolving it")
	}
	if resolved, err := reopenedAdmission.ResolveRelaySideEffectAdmission(t.Context(), descriptor.Lookup()); err != nil || !reflect.DeepEqual(resolved, want) {
		t.Fatalf("takeover revoked an already-issued admission: resolved=%+v err=%v", resolved.Body, err)
	}
}

func TestPersonalAuthorityCustodyPaymentV2BindsFullRelayNetworkDomain(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key,
		PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Unix(1_800_000_000, 0).UTC()
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(t.Context(), "runtime:payment", []string{"payment.domain-bound"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayDomain := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: -3,
		ZeroStateRootHash: testDigest, ZeroStateFileHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		WorkchainID: 0}
	domainDigest, err := agentrelay.NetworkDomainDigest(relayDomain)
	if err != nil {
		t.Fatal(err)
	}
	amount := commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native",
		AmountAtomic: "25", Unit: "nanotos"}
	obligation := commerce.SettlementObligation{AgreementBodyDigest: testDigest,
		AgreementObligationID: "payment", ObligationInstanceID: testDigest, Sequence: 1,
		PayerAgentID: "agent-1", PayeeAgentID: "agent-2", Amount: amount, MaximumAggregateAmount: amount,
		ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix()), SettlementAdapterURI: "tos.payment.direct.v1",
		SettlementParametersDigest: testDigest, MandateDigest: testDigest, StableActionID: testDigest}
	payment, err := commerce.BuildDomainBoundAgreementPaymentRequest("owner-1", "agent-1", relayDomain.NetworkID,
		domainDigest, []byte("0:destination"), obligation)
	if err != nil {
		t.Fatal(err)
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", commerce.PaymentActionKind(payment), fields, canonical,
		fence, 1, testDigest, "", "pending", payment.ExpiresAtUnix)
	if err == nil {
		action, err = authority.SignAction(action, fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Admit(action, fields, canonical, fence, nil); err != nil {
		t.Fatal(err)
	}
	custodyDomain := commerce.CustodyNetworkDomain{NetworkID: relayDomain.NetworkID, GlobalID: relayDomain.GlobalID,
		ZeroStateRootHash: relayDomain.ZeroStateRootHash, ZeroStateFileHash: relayDomain.ZeroStateFileHash,
		WorkchainID: relayDomain.WorkchainID}
	authorization, err := authority.AuthorizeCustodyPayment(action, fields, canonical, fence, payment,
		"0:source", custodyDomain, nil)
	if err != nil {
		t.Fatal(err)
	}
	paymentDigest, err := commerce.AgreementPaymentRequestDigest(payment)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.SchemaVersion != 3 || authorization.AgreementPaymentRequestDigest != paymentDigest ||
		authorization.NetworkDomain == nil || *authorization.NetworkDomain != custodyDomain {
		t.Fatalf("custody authorization omitted the full network domain: %+v", authorization)
	}
	if err := commerce.VerifyRelayCustodyActionAuthorization(authorization,
		custodyEffectPinnedKey{key: key.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatal(err)
	}
	wrongDomain := custodyDomain
	wrongDomain.WorkchainID = -1
	if _, err := authority.AuthorizeCustodyPayment(action, fields, canonical, fence, payment,
		"0:source", wrongDomain, nil); err == nil {
		t.Fatal("relay payment was authorized for another target workchain")
	}
	sponsorship := &SponsorshipCustodyBinding{FinalityProfileCBORDigest: "sha256:" + strings.Repeat("8", 64),
		ReleaseProfileDigest:    "sha256:" + strings.Repeat("9", 64),
		CorroborationSnapshotID: "sha256:" + strings.Repeat("a", 64)}
	sponsorshipAuthorization, err := authority.AuthorizeCustodyPayment(action, fields, canonical, fence, payment,
		"0:source", custodyDomain, sponsorship)
	if err != nil {
		t.Fatal(err)
	}
	if sponsorshipAuthorization.SponsorshipFinalityProfileCBORDigest != sponsorship.FinalityProfileCBORDigest ||
		sponsorshipAuthorization.SponsorshipReleaseProfileDigest != sponsorship.ReleaseProfileDigest ||
		sponsorshipAuthorization.SponsorshipCorroborationSnapshotIdentity != sponsorship.CorroborationSnapshotID {
		t.Fatalf("custody authorization omitted the exact sponsorship evidence bindings: %+v", sponsorshipAuthorization)
	}
	if err := commerce.VerifyRelayCustodyActionAuthorization(sponsorshipAuthorization,
		custodyEffectPinnedKey{key: key.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatal(err)
	}
	mutatedSponsorship := sponsorshipAuthorization
	mutatedSponsorship.SponsorshipReleaseProfileDigest = testDigest
	if err := commerce.VerifyRelayCustodyActionAuthorization(mutatedSponsorship,
		custodyEffectPinnedKey{key: key.Public().(ed25519.PublicKey)}, now); err == nil {
		t.Fatal("a release-profile substitution preserved the custody authorization signature")
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "authority")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func reserveFields(revision uint64) map[string]commerce.SemanticValue {
	return map[string]commerce.SemanticValue{
		"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
		"agreement_body_digest": commerce.Digest32(testDigest), "reservation_scope_digest": commerce.Digest32(testDigest),
		"target_revision": commerce.U64(revision),
	}
}

func zeroDigest() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
