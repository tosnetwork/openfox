package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
