package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestGiftAccountingIsDurableButCannotCloseAgreement(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner-1", "agent-1", "authority-1", key, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Now().UTC().Truncate(time.Second)
	authority.now = func() time.Time { return now }
	fence, err := authority.AcquireWriter(context.Background(), "runtime-1", []string{"accounting.record"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{OwnerID: "owner-1", AgentID: "agent-1", MandateDigest: "sha256:" + strings.Repeat("a", 64), Authority: authority}
	amount := commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "10", Unit: "nanotos"}
	evidence := []string{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("c", 64)}
	body := AccountingEntryBody{SchemaVersion: 1, Classification: AccountingGratuity, Amount: &amount,
		SourceReference: "agent-gift", EvidenceRefs: evidence, ObservedAtUnix: uint64(now.Unix())}
	entry, err := (AccountingService{Engine: engine}).Record(context.Background(), body, 1, fence)
	if err != nil || entry.Body.Classification != AccountingGratuity || len(authority.AccountingSnapshot()) != 1 {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	amount.AmountAtomic = "999"
	evidence[0] = "sha256:" + strings.Repeat("f", 64)
	entry.Body.Amount.AmountAtomic = "888"
	entry.Body.EvidenceRefs[0] = "sha256:" + strings.Repeat("e", 64)
	snapshot := authority.AccountingSnapshot()
	if len(snapshot) != 1 || snapshot[0].Body.Amount == nil || snapshot[0].Body.Amount.AmountAtomic != "10" ||
		snapshot[0].Body.EvidenceRefs[0] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("accounting commit retained caller/result aliases: %+v", snapshot)
	}
	snapshot[0].Body.Amount.AmountAtomic = "777"
	snapshot[0].Body.EvidenceRefs[0] = "sha256:" + strings.Repeat("d", 64)
	again := authority.AccountingSnapshot()
	if again[0].Body.Amount.AmountAtomic != "10" || again[0].Body.EvidenceRefs[0] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("accounting snapshot exposed journal aliases: %+v", again)
	}
	authority.mu.Lock()
	var actionID, exactDigest string
	for candidate, resolution := range authority.doc.Actions {
		if len(resolution.EvidenceRefs) != 0 {
			actionID, exactDigest = candidate, resolution.ExactRequestDigest
			break
		}
	}
	authority.mu.Unlock()
	resolution := authority.Resolve(actionID, exactDigest)
	resolution.EvidenceRefs[0] = "sha256:" + strings.Repeat("f", 64)
	if retained := authority.Resolve(actionID, exactDigest); retained.EvidenceRefs[0] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("accounting ActionResolution exposed evidence aliases: %+v", retained)
	}
	bad := again[0].Body
	bad.AgreementBodyDigest = "sha256:" + strings.Repeat("d", 64)
	if _, err := AccountingEntryID(bad); err == nil {
		t.Fatal("Gift was attributed to an Agreement")
	}
	if len(authority.SettlementSnapshot(bad.AgreementBodyDigest)) != 0 {
		t.Fatal("Gift created settlement state")
	}
	for _, invalid := range []string{"01", "+1", "1e3", "-1", strings.Repeat("9", 79)} {
		changed := entry.Body
		changed.Amount = &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: invalid, Unit: "nanotos"}
		if _, err := AccountingEntryID(changed); err == nil {
			t.Fatalf("non-canonical accounting amount %q was accepted", invalid)
		}
	}
}
