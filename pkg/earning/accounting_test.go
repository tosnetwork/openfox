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
	entry, err := (AccountingService{Engine: engine}).RecordGift(context.Background(), amount,
		"sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64), now, 1, fence)
	if err != nil || entry.Body.Classification != AccountingGratuity || len(authority.AccountingSnapshot()) != 1 {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	bad := entry.Body
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
