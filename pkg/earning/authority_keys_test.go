package earning

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

func TestPersonalAuthorityRefusesInvalidAuthorityKeys(t *testing.T) {
	valid := testAuthorityKeys()
	upper := valid
	upper.ActionKeyID = "mldsa44:" + strings.ToUpper(strings.TrimPrefix(valid.ActionKeyID, "mldsa44:"))
	short := valid
	short.ActionKeyID = valid.ActionKeyID[:len(valid.ActionKeyID)-2]
	ed25519Action := valid
	ed25519Action.ActionKeyID = "ed25519:" + strings.Repeat("a", 64)
	ed25519Custody := valid
	ed25519Custody.CustodyKeyID = "ed25519:" + strings.Repeat("a", 64)
	notDeriving := valid
	notDeriving.ActionPublicKey = testAuthorityCustody.PublicKey("another-controller")
	swapped := valid
	swapped.ActionKeyID, swapped.ActionPublicKey = valid.CustodyKeyID, valid.CustodyPublicKey
	noCustody := valid
	noCustody.Custody = nil
	cases := map[string]AuthorityKeys{"upper-case hex key ID": upper, "short key ID": short,
		"Ed25519 Action Authority key": ed25519Action, "Ed25519 custody key": ed25519Custody,
		"public key not deriving its key ID": notDeriving, "one key for both uses": swapped, "no custody": noCustody}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			if authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", keys,
				PortfolioLimits{}); err == nil {
				_ = authority.Close()
				t.Fatal("personal authority opened with invalid keys")
			}
		})
	}
	if _, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", ed25519Action, PortfolioLimits{}); !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
		t.Fatalf("Ed25519 Action Authority key was not refused with the protocol diagnostic: %v", err)
	}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", valid, PortfolioLimits{})
	if err != nil {
		t.Fatalf("valid keys were refused: %v", err)
	}
	_ = authority.Close()
}

func TestPersonalAuthorityJournalRefusesChangedPinnedKeys(t *testing.T) {
	directory := privateTempDir(t)
	authority, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", testAuthorityKeys(), PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string]AuthorityKeys{
		"another Action Authority key":      testAuthorityKeysFor("rotated-action", CustodyAuthorizationController),
		"another custody authorization key": testAuthorityKeysFor(ActionAuthorityController, "rotated-custody"),
	} {
		if reopened, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", keys, PortfolioLimits{}); err == nil {
			_ = reopened.Close()
			t.Fatalf("journal reopened under %s", name)
		}
	}
	reopened, err := OpenPersonalAuthority(directory, "owner", "agent", "authority", testAuthorityKeys(), PortfolioLimits{})
	if err != nil {
		t.Fatalf("journal did not reopen under its pinned keys: %v", err)
	}
	_ = reopened.Close()
}

func TestPersonalAuthorityResolvesOnlyItsPinnedKey(t *testing.T) {
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", testAuthorityKeys(), PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	keys := testAuthorityKeys()
	actionID, _ := mldsa44.ParseKeyIDText(keys.ActionKeyID)
	custodyID, _ := mldsa44.ParseKeyIDText(keys.CustodyKeyID)
	if key, err := authority.ResolveActionAuthorityKey("authority", actionID, time.Now()); err != nil || string(key) != string(keys.ActionPublicKey) {
		t.Fatalf("pinned key did not resolve: %v", err)
	}
	if _, err := authority.ResolveActionAuthorityKey("another-authority", actionID, time.Now()); err == nil {
		t.Fatal("pinned key resolved for another authority")
	}
	if _, err := authority.ResolveActionAuthorityKey("authority", custodyID, time.Now()); err == nil {
		t.Fatal("the custody authorization key resolved as an Action Authority key")
	}
}

// otherKeyCustody signs every request with one fixed controller, standing in
// for custody that answers with a key other than the one asked for.
type otherKeyCustody struct {
	*mldsa44test.Fake
	controller string
}

func (custody otherKeyCustody) Sign(ctx context.Context, _ string, use mldsa44.Use, payload []byte) (mldsa44.Signature, error) {
	return custody.Fake.Sign(ctx, custody.controller, use, payload)
}

func TestPersonalAuthorityRefusesCustodySignaturesFromAnotherKey(t *testing.T) {
	keys := testAuthorityKeys()
	keys.Custody = otherKeyCustody{Fake: testAuthorityCustody, controller: "unexpected-controller"}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", keys, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if _, err := authority.AcquireWriter(t.Context(), "instance", []string{"payment.direct"}, time.Hour); err == nil {
		t.Fatal("a writer fence signed by another custody key was accepted")
	}
	if _, err := authority.signCustodyAuthorization(commerce.CustodyActionAuthorization{}); err == nil {
		t.Fatal("a custody authorization signed by another key was accepted")
	}
}

func fenceUnderUse(t *testing.T, authority *PersonalAuthority, use mldsa44.Use, controller string) commerce.WriterFence {
	t.Helper()
	now := time.Now().UTC()
	body := commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner", AgentID: "agent", InstanceID: "instance",
		LeaseID: "lease:test", WriterGeneration: 1, IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), AuthorityID: "authority", Scope: []string{"payment.direct"}}
	message, err := commerce.WriterFenceSignatureMessage(body)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := testAuthorityCustody.Sign(t.Context(), controller, use, message)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.ActionAuthoritySignatureText(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return commerce.WriterFence{Body: body, KeyID: mldsa44.KeyIDText(signed.KeyID), Proof: proof}
}

func TestPersonalAuthorityRefusesFencesUnderOtherContextsAndTextForms(t *testing.T) {
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", testAuthorityKeys(), PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Now().UTC()
	valid := fenceUnderUse(t, authority, mldsa44.UseActionAuthority, ActionAuthorityController)
	if err := commerce.VerifyWriterFence(valid, authority, now, "payment.direct"); err != nil {
		t.Fatalf("an Action Authority fence did not verify: %v", err)
	}
	for name, use := range map[string]mldsa44.Use{"custody authorization context": mldsa44.UseCustodyAuthorization,
		"Agent Guarantor context": mldsa44.UseAgentGuarantor} {
		fence := fenceUnderUse(t, authority, use, ActionAuthorityController)
		if err := commerce.VerifyWriterFence(fence, authority, now, "payment.direct"); err == nil {
			t.Fatalf("a fence signed under the %s verified as Action Authority", name)
		}
	}
	custodyKey := fenceUnderUse(t, authority, mldsa44.UseActionAuthority, CustodyAuthorizationController)
	if err := commerce.VerifyWriterFence(custodyKey, authority, now, "payment.direct"); err == nil {
		t.Fatal("a fence signed by the custody authorization key verified")
	}
	ed25519Proof := valid
	ed25519Proof.Proof = "ed25519:" + strings.TrimPrefix(valid.Proof, "mldsa44:")
	if err := commerce.VerifyWriterFence(ed25519Proof, authority, now, "payment.direct"); !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
		t.Fatalf("an Ed25519 proof was not refused with the protocol diagnostic: %v", err)
	}
	padded := valid
	raw, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(valid.Proof, "mldsa44:"))
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	padded.Proof = "mldsa44:" + base64.URLEncoding.EncodeToString(raw)
	if err := commerce.VerifyWriterFence(padded, authority, now, "payment.direct"); err == nil {
		t.Fatal("a padded Base64 proof verified")
	}
	upperKey := valid
	upperKey.KeyID = "mldsa44:" + strings.ToUpper(strings.TrimPrefix(valid.KeyID, "mldsa44:"))
	if err := commerce.VerifyWriterFence(upperKey, authority, now, "payment.direct"); err == nil {
		t.Fatal("an upper-case key ID verified")
	}
}

func TestStoredCustodyAuthorizationRefusesActionAuthorityContext(t *testing.T) {
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", testAuthorityKeys(), PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	body := relayCustodyAuthorizationFixture(t)
	signed, err := authority.signCustodyAuthorization(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.verifyStoredCustodyAuthorization(signed); err != nil {
		t.Fatalf("a custody authorization did not verify: %v", err)
	}
	preimage, err := commerce.CustodyActionAuthorizationPreimage(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(preimage)
	swapped, err := testAuthorityCustody.Sign(t.Context(), CustodyAuthorizationController, mldsa44.UseActionAuthority, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	actionContext := signed
	actionContext.Proof, err = mldsa44.SignatureText(swapped.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.verifyStoredCustodyAuthorization(actionContext); err == nil {
		t.Fatal("a custody authorization signed under the Action Authority context verified")
	}
	otherKey := signed
	otherKey.KeyID = testAuthorityKeys().ActionKeyID
	if err := authority.verifyStoredCustodyAuthorization(otherKey); err == nil {
		t.Fatal("a custody authorization naming the Action Authority key verified")
	}
}

func relayCustodyAuthorizationFixture(t *testing.T) commerce.CustodyActionAuthorization {
	t.Helper()
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	return commerce.CustodyActionAuthorization{SchemaVersion: 1, OwnerID: "owner", AgentID: "agent",
		AuthorityID: "authority", SourceAccount: "0:" + strings.Repeat("8", 64), NetworkID: "tos:test",
		NetworkGlobalID: 3, StableActionID: digest("1"), ExactRequestDigest: digest("2"), WriterGeneration: 1,
		WriterFenceDigest: digest("6"), PolicyRevision: 1, MandateDigest: digest("7"), ApprovalDigestOrZero: digest("0"),
		AgreementBodyDigest: digest("3"), ObligationInstanceID: digest("4"), Destination: "0:" + strings.Repeat("9", 64),
		AmountAtomic: 1, ExpiresAtUnix: uint64(time.Now().Add(time.Hour).Unix())}
}

// newRealCustody creates a private file vault holding the named controllers
// through the real helper and returns the helper configuration that reaches it.
func newRealCustody(t *testing.T, names ...string) (TOSCTLAuthorityHelper, map[string]string) {
	t.Helper()
	helper := TOSCTLAuthorityHelper{Binary: os.Getenv(mldsa44test.BinaryEnvironment), SHA256: os.Getenv(mldsa44test.SHA256Environment)}
	directory, err := os.MkdirTemp("", "openfox-authority-custody-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	helper.VaultURL = "file://" + filepath.Join(directory, "vault.json") + "?master_key=" + hex.EncodeToString(master)
	helper.ConfigPath = filepath.Join(directory, "tosctl-config.json")
	run := func(args ...string) []byte {
		command := exec.Command(helper.Binary, args...)
		command.Env, command.Dir = []string{"VAULT_URL=" + helper.VaultURL}, "/"
		output, err := command.Output()
		if err != nil {
			t.Fatalf("tosctl %s failed", args[0])
		}
		return output
	}
	run("config", "generate", "--output="+helper.ConfigPath)
	ids := map[string]string{}
	for _, name := range names {
		var created struct {
			KeyID string `json:"key_id"`
		}
		if err := json.Unmarshal(run("agent", "native-registry", "new-controller", "--config", helper.ConfigPath,
			"--name", name, "--format", "json"), &created); err != nil {
			t.Fatal(err)
		}
		ids[name] = "mldsa44:" + created.KeyID
	}
	return helper, ids
}

// TestControllerKeyReadThroughRealTOSCTL needs the real helper named by
// TOS_SERVICE_TOSCTL and TOS_SERVICE_TOSCTL_SHA256; it is skipped, and says
// so, when they are absent.
func TestControllerKeyReadThroughRealTOSCTL(t *testing.T) {
	if os.Getenv(mldsa44test.BinaryEnvironment) == "" {
		t.Skip("set " + mldsa44test.BinaryEnvironment + " and " + mldsa44test.SHA256Environment + " to read controller keys through real tosctl")
	}
	helper, ids := newRealCustody(t, ActionAuthorityController, CustodyAuthorizationController)
	keys, err := OpenTOSCTLAuthorityKeys(t.Context(), helper, ids[ActionAuthorityController], ids[CustodyAuthorizationController])
	if err != nil {
		t.Fatalf("controller keys did not read through tosctl: %v", err)
	}
	if derived, err := mldsa44.KeyID(keys.ActionPublicKey); err != nil || mldsa44.KeyIDText(derived) != ids[ActionAuthorityController] {
		t.Fatal("tosctl returned another Action Authority key")
	}
	if _, err := OpenTOSCTLAuthorityKeys(t.Context(), helper, ids[CustodyAuthorizationController],
		ids[CustodyAuthorizationController]); err == nil {
		t.Fatal("a configured key ID that the controller key does not derive was accepted")
	}
	wrongPin := helper
	wrongPin.SHA256 = strings.Repeat("0", 64)
	if _, err := OpenTOSCTLAuthorityKeys(t.Context(), wrongPin, ids[ActionAuthorityController],
		ids[CustodyAuthorizationController]); err == nil {
		t.Fatal("a tosctl binary with another SHA-256 was run")
	}
	authority, err := OpenPersonalAuthority(privateTempDir(t), "owner", "agent", "authority", keys, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	fence, err := authority.AcquireWriter(t.Context(), "instance", []string{"payment.direct"}, time.Hour)
	if err != nil {
		t.Fatalf("real custody did not sign a writer fence: %v", err)
	}
	if err := commerce.VerifyWriterFence(fence, authority, time.Now(), "payment.direct"); err != nil {
		t.Fatalf("a real ML-DSA-44 writer fence did not verify: %v", err)
	}
}
