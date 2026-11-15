package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

// publishedOffer is a fixture with a finalized offer and its offer file.
func publishedOffer(t *testing.T) (*setupFixture, Offer, []byte) {
	t.Helper()
	f := newSetupFixture(t)
	f.mustInit(t)
	result := f.mustOffer(t)
	offer, err := ReadOfferFile(result.OfferFile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOfferFile(offer, time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return f, offer, raw
}

func TestAnOfferFileIsDecodedStrictly(t *testing.T) {
	_, offer, raw := publishedOffer(t)
	if decoded, err := DecodeOfferFile(raw); err != nil || decoded.CapabilityID != offer.CapabilityID ||
		!bytes.Equal(decoded.ManifestCBOR, offer.ManifestCBOR) {
		t.Fatalf("the untampered file did not decode: %v", err)
	}
	edit := func(change func(map[string]any)) []byte {
		t.Helper()
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		change(fields)
		out, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	otherManifest, otherDigest, _, err := BuildManifest(ManifestInput{
		ProviderAgentID:  offer.ProviderAgentID,
		Actor:            "0:" + strings.Repeat("42", 32),
		ActorCodeHash:    fakeCodeHashActor,
		Attestor:         fakeKey("someone").Text(),
		Version:          offer.Version,
		RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"wrong digest": edit(func(f map[string]any) { f["manifest_digest"] = "sha256:" + strings.Repeat("ab", 32) }),
		"manifest swapped under the stated digest": edit(func(f map[string]any) {
			f["manifest_cbor_base64"] = base64.StdEncoding.EncodeToString(otherManifest)
		}),
		"manifest of another version": edit(func(f map[string]any) { f["version"] = "9.9.9" }),
		"malformed capability":        edit(func(f map[string]any) { f["capability_id"] = "cap_zz" }),
		"malformed provider":          edit(func(f map[string]any) { f["provider_agent_id"] = "agent" }),
		"unknown field":               edit(func(f map[string]any) { f["gateway"] = "https://example.invalid" }),
		"another schema":              edit(func(f map[string]any) { f["schema"] = "tos.openfox.rail-offer.v3" }),
		"the previous schema":         edit(func(f map[string]any) { f["schema"] = "tos.openfox.rail-offer.v1" }),
		"non-canonical manifest": edit(func(f map[string]any) {
			f["manifest_cbor_base64"] = base64.StdEncoding.EncodeToString(append(offer.ManifestCBOR, 0))
		}),
		"manifest not base64": edit(func(f map[string]any) { f["manifest_cbor_base64"] = "%%%" }),
		"trailing data":       append(append([]byte(nil), raw...), []byte(`{"schema":"x"}`)...),
		"trailing garbage":    append(append([]byte(nil), raw...), 'x'),
		"empty":               nil,
		"oversize":            bytes.Repeat([]byte(" "), maxOfferFile+1),
	}
	for name, tampered := range cases {
		if _, err := DecodeOfferFile(tampered); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A consistent file for another manifest decodes: only finalized state
	// can refuse it, which the quote source does.
	consistent := edit(func(f map[string]any) {
		f["manifest_digest"] = otherDigest
		f["manifest_cbor_base64"] = base64.StdEncoding.EncodeToString(otherManifest)
	})
	if _, err := DecodeOfferFile(consistent); err != nil {
		t.Fatalf("a self-consistent file was refused before finalized state was asked: %v", err)
	}
}

// offerSessions serves the fake world to the quote builder and the buyer.
type offerSessions struct{ path string }

func (s offerSessions) BeginSession(ctx context.Context) (serviceactor.Session, error) {
	return fakeChain(s).BeginRail(ctx)
}

type buyerSession struct{ fakeSession }

func (buyerSession) RegistryTransition(
	context.Context,
	string,
	nativecore.RegistryTransitionKind,
	string,
) (*toschain.RegistryTransitionTx, error) {
	return nil, toschain.ErrRegistryTransitionUnproven
}

func (buyerSession) GetRequest(context.Context, string, uint64) (*nativecore.ServiceActorRequestViewV1, error) {
	return nil, errors.New("not served by the fake")
}

func (buyerSession) GetRefund(context.Context, string, uint64) (*nativecore.ServiceActorRefundV1, error) {
	return nil, errors.New("not served by the fake")
}

func (s offerSessions) BeginBuyerSession(ctx context.Context) (buyersdk.ServiceActorSession, error) {
	session, err := fakeChain(s).BeginRail(ctx)
	if err != nil {
		return nil, err
	}
	return buyerSession{session.(fakeSession)}, nil
}

type recordingSender struct {
	calls []buyersdk.ServiceActorCallIntent
}

func (s *recordingSender) Preflight(context.Context, buyersdk.ServiceActorCallIntent) error {
	return nil
}

func (s *recordingSender) SendCall(_ context.Context, intent buyersdk.ServiceActorCallIntent) error {
	s.calls = append(s.calls, intent)
	return nil
}

type idleLifecycle struct{}

func (idleLifecycle) Respond(context.Context, string, uint64, [32]byte, string) error { return nil }
func (idleLifecycle) Expire(context.Context, string, uint64) error                    { return nil }
func (idleLifecycle) ClaimRefund(context.Context, string, uint64, string) error       { return nil }

func offerQuotes(f *setupFixture, offer Offer) OfferQuotes {
	world := f.world()
	return OfferQuotes{
		Sessions: offerSessions{path: f.worldPath}, Network: world.network(),
		RegistryCodeHash: "tvm-cell-sha256:" + world.CodeHash, Offer: offer,
		Now: func() time.Time { return time.Unix(loadWorld(f.worldPath).Clock, 0) },
	}
}

func offerRequest(offer Offer) *nativev1.RequestQuoteProposalRequest {
	return &nativev1.RequestQuoteProposalRequest{
		CapabilityId: offer.CapabilityID, CapabilityVersion: offer.Version, BuyerAddress: testWallet,
	}
}

// The package built from an offer file goes through the unchanged purchase
// path: the protocol's discovery, package validation, the purchase checks,
// the comparison with the finalized offer and the admission in Prepare.
func TestBuyFromAnOfferFileGoesThroughTheExistingPurchasePath(t *testing.T) {
	f, offer, _ := publishedOffer(t)
	world := f.world()
	now := func() time.Time { return time.Unix(loadWorld(f.worldPath).Clock, 0) }
	manifests := &MemoryManifests{}
	quotes := &PackageQuotes{manifests: manifests}
	quotes.UseSource(offerQuotes(f, offer))
	if err := ensurePrivateDirectory(filepath.Join(f.root, "calls")); err != nil {
		t.Fatal(err)
	}
	journal, err := buyersdk.OpenServiceActorJournal(filepath.Join(f.root, "calls"), now())
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	sdk, err := buyersdk.NewServiceActorBuyer(buyersdk.ServiceActorBuyerConfig{
		Reader: offerSessions{path: f.worldPath}, Manifests: manifests, Network: world.network(),
		ActorCodeHash: fakeCodeHashActor, BuyerWallet: testWallet, Sender: sender, Journal: journal,
		Limits: buyersdk.ServiceActorLimits{
			Window: time.Hour, MaxCalls: 4, MaxPerCallNanoTOS: big.NewInt(2_000_000_000),
			MaxWindowNanoTOS: big.NewInt(10_000_000_000),
		},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	courier, err := OpenCourier(filepath.Join(f.root, "outbox"), testSigner(t, testBuyer), &recordingTransport{})
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := NewBuyer(BuyerConfig{
		AgentID: testBuyer, Wallet: testWallet, Network: world.network(), Buyer: sdk, Quotes: quotes,
		Policy: SpendingPolicy{
			MaxCommittedPerPurchase: big.NewInt(2_000_000_000), MaxCommittedInWindow: big.NewInt(10_000_000_000),
			Window: time.Hour, MaxOpenPurchases: 4, RefundReserve: big.NewInt(300_000_000),
			AllowedProviders: map[string]bool{offer.ProviderAgentID: true},
		},
		Courier: courier, Lifecycle: idleLifecycle{}, Directory: filepath.Join(f.root, "purchases"), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := buyer.Buy(context.Background(), offer.CapabilityID, offer.Version, []byte("a source archive"))
	if err != nil {
		t.Fatalf("the purchase path refused the package built from the offer file: %v", err)
	}
	if record.Schema != purchaseRecordSchema || record.Phase != PurchaseCalled ||
		record.ProviderAgentID != offer.ProviderAgentID ||
		record.ManifestDigest != offer.ManifestDigest || record.Actor != world.Actor.Address ||
		record.PriceNanoTOS != "300000000" {
		t.Fatalf("record = %+v", record)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("calls = %d", len(sender.calls))
	}
	// The call commits to the finalized terms and the finalized price.
	account, _, _ := fakeSession{world: world}.ReadActor(context.Background(), world.Actor.Address)
	terms, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(account.Data.Policy))
	if err != nil {
		t.Fatal(err)
	}
	intent := sender.calls[0]
	if intent.ExpectedTermsHash != terms || intent.Price.String() != "300000000" ||
		intent.StorageFee.String() != "250000000" || intent.Actor != world.Actor.Address {
		t.Fatalf("intent = %+v", intent)
	}

	// `serve` is another process than the `buy` that took the Quote: it
	// starts with no manifest in memory and must resolve the purchase from
	// what the purchase stored.
	served := &MemoryManifests{}
	if _, missing := served.Manifest(context.Background(), offer.ManifestDigest); missing == nil {
		t.Fatal("a new manifest store already holds the manifest, so the check below proves nothing")
	}
	servedSDK, err := buyersdk.NewServiceActorBuyer(buyersdk.ServiceActorBuyerConfig{
		Reader: offerSessions{path: f.worldPath}, Manifests: served, Network: world.network(),
		ActorCodeHash: fakeCodeHashActor, BuyerWallet: testWallet, Sender: sender, Journal: journal,
		Limits: buyersdk.ServiceActorLimits{
			Window: time.Hour, MaxCalls: 4, MaxPerCallNanoTOS: big.NewInt(2_000_000_000),
			MaxWindowNanoTOS: big.NewInt(10_000_000_000),
		},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	serving, err := NewBuyer(BuyerConfig{
		AgentID: testBuyer, Wallet: testWallet, Network: world.network(), Buyer: servedSDK,
		Quotes: &PackageQuotes{manifests: served},
		Policy: SpendingPolicy{
			MaxCommittedPerPurchase: big.NewInt(2_000_000_000), MaxCommittedInWindow: big.NewInt(10_000_000_000),
			Window: time.Hour, MaxOpenPurchases: 4, RefundReserve: big.NewInt(300_000_000),
			AllowedProviders: map[string]bool{offer.ProviderAgentID: true},
		},
		Courier: courier, Lifecycle: idleLifecycle{}, Directory: filepath.Join(f.root, "purchases"),
		Manifests: served, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fake chain serves no request getter, so the advance stops later;
	// it must not stop for want of the manifest.
	advanceErr := serving.Advance(context.Background())
	if advanceErr != nil && strings.Contains(advanceErr.Error(), "manifest") {
		t.Fatalf("a serving process cannot resolve a purchase made by another process: %v", advanceErr)
	}
	restored, err := served.Manifest(context.Background(), offer.ManifestDigest)
	if err != nil || !bytes.Equal(restored, offer.ManifestCBOR) {
		t.Fatalf("the serving process did not restore the purchase's manifest: %v", err)
	}
	// A stored package whose manifest bytes were damaged is not handed on:
	// the good entry stays, and the purchase stops with the reason.
	packagePath := filepath.Join(f.root, "purchases", record.RequestHash, "quote-package")
	raw, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	stored := &nativev1.QuoteProposalPackageV1{}
	if err = proto.Unmarshal(raw, stored); err != nil {
		t.Fatal(err)
	}
	damaged := append([]byte(nil), stored.GetCanonicalManifestCbor()...)
	damaged[bytes.Index(damaged, []byte("Deterministic"))] ^= 0x01
	stored.CanonicalManifestCbor = damaged
	if raw, err = proto.Marshal(stored); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(packagePath); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, packagePath, raw, 0o600)
	advanceErr = serving.Advance(context.Background())
	if advanceErr == nil || !strings.Contains(advanceErr.Error(), "does not hash to the digest its record names") {
		t.Fatalf("a damaged stored manifest was not refused: %v", advanceErr)
	}
	kept, err := served.Manifest(context.Background(), offer.ManifestDigest)
	if err != nil || !bytes.Equal(kept, offer.ManifestCBOR) {
		t.Fatalf("a damaged stored manifest replaced the good entry: %v", err)
	}
}

func TestTheOfferQuoteSourceBuildsAPackageTheBuyerChecksAccept(t *testing.T) {
	f, offer, _ := publishedOffer(t)
	source := offerQuotes(f, offer)
	request := offerRequest(offer)
	pkg, err := source.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	world := f.world()
	validated, err := quoteexchange.Validate(world.network(), request, pkg, time.Unix(world.Clock, 0))
	if err != nil {
		t.Fatalf("the built package does not validate: %v", err)
	}
	if err = CheckPurchaseQuote(validated, MaxInlineInputBytes); err != nil {
		t.Fatalf("the built package does not deliver as Agent Packets to its provider: %v", err)
	}
	proposal := pkg.GetProposal()
	_, transport, err := RailTransport(offer.ProviderAgentID)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.GetProviderAgentId() != offer.ProviderAgentID || proposal.GetTransportBindingDigest() != transport ||
		proposal.GetManifestDigest() != offer.ManifestDigest || proposal.GetPriceNanotos() != "300000000" ||
		proposal.GetExpiresAtUnixSeconds() != uint64(world.Clock)+uint64(OfferQuoteTTL.Seconds()) ||
		hex.EncodeToString(proposal.GetActor().GetAccountId()) != world.Actor.Address[2:] {
		t.Fatalf("proposal = %+v", proposal)
	}
}

func TestTheOfferQuoteSourceRefusesWhatFinalizedStateContradicts(t *testing.T) {
	otherManifest := func(t *testing.T, offer Offer) Offer {
		t.Helper()
		manifest, digest, _, err := BuildManifest(ManifestInput{
			ProviderAgentID: offer.ProviderAgentID, Actor: "0:" + strings.Repeat("42", 32),
			ActorCodeHash: fakeCodeHashActor, Attestor: fakeKey("someone").Text(), Version: offer.Version,
			RetentionSeconds: 86400,
		})
		if err != nil {
			t.Fatal(err)
		}
		offer.ManifestCBOR, offer.ManifestDigest = manifest, digest
		return offer
	}
	cases := map[string]struct {
		offer   func(*testing.T, Offer) Offer
		world   func(*fakeWorld, Offer)
		request func(*nativev1.RequestQuoteProposalRequest)
		// mismatch is set where the refusal must be this node's own check
		// of the offer against finalized state, made before any package is
		// built.
		mismatch bool
	}{
		"a manifest that is not the finalized one": {offer: otherManifest, mismatch: true},
		"a provider that is not the finalized owner": {offer: func(_ *testing.T, o Offer) Offer {
			o.ProviderAgentID = testBuyer
			return o
		}, mismatch: true},
		"a Capability that is not registered": {
			world: func(w *fakeWorld, o Offer) { delete(w.Capabilities, o.CapabilityID) },
		},
		"a Capability transferred to another owner": {world: func(w *fakeWorld, o Offer) {
			capability := w.Capabilities[o.CapabilityID]
			capability.Owner = testBuyer
			w.Capabilities[o.CapabilityID] = capability
		}},
		"a version the Capability does not have": {world: func(w *fakeWorld, o Offer) {
			capability := w.Capabilities[o.CapabilityID]
			capability.Version = "2.0.0"
			w.Capabilities[o.CapabilityID] = capability
		}},
		"a request for another Capability": {request: func(r *nativev1.RequestQuoteProposalRequest) {
			r.CapabilityId = "cap_" + strings.Repeat("33", 32)
		}, mismatch: true},
		"an actor whose policy names another Capability": {world: func(w *fakeWorld, _ Offer) {
			w.Actor.Metadata = strings.Repeat("ab", 32)
		}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f, offer, _ := publishedOffer(t)
			if test.world != nil {
				f.change(func(w *fakeWorld) { test.world(w, offer) })
			}
			request := offerRequest(offer)
			if test.request != nil {
				test.request(request)
			}
			if test.offer != nil {
				offer = test.offer(t, offer)
			}
			pkg, err := offerQuotes(f, offer).Quote(context.Background(), request)
			if err == nil {
				t.Fatalf("a package was built: %+v", pkg.GetProposal())
			}
			if test.mismatch && !errors.Is(err, ErrOfferMismatch) {
				t.Fatalf("the offer was not refused against finalized state before building: %v", err)
			}
		})
	}
}

func TestExactlyOneQuoteSourceIsUsed(t *testing.T) {
	quotes := &PackageQuotes{manifests: &MemoryManifests{}}
	request := &nativev1.RequestQuoteProposalRequest{
		CapabilityId:      "cap_" + strings.Repeat("33", 32),
		CapabilityVersion: "1.0.0",
	}
	if _, err := quotes.Quote(context.Background(), request); err == nil {
		t.Fatal("a Quote came from nowhere")
	}
	quotes.UsePackage(&nativev1.QuoteProposalPackageV1{})
	quotes.UseSource(FixedQuote{})
	if _, err := quotes.Quote(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "more than one Quote source") {
		t.Fatalf("two sources were accepted: %v", err)
	}
}
