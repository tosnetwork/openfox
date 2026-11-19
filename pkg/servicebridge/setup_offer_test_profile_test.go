package servicebridge

import (
	"context"
	"errors"
	"testing"
)

func tenMinuteTerms(in *OfferInput) {
	in.Terms.ResponseSLA, in.Terms.RefundClaimWindow = MinTestProfileWindowSecs, MinTestProfileWindowSecs
}

// A ten-minute offer deploys the test-network-only build, and only when the
// rail configuration pins its code hash.
func TestATestProfileOfferDeploysTheTestBuildWithTenMinuteWindows(t *testing.T) {
	f := newSetupFixture(t)
	f.init.ActorCodeHash = TestProfileActorCodeHash
	f.mustInit(t)
	f.offer.TestProfileActor = true
	tenMinuteTerms(&f.offer)
	result := f.mustOffer(t)
	world := f.world()
	for _, label := range []string{"agent service build-state", "agent service deploy"} {
		if got := fakeArgument(world.last(label).Args, "--code-profile"); got != "test" {
			t.Fatalf("%s --code-profile = %q, want test", label, got)
		}
	}
	deploy := world.last("agent service deploy")
	if fakeArgument(deploy.Args, "--response-sla") != "600" || fakeArgument(deploy.Args, "--refund-claim-window") != "600" {
		t.Fatalf("deploy args = %v", deploy.Args)
	}
	if world.Actor == nil || world.Actor.CodeHash != TestProfileActorCodeHash {
		t.Fatalf("the deployed actor runs %+v", world.Actor)
	}
	if result.Preview == nil || result.Preview.ActorCodeHash != TestProfileActorCodeHash ||
		result.Preview.Note == offerPreviewNote {
		t.Fatalf("the preview does not say it deploys the test build: %+v", result.Preview)
	}
}

// Without the flag and the pin together nothing is run: the release
// configuration refuses ten-minute windows and the test flag, and the test
// pin refuses an offer that does not say it is a test.
func TestATestProfileOfferIsRefusedUnlessFlagAndPinAgree(t *testing.T) {
	nineMinutes := func(in *OfferInput) { tenMinuteTerms(in); in.Terms.ResponseSLA-- }
	keep := func(*OfferInput) {}
	cases := map[string]struct {
		pinTest, flag  bool
		terms          func(*OfferInput)
		wantProfileErr bool
	}{
		"release pin, ten minutes":               {false, false, tenMinuteTerms, false},
		"release pin, test flag":                 {false, true, keep, true},
		"release pin, test flag and ten minutes": {false, true, tenMinuteTerms, true},
		"test pin, no flag":                      {true, false, keep, true},
		"test pin, no flag, ten minutes":         {true, false, tenMinuteTerms, false},
		"test pin, flag, one second under ten":   {true, true, nineMinutes, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			if c.pinTest {
				f.init.ActorCodeHash = TestProfileActorCodeHash
			}
			f.mustInit(t)
			f.offer.TestProfileActor = c.flag
			c.terms(&f.offer)
			calls := len(f.world().Calls)
			_, err := RunOffer(context.Background(), f.offer, f.env())
			if err == nil {
				t.Fatal("accepted")
			}
			if errors.Is(err, ErrActorProfile) != c.wantProfileErr {
				t.Fatalf("error %v, want ErrActorProfile %v", err, c.wantProfileErr)
			}
			if len(f.world().Calls) != calls {
				t.Fatalf("tosctl was run: %+v", f.world().Calls[calls:])
			}
		})
	}
}

func TestReleaseTermsKeepTheHourLowerBound(t *testing.T) {
	terms := ActorTerms{PriceNano: 1, StorageFeeNano: MinStorageFeeBaseNano + MinCleanupBountyNano,
		CleanupBountyNano: MinCleanupBountyNano, ResponseSLA: MinTestProfileWindowSecs, RefundClaimWindow: MinTestProfileWindowSecs}
	if terms.Validate() == nil || terms.ValidateFor(false) == nil {
		t.Fatal("the release bounds accepted ten-minute windows")
	}
	if err := terms.ValidateFor(true); err != nil {
		t.Fatalf("the test-profile bounds refused ten-minute windows: %v", err)
	}
	terms.RefundClaimWindow = MinTestProfileWindowSecs - 1
	if terms.ValidateFor(true) == nil {
		t.Fatal("the test-profile bounds accepted a window below ten minutes")
	}
	if MinTestProfileWindowSecs != 600 || MinPolicyWindowSecs != 3_600 {
		t.Fatalf("bounds %d / %d", MinTestProfileWindowSecs, MinPolicyWindowSecs)
	}
	if TestProfileActorCodeHash != "tvm-cell-sha256:79a566f5f4281f7abe59cd1c16a7bc3b2d990e840f42b00d55cb0ae4b0545960" {
		t.Fatalf("test-profile code hash %s", TestProfileActorCodeHash)
	}
}
