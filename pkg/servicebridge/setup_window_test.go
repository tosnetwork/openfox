package servicebridge

import (
	"context"
	"testing"
)

// The inclusion window of the Capability registration is counted from the
// moment the wallet message is handed over, not from the start of the
// build that precedes it: the build may take as long as a tosctl call, and
// the wallet message is signed only after it.
func TestTheCapabilityWindowStartsWhenTheWalletMessageIsHandedOver(t *testing.T) {
	const buildSeconds = 200
	f := newSetupFixture(t)
	f.mustInit(t)
	f.script("wallet send", fakeLost)
	started := f.world().Clock
	// The registration build takes 200 seconds, then the send is lost.
	slow := hookedEnv(f, "agent native-registry action", func(w *fakeWorld) { w.Clock += buildSeconds })
	_, err := RunOffer(context.Background(), f.offer, slow)
	mustFail(t, err, ErrOutcomeUnknown)
	step := f.journal(t).Offer.Capability
	if step.State != stepSending || step.StartedUnix < started+buildSeconds {
		t.Fatalf("the step is stamped %d, before the wallet message was handed over at %d or later: %+v",
			step.StartedUnix, started+buildSeconds, step)
	}
	sends := f.world().count("wallet send")
	// A wallet message signed when the build ended is still valid when a
	// window counted from the start of the build has passed.
	f.change(func(w *fakeWorld) { w.Clock = started + int64(sendResolutionWindow.Seconds()) + 1 })
	_, err = RunOffer(context.Background(), f.offer, f.env())
	mustFail(t, err, ErrOutcomeUnknown, "nothing was re-sent")
	if f.world().count("wallet send") != sends {
		t.Fatal("the registration was sent again while its first wallet message could still be included")
	}
	// Past the window counted from the handover it is sent again, once.
	f.change(func(w *fakeWorld) { w.Clock = step.StartedUnix + int64(sendResolutionWindow.Seconds()) + 1 })
	f.mustOffer(t)
	if f.world().count("wallet send") != sends+1 {
		t.Fatalf("after the window: %d sends, want %d", f.world().count("wallet send"), sends+1)
	}
}

// Whether an earlier message can still be included is decided on finalized
// chain time alone. The host's clock neither ends the window early nor
// keeps it open.
func TestTheInclusionWindowEndsOnFinalizedChainTimeNotOnTheLocalClock(t *testing.T) {
	window := int64(sendResolutionWindow.Seconds())
	t.Run("init: local time past the window, chain time not", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeKillBefore)
		f.runKilled(t, "init", f.init)
		f.change(func(w *fakeWorld) { w.LocalAhead = window + 600 })
		_, err := RunInit(context.Background(), f.init, f.env())
		mustFail(t, err, ErrOutcomeUnknown, "nothing was re-sent")
		if f.world().count("wallet send") != 1 {
			t.Fatal("the local clock ended the inclusion window")
		}
	})
	t.Run("init: chain time past the window, local time not", func(t *testing.T) {
		f := newSetupFixture(t)
		f.script("wallet send", fakeKillBefore)
		f.runKilled(t, "init", f.init)
		f.change(func(w *fakeWorld) { w.Clock += window + 1; w.LocalAhead = -(window + 1) })
		f.mustInit(t)
		if f.world().count("wallet send") != 2 {
			t.Fatal("a registration past its window on chain time was not sent again")
		}
	})
	t.Run("withdraw: local time past the window, chain time not", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeKillBefore)
		f.runKilled(t, "withdraw", in)
		f.change(func(w *fakeWorld) { w.LocalAhead = window + 600 })
		_, err := RunWithdraw(context.Background(), in, f.env())
		mustFail(t, err, ErrWithdrawalPending)
		if f.world().count(withdrawLabel) != 1 {
			t.Fatal("the local clock ended the withdrawal's inclusion window")
		}
	})
	t.Run("withdraw: chain time past the window, local time not", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeKillBefore)
		f.runKilled(t, "withdraw", in)
		f.change(func(w *fakeWorld) { w.Clock += window + 1; w.LocalAhead = -(window + 1) })
		if _, err := RunWithdraw(context.Background(), in, f.env()); err != nil {
			t.Fatal(err)
		}
		records := withdrawals(t, f)
		if len(records) != 2 || f.world().count(withdrawLabel) != 2 {
			t.Fatalf("a withdrawal past its window on chain time was not sent again: %+v", records)
		}
	})
}

// A wallet whose messages carry no expiry never sends: for it "the earlier
// message can no longer be included" is never true.
func TestOnlyAWalletWhoseMessagesExpireSends(t *testing.T) {
	for _, walletType := range []string{"V1R3", "V2R2", "unknown"} {
		t.Run("init "+walletType, func(t *testing.T) {
			f := newSetupFixture(t)
			f.change(func(w *fakeWorld) { w.WalletType = walletType })
			_, err := RunInit(context.Background(), f.init, f.env())
			mustFail(t, err, ErrWalletTypeUnsupported, walletType, "V3R2, V4R2 or V5R1")
			world := f.world()
			if world.sends() != 0 || world.count("agent native-registry register-agent") != 0 {
				t.Fatalf("a %s wallet signed or sent: %+v", walletType, world.Calls)
			}
		})
		t.Run("offer "+walletType, func(t *testing.T) {
			f := newSetupFixture(t)
			f.mustInit(t)
			f.change(func(w *fakeWorld) { w.WalletType = walletType })
			before := f.world().sends()
			_, err := RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, ErrWalletTypeUnsupported, walletType)
			if world := f.world(); world.sends() != before || world.Actor != nil {
				t.Fatalf("a %s wallet deployed or sent", walletType)
			}
		})
		t.Run("offer resumed "+walletType, func(t *testing.T) {
			// The deployment is finalized; the remaining steps are refused
			// too, though they do not pass the funding check.
			f := newSetupFixture(t)
			f.mustInit(t)
			f.script("wallet send", fakeRefuseBalance)
			if _, err := RunOffer(context.Background(), f.offer, f.env()); err == nil {
				t.Fatal("the scripted refusal did not stop the offer")
			}
			if f.world().Actor == nil {
				t.Fatal("the deployment did not land, so this case tests nothing")
			}
			f.change(func(w *fakeWorld) { w.WalletType = walletType })
			before := f.world().sends()
			_, err := RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, ErrWalletTypeUnsupported, walletType)
			if f.world().sends() != before {
				t.Fatalf("a %s wallet sent the Capability registration", walletType)
			}
		})
		t.Run("withdraw "+walletType, func(t *testing.T) {
			f, in := newWithdrawFixture(t, 5_000_000_000)
			in.AmountNano = 1_000_000_000
			f.change(func(w *fakeWorld) { w.WalletType = walletType })
			_, err := RunWithdraw(context.Background(), in, f.env())
			mustFail(t, err, ErrWalletTypeUnsupported, walletType)
			if f.world().count(withdrawLabel) != 0 || len(withdrawals(t, f)) != 0 {
				t.Fatalf("a %s wallet sent or recorded a withdrawal", walletType)
			}
		})
	}
	t.Run("a type tosctl did not report", func(t *testing.T) {
		wallet := WalletView{Name: "provider", Address: fakeWalletAddress, StateKnown: true, State: "active"}
		mustFail(t, requireExpiringWallet(wallet), ErrWalletTypeUnsupported, "did not report the type")
	})
	for _, walletType := range []string{"V3R2", "V4R2", "V5R1"} {
		wallet := WalletView{Name: "provider", Address: fakeWalletAddress, Type: walletType}
		if err := requireExpiringWallet(wallet); err != nil {
			t.Fatalf("%s was refused: %v", walletType, err)
		}
	}
}
