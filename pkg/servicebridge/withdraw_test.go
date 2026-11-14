package servicebridge

import (
	"context"
	"strings"
	"testing"
	"time"
)

// newWithdrawFixture is a published provider whose actor holds revenue.
func newWithdrawFixture(t *testing.T, revenue uint64) (*setupFixture, WithdrawInput) {
	t.Helper()
	f := newSetupFixture(t)
	f.mustInit(t)
	f.mustOffer(t)
	f.change(func(w *fakeWorld) { w.Actor.Revenue = revenue })
	return f, WithdrawInput{RailConfigPath: f.init.RailConfigPath, Yes: true}
}

func withdrawals(t *testing.T, f *setupFixture) []WithdrawalRecord {
	t.Helper()
	records, err := ReadWithdrawals(f.init.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

const withdrawLabel = "agent service send withdraw-revenue"

func TestWithdrawSendsExactlyThePreviewedAmountAndRecordsItsFinalizedOutcome(t *testing.T) {
	f, in := newWithdrawFixture(t, 5_000_000_000)
	in.AmountNano = 1_250_000_001
	result, err := RunWithdraw(context.Background(), in, f.env())
	if err != nil {
		t.Fatal(err)
	}
	world := f.world()
	send := world.last(withdrawLabel)
	if fakeArgument(send.Args, "--withdraw-amount") != "1.250000001" ||
		fakeArgument(send.Args, "--from") != fakeWalletName ||
		fakeArgument(send.Args, "--address") != world.Actor.Address {
		t.Fatalf("send = %v", send.Args)
	}
	if world.Actor.Revenue != 3_749_999_999 {
		t.Fatalf("revenue = %d", world.Actor.Revenue)
	}
	preview := result.Preview
	if preview.Destination != fakeWalletAddress || preview.AmountNano != "1250000001" ||
		preview.CreditedNano != "5000000000" || preview.RemainingNano != "3749999999" || preview.AttachedNano != "200000000" {
		t.Fatalf("preview = %+v", preview)
	}
	records := withdrawals(t, f)
	if len(records) != 1 {
		t.Fatalf("records = %+v", records)
	}
	record := records[0]
	if record.State != WithdrawalFinalized || record.PayoutNano != "1250000001" ||
		record.CreditedAfterNano != "3749999999" ||
		record.WalletCredit != WalletCreditNotVerified ||
		record.TransactionHash == "" ||
		fakeArgument(send.Args, "--query-id") == "" ||
		record.Destination != fakeWalletAddress {
		t.Fatalf("record = %+v", record)
	}
	// Status lists it and still claims nothing about the wallet.
	config, err := LoadNodeConfig(in.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadProviderStatus(
		context.Background(),
		config,
		fakeStatusChain{path: f.worldPath},
		time.Unix(f.world().Clock, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Withdrawals) != 1 || status.Withdrawals[0].State != WithdrawalFinalized ||
		status.Withdrawals[0].WalletCredit != WalletCreditNotVerified || status.Actor.WalletReceipt != walletReceiptNotTracked ||
		status.Actor.CreditedRevenueNanoTOS != "3749999999" {
		t.Fatalf("status = %+v actor %+v", status.Withdrawals, status.Actor)
	}
	// --all takes exactly what is credited.
	all := WithdrawInput{RailConfigPath: in.RailConfigPath, All: true, Yes: true}
	if _, err = RunWithdraw(context.Background(), all, f.env()); err != nil {
		t.Fatal(err)
	}
	if world = f.world(); world.Actor.Revenue != 0 ||
		fakeArgument(world.last(withdrawLabel).Args, "--withdraw-amount") != "3.749999999" {
		t.Fatalf("--all left %d", world.Actor.Revenue)
	}
	_, err = RunWithdraw(context.Background(), all, f.env())
	mustFail(t, err, ErrNothingToWithdraw)
}

// fakeStatusChain adapts the fake world to the status reader.
type fakeStatusChain struct{ path string }

func (c fakeStatusChain) BeginStatus(ctx context.Context) (StatusSession, error) {
	session, err := fakeChain(c).BeginRail(ctx)
	return session, err
}

func TestWithdrawRefusesZeroOverCreditAndAnotherOwnerBeforeSending(t *testing.T) {
	cases := map[string]struct {
		in     WithdrawInput
		change func(*fakeWorld)
		target error
	}{
		"zero":           {WithdrawInput{}, nil, ErrWithdrawZero},
		"one nano over":  {WithdrawInput{AmountNano: 5_000_000_001}, nil, ErrWithdrawOverCredit},
		"amount and all": {WithdrawInput{AmountNano: 1, All: true}, nil, nil},
		"nothing credited": {
			WithdrawInput{All: true},
			func(w *fakeWorld) { w.Actor.Revenue = 0 },
			ErrNothingToWithdraw,
		},
		"another owner": {
			WithdrawInput{AmountNano: 1},
			func(w *fakeWorld) { w.Actor.Owner = "0:" + strings.Repeat("31", 32) },
			nil,
		},
		"beyond exact tosctl": {
			WithdrawInput{All: true},
			func(w *fakeWorld) { w.Actor.Revenue = MaxTOSCTLAmountNano + 1 },
			nil,
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f, base := newWithdrawFixture(t, 5_000_000_000)
			if test.change != nil {
				f.change(test.change)
			}
			test.in.RailConfigPath, test.in.Yes = base.RailConfigPath, true
			_, err := RunWithdraw(context.Background(), test.in, f.env())
			mustFail(t, err, test.target)
			if world := f.world(); world.count(withdrawLabel) != 0 || world.Actor.Revenue == 0 && test.change == nil {
				t.Fatal("a refused withdrawal was sent")
			}
			if len(withdrawals(t, f)) != 0 {
				t.Fatal("a refused withdrawal was recorded")
			}
		})
	}
	// Exactly the credit is accepted.
	f, in := newWithdrawFixture(t, 5_000_000_000)
	in.AmountNano = 5_000_000_000
	if _, err := RunWithdraw(context.Background(), in, f.env()); err != nil {
		t.Fatal(err)
	}
}

func TestWithdrawWithoutYesPreviewsAndSendsNothing(t *testing.T) {
	f, in := newWithdrawFixture(t, 5_000_000_000)
	in.AmountNano, in.Yes = 1_000_000_000, false
	result, err := RunWithdraw(context.Background(), in, f.env())
	mustFail(t, err, ErrConfirmationRequired)
	if result.Preview == nil || result.Preview.AmountNano != "1000000000" || result.Confirmed {
		t.Fatalf("result = %+v", result)
	}
	if f.world().count(withdrawLabel) != 0 || len(withdrawals(t, f)) != 0 {
		t.Fatal("a withdrawal was sent or recorded without --yes")
	}
}

func TestWithdrawResolvesAnUnknownOutcomeFromFinalizedStateBeforeSendingAgain(t *testing.T) {
	t.Run("killed after the message landed", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeKillAfter)
		f.runKilled(t, "withdraw", in)
		if records := withdrawals(t, f); len(records) != 1 || records[0].State != WithdrawalSubmitted {
			t.Fatalf("the withdrawal was not recorded before it was sent: %+v", records)
		}
		// Revenue credited meanwhile does not hide the withdrawal.
		f.change(func(w *fakeWorld) { w.Actor.Revenue += 400_000_000 })
		if _, err := RunWithdraw(context.Background(), in, f.env()); err != nil {
			t.Fatal(err)
		}
		records := withdrawals(t, f)
		world := f.world()
		if len(records) != 2 || records[0].State != WithdrawalFinalized || records[1].State != WithdrawalFinalized ||
			world.count(withdrawLabel) != 2 || world.Actor.Revenue != 3_400_000_000 {
			t.Fatalf("records = %+v revenue %d", records, world.Actor.Revenue)
		}
	})
	t.Run("killed before the message had any effect", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeKillBefore)
		f.runKilled(t, "withdraw", in)
		_, err := RunWithdraw(context.Background(), in, f.env())
		mustFail(t, err, ErrWithdrawalPending)
		if f.world().count(withdrawLabel) != 1 {
			t.Fatal("a second withdrawal was sent while the first could still be included")
		}
		f.change(func(w *fakeWorld) { w.Clock += int64(sendResolutionWindow.Seconds()) + 1 })
		if _, err = RunWithdraw(context.Background(), in, f.env()); err != nil {
			t.Fatal(err)
		}
		records := withdrawals(t, f)
		world := f.world()
		if len(records) != 2 || records[1].State != WithdrawalNotIncluded || records[0].State != WithdrawalFinalized ||
			world.Actor.Revenue != 4_000_000_000 {
			t.Fatalf("records = %+v revenue %d", records, world.Actor.Revenue)
		}
	})
	t.Run("the send fails and nothing lands", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeLost)
		_, err := RunWithdraw(context.Background(), in, f.env())
		mustFail(t, err, ErrOutcomeUnknown)
		if records := withdrawals(t, f); len(records) != 1 || records[0].State != WithdrawalUnknown {
			t.Fatalf("records = %+v", records)
		}
		_, err = RunWithdraw(context.Background(), in, f.env())
		mustFail(t, err, ErrWithdrawalPending)
		if f.world().count(withdrawLabel) != 1 {
			t.Fatal("the unknown outcome was answered by sending again")
		}
	})
	t.Run("the send fails but the message landed", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeLandedError)
		if _, err := RunWithdraw(context.Background(), in, f.env()); err != nil {
			t.Fatal(err)
		}
		if records := withdrawals(t, f); records[0].State != WithdrawalFinalized {
			t.Fatalf("records = %+v", records)
		}
	})
	t.Run("the transaction is included and fails", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeFailedTx)
		_, err := RunWithdraw(context.Background(), in, f.env())
		mustFail(t, err, nil, WithdrawalFailed, "exit code 77")
		if records := withdrawals(
			t,
			f,
		); records[0].State != WithdrawalFailed ||
			f.world().Actor.Revenue != 5_000_000_000 {
			t.Fatalf("records = %+v", records)
		}
	})
	t.Run("tosctl refuses before broadcasting", func(t *testing.T) {
		f, in := newWithdrawFixture(t, 5_000_000_000)
		in.AmountNano = 1_000_000_000
		f.script(withdrawLabel, fakeRefuseBalance)
		_, err := RunWithdraw(context.Background(), in, f.env())
		mustFail(t, err, nil, string(TOSCTLFailureBalance))
		if records := withdrawals(t, f); records[0].State != WithdrawalNotIncluded {
			t.Fatalf("records = %+v", records)
		}
		// Nothing is in flight, so the next withdrawal is not blocked.
		if _, err = RunWithdraw(context.Background(), in, f.env()); err != nil {
			t.Fatal(err)
		}
	})
}

// A finalized transaction with another query id, another sender or another
// payout is not this withdrawal.
func TestAWithdrawalIsFinalizedOnlyByItsOwnTransaction(t *testing.T) {
	f, in := newWithdrawFixture(t, 5_000_000_000)
	in.AmountNano = 1_000_000_000
	f.script(withdrawLabel, fakeLost)
	if _, err := RunWithdraw(context.Background(), in, f.env()); err == nil {
		t.Fatal("the scripted failure did not happen")
	}
	record := withdrawals(t, f)[0]
	resolve := func(change func(*fakeWorld)) string {
		t.Helper()
		world := updateWorld(f.worldPath, change)
		resolved, err := resolveWithdrawal(context.Background(), fakeSession{world: world}, record)
		if err != nil {
			t.Fatal(err)
		}
		updateWorld(f.worldPath, func(w *fakeWorld) { w.History = nil })
		return resolved.State
	}
	own := func(w *fakeWorld) {
		w.History = append(w.History, f.withdrawTx(w, record.QueryID, fakeWalletAddress, record.AmountNano))
	}
	if state := resolve(own); state != WithdrawalFinalized {
		t.Fatalf("its own transaction resolved as %s", state)
	}
	for name, change := range map[string]func(*fakeWorld){
		"another query id": func(w *fakeWorld) {
			w.History = append(w.History, f.withdrawTx(w, record.QueryID+1, fakeWalletAddress, record.AmountNano))
		},
		"another sender": func(w *fakeWorld) {
			w.History = append(w.History, f.withdrawTx(w, record.QueryID, "0:"+strings.Repeat("31", 32), record.AmountNano))
		},
		"another payout": func(w *fakeWorld) {
			w.History = append(w.History, f.withdrawTx(w, record.QueryID, fakeWalletAddress, "999999999"))
		},
		"before the anchor": func(w *fakeWorld) {
			old := f.withdrawTx(w, record.QueryID, fakeWalletAddress, record.AmountNano)
			old.LT = record.Anchor.LT
			w.History = append(w.History, old)
		},
	} {
		if state := resolve(change); state == WithdrawalFinalized {
			t.Errorf("%s resolved the withdrawal as finalized", name)
		}
	}
}
