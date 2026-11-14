package servicebridge

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

func TestEveryRequestProjectsToOneExplicitOperatorState(t *testing.T) {
	const response = "aa"
	responseHash := strings.Repeat(response, 32)
	readFacts := func(history []toschain.ActorTransaction, complete bool, pending, refunds []uint64) *actorFacts {
		data := &nativecore.ServiceActorDataV1{
			Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{},
			Refunds: map[uint64]nativecore.ServiceActorRefundV1{},
		}
		for _, id := range pending {
			data.Pending[id] = nativecore.ServiceActorPendingRequestV1{}
		}
		for _, id := range refunds {
			data.Refunds[id] = nativecore.ServiceActorRefundV1{}
		}
		result := toschain.HistoryComplete
		if !complete {
			result = toschain.HistoryAnchorReached
		}
		return &actorFacts{
			read: true, found: true, account: &toschain.ActorAccount{Data: data},
			history: &toschain.ActorHistory{Result: result, Transactions: history},
		}
	}
	respond := func(hash string) []toschain.ActorTransaction {
		return []toschain.ActorTransaction{{Kind: toschain.ActorTxRespond, RequestID: 7, ResponseHash: hash}}
	}
	cases := []struct {
		name   string
		record string
		slot   railgate.SlotState
		facts  *actorFacts
		want   string
		fact   string
	}{
		{"admitted slot, chain not read", "", railgate.SlotAdmitted, nil, OperatorAdmitted, ChainFactNotRead},
		{
			"started slot, pending", "", railgate.SlotStarted, readFacts(nil, true, []uint64{7}, nil),
			OperatorExecuting, ChainFactPending,
		},
		{"ambiguous slot", "", railgate.SlotAmbiguous, nil, OperatorOutcomeUnknown, ChainFactNotRead},
		{
			"executed, pending", ProviderExecuted, "", readFacts(nil, true, []uint64{7}, nil),
			OperatorResultAvailable, ChainFactPending,
		},
		{"responding, offline", ProviderResponding, "", nil, OperatorOutcomeUnknown, ChainFactNotRead},
		{
			"responding, pending", ProviderResponding, "", readFacts(nil, true, []uint64{7}, nil),
			OperatorResultAvailable, ChainFactPending,
		},
		{
			"responding, finalized respond", ProviderResponding, "", readFacts(respond(responseHash), true, nil, nil),
			OperatorResponded, ChainFactResponded,
		},
		{
			"respond with another hash",
			ProviderDelivering,
			"",
			readFacts(respond(strings.Repeat("bb", 32)), true, nil, nil),
			OperatorOutcomeUnknown,
			ChainFactOtherResponse,
		},
		{"delivering, offline", ProviderDelivering, "", nil, OperatorResponded, ChainFactNotRead},
		{
			"delivering yet pending on chain", ProviderAcked, "", readFacts(nil, true, []uint64{7}, nil),
			OperatorOutcomeUnknown, ChainFactPending,
		},
		{
			"failed, refundable", ProviderFailed, "", readFacts(nil, true, nil, []uint64{7}),
			OperatorRefunded, ChainFactRefundable,
		},
		{
			"failed, pending", ProviderFailed, "", readFacts(nil, true, []uint64{7}, nil),
			OperatorOutcomeUnknown, ChainFactPending,
		},
		{"refund claimed", ProviderFailed, "", readFacts([]toschain.ActorTransaction{
			{Kind: toschain.ActorTxClaim, RequestID: 7},
			{Kind: toschain.ActorTxExpire, RequestID: 7},
		}, true, nil, nil), OperatorRefunded, ChainFactRefundClaimed},
		{"swept", ProviderAbandoned, "", readFacts([]toschain.ActorTransaction{
			{Kind: toschain.ActorTxSweep, RequestID: 7},
		}, true, nil, nil), OperatorSwept, ChainFactSwept},
		{"another request's sweep is not this one's", ProviderExecuted, "", readFacts([]toschain.ActorTransaction{
			{Kind: toschain.ActorTxSweep, RequestID: 8},
		}, true, []uint64{7}, nil), OperatorResultAvailable, ChainFactPending},
		{
			"gone with incomplete history", ProviderResponding, "", readFacts(respond(responseHash), false, nil, nil),
			OperatorOutcomeUnknown, ChainFactHistoryIncomplete,
		},
		{
			"delivering past the history bound", ProviderDelivering, "", readFacts(nil, false, nil, nil),
			OperatorResponded, ChainFactHistoryIncomplete,
		},
		{
			"delivering, history read failed", ProviderDelivering, "", withoutHistory(readFacts(nil, true, nil, nil)),
			OperatorResponded, ChainFactHistoryIncomplete,
		},
		{
			"responding, history read failed", ProviderResponding, "", withoutHistory(readFacts(nil, true, nil, nil)),
			OperatorOutcomeUnknown, ChainFactHistoryIncomplete,
		},
		{
			"failed record, finalized respond", ProviderFailed, "", readFacts(respond(responseHash), true, nil, nil),
			OperatorOutcomeUnknown, ChainFactUnmatchedResponse,
		},
		{
			"completed slot, finalized respond", "", railgate.SlotCompleted,
			readFacts(respond(responseHash), true, nil, nil), OperatorResponded, ChainFactResponded,
		},
		{
			"failed slot, finalized respond", "", railgate.SlotFailed,
			readFacts(respond(responseHash), true, nil, nil), OperatorOutcomeUnknown, ChainFactUnmatchedResponse,
		},
		{
			"delivering, actor not active", ProviderDelivering, "", &actorFacts{read: true},
			OperatorResponded, ChainFactActorInactive,
		},
		{
			"responding, actor not active", ProviderResponding, "", &actorFacts{read: true},
			OperatorOutcomeUnknown, ChainFactActorInactive,
		},
		{
			"gone with no terminal transaction", ProviderExecuted, "", readFacts(nil, true, nil, nil),
			OperatorOutcomeUnknown, ChainFactNotFound,
		},
		{
			"actor read failed", ProviderDelivering, "", &actorFacts{err: "rpc down"}, OperatorResponded,
			ChainFactNotRead,
		},
	}
	actor := "0:" + strings.Repeat("77", 32)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var records []ProviderRecord
			var slots []railgate.Slot
			// As in production, only attested work carries a response hash.
			if test.record != "" {
				record := ProviderRecord{
					Schema: providerRecordSchema, State: test.record, Actor: actor, RequestID: 7,
					ResponseHash: responseHash,
				}
				if test.record == ProviderFailed || test.record == ProviderAbandoned {
					record.ResponseHash = ""
				}
				records = append(records, record)
			}
			if test.slot != "" {
				slot := railgate.Slot{Actor: actor, RequestID: 7, State: test.slot}
				if test.slot == railgate.SlotCompleted {
					slot.ResponseHash = responseHash
				}
				slots = append(slots, slot)
			}
			got := projectProviderStatus(records, slots, map[string]*actorFacts{actor: test.facts})
			if len(got) != 1 {
				t.Fatalf("%d entries for one request", len(got))
			}
			wantSource := RequestSourceRecord
			if test.record == "" {
				wantSource = RequestSourceSlot
			}
			if got[0].Source != wantSource || (wantSource == RequestSourceSlot) == (got[0].Schema != "") {
				t.Fatalf("source %q schema %q for a %s entry", got[0].Source, got[0].Schema, wantSource)
			}
			if got[0].OperatorState != test.want || got[0].ChainFact != test.fact || got[0].StateReason == "" {
				t.Fatalf("state %s fact %s (%s), want %s %s", got[0].OperatorState, got[0].ChainFact,
					got[0].StateReason, test.want, test.fact)
			}
		})
	}
}

// withoutHistory is a read whose history walk failed.
func withoutHistory(facts *actorFacts) *actorFacts {
	facts.history = nil
	return facts
}

// statusChain is a fake finalized chain for one actor.
type statusChain struct {
	err     error
	account *toschain.ActorAccount
	history *toschain.ActorHistory
}

func (c *statusChain) BeginStatus(context.Context) (StatusSession, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c, nil
}

func (c *statusChain) Checkpoint() uint64   { return 42 }
func (c *statusChain) ChainTime() time.Time { return time.Unix(1_800_000_000, 0) }

func (c *statusChain) ReadActor(_ context.Context, actor string) (*toschain.ActorAccount, bool, error) {
	if c.account == nil || actor != c.account.Address {
		return nil, false, nil
	}
	return c.account, true, nil
}

func (c *statusChain) History(context.Context, string, *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	return c.history, nil
}

// statusNode writes a provider state directory with one responding record
// and a manifest whose actor is 0:77..77.
func statusNode(t *testing.T) (NodeConfig, string) {
	t.Helper()
	state := privateStateDir(t)
	directory := filepath.Join(state, "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	actor := "0:" + strings.Repeat("77", 32)
	provider := &Provider{config: ProviderConfig{Directory: directory, Now: time.Now}}
	key := railgate.SlotKey{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("ab", 32), Actor: actor, RequestID: 7}
	if err := provider.store(key, ProviderRecord{
		State: ProviderResponding, Actor: actor, RequestID: 7,
		QuoteCommitment: key.QuoteCommitment, ResponseHash: strings.Repeat("aa", 32),
	}, true); err != nil {
		t.Fatal(err)
	}
	manifest, _, _, err := BuildManifest(ManifestInput{
		ProviderAgentID: testSeller, Actor: actor,
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), Attestor: "mldsa44:" + strings.Repeat("99", 32),
		Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(t.TempDir(), "manifest.cbor")
	if err := os.WriteFile(manifestFile, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return NodeConfig{StateDir: state, Provider: &ProviderNode{ManifestFile: manifestFile}}, actor
}

func TestStatusReportsCreditedRevenueApartFromWalletReceiptAndUnknownWhenUnread(t *testing.T) {
	config, actor := statusNode(t)
	now := time.Unix(1_800_000_100, 0)
	chain := &statusChain{
		account: &toschain.ActorAccount{
			Address:     actor,
			BalanceNano: 5_000_000_000,
			Data: &nativecore.ServiceActorDataV1{
				Active: true, PendingCount: 0, LiveCount: 0,
				Accounting: nativecore.ServiceActorAccountingV1{
					WithdrawableRevenue: big.NewInt(500_000_000),
					LockedStorageFees: big.NewInt(
						0,
					), PendingLiability: big.NewInt(0), RefundableLiability: big.NewInt(0),
				},
				Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{},
				Refunds: map[uint64]nativecore.ServiceActorRefundV1{},
			},
		},
		history: &toschain.ActorHistory{Result: toschain.HistoryComplete, Transactions: []toschain.ActorTransaction{
			{Kind: toschain.ActorTxRespond, RequestID: 7, ResponseHash: strings.Repeat("aa", 32)},
		}},
	}
	status, err := ReadProviderStatus(context.Background(), config, chain, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Schema != ProviderStatusSchema || status.Version != ProviderStatusVersion || status.Admission.Paused {
		t.Fatalf("header: %+v", status)
	}
	if len(status.Requests) != 1 || status.Requests[0].OperatorState != OperatorResponded {
		t.Fatalf("requests: %+v", status.Requests)
	}
	summary := status.Actor
	if !summary.Read || summary.CreditedRevenueNanoTOS != "500000000" || summary.BalanceNanoTOS != "5000000000" ||
		summary.WalletReceipt != walletReceiptNotTracked || !strings.Contains(summary.RevenueNote, "not received") {
		t.Fatalf("actor summary: %+v", summary)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	// The earlier listing's fields stay at the top level of each request.
	for _, field := range []string{
		`"state":"responding"`, `"request_id":7`, `"operator_state":"responded"`,
		`"credited_revenue_nanotos":"500000000"`, `"wallet_receipt":"not_tracked"`,
	} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("%s is missing from %s", field, encoded)
		}
	}

	chain.err = errors.New("no quorum")
	status, err = ReadProviderStatus(context.Background(), config, chain, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.Requests[0].OperatorState != OperatorOutcomeUnknown || status.Actor.Read ||
		!strings.Contains(status.Actor.Error, "no quorum") || status.Actor.CreditedRevenueNanoTOS != "" {
		t.Fatalf("a failed chain read was not reported as unknown: %+v %+v", status.Requests[0], status.Actor)
	}
	offline, err := ReadProviderStatus(context.Background(), config, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if offline.Requests[0].OperatorState != OperatorOutcomeUnknown ||
		offline.Requests[0].ChainFact != ChainFactNotRead {
		t.Fatalf("an offline respond was reported as known: %+v", offline.Requests[0])
	}
	if _, _, pauseErr := PauseAdmission(config.StateDir, "drain", now); pauseErr != nil {
		t.Fatal(pauseErr)
	}
	paused, err := ReadProviderStatus(context.Background(), config, nil, now)
	if err != nil || !paused.Admission.Paused || paused.Admission.Reason != "drain" {
		t.Fatalf("pause not shown: %+v %v", paused.Admission, err)
	}
}

func TestStatusListsAdmittedSlotsThatHaveNoRecordYet(t *testing.T) {
	config, actor := statusNode(t)
	slots := filepath.Join(config.StateDir, "slots")
	if err := ensurePrivateDirectory(slots); err != nil {
		t.Fatal(err)
	}
	slot := railgate.Slot{
		Schema: railgateSlotSchema, QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("cd", 32),
		Actor: actor, RequestID: 9, RequestHash: strings.Repeat("12", 32), State: railgate.SlotStarted,
		UpdatedUnix: 1_800_000_000,
	}
	raw, err := json.Marshal(slot)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := writeSynced(filepath.Join(slots, strings.Repeat("e", 64)+".json"), raw); writeErr != nil {
		t.Fatal(writeErr)
	}
	status, err := ReadProviderStatus(context.Background(), config, nil, time.Unix(1_800_000_100, 0))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, request := range status.Requests {
		if request.RequestID == 9 {
			found = request.OperatorState == OperatorExecuting && request.SlotState == string(railgate.SlotStarted)
		}
	}
	if !found {
		t.Fatalf("an executing request without a record is not listed: %+v", status.Requests)
	}
	if err := os.WriteFile(filepath.Join(slots, strings.Repeat("f", 64)+".json"), []byte(`{"schema":"x"}`),
		0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProviderStatus(context.Background(), config, nil, time.Now()); err == nil {
		t.Fatal("a malformed slot was listed")
	}
}
