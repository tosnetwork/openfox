package agentgift

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeProtocol struct{}
type fakeResponse struct {
	Destination   string
	NotAfter      uint32
	RequestDigest string
}
type fakeOffer struct {
	BOC      []byte
	Greeting string
}

func digest(v []byte) string { h := sha256.Sum256(v); return "sha256:" + hex.EncodeToString(h[:]) }
func (fakeProtocol) CreateAddressRequest(_ context.Context, v RequestIntent) ([]byte, string, error) {
	b, e := json.Marshal(v)
	return b, digest(b), e
}
func (fakeProtocol) InspectAddressRequest(_ context.Context, b []byte) (RequestIntent, string, error) {
	var v RequestIntent
	e := json.Unmarshal(b, &v)
	return v, digest(b), e
}
func (fakeProtocol) CreateAddressResponse(_ context.Context, req []byte, destination string, until uint32) ([]byte, ResponseTerms, error) {
	v := fakeResponse{destination, until, digest(req)}
	b, e := json.Marshal(v)
	return b, ResponseTerms{DestinationAddress: destination, ResponseNotAfter: until, RequestDigest: v.RequestDigest, ResponseDigest: digest(b)}, e
}
func (fakeProtocol) ValidateAddressResponse(_ context.Context, req, response []byte) (ResponseTerms, error) {
	var v fakeResponse
	if json.Unmarshal(response, &v) != nil || v.RequestDigest != digest(req) {
		return ResponseTerms{}, errors.New("bad response")
	}
	return ResponseTerms{DestinationAddress: v.Destination, ResponseNotAfter: v.NotAfter, RequestDigest: v.RequestDigest, ResponseDigest: digest(response)}, nil
}
func (fakeProtocol) CreateSignedOffer(_ context.Context, _, _ []byte, boc []byte, greeting string) ([]byte, string, error) {
	b, e := json.Marshal(fakeOffer{append([]byte(nil), boc...), greeting})
	return b, digest(boc), e
}
func (fakeProtocol) VerifySignedOffer(_ context.Context, request, response, offer []byte) (SignedTerms, error) {
	var req RequestIntent
	var res fakeResponse
	var off fakeOffer
	if json.Unmarshal(request, &req) != nil || json.Unmarshal(response, &res) != nil || json.Unmarshal(offer, &off) != nil || len(off.BOC) == 0 {
		return SignedTerms{}, errors.New("bad offer")
	}
	return SignedTerms{SignedGiftID: digest(off.BOC), ExactBOCDigest: digest(append([]byte("boc"), off.BOC...)), SenderAgentAccount: req.SenderAgentAccount, DestinationAddress: res.Destination, AmountAtomic: req.AmountAtomic, DeploymentID: "sha256:" + string(bytes.Repeat([]byte{'9'}, 64)), FeeReserveAtomic: "1000000", Seqno: 3, ValidUntil: res.NotAfter, ExactSignedBOC: append([]byte(nil), off.BOC...)}, nil
}

type fakeResolver struct {
	recipient string
	final     State
}

func (f *fakeResolver) ResolveRecipient(context.Context, string) (string, error) {
	return f.recipient, nil
}
func (f *fakeResolver) ResolveFinality(context.Context, Record) (FinalityResult, error) {
	if f.final == "" {
		return FinalityResult{}, nil
	}
	return FinalityResult{State: f.final}, nil
}

type sent struct {
	recipient, kind, key string
	body                 []byte
}
type fakeMessenger struct {
	sent []sent
	fail bool
}

func (f *fakeMessenger) SendEstablishedDirect(_ context.Context, r, k string, b []byte, key string) (string, error) {
	f.sent = append(f.sent, sent{r, k, key, append([]byte(nil), b...)})
	if f.fail {
		f.fail = false
		return "", errors.New("ambiguous send")
	}
	return "evt_" + hex.EncodeToString(make([]byte, 32)), nil
}

type fakeCustody struct {
	boc          []byte
	prepareCalls int
	signCalls    int
	cancelCalls  int
	failSign     bool
	failCancel   bool
}

func (f *fakeCustody) SenderAccount(context.Context) (string, error) {
	return "-1:" + string(bytes.Repeat([]byte{'c'}, 64)), nil
}
func (f *fakeCustody) PrepareNativeGift(_ context.Context, request SignRequest) (CustodyReview, error) {
	f.prepareCalls++
	var intent RequestIntent
	var response fakeResponse
	if json.Unmarshal(request.CanonicalRequest, &intent) != nil || json.Unmarshal(request.CanonicalResponse, &response) != nil {
		return CustodyReview{}, errors.New("bad custody input")
	}
	return CustodyReview{
		Network: intent.Network, GlobalID: intent.GlobalID, RecipientAgentID: intent.RecipientAgentID,
		SenderAgentAccount: intent.SenderAgentAccount, OwnerWallet: "-1:" + string(bytes.Repeat([]byte{'e'}, 64)),
		ControllerKeyID: "controller:test", DestinationAddress: response.Destination,
		DeploymentID: "sha256:" + string(bytes.Repeat([]byte{'9'}, 64)),
		AmountAtomic: intent.AmountAtomic, FeeReserveAtomic: "1000000", Seqno: 3,
		ValidUntil: response.NotAfter, RequestDigest: digest(request.CanonicalRequest),
		ResponseDigest: digest(request.CanonicalResponse), UnsignedTransferDigest: "sha256:" + string(bytes.Repeat([]byte{'f'}, 64)),
	}, nil
}
func (f *fakeCustody) SignNativeGift(context.Context, SignRequest) ([]byte, error) {
	f.signCalls++
	if len(f.boc) == 0 {
		f.boc = []byte{0xb5, 0xee, 1, 2, 3}
	}
	if f.failSign {
		f.failSign = false
		return nil, errors.New("ambiguous custody result")
	}
	return append([]byte(nil), f.boc...), nil
}
func (f *fakeCustody) CancelSeqno(context.Context, CancelRequest) ([]byte, error) {
	f.cancelCalls++
	if f.failCancel {
		f.failCancel = false
		return nil, errors.New("ambiguous cancellation preparation")
	}
	return []byte{9}, nil
}

type fakeBroadcast struct {
	calls int
	fail  bool
}

func (f *fakeBroadcast) BroadcastExactBOC(_ context.Context, b []byte) error {
	f.calls++
	if len(b) == 0 {
		return errors.New("empty")
	}
	if f.fail {
		return errors.New("ambiguous broadcast")
	}
	return nil
}

type fakeAddress struct {
	value string
	calls int
}

func (f *fakeAddress) SelectDestination(context.Context, string) (string, error) {
	f.calls++
	return f.value, nil
}

type fakeOwner struct {
	reviews []OwnerReview
	fail    bool
}

func (f *fakeOwner) Authorize(_ context.Context, v OwnerReview) (string, error) {
	f.reviews = append(f.reviews, v)
	if f.fail {
		f.fail = false
		return "", errors.New("ambiguous owner confirmation")
	}
	if v.FundsLocked {
		return "", errors.New("false locked claim")
	}
	return "sha256:" + string(bytes.Repeat([]byte{'a'}, 64)), nil
}

func openTestJournal(t *testing.T, name string) *Journal {
	t.Helper()
	d := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}
func newTestService(t *testing.T, j *Journal, p Protocol, r *fakeResolver, m *fakeMessenger, c *fakeCustody, b *fakeBroadcast, a *fakeAddress, o *fakeOwner) *Service {
	t.Helper()
	s, e := NewService(j, p, r, m, c, b, a, o)
	if e != nil {
		t.Fatal(e)
	}
	s.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	return s
}

func TestSenderRecipientEndToEndAndFinalizedPaid(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	sender := newTestService(t, openTestJournal(t, "sender"), p, r, m, c, b, a, o)
	record, err := sender.StartSender(ctx, ModelProposal{Recipient: "bob.tos", AmountAtomic: "1000000000", RequestedValidUntil: 1_800_003_600, Greeting: "hi"}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.RequestAddress(ctx, record.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	recipient := newTestService(t, openTestJournal(t, "recipient"), p, r, m, c, b, a, o)
	rr, err := recipient.ObserveRecipientRequest(ctx, record.CanonicalRequest, record.RecipientAgentID, record.SenderAgentID)
	if err != nil {
		t.Fatal(err)
	}
	rr, err = recipient.RespondAddress(ctx, rr.IntentID, 1_800_003_500)
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.ObserveAddressResponse(ctx, record.IntentID, rr.CanonicalResponse)
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.Authorize(ctx, record.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.Sign(ctx, record.IntentID, "hi")
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.DeliverOffer(ctx, record.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOffer := append([]byte(nil), record.CanonicalOffer...)
	rr, err = recipient.ObserveAndBroadcastOffer(ctx, rr.IntentID, canonicalOffer)
	if err != nil {
		t.Fatal(err)
	}
	if rr.State != StateBroadcastSubmitted || rr.RetryNotBeforeUnix <= 1_800_000_000 || b.calls != 1 || len(o.reviews) != 1 || o.reviews[0].Action != "send" {
		t.Fatalf("wrong flow: %+v", rr)
	}
	r.final = StateFinalizedPaid
	if record, err = sender.Refresh(ctx, record.IntentID); err != nil || record.State != StateFinalizedPaid {
		t.Fatalf("sender finality: %+v %v", record, err)
	}
	if rr, err = recipient.Refresh(ctx, rr.IntentID); err != nil || rr.State != StateFinalizedPaid {
		t.Fatalf("recipient finality: %+v %v", rr, err)
	}
	if len(rr.CanonicalOffer) != 0 || len(rr.ExactSignedBOC) != 0 || rr.CanonicalOfferDigest == "" {
		t.Fatalf("terminal recipient record was not safely compacted: %+v", rr)
	}
	if duplicate, duplicateErr := recipient.ObserveAndBroadcastOffer(ctx, rr.IntentID, canonicalOffer); duplicateErr != nil || duplicate.State != StateFinalizedPaid || b.calls != 1 {
		t.Fatalf("terminal exact duplicate was not idempotent: %+v %v", duplicate, duplicateErr)
	}
	changed := append([]byte(nil), canonicalOffer...)
	changed = append(changed, 0)
	if _, conflictErr := recipient.ObserveAndBroadcastOffer(ctx, rr.IntentID, changed); conflictErr == nil {
		t.Fatal("terminal changed offer did not conflict")
	}
}

func TestInvalidOfferDoesNotPoisonDurableRecipientState(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	sender := newTestService(t, openTestJournal(t, "invalid-offer-sender"), p, r, m, c, b, a, o)
	record, _ := sender.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	record, _ = sender.RequestAddress(ctx, record.IntentID)
	recipient := newTestService(t, openTestJournal(t, "invalid-offer-recipient"), p, r, m, c, b, a, o)
	received, _ := recipient.ObserveRecipientRequest(ctx, record.CanonicalRequest, record.RecipientAgentID, record.SenderAgentID)
	received, _ = recipient.RespondAddress(ctx, received.IntentID, 1_800_003_500)
	if _, err := recipient.ObserveAndBroadcastOffer(ctx, received.IntentID, []byte("not-json")); err == nil {
		t.Fatal("invalid offer was accepted")
	}
	persisted := recipient.ListRecords()[0]
	if persisted.State != StateAddressResponseSent || len(persisted.CanonicalOffer) != 0 || persisted.CanonicalOfferDigest != "" || b.calls != 0 {
		t.Fatalf("invalid offer poisoned durable state: %+v", persisted)
	}
}

func TestInboundPerPeerCapacityStillAllowsExactDuplicate(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	peer := "agent_" + string(bytes.Repeat([]byte{'a'}, 64))
	local := "agent_" + string(bytes.Repeat([]byte{'b'}, 64))
	s := newTestService(t, openTestJournal(t, "peer-capacity"), p, &fakeResolver{recipient: local}, &fakeMessenger{}, &fakeCustody{}, &fakeBroadcast{}, &fakeAddress{}, &fakeOwner{})
	var first []byte
	for index := 0; index < maxActiveGiftsPerPeer; index++ {
		request, _, err := p.CreateAddressRequest(ctx, RequestIntent{Network: "tos-local", GlobalID: 42,
			IntentID: fmt.Sprintf("%064x", index+1), SenderAgentID: peer, RecipientAgentID: local,
			SenderAgentAccount: "-1:" + string(bytes.Repeat([]byte{'c'}, 64)), AmountAtomic: "1", RequestedValidUntil: 1_800_003_600})
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			first = request
		}
		if _, err := s.ObserveRecipientRequest(ctx, request, local, peer); err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
	}
	if _, err := s.ObserveRecipientRequest(ctx, first, local, peer); err != nil {
		t.Fatalf("exact duplicate was rejected at capacity: %v", err)
	}
	extra, _, _ := p.CreateAddressRequest(ctx, RequestIntent{Network: "tos-local", GlobalID: 42,
		IntentID: fmt.Sprintf("%064x", maxActiveGiftsPerPeer+1), SenderAgentID: peer, RecipientAgentID: local,
		SenderAgentAccount: "-1:" + string(bytes.Repeat([]byte{'c'}, 64)), AmountAtomic: "1", RequestedValidUntil: 1_800_003_600})
	if _, err := s.ObserveRecipientRequest(ctx, extra, local, peer); err == nil {
		t.Fatal("per-peer active Gift capacity was not enforced")
	}
}

func TestJournalHasHardRecordCapacity(t *testing.T) {
	j := openTestJournal(t, "hard-capacity")
	j.records = make(map[string]Record, maxGiftRecords)
	for index := 0; index < maxGiftRecords; index++ {
		j.records[fmt.Sprintf("%064x", index)] = Record{}
	}
	if _, err := j.Create(Record{IntentID: strings.Repeat("f", 64)}); err == nil {
		t.Fatal("journal accepted a record past its hard capacity")
	}
}

func TestJournalEvictsOldestTerminalAtCapacity(t *testing.T) {
	j := openTestJournal(t, "terminal-eviction")
	sender := "agent_" + strings.Repeat("a", 64)
	recipient := "agent_" + strings.Repeat("b", 64)
	j.records = make(map[string]Record, maxGiftRecords)
	for index := 0; index < maxGiftRecords; index++ {
		intent := fmt.Sprintf("%064x", index)
		j.records[intent] = Record{IntentID: intent, Role: RoleRecipient, State: StateFinalizedPaid,
			Network: "tos-local", GlobalID: 42, SenderAgentID: sender, RecipientAgentID: recipient,
			SenderAgentAccount: "-1:" + strings.Repeat("c", 64), AmountAtomic: "1", RequestedValidUntil: 1,
			CreatedAtUnix: 1, UpdatedAtUnix: int64(index + 1)}
	}
	newIntent := strings.Repeat("f", 64)
	created, err := j.Create(Record{IntentID: newIntent, Role: RoleRecipient, State: StateAddressRequestObserved,
		Network: "tos-local", GlobalID: 42, SenderAgentID: sender, RecipientAgentID: recipient,
		SenderAgentAccount: "-1:" + strings.Repeat("c", 64), AmountAtomic: "1", RequestedValidUntil: 2,
		CanonicalRequest: []byte{1}, CreatedAtUnix: 2, UpdatedAtUnix: 2})
	if err != nil || created.IntentID != newIntent || len(j.List()) != maxGiftRecords {
		t.Fatalf("terminal eviction failed: created=%+v err=%v count=%d", created, err, len(j.List()))
	}
	if _, found := j.Get(fmt.Sprintf("%064x", 0)); found {
		t.Fatal("oldest terminal record was not evicted")
	}
}

func TestJournalRequiresLifetimeExclusiveProcessLock(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "exclusive")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(directory); err == nil {
		t.Fatal("second process handle acquired the same Gift journal")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatalf("journal lock was not released: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCrashRecoveryReusesExactSignedBOCAndResponse(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{failSign: true}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	j := openTestJournal(t, "journal")
	s := newTestService(t, j, p, r, m, c, b, a, o)
	rec, _ := s.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	rec, _ = s.RequestAddress(ctx, rec.IntentID)
	response, terms, _ := p.CreateAddressResponse(ctx, rec.CanonicalRequest, a.value, 1_800_003_500)
	_ = terms
	rec, _ = s.ObserveAddressResponse(ctx, rec.IntentID, response)
	rec, _ = s.Authorize(ctx, rec.IntentID)
	if _, err := s.Sign(ctx, rec.IntentID, ""); err == nil {
		t.Fatal("expected ambiguous sign")
	}
	if persisted, _ := j.Get(rec.IntentID); persisted.PendingEffect != EffectSignBOC {
		t.Fatal("sign effect was not durable before custody")
	}
	directory := filepath.Dir(j.path)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	recovered := newTestService(t, reopened, p, r, m, c, b, a, o)
	signed, err := recovered.Sign(ctx, rec.IntentID, "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := recovered.Sign(ctx, rec.IntentID, "")
	if err != nil || !bytes.Equal(signed.ExactSignedBOC, again.ExactSignedBOC) || c.signCalls != 2 {
		t.Fatalf("sign retry changed BOC or signed twice after completion")
	}
}

func TestRecipientRestartReusesExactAddressResponse(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	sender := newTestService(t, openTestJournal(t, "response-sender"), p, r, m, c, b, a, o)
	record, _ := sender.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	record, _ = sender.RequestAddress(ctx, record.IntentID)
	j := openTestJournal(t, "response-recipient")
	recipient := newTestService(t, j, p, r, m, c, b, a, o)
	received, err := recipient.ObserveRecipientRequest(ctx, record.CanonicalRequest, record.RecipientAgentID, record.SenderAgentID)
	if err != nil {
		t.Fatal(err)
	}
	m.fail = true
	if _, err := recipient.RespondAddress(ctx, received.IntentID, 1_800_003_500); err == nil {
		t.Fatal("expected ambiguous address response send")
	}
	persisted, _ := j.Get(received.IntentID)
	if persisted.PendingEffect != EffectSendAddressResponse || len(persisted.CanonicalResponse) == 0 || a.calls != 1 {
		t.Fatalf("address response was not durable before send: %+v", persisted)
	}
	exactResponse := append([]byte(nil), persisted.CanonicalResponse...)
	directory := filepath.Dir(j.path)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	recovered := newTestService(t, reopened, p, r, m, c, b, a, o)
	completed, err := recovered.RespondAddress(ctx, received.IntentID, 1_800_003_500)
	if err != nil || completed.State != StateAddressResponseSent || a.calls != 1 || !bytes.Equal(completed.CanonicalResponse, exactResponse) {
		t.Fatalf("recipient restart changed response: %+v %v", completed, err)
	}
	if len(m.sent) < 3 || !bytes.Equal(m.sent[len(m.sent)-2].body, m.sent[len(m.sent)-1].body) {
		t.Fatal("recipient restart did not resend the exact canonical response")
	}
}

func TestOwnerAuthorizationReviewIsDurableAndExactlyRetried(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{fail: true}
	j := openTestJournal(t, "owner-review")
	s := newTestService(t, j, p, r, m, c, b, a, o)
	record, _ := s.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	record, _ = s.RequestAddress(ctx, record.IntentID)
	response, _, _ := p.CreateAddressResponse(ctx, record.CanonicalRequest, a.value, 1_800_003_500)
	record, _ = s.ObserveAddressResponse(ctx, record.IntentID, response)
	if _, err := s.Authorize(ctx, record.IntentID); err == nil {
		t.Fatal("expected ambiguous owner confirmation")
	}
	persisted, _ := j.Get(record.IntentID)
	if persisted.State != StateOwnerAuthorizationRequired || persisted.OwnerWallet == "" || persisted.UnsignedTransferDigest == "" || c.prepareCalls != 1 {
		t.Fatalf("complete owner review was not durable: %+v", persisted)
	}
	recovered := newTestService(t, j, p, r, m, c, b, a, o)
	authorized, err := recovered.Authorize(ctx, record.IntentID)
	if err != nil || authorized.State != StateOwnerAuthorized || c.prepareCalls != 1 || len(o.reviews) != 2 || o.reviews[0] != o.reviews[1] {
		t.Fatalf("owner review was not exactly retried: %+v %v", authorized, err)
	}
}

func TestAmbiguousBroadcastRequiresFinalizedResolution(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{}
	b := &fakeBroadcast{fail: true}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	// Build the full exchange with two journals, then fail after entering broadcaster.
	s := newTestService(t, openTestJournal(t, "s"), p, r, m, c, b, a, o)
	rec, _ := s.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	rec, _ = s.RequestAddress(ctx, rec.IntentID)
	rsvc := newTestService(t, openTestJournal(t, "r"), p, r, m, c, b, a, o)
	rr, _ := rsvc.ObserveRecipientRequest(ctx, rec.CanonicalRequest, rec.RecipientAgentID, rec.SenderAgentID)
	rr, _ = rsvc.RespondAddress(ctx, rr.IntentID, 1_800_003_500)
	rec, _ = s.ObserveAddressResponse(ctx, rec.IntentID, rr.CanonicalResponse)
	rec, _ = s.Authorize(ctx, rec.IntentID)
	rec, _ = s.Sign(ctx, rec.IntentID, "")
	if _, err := rsvc.ObserveAndBroadcastOffer(ctx, rr.IntentID, rec.CanonicalOffer); err == nil {
		t.Fatal("expected ambiguous broadcast")
	}
	if _, err := rsvc.ObserveAndBroadcastOffer(ctx, rr.IntentID, rec.CanonicalOffer); err == nil || b.calls != 1 {
		t.Fatal("ambiguous broadcast was blindly retried")
	}
	r.final = StateCurrentlyExecutable
	resolved, err := rsvc.Refresh(ctx, rr.IntentID)
	if err != nil || resolved.State != StateCurrentlyExecutable || resolved.PendingEffect != EffectNone {
		t.Fatalf("finalized executable recovery did not release exact retry: %+v %v", resolved, err)
	}
	if _, err := rsvc.ObserveAndBroadcastOffer(ctx, rr.IntentID, rec.CanonicalOffer); err == nil || b.calls != 1 {
		t.Fatal("exact BOC retry ignored durable backoff")
	}
	rsvc.now = func() time.Time { return time.Unix(1_800_000_031, 0).UTC() }
	b.fail = false
	resolved, err = rsvc.ObserveAndBroadcastOffer(ctx, rr.IntentID, rec.CanonicalOffer)
	if err != nil || resolved.State != StateBroadcastSubmitted || b.calls != 2 {
		t.Fatalf("exact BOC retry failed: %+v %v", resolved, err)
	}
	r.final = StateFinalizedPaid
	resolved, err = rsvc.Refresh(ctx, rr.IntentID)
	if err != nil || resolved.State != StateFinalizedPaid || resolved.PendingEffect != EffectNone {
		t.Fatalf("finalized recovery failed: %+v %v", resolved, err)
	}
}

func TestCancellationPersistsExactBOCBeforeBroadcastAndWaitsForFinality(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	s := newTestService(t, openTestJournal(t, "cancel"), p, r, m, c, b, a, o)
	record, _ := s.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	record, _ = s.RequestAddress(ctx, record.IntentID)
	response, _, _ := p.CreateAddressResponse(ctx, record.CanonicalRequest, a.value, 1_800_003_500)
	record, _ = s.ObserveAddressResponse(ctx, record.IntentID, response)
	record, _ = s.Authorize(ctx, record.IntentID)
	record, _ = s.Sign(ctx, record.IntentID, "")
	record, err := s.Cancel(ctx, record.IntentID)
	if err != nil || record.PendingEffect != EffectCancel || len(record.ExactCancellationBOC) == 0 || b.calls != 1 || len(o.reviews) != 2 || o.reviews[1].Action != "cancel" || o.reviews[1].SignedGiftID == "" {
		t.Fatalf("cancellation was not durable and authorized: %+v %v", record, err)
	}
	if _, err := s.Cancel(ctx, record.IntentID); err == nil || b.calls != 1 {
		t.Fatal("ambiguous cancellation was rebroadcast")
	}
	r.final = StateCurrentlyExecutable
	record, err = s.Refresh(ctx, record.IntentID)
	if err != nil || record.State != StateCurrentlyExecutable || record.PendingEffect != EffectNone {
		t.Fatalf("cancellation retry was not released by finalized state: %+v %v", record, err)
	}
	if _, err := s.Cancel(ctx, record.IntentID); err == nil || b.calls != 1 {
		t.Fatal("exact cancellation retry ignored durable backoff")
	}
	s.now = func() time.Time { return time.Unix(1_800_000_031, 0).UTC() }
	record, err = s.Cancel(ctx, record.IntentID)
	if err != nil || b.calls != 2 || c.cancelCalls != 1 || len(o.reviews) != 2 || !bytes.Equal(record.ExactCancellationBOC, []byte{9}) {
		t.Fatalf("cancellation did not reuse exact authorized BOC: %+v %v", record, err)
	}
	r.final = StateInvalidatedUnpaid
	record, err = s.Refresh(ctx, record.IntentID)
	if err != nil || record.State != StateInvalidatedUnpaid || record.PendingEffect != EffectNone {
		t.Fatalf("cancellation finality did not resolve: %+v %v", record, err)
	}
}

func TestCancellationPreparationCrashCannotDeliverOfferAndResumesExactly(t *testing.T) {
	ctx := context.Background()
	p := fakeProtocol{}
	r := &fakeResolver{recipient: "agent_" + string(bytes.Repeat([]byte{'b'}, 64))}
	m := &fakeMessenger{}
	c := &fakeCustody{failCancel: true}
	b := &fakeBroadcast{}
	a := &fakeAddress{value: "0:" + string(bytes.Repeat([]byte{'d'}, 64))}
	o := &fakeOwner{}
	s := newTestService(t, openTestJournal(t, "cancel-prepare-crash"), p, r, m, c, b, a, o)
	record, _ := s.StartSender(ctx, ModelProposal{Recipient: "bob", AmountAtomic: "1", RequestedValidUntil: 1_800_003_600}, "tos-local", 42, "agent_"+string(bytes.Repeat([]byte{'a'}, 64)))
	record, _ = s.RequestAddress(ctx, record.IntentID)
	response, _, _ := p.CreateAddressResponse(ctx, record.CanonicalRequest, a.value, 1_800_003_500)
	record, _ = s.ObserveAddressResponse(ctx, record.IntentID, response)
	record, _ = s.Authorize(ctx, record.IntentID)
	record, _ = s.Sign(ctx, record.IntentID, "")
	if _, err := s.Cancel(ctx, record.IntentID); err == nil {
		t.Fatal("expected cancellation preparation failure")
	}
	persisted := s.ListRecords()[0]
	if persisted.PendingEffect != EffectPrepareCancel || persisted.CancellationAuthorizationDigest == "" || c.cancelCalls != 1 {
		t.Fatalf("cancellation authorization was not durable: %+v", persisted)
	}
	if _, err := s.DeliverOffer(ctx, record.IntentID); err == nil || len(m.sent) != 1 {
		t.Fatal("Gift offer was delivered while owner-authorized cancellation was pending")
	}
	resumed, err := s.Cancel(ctx, record.IntentID)
	if err != nil || resumed.PendingEffect != EffectCancel || c.cancelCalls != 2 || len(o.reviews) != 2 {
		t.Fatalf("cancellation preparation did not resume exactly: %+v %v", resumed, err)
	}
}
