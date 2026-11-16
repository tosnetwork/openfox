package servicebridge

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// relayClock is a settable clock shared by a test's nodes and relays.
type relayClock struct {
	mutex sync.Mutex
	now   time.Time
}

func newRelayClock() *relayClock { return &relayClock{now: time.Now().Truncate(time.Second)} }

func (c *relayClock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.now
}

func (c *relayClock) Advance(by time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.now = c.now.Add(by)
}

type fakeStored struct {
	raw      []byte
	keyID    [32]byte
	received uint64
	expires  uint64
}

// fakeRelay is an in-memory relay with the Agent Packet Relay V1 HTTP
// semantics the client relies on, plus knobs a test uses to make it fail or
// lie. It never decrypts.
type fakeRelay struct {
	t      *testing.T
	clock  *relayClock
	server *httptest.Server
	URL    string
	mutex  sync.Mutex
	boxes  map[string]map[[32]byte]*fakeStored
	tombs  map[[32]byte]uint64
	// failDeposits answers 503 to that many deposits.
	failDeposits int
	// slowDeposits answers 408 to that many deposits, as a relay whose read
	// deadline a body missed.
	slowDeposits int
	// expiryRefusals answers 422 to that many deposits.
	expiryRefusals int
	// storeThenFail stores the next deposit and answers 500, an ambiguous
	// outcome for the sender.
	storeThenFail bool
	// conflictAll answers 409 to every deposit, as if an observer had
	// pre-empted every envelope id.
	conflictAll bool
	// conflictIDs answers 409 to deposits under these envelope ids only.
	conflictIDs map[[32]byte]bool
	// listFails answers 503 to listings.
	listFails bool
	// listStatus, when set, answers listings with that bare status.
	listStatus int
	// listDelay holds every listing that long before answering.
	listDelay time.Duration
	// replay keeps acknowledged envelopes listed and downloadable, as a
	// malicious relay may.
	replay bool
	// deposits records every deposit body and the status answered.
	deposits []fakeDeposit
	acks     int
	// ackFails answers 503 to that many acknowledgements.
	ackFails int
	// ackRequests counts every acknowledgement request, answered or not.
	ackRequests int
	// ackBodies records every acknowledgement secret presented.
	ackBodies [][]byte
	// ttl is the retention the relay applies and advertises; zero is 24 h.
	ttl uint64
	// describeFails answers 503 to the relay description.
	describeFails bool
	// describes counts description requests.
	describes int
	// ackForbidden answers 403 to every acknowledgement, a refusal that
	// cannot change, so a withdrawal there ends unconfirmed.
	ackForbidden bool
}

// retention is the relay's TTL in seconds; the caller holds the mutex.
func (f *fakeRelay) retention() uint64 {
	if f.ttl == 0 {
		return 86400
	}
	return f.ttl
}

// describeCount reports the description requests so far.
func (f *fakeRelay) describeCount() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.describes
}

// setTTL changes the relay's retention and advertised TTL.
func (f *fakeRelay) setTTL(seconds uint64) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.ttl = seconds
}

type fakeDeposit struct {
	raw    []byte
	status int
}

func startFakeRelay(t *testing.T, clock *relayClock) *fakeRelay {
	t.Helper()
	relay := &fakeRelay{
		t: t, clock: clock, boxes: map[string]map[[32]byte]*fakeStored{}, tombs: map[[32]byte]uint64{},
	}
	relay.server = httptest.NewServer(relay)
	t.Cleanup(relay.server.Close)
	relay.URL = relay.server.URL
	return relay
}

// twoRelays returns two fake relays in ascending URL order.
func twoRelays(t *testing.T, clock *relayClock) (*fakeRelay, *fakeRelay) {
	a, b := startFakeRelay(t, clock), startFakeRelay(t, clock)
	if a.URL > b.URL {
		a, b = b, a
	}
	return a, b
}

func (f *fakeRelay) errorBody(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"schema":"tos.service.agent-packet-relay.error.v1","code":"` + code + `"}`))
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		f.errorBody(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if request.URL.Path == "/v1/relay" && request.Method == http.MethodGet {
		f.mutex.Lock()
		f.describes++
		fails, ttl := f.describeFails, f.retention()
		f.mutex.Unlock()
		if fails {
			f.errorBody(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"schema":"tos.service.agent-packet-relay.relay.v1","max_envelope_bytes":262144,`+
			`"max_ttl_seconds":%d,"per_recipient_max_envelopes":256,"per_recipient_max_bytes":16777216}`, ttl)
		return
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/mailboxes/"), "/")
	if !strings.HasPrefix(request.URL.Path, "/v1/mailboxes/") || len(parts) < 2 || parts[1] != "envelopes" ||
		!agentIDPattern.MatchString(parts[0]) {
		f.errorBody(w, http.StatusNotFound, "not_found")
		return
	}
	agent := parts[0]
	if len(parts) == 2 && request.Method == http.MethodGet {
		f.list(w, agent)
		return
	}
	if len(parts) < 3 || !hex64Pattern.MatchString(parts[2]) {
		f.errorBody(w, http.StatusNotFound, "not_found")
		return
	}
	var id [32]byte
	if _, err := hex.Decode(id[:], []byte(parts[2])); err != nil {
		f.errorBody(w, http.StatusNotFound, "not_found")
		return
	}
	switch {
	case len(parts) == 3 && request.Method == http.MethodPut:
		f.deposit(w, request, agent, id)
	case len(parts) == 3 && request.Method == http.MethodGet:
		f.download(w, agent, id)
	case len(parts) == 4 && parts[3] == "ack" && request.Method == http.MethodPost:
		f.ack(w, request, agent, id)
	default:
		f.errorBody(w, http.StatusNotFound, "not_found")
	}
}

func (f *fakeRelay) nowUnix() uint64 { return uint64(f.clock.Now().Unix()) }

func (f *fakeRelay) deposit(w http.ResponseWriter, request *http.Request, agent string, id [32]byte) {
	raw, err := io.ReadAll(io.LimitReader(request.Body, agentpacketseal.MaxEnvelopeBytes+1))
	if err != nil || len(raw) > agentpacketseal.MaxEnvelopeBytes {
		f.errorBody(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	answer := func(status int, code string) {
		f.deposits = append(f.deposits, fakeDeposit{raw: append([]byte(nil), raw...), status: status})
		if code == "" {
			w.WriteHeader(status)
			return
		}
		f.errorBody(w, status, code)
	}
	if f.failDeposits > 0 {
		f.failDeposits--
		answer(http.StatusServiceUnavailable, "unavailable")
		return
	}
	if f.slowDeposits > 0 {
		f.slowDeposits--
		answer(http.StatusRequestTimeout, "request_timeout")
		return
	}
	if f.expiryRefusals > 0 {
		f.expiryRefusals--
		answer(http.StatusUnprocessableEntity, "expiry_out_of_bounds")
		return
	}
	header, err := agentpacketseal.ParseEnvelope(raw)
	if err != nil || header.RecipientAgentID != agent || header.EnvelopeID != id {
		answer(http.StatusBadRequest, "invalid_request")
		return
	}
	now := f.nowUnix()
	if header.ExpiresAtUnix <= now || header.ExpiresAtUnix > now+86400+300 {
		answer(http.StatusUnprocessableEntity, "expiry_out_of_bounds")
		return
	}
	if f.conflictAll || f.conflictIDs[id] {
		answer(http.StatusConflict, "conflict")
		return
	}
	if _, tomb := f.tombs[id]; tomb {
		answer(http.StatusGone, "gone")
		return
	}
	box := f.boxes[agent]
	if box == nil {
		box = map[[32]byte]*fakeStored{}
		f.boxes[agent] = box
	}
	if stored, ok := box[id]; ok {
		if bytes.Equal(stored.raw, raw) {
			answer(http.StatusOK, "")
		} else {
			answer(http.StatusConflict, "conflict")
		}
		return
	}
	expires := header.ExpiresAtUnix
	if expires > now+f.retention() {
		expires = now + f.retention()
	}
	box[id] = &fakeStored{
		raw: append([]byte(nil), raw...), keyID: header.RecipientKeyID, received: now,
		expires: expires,
	}
	if f.storeThenFail {
		f.storeThenFail = false
		answer(http.StatusInternalServerError, "unavailable")
		return
	}
	answer(http.StatusCreated, "")
}

// put stores bytes under an id directly, as an observer depositing junk
// under a public envelope id would.
func (f *fakeRelay) put(agent string, id [32]byte, raw []byte) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	box := f.boxes[agent]
	if box == nil {
		box = map[[32]byte]*fakeStored{}
		f.boxes[agent] = box
	}
	header, _ := agentpacketseal.ParseEnvelope(raw)
	now := f.nowUnix()
	box[id] = &fakeStored{
		raw: append([]byte(nil), raw...), keyID: header.RecipientKeyID, received: now,
		expires: now + 3600,
	}
}

func (f *fakeRelay) list(w http.ResponseWriter, agent string) {
	f.mutex.Lock()
	delay, status := f.listDelay, f.listStatus
	f.mutex.Unlock()
	if delay > 0 {
		// Held outside the mutex, so the relay keeps serving other requests.
		time.Sleep(delay)
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if f.listFails {
		w.Header().Set("Retry-After", "7")
		f.errorBody(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	type entry struct {
		EnvelopeID     string `json:"envelope_id"`
		RecipientKeyID string `json:"recipient_key_id"`
		Size           int    `json:"size"`
		ReceivedAtUnix uint64 `json:"received_at_unix"`
		ExpiresAtUnix  uint64 `json:"expires_at_unix"`
	}
	entries := []entry{}
	now := f.nowUnix()
	for id, stored := range f.boxes[agent] {
		if now >= stored.expires {
			continue
		}
		entries = append(entries, entry{
			EnvelopeID: hex.EncodeToString(id[:]), RecipientKeyID: agentpacketseal.KeyIDText(stored.keyID),
			Size: len(stored.raw), ReceivedAtUnix: stored.received, ExpiresAtUnix: stored.expires,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ReceivedAtUnix != entries[j].ReceivedAtUnix {
			return entries[i].ReceivedAtUnix < entries[j].ReceivedAtUnix
		}
		return entries[i].EnvelopeID < entries[j].EnvelopeID
	})
	encoded, err := json.Marshal(map[string]any{
		"schema": "tos.service.agent-packet-relay.mailbox.v1", "agent_id": agent, "envelopes": entries,
	})
	if err != nil {
		f.t.Errorf("encode listing: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}

func (f *fakeRelay) download(w http.ResponseWriter, agent string, id [32]byte) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	stored, ok := f.boxes[agent][id]
	if !ok || f.nowUnix() >= stored.expires {
		f.errorBody(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(stored.raw)
}

func (f *fakeRelay) ack(w http.ResponseWriter, request *http.Request, agent string, id [32]byte) {
	raw, err := io.ReadAll(io.LimitReader(request.Body, 33))
	if err != nil || len(raw) != 32 {
		f.errorBody(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var secret [32]byte
	copy(secret[:], raw)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.ackRequests++
	f.ackBodies = append(f.ackBodies, append([]byte(nil), raw...))
	if f.ackFails > 0 {
		f.ackFails--
		f.errorBody(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if f.ackForbidden || !agentpacketseal.CheckAck(id, secret) {
		f.errorBody(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, tomb := f.tombs[id]; tomb {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	stored, ok := f.boxes[agent][id]
	if !ok {
		f.errorBody(w, http.StatusNotFound, "not_found")
		return
	}
	f.acks++
	f.tombs[id] = stored.expires
	if !f.replay {
		delete(f.boxes[agent], id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// holds reports whether the relay holds id for agent.
func (f *fakeRelay) holds(agent string, id [32]byte) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	_, ok := f.boxes[agent][id]
	return ok
}

// ackCounts reports the acknowledgement requests and deletions so far.
func (f *fakeRelay) ackCounts() (requests, deletions int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.ackRequests, f.acks
}

// count reports how many envelopes the relay holds for agent.
func (f *fakeRelay) count(agent string) int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return len(f.boxes[agent])
}

// stored returns the bytes held under id.
func (f *fakeRelay) stored(agent string, id [32]byte) []byte {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if stored, ok := f.boxes[agent][id]; ok {
		return append([]byte(nil), stored.raw...)
	}
	return nil
}

func (f *fakeRelay) depositLog() []fakeDeposit {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return append([]fakeDeposit(nil), f.deposits...)
}

func (f *fakeRelay) allBytes() []byte {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var out []byte
	for _, box := range f.boxes {
		for _, stored := range box {
			out = append(out, stored.raw...)
		}
	}
	for _, deposit := range f.deposits {
		out = append(out, deposit.raw...)
	}
	return out
}
