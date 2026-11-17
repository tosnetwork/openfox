package servicebridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/firewall"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// The owner socket here is the daemon's real local API server, on a real
// journal, serving the owner principal: every decision openfox prepares is
// signed with the owner key the server knows and verified by the server
// itself. Only the room runtime behind it is recorded instead of run.

const (
	ownerTestRoom  = "room_" + "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	ownerTestAgent = "agent_" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	ownerTestMEP   = "mep_" + "6666666666666666666666666666666666666666666666666666666666666666"
	ownerTestDev   = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
)

// testInviteToken is an invite_ token in the daemon's encoding: 32 bytes of
// fill in unpadded base64url.
func testInviteToken(fill byte) string {
	return "invite_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func ownerTestKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x0f}, ed25519.SeedSize))
}

type ownerTestSuite struct{}

func (ownerTestSuite) AlgorithmID() string { return "tos.messaging.e2ee.test-double.v1" }
func (ownerTestSuite) NewPrekeyMaterial() ([]byte, []byte, error) {
	return []byte("p"), []byte("q"), nil
}
func (ownerTestSuite) KeyMaterial(state e2ee.State) (e2ee.State, error) { return state, nil }
func (ownerTestSuite) Accept([]byte, []byte, []byte, []byte) (e2ee.State, error) {
	return e2ee.State(make([]byte, 8)), nil
}

func (ownerTestSuite) Initiate([]byte, []byte, []byte) (e2ee.State, []byte, error) {
	return e2ee.State(make([]byte, 8)), []byte("initial"), nil
}

func (ownerTestSuite) Seal(state e2ee.State, plaintext, _ []byte) ([]byte, e2ee.State, error) {
	next := make([]byte, 8)
	binary.BigEndian.PutUint64(next, binary.BigEndian.Uint64(state)+1)
	return append([]byte("sealed:"), plaintext...), next, nil
}

func (ownerTestSuite) Open(e2ee.State, []byte, []byte) ([]byte, e2ee.State, error) {
	return nil, nil, e2ee.ErrNotAuthentic
}

type ownerTestSender struct{}

func (ownerTestSender) Send(context.Context, dispatch.Message) error { return nil }

type ownerTestBindings struct{}

func (ownerTestBindings) BindingFor(eventlog.Delivery) (e2ee.Binding, error) {
	return e2ee.Binding{}, errors.New("no sessions in the owner socket tests")
}

// recordingRoomOperator records the room decisions the server hands on.
type recordingRoomOperator struct {
	mutex sync.Mutex
	calls []string
}

func (r *recordingRoomOperator) record(call string) error {
	r.mutex.Lock()
	r.calls = append(r.calls, call)
	r.mutex.Unlock()
	return nil
}

func (r *recordingRoomOperator) recorded() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *recordingRoomOperator) CreateRoom(_ context.Context, roomID string) error {
	return r.record("create " + roomID)
}

func (r *recordingRoomOperator) AddRoomMember(_ context.Context, roomID, agentID string) error {
	return r.record("add " + roomID + " " + agentID)
}

func (r *recordingRoomOperator) RemoveRoomMember(_ context.Context, roomID, agentID string) error {
	return r.record("remove " + roomID + " " + agentID)
}

func (r *recordingRoomOperator) JoinRoom(_ context.Context, roomID, authorityAgentID string) error {
	return r.record("join " + roomID + " " + authorityAgentID)
}

func (r *recordingRoomOperator) ComposeRoomMessage(context.Context, localapi.RoomComposition) (string, bool, error) {
	return "", false, errors.New("not composed in the owner socket tests")
}

// ownerSocket is a real local API server listening for one principal.
type ownerSocket struct {
	path  string
	rooms *recordingRoomOperator
}

func startOwnerSocket(t *testing.T, principal localapi.Principal) ownerSocket {
	t.Helper()
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	network := &nativev1.NetworkDomain{
		NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
	}
	dispatcher, err := dispatch.New(dispatch.Config{
		Journal: journal, Suite: ownerTestSuite{}, Sender: ownerTestSender{}, Bindings: ownerTestBindings{},
		Identity: dispatch.Identity{AgentID: testSeller, EndpointID: ownerTestMEP, DeviceID: ownerTestDev},
		Network:  network,
	})
	if err != nil {
		t.Fatal(err)
	}
	rooms := &recordingRoomOperator{}
	server, err := localapi.NewServer(localapi.Config{
		Journal: journal, Dispatcher: dispatcher, Policy: firewall.Default(),
		OwnerKey: ownerTestKey().Public().(ed25519.PublicKey), LocalEndpointID: ownerTestMEP, RoomOperator: rooms,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err = os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "owner.sock")
	listener, err := localapi.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = server.Serve(ctx, listener, principal) }()
	return ownerSocket{path: path, rooms: rooms}
}

// ownerTestConfig writes a chat node configuration naming the owner socket.
func ownerTestConfig(t *testing.T, ownerSocketPath string) string {
	t.Helper()
	state := t.TempDir()
	config := NodeConfig{
		AgentID: testSeller, StateDir: state, RelayURLs: []string{"https://relay.example"},
		ReceiverSocket: filepath.Join(state, "rail.sock"),
		Chat: &ChatConfig{
			CarrierSocket: filepath.Join(state, "c.sock"), MessengerCarrierSocket: filepath.Join(state, "d.sock"),
			CardPath: filepath.Join(state, "card.json"), OwnerSocket: ownerSocketPath,
		},
	}
	path := filepath.Join(t.TempDir(), "rail.json")
	if err := writeNodeConfig(path, config); err != nil {
		t.Fatal(err)
	}
	return path
}

// signDecisionFile signs a prepared decision file as the owner's offline
// signer does and writes the signed decision next to it.
func signDecisionFile(t *testing.T, prepared string, key ed25519.PrivateKey) string {
	t.Helper()
	decision, err := readOwnerDecision(prepared)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := localapi.SignDecision(decision.Request, decision.Request.Challenge, key)
	if err != nil {
		t.Fatal(err)
	}
	decision.Request.OwnerSignature = signature
	encoded, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	signed := prepared + ".signed"
	if err := writeSynced(signed, encoded); err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestRoomDecisionsArePreparedSignedOfflineAndVerifiedByTheDaemon(t *testing.T) {
	socket := startOwnerSocket(t, localapi.PrincipalOwner)
	config := ownerTestConfig(t, socket.path)
	ctx := context.Background()
	out := t.TempDir()
	for index, test := range []struct {
		op    ChatRoomOp
		agent string
		want  string
	}{
		{ChatRoomCreate, "", "create " + ownerTestRoom},
		{ChatRoomAdd, ownerTestAgent, "add " + ownerTestRoom + " " + ownerTestAgent},
		{ChatRoomRemove, ownerTestAgent, "remove " + ownerTestRoom + " " + ownerTestAgent},
		{ChatRoomJoin, ownerTestAgent, "join " + ownerTestRoom + " " + ownerTestAgent},
	} {
		decisionPath := filepath.Join(out, string(test.op)+".json")
		prepared, err := ChatRoomPrepare(ctx, config, test.op, ownerTestRoom, test.agent, decisionPath)
		if err != nil {
			t.Fatalf("%s: %v", test.op, err)
		}
		info, err := os.Lstat(decisionPath)
		if err != nil || info.Mode().Perm() != 0o600 || prepared.DecisionFile != decisionPath {
			t.Fatalf("%s: the decision file is not owner-only: %v %v", test.op, info, err)
		}
		if len(socket.rooms.recorded()) != index {
			t.Fatalf("%s: preparing reached the room runtime", test.op)
		}
		submitted, err := ChatOwnerSubmit(ctx, config, signDecisionFile(t, decisionPath, ownerTestKey()))
		if err != nil {
			t.Fatalf("%s: %v", test.op, err)
		}
		calls := socket.rooms.recorded()
		if len(calls) != index+1 || calls[index] != test.want || submitted.RoomID != ownerTestRoom {
			t.Fatalf("%s: the room runtime got %v", test.op, calls)
		}
	}
	rooms, err := ChatRoomList(ctx, config)
	if err != nil || rooms.Rooms == nil || rooms.Invites == nil {
		t.Fatalf("room list: %+v %v", rooms, err)
	}
}

func TestADecisionIsSpentOnceAndOnlyTheOwnerKeyDecides(t *testing.T) {
	socket := startOwnerSocket(t, localapi.PrincipalOwner)
	config := ownerTestConfig(t, socket.path)
	ctx := context.Background()
	out := t.TempDir()
	prepare := func(name string) string {
		path := filepath.Join(out, name)
		if _, err := ChatRoomPrepare(ctx, config, ChatRoomCreate, ownerTestRoom, "", path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Another key's signature is refused by the daemon; nothing is decided.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x01}, ed25519.SeedSize))
	if _, err := ChatOwnerSubmit(ctx, config, signDecisionFile(t, prepare("other.json"), other)); err == nil {
		t.Fatal("a decision signed by another key was accepted")
	}
	// The owner's signature decides once; the same signed decision again is
	// refused, its challenge spent.
	signed := signDecisionFile(t, prepare("owner.json"), ownerTestKey())
	if _, err := ChatOwnerSubmit(ctx, config, signed); err != nil {
		t.Fatal(err)
	}
	if _, err := ChatOwnerSubmit(ctx, config, signed); err == nil {
		t.Fatal("a signed decision was accepted twice")
	}
	if calls := socket.rooms.recorded(); len(calls) != 1 {
		t.Fatalf("the room runtime got %v", calls)
	}
}

func TestADecisionIsCheckedBeforeItIsSubmitted(t *testing.T) {
	socket := startOwnerSocket(t, localapi.PrincipalOwner)
	config := ownerTestConfig(t, socket.path)
	ctx := context.Background()
	out := t.TempDir()
	prepared := filepath.Join(out, "create.json")
	if _, err := ChatRoomPrepare(ctx, config, ChatRoomCreate, ownerTestRoom, "", prepared); err != nil {
		t.Fatal(err)
	}
	// An unsigned decision is not sent: it is refused here, not by the daemon.
	if _, err := ChatOwnerSubmit(ctx, config, prepared); err == nil ||
		!strings.Contains(err.Error(), "no canonical Ed25519 signature") {
		t.Fatalf("an unsigned decision: %v", err)
	}
	// A decision whose request changed after it was prepared is not sent,
	// even when signed, since its signing bytes no longer match.
	decision, err := readOwnerDecision(signDecisionFile(t, prepared, ownerTestKey()))
	if err != nil {
		t.Fatal(err)
	}
	decision.Request.RoomID = "room_" + strings.Repeat("7", 64)
	encoded, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(out, "tampered.json")
	if err := writeSynced(tampered, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := ChatOwnerSubmit(ctx, config, tampered); !errors.Is(err, errChatOwnerDecision) {
		t.Fatalf("a tampered decision: %v", err)
	}
	if calls := socket.rooms.recorded(); len(calls) != 0 {
		t.Fatalf("the room runtime got %v", calls)
	}
	// An existing --out is never replaced.
	if _, err := ChatRoomPrepare(ctx, config, ChatRoomCreate, ownerTestRoom, "", prepared); err == nil {
		t.Fatal("preparing replaced an existing file")
	}
}

// countingOwner is an owner socket that counts calls and answers a fixed
// challenge, for the checks that must happen before any call.
type countingOwner struct {
	calls    int
	response localapi.Response
}

func (c *countingOwner) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	c.calls++
	if request.Op == localapi.OpChallenge {
		return localapi.Response{OK: true, Challenge: strings.Repeat("c", 64)}, nil
	}
	return c.response, nil
}

func TestRoomAndInviteTermsAreCheckedBeforeTheDaemonIsAsked(t *testing.T) {
	owner := &countingOwner{}
	ctx := context.Background()
	out := t.TempDir()
	for name, test := range map[string]struct {
		op          ChatRoomOp
		room, agent string
	}{
		"bad room":         {ChatRoomCreate, "room_x", ""},
		"create an agent":  {ChatRoomCreate, ownerTestRoom, ownerTestAgent},
		"add no agent":     {ChatRoomAdd, ownerTestRoom, ""},
		"join a bad agent": {ChatRoomJoin, ownerTestRoom, "agent_x"},
		"unknown op":       {ChatRoomOp("rename"), ownerTestRoom, ownerTestAgent},
	} {
		if _, err := roomRequest(test.op, test.room, test.agent); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	now := time.Unix(1_800_000_000, 0)
	token := filepath.Join(out, "token")
	if err := os.WriteFile(token, []byte(testInviteToken(0xab)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(out, "loose")
	if err := os.WriteFile(loose, []byte(testInviteToken(0xab)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(out, "junk")
	if err := os.WriteFile(junk, []byte("invite_"+strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	zero := filepath.Join(out, "zero")
	if err := os.WriteFile(zero, []byte(testInviteToken(0)), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := uint64(now.Add(time.Hour).Unix())
	for name, test := range map[string]struct {
		recipient string
		invite    ChatInvite
	}{
		"bad recipient":   {"agent_x", ChatInvite{TokenFile: token, ExpiresAtUnix: valid}},
		"expired":         {ownerTestAgent, ChatInvite{TokenFile: token, ExpiresAtUnix: uint64(now.Unix())}},
		"beyond 30 days":  {ownerTestAgent, ChatInvite{TokenFile: token, ExpiresAtUnix: uint64(now.Unix()) + 31*86400}},
		"loose token":     {ownerTestAgent, ChatInvite{TokenFile: loose, ExpiresAtUnix: valid}},
		"not a token":     {ownerTestAgent, ChatInvite{TokenFile: junk, ExpiresAtUnix: valid}},
		"zero token":      {ownerTestAgent, ChatInvite{TokenFile: zero, ExpiresAtUnix: valid}},
		"relative path":   {ownerTestAgent, ChatInvite{TokenFile: "token", ExpiresAtUnix: valid}},
		"no token at all": {ownerTestAgent, ChatInvite{TokenFile: filepath.Join(out, "absent"), ExpiresAtUnix: valid}},
	} {
		if _, err := presentInviteRequest(test.recipient, test.invite, now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	request, err := presentInviteRequest(ownerTestAgent, ChatInvite{TokenFile: token, ExpiresAtUnix: valid}, now)
	if err != nil || request.InviteToken != testInviteToken(0xab) {
		t.Fatalf("a valid invite: %+v %v", request, err)
	}
	// A runtime-side operation is never prepared as a decision.
	if _, err := prepareOwnerDecision(ctx, owner, localapi.Request{Op: localapi.OpListRooms}); err == nil {
		t.Fatal("a non-decision was prepared")
	}
	if owner.calls != 0 {
		t.Fatalf("the daemon was asked %d times", owner.calls)
	}
}

func TestAnInviteIsPresentedAloneOrWithItsContactImport(t *testing.T) {
	socket := startOwnerSocket(t, localapi.PrincipalOwner)
	config := ownerTestConfig(t, socket.path)
	ctx := context.Background()
	out := t.TempDir()
	token := filepath.Join(out, "token")
	if err := os.WriteFile(token, []byte(testInviteToken(0xcd)), 0o600); err != nil {
		t.Fatal(err)
	}
	invite := ChatInvite{TokenFile: token, ExpiresAtUnix: uint64(time.Now().Add(time.Hour).Unix())}
	alone := filepath.Join(out, "present.json")
	if _, err := ChatInvitePresent(ctx, config, ownerTestAgent, invite, alone, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := ChatOwnerSubmit(ctx, config, signDecisionFile(t, alone, ownerTestKey())); err != nil {
		t.Fatalf("the daemon refused the presented invite: %v", err)
	}
	// With a contact import: the decision names the contact's Agent, and an
	// invalid invite stops the import before anything is imported.
	clock := newRelayClock()
	peer := newChatTestNode(t, clock, testBuyer, relayAgents(), startFakeRelay(t, clock).URL)
	contact := peer.contactOf()
	client, err := localapi.NewClient(socket.path, 0)
	if err != nil {
		t.Fatal(err)
	}
	imports := 0
	doImport := func() (*ChatContactImported, error) {
		imports++
		return &ChatContactImported{AgentID: testBuyer}, nil
	}
	expired := ChatInvite{TokenFile: token, ExpiresAtUnix: 1}
	if _, err = importWithInvite(ctx, client, contact, expired, config, filepath.Join(out, "x.json"), time.Now(),
		doImport); err == nil || imports != 0 {
		t.Fatalf("an expired invite: %v, %d imports", err, imports)
	}
	if _, err = importWithInvite(ctx, client, contact, invite, config, alone, time.Now(), doImport); err == nil ||
		imports != 0 {
		t.Fatalf("an existing --invite-out: %v, %d imports", err, imports)
	}
	withImport := filepath.Join(out, "with-import.json")
	imported, err := importWithInvite(ctx, client, contact, invite, config, withImport, time.Now(), doImport)
	if err != nil || imports != 1 || imported.InviteDecision == nil {
		t.Fatalf("an import with an invite: %+v %v", imported, err)
	}
	decision, err := readOwnerDecision(withImport)
	if err != nil || decision.Request.Op != localapi.OpPresentInvite ||
		decision.Request.InviteRecipientAgentID != testBuyer {
		t.Fatalf("the invite decision: %+v %v", decision, err)
	}
	if _, err := ChatOwnerSubmit(ctx, config, signDecisionFile(t, withImport, ownerTestKey())); err != nil {
		t.Fatal(err)
	}
}

func TestTheRuntimeSocketRefusesEveryRoomDecision(t *testing.T) {
	socket := startOwnerSocket(t, localapi.PrincipalRuntime)
	config := ownerTestConfig(t, socket.path)
	ctx := context.Background()
	prepared := filepath.Join(t.TempDir(), "create.json")
	// The runtime socket issues no challenge: nothing can even be prepared.
	if _, err := ChatRoomPrepare(ctx, config, ChatRoomCreate, ownerTestRoom, "", prepared); err == nil {
		t.Fatal("a decision was prepared on the runtime socket")
	}
	if calls := socket.rooms.recorded(); len(calls) != 0 {
		t.Fatalf("the room runtime got %v", calls)
	}
}

// listingOwner answers rooms.list with fixed rooms.
type listingOwner struct{ rooms []localapi.RoomSummary }

func (l listingOwner) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	if request.Op != localapi.OpListRooms {
		return localapi.Response{}, errors.New("unexpected operation")
	}
	return localapi.Response{OK: true, Rooms: l.rooms}, nil
}

func TestStatusAndPreflightShowTheDaemonsRoomsAndInvites(t *testing.T) {
	listed, err := listChatRooms(context.Background(), listingOwner{rooms: []localapi.RoomSummary{
		{RoomID: ownerTestRoom, State: "joined", AuthorityAgentID: testSeller, IsAuthority: true},
		{
			RoomID: "room_" + strings.Repeat("7", 64), State: "invited", AuthorityAgentID: ownerTestAgent,
			InviteExpiresAtUnix: 1_900_000_000,
		},
	}})
	if err != nil || len(listed.Rooms) != 1 || len(listed.Invites) != 1 || listed.Invites[0].State != "invited" {
		t.Fatalf("rooms %+v %v", listed, err)
	}
	socket := startOwnerSocket(t, localapi.PrincipalOwner)
	config := ownerTestConfig(t, socket.path)
	report, err := ReadChatStatus(config, time.Now())
	if err != nil || report.DaemonRooms == nil || report.DaemonRoomsProblem != "" {
		t.Fatalf("status with the owner socket: %+v %v", report, err)
	}
	down := ownerTestConfig(t, filepath.Join(t.TempDir(), "absent.sock"))
	report, err = ReadChatStatus(down, time.Now())
	if err != nil || report.DaemonRooms != nil || report.DaemonRoomsProblem == "" {
		t.Fatalf("status without an answering owner socket: %+v %v", report, err)
	}
	run := func(path string) PreflightCheck {
		loaded, err := loadChatConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		p := &preflight{
			ctx: context.Background(), config: loaded, passed: map[string]bool{},
			report: &PreflightReport{OK: true},
		}
		p.checkChatOwner()
		return p.report.Checks[0]
	}
	if check := run(config); check.Status != CheckPass || !strings.Contains(check.Message, "answers") {
		t.Fatalf("preflight with the owner socket: %+v", check)
	}
	if check := run(down); check.Status != CheckFail {
		t.Fatalf("preflight without an answering owner socket: %+v", check)
	}
	if check := run(ownerTestConfig(t, "")); check.Status != CheckPass || !strings.Contains(check.Message, "off") {
		t.Fatalf("preflight without an owner socket: %+v", check)
	}
}

// The commands a prepared decision prints run as printed: the daemon's own
// owner tool (built from the pinned module) signs into a new 0600 file with
// nothing on standard output, and the openfox command named submits it.
func TestThePrintedNextStepsRunAsGiven(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "tos-messenger-owner")
	build := exec.Command("go", "build", "-o", tool, "github.com/tosnetwork/ai/messenger/cmd/tos-messenger-owner")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the daemon's owner tool: %v\n%s", err, output)
	}
	socket := startOwnerSocket(t, localapi.PrincipalOwner)
	config := ownerTestConfig(t, socket.path)
	out := t.TempDir()
	token := filepath.Join(out, "token")
	if err := os.WriteFile(token, []byte(testInviteToken(0x5c)), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(out, "owner.key")
	if err := os.WriteFile(key, []byte(hex.EncodeToString(ownerTestKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := ChatInvitePresent(context.Background(), config, ownerTestAgent,
		ChatInvite{TokenFile: token, ExpiresAtUnix: uint64(time.Now().Add(time.Hour).Unix())},
		filepath.Join(out, "present.json"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(prepared.Next, "`")
	if len(parts) != 5 {
		t.Fatalf("the next steps name %d commands: %s", (len(parts)-1)/2, prepared.Next)
	}
	sign, submit := strings.Fields(parts[1]), strings.Fields(parts[3])
	if sign[0] != "tos-messenger-owner" {
		t.Fatalf("the signing command: %v", sign)
	}
	for index, field := range sign {
		if field == "OWNER_KEY_FILE" {
			sign[index] = key
		}
	}
	command := exec.Command(tool, sign[1:]...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err = command.Run(); err != nil {
		t.Fatalf("the printed signing command failed: %v\n%s", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("the signed decision went to standard output")
	}
	info, err := os.Lstat(prepared.SignedFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the signed decision is not a new owner-only file: %v %v", info, err)
	}
	want := []string{
		"openfox", "earning", "chat", "owner", "submit", "--rail-config", config, "--decision",
		prepared.SignedFile,
	}
	if strings.Join(submit, " ") != strings.Join(want, " ") {
		t.Fatalf("the submit command: %v", submit)
	}
	if _, err := ChatOwnerSubmit(context.Background(), submit[6], submit[8]); err != nil {
		t.Fatalf("the printed submit command's decision: %v", err)
	}
}
