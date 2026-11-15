package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// The values below are synthetic shapes, not contract-produced vectors: they
// let the real rail gate and its verifier admit one request, with the
// protocol's own builders and decoders.
const gfCapability = "cap_3333333333333333333333333333333333333333333333333333333333333333"

var (
	gfActor    = "0:" + strings.Repeat("77", 32)
	gfOwner    = "0:" + strings.Repeat("11", 32)
	gfCodeHash = "tvm-cell-sha256:" + strings.Repeat("88", 32)
	gfKey      = bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	gfKeyID    = func() [32]byte { id, _ := mldsa44.KeyID(gfKey); return id }()
	gfCallHash = strings.Repeat("0a", 32)
)

// testClock is a clock a test moves.
type testClock struct {
	mutex sync.Mutex
	now   time.Time
}

func (c *testClock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.now = now
}

// gfChain is a fake finalized chain holding one Capability, its actor and
// one pending request.
type gfChain struct {
	mutex      sync.Mutex
	checkpoint uint64
	chainTime  time.Time
	capability *nativev1.NativeStateV1
	agent      *nativev1.NativeStateV1
	data       *nativecore.ServiceActorDataV1
	history    []toschain.ActorTransaction
	// unavailable makes every finalized read fail.
	unavailable bool
}

// time is the finalized chain time, which is also the verifier's clock.
func (c *gfChain) time() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.chainTime
}

func (c *gfChain) setTime(now time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.chainTime = now
}

// setUnavailable makes every finalized read fail until it is cleared.
func (c *gfChain) setUnavailable(unavailable bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.unavailable = unavailable
}

func (c *gfChain) BeginSession(context.Context) (railgate.Session, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.unavailable {
		return nil, errors.New("no finalized checkpoint by a strict majority")
	}
	c.checkpoint++
	return &gfSession{
		checkpoint: c.checkpoint, chainTime: c.chainTime,
		capability: proto.Clone(c.capability).(*nativev1.NativeStateV1),
		agent:      proto.Clone(c.agent).(*nativev1.NativeStateV1), data: c.data,
		history: append([]toschain.ActorTransaction(nil), c.history...),
	}, nil
}

type gfSession struct {
	checkpoint        uint64
	chainTime         time.Time
	capability, agent *nativev1.NativeStateV1
	data              *nativecore.ServiceActorDataV1
	history           []toschain.ActorTransaction
}

func (s *gfSession) RegistryTransition(
	context.Context, string, nativecore.RegistryTransitionKind, string,
) (*toschain.RegistryTransitionTx, error) {
	return nil, toschain.ErrRegistryTransitionUnproven
}

func (s *gfSession) Checkpoint() uint64   { return s.checkpoint }
func (s *gfSession) ChainTime() time.Time { return s.chainTime }

func (s *gfSession) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	var state *nativev1.NativeStateV1
	switch id {
	case gfCapability:
		state = s.capability
	case testSeller:
		state = s.agent
	default:
		return nil, false, nil
	}
	state.Reference = &nativev1.ChainReference{FinalizedCheckpoint: s.checkpoint}
	return state, true, nil
}

func (s *gfSession) head() toschain.ActorTxID {
	if len(s.history) == 0 {
		return toschain.ActorTxID{}
	}
	return toschain.ActorTxID{LT: s.history[0].LT, Hash: s.history[0].Hash}
}

func (s *gfSession) ReadActor(_ context.Context, account string) (*toschain.ActorAccount, bool, error) {
	if account != gfActor {
		return nil, false, nil
	}
	return &toschain.ActorAccount{
		Address: account, CodeHash: gfCodeHash, Data: s.data, LastTransaction: s.head(),
	}, true, nil
}

func (s *gfSession) History(_ context.Context, _ string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	if anchor != nil {
		return nil, errors.New("not used")
	}
	return &toschain.ActorHistory{Result: toschain.HistoryComplete, Head: s.head(), Transactions: s.history}, nil
}

func (s *gfSession) GetRequest(
	_ context.Context, _ string, id uint64,
) (*nativecore.ServiceActorRequestViewV1, error) {
	entry, ok := s.data.Pending[id]
	if !ok {
		return nil, nil
	}
	return &nativecore.ServiceActorRequestViewV1{
		Caller: entry.Caller, Price: entry.Price, StorageFee: entry.StorageFee,
		CleanupBounty: entry.CleanupBounty, ResponseDeadline: entry.ResponseDeadline,
		RefundClaimDeadline: entry.RefundClaimDeadline, PolicyVersion: entry.PolicyVersion,
		RequestHash: entry.RequestHash, TermsHash: entry.TermsHash, HasAttestor: entry.HasAttestor,
		AttestorKeyID: entry.AttestorKeyID,
	}, nil
}

func (s *gfSession) GetRefund(_ context.Context, _ string, id uint64) (*nativecore.ServiceActorRefundV1, error) {
	entry, ok := s.data.Refunds[id]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}

// respondedHistory is a finalized history in which the request was answered
// with hash.
type respondedHistory struct {
	railgate.Session
	requestID uint64
	hash      func() string
}

func (h respondedHistory) History(context.Context, string, *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	history := &toschain.ActorHistory{Result: toschain.HistoryComplete}
	if hash := h.hash(); hash != "" {
		history.Transactions = []toschain.ActorTransaction{
			{Kind: toschain.ActorTxRespond, RequestID: h.requestID, ResponseHash: hash},
		}
	}
	return history, nil
}

// scriptedHistory is the provider's finalized history reader; the respond
// is finalized once finalized is set to its response hash.
type scriptedHistory struct {
	mutex     sync.Mutex
	finalized string
}

func (h *scriptedHistory) finalize(hash string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.finalized = hash
}

func (h *scriptedHistory) BeginSession(context.Context) (railgate.Session, error) {
	return respondedHistory{hash: func() string {
		h.mutex.Lock()
		defer h.mutex.Unlock()
		return h.finalized
	}}, nil
}

// gateFixture is a provider offer with one finalized pending request, its
// task message, and the verifier of a real rail gate.
type gateFixture struct {
	chain          *gfChain
	clock          *testClock
	message        Message
	archive        []byte
	manifest       nativecore.SoftwareWorkManifestV1
	manifestDigest string
	manifestCBOR   []byte
	deadline       uint64
}

// newGateFixture builds the fixture deterministically from start, so two
// processes given the same start agree on every hash.
func newGateFixture(t *testing.T, start time.Time) *gateFixture {
	t.Helper()
	attestor := mldsa44.KeyIDText(gfKeyID)
	manifestCBOR, digest, manifest, err := BuildManifest(ManifestInput{
		ProviderAgentID: testSeller, Actor: gfActor, ActorCodeHash: gfCodeHash, Attestor: attestor,
		Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{
		Network: testNetwork, CapabilityID: gfCapability, ProviderAgentID: testSeller, CapabilityVersion: "1.0.0",
		ManifestDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	terms := nativecore.ServiceActorTermsV1{
		PolicyVersion: 2, PricePerCall: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000),
		CleanupBounty: big.NewInt(100_000_000), ResponseSLA: 3600, RefundClaimWindow: 3600, MetadataHash: metadata,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme, HasAttestor: true, AttestorKeyID: gfKeyID,
	}
	policy := nativecore.ServiceActorPolicyV1{
		PolicyVersion: terms.PolicyVersion, PricePerCall: terms.PricePerCall, StorageFee: terms.StorageFee,
		CleanupBounty: terms.CleanupBounty, ResponseSLA: terms.ResponseSLA,
		RefundClaimWindow: terms.RefundClaimWindow, OpenAccess: true, MetadataHash: metadata,
		ProofSchemeHash: terms.ProofSchemeHash, HasAttestor: true, AttestorKeyID: gfKeyID, AttestorKey: gfKey,
	}
	binding, _, err := RailTransport(testSeller)
	if err != nil {
		t.Fatal(err)
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	termsHash, err := nativecore.ServiceActorTermsHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{
		ProposalId: "provider-1", CapabilityId: gfCapability, CapabilityVersion: "1.0.0",
		ProviderAgentId: testSeller, ManifestDigest: digest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: uint64(start.Add(30 * time.Minute).Unix()),
		Actor:                &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
		ActorCodeHash:        gfCodeHash, PolicyVersion: terms.PolicyVersion,
		TermsHash: hex.EncodeToString(termsHash[:]), PriceNanotos: "300000000", StorageFeeNanotos: "200000000",
		AttestorKeyId: attestor,
	}
	pkg := &nativev1.QuoteProposalPackageV1{
		Proposal: proposal, CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: transport.ToBOC(),
	}
	quote, _, err := nativecore.BuildAcceptedQuoteCommitment(testNetwork, proposal)
	if err != nil {
		t.Fatal(err)
	}
	var quoteHash [32]byte
	copy(quoteHash[:], quote.Hash())
	archive := fill(4096, 9)
	requestCell, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{
		QuoteCommitment: quoteHash, ExecutionID: testExecutionID, InputDigest: InputDigest(sha256Sum(archive)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var requestHash [32]byte
	copy(requestHash[:], requestCell.Hash())

	called := uint32(start.Unix()) - 100
	termsCell, err := nativecore.BuildServiceActorTermsCell(terms)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := address.ParseRawAddr(testWallet)
	if err != nil {
		t.Fatal(err)
	}
	deadline := uint64(called) + uint64(terms.ResponseSLA)
	snapshotCell := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorRequestSnapshotTag, 32).
		MustStoreUInt(0, 64).MustStoreAddr(caller).MustStoreSlice(requestHash[:], 256).
		MustStoreUInt(deadline, 64).MustStoreUInt(deadline+uint64(terms.RefundClaimWindow), 64).
		MustStoreRef(termsCell).EndCell()
	call := toschain.ActorTransaction{
		LT: 10, Hash: gfCallHash, Now: called, Kind: toschain.ActorTxCall, Sender: testWallet,
		Opcode: nativecore.ServiceActorCallOpcode, QueryID: 9,
		Call: &toschain.ActorCallBody{
			QueryID: 9, RequestHash: hex.EncodeToString(requestHash[:]),
			ExpectedTermsHash: hex.EncodeToString(termsCell.Hash()),
		},
		Snapshot: &toschain.ActorSAR1{BodyBOC: base64.StdEncoding.EncodeToString(snapshotCell.ToBOC())},
	}
	snapshot, err := call.Snapshot.Decode()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := nativecore.StandardAddress(gfOwner)
	if err != nil {
		t.Fatal(err)
	}
	callerKey, err := snapshot.Caller.SliceHash()
	if err != nil {
		t.Fatal(err)
	}
	data := &nativecore.ServiceActorDataV1{
		Owner: owner, Active: true, NextRequestID: 1, Policy: policy,
		Accounting: nativecore.ServiceActorAccountingV1{
			WithdrawableRevenue: new(big.Int), LockedStorageFees: new(big.Int).Set(terms.StorageFee),
			PendingLiability: new(big.Int).Set(terms.PricePerCall), RefundableLiability: new(big.Int),
		},
		Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{0: {
			Caller: snapshot.Caller, Price: terms.PricePerCall, StorageFee: terms.StorageFee,
			CleanupBounty: terms.CleanupBounty, ResponseDeadline: snapshot.ResponseDeadline,
			RefundClaimDeadline: snapshot.RefundClaimDeadline, PolicyVersion: terms.PolicyVersion,
			RequestHash: snapshot.RequestHash, TermsHash: snapshot.TermsHash, HasAttestor: true,
			AttestorKeyID: gfKeyID,
		}},
		Refunds:          map[uint64]nativecore.ServiceActorRefundV1{},
		CallerLiveCounts: map[[32]byte]uint32{callerKey: 1},
		PendingCount:     1, LiveCount: 1,
	}
	chain := &gfChain{
		checkpoint: 10, chainTime: start, data: data, history: []toschain.ActorTransaction{call},
		capability: &nativev1.NativeStateV1{Network: testNetwork, State: &nativev1.NativeStateV1_Capability{
			Capability: &nativev1.CapabilityStateV1{
				CapabilityId: gfCapability, OwnerAgentId: testSeller,
				Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: digest}},
			},
		}},
		agent: &nativev1.NativeStateV1{Network: testNetwork, State: &nativev1.NativeStateV1_Agent{
			Agent: &nativev1.AgentStateV1{AgentId: testSeller},
		}},
	}
	message, _ := taskMessage(t, pkg, archive, testBuyer)
	message.RequestHash = requestHash
	copy(message.ActorAccount[:], bytes.Repeat([]byte{0x77}, 32))
	return &gateFixture{
		chain: chain, clock: &testClock{now: start}, message: message, archive: archive, manifest: manifest,
		manifestDigest: digest, manifestCBOR: manifestCBOR, deadline: deadline,
	}
}

// serviceNode is a provider on the real rail gate that executes through an
// executor service.
type serviceNode struct {
	provider  *Provider
	gate      *railgate.Gate
	runner    *SocketRunner
	lifecycle *countingLifecycle
	transport *recordingTransport
	history   *scriptedHistory
	state     string
}

// openServiceNode assembles the provider over state, as a node start does:
// opening the gate recovers the slots a previous process left.
func openServiceNode(t *testing.T, fixture *gateFixture, state string, client ExecutorService) *serviceNode {
	t.Helper()
	return openServiceNodeWith(t, fixture, state, client, fixture.manifestDigest)
}

// openServiceNodeWith configures the node's runner with runnerManifest and
// the fixture's current limits, which a test may have changed since the
// request was admitted.
func openServiceNodeWith(
	t *testing.T,
	fixture *gateFixture,
	state string,
	client ExecutorService,
	runnerManifest string,
) *serviceNode {
	t.Helper()
	manifests := &MemoryManifests{}
	manifests.Put(fixture.manifestDigest, fixture.manifestCBOR)
	respond := 2 * time.Minute
	verifier, err := railgate.NewVerifier(railgate.VerifierConfig{
		Reader: fixture.chain, Manifests: manifests, Network: testNetwork, ActorCodeHash: gfCodeHash,
		ProviderAgentID: testSeller, CapabilityID: gfCapability, Version: "1.0.0",
		ExecutionBudget: 180 * time.Second, RespondBudget: respond,
		// The verifier measures its slack at the fixture's start; only the
		// provider's own clock is moved by a test.
		Now: fixture.chain.time,
	})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := railgate.OpenGate(verifier, filepath.Join(state, "slots"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	runner, err := NewSocketRunner(SocketRunnerConfig{
		StateDir: filepath.Join(state, "executor-service"), ManifestDigest: runnerManifest,
		ToolchainDigest: fixture.manifest.ToolchainDigest, Limits: fixture.manifest.Limits, Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	node := &serviceNode{
		gate: gate, runner: runner, lifecycle: &countingLifecycle{}, transport: &recordingTransport{},
		history: &scriptedHistory{}, state: state,
	}
	courier, err := OpenCourier(filepath.Join(state, "outbox"), testSigner(t, testSeller), node.transport)
	if err != nil {
		t.Fatal(err)
	}
	node.provider, err = NewProvider(ProviderConfig{
		AgentID: testSeller, CapabilityID: gfCapability, Version: "1.0.0", Network: testNetwork, Gate: gate,
		Service: runner, RespondBudget: respond, Store: runner, Lifecycle: node.lifecycle,
		AttestorController: "service-attestor", Courier: courier, History: node.history,
		Directory: filepath.Join(state, "provider"), Now: fixture.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return node
}

// record returns the node's single provider record.
func (n *serviceNode) record(t *testing.T) ProviderRecord {
	t.Helper()
	records, err := n.provider.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("the provider holds %d records, not one", len(records))
	}
	return records[0]
}

// slotState returns the gate's state of the node's single request.
func (n *serviceNode) slotState(t *testing.T) railgate.SlotState {
	t.Helper()
	slot, found, err := n.gate.Lookup(recordKey(n.record(t)))
	if err != nil || !found {
		t.Fatalf("the request has no slot: %v", err)
	}
	return slot.State
}

// slot returns the gate's record of the node's single request.
func (n *serviceNode) slot(t *testing.T) railgate.Slot {
	t.Helper()
	slot, found, err := n.gate.Lookup(recordKey(n.record(t)))
	if err != nil || !found {
		t.Fatalf("the request has no slot: %v", err)
	}
	return slot
}
