package nativeimpl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openfoxgift "github.com/tosnetwork/openfox/pkg/agentgift"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	protocolgift "github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
)

const rustGiftBOC = "te6ccgEBAgEApgABRYn/gcFMuh/DSQZFasqNaT3ITOt7HHKnDMUAP9yhpWvoLEIMAQD7qWXpKJPScATturw4khEH749KXPRHgxeHEe/xQnydpujylIqd7JfcJr42YcyR+CxCy9kgme+pEhmIeRPzWqBYBUFHUAQAAAAqAAAAAAAAAAAAAAAAdzWUAIAEREREREREREREREREREREREREREREREREREREREREREh3NZQB"

type fixtureGiftChain struct {
	account     protocolgift.FinalizedAgentAccount
	paid        bool
	observation *protocolgift.FinalizedGiftObservation
}

type fixtureRecipientAuthority struct{}

func (fixtureRecipientAuthority) ResolveCanonicalAgent(_ context.Context, value string) (string, error) {
	if len(value) != 70 || !strings.HasPrefix(value, "agent_") {
		return "", errors.New("not a canonical fixture AgentID")
	}
	return value, nil
}

type recordingMessengerCaller struct {
	request localapi.Request
}

type runtimeMessengerCaller struct {
	pending   localapi.PendingEvent
	completed bool
}

type multiRuntimeCaller struct {
	events   []localapi.PendingEvent
	outcomes map[string]localapi.Operation
}

type retryingRuntimeCaller struct {
	calls  int
	cancel context.CancelFunc
	done   chan struct{}
}

func (c *retryingRuntimeCaller) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	if request.Op != localapi.OpPendingAgentGifts {
		return localapi.Response{}, errors.New("unexpected retry test operation")
	}
	c.calls++
	if c.calls == 1 {
		return localapi.Response{}, errors.New("temporary Messenger outage")
	}
	c.cancel()
	close(c.done)
	return localapi.Response{OK: true}, nil
}

func (c *multiRuntimeCaller) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	if c.outcomes == nil {
		c.outcomes = make(map[string]localapi.Operation)
	}
	switch request.Op {
	case localapi.OpPendingAgentGifts:
		pending := make([]localapi.PendingEvent, 0, len(c.events))
		for _, event := range c.events {
			if c.outcomes[event.EventID] == "" {
				pending = append(pending, event)
			}
		}
		return localapi.Response{OK: true, Events: pending}, nil
	case localapi.OpClaimAgentGift:
		for _, event := range c.events {
			if event.EventID == request.EventID && c.outcomes[event.EventID] == "" {
				claimed := event
				return localapi.Response{OK: true, Event: &claimed}, nil
			}
		}
		return localapi.Response{}, errors.New("unknown multi-runtime claim")
	case localapi.OpComplete, localapi.OpReject:
		c.outcomes[request.EventID] = request.Op
		return localapi.Response{OK: true}, nil
	default:
		return localapi.Response{}, errors.New("unexpected multi-runtime operation")
	}
}

type agentStatusRunner struct{ raw []byte }

func (r agentStatusRunner) run(context.Context, string, ...string) ([]byte, error) {
	return append([]byte(nil), r.raw...), nil
}

func TestDecodePreparedActionBindsTOSCTLDeploymentGeneration(t *testing.T) {
	boc := []byte("canonical-fixture-boc")
	digest := sha256.Sum256(boc)
	deploymentID := "sha256:" + strings.Repeat("55", 32)
	value := preparedAction{
		Schema:               "tosctl.agent-account.prepared-action.v1",
		ActionID:             strings.Repeat("11", 32),
		Action:               "agent-native-send",
		Account:              "-1:" + strings.Repeat("22", 32),
		DeploymentID:         deploymentID,
		ControllerEpoch:      7,
		Seqno:                9,
		NetworkGlobalID:      -3,
		ValidUntil:           2_000_000_000,
		ExactSignedBOC:       base64.StdEncoding.EncodeToString(boc),
		ExactSignedBOCDigest: "sha256:" + hex.EncodeToString(digest[:]),
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePreparedAction(raw, value.ActionID, value.Action, value.Account, deploymentID, value.ControllerEpoch, value.Seqno, value.NetworkGlobalID, value.ValidUntil)
	if err != nil || !bytes.Equal(decoded, boc) {
		t.Fatalf("tosctl-shaped prepared action did not round trip: %x %v", decoded, err)
	}
	if _, err := decodePreparedAction(raw, value.ActionID, value.Action, value.Account, strings.TrimPrefix(deploymentID, "sha256:"), value.ControllerEpoch, value.Seqno, value.NetworkGlobalID, value.ValidUntil); err == nil {
		t.Fatal("bare-hex deployment ID was accepted across the tosctl/OpenFox boundary")
	}
}

func (c *runtimeMessengerCaller) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	switch request.Op {
	case localapi.OpPendingAgentGifts:
		if c.completed {
			return localapi.Response{OK: true}, nil
		}
		return localapi.Response{OK: true, Events: []localapi.PendingEvent{c.pending}}, nil
	case localapi.OpClaimAgentGift:
		if request.EventID != c.pending.EventID || request.LeaseID == "" {
			return localapi.Response{}, errors.New("wrong runtime claim")
		}
		claimed := c.pending
		return localapi.Response{OK: true, Event: &claimed}, nil
	case localapi.OpComplete:
		if request.EventID != c.pending.EventID || request.LeaseID == "" {
			return localapi.Response{}, errors.New("wrong runtime completion")
		}
		c.completed = true
		return localapi.Response{OK: true}, nil
	default:
		return localapi.Response{}, errors.New("unexpected runtime Messenger operation")
	}
}

func (c *recordingMessengerCaller) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	c.request = request
	return localapi.Response{OK: true, AgentID: request.Recipient, EventID: "evt_" + strings.Repeat("e", 64), Readiness: "queued"}, nil
}

func TestAgentGiftMessengerUsesOnlyDaemonOwnedDirectApplicationAPI(t *testing.T) {
	caller := &recordingMessengerCaller{}
	messenger, err := NewAgentGiftMessenger(caller, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	messenger.now = func() time.Time { return time.Unix(1_900_000_000, 0) }
	recipient := "agent_" + strings.Repeat("a", 64)
	canonical := []byte{0xa1, 0x01, 0x02}
	event, err := messenger.SendEstablishedDirect(context.Background(), recipient, "agent.gift.address-request", canonical, strings.Repeat("b", 64))
	if err != nil || event == "" || caller.request.Op != localapi.OpSendDirectApplication || caller.request.Recipient != recipient || caller.request.ApplicationKind != "agent.gift.address-request" || string(caller.request.ApplicationBody) != string(canonical) || caller.request.RoomID != "" || caller.request.SessionID != "" || caller.request.RecipientEndpointID != "" {
		t.Fatalf("wrong Messenger authority boundary: %+v %v", caller.request, err)
	}
}

func TestTOSCTLCustodyConsumesCompleteStrictAgentAccountStatus(t *testing.T) {
	matched := true
	seqno := uint32(7)
	epoch := uint64(3)
	value := agentAccountStatus{Wallet: "agent", Address: "-1:" + strings.Repeat("a", 64), State: "active", Balance: "2.000000000", CodeHash: strings.TrimPrefix(protocolgift.AgentAccountCodeHash, "tvm-cell-sha256:"), TemplateMatches: &matched, Owner: "-1:" + strings.Repeat("b", 64), ControllerPublicKey: strings.Repeat("c", 64), DeploymentID: strings.Repeat("d", 64), ControllerEpoch: &epoch, Seqno: &seqno, MatchesProfile: &matched}
	raw, _ := json.Marshal(value)
	custody := &TOSCTLGiftCustody{config: TOSCTLGiftCustodyConfig{BinaryPath: "/tosctl", ConfigPath: "/config", WalletName: value.Wallet, OwnerWallet: value.Owner, Timeout: time.Second}, runner: agentStatusRunner{raw: raw}}
	address, err := custody.SenderAccount(context.Background())
	if err != nil || address != value.Address {
		t.Fatalf("strict status failed: %q %v", address, err)
	}
	var changed map[string]any
	_ = json.Unmarshal(raw, &changed)
	changed["unknown"] = true
	changedRaw, _ := json.Marshal(changed)
	custody.runner = agentStatusRunner{raw: changedRaw}
	if _, err := custody.SenderAccount(context.Background()); err == nil {
		t.Fatal("unknown tosctl status field was accepted")
	}
}

func TestAgentGiftRecipientAuthorityResolvesAliasOnceFromFinalizedEvidence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	want := "agent_" + strings.Repeat("a", 64)
	client := aliasClientFunc(func(_ context.Context, request *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
		if request.Name != "alice.tos" || request.Kind != nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT {
			return nil, errors.New("wrong alias authority request")
		}
		return validAliasEvidence(want, "alice.tos", request.Kind, uint64(now.Unix())), nil
	})
	authority, err := NewAgentGiftDNSRecipientAuthority(client, testAliasNetwork(), "openfox-agent-gift")
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return now }
	got, err := authority.ResolveCanonicalAgent(context.Background(), "alice.tos")
	if err != nil || got != want {
		t.Fatalf("alias did not freeze to canonical AgentID: %q %v", got, err)
	}
	got, err = authority.ResolveCanonicalAgent(context.Background(), want)
	if err != nil || got != want {
		t.Fatalf("canonical AgentID pass-through failed: %q %v", got, err)
	}
}

func TestAgentGiftResolverMapsExecutableFundingAndPolicyStates(t *testing.T) {
	base := protocolgift.FinalizedGiftObservation{Available: true, ExecutionFinalityKnown: true, FinalizedChainTime: 100, ExpectedDeploymentID: "deploy", CurrentDeploymentID: "deploy", SignedSeqno: 3, CurrentSeqno: 3, ValidUntil: 200, ControllerCurrentlyMatches: true, PolicyCurrentlyAllows: true, BalanceAtomic: 200, AmountAtomic: 100, FeeReserveAtomic: 10}
	chain := fixtureChain(t)
	chain.observation = &base
	resolver, err := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	record := openfoxgift.Record{DeploymentID: "deploy", Seqno: 3, ValidUntil: 200}
	result, err := resolver.ResolveFinality(context.Background(), record)
	if err != nil || result.State != openfoxgift.StateCurrentlyExecutable {
		t.Fatalf("executable state: %+v %v", result, err)
	}
	chain.observation.BalanceAtomic = 109
	result, err = resolver.ResolveFinality(context.Background(), record)
	if err != nil || result.State != openfoxgift.StateInsufficientFunds {
		t.Fatalf("insufficient state: %+v %v", result, err)
	}
	chain.observation.BalanceAtomic = 200
	chain.observation.PolicyCurrentlyAllows = false
	result, err = resolver.ResolveFinality(context.Background(), record)
	if err != nil || result.State != openfoxgift.StateCurrentlyUnexecutable {
		t.Fatalf("policy state: %+v %v", result, err)
	}
	chain.observation.PolicyCurrentlyAllows = true
	chain.observation.ExactExternalBOCExecuted = true
	chain.observation.DestinationCreditFinalityKnown = false
	result, err = resolver.ResolveFinality(context.Background(), record)
	if err != nil || result.State != openfoxgift.StateFinalityUnknown {
		t.Fatalf("pending destination credit state: %+v %v", result, err)
	}
}

func TestAgentGiftRuntimeClaimsProcessesAndCompletesDaemonEvent(t *testing.T) {
	ctx := context.Background()
	chain := fixtureChain(t)
	protocol, _ := NewAgentGiftProtocol(chain, 1_000_000, 60)
	resolver, _ := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	wire := &fixtureGiftMessenger{}
	boc, _ := base64.StdEncoding.DecodeString(rustGiftBOC)
	custody := &fixtureGiftCustody{chain: chain, boc: boc}
	broadcaster := &fixtureGiftBroadcaster{}
	owner, _ := NewAgentGiftOwnerAuthorizer(&recordingConfirmer{})
	recipientID := "agent_" + strings.Repeat("c", 64)
	senderID := "agent_" + strings.Repeat("b", 64)
	service, err := openfoxgift.NewService(fixtureJournal(t, "runtime-recipient"), protocol, resolver, wire, custody, broadcaster, fixtureGiftAddress{address: "0:" + strings.Repeat("2", 64)}, owner)
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := protocol.CreateAddressRequest(ctx, openfoxgift.RequestIntent{Network: "tos-test", GlobalID: 42, IntentID: strings.Repeat("a", 64), SenderAgentID: senderID, RecipientAgentID: recipientID, SenderAgentAccount: chain.account.Address, AmountAtomic: "1000000000", RequestedValidUntil: 2_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.GiftAddressRequest{CanonicalRequest: request})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: testAliasNetwork(), ConversationID: "conv_" + strings.Repeat("1", 64), SenderAgentID: senderID, SenderEndpointID: "mep_" + strings.Repeat("3", 64), SenderDeviceID: "dev_" + strings.Repeat("4", 64), CreatedAtUnix: 1_999_999_000, ExpiresAtUnix: 2_000_000_000, Kind: "agent.gift.address-request", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	eventJSON, _ := envelope.EncodeEventJSON(event)
	caller := &runtimeMessengerCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: eventJSON}}
	runtime, err := NewAgentGiftRuntime(service, caller, AgentGiftRuntimeConfig{LocalAgentID: recipientID, Network: "tos-test", GlobalID: 42, ResponseLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runtime.now = func() time.Time { return time.Unix(1_999_999_000, 0).UTC() }
	if err := runtime.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	records := service.ListRecords()
	if !caller.completed || len(records) != 1 || records[0].State != openfoxgift.StateAddressResponseSent || len(wire.body) == 0 {
		t.Fatalf("runtime did not durably process claimed Event: completed=%v records=%+v", caller.completed, records)
	}
}

func TestAgentGiftRuntimeQuarantinesPoisonEventAndContinues(t *testing.T) {
	ctx := context.Background()
	chain := fixtureChain(t)
	protocol, _ := NewAgentGiftProtocol(chain, 1_000_000, 60)
	resolver, _ := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	wire := &fixtureGiftMessenger{}
	boc, _ := base64.StdEncoding.DecodeString(rustGiftBOC)
	service, _ := openfoxgift.NewService(fixtureJournal(t, "runtime-poison"), protocol, resolver, wire, &fixtureGiftCustody{chain: chain, boc: boc}, &fixtureGiftBroadcaster{}, fixtureGiftAddress{address: "0:" + strings.Repeat("2", 64)}, mustOwner(t))
	recipientID := "agent_" + strings.Repeat("c", 64)
	senderID := "agent_" + strings.Repeat("b", 64)
	valid, _, _ := protocol.CreateAddressRequest(ctx, openfoxgift.RequestIntent{Network: "tos-test", GlobalID: 42, IntentID: strings.Repeat("a", 64), SenderAgentID: senderID, RecipientAgentID: recipientID, SenderAgentAccount: chain.account.Address, AmountAtomic: "1000000000", RequestedValidUntil: 2_000_000_000})
	makeEvent := func(canonical []byte, digit string) localapi.PendingEvent {
		content, err := payload.Encode(payload.GiftAddressRequest{CanonicalRequest: canonical})
		if err != nil {
			t.Fatal(err)
		}
		event, err := envelope.NewEvent(envelope.Event{Network: testAliasNetwork(), ConversationID: "conv_" + strings.Repeat(digit, 64), SenderAgentID: senderID, SenderEndpointID: "mep_" + strings.Repeat("3", 64), SenderDeviceID: "dev_" + strings.Repeat("4", 64), CreatedAtUnix: 1_999_999_000, ExpiresAtUnix: 2_000_000_000, Kind: "agent.gift.address-request", Content: content})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := envelope.EncodeEventJSON(event)
		return localapi.PendingEvent{EventID: event.EventID, Event: raw}
	}
	poison := makeEvent([]byte{0xff}, "5")
	good := makeEvent(valid, "6")
	corrupt := localapi.PendingEvent{EventID: "evt_" + strings.Repeat("7", 64), Event: []byte("{")}
	caller := &multiRuntimeCaller{events: []localapi.PendingEvent{corrupt, poison, good}}
	runtime, _ := NewAgentGiftRuntime(service, caller, AgentGiftRuntimeConfig{LocalAgentID: recipientID, Network: "tos-test", GlobalID: 42, ResponseLifetime: time.Hour})
	runtime.now = func() time.Time { return time.Unix(1_999_999_000, 0).UTC() }
	if err := runtime.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	counts := runtime.FaultCounts()
	if caller.outcomes[poison.EventID] != localapi.OpReject || caller.outcomes[good.EventID] != localapi.OpComplete || caller.outcomes[corrupt.EventID] != "" || counts[AgentGiftFaultInboundRejected] != 1 || counts[AgentGiftFaultPendingCorrupt] != 1 || len(service.ListRecords()) != 1 {
		t.Fatalf("poison isolation failed: outcomes=%v faults=%v", caller.outcomes, counts)
	}
}

func TestAgentGiftRuntimeRetriesMessengerInfrastructureFailure(t *testing.T) {
	chain := fixtureChain(t)
	protocol, _ := NewAgentGiftProtocol(chain, 1_000_000, 60)
	resolver, _ := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	service, _ := openfoxgift.NewService(fixtureJournal(t, "runtime-infrastructure"), protocol, resolver,
		&fixtureGiftMessenger{}, &fixtureGiftCustody{chain: chain}, &fixtureGiftBroadcaster{},
		fixtureGiftAddress{address: "0:" + strings.Repeat("2", 64)}, mustOwner(t))
	ctx, cancel := context.WithCancel(context.Background())
	caller := &retryingRuntimeCaller{cancel: cancel, done: make(chan struct{})}
	runtime, err := NewAgentGiftRuntime(service, caller, AgentGiftRuntimeConfig{
		LocalAgentID: "agent_" + strings.Repeat("c", 64), Network: "tos-test", GlobalID: 42,
		PollInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if caller.calls != 2 || runtime.FaultCounts()[AgentGiftFaultInfrastructure] != 1 {
		t.Fatalf("transient Messenger failure stopped reconciliation: calls=%d faults=%v", caller.calls, runtime.FaultCounts())
	}
}

func TestInboundAddressResponseRequiresSeparateOwnerAuthorizationCall(t *testing.T) {
	ctx := context.Background()
	chain := fixtureChain(t)
	protocol, _ := NewAgentGiftProtocol(chain, 1_000_000, 60)
	resolver, _ := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	confirmer := &recordingConfirmer{}
	owner, _ := NewAgentGiftOwnerAuthorizer(confirmer)
	senderID := "agent_" + strings.Repeat("b", 64)
	recipientID := "agent_" + strings.Repeat("c", 64)
	service, _ := openfoxgift.NewService(fixtureJournal(t, "runtime-explicit-owner"), protocol, resolver,
		&fixtureGiftMessenger{}, &fixtureGiftCustody{chain: chain}, &fixtureGiftBroadcaster{},
		fixtureGiftAddress{address: "0:" + strings.Repeat("2", 64)}, owner)
	record, err := service.StartSender(ctx, openfoxgift.ModelProposal{Recipient: recipientID, AmountAtomic: "1000000000", RequestedValidUntil: 2_000_000_000}, "tos-test", 42, senderID)
	if err != nil {
		t.Fatal(err)
	}
	record, err = service.RequestAddress(ctx, record.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := protocol.CreateAddressResponse(ctx, record.CanonicalRequest, "0:"+strings.Repeat("2", 64), 2_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := NewAgentGiftRuntime(service, &runtimeMessengerCaller{}, AgentGiftRuntimeConfig{LocalAgentID: senderID, Network: "tos-test", GlobalID: 42})
	durable, err := runtime.applyInbound(ctx, AgentGiftInbound{EventID: "evt_" + strings.Repeat("1", 64), SenderAgentID: recipientID, Kind: "agent.gift.address-response", Canonical: response})
	if err != nil || !durable {
		t.Fatalf("response application failed: durable=%v err=%v", durable, err)
	}
	persisted := service.ListRecords()[0]
	if persisted.State != openfoxgift.StateAddressReceived || confirmer.review.IntentID != "" {
		t.Fatalf("network event triggered owner authority: state=%s review=%+v", persisted.State, confirmer.review)
	}
}

func mustOwner(t *testing.T) *AgentGiftOwnerAuthorizer {
	t.Helper()
	owner, err := NewAgentGiftOwnerAuthorizer(&recordingConfirmer{})
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func (f *fixtureGiftChain) FinalizedAgentAccount(context.Context, string) (protocolgift.FinalizedAgentAccount, uint32, error) {
	return f.account, 1_999_999_000, nil
}
func (f *fixtureGiftChain) ResolveFinalizedGift(_ context.Context, record openfoxgift.Record) (protocolgift.FinalizedGiftObservation, error) {
	if f.observation != nil {
		return *f.observation, nil
	}
	return protocolgift.FinalizedGiftObservation{Available: true, ExecutionFinalityKnown: true, FinalizedChainTime: 1_999_999_100, ExpectedDeploymentID: record.DeploymentID, CurrentDeploymentID: record.DeploymentID, SignedSeqno: record.Seqno, CurrentSeqno: record.Seqno + 1, ValidUntil: record.ValidUntil, ExactExternalBOCExecuted: f.paid, ExactDestinationCredit: f.paid, DestinationCreditFinalityKnown: f.paid, ControllerCurrentlyMatches: true, PolicyCurrentlyAllows: true, BalanceAtomic: 2_000_000_000, AmountAtomic: 1_000_000_000, FeeReserveAtomic: 1_000_000}, nil
}

func fixtureChain(t *testing.T) *fixtureGiftChain {
	t.Helper()
	public, err := hex.DecodeString("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureGiftChain{account: protocolgift.FinalizedAgentAccount{Active: true, Address: "-1:c0e0a65d0fe1a48322b56546b49ee42675bd8e39538662801fee50d2b5f41621", OwnerAddress: "-1:" + strings.Repeat("1", 64), CodeHash: protocolgift.AgentAccountCodeHash, DeploymentID: "sha256:" + strings.Repeat("d", 64), GlobalID: 42, TVMVersion: protocolgift.MinimumAgentAccountTVMVersion, ControllerPublicKey: ed25519.PublicKey(public), ControllerEpoch: 0, Seqno: 0, BalanceAtomic: 2_000_000_000, MaxPerTxAtomic: 2_000_000_000, DailyRemainingAtomic: 2_000_000_000, DefaultTaskTimeoutSecs: 3_600}}
}

func TestAgentGiftProtocolConsumesRustFixtureAndRejectsExchangeSubstitution(t *testing.T) {
	ctx := context.Background()
	chain := fixtureChain(t)
	adapter, err := NewAgentGiftProtocol(chain, 1_000_000, 60)
	if err != nil {
		t.Fatal(err)
	}
	intent := openfoxgift.RequestIntent{Network: "tos-fixture", GlobalID: 42, IntentID: strings.Repeat("a", 64), SenderAgentID: "agent_" + strings.Repeat("b", 64), RecipientAgentID: "agent_" + strings.Repeat("c", 64), SenderAgentAccount: chain.account.Address, AmountAtomic: "1000000000", RequestedValidUntil: 2_000_000_000}
	request, _, err := adapter.CreateAddressRequest(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := adapter.CreateAddressResponse(ctx, request, "0:"+strings.Repeat("2", 64), 2_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	boc, _ := base64.StdEncoding.DecodeString(rustGiftBOC)
	offer, signedID, err := adapter.CreateSignedOffer(ctx, request, response, boc, "private greeting")
	if err != nil {
		t.Fatal(err)
	}
	terms, err := adapter.VerifySignedOffer(ctx, request, response, offer)
	if err != nil || terms.SignedGiftID != signedID || terms.DestinationAddress != "0:"+strings.Repeat("2", 64) {
		t.Fatalf("fixture verification failed: %+v %v", terms, err)
	}
	changed, _, _ := adapter.CreateAddressResponse(ctx, request, "0:"+strings.Repeat("3", 64), 2_000_000_000)
	if _, err := adapter.VerifySignedOffer(ctx, request, changed, offer); err == nil {
		t.Fatal("destination substitution was accepted")
	}
}

type recordingConfirmer struct {
	review openfoxgift.OwnerReview
	err    error
}

func (r *recordingConfirmer) ConfirmAgentGift(_ context.Context, review openfoxgift.OwnerReview) error {
	r.review = review
	return r.err
}

func TestOwnerAuthorizerHashesOnlyTheCompleteConfirmedReview(t *testing.T) {
	confirmer := &recordingConfirmer{}
	authorizer, _ := NewAgentGiftOwnerAuthorizer(confirmer)
	review := openfoxgift.OwnerReview{Action: "send", IntentID: strings.Repeat("a", 64), RecipientAgentID: "agent_" + strings.Repeat("b", 64), Network: "tos-fixture", GlobalID: 42, AmountAtomic: "1000000000", DestinationAddress: "0:" + strings.Repeat("2", 64), SenderAgentAccount: "-1:" + strings.Repeat("3", 64), OwnerWallet: "-1:" + strings.Repeat("4", 64), ControllerKeyID: "controller:test", DeploymentID: "sha256:" + strings.Repeat("d", 64), ControllerEpoch: 9, FeeReserveAtomic: "1000000", Seqno: 7, ValidUntil: 2_000_000_000, RequestDigest: "sha256:" + strings.Repeat("5", 64), ResponseDigest: "sha256:" + strings.Repeat("6", 64), UnsignedTransferDigest: "sha256:" + strings.Repeat("7", 64), FundsLocked: false}
	digest, err := authorizer.Authorize(context.Background(), review)
	if err != nil || digest == "" || confirmer.review.Seqno != 7 || confirmer.review.FeeReserveAtomic != "1000000" || confirmer.review.FundsLocked {
		t.Fatalf("incomplete owner review: %+v %v", confirmer.review, err)
	}
	changed := review
	changed.Seqno++
	changedDigest, err := authorizer.Authorize(context.Background(), changed)
	if err != nil || changedDigest == digest {
		t.Fatal("changed owner semantics reused an authorization digest")
	}
	confirmer.err = errors.New("declined")
	if _, err := authorizer.Authorize(context.Background(), review); err == nil {
		t.Fatal("declined owner review was authorized")
	}
}

func TestTerminalOwnerConfirmationRendersCompleteRiskReviewAndNeedsExactPhrase(t *testing.T) {
	review := openfoxgift.OwnerReview{Action: "send", IntentID: strings.Repeat("a", 64), RecipientAgentID: "agent_" + strings.Repeat("b", 64), Network: "tos-test", GlobalID: 42, AmountAtomic: "1000000000", DestinationAddress: "0:" + strings.Repeat("2", 64), SenderAgentAccount: "-1:" + strings.Repeat("3", 64), OwnerWallet: "-1:" + strings.Repeat("4", 64), ControllerKeyID: "controller:test", FeeReserveAtomic: "1000000", Seqno: 7, ValidUntil: 2_000_000_000, RequestDigest: "sha256:" + strings.Repeat("5", 64), ResponseDigest: "sha256:" + strings.Repeat("6", 64), UnsignedTransferDigest: "sha256:" + strings.Repeat("7", 64)}
	input := strings.NewReader("AUTHORIZE send " + review.IntentID + "\n")
	var output bytes.Buffer
	if err := confirmAgentGiftOnTerminal(context.Background(), input, &output, review); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, required := range []string{review.RecipientAgentID, review.Network, review.AmountAtomic, review.DestinationAddress, review.SenderAgentAccount, review.OwnerWallet, review.ControllerKeyID, review.FeeReserveAtomic, review.RequestDigest, review.ResponseDigest, "Funds are not locked", "Only finalized exact destination credit"} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("owner review omitted %q", required)
		}
	}
	if err := confirmAgentGiftOnTerminal(context.Background(), strings.NewReader("yes\n"), &bytes.Buffer{}, review); err == nil {
		t.Fatal("non-specific owner approval phrase was accepted")
	}
}

type fixtureGiftMessenger struct {
	recipient, kind string
	body            []byte
}

func (m *fixtureGiftMessenger) SendEstablishedDirect(_ context.Context, recipient, kind string, body []byte, _ string) (string, error) {
	m.recipient, m.kind, m.body = recipient, kind, append([]byte(nil), body...)
	return "evt_" + strings.Repeat("8", 64), nil
}

type fixtureGiftCustody struct {
	chain       *fixtureGiftChain
	boc         []byte
	cancelCalls int
	failCancel  bool
}

func (c *fixtureGiftCustody) SenderAccount(context.Context) (string, error) {
	return c.chain.account.Address, nil
}
func (c *fixtureGiftCustody) PrepareNativeGift(_ context.Context, request openfoxgift.SignRequest) (openfoxgift.CustodyReview, error) {
	req, err := protocolgift.DecodeAddressRequest(request.CanonicalRequest)
	if err != nil {
		return openfoxgift.CustodyReview{}, err
	}
	res, err := protocolgift.DecodeAddressResponse(request.CanonicalResponse)
	if err != nil {
		return openfoxgift.CustodyReview{}, err
	}
	requestDigest, _ := protocolgift.RequestDigest(req)
	responseDigest, _ := protocolgift.ResponseDigest(res)
	unsignedDigest, _ := protocolgift.UnsignedTransferDigest(protocolgift.UnsignedTransferV1{Network: req.Network, GlobalID: req.GlobalID, SenderAgentAccount: req.SenderAgentAccount, DeploymentID: c.chain.account.DeploymentID, ControllerEpoch: c.chain.account.ControllerEpoch, Seqno: c.chain.account.Seqno, ValidUntil: res.ResponseNotAfter, DestinationAddress: res.DestinationAddress, AmountAtomic: req.AmountAtomic, SendMode: 3, Bounce: false})
	return openfoxgift.CustodyReview{Network: req.Network, GlobalID: req.GlobalID, RecipientAgentID: req.RecipientAgentID, SenderAgentAccount: req.SenderAgentAccount, OwnerWallet: c.chain.account.OwnerAddress, ControllerKeyID: "controller:fixture", DeploymentID: c.chain.account.DeploymentID, DestinationAddress: res.DestinationAddress, AmountAtomic: req.AmountAtomic, FeeReserveAtomic: "1000000", RequestDigest: requestDigest, ResponseDigest: responseDigest, UnsignedTransferDigest: unsignedDigest, ControllerEpoch: c.chain.account.ControllerEpoch, Seqno: c.chain.account.Seqno, ValidUntil: res.ResponseNotAfter}, nil
}
func (c *fixtureGiftCustody) SignNativeGift(_ context.Context, request openfoxgift.SignRequest) ([]byte, error) {
	if request.OwnerAuthorizationDigest == "" || request.UnsignedTransferDigest == "" {
		return nil, errors.New("missing fixture authorization")
	}
	return append([]byte(nil), c.boc...), nil
}
func (c *fixtureGiftCustody) CancelSeqno(context.Context, openfoxgift.CancelRequest) ([]byte, error) {
	c.cancelCalls++
	if c.failCancel {
		c.failCancel = false
		return nil, errors.New("fixture cancellation preparation failed")
	}
	return []byte{1}, nil
}

type fixtureGiftBroadcaster struct{ calls int }

func (b *fixtureGiftBroadcaster) BroadcastExactBOC(_ context.Context, boc []byte) error {
	if len(boc) == 0 {
		return errors.New("empty fixture BOC")
	}
	b.calls++
	return nil
}

type fixtureGiftAddress struct{ address string }

func (a fixtureGiftAddress) SelectDestination(context.Context, string) (string, error) {
	return a.address, nil
}

func fixtureJournal(t *testing.T, name string) *openfoxgift.Journal {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := openfoxgift.OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func TestFixtureEndToEndAcrossOpenFoxProtocolAndRustAgentAccountBOC(t *testing.T) {
	ctx := context.Background()
	chain := fixtureChain(t)
	protocol, _ := NewAgentGiftProtocol(chain, 1_000_000, 60)
	resolver, _ := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	wire := &fixtureGiftMessenger{}
	boc, _ := base64.StdEncoding.DecodeString(rustGiftBOC)
	custody := &fixtureGiftCustody{chain: chain, boc: boc}
	broadcaster := &fixtureGiftBroadcaster{}
	owner, _ := NewAgentGiftOwnerAuthorizer(&recordingConfirmer{})
	address := fixtureGiftAddress{address: "0:" + strings.Repeat("2", 64)}
	sender, err := openfoxgift.NewService(fixtureJournal(t, "sender"), protocol, resolver, wire, custody, broadcaster, address, owner)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := openfoxgift.NewService(fixtureJournal(t, "recipient"), protocol, resolver, wire, custody, broadcaster, address, owner)
	if err != nil {
		t.Fatal(err)
	}
	senderID := "agent_" + strings.Repeat("b", 64)
	recipientID := "agent_" + strings.Repeat("c", 64)
	record, err := sender.StartSender(ctx, openfoxgift.ModelProposal{Recipient: recipientID, AmountAtomic: "1000000000", RequestedValidUntil: 2_000_000_000, Greeting: "private"}, "tos-fixture", 42, senderID)
	if err != nil {
		t.Fatal(err)
	}
	record, _ = sender.RequestAddress(ctx, record.IntentID)
	recipientRecord, err := recipient.ObserveRecipientRequest(ctx, wire.body, recipientID, senderID)
	if err != nil {
		t.Fatal(err)
	}
	recipientRecord, err = recipient.RespondAddress(ctx, recipientRecord.IntentID, 2_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.ObserveAddressResponse(ctx, record.IntentID, wire.body)
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.Authorize(ctx, record.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	record, err = sender.Sign(ctx, record.IntentID, "private")
	if err != nil {
		t.Fatal(err)
	}
	record, _ = sender.DeliverOffer(ctx, record.IntentID)
	recipientRecord, err = recipient.ObserveAndBroadcastOffer(ctx, recipientRecord.IntentID, wire.body)
	if err != nil || broadcaster.calls != 1 || recipientRecord.State != openfoxgift.StateBroadcastSubmitted {
		t.Fatalf("fixture broadcast: %+v %v", recipientRecord, err)
	}
	chain.paid = true
	if record, err = sender.Refresh(ctx, record.IntentID); err != nil || record.State != openfoxgift.StateFinalizedPaid {
		t.Fatalf("sender finalized fixture: %+v %v", record, err)
	}
	if recipientRecord, err = recipient.Refresh(ctx, recipientRecord.IntentID); err != nil || recipientRecord.State != openfoxgift.StateFinalizedPaid {
		t.Fatalf("recipient finalized fixture: %+v %v", recipientRecord, err)
	}
}

func TestAgentGiftRuntimeResumesCancellationPreparationBeforeOfferDelivery(t *testing.T) {
	ctx := context.Background()
	chain := fixtureChain(t)
	protocol, _ := NewAgentGiftProtocol(chain, 1_000_000, 60)
	resolver, _ := NewAgentGiftResolver(chain, fixtureRecipientAuthority{})
	wire := &fixtureGiftMessenger{}
	boc, _ := base64.StdEncoding.DecodeString(rustGiftBOC)
	custody := &fixtureGiftCustody{chain: chain, boc: boc, failCancel: true}
	broadcaster := &fixtureGiftBroadcaster{}
	owner, _ := NewAgentGiftOwnerAuthorizer(&recordingConfirmer{})
	service, _ := openfoxgift.NewService(fixtureJournal(t, "runtime-cancel"), protocol, resolver, wire, custody, broadcaster, fixtureGiftAddress{address: "0:" + strings.Repeat("2", 64)}, owner)
	senderID := "agent_" + strings.Repeat("b", 64)
	recipientID := "agent_" + strings.Repeat("c", 64)
	record, _ := service.StartSender(ctx, openfoxgift.ModelProposal{Recipient: recipientID, AmountAtomic: "1000000000", RequestedValidUntil: 2_000_000_000}, "tos-fixture", 42, senderID)
	record, _ = service.RequestAddress(ctx, record.IntentID)
	response, _, _ := protocol.CreateAddressResponse(ctx, record.CanonicalRequest, "0:"+strings.Repeat("2", 64), 2_000_000_000)
	record, _ = service.ObserveAddressResponse(ctx, record.IntentID, response)
	record, _ = service.Authorize(ctx, record.IntentID)
	record, _ = service.Sign(ctx, record.IntentID, "")
	if _, err := service.Cancel(ctx, record.IntentID); err == nil {
		t.Fatal("expected cancellation preparation failure")
	}
	persisted := service.ListRecords()[0]
	if persisted.PendingEffect != openfoxgift.EffectPrepareCancel {
		t.Fatalf("wrong crash state: %+v", persisted)
	}
	caller := &recordingMessengerCaller{}
	runtime, _ := NewAgentGiftRuntime(service, caller, AgentGiftRuntimeConfig{LocalAgentID: senderID, Network: "tos-fixture", GlobalID: 42})
	if err := runtime.advance(ctx, persisted); err != nil {
		t.Fatal(err)
	}
	resumed := service.ListRecords()[0]
	if resumed.PendingEffect != openfoxgift.EffectCancel || custody.cancelCalls != 2 || wire.kind == "agent.gift.signed-boc-offer" {
		t.Fatalf("runtime did not prioritize cancellation recovery: %+v", resumed)
	}
}
