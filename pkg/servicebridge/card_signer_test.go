package servicebridge

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// cardSignerOf decodes a held card and returns the key that signed it.
func cardSignerOf(t *testing.T, agent string, cardJSON []byte) [mldsa44.KeyIDSize]byte {
	t.Helper()
	_, signer, err := decodeOwnCardSigned(agent, cardJSON)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func keyIDOf(t *testing.T, text string) [mldsa44.KeyIDSize]byte {
	t.Helper()
	keyID, err := mldsa44.ParseKeyIDText(text)
	if err != nil {
		t.Fatal(err)
	}
	return keyID
}

func TestTheCardSignerRefusesThePacketControllerAndAMissingController(t *testing.T) {
	packet := packetKeys.KeyID(testSeller)
	if _, err := NewCardSigner(packetKeys, "seller-card", packet, testSeller, packet); !errors.Is(err,
		ErrCardControllerIsPacketController) {
		t.Fatalf("the packet controller was accepted as the card controller: %v", err)
	}
	if _, err := NewCardSigner(packetKeys, "", "", testSeller, packet); !errors.Is(err, ErrCardControllerMissing) {
		t.Fatalf("a missing card controller was not refused as missing: %v", err)
	}
	config := NodeConfig{AgentID: testSeller, PacketController: testSeller, PacketKeyID: packet}
	if _, err := newConfigCardSigner(packetKeys, config); !errors.Is(err, ErrCardControllerMissing) {
		t.Fatalf("a configuration without a card controller was not refused as missing: %v", err)
	}
	config.CardController, config.CardKeyID = "another-name", packet
	if err := validateCardConfig(config); !errors.Is(err, ErrCardControllerIsPacketController) {
		t.Fatalf("a card key equal to the packet key was accepted: %v", err)
	}
	config.CardController, config.CardKeyID = testCardController(testSeller),
		packetKeys.KeyID(testCardController(testSeller))
	if err := validateCardConfig(config); err != nil {
		t.Fatalf("a valid card controller was refused: %v", err)
	}
}

func TestTheChatLaneRefusesToSignCardsWithThePacketController(t *testing.T) {
	clock := newRelayClock()
	dir := t.TempDir()
	if err := ensurePrivateDirectory(filepath.Join(dir, relayStateDir)); err != nil {
		t.Fatal(err)
	}
	daemon, err := carrierapi.NewClient(filepath.Join(dir, "absent.sock"), 0)
	if err != nil {
		t.Fatal(err)
	}
	lane := chatLaneConfig{
		Relays: []string{"http://127.0.0.1:9"}, CardPath: filepath.Join(dir, "card.json"),
		Signer: testSigner(t, testSeller), Daemon: daemon,
	}
	open := func(lane chatLaneConfig) error {
		_, err := openChatCarrier(filepath.Join(dir, relayStateDir), testSeller, lane, packetKeys, relayAgents(),
			newRelayPool(nil), clock.Now, nil)
		return err
	}
	if err := open(lane); !errors.Is(err, ErrCardControllerMissing) {
		t.Fatalf("a chat lane without a card signer was opened: %v", err)
	}
	// A card signer built around the packet controller, bypassing its
	// constructor, is still refused.
	lane.CardSigner = &CardSigner{packet: testSigner(t, testSeller)}
	if err := open(lane); !errors.Is(err, ErrCardControllerIsPacketController) {
		t.Fatalf("a chat lane whose card signer is the packet controller was opened: %v", err)
	}
	lane.CardSigner = testCardSigner(t, testSeller)
	if err := open(lane); err != nil {
		t.Fatalf("a chat lane with the card-signing controller was refused: %v", err)
	}
}

func TestChatCardsAreSignedByTheCardControllerAndVerifyAgainstFinalizedPolicy(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	node := newChatTestNode(t, clock, testSeller, agents, relay.URL)
	card, err := node.chat.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := cardSignerOf(t, node.agent, card.CardJSON); got != keyIDOf(t,
		packetKeys.KeyID(testCardController(node.agent))) {
		t.Fatalf("the chat card is signed by %x, not the card-signing controller", got)
	}
	if got := cardSignerOf(t, node.agent, card.CardJSON); got == keyIDOf(t, packetKeys.KeyID(node.agent)) {
		t.Fatal("the chat card is signed by the packet controller")
	}
	packet, err := agentpacket.DecodeJSON(card.CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = agentpacketseal.VerifyKeyCard(context.Background(), packetKeys, agents, packet,
		clock.Now()); err != nil {
		t.Fatalf("a card signed by the card-signing controller does not verify: %v", err)
	}
	// The rail card is still the packet controller's: only chat moved.
	rail, err := node.carrier.Keys.Current(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := cardSignerOf(t, node.agent, rail.CardJSON); got != keyIDOf(t, packetKeys.KeyID(node.agent)) {
		t.Fatalf("the rail card is signed by %x, not the packet controller", got)
	}
}

func TestARevokedOrRotatedCardControllerIsRefusedAndTheCardIsReissued(t *testing.T) {
	ctx := context.Background()
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	peerCards, err := OpenPeerCards(filepath.Join(t.TempDir(), "peers"), packetKeys, agents, chatNoOwners{},
		clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	peerCards.AllowLoopbackRelays(true)
	dir := t.TempDir()
	keyDir := filepath.Join(dir, relayChatKeysDir)
	signer := testCardSigner(t, testSeller)
	signer.packet.now = clock.Now
	keys, err := OpenChatRelayKeys(keyDir, testSeller, []string{relay.URL}, signer, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := keys.Current(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = peerCards.Learn(ctx, first.CardJSON, testSeller, ""); err != nil {
		t.Fatalf("a card of the card-signing controller was refused: %v", err)
	}
	firstPacket, err := agentpacket.DecodeJSON(first.CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(packet agentpacket.Packet) error {
		_, _, verifyErr := agentpacketseal.VerifyKeyCard(ctx, packetKeys, agents, packet, clock.Now())
		return verifyErr
	}

	// Revoked: the card controller is removed from the finalized policy.
	// Its card no longer verifies, a sender refuses to seal to it, and the
	// packet controller still signs packets.
	agents.setCardController(testSeller, "")
	if err = verify(firstPacket); err == nil {
		t.Fatal("a card of a removed card-signing controller still verifies")
	}
	// A held card is verified again once its last check is older than the
	// re-verification bound.
	clock.Advance(RelayCardReverify)
	if _, err = peerCards.Current(ctx, testSeller); err == nil {
		t.Fatal("a sender still seals to a card of a removed card-signing controller")
	}
	if err = verifyPacketSender(ctx, agents, testSeller); err != nil {
		t.Fatalf("revoking the card controller stopped the packet controller: %v", err)
	}

	// Rotated: a new card controller replaces the old one. The old card
	// stays refused; the node, signing with the new controller, issues a
	// successor instead of handing out the old card, and keeps the old key
	// until its retention ends.
	const rotated = "card-rotated"
	agents.setCardController(testSeller, rotated)
	if err = verify(firstPacket); err == nil {
		t.Fatal("a card of a rotated-out card-signing controller still verifies")
	}
	next, err := NewCardSigner(packetKeys, rotated, packetKeys.KeyID(rotated), testSeller,
		packetKeys.KeyID(testSeller))
	if err != nil {
		t.Fatal(err)
	}
	next.packet.now = clock.Now
	reopened, err := OpenChatRelayKeys(keyDir, testSeller, []string{relay.URL}, next, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Current(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if second.KeyID == first.KeyID {
		t.Fatal("the card of the rotated-out controller was handed out again")
	}
	if got := cardSignerOf(t, testSeller, second.CardJSON); got != keyIDOf(t, packetKeys.KeyID(rotated)) {
		t.Fatalf("the re-issued card is signed by %x, not the new card-signing controller", got)
	}
	secondPacket, err := agentpacket.DecodeJSON(second.CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err = verify(secondPacket); err != nil {
		t.Fatalf("the re-issued card does not verify: %v", err)
	}
	if _, held := reopened.private(first.KeyID); !held {
		t.Fatal("the old key was destroyed before its retention ended")
	}
	if err = peerCards.Learn(ctx, second.CardJSON, testSeller, ""); err != nil {
		t.Fatalf("the re-issued card was refused: %v", err)
	}
	found, err := peerCards.Current(ctx, testSeller)
	if err != nil || found.Card.KeyID != second.KeyID {
		t.Fatalf("a sender does not seal to the re-issued card: %v", err)
	}
}

// verifyPacketSender checks that the Agent's packet controller still signs
// packets that verify against finalized state.
func verifyPacketSender(ctx context.Context, agents agentpacket.AgentResolver, agent string) error {
	signer, err := NewPacketSigner(packetKeys, agent, packetKeys.KeyID(agent), agent)
	if err != nil {
		return err
	}
	packet, err := signer.sign(ctx, testBuyer, relayCapability, "", []byte("still sends"))
	if err != nil {
		return err
	}
	return agentpacket.VerifySender(ctx, packetKeys, agents, packet)
}

func TestThePeerCardVerifierRuleIsTheSpecsAnyFinalizedController(t *testing.T) {
	// The relay specification makes the dedicated card controller the
	// issuer's recommendation: a verifier checks VerifyKeyCard (a live
	// controller of the finalized policy) and has no policy role to tell a
	// card controller from a packet controller. A peer's card signed by its
	// packet controller therefore verifies; what this node enforces is on
	// its own cards.
	ctx := context.Background()
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	agents := relayAgents()
	keyDir := filepath.Join(t.TempDir(), "keys")
	if err := ensurePrivateDirectory(keyDir); err != nil {
		t.Fatal(err)
	}
	keys, err := OpenChatRelayKeys(keyDir, testSeller, []string{relay.URL}, testSigner(t, testSeller), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	card, err := keys.Current(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := agentpacket.DecodeJSON(card.CardJSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = agentpacketseal.VerifyKeyCard(ctx, packetKeys, agents, packet, clock.Now()); err != nil {
		t.Fatalf("a peer card signed by a finalized controller was refused: %v", err)
	}
}

func TestCheckCardControllerRequiresAPolicyControllerWithoutAuthority(t *testing.T) {
	card := packetKeys.KeyID(testCardController(testSeller))
	packet := packetKeys.KeyID(testSeller)
	cases := map[string]struct {
		mutate func(*nativev1.AgentStateV1)
		key    string
		want   error
	}{
		"registered as init does": {mutate: func(*nativev1.AgentStateV1) {}, key: card},
		"the packet controller": {
			mutate: func(*nativev1.AgentStateV1) {}, key: packet, want: ErrCardControllerIsPacketController,
		},
		"not in the policy": {
			mutate: func(a *nativev1.AgentStateV1) { a.Policy.Controllers = a.Policy.Controllers[:1] }, key: card,
			want: ErrCardControllerNotInPolicy,
		},
		"meets the threshold alone": {
			mutate: func(a *nativev1.AgentStateV1) { a.Policy.Controllers[1].Weight = a.Policy.Threshold },
			key:    card, want: ErrCardControllerHasAuthority,
		},
		"holds recovery": {
			mutate: func(a *nativev1.AgentStateV1) { a.Policy.Controllers[1].Recovery = true }, key: card,
			want: ErrCardControllerHasAuthority,
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			agent := agentState(testSeller)
			test.mutate(agent)
			err := checkCardController(agent, test.key, packet)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	tombstoned := agentState(testSeller)
	tombstoned.Tombstoned = true
	if err := checkCardController(tombstoned, card, packet); err == nil {
		t.Fatal("a tombstoned Agent's card controller was accepted")
	}
	if err := checkCardController(nil, card, packet); err == nil {
		t.Fatal("an absent Agent's card controller was accepted")
	}
}

// fakeVaultSigner signs as the fake world's controllers: the key is the
// named controller's, the signature bytes are not checked by anything the
// setup tests run.
type fakeVaultSigner struct{}

func (fakeVaultSigner) Sign(_ context.Context, controller string, _ mldsa44.Use, _ []byte) (mldsa44.Signature,
	error,
) {
	key := fakeKey(controller)
	return mldsa44.Signature{
		KeyID: key.KeyID, PublicKey: key.PublicKey, Signature: make([]byte, mldsa44.SignatureSize),
	}, nil
}

// chatSetupFixture is an initialized node with a chat section on the fake
// world.
func chatSetupFixture(t *testing.T) (*setupFixture, *InitResult, SetupEnv) {
	t.Helper()
	f := newSetupFixture(t)
	f.init.MessengerSocket = ""
	f.init.RelayURLs = []string{"http://127.0.0.1:9"}
	f.init.Chat = &ChatConfig{MessengerCarrierSocket: filepath.Join(f.root, "daemon.sock")}
	result := f.mustInit(t)
	env := f.env()
	env.PacketSigner = func(TOSCTLConfig, string) (mldsa44.Signer, error) { return fakeVaultSigner{}, nil }
	return f, result, env
}

func TestChatInitSignsTheCardWithTheProvisionedCardController(t *testing.T) {
	f, initResult, env := chatSetupFixture(t)
	result, err := ChatRepublish(context.Background(), f.init.RailConfigPath, env)
	if err != nil {
		t.Fatal(err)
	}
	if result.CardController != initResult.CardController || result.CardKeyID != initResult.CardKeyID {
		t.Fatalf("the card reports controller %q (%s)", result.CardController, result.CardKeyID)
	}
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	key, published, err := heldChatCard(config, env.Now())
	if err != nil || !published {
		t.Fatalf("the card path does not hold the current card: %v", err)
	}
	if got := cardSignerOf(t, config.AgentID, key.CardJSON); got != fakeKey(initResult.CardController).KeyID {
		t.Fatalf("the chat card is signed by %x, not the card-signing controller", got)
	}
}

func TestChatInitRefusesACardControllerTheFinalizedPolicyDoesNotHold(t *testing.T) {
	f, initResult, env := chatSetupFixture(t)
	// The finalized policy no longer holds the card controller.
	f.change(func(w *fakeWorld) {
		w.Agents[initResult.AgentID] = fakePolicyJSON(t, 2, fakeController(f.init.PacketController, 2, 15))
	})
	_, err := ChatRepublish(context.Background(), f.init.RailConfigPath, env)
	if !errors.Is(err, ErrCardControllerNotInPolicy) {
		t.Fatalf("a card controller outside the finalized policy signed a card: %v", err)
	}
	config, loadErr := LoadNodeConfig(f.init.RailConfigPath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, _, heldErr := heldChatCard(config, env.Now()); heldErr == nil {
		t.Fatal("a chat card was issued although the card controller is not in the finalized policy")
	}
	// A configuration that names no card controller says so.
	config.CardController, config.CardKeyID = "", ""
	if err = writeNodeConfig(f.init.RailConfigPath, config); err != nil {
		t.Fatal(err)
	}
	if _, err = ChatRepublish(context.Background(), f.init.RailConfigPath, env); !errors.Is(err,
		ErrCardControllerMissing) {
		t.Fatalf("a node without a card controller was not refused as missing: %v", err)
	}
}

func TestAdoptingARotatedCardControllerReissuesTheChatCard(t *testing.T) {
	f, initResult, env := chatSetupFixture(t)
	ctx := context.Background()
	first, err := ChatRepublish(ctx, f.init.RailConfigPath, env)
	if err != nil {
		t.Fatal(err)
	}
	const rotated = "card-rotated"
	// The new controller is in the vault but not yet in the finalized
	// policy: adopting it is refused and the configuration is unchanged.
	f.change(func(w *fakeWorld) { w.Controllers[rotated] = true })
	if _, err = ChatAdoptCardController(ctx, f.init.RailConfigPath, rotated, env); !errors.Is(err,
		ErrCardControllerNotInPolicy) {
		t.Fatalf("a controller outside the finalized policy was adopted: %v", err)
	}
	if config, loadErr := LoadNodeConfig(f.init.RailConfigPath); loadErr != nil ||
		config.CardController != initResult.CardController {
		t.Fatalf("a refused adoption changed the configuration: %v", loadErr)
	}
	// The packet controller cannot be adopted as the card controller.
	if _, err = ChatAdoptCardController(ctx, f.init.RailConfigPath, f.init.PacketController, env); !errors.Is(err,
		ErrCardControllerIsPacketController) {
		t.Fatalf("the packet controller was adopted as the card controller: %v", err)
	}
	// A policy update rotated the card controller on chain.
	f.change(func(w *fakeWorld) {
		w.Agents[initResult.AgentID] = fakePolicyJSON(t, 2, fakeController(f.init.PacketController, 2, 15),
			fakeController(rotated, 1, cardControllerPurposes))
	})
	if _, err = ChatRepublish(ctx, f.init.RailConfigPath, env); !errors.Is(err, ErrCardControllerNotInPolicy) {
		t.Fatalf("the rotated-out card controller still signs: %v", err)
	}
	second, err := ChatAdoptCardController(ctx, f.init.RailConfigPath, rotated, env)
	if err != nil {
		t.Fatal(err)
	}
	if second.KeyID == first.KeyID || second.CardController != rotated ||
		second.CardKeyID != fakeKey(rotated).Text() {
		t.Fatalf("the card was not re-issued under the new controller: %+v", second)
	}
	config, err := LoadNodeConfig(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.CardController != rotated || config.CardKeyID != fakeKey(rotated).Text() {
		t.Fatalf("the configuration names card controller %q (%s)", config.CardController, config.CardKeyID)
	}
	key, published, err := heldChatCard(config, env.Now())
	if err != nil || !published || agentpacketseal.KeyIDText(key.KeyID) != second.KeyID {
		t.Fatalf("the published card is not the re-issued one: %v", err)
	}
	if got := cardSignerOf(t, config.AgentID, key.CardJSON); got != fakeKey(rotated).KeyID {
		t.Fatalf("the published card is signed by %x", got)
	}
}

// chatPreflight is a ready relay node with a chat section, its chat card
// issued by the card-signing controller and published at the card path.
func chatPreflight(t *testing.T) *pfFixture {
	t.Helper()
	f, _ := relayPreflight(t, true)
	clock := &relayClock{now: pfChainNow}
	card := testCardController(testSeller)
	f.config.MessengerSocket = ""
	f.config.CardController, f.config.CardKeyID = card, packetKeys.KeyID(card)
	f.probes[card] = keyIDOf(t, packetKeys.KeyID(card))
	root := filepath.Join(f.config.StateDir, relayStateDir)
	f.config.Chat = &ChatConfig{
		CarrierSocket: filepath.Join(root, "c.sock"), MessengerCarrierSocket: filepath.Join(root, "d.sock"),
		CardPath: filepath.Join(root, "chat-card.json"),
	}
	signer := testCardSigner(t, testSeller)
	signer.packet.now = clock.Now
	keys, err := OpenChatRelayKeys(filepath.Join(root, relayChatKeysDir), testSeller, f.config.RelayURLs, signer,
		clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Current(context.Background(), offerCardCover(uint64(clock.Now().Unix())))
	if err != nil {
		t.Fatal(err)
	}
	if err = publishChatCard(f.config.Chat.CardPath, key.CardJSON); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPreflightChecksTheCardSigningController(t *testing.T) {
	f := chatPreflight(t)
	_, checks := f.run(t)
	for _, id := range []string{"chat.config", "chat.card_controller", "chat.card"} {
		if checks[id].Status != CheckPass {
			t.Fatalf("%s: %s (%s)", id, checks[id].Status, checks[id].Message)
		}
	}
	card := testCardController(testSeller)
	cases := map[string]struct {
		mutate func(*pfFixture)
		want   map[string]string
	}{
		"no card controller configured": {
			mutate: func(f *pfFixture) { f.config.CardController, f.config.CardKeyID = "", "" },
			want:   map[string]string{"chat.card_controller": CheckFail, "chat.card": CheckUnknown},
		},
		"the vault holds another key": {
			mutate: func(f *pfFixture) { f.probes[card] = [32]byte{9} },
			want:   map[string]string{"chat.card_controller": CheckFail, "chat.card": CheckUnknown},
		},
		"the card controller left the finalized policy": {
			mutate: func(f *pfFixture) {
				agent := agentState(testSeller)
				agent.Policy.Controllers = agent.Policy.Controllers[:1]
				f.chain.agent = &nativev1.NativeStateV1{Network: testNetwork,
					State: &nativev1.NativeStateV1_Agent{Agent: agent}}
			},
			want: map[string]string{"chat.card_controller": CheckFail, "chat.card": CheckUnknown},
		},
		"the card controller holds authority": {
			mutate: func(f *pfFixture) {
				agent := agentState(testSeller)
				agent.Policy.Controllers[1].Weight = agent.Policy.Threshold
				f.chain.agent = &nativev1.NativeStateV1{Network: testNetwork,
					State: &nativev1.NativeStateV1_Agent{Agent: agent}}
			},
			want: map[string]string{"chat.card_controller": CheckFail, "chat.card": CheckUnknown},
		},
		"the published card is the packet controller's": {
			mutate: func(f *pfFixture) {
				clock := &relayClock{now: pfChainNow}
				signer := testSigner(t, testSeller)
				signer.now = clock.Now
				dir := filepath.Join(f.config.StateDir, relayStateDir, relayChatKeysDir)
				keys, err := OpenChatRelayKeys(dir, testSeller, f.config.RelayURLs, signer, clock.Now)
				if err != nil {
					t.Fatal(err)
				}
				clock.Advance(time.Second)
				key, err := keys.Current(context.Background(), offerCardCover(uint64(clock.Now().Unix())))
				if err != nil {
					t.Fatal(err)
				}
				if err = publishChatCard(f.config.Chat.CardPath, key.CardJSON); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]string{"chat.card_controller": CheckPass, "chat.card": CheckFail},
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f := chatPreflight(t)
			test.mutate(f)
			report, checks := f.run(t)
			for id, want := range test.want {
				if checks[id].Status != want {
					t.Errorf("%s: %s (%s), want %s", id, checks[id].Status, checks[id].Message, want)
				}
			}
			if report.OK {
				t.Fatal("the preflight passed")
			}
		})
	}
}
