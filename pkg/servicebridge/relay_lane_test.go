package servicebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(raw, []byte("\n"))
}

// goldenNodeConfig strictly decodes the full golden configuration, which
// names messenger_socket and has a chat section.
func goldenNodeConfig(t *testing.T) NodeConfig {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(readGolden(t, "node-config-full.golden.json")))
	decoder.DisallowUnknownFields()
	var config NodeConfig
	if err := decoder.Decode(&config); err != nil {
		t.Fatal(err)
	}
	if config.MessengerSocket == "" || config.Chat == nil {
		t.Fatal("the golden configuration lost messenger_socket or its chat section")
	}
	return config
}

// requireNothingSent fails unless a refused init sent no registration and
// no wallet message and wrote no configuration.
func requireNothingSent(t *testing.T, setup *setupFixture) {
	t.Helper()
	world := setup.world()
	if world.count("agent native-registry register-agent") != 0 || world.count("wallet send") != 0 {
		t.Fatalf("init sent something before refusing: %+v", world.Calls)
	}
	if _, err := os.Stat(setup.init.RailConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("init wrote a configuration it refused: %v", err)
	}
}

// A program that registered no relay lane does not interpret the chat
// section, and still writes the configuration back byte for byte: every
// field in its place, the section as it was read.
func TestAConfigurationKeepsItsEncodingWithoutARelayLane(t *testing.T) {
	withoutExtensions(t)
	config := goldenNodeConfig(t)
	if config.Chat.Value != nil {
		t.Fatal("the chat section was interpreted with no lane registered")
	}
	indented, err := EncodeNodeConfig(config)
	if err != nil || !bytes.Equal(indented, readGolden(t, "node-config-full.golden.json")) {
		t.Fatalf("the indented encoding changed: %v\n%s", err, indented)
	}
	compact, err := json.Marshal(config)
	if err != nil || !bytes.Equal(compact, readGolden(t, "node-config-full.compact.golden.json")) {
		t.Fatalf("the compact encoding changed: %v\n%s", err, compact)
	}
	path := filepath.Join(t.TempDir(), "rail.json")
	if err = writeNodeConfig(path, config); err != nil {
		t.Fatalf("the configuration does not read back as written: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(written, []byte("\n")), indented) {
		t.Fatalf("the written configuration differs from its encoding: %v", err)
	}
}

// A chat section in a program that registered no relay lane is refused at
// node open, by init before anything is sent, and by preflight.
func TestAChatSectionIsRefusedWithoutARelayLane(t *testing.T) {
	withoutExtensions(t)
	section := goldenNodeConfig(t).Chat
	config := NodeConfig{
		StateDir: t.TempDir(), RelayURLs: []string{"https://relay.example"}, Provider: &ProviderNode{}, Chat: section,
	}
	if err := validateLaneSection(config); !errors.Is(err, ErrNoRelayLane) {
		t.Fatalf("the section was not refused: %v", err)
	}
	if _, err := OpenNode(context.Background(), config, NodeOptions{}); !errors.Is(err, ErrNoRelayLane) {
		t.Fatalf("a node opened with a chat section and no lane: %v", err)
	}
	if got := ownRelayURLs(config); len(got) != 1 {
		t.Fatalf("an uninterpreted section named relays: %v", got)
	}

	setup := newSetupFixture(t)
	setup.init.MessengerSocket, setup.init.RelayURLs = "", []string{"https://relay.example"}
	setup.init.Chat = section
	if _, err := RunInit(context.Background(), setup.init, setup.env()); !errors.Is(err, ErrNoRelayLane) {
		t.Fatalf("init accepted a chat section with no lane: %v", err)
	}
	requireNothingSent(t, setup)

	preflight := newPreflightFixture(t)
	preflight.config.Chat = section
	report, checks := preflight.run(t)
	check := checks["chat.config"]
	if report.OK || check.Status != CheckFail || !strings.Contains(check.Message, "carries no relay lane") {
		t.Fatalf("preflight did not fail the chat section: ok=%v %+v", report.OK, check)
	}
}

// messenger_socket in a program that registered no fallback transport is
// refused at node open, by init before anything is sent, and by preflight.
func TestMessengerSocketIsRefusedWithoutAFallbackTransport(t *testing.T) {
	withoutExtensions(t)
	socket := "/run/m/local.sock"
	if _, err := openPacketTransport(NodeConfig{AgentID: testBuyer, MessengerSocket: socket}, nil); !errors.Is(err,
		ErrNoFallbackTransport) {
		t.Fatalf("a transport opened on messenger_socket with no fallback: %v", err)
	}
	if _, err := OpenNode(context.Background(), NodeConfig{
		StateDir: t.TempDir(), Provider: &ProviderNode{}, MessengerSocket: socket,
	}, NodeOptions{}); !errors.Is(err, ErrNoFallbackTransport) {
		t.Fatalf("a node opened on messenger_socket with no fallback: %v", err)
	}

	setup := newSetupFixture(t)
	if setup.init.MessengerSocket == "" {
		t.Fatal("the setup fixture no longer names messenger_socket")
	}
	_, err := RunInit(context.Background(), setup.init, setup.env())
	if err == nil || !strings.Contains(err.Error(), "has no packet transport for it") {
		t.Fatalf("init accepted messenger_socket with no fallback: %v", err)
	}
	requireNothingSent(t, setup)

	preflight := newPreflightFixture(t)
	if preflight.config.MessengerSocket == "" {
		t.Fatal("the preflight fixture no longer names messenger_socket")
	}
	report, checks := preflight.run(t)
	check := checks["transport.peers"]
	if report.OK || check.Status != CheckFail || !strings.Contains(check.Message, "has no packet transport for it") {
		t.Fatalf("preflight did not fail messenger_socket: ok=%v %+v", report.OK, check)
	}
}

// The courier never gives a rail packet a relay frame kind, whatever rail
// frame it carries.
func TestTheCourierSendsEveryRailFrameWithoutARelayFrameKind(t *testing.T) {
	now := uint64(1_900_000_000)
	transport := &recordingTransport{}
	courier, err := OpenCourier(filepath.Join(t.TempDir(), "outbox"), testSigner(t, testSeller), transport)
	if err != nil {
		t.Fatal(err)
	}
	courier.now = func() time.Time { return time.Unix(int64(now), 0) }
	for _, kind := range []byte{FrameTask, FrameResult, FrameResultAck, FrameResultRequest} {
		envelope := testEnvelope()
		envelope.Kind, envelope.NotAfterUnix = kind, now+7200
		if _, err := courier.Deliver(context.Background(), envelope, []byte("rail frame")); err != nil {
			t.Fatalf("frame kind %d: %v", kind, err)
		}
	}
	packets := transport.packets()
	if len(packets) < 4 {
		t.Fatalf("%d packets were sent for four messages", len(packets))
	}
	for _, packet := range packets {
		if packet.FrameKind != 0 {
			t.Fatalf("a rail packet carries relay frame kind %d", packet.FrameKind)
		}
	}
}

// The rail's envelope journal never holds a relay frame kind: no record the
// rail writes names one, a packet that carries one is refused before
// anything is journaled, and a record that names one is not read back as a
// rail record.
func TestTheRailJournalNeverHoldsARelayFrameKind(t *testing.T) {
	clock := newRelayClock()
	relay := startFakeRelay(t, clock)
	seller, buyer := railPair(t, clock, relay)
	envelope := relayEnvelopeTo(testBuyer)
	envelope.NotAfterUnix = uint64(clock.Now().Add(6 * time.Hour).Unix())
	if _, err := seller.courier.Deliver(context.Background(), envelope, markedBody(40)); err != nil {
		t.Fatal(err)
	}
	seller.redeposit()
	buyer.pollAll()
	seller.redeposit()
	directory := filepath.Join(seller.dir, relayStateDir, relayOutboxDir)
	records := seller.journal()
	if len(records) == 0 {
		t.Fatal("the rail journaled nothing")
	}
	for _, record := range records {
		if record.FrameKind != 0 {
			t.Fatalf("a rail record carries relay frame kind %d", record.FrameKind)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, entry := range entries {
		if !relayOutboxFilePattern.MatchString(entry.Name()) {
			continue
		}
		files++
		raw, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr != nil || bytes.Contains(raw, []byte(`"frame_kind"`)) {
			t.Fatalf("rail journal file %s names a frame kind: %v", entry.Name(), readErr)
		}
	}
	if files != len(records) {
		t.Fatalf("%d journal files for %d records", files, len(records))
	}

	// A packet that carries a relay frame kind is refused, and nothing is
	// journaled for it.
	key := "idem_" + strings.Repeat("5c", 32)
	err = seller.carrier.Transport.Send(context.Background(), OutboundPacket{
		RecipientAgentID: testBuyer, JSON: []byte(`{"packet":"with a frame kind"}`), IdempotencyKey: key,
		ExpiresAtUnix: uint64(clock.Now().Unix()) + 60, FrameKind: 1,
	})
	if !errors.Is(err, ErrRelayFrameKind) {
		t.Fatalf("the rail transport took a packet with a relay frame kind: %v", err)
	}
	if _, err = os.Stat(seller.carrier.Transport.recordPath(key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused packet was journaled: %v", err)
	}

	// A record that names a frame kind is unreadable to the rail and
	// readable only to a reader that carries that kind.
	foreign := records[0]
	foreign.IdempotencyKey, foreign.FrameKind = key, 1
	if err = writeRecord(seller.carrier.Transport.recordPath(key), foreign, true); err != nil {
		t.Fatal(err)
	}
	unreadable := func(views []RelayOutboxView) int {
		count := 0
		for _, view := range views {
			if view.Unreadable != "" {
				count++
			}
		}
		return count
	}
	views, err := ReadRelayOutbox(directory)
	if err != nil || len(views) != len(records)+1 || unreadable(views) != 1 {
		t.Fatalf("the rail reader lists %d records, %d unreadable: %v", len(views), unreadable(views), err)
	}
	views, err = ReadRelayOutboxOfKinds(directory, 1)
	if err != nil || len(views) != len(records)+1 || unreadable(views) != 0 {
		t.Fatalf("a reader of kind 1 lists %d records, %d unreadable: %v", len(views), unreadable(views), err)
	}
}

// A key set of another purpose needs a schema of its own: the rail's schema
// and no schema are refused, so no such set can read or write rail keys.
func TestAKeySetOfAnotherPurposeNeedsItsOwnSchema(t *testing.T) {
	relays := []string{"https://relay.example"}
	for _, schema := range []string{"", relayKeySchema} {
		signer := testSigner(t, testSeller)
		if _, err := OpenRelayKeysFor(t.TempDir(), testSeller, relays, signer, nil, schema); err == nil {
			t.Fatalf("a key set of another purpose opened with schema %q", schema)
		}
	}
	keys, err := OpenRelayKeysFor(filepath.Join(t.TempDir(), "keys"), testSeller, relays, testSigner(t, testSeller),
		nil, "tos.test.relay-other-key.v1")
	if err != nil || keys.keySchema() != "tos.test.relay-other-key.v1" {
		t.Fatalf("a key set with its own schema did not open: %v", err)
	}
}
