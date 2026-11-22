package servicebridge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// goldenChatConfig is the chat section of the full golden configuration.
func goldenChatConfig() *ChatConfig {
	return &ChatConfig{
		RelayURLs: []string{"https://chat-relay.example/a?b=1&c=<2>"}, CarrierSocket: "/var/lib/rail/chat-carrier.sock",
		MessengerCarrierSocket: "/run/m/carrier.sock", CardPath: "/var/lib/rail/relay/chat-card.json",
		EvidenceExportDir: "/var/lib/m/evidence", ContactDir: "/var/lib/m/contacts", TimeoutSeconds: 45,
		OwnerSocket: "/run/m/owner.sock",
	}
}

// goldenTypedNodeConfig is the full golden configuration built from Go
// values, every field set that the golden file names.
func goldenTypedNodeConfig() NodeConfig {
	return NodeConfig{
		Network:          NetworkConfig{NetworkID: "tos-test", GenesisRootHash: "11", GenesisFileHash: "22"},
		GlobalConfigFile: "/etc/rail/global.config.json",
		RPCEndpoints:     []string{"https://rpc-a.example", "https://rpc-b.example"},
		Quorum:           2, RegistryCodeBOC: "/etc/rail/registry.boc", RegistryCodeHash: "33", ActorCodeHash: "44",
		StateDir: "/var/lib/rail", AgentID: "agent_55", PacketController: "packet", PacketKeyID: "66",
		TOSCTL: TOSCTLConfig{
			Binary: "/usr/bin/tosctl", SHA256: "77", ConfigPath: "/etc/rail/tosctl.json", VaultURLEnv: "VAULT_URL",
		},
		WalletName: "owner", WalletAddress: "0:88", MessengerSocket: "/run/m/local.sock",
		DirectPeers: map[string]string{"agent_99": "/run/peer/rail.sock"},
		RelayURLs:   []string{"https://relay-a.example", "https://relay-b.example"},
		RelayCAFile: "/var/lib/rail/relay/ca.pem", RelayCASHA256: "aa",
		ReceiverSocket: "/var/lib/rail/rail-receiver.sock",
		Provider: &ProviderNode{
			CapabilityID: "cap_bb", Version: "1.0.0", ManifestFile: "/var/lib/rail/manifest.cbor",
			AttestorController: "attestor", RespondBudgetSecond: 600, ExecutorSocket: "/run/executor.sock",
			OfferFile: "/var/lib/rail/offer.json", GatewayCardFile: "/var/lib/rail/card.json",
		},
		MaxAssemblies: &AssemblyBounds{PerSender: 4, Total: 64},
		Chat:          NewChatSection(goldenChatConfig()),
	}
}

// The golden files hold what the node configuration encoded to while the
// chat section was a field of the chat type. With the section behind the
// registered lane the encoding is the same bytes: field order, omitted
// fields and escaping, indented and compact.
func TestTheNodeConfigurationEncodingIsUnchangedWithTheChatLane(t *testing.T) {
	config := goldenTypedNodeConfig()
	indented, err := EncodeNodeConfig(config)
	if err != nil || !bytes.Equal(indented, readGolden(t, "node-config-full.golden.json")) {
		t.Fatalf("the indented encoding changed: %v\n%s", err, indented)
	}
	compact, err := json.Marshal(config)
	if err != nil || !bytes.Equal(compact, readGolden(t, "node-config-full.compact.golden.json")) {
		t.Fatalf("the compact encoding changed: %v\n%s", err, compact)
	}
	minimal, err := EncodeNodeConfig(NodeConfig{
		StateDir: "/var/lib/rail", ReceiverSocket: "/var/lib/rail/rail-receiver.sock",
		Chat: NewChatSection(&ChatConfig{
			CarrierSocket: "/c.sock", MessengerCarrierSocket: "/d.sock", CardPath: "/card.json",
		}),
	})
	if err != nil || !bytes.Equal(minimal, readGolden(t, "node-config-chat-minimal.golden.json")) {
		t.Fatalf("the encoding of omitted fields changed: %v\n%s", err, minimal)
	}

	// Read back, the section is the chat configuration again, and encodes
	// to the same bytes.
	decoded := goldenNodeConfig(t)
	if chat := ChatSection(decoded); chat == nil || !reflect.DeepEqual(chat, goldenChatConfig()) {
		t.Fatalf("the chat section read back as %+v", chat)
	}
	again, err := EncodeNodeConfig(decoded)
	if err != nil || !bytes.Equal(again, indented) {
		t.Fatalf("the configuration does not encode as it was read: %v", err)
	}
	if !reflect.DeepEqual(normalizeConfig(decoded), normalizeConfig(config)) {
		t.Fatal("the configuration read back differs from the one encoded")
	}
}

// The chat section is still decoded strictly: an unknown field in it
// refuses the configuration, and an absent or null section is no section.
func TestTheChatSectionIsDecodedStrictly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rail.json")
	write := func(document string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"chat":{"carrier_socket":"/c.sock","surprise":1}}`)
	if _, err := LoadNodeConfig(path); err == nil {
		t.Fatal("an unknown field in the chat section was accepted")
	}
	write(`{"chat":"/c.sock"}`)
	if _, err := LoadNodeConfig(path); err == nil {
		t.Fatal("a chat section that is not an object was accepted")
	}
	for _, document := range []string{`{}`, `{"chat":null}`} {
		write(document)
		config, err := LoadNodeConfig(path)
		if err != nil || config.Chat != nil || ChatSection(config) != nil {
			t.Fatalf("%s: %v, section %+v", document, err, config.Chat)
		}
	}
	write(`{"chat":{"carrier_socket":"/c.sock"}}`)
	config, err := LoadNodeConfig(path)
	if err != nil || ChatSection(config) == nil || ChatSection(config).CarrierSocket != "/c.sock" {
		t.Fatalf("a chat section did not load: %v", err)
	}
}

// The chat journal carries relay frame kinds; the rail reader lists such a
// record as unreadable, the chat reader reads it.
func TestTheChatJournalIsReadWithItsFrameKinds(t *testing.T) {
	transport := &RelayTransport{directory: t.TempDir()}
	if err := transport.setFrameKinds(chatMaxFrameKind, chatUnreadableFrameKind); err != nil {
		t.Fatal(err)
	}
	if err := transport.setFrameKinds(chatUnreadableFrameKind-1, chatUnreadableFrameKind); err == nil {
		t.Fatal("an unreadable kind above the highest kind was accepted")
	}
	key := "idem_" + strings.Repeat("a", 64)
	record := worstCaseRecord(key)
	record.FrameKind = chatMaxFrameKind
	if err := writeRecord(transport.recordPath(key), record, true); err != nil {
		t.Fatal(err)
	}
	if _, found, err := transport.load(transport.recordPath(key)); err != nil || !found {
		t.Fatalf("the chat transport did not read its own record: %v", err)
	}
	if stored := transport.unreadableStored("name.json"); stored.FrameKind != chatUnreadableFrameKind {
		t.Fatalf("an unreadable chat record counts as kind %d", stored.FrameKind)
	}
	chat, err := ReadChatOutbox(transport.directory)
	if err != nil || len(chat) != 1 || chat[0].Unreadable != "" || chat[0].FrameKind != chatMaxFrameKind {
		t.Fatalf("the chat reader: %+v %v", chat, err)
	}
	rail, err := ReadRelayOutbox(transport.directory)
	if err != nil || len(rail) != 1 || rail[0].Unreadable == "" {
		t.Fatalf("the rail reader took a chat record: %+v %v", rail, err)
	}
	record.FrameKind = chatMaxFrameKind + 1
	if err := writeRecord(transport.recordPath(key), record, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := transport.load(transport.recordPath(key)); err == nil {
		t.Fatal("a record above the highest chat frame kind was read")
	}
}
