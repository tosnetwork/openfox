package servicebridge

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// A chat record may hold an envelope and a signed packet at the full sealed
// packet bound. The journal must read back every record it can write, or one
// large chat message wedges every later carry and re-deposit of the node.
func TestAJournalRecordAtTheSealedPacketBoundIsReadBack(t *testing.T) {
	transport := &RelayTransport{directory: t.TempDir()}
	key := "idem_" + strings.Repeat("a", 64)
	record := relayOutboxRecord{
		Schema: relayOutboxSchema, Recipient: "agent_" + strings.Repeat("b", 64), IdempotencyKey: key,
		EnvelopeID: strings.Repeat("c", 64), AckSecret: strings.Repeat("d", 64),
		EnvelopeBase64: base64.StdEncoding.EncodeToString(make([]byte, agentpacketseal.MaxEnvelopeBytes)),
		PacketBase64:   base64.StdEncoding.EncodeToString(make([]byte, agentpacketseal.MaxPacketJSONBytes)),
	}
	for index := 0; index < maxRelayWithdrawals; index++ {
		record.Withdrawals = append(record.Withdrawals, relayWithdrawal{EnvelopeID: strings.Repeat("e", 64),
			AckSecret: strings.Repeat("f", 64), Relays: []string{"https://relay.example"}})
	}
	path := transport.recordPath(key)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transport.store(path, record); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 512<<10 {
		t.Fatalf("the record is %d bytes; the test must exceed the former 512 KiB bound", info.Size())
	}
	loaded, found, err := transport.load(path)
	if err != nil || !found {
		t.Fatalf("a record this node wrote was refused: found=%v err=%v", found, err)
	}
	if loaded.EnvelopeBase64 != record.EnvelopeBase64 || loaded.PacketBase64 != record.PacketBase64 {
		t.Fatal("the record read back differs")
	}
}
