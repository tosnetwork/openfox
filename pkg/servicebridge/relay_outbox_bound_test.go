package servicebridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// longRelays are agentpacketseal.MaxRelays relay URLs of 256 bytes each.
func longRelays() []string {
	relays := make([]string, 0, agentpacketseal.MaxRelays)
	for index := range agentpacketseal.MaxRelays {
		prefix := fmt.Sprintf("https://relay-%d.example/", index)
		relays = append(relays, prefix+strings.Repeat("p", 256-len(prefix)))
	}
	return relays
}

// worstCaseRecord is the largest journal record the node can write: an
// envelope and a packet at the sealed bounds, the most relays in every list
// and the most withdrawals, each naming the most relays.
func worstCaseRecord(key string) relayOutboxRecord {
	record := relayOutboxRecord{
		Schema: relayOutboxSchema, Recipient: "agent_" + strings.Repeat("b", 64), IdempotencyKey: key,
		KeyID: "hpke:" + strings.Repeat("9", 64), Relays: longRelays(), EnvelopeID: strings.Repeat("c", 64),
		EnvelopeBase64: base64.StdEncoding.EncodeToString(make([]byte, agentpacketseal.MaxEnvelopeBytes)),
		ExpiresAtUnix:  ^uint64(0), Accepted: longRelays(), Conflicts: longRelays(), Seals: 1 << 30,
		AckSecret: strings.Repeat("d", 64), CardNotAfterUnix: ^uint64(0),
		PacketBase64:        base64.StdEncoding.EncodeToString(make([]byte, agentpacketseal.MaxPacketJSONBytes)),
		PacketExpiresAtUnix: ^uint64(0), AcceptedAtUnix: ^uint64(0), Settled: true,
		Residual: relayResidual{Count: maxRelayResidual, UntilUnix: ^uint64(0)},
	}
	relays := longRelays()
	for range maxRelayWithdrawals {
		// Splitting the relays between the two lists costs one more key.
		record.Withdrawals = append(record.Withdrawals, relayWithdrawal{
			EnvelopeID: strings.Repeat("e", 64), AckSecret: strings.Repeat("f", 64),
			Relays: relays[:len(relays)-1], Unconfirmed: relays[len(relays)-1:], ExpiresAtUnix: ^uint64(0),
			AfterAccepted: true,
		})
	}
	return record
}

// A record may hold an envelope and a signed packet at the full sealed
// packet bound. The journal must read back every record it can write, or one
// large message wedges the node's carriage.
func TestTheWorstCaseJournalRecordFitsItsBoundAndIsReadBack(t *testing.T) {
	transport := &RelayTransport{directory: t.TempDir()}
	key := "idem_" + strings.Repeat("a", 64)
	record := worstCaseRecord(key)
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= 512<<10 || len(encoded) > maxRelayOutboxRecordBytes {
		t.Fatalf("the worst-case record is %d bytes: it must exceed the former 512 KiB bound and fit %d",
			len(encoded), maxRelayOutboxRecordBytes)
	}
	path := transport.recordPath(key)
	if err = writeRecord(path, record, true); err != nil {
		t.Fatalf("the worst-case record was refused: %v", err)
	}
	loaded, found, err := transport.load(path)
	if err != nil || !found {
		t.Fatalf("a record this node wrote was refused: found=%v err=%v", found, err)
	}
	again, err := json.Marshal(loaded)
	if err != nil || string(again) != string(encoded) {
		t.Fatal("the record read back differs")
	}
}

// The writer refuses what the reader would refuse, before any deposit.
func TestARecordAboveTheReadBoundIsNeverWritten(t *testing.T) {
	transport := &RelayTransport{directory: t.TempDir()}
	key := "idem_" + strings.Repeat("a", 64)
	record := worstCaseRecord(key)
	record.PacketBase64 += strings.Repeat("A", maxRelayOutboxRecordBytes)
	path := transport.recordPath(key)
	if err := writeRecord(path, record, true); !errors.Is(err, ErrRelayRecordTooLarge) {
		t.Fatalf("an over-bound record was not refused: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an over-bound record left a file")
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transport.store(path, record); !errors.Is(err, ErrRelayRecordTooLarge) {
		t.Fatalf("an over-bound replacement was not refused: %v", err)
	}
}
