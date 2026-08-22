// Command openfox-messenger-evidence verifies transcript exports from two
// independently operated openfox-messenger-agent processes. It checks event
// identity, authenticated peer continuity, content equality, reply causality,
// and an optional restart epoch. It does not claim independent operation; the
// evidence record must separately identify operators, hosts, and checkpoints.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	controlSchema = "tos.openfox.production-messenger-agent-control.v1"
	maxEvidence   = 16 << 20
)

type transcriptLine struct {
	Direction      string `json:"direction"`
	PeerAgentID    string `json:"peer_agent_id,omitempty"`
	RecipientInput string `json:"recipient_input,omitempty"`
	EventID        string `json:"event_id"`
	ReplyToEventID string `json:"reply_to_event_id,omitempty"`
	Content        string `json:"content"`
	RunID          string `json:"run_id"`
	AppliedUnix    int64  `json:"applied_unix"`
}

type evidence struct {
	Schema     string           `json:"schema"`
	AgentID    string           `json:"agent_id"`
	RunID      string           `json:"run_id"`
	Transcript []transcriptLine `json:"transcript"`
}

func main() {
	left := flag.String("left", "", "first transcript export JSON")
	right := flag.String("right", "", "second transcript export JSON")
	restart := flag.String("require-restart-agent", "", "canonical AgentID that must have transcript entries from two run IDs")
	flag.Parse()
	if flag.NArg() != 0 || *left == "" || *right == "" {
		fmt.Fprintln(os.Stderr, "usage: openfox-messenger-evidence -left alice.json -right bob.json [-require-restart-agent agent_...]")
		os.Exit(2)
	}
	a, err := readEvidence(*left)
	var b evidence
	if err == nil {
		b, err = readEvidence(*right)
		if err == nil {
			err = verifyPair(a, b, *restart)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		os.Exit(1)
	}
	fmt.Printf("PASS agent_a=%s agent_b=%s authenticated_round_trip=true restart_agent=%s\n", a.AgentID, b.AgentID, *restart)
}

func readEvidence(path string) (evidence, error) {
	var result evidence
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxEvidence {
		return result, errors.New("evidence must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Schema != controlSchema || !canonicalAgent(result.AgentID) ||
		!canonicalRunID(result.RunID) || len(result.Transcript) == 0 || len(result.Transcript) > 100000 {
		return result, errors.New("invalid Messenger transcript evidence")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, errors.New("trailing Messenger evidence data")
	}
	return result, nil
}

func verifyPair(a, b evidence, restartAgent string) error {
	if a.AgentID == b.AgentID {
		return errors.New("evidence needs two distinct canonical AgentIDs")
	}
	if restartAgent != "" && restartAgent != a.AgentID && restartAgent != b.AgentID {
		return errors.New("restart AgentID is not one of the evidence owners")
	}
	if err := validateTranscript(a); err != nil {
		return fmt.Errorf("first transcript: %w", err)
	}
	if err := validateTranscript(b); err != nil {
		return fmt.Errorf("second transcript: %w", err)
	}
	if !hasRoundTrip(a, b) && !hasRoundTrip(b, a) {
		return errors.New("no complete authenticated Event/reply round trip crosses both transcripts")
	}
	if restartAgent != "" {
		target := a
		if b.AgentID == restartAgent {
			target = b
		}
		runs := map[string]struct{}{}
		for _, line := range target.Transcript {
			runs[line.RunID] = struct{}{}
		}
		if len(runs) < 2 {
			return errors.New("required Agent has no durable activity across two process run IDs")
		}
	}
	return nil
}

func validateTranscript(value evidence) error {
	seen := map[string]transcriptLine{}
	for _, line := range value.Transcript {
		if !canonicalEventID(line.EventID) || !canonicalRunID(line.RunID) || line.AppliedUnix <= 0 || line.Content == "" ||
			(line.Direction != "inbound" && line.Direction != "outbound") ||
			(line.ReplyToEventID != "" && !canonicalEventID(line.ReplyToEventID)) {
			return errors.New("malformed transcript line")
		}
		if line.Direction == "inbound" && !canonicalAgent(line.PeerAgentID) {
			return errors.New("inbound event lacks canonical authenticated peer")
		}
		if line.Direction == "outbound" && (line.PeerAgentID != "" ||
			(line.ReplyToEventID == "") != (line.RecipientInput != "")) {
			return errors.New("outbound line has invalid recipient-intent/reply shape")
		}
		if _, duplicate := seen[line.EventID]; duplicate {
			return errors.New("duplicate Event ID in transcript")
		}
		seen[line.EventID] = line
	}
	return nil
}

func hasRoundTrip(sender, receiver evidence) bool {
	receiverByID := index(receiver.Transcript)
	senderByID := index(sender.Transcript)
	for _, sent := range sender.Transcript {
		if sent.Direction != "outbound" || sent.ReplyToEventID != "" || sent.RecipientInput == "" {
			continue
		}
		got, ok := receiverByID[sent.EventID]
		if !ok || got.Direction != "inbound" || got.PeerAgentID != sender.AgentID || got.Content != sent.Content {
			continue
		}
		for _, reply := range receiver.Transcript {
			if reply.Direction != "outbound" || reply.ReplyToEventID != sent.EventID {
				continue
			}
			returned, ok := senderByID[reply.EventID]
			if ok && returned.Direction == "inbound" && returned.PeerAgentID == receiver.AgentID &&
				returned.ReplyToEventID == sent.EventID && returned.Content == reply.Content {
				return true
			}
		}
	}
	return false
}

func index(lines []transcriptLine) map[string]transcriptLine {
	result := make(map[string]transcriptLine, len(lines))
	for _, line := range lines {
		result[line.EventID] = line
	}
	return result
}

func canonicalAgent(value string) bool   { return canonicalHex(value, "agent_", 64) }
func canonicalEventID(value string) bool { return canonicalHex(value, "evt_", 64) }
func canonicalRunID(value string) bool   { return canonicalHex(value, "run_", 32) }

func canonicalHex(value, prefix string, digits int) bool {
	if len(value) != len(prefix)+digits || !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}
