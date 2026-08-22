package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyAcceptance(t *testing.T) {
	config, sends := acceptanceFixture(t, false, false, false)
	report, err := verify(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != reportSchema || report.Scope != "same-host-local-route-only" ||
		!report.ExactReplayStable || report.RelayPlaintextFound || report.RelayMode != "0600" ||
		len(report.Agents) != 3 || len(report.Artifacts) != 5 || sends.Load() != 1 {
		t.Fatalf("unexpected report: %#v sends=%d", report, sends.Load())
	}
	for _, agent := range report.Agents {
		if !agent.ActiveMember || agent.ReplyMode != "agent-loop" ||
			agent.TranscriptRecords != 4 || agent.AcceptanceEvents != 3 {
			t.Fatalf("unexpected Agent evidence: %#v", agent)
		}
	}
}

func TestVerifyRejectsReplayAndRelaySubstitution(t *testing.T) {
	t.Run("replay Event", func(t *testing.T) {
		config, _ := acceptanceFixture(t, true, false, false)
		if _, err := verify(context.Background(), config); err == nil ||
			!strings.Contains(err.Error(), "substituted Event ID") {
			t.Fatalf("substituted replay accepted: %v", err)
		}
	})
	t.Run("Relay plaintext", func(t *testing.T) {
		config, sends := acceptanceFixture(t, false, true, false)
		if _, err := verify(context.Background(), config); err == nil ||
			!strings.Contains(err.Error(), "Relay state contains") {
			t.Fatalf("Relay plaintext accepted: %v", err)
		}
		if sends.Load() != 0 {
			t.Fatal("verifier replayed before rejecting Relay plaintext")
		}
	})
}

func TestVerifyDoesNotReplayUnboundRequestID(t *testing.T) {
	config, sends := acceptanceFixture(t, false, false, false)
	config.requestID = "different-unbound-request"
	if _, err := verify(context.Background(), config); err == nil ||
		!strings.Contains(err.Error(), "opening Event substitution") {
		t.Fatalf("unbound request ID accepted: %v", err)
	}
	if sends.Load() != 0 {
		t.Fatalf("verifier sent an unbound request ID %d time(s)", sends.Load())
	}
}

func TestVerifyComparesCompleteTranscriptAcrossReplay(t *testing.T) {
	config, sends := acceptanceFixture(t, false, false, true)
	if _, err := verify(context.Background(), config); err == nil ||
		!strings.Contains(err.Error(), "changed complete transcript") {
		t.Fatalf("non-acceptance transcript mutation accepted: %v", err)
	}
	if sends.Load() != 1 {
		t.Fatalf("replay sends=%d want=1", sends.Load())
	}
}

func TestVerifyTranscriptRejectsCausalAndRuntimeForgery(t *testing.T) {
	base := fixtureOptions()
	tests := []struct {
		name       string
		viewer     string
		transcript []transcriptLine
		records    int
	}{
		{
			name: "duplicate opening", viewer: aliceID,
			transcript: append(transcriptFor(aliceID, base), transcriptFor(aliceID, base)[0]), records: 4,
		},
		{
			name: "extra reply", viewer: aliceID,
			transcript: append(transcriptFor(aliceID, base), transcriptLine{
				Direction: "inbound", AgentID: bobID, EventID: "msg_" + strings.Repeat("4", 64),
				ReplyToEventID: base.openingEventID, Content: "extra",
			}), records: 4,
		},
		{
			name: "producer runtime missing", viewer: bobID,
			transcript: mutateLine(transcriptFor(bobID, base), base.bobReplyEventID, func(line *transcriptLine) {
				line.Runtime = ""
			}), records: 3,
		},
		{
			name: "reply target substituted", viewer: carolID,
			transcript: mutateLine(transcriptFor(carolID, base), base.carolReplyID, func(line *transcriptLine) {
				line.ReplyToEventID = "msg_" + strings.Repeat("9", 64)
			}), records: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.expectedRecords = test.records
			if _, err := verifyTranscript(test.viewer, transcriptResponse{
				Schema: controlSchema, Transcript: test.transcript,
			}, config); err == nil {
				t.Fatal("forged transcript accepted")
			}
		})
	}
}

func TestVerifyArtifactsRejectsDigestAndSymlinkSubstitution(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "agent")
	if err := os.WriteFile(executable, []byte("fixture executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("0", 64)
	if _, err := verifyArtifacts([]string{"agent=" + wrong + ":" + executable}); err == nil {
		t.Fatal("wrong artifact digest accepted")
	}
	symlink := filepath.Join(directory, "agent-link")
	if err := os.Symlink(executable, symlink); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("fixture executable\n"))
	if _, err := verifyArtifacts([]string{"agent=" + hex.EncodeToString(digest[:]) + ":" + symlink}); err == nil {
		t.Fatal("artifact symlink accepted")
	}
}

func TestRejectDuplicateJSONKeys(t *testing.T) {
	for _, raw := range []string{
		`{"schema":"first","schema":"second"}`,
		`{"outer":{"agent_id":"a","agent_id":"b"}}`,
		`[{"event_id":"a","event_id":"b"}]`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(raw)); err == nil {
			t.Fatalf("duplicate JSON accepted: %s", raw)
		}
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"schema":"ok","nested":[{"event_id":"one"}]}`)); err != nil {
		t.Fatalf("unique JSON rejected: %v", err)
	}
}

func TestControlJSONRejectsProtocolWeakening(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
	}{
		{
			name: "duplicate key",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"schema":"first","schema":"second"}`))
			}),
		},
		{
			name: "unknown field",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"schema":"ok","unknown":true}`))
			}),
		},
		{
			name: "redirect",
			handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				http.Redirect(w, request, "/substituted", http.StatusFound)
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socket := startUnixServer(t, test.handler)
			var response healthResponse
			err := controlJSON(
				context.Background(), socket, time.Second, http.MethodGet, "/test", nil, &response,
			)
			if err == nil {
				t.Fatal("weakened control response accepted")
			}
		})
	}
}

func acceptanceFixture(
	t *testing.T,
	substituteReplay, leakPlaintext, mutateTranscriptAfterReplay bool,
) (options, *atomic.Int32) {
	t.Helper()
	config := fixtureOptions()
	sends := &atomic.Int32{}
	config.controlSockets = make(map[string]string, 3)
	for _, agentID := range []string{aliceID, bobID, carolID} {
		health := healthResponse{
			Schema: controlSchema, OK: true, AgentID: agentID, RoomID: config.roomID,
			ActiveMember: true, ReplyMode: "agent-loop",
		}
		replayID := config.openingEventID
		if substituteReplay && agentID == aliceID {
			replayID = "msg_" + strings.Repeat("9", 64)
		}
		config.controlSockets[agentID] = startControlServer(
			t, health, transcriptResponse{Schema: controlSchema, Transcript: transcriptFor(agentID, config)},
			replayID, sends, mutateTranscriptAfterReplay,
		)
	}
	directory := t.TempDir()
	config.relayState = filepath.Join(directory, "relay.json")
	relayBody := []byte(`{"messages":[{"content":"opaque-ciphertext"}]}`)
	if leakPlaintext {
		relayBody = append(relayBody, []byte(config.content)...)
	}
	if err := os.WriteFile(config.relayState, relayBody, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"openfox-messenger-lab-agent", "openfox-messenger-lab-deploy", "tos-messenger-lab-group",
		"tos-messenger-openfox-mls", "tos-openmls-driver",
	} {
		executable := filepath.Join(directory, name)
		executableBody := []byte("fixture executable " + name + "\n")
		if err := os.WriteFile(executable, executableBody, 0o700); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(executableBody)
		config.artifacts = append(
			config.artifacts, name+"="+hex.EncodeToString(digest[:])+":"+executable,
		)
	}
	return config, sends
}

func fixtureOptions() options {
	return options{
		roomID:          "room_" + strings.Repeat("1", 64),
		requestID:       "acceptance-test-v1",
		content:         "process-probe: machine acceptance",
		openingEventID:  "msg_" + strings.Repeat("1", 64),
		bobReplyEventID: "msg_" + strings.Repeat("2", 64),
		carolReplyID:    "msg_" + strings.Repeat("3", 64),
		expectedRecords: 4,
		timeout:         2 * time.Second,
	}
}

func transcriptFor(viewer string, config options) []transcriptLine {
	lines := []transcriptLine{
		{
			AgentID: aliceID, EventID: config.openingEventID,
			ClientID: config.requestID, Content: config.content,
		},
		{
			AgentID:        bobID,
			EventID:        config.bobReplyEventID,
			ReplyToEventID: config.openingEventID,
			Content:        "ack-from-bob",
		},
		{
			AgentID:        carolID,
			EventID:        config.carolReplyID,
			ReplyToEventID: config.openingEventID,
			Content:        "ack-from-carol",
		},
		{
			AgentID: aliceID, EventID: "msg_" + strings.Repeat("4", 64),
			Content: "unrelated historical message",
		},
	}
	for index := range lines {
		lines[index].Direction = "inbound"
		if lines[index].AgentID == viewer {
			lines[index].Direction = "outbound"
			if lines[index].EventID != config.openingEventID {
				lines[index].Runtime = "openfox-agent-loop"
			}
		}
		if lines[index].EventID == config.openingEventID && viewer != aliceID {
			lines[index].ClientID = ""
		}
	}
	return lines
}

func mutateLine(lines []transcriptLine, eventID string, mutate func(*transcriptLine)) []transcriptLine {
	result := append([]transcriptLine(nil), lines...)
	for index := range result {
		if result[index].EventID == eventID {
			mutate(&result[index])
		}
	}
	return result
}

func startControlServer(t *testing.T, health healthResponse, transcript transcriptResponse,
	replayID string, sends *atomic.Int32, mutateTranscriptAfterReplay bool,
) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeFixtureJSON(w, health)
	})
	mux.HandleFunc("GET /v1/transcript", func(w http.ResponseWriter, _ *http.Request) {
		current := transcript
		if mutateTranscriptAfterReplay && health.AgentID == bobID && sends.Load() > 0 {
			current.Transcript = append([]transcriptLine(nil), transcript.Transcript...)
			current.Transcript[len(current.Transcript)-1].Content = "substituted historical message"
		}
		writeFixtureJSON(w, current)
	})
	mux.HandleFunc("POST /v1/send", func(w http.ResponseWriter, request *http.Request) {
		sends.Add(1)
		var body map[string]string
		if err := json.NewDecoder(request.Body).
			Decode(&body); err != nil || body["request_id"] == "" ||
			body["content"] == "" {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		writeFixtureJSON(w, sendResponse{Schema: controlSchema, EventID: replayID})
	})
	return startUnixServer(t, mux)
}

func startUnixServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		_ = listener.Close()
	})
	return socket
}

func writeFixtureJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
