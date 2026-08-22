// Command openfox-messenger-lab-verify produces machine-checkable evidence for
// an already running three-Agent OpenFox Messenger lab deployment. It verifies
// the owner-private control boundaries, the exact causal Event chain, durable
// idempotent replay, Relay opacity, and deployed artifact identities. It does
// not claim a public route or independent operation.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	controlSchema   = "openfox.messenger-lab-agent-control.v1"
	reportSchema    = "openfox.messenger-lab-acceptance.v1"
	maxControlBytes = 64 << 20
	maxRelayBytes   = 64 << 20
	maxTimeout      = 30 * time.Second

	aliceID = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bobID   = "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	carolID = "agent_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var (
	roomPattern       = regexp.MustCompile(`^room_[0-9a-f]{64}$`)
	eventPattern      = regexp.MustCompile(`^msg_[0-9a-f]{64}$`)
	requestPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	artifactPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requiredArtifacts = map[string]bool{
		"openfox-messenger-lab-agent":  true,
		"openfox-messenger-lab-deploy": true,
		"tos-messenger-lab-group":      true,
		"tos-messenger-openfox-mls":    true,
		"tos-openmls-driver":           true,
	}
)

type stringFlags []string

func (f *stringFlags) String() string         { return strings.Join(*f, ",") }
func (f *stringFlags) Set(value string) error { *f = append(*f, value); return nil }

type options struct {
	controlSockets  map[string]string
	relayState      string
	roomID          string
	requestID       string
	content         string
	openingEventID  string
	bobReplyEventID string
	carolReplyID    string
	expectedRecords int
	timeout         time.Duration
	artifacts       []string
}

type healthResponse struct {
	Schema       string `json:"schema"`
	OK           bool   `json:"ok"`
	AgentID      string `json:"agent_id"`
	RoomID       string `json:"room_id"`
	ActiveMember bool   `json:"active_member"`
	ReplyMode    string `json:"reply_mode"`
}

type transcriptLine struct {
	Direction      string `json:"direction"`
	AgentID        string `json:"agent_id"`
	EventID        string `json:"event_id"`
	ClientID       string `json:"client_id,omitempty"`
	ReplyToEventID string `json:"reply_to_event_id,omitempty"`
	Runtime        string `json:"runtime,omitempty"`
	Content        string `json:"content"`
}

type transcriptResponse struct {
	Schema     string           `json:"schema"`
	Transcript []transcriptLine `json:"transcript"`
}

type sendResponse struct {
	Schema  string `json:"schema"`
	EventID string `json:"event_id"`
}

type artifactEvidence struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type agentEvidence struct {
	AgentID           string `json:"agent_id"`
	ControlSocket     string `json:"control_socket"`
	ActiveMember      bool   `json:"active_member"`
	ReplyMode         string `json:"reply_mode"`
	TranscriptRecords int    `json:"transcript_records"`
	AcceptanceEvents  int    `json:"acceptance_events"`
}

type acceptanceReport struct {
	Schema              string             `json:"schema"`
	VerifiedAt          string             `json:"verified_at"`
	Scope               string             `json:"scope"`
	RoomID              string             `json:"room_id"`
	RequestID           string             `json:"request_id"`
	OpeningEventID      string             `json:"opening_event_id"`
	BobReplyEventID     string             `json:"bob_reply_event_id"`
	CarolReplyEventID   string             `json:"carol_reply_event_id"`
	ExactReplayStable   bool               `json:"exact_replay_stable"`
	RelayState          string             `json:"relay_state"`
	RelayMode           string             `json:"relay_mode"`
	RelayBytes          int64              `json:"relay_bytes"`
	RelaySHA256         string             `json:"relay_sha256"`
	RelayPlaintextFound bool               `json:"relay_plaintext_found"`
	Agents              []agentEvidence    `json:"agents"`
	Artifacts           []artifactEvidence `json:"artifacts"`
}

func main() {
	var artifacts stringFlags
	aliceControl := flag.String("alice-control", "", "absolute Alice control Unix socket")
	bobControl := flag.String("bob-control", "", "absolute Bob control Unix socket")
	carolControl := flag.String("carol-control", "", "absolute Carol control Unix socket")
	relayState := flag.String("relay-state", "", "absolute opaque Relay state file")
	roomID := flag.String("room-id", "", "expected room_<64 lowercase hex>")
	requestID := flag.String("request-id", "", "stable request ID to replay")
	content := flag.String("content", "", "exact opening plaintext")
	openingEventID := flag.String("opening-event-id", "", "expected opening Event ID")
	bobReplyEventID := flag.String("bob-reply-event-id", "", "expected Bob reply Event ID")
	carolReplyEventID := flag.String("carol-reply-event-id", "", "expected Carol reply Event ID")
	expectedRecords := flag.Int("expected-transcript-records", 0, "exact record count required in every transcript")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout, at most 30s")
	flag.Var(&artifacts, "artifact", "name=sha256:/absolute/executable (repeat)")
	flag.Parse()

	report, err := verify(context.Background(), options{
		controlSockets: map[string]string{aliceID: *aliceControl, bobID: *bobControl, carolID: *carolControl},
		relayState:     *relayState, roomID: *roomID, requestID: *requestID, content: *content,
		openingEventID: *openingEventID, bobReplyEventID: *bobReplyEventID,
		carolReplyID: *carolReplyEventID, expectedRecords: *expectedRecords,
		timeout: *timeout, artifacts: artifacts,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-lab-verify:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "openfox-messenger-lab-verify:", err)
		os.Exit(1)
	}
}

func verify(ctx context.Context, config options) (acceptanceReport, error) {
	if err := validateOptions(config); err != nil {
		return acceptanceReport{}, err
	}
	artifacts, artifactErr := verifyArtifacts(config.artifacts)
	if artifactErr != nil {
		return acceptanceReport{}, artifactErr
	}
	relayInfo, relayBody, relayErr := readRelayState(config.relayState)
	if relayErr != nil {
		return acceptanceReport{}, relayErr
	}

	agentIDs := []string{aliceID, bobID, carolID}
	report := acceptanceReport{
		Schema: reportSchema, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Scope: "same-host-local-route-only", RoomID: config.roomID, RequestID: config.requestID,
		OpeningEventID: config.openingEventID, BobReplyEventID: config.bobReplyEventID,
		CarolReplyEventID: config.carolReplyID, RelayState: config.relayState,
		RelayMode: fmt.Sprintf("%04o", relayInfo.Mode().Perm()), RelayBytes: int64(len(relayBody)),
		RelaySHA256: hexDigest(relayBody), Artifacts: artifacts,
	}
	var canonicalReplies map[string]string
	socketIdentities := make(map[string]os.FileInfo, len(agentIDs))
	initialTranscripts := make(map[string]transcriptResponse, len(agentIDs))
	for _, agentID := range agentIDs {
		socket := config.controlSockets[agentID]
		before, socketErr := validateSocket(socket)
		if socketErr != nil {
			return acceptanceReport{}, fmt.Errorf("%s control boundary: %w", agentID, socketErr)
		}
		health, healthErr := getHealth(ctx, socket, config.timeout)
		if healthErr != nil {
			return acceptanceReport{}, fmt.Errorf("%s health: %w", agentID, healthErr)
		}
		if health.Schema != controlSchema || !health.OK || health.AgentID != agentID ||
			health.RoomID != config.roomID || !health.ActiveMember || health.ReplyMode != "agent-loop" {
			return acceptanceReport{}, fmt.Errorf("%s health authority mismatch", agentID)
		}
		transcript, transcriptErr := getTranscript(ctx, socket, config.timeout)
		if transcriptErr != nil {
			return acceptanceReport{}, fmt.Errorf("%s transcript: %w", agentID, transcriptErr)
		}
		replies, verifyErr := verifyTranscript(agentID, transcript, config)
		if verifyErr != nil {
			return acceptanceReport{}, fmt.Errorf("%s transcript: %w", agentID, verifyErr)
		}
		if canonicalReplies == nil {
			canonicalReplies = replies
		} else if canonicalReplies[config.bobReplyEventID] != replies[config.bobReplyEventID] ||
			canonicalReplies[config.carolReplyID] != replies[config.carolReplyID] {
			return acceptanceReport{}, errors.New("reply plaintext differs across Agent transcripts")
		}
		if err := validateSocketIdentity(socket, before); err != nil {
			return acceptanceReport{}, fmt.Errorf("%s control boundary: %w", agentID, err)
		}
		socketIdentities[agentID] = before
		initialTranscripts[agentID] = transcript
		report.Agents = append(report.Agents, agentEvidence{
			AgentID: agentID, ControlSocket: socket, ActiveMember: true,
			ReplyMode: health.ReplyMode, TranscriptRecords: len(transcript.Transcript), AcceptanceEvents: 3,
		})
	}

	plaintexts := []string{
		config.content,
		canonicalReplies[config.bobReplyEventID],
		canonicalReplies[config.carolReplyID],
	}
	for _, plaintext := range plaintexts {
		if plaintext == "" || bytes.Contains(relayBody, []byte(plaintext)) {
			report.RelayPlaintextFound = true
			return acceptanceReport{}, errors.New("Relay state contains acceptance plaintext")
		}
	}

	replay, replayErr := postReplay(ctx, config.controlSockets[aliceID], config, config.timeout)
	if replayErr != nil {
		return acceptanceReport{}, fmt.Errorf("exact replay: %w", replayErr)
	}
	if replay.Schema != controlSchema || replay.EventID != config.openingEventID {
		return acceptanceReport{}, errors.New("exact replay returned a substituted Event ID")
	}
	report.ExactReplayStable = true

	for _, agentID := range agentIDs {
		transcript, transcriptErr := getTranscript(ctx, config.controlSockets[agentID], config.timeout)
		if transcriptErr != nil {
			return acceptanceReport{}, fmt.Errorf("%s post-replay transcript: %w", agentID, transcriptErr)
		}
		if !reflect.DeepEqual(transcript, initialTranscripts[agentID]) {
			return acceptanceReport{}, fmt.Errorf("%s exact replay changed complete transcript", agentID)
		}
		replies, verifyErr := verifyTranscript(agentID, transcript, config)
		if verifyErr != nil {
			return acceptanceReport{}, fmt.Errorf("%s post-replay transcript: %w", agentID, verifyErr)
		}
		if canonicalReplies[config.bobReplyEventID] != replies[config.bobReplyEventID] ||
			canonicalReplies[config.carolReplyID] != replies[config.carolReplyID] {
			return acceptanceReport{}, errors.New("reply plaintext changed after exact replay")
		}
		if err := validateSocketIdentity(config.controlSockets[agentID], socketIdentities[agentID]); err != nil {
			return acceptanceReport{}, fmt.Errorf("%s post-replay control boundary: %w", agentID, err)
		}
	}
	relayInfoAfter, relayAfter, relayErr := readRelayState(config.relayState)
	if relayErr != nil {
		return acceptanceReport{}, fmt.Errorf("post-replay Relay state: %w", relayErr)
	}
	if !os.SameFile(relayInfo, relayInfoAfter) || !bytes.Equal(relayBody, relayAfter) {
		return acceptanceReport{}, errors.New("exact replay changed opaque Relay state")
	}
	return report, nil
}

func validateOptions(config options) error {
	if !roomPattern.MatchString(config.roomID) || !requestPattern.MatchString(config.requestID) ||
		!eventPattern.MatchString(config.openingEventID) || !eventPattern.MatchString(config.bobReplyEventID) ||
		!eventPattern.MatchString(config.carolReplyID) || config.openingEventID == config.bobReplyEventID ||
		config.openingEventID == config.carolReplyID || config.bobReplyEventID == config.carolReplyID {
		return errors.New("room, request, or distinct Event identities are invalid")
	}
	if strings.TrimSpace(config.content) == "" || len(config.content) > 128<<10 {
		return errors.New("content must be non-empty and at most 128 KiB")
	}
	if config.expectedRecords < 3 || config.expectedRecords > 4096 {
		return errors.New("expected-transcript-records must be within 3..4096")
	}
	if config.timeout <= 0 || config.timeout > maxTimeout {
		return errors.New("timeout must be within 1ns..30s")
	}
	if len(config.artifacts) != len(requiredArtifacts) {
		return errors.New("all five pinned deployment artifacts are required")
	}
	if len(config.controlSockets) != 3 {
		return errors.New("exactly three control sockets are required")
	}
	paths := make(map[string]bool, len(config.controlSockets)+1)
	for _, path := range config.controlSockets {
		if !safeAbsolutePath(path) || paths[path] {
			return errors.New("control sockets must be distinct safe absolute paths")
		}
		paths[path] = true
	}
	if !safeAbsolutePath(config.relayState) || paths[config.relayState] {
		return errors.New("Relay state must be a distinct safe absolute path")
	}
	return nil
}

func safeAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, "//") &&
		!strings.ContainsAny(path, "\x00\r\n")
}

func verifyTranscript(viewer string, response transcriptResponse, config options) (map[string]string, error) {
	if response.Schema != controlSchema || len(response.Transcript) != config.expectedRecords {
		return nil, errors.New("schema or exact record count mismatch")
	}
	targets := map[string]string{
		config.openingEventID:  aliceID,
		config.bobReplyEventID: bobID,
		config.carolReplyID:    carolID,
	}
	seen := make(map[string]int, 3)
	replies := make(map[string]string, 2)
	repliesToOpening := 0
	for _, line := range response.Transcript {
		if line.ReplyToEventID == config.openingEventID {
			repliesToOpening++
		}
		author, wanted := targets[line.EventID]
		if !wanted {
			continue
		}
		seen[line.EventID]++
		if line.AgentID != author || line.Content == "" {
			return nil, errors.New("acceptance Event author or content mismatch")
		}
		expectedDirection := "inbound"
		if viewer == author {
			expectedDirection = "outbound"
		}
		if line.Direction != expectedDirection {
			return nil, errors.New("acceptance Event direction mismatch")
		}
		if line.EventID == config.openingEventID {
			clientBindingValid := viewer == aliceID && line.ClientID == config.requestID ||
				viewer != aliceID && line.ClientID == ""
			if line.Content != config.content || line.ReplyToEventID != "" || line.Runtime != "" ||
				!clientBindingValid {
				return nil, errors.New("opening Event substitution")
			}
			continue
		}
		if line.ReplyToEventID != config.openingEventID {
			return nil, errors.New("reply causality mismatch")
		}
		if viewer == author {
			if line.Runtime != "openfox-agent-loop" {
				return nil, errors.New("reply did not originate in AgentLoop")
			}
		} else if line.Runtime != "" {
			return nil, errors.New("recipient transcript asserted producer runtime")
		}
		replies[line.EventID] = line.Content
	}
	if repliesToOpening != 2 || len(seen) != 3 || len(replies) != 2 {
		return nil, errors.New("acceptance Event set is incomplete or duplicated")
	}
	for eventID := range targets {
		if seen[eventID] != 1 {
			return nil, errors.New("acceptance Event is missing or duplicated")
		}
	}
	return replies, nil
}

func getHealth(ctx context.Context, socket string, timeout time.Duration) (healthResponse, error) {
	var response healthResponse
	err := controlJSON(ctx, socket, timeout, http.MethodGet, "/v1/health", nil, &response)
	return response, err
}

func getTranscript(ctx context.Context, socket string, timeout time.Duration) (transcriptResponse, error) {
	var response transcriptResponse
	err := controlJSON(ctx, socket, timeout, http.MethodGet, "/v1/transcript", nil, &response)
	return response, err
}

func postReplay(ctx context.Context, socket string, config options, timeout time.Duration) (sendResponse, error) {
	body, err := json.Marshal(map[string]string{"request_id": config.requestID, "content": config.content})
	if err != nil {
		return sendResponse{}, err
	}
	var response sendResponse
	err = controlJSON(ctx, socket, timeout, http.MethodPost, "/v1/send", bytes.NewReader(body), &response)
	return response, err
}

func controlJSON(
	ctx context.Context,
	socket string,
	timeout time.Duration,
	method, path string,
	body io.Reader,
	target any,
) error {
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("control redirect refused")
		},
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" {
		return fmt.Errorf("unexpected HTTP response: %s", response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxControlBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxControlBytes {
		return errors.New("control response exceeds 64 MiB")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("control response has trailing JSON")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("control response has trailing JSON")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("control response contains a duplicate JSON key")
			}
			seen[key] = true
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func validateSocket(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("path is not a mode-0600 Unix socket")
	}
	return info, nil
}

func validateSocketIdentity(path string, before os.FileInfo) error {
	after, err := validateSocket(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("Unix socket was substituted during verification")
	}
	return nil
}

func readRelayState(path string) (os.FileInfo, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maxRelayBytes {
		return nil, nil, errors.New("Relay state must be a non-empty bounded regular mode-0600 file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 ||
		int64(len(body)) != after.Size() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, nil, errors.New("Relay state was substituted during verification")
	}
	return after, body, nil
}

func verifyArtifacts(values []string) ([]artifactEvidence, error) {
	result := make([]artifactEvidence, 0, len(values))
	names := make(map[string]bool, len(values))
	paths := make(map[string]bool, len(values))
	for _, value := range values {
		name, rest, ok := strings.Cut(value, "=")
		digest, path, ok2 := strings.Cut(rest, ":")
		if !ok || !ok2 || !artifactPattern.MatchString(name) || !digestPattern.MatchString(digest) ||
			!safeAbsolutePath(path) || names[name] || paths[path] {
			return nil, errors.New("artifact must be unique name=sha256:/absolute/executable")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 ||
			info.Size() < 1 {
			return nil, fmt.Errorf("artifact is not a regular executable: %s", name)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		openedInfo, err := file.Stat()
		if err != nil || !os.SameFile(info, openedInfo) {
			file.Close()
			return nil, fmt.Errorf("artifact was substituted before hashing: %s", name)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		hashedInfo, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil || !os.SameFile(openedInfo, hashedInfo) ||
			openedInfo.Size() != hashedInfo.Size() || !openedInfo.ModTime().Equal(hashedInfo.ModTime()) {
			return nil, fmt.Errorf("hash artifact %s", name)
		}
		actual := hex.EncodeToString(hash.Sum(nil))
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0o111 == 0 ||
			info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || actual != digest {
			return nil, fmt.Errorf("artifact identity mismatch: %s", name)
		}
		names[name], paths[path] = true, true
		result = append(result, artifactEvidence{Name: name, Path: path, SHA256: actual})
	}
	if len(names) != len(requiredArtifacts) {
		return nil, errors.New("all five pinned deployment artifacts are required")
	}
	for name := range requiredArtifacts {
		if !names[name] {
			return nil, fmt.Errorf("required deployment artifact is missing: %s", name)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func hexDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
