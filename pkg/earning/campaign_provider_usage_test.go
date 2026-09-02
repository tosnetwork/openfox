package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	"github.com/tosnetwork/openfox/pkg/providers"
)

const (
	campaignProviderUsageMaximumJournalBytes = 16 << 20
	campaignProviderUsageAmountUnknown       = "unknown"
	campaignProviderUsageSummaryFilename     = "eight-agent-capability-market-round-4-provider-usage-summary.json"
	campaignProviderUsageInFlightFilename    = "inflight-call.json"
)

// campaignProviderUsageCall is deliberately metadata-only. Never add prompt,
// response, tool, model-option, or provider-error fields to this owner-private
// journal: those values can contain the agent's private working context.
type campaignProviderUsageCall struct {
	CampaignRunID    string `json:"campaign_run_id"`
	Agent            string `json:"agent"`
	CallIndex        uint64 `json:"call_index"`
	CompletedAt      string `json:"completed_at"`
	UsageStatus      string `json:"usage_status"`
	PromptTokens     uint64 `json:"prompt_tokens,omitempty"`
	CompletionTokens uint64 `json:"completion_tokens,omitempty"`
	TotalTokens      uint64 `json:"total_tokens,omitempty"`
	Failed           bool   `json:"failed"`
}

// campaignProviderUsageInFlightCall is a durable, metadata-only write-ahead
// marker. It is persisted before the real Provider is invoked and removed
// only after the completed call is durable in the append-only journal. An
// unmatched marker makes recovery fail closed instead of silently omitting a
// call that may already have incurred cost.
type campaignProviderUsageInFlightCall struct {
	CampaignRunID string `json:"campaign_run_id"`
	Agent         string `json:"agent"`
	CallIndex     uint64 `json:"call_index"`
	StartedAt     string `json:"started_at"`
}

type campaignProviderUsageAgentSummary struct {
	CampaignRunID     string `json:"campaign_run_id"`
	Agent             string `json:"agent"`
	Calls             uint64 `json:"calls"`
	UsageCalls        uint64 `json:"usage_calls"`
	MissingUsageCalls uint64 `json:"missing_usage_calls"`
	InvalidUsageCalls uint64 `json:"invalid_usage_calls"`
	FailedCalls       uint64 `json:"failed_calls"`
	PromptTokens      uint64 `json:"prompt_tokens"`
	CompletionTokens  uint64 `json:"completion_tokens"`
	TotalTokens       uint64 `json:"total_tokens"`
	AmountStatus      string `json:"amount_status"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

type campaignProviderUsageAggregate struct {
	Agents            uint64 `json:"agents"`
	Calls             uint64 `json:"calls"`
	UsageCalls        uint64 `json:"usage_calls"`
	MissingUsageCalls uint64 `json:"missing_usage_calls"`
	InvalidUsageCalls uint64 `json:"invalid_usage_calls"`
	FailedCalls       uint64 `json:"failed_calls"`
	PromptTokens      uint64 `json:"prompt_tokens"`
	CompletionTokens  uint64 `json:"completion_tokens"`
	TotalTokens       uint64 `json:"total_tokens"`
}

type campaignProviderUsageSummary struct {
	CampaignRunID string                              `json:"campaign_run_id"`
	GeneratedAt   string                              `json:"generated_at"`
	AmountStatus  string                              `json:"amount_status"`
	Agents        []campaignProviderUsageAgentSummary `json:"agents"`
	Aggregate     campaignProviderUsageAggregate      `json:"aggregate"`
}

// campaignProviderUsageReference is embedded in the experimental Round 4
// report and financial summary. It is an evidence pointer, not a protocol
// schema, and intentionally carries no estimated or converted currency value.
type campaignProviderUsageReference struct {
	CampaignRunID       string `json:"campaign_run_id"`
	SummaryRelativePath string `json:"summary_relative_path"`
	SummaryDigest       string `json:"summary_digest"`
	AmountStatus        string `json:"amount_status"`
	Calls               uint64 `json:"calls"`
	UsageCalls          uint64 `json:"usage_calls"`
	MissingUsageCalls   uint64 `json:"missing_usage_calls"`
	InvalidUsageCalls   uint64 `json:"invalid_usage_calls"`
	FailedCalls         uint64 `json:"failed_calls"`
	PromptTokens        uint64 `json:"prompt_tokens"`
	CompletionTokens    uint64 `json:"completion_tokens"`
	TotalTokens         uint64 `json:"total_tokens"`
}

type campaignProviderUsageRecorder struct {
	mu            sync.Mutex
	runID         string
	agent         string
	journalPath   string
	summaryPath   string
	inFlightPath  string
	journal       *os.File
	summary       campaignProviderUsageAgentSummary
	now           func() time.Time
	inFlight      bool
	inFlightIndex uint64
	sealed        bool
	closed        bool
}

type campaignProviderUsageProvider struct {
	delegate providers.LLMProvider
	recorder *campaignProviderUsageRecorder
	callMu   sync.Mutex
	close    sync.Once
}

func openCampaignProviderUsageRecorder(root, runID, agent string) (*campaignProviderUsageRecorder, error) {
	if !filepath.IsAbs(root) || strings.TrimSpace(agent) == "" || filepath.Base(agent) != agent ||
		agent == "." || agent == ".." {
		return nil, errors.New("campaign provider usage owner path is invalid")
	}
	if err := validateCampaignRunID(runID); err != nil {
		return nil, fmt.Errorf("campaign provider usage run scope: %w", err)
	}
	directory := filepath.Join(root, "campaign", "provider-usage", agent)
	if err := ensureCampaignProviderUsagePrivateDirectory(root, directory); err != nil {
		return nil, err
	}
	recorder := &campaignProviderUsageRecorder{
		runID:        runID,
		agent:        agent,
		journalPath:  filepath.Join(directory, "calls.jsonl"),
		summaryPath:  filepath.Join(directory, "summary.json"),
		inFlightPath: filepath.Join(directory, campaignProviderUsageInFlightFilename),
		now:          func() time.Time { return time.Now().UTC() },
		summary: campaignProviderUsageAgentSummary{
			CampaignRunID: runID, Agent: agent, AmountStatus: campaignProviderUsageAmountUnknown,
		},
	}
	if err := recorder.recover(); err != nil {
		return nil, err
	}
	journal, err := os.OpenFile(recorder.journalPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open campaign provider usage journal: %w", err)
	}
	if err := validateCampaignProviderUsagePrivateFile(recorder.journalPath, journal); err != nil {
		_ = journal.Close()
		return nil, err
	}
	recorder.journal = journal
	if err := recorder.writeSummaryLocked(); err != nil {
		_ = journal.Close()
		return nil, err
	}
	return recorder, nil
}

func ensureCampaignProviderUsagePrivateDirectory(root, path string) error {
	root, path = filepath.Clean(root), filepath.Clean(path)
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return errors.New("campaign provider usage directory scope is invalid")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("campaign provider usage directory escapes its campaign root")
	}
	if err := syncCampaignProviderUsagePrivateDirectory(root); err != nil {
		return fmt.Errorf("validate campaign provider usage root: %w", err)
	}
	if relative == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("campaign provider usage directory component is invalid")
		}
		next := filepath.Join(current, component)
		if err := os.Mkdir(next, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create campaign provider usage directory: %w", err)
		}
		// Syncing the parent makes this child directory entry durable. Syncing
		// the child makes any already-present descendants durable before a
		// marker-gated real Provider call can begin.
		if err := syncCampaignProviderUsagePrivateDirectory(current); err != nil {
			return fmt.Errorf("sync campaign provider usage parent directory: %w", err)
		}
		if err := syncCampaignProviderUsagePrivateDirectory(next); err != nil {
			return fmt.Errorf("validate campaign provider usage directory: %w", err)
		}
		current = next
	}
	return nil
}

func syncCampaignProviderUsagePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("campaign provider usage directory is not owner-private")
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	opened, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return err
	}
	if !os.SameFile(info, opened) {
		_ = directory.Close()
		return errors.New("campaign provider usage directory changed while opening")
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func validateCampaignProviderUsagePrivateFile(path string, file *os.File) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect campaign provider usage file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("campaign provider usage file is not owner-private regular data")
	}
	if file != nil {
		opened, statErr := file.Stat()
		if statErr != nil {
			return fmt.Errorf("inspect open campaign provider usage file: %w", statErr)
		}
		if !os.SameFile(info, opened) {
			return errors.New("campaign provider usage file changed while opening")
		}
	}
	return nil
}

func (recorder *campaignProviderUsageRecorder) recover() error {
	info, err := os.Lstat(recorder.journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return recorder.recoverInFlightMarker(nil)
	}
	if err != nil {
		return fmt.Errorf("inspect campaign provider usage journal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("campaign provider usage journal is not owner-private regular data")
	}
	if info.Size() > campaignProviderUsageMaximumJournalBytes {
		return errors.New("campaign provider usage journal exceeds its recovery bound")
	}
	journal, err := os.OpenFile(recorder.journalPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open campaign provider usage journal for recovery: %w", err)
	}
	defer journal.Close()
	if err := validateCampaignProviderUsagePrivateFile(recorder.journalPath, journal); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(journal, campaignProviderUsageMaximumJournalBytes+1))
	if err != nil {
		return fmt.Errorf("read campaign provider usage journal: %w", err)
	}
	if len(data) > campaignProviderUsageMaximumJournalBytes {
		return errors.New("campaign provider usage journal exceeds its recovery bound")
	}
	if len(data) == 0 {
		return recorder.recoverInFlightMarker(journal)
	}
	if data[len(data)-1] != '\n' {
		return errors.New("campaign provider usage journal has an incomplete final record")
	}
	for lineNumber, line := range bytes.Split(data[:len(data)-1], []byte{'\n'}) {
		if len(line) == 0 {
			return fmt.Errorf("campaign provider usage journal record %d is empty", lineNumber+1)
		}
		if _, err := campaignExactJSONObject(line,
			[]string{"campaign_run_id", "agent", "call_index", "completed_at", "usage_status", "failed"},
			[]string{"prompt_tokens", "completion_tokens", "total_tokens"}, nil,
		); err != nil {
			return fmt.Errorf("campaign provider usage journal record %d has invalid JSON shape: %w", lineNumber+1, err)
		}
		var call campaignProviderUsageCall
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&call); err != nil {
			return fmt.Errorf("decode campaign provider usage journal record %d: %w", lineNumber+1, err)
		}
		if err := requireCampaignJSONEOF(decoder); err != nil {
			return fmt.Errorf("finish campaign provider usage journal record %d: %w", lineNumber+1, err)
		}
		if err := recorder.applyCall(&recorder.summary, call); err != nil {
			return fmt.Errorf("validate campaign provider usage journal record %d: %w", lineNumber+1, err)
		}
	}
	return recorder.recoverInFlightMarker(journal)
}

func (recorder *campaignProviderUsageRecorder) recoverInFlightMarker(journal *os.File) error {
	info, err := os.Lstat(recorder.inFlightPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect campaign provider usage in-flight marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > 4<<10 {
		return errors.New("campaign provider usage in-flight marker is invalid")
	}
	raw, err := os.ReadFile(recorder.inFlightPath)
	if err != nil {
		return fmt.Errorf("read campaign provider usage in-flight marker: %w", err)
	}
	if _, err := campaignExactJSONObject(raw,
		[]string{"campaign_run_id", "agent", "call_index", "started_at"}, nil, nil,
	); err != nil {
		return fmt.Errorf("campaign provider usage in-flight marker has invalid JSON shape: %w", err)
	}
	var marker campaignProviderUsageInFlightCall
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return fmt.Errorf("decode campaign provider usage in-flight marker: %w", err)
	}
	if err := requireCampaignJSONEOF(decoder); err != nil {
		return fmt.Errorf("finish campaign provider usage in-flight marker: %w", err)
	}
	if marker.CampaignRunID != recorder.runID || marker.Agent != recorder.agent || marker.CallIndex == 0 {
		return errors.New("campaign provider usage in-flight marker identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, marker.StartedAt); err != nil {
		return errors.New("campaign provider usage in-flight marker time is invalid")
	}
	if marker.CallIndex == recorder.summary.Calls {
		// The journal record is already durable. A crash or directory-sync
		// failure may merely have left the conservative marker behind. Sync
		// the exact inode from which recovery read before deleting the WAL;
		// page-cache visibility alone is not durability.
		if journal == nil {
			return errors.New("campaign provider usage completed marker has no recoverable journal")
		}
		if err := journal.Sync(); err != nil {
			return fmt.Errorf("sync recovered campaign provider usage journal: %w", err)
		}
		if err := removeCampaignProviderUsageFileDurably(recorder.inFlightPath); err != nil {
			return fmt.Errorf("clear reconciled campaign provider usage in-flight marker: %w", err)
		}
		return nil
	}
	nextIndex, err := addCampaignProviderUsageCount(recorder.summary.Calls, 1)
	if err != nil {
		return err
	}
	if marker.CallIndex == nextIndex {
		return errors.New("campaign provider usage has an incomplete call whose cost cannot be attributed")
	}
	return errors.New("campaign provider usage in-flight marker sequence is invalid")
}

func removeCampaignProviderUsageFileDurably(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func (recorder *campaignProviderUsageRecorder) BeginCall() error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.closed || recorder.sealed || recorder.journal == nil || recorder.inFlight {
		return errors.New("campaign provider usage recorder is unavailable")
	}
	if _, err := os.Lstat(recorder.inFlightPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("campaign provider usage recorder has a retained in-flight marker")
		}
		return fmt.Errorf("inspect campaign provider usage in-flight marker before call: %w", err)
	}
	callIndex, err := addCampaignProviderUsageCount(recorder.summary.Calls, 1)
	if err != nil {
		recorder.poisonLocked()
		return err
	}
	marker := campaignProviderUsageInFlightCall{
		CampaignRunID: recorder.runID,
		Agent:         recorder.agent,
		CallIndex:     callIndex,
		StartedAt:     recorder.now().UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(marker)
	if err != nil {
		recorder.poisonLocked()
		return fmt.Errorf("encode campaign provider usage in-flight marker: %w", err)
	}
	if err := fileutil.WriteFileAtomic(recorder.inFlightPath, encoded, 0o600); err != nil {
		recorder.poisonLocked()
		return fmt.Errorf("write campaign provider usage in-flight marker: %w", err)
	}
	if err := validateCampaignProviderUsagePrivateFile(recorder.inFlightPath, nil); err != nil {
		recorder.poisonLocked()
		return err
	}
	recorder.inFlight = true
	recorder.inFlightIndex = marker.CallIndex
	return nil
}

func (recorder *campaignProviderUsageRecorder) Record(response *providers.LLMResponse, callErr error) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	expectedIndex, indexErr := addCampaignProviderUsageCount(recorder.summary.Calls, 1)
	if recorder.closed || recorder.journal == nil || !recorder.inFlight || indexErr != nil ||
		recorder.inFlightIndex != expectedIndex {
		return errors.New("campaign provider usage recorder is closed")
	}
	call := campaignProviderUsageCall{
		CampaignRunID: recorder.runID,
		Agent:         recorder.agent,
		CallIndex:     recorder.inFlightIndex,
		CompletedAt:   recorder.now().UTC().Format(time.RFC3339Nano),
		UsageStatus:   "missing",
		Failed:        callErr != nil,
	}
	if response != nil && response.Usage != nil {
		usage := response.Usage
		if usage.PromptTokens < 0 || usage.CompletionTokens < 0 || usage.TotalTokens <= 0 ||
			usage.PromptTokens > usage.TotalTokens ||
			usage.CompletionTokens > usage.TotalTokens-usage.PromptTokens {
			call.UsageStatus = "invalid"
		} else {
			call.UsageStatus = "observed"
			call.PromptTokens = uint64(usage.PromptTokens)
			call.CompletionTokens = uint64(usage.CompletionTokens)
			call.TotalTokens = uint64(usage.TotalTokens)
		}
	}
	next := recorder.summary
	if err := recorder.applyCall(&next, call); err != nil {
		recorder.poisonLocked()
		return err
	}
	encoded, err := json.Marshal(call)
	if err != nil {
		recorder.poisonLocked()
		return fmt.Errorf("encode campaign provider usage call: %w", err)
	}
	encoded = append(encoded, '\n')
	journalInfo, err := recorder.journal.Stat()
	if err != nil {
		recorder.poisonLocked()
		return fmt.Errorf("inspect campaign provider usage journal before append: %w", err)
	}
	if journalInfo.Size() > campaignProviderUsageMaximumJournalBytes-int64(len(encoded)) {
		recorder.poisonLocked()
		return errors.New("campaign provider usage journal exceeds its append bound")
	}
	written, err := recorder.journal.Write(encoded)
	if err != nil || written != len(encoded) {
		recorder.poisonLocked()
		if err == nil {
			err = io.ErrShortWrite
		}
		return fmt.Errorf("append campaign provider usage call: wrote %d of %d bytes: %w",
			written, len(encoded), err)
	}
	if err := recorder.journal.Sync(); err != nil {
		recorder.poisonLocked()
		return fmt.Errorf("sync campaign provider usage call: %w", err)
	}
	recorder.summary = next
	if err := recorder.writeSummaryLocked(); err != nil {
		recorder.poisonLocked()
		return err
	}
	if err := removeCampaignProviderUsageFileDurably(recorder.inFlightPath); err != nil {
		recorder.poisonLocked()
		return fmt.Errorf("clear campaign provider usage in-flight marker: %w", err)
	}
	recorder.inFlight = false
	recorder.inFlightIndex = 0
	return nil
}

func (recorder *campaignProviderUsageRecorder) poisonLocked() {
	recorder.closed = true
	if recorder.journal != nil {
		_ = recorder.journal.Close()
		recorder.journal = nil
	}
}

func (recorder *campaignProviderUsageRecorder) applyCall(
	summary *campaignProviderUsageAgentSummary,
	call campaignProviderUsageCall,
) error {
	if summary == nil {
		return errors.New("campaign provider usage call identity or sequence is invalid")
	}
	expectedIndex, err := addCampaignProviderUsageCount(summary.Calls, 1)
	if err != nil || call.CampaignRunID != recorder.runID || summary.CampaignRunID != recorder.runID ||
		call.Agent != recorder.agent || call.CallIndex != expectedIndex {
		return errors.New("campaign provider usage call identity or sequence is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, call.CompletedAt); err != nil {
		return errors.New("campaign provider usage call time is invalid")
	}
	if call.UsageStatus != "observed" && call.UsageStatus != "missing" && call.UsageStatus != "invalid" {
		return errors.New("campaign provider usage status is invalid")
	}
	if call.UsageStatus == "observed" &&
		(call.TotalTokens == 0 || call.PromptTokens > call.TotalTokens ||
			call.CompletionTokens > call.TotalTokens-call.PromptTokens) {
		return errors.New("campaign provider observed usage arithmetic is invalid")
	}
	if call.UsageStatus != "observed" &&
		(call.PromptTokens != 0 || call.CompletionTokens != 0 || call.TotalTokens != 0) {
		return errors.New("campaign provider usage missing call contains token counts")
	}
	next := *summary
	err = nil
	if next.Calls, err = addCampaignProviderUsageCount(next.Calls, 1); err != nil {
		return err
	}
	if call.UsageStatus == "observed" {
		if next.UsageCalls, err = addCampaignProviderUsageCount(next.UsageCalls, 1); err != nil {
			return err
		}
		if next.PromptTokens, err = addCampaignProviderUsageCount(next.PromptTokens, call.PromptTokens); err != nil {
			return err
		}
		if next.CompletionTokens, err = addCampaignProviderUsageCount(next.CompletionTokens, call.CompletionTokens); err != nil {
			return err
		}
		if next.TotalTokens, err = addCampaignProviderUsageCount(next.TotalTokens, call.TotalTokens); err != nil {
			return err
		}
	} else if call.UsageStatus == "invalid" {
		if next.InvalidUsageCalls, err = addCampaignProviderUsageCount(next.InvalidUsageCalls, 1); err != nil {
			return err
		}
	} else if next.MissingUsageCalls, err = addCampaignProviderUsageCount(next.MissingUsageCalls, 1); err != nil {
		return err
	}
	if call.Failed {
		if next.FailedCalls, err = addCampaignProviderUsageCount(next.FailedCalls, 1); err != nil {
			return err
		}
	}
	next.Agent = recorder.agent
	next.CampaignRunID = recorder.runID
	next.AmountStatus = campaignProviderUsageAmountUnknown
	next.UpdatedAt = call.CompletedAt
	*summary = next
	return nil
}

func addCampaignProviderUsageCount(left, right uint64) (uint64, error) {
	if ^uint64(0)-left < right {
		return 0, errors.New("campaign provider usage counter overflow")
	}
	return left + right, nil
}

func (recorder *campaignProviderUsageRecorder) writeSummaryLocked() error {
	encoded, err := json.Marshal(recorder.summary)
	if err != nil {
		return fmt.Errorf("encode campaign provider usage summary: %w", err)
	}
	if err := fileutil.WriteFileAtomic(recorder.summaryPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write campaign provider usage summary: %w", err)
	}
	if err := validateCampaignProviderUsagePrivateFile(recorder.summaryPath, nil); err != nil {
		return err
	}
	return nil
}

func (recorder *campaignProviderUsageRecorder) snapshotLocked() (campaignProviderUsageAgentSummary, error) {
	if recorder.closed || recorder.journal == nil || recorder.inFlight {
		return campaignProviderUsageAgentSummary{}, errors.New("campaign provider usage recorder is not finalizable")
	}
	if _, err := os.Lstat(recorder.inFlightPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return campaignProviderUsageAgentSummary{}, errors.New(
				"campaign provider usage recorder retains an unresolved call",
			)
		}
		return campaignProviderUsageAgentSummary{}, fmt.Errorf(
			"inspect campaign provider usage in-flight marker before snapshot: %w", err,
		)
	}
	if recorder.summary.UsageCalls > recorder.summary.Calls ||
		recorder.summary.MissingUsageCalls > recorder.summary.Calls-recorder.summary.UsageCalls ||
		recorder.summary.InvalidUsageCalls !=
			recorder.summary.Calls-recorder.summary.UsageCalls-recorder.summary.MissingUsageCalls ||
		recorder.summary.FailedCalls > recorder.summary.Calls ||
		recorder.summary.CampaignRunID != recorder.runID || recorder.summary.Agent != recorder.agent ||
		recorder.summary.AmountStatus != campaignProviderUsageAmountUnknown {
		return campaignProviderUsageAgentSummary{}, errors.New("campaign provider usage summary invariant failed")
	}
	return recorder.summary, nil
}

func (recorder *campaignProviderUsageRecorder) Snapshot() (campaignProviderUsageAgentSummary, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.snapshotLocked()
}

// SealAndSnapshot is the final-report boundary. It takes the same recorder
// lock as BeginCall, rejects unresolved or poisoned accounting, and prevents a
// new Provider call from starting after this Agent's final totals were read.
func (recorder *campaignProviderUsageRecorder) SealAndSnapshot() (campaignProviderUsageAgentSummary, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	summary, err := recorder.snapshotLocked()
	if err != nil {
		return campaignProviderUsageAgentSummary{}, err
	}
	recorder.sealed = true
	return summary, nil
}

func (recorder *campaignProviderUsageRecorder) Close() {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.closed {
		return
	}
	recorder.closed = true
	if recorder.journal != nil {
		_ = recorder.journal.Sync()
		_ = recorder.journal.Close()
		recorder.journal = nil
	}
}

func (provider *campaignProviderUsageProvider) Chat(
	ctx context.Context,
	messages []providers.Message,
	tools []providers.ToolDefinition,
	model string,
	options map[string]any,
) (*providers.LLMResponse, error) {
	if provider == nil || provider.delegate == nil || provider.recorder == nil {
		return nil, errors.New("campaign provider usage wrapper is incomplete")
	}
	provider.callMu.Lock()
	defer provider.callMu.Unlock()
	if err := provider.recorder.BeginCall(); err != nil {
		return nil, err
	}
	response, callErr := provider.delegate.Chat(ctx, messages, tools, model, options)
	if recordErr := provider.recorder.Record(response, callErr); recordErr != nil {
		return response, errors.Join(callErr, fmt.Errorf("persist owner-private provider usage: %w", recordErr))
	}
	return response, callErr
}

func (provider *campaignProviderUsageProvider) GetDefaultModel() string {
	if provider == nil || provider.delegate == nil {
		return ""
	}
	return provider.delegate.GetDefaultModel()
}

func (provider *campaignProviderUsageProvider) Close() {
	if provider == nil {
		return
	}
	provider.close.Do(func() {
		provider.callMu.Lock()
		defer provider.callMu.Unlock()
		if provider.recorder != nil {
			provider.recorder.Close()
		}
		if stateful, ok := provider.delegate.(providers.StatefulProvider); ok {
			stateful.Close()
		}
	})
}

func wrapCampaignProviderUsage(root, runID, agent string, provider providers.LLMProvider) (
	providers.LLMProvider,
	*campaignProviderUsageRecorder,
	error,
) {
	if provider == nil {
		return nil, nil, errors.New("campaign provider usage delegate is nil")
	}
	recorder, err := openCampaignProviderUsageRecorder(root, runID, agent)
	if err != nil {
		return nil, nil, err
	}
	return &campaignProviderUsageProvider{delegate: provider, recorder: recorder}, recorder, nil
}

func writeCampaignProviderUsageSummary(root, runID string, runtimes []*campaignRuntime) (
	*campaignProviderUsageReference,
	error,
) {
	if !filepath.IsAbs(root) || len(runtimes) == 0 || validateCampaignRunID(runID) != nil {
		return nil, errors.New("campaign provider usage aggregate scope is invalid")
	}
	agents := make([]campaignProviderUsageAgentSummary, 0, len(runtimes))
	seen := make(map[string]struct{}, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil || runtime.providerUsage == nil || runtime.definition.Name == "" {
			return nil, errors.New("campaign provider usage runtime is incomplete")
		}
		if _, exists := seen[runtime.definition.Name]; exists {
			return nil, errors.New("campaign provider usage runtime is duplicated")
		}
		seen[runtime.definition.Name] = struct{}{}
		summary, err := runtime.providerUsage.SealAndSnapshot()
		if err != nil {
			return nil, err
		}
		if summary.CampaignRunID != runID || summary.Agent != runtime.definition.Name {
			return nil, errors.New("campaign provider usage runtime identity does not match")
		}
		agents = append(agents, summary)
	}
	sort.Slice(agents, func(left, right int) bool { return agents[left].Agent < agents[right].Agent })
	document := campaignProviderUsageSummary{
		CampaignRunID: runID,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		AmountStatus:  campaignProviderUsageAmountUnknown,
		Agents:        agents,
		Aggregate: campaignProviderUsageAggregate{
			Agents: uint64(len(agents)),
		},
	}
	for _, agent := range agents {
		var err error
		if document.Aggregate.Calls, err = addCampaignProviderUsageCount(document.Aggregate.Calls, agent.Calls); err != nil {
			return nil, err
		}
		if document.Aggregate.UsageCalls, err = addCampaignProviderUsageCount(document.Aggregate.UsageCalls, agent.UsageCalls); err != nil {
			return nil, err
		}
		if document.Aggregate.MissingUsageCalls, err = addCampaignProviderUsageCount(document.Aggregate.MissingUsageCalls, agent.MissingUsageCalls); err != nil {
			return nil, err
		}
		if document.Aggregate.InvalidUsageCalls, err = addCampaignProviderUsageCount(document.Aggregate.InvalidUsageCalls, agent.InvalidUsageCalls); err != nil {
			return nil, err
		}
		if document.Aggregate.FailedCalls, err = addCampaignProviderUsageCount(document.Aggregate.FailedCalls, agent.FailedCalls); err != nil {
			return nil, err
		}
		if document.Aggregate.PromptTokens, err = addCampaignProviderUsageCount(document.Aggregate.PromptTokens, agent.PromptTokens); err != nil {
			return nil, err
		}
		if document.Aggregate.CompletionTokens, err = addCampaignProviderUsageCount(document.Aggregate.CompletionTokens, agent.CompletionTokens); err != nil {
			return nil, err
		}
		if document.Aggregate.TotalTokens, err = addCampaignProviderUsageCount(document.Aggregate.TotalTokens, agent.TotalTokens); err != nil {
			return nil, err
		}
	}
	if document.Aggregate.UsageCalls > document.Aggregate.Calls ||
		document.Aggregate.MissingUsageCalls > document.Aggregate.Calls-document.Aggregate.UsageCalls ||
		document.Aggregate.InvalidUsageCalls !=
			document.Aggregate.Calls-document.Aggregate.UsageCalls-document.Aggregate.MissingUsageCalls ||
		document.Aggregate.FailedCalls > document.Aggregate.Calls {
		return nil, errors.New("campaign provider usage aggregate invariant failed")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode campaign provider usage aggregate: %w", err)
	}
	reportsDirectory := filepath.Join(root, "reports")
	if err := ensureCampaignProviderUsagePrivateDirectory(root, reportsDirectory); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	digestHex := hex.EncodeToString(digest[:])
	filename := strings.TrimSuffix(campaignProviderUsageSummaryFilename, ".json") + "-" + digestHex + ".json"
	relativePath := filepath.ToSlash(filepath.Join("reports", filename))
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := writeCampaignProviderUsageImmutable(path, encoded); err != nil {
		return nil, fmt.Errorf("write campaign provider usage aggregate: %w", err)
	}
	if err := validateCampaignProviderUsagePrivateFile(path, nil); err != nil {
		return nil, err
	}
	return &campaignProviderUsageReference{
		CampaignRunID:       runID,
		SummaryRelativePath: relativePath,
		SummaryDigest:       "sha256:" + digestHex,
		AmountStatus:        campaignProviderUsageAmountUnknown,
		Calls:               document.Aggregate.Calls,
		UsageCalls:          document.Aggregate.UsageCalls,
		MissingUsageCalls:   document.Aggregate.MissingUsageCalls,
		InvalidUsageCalls:   document.Aggregate.InvalidUsageCalls,
		FailedCalls:         document.Aggregate.FailedCalls,
		PromptTokens:        document.Aggregate.PromptTokens,
		CompletionTokens:    document.Aggregate.CompletionTokens,
		TotalTokens:         document.Aggregate.TotalTokens,
	}, nil
}

func writeCampaignProviderUsageImmutable(path string, encoded []byte) error {
	retained, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(retained, encoded) {
			return nil
		}
		return errors.New("content-addressed provider usage summary conflicts with retained bytes")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fileutil.WriteFileAtomic(path, encoded, 0o600)
}

type campaignProviderUsageTestProvider struct {
	mu        sync.Mutex
	responses []*providers.LLMResponse
	errors    []error
	calls     int
	closed    int
}

func (provider *campaignProviderUsageTestProvider) Chat(
	_ context.Context,
	_ []providers.Message,
	_ []providers.ToolDefinition,
	_ string,
	_ map[string]any,
) (*providers.LLMResponse, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	index := provider.calls
	provider.calls++
	var response *providers.LLMResponse
	if index < len(provider.responses) {
		response = provider.responses[index]
	}
	var err error
	if index < len(provider.errors) {
		err = provider.errors[index]
	}
	return response, err
}

func (*campaignProviderUsageTestProvider) GetDefaultModel() string { return "usage-test" }

func (provider *campaignProviderUsageTestProvider) Close() {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.closed++
}

func recordCampaignProviderUsageTestCall(t *testing.T, recorder *campaignProviderUsageRecorder,
	response *providers.LLMResponse, callErr error,
) {
	t.Helper()
	if err := recorder.BeginCall(); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(response, callErr); err != nil {
		t.Fatal(err)
	}
}

func TestCampaignProviderUsageWrapperRecordsMetadataOnlyAndDelegatesClose(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	privateMarker := "PRIVATE-PROMPT-AND-RESPONSE-MARKER"
	delegate := &campaignProviderUsageTestProvider{
		responses: []*providers.LLMResponse{
			{Content: privateMarker, Usage: &providers.UsageInfo{PromptTokens: 10, CompletionTokens: 4, TotalTokens: 14}},
			{Content: privateMarker},
			nil,
			{Content: privateMarker, Usage: &providers.UsageInfo{PromptTokens: -1, CompletionTokens: 2, TotalTokens: 1}},
			{Content: privateMarker, Usage: &providers.UsageInfo{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 1}},
		},
		errors: []error{nil, nil, errors.New(privateMarker), nil},
	}
	const runID = "round4:provider-usage-test-001"
	wrapped, recorder, err := wrapCampaignProviderUsage(root, runID, "agent-a", delegate)
	if err != nil {
		t.Fatal(err)
	}
	for call := 0; call < 5; call++ {
		_, _ = wrapped.Chat(t.Context(), []providers.Message{{Role: "user", Content: privateMarker}}, nil, "model", nil)
	}
	summary, err := recorder.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if summary.CampaignRunID != runID || summary.Calls != 5 || summary.UsageCalls != 1 ||
		summary.MissingUsageCalls != 2 || summary.InvalidUsageCalls != 2 ||
		summary.FailedCalls != 1 || summary.PromptTokens != 10 || summary.CompletionTokens != 4 ||
		summary.TotalTokens != 14 || summary.AmountStatus != campaignProviderUsageAmountUnknown {
		t.Fatalf("unexpected provider usage summary: %+v", summary)
	}
	journal, err := os.ReadFile(recorder.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	storedSummary, err := os.ReadFile(recorder.summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(journal, []byte(privateMarker)) || bytes.Contains(storedSummary, []byte(privateMarker)) {
		t.Fatal("provider usage evidence retained private prompt, response, or error content")
	}
	for _, path := range []string{recorder.journalPath, recorder.summaryPath} {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("provider usage evidence is not owner-private: %s %o", path, info.Mode().Perm())
		}
	}
	stateful, ok := wrapped.(providers.StatefulProvider)
	if !ok {
		t.Fatal("provider usage wrapper did not preserve StatefulProvider cleanup")
	}
	stateful.Close()
	stateful.Close()
	if delegate.closed != 1 {
		t.Fatalf("provider usage wrapper delegated close %d times", delegate.closed)
	}
}

func TestCampaignProviderUsageRecorderRecoversAppendOnlyJournal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const runID = "round4:provider-usage-test-002"
	recorder, err := openCampaignProviderUsageRecorder(root, runID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	recordCampaignProviderUsageTestCall(t, recorder, &providers.LLMResponse{Usage: &providers.UsageInfo{
		PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5,
	}}, nil)
	recorder.Close()
	recovered, err := openCampaignProviderUsageRecorder(root, runID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	recordCampaignProviderUsageTestCall(t, recovered, nil, errors.New("provider unavailable"))
	summary, err := recovered.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if summary.Calls != 2 || summary.UsageCalls != 1 || summary.MissingUsageCalls != 1 || summary.InvalidUsageCalls != 0 ||
		summary.FailedCalls != 1 || summary.TotalTokens != 5 {
		t.Fatalf("journal recovery lost provider usage: %+v", summary)
	}
	data, err := os.ReadFile(recovered.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for expected := uint64(1); expected <= 2; expected++ {
		var call campaignProviderUsageCall
		if err := decoder.Decode(&call); err != nil {
			t.Fatal(err)
		}
		if call.CampaignRunID != runID || call.CallIndex != expected {
			t.Fatalf("recovered journal call index=%d, want %d", call.CallIndex, expected)
		}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("recovered journal has unexpected trailing data: %v", err)
	}
}

func TestCampaignProviderUsageSummaryIsPerAgentAndUnpriced(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimes := make([]*campaignRuntime, 0, 2)
	const runID = "round4:provider-usage-test-003"
	for index, name := range []string{"seller", "buyer"} {
		recorder, err := openCampaignProviderUsageRecorder(root, runID, name)
		if err != nil {
			t.Fatal(err)
		}
		defer recorder.Close()
		recordCampaignProviderUsageTestCall(t, recorder, &providers.LLMResponse{Usage: &providers.UsageInfo{
			PromptTokens: index + 1, CompletionTokens: index + 2, TotalTokens: index*2 + 3,
		}}, nil)
		runtimes = append(runtimes, &campaignRuntime{
			definition: eightAgentManifestEntry{Name: name}, providerUsage: recorder,
		})
	}
	reference, err := writeCampaignProviderUsageSummary(root, runID, runtimes)
	if err != nil {
		t.Fatal(err)
	}
	if reference.CampaignRunID != runID || reference.AmountStatus != campaignProviderUsageAmountUnknown || reference.Calls != 2 ||
		reference.UsageCalls != 2 || reference.MissingUsageCalls != 0 || reference.InvalidUsageCalls != 0 ||
		reference.FailedCalls != 0 ||
		reference.PromptTokens != 3 || reference.CompletionTokens != 5 || reference.TotalTokens != 8 {
		t.Fatalf("unexpected provider usage reference: %+v", reference)
	}
	if filepath.IsAbs(reference.SummaryRelativePath) || !strings.HasPrefix(reference.SummaryDigest, "sha256:") {
		t.Fatalf("provider usage reference escaped campaign root: %+v", reference)
	}
	path := filepath.Join(root, filepath.FromSlash(reference.SummaryRelativePath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"amount_atomic", "estimated_cost", "price", "messages", "response", "content"} {
		if bytes.Contains(bytes.ToLower(data), []byte(forbidden)) {
			t.Fatalf("provider usage summary contains forbidden field %q: %s", forbidden, data)
		}
	}
	digest := sha256.Sum256(data)
	if reference.SummaryDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("provider usage summary digest does not match the persisted bytes")
	}
	var summary campaignProviderUsageSummary
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if err := requireCampaignJSONEOF(decoder); err != nil {
		t.Fatal(err)
	}
	if summary.CampaignRunID != runID || len(summary.Agents) != 2 || summary.Agents[0].Agent != "buyer" || summary.Agents[1].Agent != "seller" ||
		summary.AmountStatus != campaignProviderUsageAmountUnknown {
		t.Fatalf("provider usage summary is not stable per-agent evidence: %+v", summary)
	}
	if err := runtimes[0].providerUsage.BeginCall(); err == nil {
		t.Fatal("final provider aggregate did not seal its source recorder")
	}
	for index, runtime := range runtimes {
		runtime.providerUsage.Close()
		recovered, recoverErr := openCampaignProviderUsageRecorder(root, runID, runtime.definition.Name)
		if recoverErr != nil {
			t.Fatal(recoverErr)
		}
		defer recovered.Close()
		runtimes[index].providerUsage = recovered
	}
	recordCampaignProviderUsageTestCall(t, runtimes[0].providerUsage, nil, nil)
	nextReference, err := writeCampaignProviderUsageSummary(root, runID, runtimes)
	if err != nil {
		t.Fatal(err)
	}
	if nextReference.SummaryRelativePath == reference.SummaryRelativePath ||
		nextReference.SummaryDigest == reference.SummaryDigest {
		t.Fatal("changed provider usage aggregate reused a published content identity")
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, data) {
		t.Fatalf("refinalization replaced a previously referenced provider summary: err=%v", err)
	}
}

func TestCampaignProviderUsageRecorderRejectsDifferentRunJournal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	recorder, err := openCampaignProviderUsageRecorder(root, "round4:provider-usage-old", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	recordCampaignProviderUsageTestCall(t, recorder, nil, nil)
	recorder.Close()
	if _, err := openCampaignProviderUsageRecorder(root, "round4:provider-usage-new", "agent-a"); err == nil {
		t.Fatal("provider usage recovery accepted a journal from a different campaign run")
	}
}

func TestCampaignProviderUsageRecorderRequiresExactBooleanAndFieldNames(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "missing-failed", mutate: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`,"failed":false`), nil, 1)
		}},
		{name: "case-alias", mutate: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"agent":"agent-a"`),
				[]byte(`"Agent":"agent-a","agent":"agent-a"`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			const runID = "round4:provider-shape-test"
			recorder, err := openCampaignProviderUsageRecorder(root, runID, "agent-a")
			if err != nil {
				t.Fatal(err)
			}
			recordCampaignProviderUsageTestCall(t, recorder, nil, nil)
			recorder.Close()
			raw, err := os.ReadFile(recorder.journalPath)
			if err != nil {
				t.Fatal(err)
			}
			mutated := test.mutate(raw)
			if bytes.Equal(mutated, raw) {
				t.Fatal("provider usage test did not mutate the journal")
			}
			if err := fileutil.WriteFileAtomic(recorder.journalPath, mutated, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := openCampaignProviderUsageRecorder(root, runID, "agent-a"); err == nil {
				t.Fatal("provider usage recovery accepted a non-canonical or incomplete record")
			}
		})
	}
}

func TestCampaignProviderUsageRecorderRejectsImpossibleObservedUsageOnRecovery(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "zero-total", mutate: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`,"total_tokens":5`), nil, 1)
		}},
		{name: "components-exceed-total", mutate: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"total_tokens":5`), []byte(`"total_tokens":1`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			const runID = "round4:provider-observed-recovery-test"
			recorder, err := openCampaignProviderUsageRecorder(root, runID, "agent-a")
			if err != nil {
				t.Fatal(err)
			}
			recordCampaignProviderUsageTestCall(t, recorder, &providers.LLMResponse{Usage: &providers.UsageInfo{
				PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5,
			}}, nil)
			recorder.Close()
			raw, err := os.ReadFile(recorder.journalPath)
			if err != nil {
				t.Fatal(err)
			}
			mutated := test.mutate(raw)
			if bytes.Equal(mutated, raw) {
				t.Fatal("provider usage test did not mutate observed usage")
			}
			if err := fileutil.WriteFileAtomic(recorder.journalPath, mutated, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := openCampaignProviderUsageRecorder(root, runID, "agent-a"); err == nil {
				t.Fatal("provider usage recovery accepted impossible observed token arithmetic")
			}
		})
	}
}

func TestCampaignProviderUsageRecoveryReconcilesCompletedInFlightMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const runID = "round4:provider-completed-marker-test"
	recorder, err := openCampaignProviderUsageRecorder(root, runID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	recordCampaignProviderUsageTestCall(t, recorder, nil, nil)
	marker := campaignProviderUsageInFlightCall{
		CampaignRunID: runID,
		Agent:         "agent-a",
		CallIndex:     1,
		StartedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileutil.WriteFileAtomic(recorder.inFlightPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	recorder.Close()
	recovered, err := openCampaignProviderUsageRecorder(root, runID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err := os.Lstat(recovered.inFlightPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconciled provider in-flight marker was not removed: %v", err)
	}
	summary, err := recovered.Snapshot()
	if err != nil || summary.Calls != 1 || summary.MissingUsageCalls != 1 {
		t.Fatalf("completed provider call was not recovered exactly once: summary=%+v err=%v", summary, err)
	}
}

func TestCampaignProviderUsagePoisonStopsAnotherProviderCall(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	delegate := &campaignProviderUsageTestProvider{responses: []*providers.LLMResponse{{
		Usage: &providers.UsageInfo{PromptTokens: 2, CompletionTokens: 1, TotalTokens: 3},
	}}}
	wrapped, recorder, err := wrapCampaignProviderUsage(root, "round4:provider-poison-test", "agent-a", delegate)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.(providers.StatefulProvider).Close()
	if err := recorder.journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.Chat(t.Context(), nil, nil, "model", nil); err == nil {
		t.Fatal("uncertain provider usage append did not fail")
	}
	if delegate.calls != 1 {
		t.Fatalf("initial provider call count=%d, want 1", delegate.calls)
	}
	if _, err := wrapped.Chat(t.Context(), nil, nil, "model", nil); err == nil {
		t.Fatal("poisoned provider usage recorder accepted another call")
	}
	if delegate.calls != 1 {
		t.Fatalf("poisoned recorder permitted another real provider call: %d", delegate.calls)
	}
	if _, err := recorder.Snapshot(); err == nil {
		t.Fatal("poisoned provider usage recorder produced a finalizable snapshot")
	}
	info, err := os.Lstat(recorder.inFlightPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("failed provider accounting did not retain a private durable marker: info=%v err=%v", info, err)
	}
	if _, err := openCampaignProviderUsageRecorder(root, "round4:provider-poison-test", "agent-a"); err == nil {
		t.Fatal("provider usage recovery silently omitted an already executed call")
	}
}
