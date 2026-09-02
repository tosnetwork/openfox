package earning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	campaignRunIDMarkerFilename = "campaign-run-id.txt"
	campaignRunLockFilename     = "campaign-run.lock"
)

func validateCampaignRunID(runID string) error {
	if len(runID) < 8 || len(runID) > 128 || strings.TrimSpace(runID) != runID {
		return errors.New("campaign run ID must contain 8 through 128 unpadded ASCII characters")
	}
	isAlphaNumeric := func(value byte) bool {
		return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
	}
	if !isAlphaNumeric(runID[0]) || !isAlphaNumeric(runID[len(runID)-1]) {
		return errors.New("campaign run ID must start and end with an ASCII letter or digit")
	}
	for index := 0; index < len(runID); index++ {
		value := runID[index]
		if isAlphaNumeric(value) || value == '.' || value == '_' || value == ':' || value == '-' {
			continue
		}
		return errors.New("campaign run ID contains a character outside [A-Za-z0-9._:-]")
	}
	return nil
}

// ensureCampaignRunScope establishes a fail-closed, owner-private nonce at the
// campaign root. All Round 4 recovery happens only after this marker has been
// checked, so a copied checkpoint or journal cannot silently become this run.
func ensureCampaignRunScope(root, runID string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("campaign run root must be a clean absolute path")
	}
	if err := validateCampaignRunID(runID); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect campaign run root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("campaign run root is not an owner-private directory")
	}
	markerPath := filepath.Join(root, campaignRunIDMarkerFilename)
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, err = marker.WriteString(runID + "\n"); err == nil {
			err = marker.Sync()
		}
		if closeErr := marker.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("write campaign run marker: %w", err)
		}
		rootDirectory, openErr := os.Open(root)
		if openErr != nil {
			return fmt.Errorf("open campaign run root for sync: %w", openErr)
		}
		syncErr := rootDirectory.Sync()
		closeErr := rootDirectory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync campaign run root: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close campaign run root: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create campaign run marker: %w", err)
	}
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		return fmt.Errorf("inspect campaign run marker: %w", err)
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.Mode().Perm() != 0o600 ||
		markerInfo.Size() < 2 || markerInfo.Size() > 129 {
		return errors.New("campaign run marker is not exact owner-private regular data")
	}
	stored, err := os.ReadFile(markerPath)
	if err != nil {
		return fmt.Errorf("read campaign run marker: %w", err)
	}
	if string(stored) != runID+"\n" {
		return errors.New("campaign run marker belongs to a different run")
	}
	return nil
}

func acquireCampaignRunLock(root, runID string) (*os.File, error) {
	if err := validateCampaignRunID(runID); err != nil {
		return nil, err
	}
	path := filepath.Join(root, campaignRunLockFilename)
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open campaign run lock: %w", err)
	}
	fail := func(cause error) (*os.File, error) {
		_ = lock.Close()
		return nil, cause
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fail(fmt.Errorf("inspect campaign run lock: %w", err))
	}
	openedInfo, err := lock.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect open campaign run lock: %w", err))
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!os.SameFile(info, openedInfo) {
		return fail(errors.New("campaign run lock is not exact owner-private regular data"))
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(errors.New("another process already owns this campaign run"))
	}
	if err := lock.Truncate(0); err != nil {
		return fail(fmt.Errorf("truncate campaign run lock: %w", err))
	}
	if _, err := lock.Seek(0, 0); err != nil {
		return fail(fmt.Errorf("rewind campaign run lock: %w", err))
	}
	if _, err := lock.WriteString(runID + "\n"); err != nil {
		return fail(fmt.Errorf("write campaign run lock: %w", err))
	}
	if err := lock.Sync(); err != nil {
		return fail(fmt.Errorf("sync campaign run lock: %w", err))
	}
	return lock, nil
}

func validateCampaignCheckpointRunScope(report eightAgentCampaignReport, expectedRunID string) error {
	if expectedRunID != "" {
		if err := validateCampaignRunID(expectedRunID); err != nil {
			return err
		}
	}
	if report.CampaignRunID != expectedRunID {
		return errors.New("campaign checkpoint belongs to a different run")
	}
	for _, result := range report.Results {
		if result.CampaignRunID != expectedRunID {
			return fmt.Errorf("campaign checkpoint result %d belongs to a different run", result.Sequence)
		}
	}
	if report.ProviderUsage != nil && report.ProviderUsage.CampaignRunID != expectedRunID {
		return errors.New("campaign checkpoint provider usage belongs to a different run")
	}
	if report.ValidatorDelegation != nil && report.ValidatorDelegation.CampaignRunID != expectedRunID {
		return errors.New("campaign checkpoint delegation evidence belongs to a different run")
	}
	return nil
}

func TestEnsureCampaignRunScopeCreatesAndRejectsMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const runID = "round4:test-nonce-001"
	if err := ensureCampaignRunScope(root, runID); err != nil {
		t.Fatal(err)
	}
	if err := ensureCampaignRunScope(root, runID); err != nil {
		t.Fatalf("same run marker was not idempotent: %v", err)
	}
	if err := ensureCampaignRunScope(root, "round4:test-nonce-002"); err == nil {
		t.Fatal("different run ID reused an existing campaign root")
	}
	marker := filepath.Join(root, campaignRunIDMarkerFilename)
	info, err := os.Lstat(marker)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("campaign marker is not exact mode 0600 regular data: info=%v err=%v", info, err)
	}
}

func TestValidateCampaignRunIDRejectsUnsafeValues(t *testing.T) {
	for _, value := range []string{"short", ":round4bad", "round4bad:", "round4/escape", "round4 newline\n"} {
		if validateCampaignRunID(value) == nil {
			t.Fatalf("unsafe campaign run ID was accepted: %q", value)
		}
	}
}

func TestValidateCampaignCheckpointRunScopeRejectsNestedMismatch(t *testing.T) {
	const runID = "round4:checkpoint-scope-test"
	report := eightAgentCampaignReport{
		CampaignRunID: runID,
		Results:       []eightAgentJobResult{{CampaignRunID: runID}},
		ProviderUsage: &campaignProviderUsageReference{CampaignRunID: runID},
		ValidatorDelegation: &campaignValidatorDelegation{
			CampaignRunID: runID,
		},
	}
	if err := validateCampaignCheckpointRunScope(report, runID); err != nil {
		t.Fatal(err)
	}
	report.Results[0].CampaignRunID = "round4:stale-checkpoint-result"
	if err := validateCampaignCheckpointRunScope(report, runID); err == nil {
		t.Fatal("checkpoint accepted a nested result from a different run")
	}
}

func TestAcquireCampaignRunLockRejectsConcurrentSameNonce(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const runID = "round4:single-writer-test"
	if err := ensureCampaignRunScope(root, runID); err != nil {
		t.Fatal(err)
	}
	first, err := acquireCampaignRunLock(root, runID)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireCampaignRunLock(root, runID); err == nil {
		_ = second.Close()
		_ = first.Close()
		t.Fatal("a second process handle acquired the same campaign run lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := acquireCampaignRunLock(root, runID)
	if err != nil {
		t.Fatalf("released campaign run could not be recovered: %v", err)
	}
	_ = restarted.Close()
}
