package servicebridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AdmissionPauseFile is the owner-only marker in state_dir that stops the
// provider from admitting new requests. Work already admitted is unaffected:
// it executes, responds and delivers, or falls to the buyer's refund path.
const AdmissionPauseFile = "admission-paused"

const admissionPauseSchema = "tos.openfox.rail-admission-pause.v1"

// maxPauseReason bounds the operator's note so the marker stays small.
const maxPauseReason = 256

// ErrAdmissionPaused reports that a task was not admitted because the owner
// paused admission. The task message is kept pending, not counted as a
// failed handling, so it is admitted after a resume if the request is still
// admissible then.
var ErrAdmissionPaused = errors.New("servicebridge: new admissions are paused by the owner")

// AdmissionPause is the content of the pause marker.
type AdmissionPause struct {
	Schema     string `json:"schema"`
	PausedUnix int64  `json:"paused_unix"`
	Reason     string `json:"reason,omitempty"`
}

func pausePath(stateDir string) (string, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return "", errors.New("servicebridge: state_dir must be clean and absolute")
	}
	return filepath.Join(stateDir, AdmissionPauseFile), nil
}

// ReadAdmissionPause reports whether admission is paused. A marker that
// exists but cannot be read or decoded is an error; callers that decide
// admission treat that error as paused.
func ReadAdmissionPause(stateDir string) (*AdmissionPause, error) {
	path, err := pausePath(stateDir)
	if err != nil {
		return nil, err
	}
	var pause AdmissionPause
	if err := readJSON(path, 4<<10, &pause); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("servicebridge: the admission pause marker is unreadable: %w", err)
	}
	if pause.Schema != admissionPauseSchema || pause.PausedUnix <= 0 || len(pause.Reason) > maxPauseReason {
		return nil, errors.New("servicebridge: the admission pause marker is invalid")
	}
	return &pause, nil
}

// PauseAdmission durably writes the pause marker. It refuses to replace an
// existing marker, so the first pause time is kept; already reports that
// admission was paused before this call.
func PauseAdmission(stateDir, reason string, now time.Time) (pause *AdmissionPause, already bool, err error) {
	if len(reason) > maxPauseReason || strings.ContainsAny(reason, "\x00\n\r") {
		return nil, false, errors.New("servicebridge: the pause reason must be one line of at most 256 bytes")
	}
	path, err := pausePath(stateDir)
	if err != nil {
		return nil, false, err
	}
	if dirErr := checkPrivateDirectory(stateDir); dirErr != nil {
		return nil, false, dirErr
	}
	if existing, readErr := ReadAdmissionPause(stateDir); readErr != nil {
		return nil, false, readErr
	} else if existing != nil {
		return existing, true, nil
	}
	pause = &AdmissionPause{Schema: admissionPauseSchema, PausedUnix: now.Unix(), Reason: reason}
	if pause.PausedUnix <= 0 {
		return nil, false, errors.New("servicebridge: the clock is before the epoch")
	}
	data, err := json.Marshal(pause)
	if err != nil {
		return nil, false, errors.New("servicebridge: encode the admission pause marker")
	}
	if err := writeSynced(path, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := ReadAdmissionPause(stateDir)
			if readErr != nil {
				return nil, false, readErr
			}
			return existing, true, nil
		}
		return nil, false, err
	}
	return pause, false, nil
}

// ResumeAdmission removes the pause marker durably. wasPaused is false when
// no marker existed.
func ResumeAdmission(stateDir string) (wasPaused bool, err error) {
	path, err := pausePath(stateDir)
	if err != nil {
		return false, err
	}
	if dirErr := checkPrivateDirectory(stateDir); dirErr != nil {
		return false, dirErr
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("servicebridge: stat the admission pause marker")
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("servicebridge: the admission pause marker is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return false, errors.New("servicebridge: remove the admission pause marker")
	}
	return true, syncDirectory(stateDir)
}
