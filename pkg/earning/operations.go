package earning

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const operationsSchema = "tos.openfox.earning-operations.v1"

type OperationalMode string

const (
	OperationalRunning  OperationalMode = "running"
	OperationalPaused   OperationalMode = "paused"
	OperationalDraining OperationalMode = "draining"
)

type OperationalScopeState struct {
	Mode          OperationalMode `json:"mode"`
	Revision      uint64          `json:"revision"`
	UpdatedAtUnix uint64          `json:"updated_at_unix"`
	Reason        string          `json:"reason,omitempty"`
}

type OperationalAuditRecord struct {
	Sequence      uint64          `json:"sequence"`
	Actor         string          `json:"actor"`
	Scope         string          `json:"scope"`
	PriorMode     OperationalMode `json:"prior_mode"`
	ResultMode    OperationalMode `json:"result_mode"`
	Reason        string          `json:"reason"`
	AppliedAtUnix uint64          `json:"applied_at_unix"`
}

type operationsDocument struct {
	Schema       string                           `json:"schema"`
	Revision     uint64                           `json:"revision"`
	NextSequence uint64                           `json:"next_sequence"`
	Scopes       map[string]OperationalScopeState `json:"scopes"`
	Audit        []OperationalAuditRecord         `json:"audit"`
}

// OperationalController is the durable, owner-local emergency-stop and drain
// boundary. Its file is deliberately separate from model-visible state. The
// process-wide PersonalAuthority lock makes changes serial with economic
// actions in the personal deployment profile.
type OperationalController struct {
	mu   sync.Mutex
	path string
	doc  operationsDocument
	now  func() time.Time
}

func OpenOperationalController(directory string) (*OperationalController, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("operations directory must be an owner-private directory")
	}
	controller := &OperationalController{path: filepath.Join(directory, "earning-operations.json"), now: time.Now,
		doc: operationsDocument{Schema: operationsSchema, Revision: 1, NextSequence: 1, Scopes: map[string]OperationalScopeState{}}}
	if _, err := os.Lstat(controller.path); errors.Is(err, os.ErrNotExist) {
		if err := controller.persist(controller.doc); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if err := controller.load(); err != nil {
		return nil, err
	}
	return controller, nil
}

func (controller *OperationalController) load() error {
	info, err := os.Lstat(controller.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() > 4<<20 {
		return errors.New("operations journal is not an owner-only bounded regular file")
	}
	raw, err := os.ReadFile(controller.path)
	if err != nil {
		return err
	}
	var document operationsDocument
	if err := json.Unmarshal(raw, &document); err != nil || document.Schema != operationsSchema || document.Revision == 0 || document.NextSequence == 0 || document.Scopes == nil {
		return errors.New("operations journal is invalid")
	}
	for scope, state := range document.Scopes {
		if scope == "" || !validOperationalMode(state.Mode) || state.Revision == 0 || state.UpdatedAtUnix == 0 {
			return errors.New("operations journal has an invalid scope")
		}
	}
	controller.doc = document
	return nil
}

func validOperationalMode(mode OperationalMode) bool {
	return mode == OperationalRunning || mode == OperationalPaused || mode == OperationalDraining
}

func (controller *OperationalController) persist(document operationsDocument) error {
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(controller.path, append(raw, '\n'), 0o600)
}

// SetMode is an authenticated local operator mutation: the caller identity is
// supplied by the owner-only control socket/CLI and retained in the audit log.
func (controller *OperationalController) SetMode(actor, scope string, mode OperationalMode, reason string) (OperationalAuditRecord, error) {
	if controller == nil || actor == "" || !validOperationalScope(scope) || !validOperationalMode(mode) || reason == "" || len(reason) > 1024 {
		return OperationalAuditRecord{}, errors.New("operational mutation is incomplete")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	lock, err := acquireAuthorityLock(filepath.Dir(controller.path))
	if err != nil {
		return OperationalAuditRecord{}, err
	}
	defer releaseAuthorityLock(lock)
	if err := controller.load(); err != nil {
		return OperationalAuditRecord{}, err
	}
	now := controller.now().UTC()
	prior := controller.doc.Scopes[scope]
	if prior.Mode == "" {
		prior.Mode = OperationalRunning
	}
	record := OperationalAuditRecord{Sequence: controller.doc.NextSequence, Actor: actor, Scope: scope,
		PriorMode: prior.Mode, ResultMode: mode, Reason: reason, AppliedAtUnix: uint64(now.Unix())}
	next := controller.doc
	next.Scopes = cloneScopeStates(controller.doc.Scopes)
	next.Audit = append(append([]OperationalAuditRecord(nil), controller.doc.Audit...), record)
	if len(next.Audit) > 4096 {
		next.Audit = append([]OperationalAuditRecord(nil), next.Audit[len(next.Audit)-4096:]...)
	}
	next.Revision++
	next.NextSequence++
	next.Scopes[scope] = OperationalScopeState{Mode: mode, Revision: next.Revision, UpdatedAtUnix: uint64(now.Unix()), Reason: reason}
	if err := controller.persist(next); err != nil {
		return OperationalAuditRecord{}, err
	}
	controller.doc = next
	return record, nil
}

func validOperationalScope(scope string) bool {
	if scope == "*" {
		return true
	}
	if len(scope) == 0 || len(scope) > 128 || scope[0] < 'a' || scope[0] > 'z' {
		return false
	}
	for _, character := range scope[1:] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '.' && character != '-' && character != '_' {
					return false
				}
			}
		}
	}
	return true
}

func cloneScopeStates(input map[string]OperationalScopeState) map[string]OperationalScopeState {
	result := make(map[string]OperationalScopeState, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func (controller *OperationalController) Snapshot() (uint64, []OperationalScopeStateView, []OperationalAuditRecord) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	_ = controller.load()
	states := make([]OperationalScopeStateView, 0, len(controller.doc.Scopes))
	for scope, state := range controller.doc.Scopes {
		states = append(states, OperationalScopeStateView{Scope: scope, State: state})
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Scope < states[j].Scope })
	return controller.doc.Revision, states, append([]OperationalAuditRecord(nil), controller.doc.Audit...)
}

type OperationalScopeStateView struct {
	Scope string                `json:"scope"`
	State OperationalScopeState `json:"state"`
}

// Permits blocks every effect while paused. Drain permits effects needed to
// finish accepted obligations, but rejects effects that create new exposure.
func (controller *OperationalController) Permits(scope string, createsCommitment bool) bool {
	if controller == nil {
		return true
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.load() != nil {
		return false
	}
	state, found := controller.doc.Scopes[scope]
	if !found {
		state = controller.doc.Scopes["*"]
	}
	switch state.Mode {
	case OperationalPaused:
		return false
	case OperationalDraining:
		return !createsCommitment
	default:
		return true
	}
}
