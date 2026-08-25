package earning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// DirectoryPublicationSink is the independently implemented local Carrier
// path. Its admission profile is owner-private filesystem custody plus the same
// proof-carrying AuthorizedAction used by remote Carriers.
type DirectoryPublicationSink struct {
	mu        sync.Mutex
	carrierID string
	directory string
	authority EconomicAuthority
	lock      *os.File
}

func OpenDirectoryPublicationSink(directory, carrierID string, authority EconomicAuthority) (*DirectoryPublicationSink, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || carrierID == "" || authority == nil {
		return nil, errors.New("directory publication configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("directory publication root is not owner-private")
	}
	lock, err := acquireAuthorityLock(directory)
	if err != nil {
		return nil, err
	}
	return &DirectoryPublicationSink{carrierID: carrierID, directory: directory, authority: authority, lock: lock}, nil
}

func (sink *DirectoryPublicationSink) Close() error {
	if sink == nil || sink.lock == nil {
		return nil
	}
	err := releaseAuthorityLock(sink.lock)
	sink.lock = nil
	return err
}

func (sink *DirectoryPublicationSink) PublishIntent(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, canonical []byte,
	intent commerce.SignedAgentIntent) (commerce.ActionResolution, error) {
	if sink == nil || sink.lock == nil || ctx == nil || ctx.Err() != nil || action.ActionKind != "publication.publish" ||
		action.AgentID != intent.Body.IssuerAgentID {
		return commerce.ActionResolution{}, errors.New("directory publication request is invalid")
	}
	encoded, err := codec.Marshal(intent)
	now := sink.authority.AuthorityNow()
	if err != nil || !bytes.Equal(encoded, canonical) || commerce.VerifyAuthorizedAction(action, fields, canonical, fence, sink.authority, now) != nil ||
		sink.authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return commerce.ActionResolution{}, errors.New("directory publication action is not current and exact")
	}
	digest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := json.Marshal(intent)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return commerce.ActionResolution{}, errors.New("directory publication object is invalid or oversized")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if existing, readErr := sink.resolveLocked(action.StableActionID, action.ExactRequestDigest); readErr == nil && existing.State != commerce.ActionUnknown {
		return existing, nil
	}
	path := filepath.Join(sink.directory, strings.TrimPrefix(digest, "sha256:")+".json")
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, raw) {
			return commerce.ActionResolution{}, errors.New("directory Intent digest conflicts with stored bytes")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return commerce.ActionResolution{}, readErr
	} else if err := writeOwnerExclusive(path, raw); err != nil {
		return commerce.ActionResolution{}, err
	}
	if err := sink.ensureIndexLocked(digest); err != nil {
		return commerce.ActionResolution{}, err
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, SinkReference: digest, EvidenceRefs: []string{digest}, StateRevision: 1}
	resolutionRaw, _ := json.Marshal(resolution)
	if err := writeOwnerExclusive(sink.actionPath(action.StableActionID), resolutionRaw); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return commerce.ActionResolution{}, err
		}
		return sink.resolveLocked(action.StableActionID, action.ExactRequestDigest)
	}
	return resolution, nil
}

func (sink *DirectoryPublicationSink) WithdrawIntent(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, fields map[string]commerce.SemanticValue, canonical []byte,
	withdrawal commerce.SignedAgentIntentWithdrawal) (commerce.ActionResolution, error) {
	if sink == nil || sink.lock == nil || ctx == nil || ctx.Err() != nil || action.ActionKind != "publication.withdraw" ||
		action.AgentID != withdrawal.Body.IssuerAgentID {
		return commerce.ActionResolution{}, errors.New("directory withdrawal request is invalid")
	}
	encoded, err := codec.Marshal(withdrawal)
	now := sink.authority.AuthorityNow()
	if err != nil || !bytes.Equal(encoded, canonical) || commerce.VerifyAuthorizedAction(action, fields, canonical, fence, sink.authority, now) != nil ||
		sink.authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return commerce.ActionResolution{}, errors.New("directory withdrawal action is not current and exact")
	}
	intentPath := filepath.Join(sink.directory, strings.TrimPrefix(withdrawal.Body.IntentDigest, "sha256:")+".json")
	rawIntent, err := os.ReadFile(intentPath)
	if err != nil {
		return commerce.ActionResolution{}, errors.New("directory withdrawal has no retained exact Intent")
	}
	var intent commerce.SignedAgentIntent
	if json.Unmarshal(rawIntent, &intent) != nil || intent.Body.IssuerAgentID != withdrawal.Body.IssuerAgentID ||
		intent.Body.ObjectID != withdrawal.Body.ObjectID || intent.Body.Revision != withdrawal.Body.IntentRevision {
		return commerce.ActionResolution{}, errors.New("directory withdrawal differs from retained Intent")
	}
	raw, err := json.Marshal(withdrawal)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	digest, err := commerce.IntentWithdrawalDigest(withdrawal.Body)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if existing, readErr := sink.resolveLocked(action.StableActionID, action.ExactRequestDigest); readErr == nil && existing.State != commerce.ActionUnknown {
		return existing, nil
	}
	path := filepath.Join(sink.directory, ".withdrawal-"+strings.TrimPrefix(withdrawal.Body.IntentDigest, "sha256:")+".json")
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, raw) {
			return commerce.ActionResolution{}, errors.New("directory Intent has a conflicting withdrawal")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return commerce.ActionResolution{}, readErr
	} else if err := writeOwnerExclusive(path, raw); err != nil {
		return commerce.ActionResolution{}, err
	}
	if err := sink.ensureWithdrawalIndexLocked(withdrawal.Body.IntentDigest); err != nil {
		return commerce.ActionResolution{}, err
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, SinkReference: digest, EvidenceRefs: []string{digest}, StateRevision: 1}
	resolutionRaw, _ := json.Marshal(resolution)
	if err := writeOwnerExclusive(sink.actionPath(action.StableActionID), resolutionRaw); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return commerce.ActionResolution{}, err
		}
		return sink.resolveLocked(action.StableActionID, action.ExactRequestDigest)
	}
	return resolution, nil
}

func (sink *DirectoryPublicationSink) ResolveAction(ctx context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	if sink == nil || sink.lock == nil || ctx == nil || ctx.Err() != nil || !canonicalSHA256(actionID) || !canonicalSHA256(requestDigest) {
		return commerce.ActionResolution{}, errors.New("directory publication action query is invalid")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.resolveLocked(actionID, requestDigest)
}

func (sink *DirectoryPublicationSink) resolveLocked(actionID, requestDigest string) (commerce.ActionResolution, error) {
	raw, err := os.ReadFile(sink.actionPath(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest,
			State: commerce.ActionUnknown, StateRevision: 1}, nil
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var resolution commerce.ActionResolution
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&resolution) != nil || ensureJSONEOF(decoder) != nil || commerce.ValidateActionResolution(resolution) != nil {
		return commerce.ActionResolution{}, errors.New("directory publication action journal is invalid")
	}
	if resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest,
			State: commerce.ActionConflict, StateRevision: resolution.StateRevision + 1}, nil
	}
	return resolution, nil
}

func (sink *DirectoryPublicationSink) actionPath(actionID string) string {
	return filepath.Join(sink.directory, ".action-"+strings.TrimPrefix(actionID, "sha256:")+".json")
}

func (sink *DirectoryPublicationSink) nextSequenceLocked() (uint64, error) {
	path := filepath.Join(sink.directory, ".carrier-sequence")
	raw, err := os.ReadFile(path)
	current := uint64(0)
	if err == nil {
		current, err = strconv.ParseUint(string(raw), 10, 64)
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil || current == ^uint64(0) {
		return 0, errors.New("directory Carrier sequence is invalid or exhausted")
	}
	next := current + 1
	if err := fileutil.WriteFileAtomic(path, []byte(strconv.FormatUint(next, 10)), 0o600); err != nil {
		return 0, err
	}
	return next, nil
}

func (sink *DirectoryPublicationSink) ensureIndexLocked(digest string) error {
	suffix := "-" + strings.TrimPrefix(digest, "sha256:")
	entries, err := os.ReadDir(sink.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), ".cursor-") && strings.HasSuffix(entry.Name(), suffix) {
			return nil
		}
	}
	sequence, err := sink.nextSequenceLocked()
	if err != nil {
		return err
	}
	indexPath := filepath.Join(sink.directory, ".cursor-"+fmt.Sprintf("%020d", sequence)+suffix)
	return writeOwnerExclusive(indexPath, []byte(digest))
}

func (sink *DirectoryPublicationSink) ensureWithdrawalIndexLocked(digest string) error {
	suffix := "-" + strings.TrimPrefix(digest, "sha256:")
	entries, err := os.ReadDir(sink.directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), ".withdrawal-cursor-") && strings.HasSuffix(entry.Name(), suffix) {
			return nil
		}
	}
	sequence, err := sink.nextSequenceLocked()
	if err != nil {
		return err
	}
	path := filepath.Join(sink.directory, ".withdrawal-cursor-"+fmt.Sprintf("%020d", sequence)+suffix)
	return writeOwnerExclusive(path, []byte(digest))
}

func writeOwnerExclusive(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
