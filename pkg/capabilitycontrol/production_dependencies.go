package capabilitycontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type fileMonotonicEntry struct {
	Revision   uint64 `json:"revision"`
	Commitment []byte `json:"commitment"`
}

type FileMonotonicAuthority struct {
	root  string
	mu    sync.Mutex
	lock  *stateLock
	state map[string]fileMonotonicEntry
}

// OpenFileMonotonicAuthority opens a separately administered high-water
// directory. Deployments requiring VM-snapshot resistance must place this
// directory on hardware/remote monotonic storage; it must never be inside the
// capability projection or workspace directory.
func OpenFileMonotonicAuthority(root, forbiddenProjectionRoot string) (*FileMonotonicAuthority, error) {
	if root == "" || forbiddenProjectionRoot == "" {
		return nil, errors.New("separate monotonic authority and projection roots are required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	projection, err := filepath.Abs(forbiddenProjectionRoot)
	if err != nil {
		return nil, err
	}
	if absolute == projection || isWithin(absolute, projection) || isWithin(projection, absolute) {
		return nil, errors.New("monotonic authority must be outside the capability projection tree")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	lock, err := acquireStateLock(filepath.Join(absolute, ".monotonic-writer.lock"))
	if err != nil {
		return nil, err
	}
	authority := &FileMonotonicAuthority{root: absolute, lock: lock, state: map[string]fileMonotonicEntry{}}
	raw, err := os.ReadFile(filepath.Join(absolute, "high-waters.json"))
	if err == nil {
		if json.Unmarshal(raw, &authority.state) != nil || authority.state == nil {
			_ = lock.close()
			return nil, errors.New("monotonic authority state is corrupt")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = lock.close()
		return nil, err
	}
	return authority, nil
}

func (authority *FileMonotonicAuthority) Close() error {
	if authority == nil || authority.lock == nil {
		return nil
	}
	return authority.lock.close()
}

func (authority *FileMonotonicAuthority) ResolveInstallationID(_ context.Context, domainKind trusted.DomainKind, domainID, ownerID, agentID []byte) ([]byte, error) {
	if authority == nil || authority.root == "" || len(domainID) == 0 || len(ownerID) == 0 || len(agentID) == 0 {
		return nil, errors.New("installation identity authority is unavailable")
	}
	digest := sha256.Sum256(bytes.Join([][]byte{[]byte("tos.file-installation-identity.v1"), []byte(authority.root), []byte{byte(domainKind)}, domainID, ownerID, agentID}, []byte{0}))
	return append([]byte(nil), digest[:16]...), nil
}

func (authority *FileMonotonicAuthority) Read(_ context.Context, scope []byte) (uint64, []byte, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	entry := authority.state[hex.EncodeToString(scope)]
	return entry.Revision, append([]byte(nil), entry.Commitment...), nil
}

func (authority *FileMonotonicAuthority) Check(_ context.Context, scope []byte, revision uint64, commitment []byte) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	key := hex.EncodeToString(scope)
	entry, ok := authority.state[key]
	if !ok && revision == 0 {
		authority.state[key] = fileMonotonicEntry{Revision: revision, Commitment: append([]byte(nil), commitment...)}
		return authority.persistLocked()
	}
	if !ok || entry.Revision != revision || !bytes.Equal(entry.Commitment, commitment) {
		return errors.New("rollback-resistant authority high-water mismatch")
	}
	return nil
}

func (authority *FileMonotonicAuthority) CompareAndAdvance(_ context.Context, scope []byte, prior, next uint64, commitment []byte) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	key := hex.EncodeToString(scope)
	entry, ok := authority.state[key]
	if !ok || entry.Revision != prior || next != prior+1 || len(commitment) != sha256.Size {
		return errors.New("monotonic authority compare-and-advance conflict")
	}
	authority.state[key] = fileMonotonicEntry{Revision: next, Commitment: append([]byte(nil), commitment...)}
	if err := authority.persistLocked(); err != nil {
		authority.state[key] = entry
		return err
	}
	return nil
}

func (authority *FileMonotonicAuthority) CompareAndAdvanceCapabilityControl(_ context.Context, scope []byte, prior, next uint64, commitment, ownerID, agentID []byte, accepting bool) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	key := hex.EncodeToString(scope)
	entry, ok := authority.state[key]
	if !ok || entry.Revision != prior || next != prior+1 || len(commitment) != sha256.Size || len(ownerID) == 0 || len(agentID) == 0 {
		return errors.New("atomic capability-control compare-and-advance conflict")
	}
	fenceKey := "capability-acquisition:" + hex.EncodeToString(capabilityAcquisitionScope(ownerID, agentID))
	priorFence, hadFence := authority.state[fenceKey]
	state := byte(0)
	if accepting {
		state = 1
	}
	fenceCommitment := sha256.Sum256(bytes.Join([][]byte{[]byte("tos.capability-acquisition-state.v1"), scope, commitment, []byte{state}}, []byte{0}))
	authority.state[key] = fileMonotonicEntry{Revision: next, Commitment: append([]byte(nil), commitment...)}
	authority.state[fenceKey] = fileMonotonicEntry{Revision: next, Commitment: fenceCommitment[:]}
	if err := authority.persistLocked(); err != nil {
		authority.state[key] = entry
		if hadFence {
			authority.state[fenceKey] = priorFence
		} else {
			delete(authority.state, fenceKey)
		}
		return err
	}
	return nil
}

func (authority *FileMonotonicAuthority) persistLocked() error {
	raw, err := json.MarshalIndent(authority.state, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(filepath.Join(authority.root, "high-waters.json"), append(raw, '\n'), 0o600)
}

type SystemHighWaterClock struct{}

func (SystemHighWaterClock) Now(context.Context) (time.Time, error) { return time.Now().UTC(), nil }

type DirectoryPublisherAuthorityVerifier struct{ Directory string }

func (verifier DirectoryPublisherAuthorityVerifier) RequiredPublisherSources(_ context.Context, policyDigest []byte) ([][]byte, error) {
	if !filepath.IsAbs(verifier.Directory) || len(policyDigest) != sha256.Size {
		return nil, errors.New("publisher source registry is unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(verifier.Directory, hex.EncodeToString(policyDigest)+".sources.json"))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("policy-bound publisher source registry is unavailable or unbounded")
	}
	commitment := sha256.Sum256(raw)
	if !bytes.Equal(commitment[:], policyDigest) {
		return nil, errors.New("publisher source registry does not match the active capability policy commitment")
	}
	var encoded []string
	if json.Unmarshal(raw, &encoded) != nil || len(encoded) == 0 || len(encoded) > 32 {
		return nil, errors.New("policy-bound publisher source registry is invalid")
	}
	result := make([][]byte, 0, len(encoded))
	for _, value := range encoded {
		source, decodeErr := decodeHexExact(value, sha256.Size)
		if decodeErr != nil {
			return nil, errors.New("policy-bound publisher source identity is invalid")
		}
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i], result[j]) < 0 })
	for i := 1; i < len(result); i++ {
		if bytes.Equal(result[i-1], result[i]) {
			return nil, errors.New("policy-bound publisher source registry contains duplicates")
		}
	}
	return result, nil
}

func (verifier DirectoryPublisherAuthorityVerifier) CurrentPublisherObservations(_ context.Context, artifact trusted.ProfileObjectV1, _ trusted.ProfileAuthorizationEnvelopeV1, _ trusted.ProfileObjectV1, _ uint64) ([]PublisherObservation, error) {
	if !filepath.IsAbs(verifier.Directory) {
		return nil, errors.New("publisher observation directory is unavailable")
	}
	digest, err := trusted.ObjectDigest(artifact)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(verifier.Directory, hex.EncodeToString(digest)+".json"))
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("publisher observation bundle is unavailable or unbounded")
	}
	var observations []PublisherObservation
	if json.Unmarshal(raw, &observations) != nil || len(observations) == 0 || len(observations) > 32 {
		return nil, errors.New("publisher observation bundle is invalid")
	}
	// Canonical ordering makes duplicate/equivocating bundles deterministic.
	sort.Slice(observations, func(i, j int) bool {
		left, _ := trusted.ObjectDigest(observations[i].Object)
		right, _ := trusted.ObjectDigest(observations[j].Object)
		return bytes.Compare(left, right) < 0
	})
	return observations, nil
}

type ProductionStoreOptions struct {
	ProjectionRoot, PublisherObservationDirectory string
	DomainKind                                    trusted.DomainKind
	DomainID, OwnerID, AgentID                    []byte
	Authority                                     ProductionAuthority
}

func OpenProduction(options ProductionStoreOptions) (*Store, ProductionAuthority, error) {
	if options.Authority == nil {
		return nil, nil, errors.New("production capability control requires an external monotonic and trusted-time authority")
	}
	authority := options.Authority
	store, err := OpenProductionInDomain(options.ProjectionRoot, options.DomainKind, options.DomainID, options.OwnerID, options.AgentID, authority,
		authority, authority, DirectoryPublisherAuthorityVerifier{options.PublisherObservationDirectory})
	if err != nil {
		_ = authority.Close()
		return nil, nil, err
	}
	return store, authority, nil
}

func isWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !stringsHasPathTraversal(relative)
}

func stringsHasPathTraversal(path string) bool {
	return filepath.IsAbs(path) || path == ".." || len(path) >= 3 && path[:3] == ".."+string(filepath.Separator)
}
