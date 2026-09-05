package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

const (
	fileArchiveIdentityName       = "archive-identity.json"
	fileArchiveObjectPrefix       = "object-"
	fileArchiveObjectSuffix       = ".json"
	fileArchiveMaximumObjects     = 100_000
	fileArchiveMaximumObjectBytes = 2 << 20
	fileArchiveMaximumTotalBytes  = 1 << 40
	fileArchiveEnvelopeOverhead   = 8 << 10
)

type FileEvidenceArchiveConfig struct {
	Directory           string
	SigningKey          ed25519.PrivateKey
	MaximumObjects      uint32
	MaximumObjectBytes  uint64
	MaximumContentBytes uint64
	Now                 func() time.Time
}

type fileArchiveIdentity struct {
	SchemaVersion uint16 `json:"schema_version"`
	OperatorID    string `json:"operator_id"`
}

type fileArchiveEnvelope struct {
	SchemaVersion     uint16          `json:"schema_version"`
	CanonicalSourceID string          `json:"canonical_source_id"`
	ContentType       string          `json:"content_type"`
	ContentDigest     protocol.Hash32 `json:"content_digest"`
	ArchiveLocator    string          `json:"archive_locator"`
	Content           []byte          `json:"content"`
	RetainUntil       uint64          `json:"retain_until"`
}

// FileEvidenceArchiveReplica is a bounded, single-writer content-addressed
// replica. Operators must place replicas in independent failure domains and
// pin each replica's signing key in the market Oracle profile.
type FileEvidenceArchiveReplica struct {
	mu                  sync.Mutex
	root                *os.Root
	lock                *os.File
	signingKey          ed25519.PrivateKey
	operatorID          string
	maximumObjects      uint32
	maximumObjectBytes  uint64
	maximumContentBytes uint64
	objectCount         uint32
	contentBytes        uint64
	now                 func() time.Time
}

func OpenFileEvidenceArchiveReplica(config FileEvidenceArchiveConfig) (*FileEvidenceArchiveReplica, error) {
	if config.MaximumObjects == 0 || config.MaximumObjects > fileArchiveMaximumObjects ||
		config.MaximumObjectBytes == 0 || config.MaximumObjectBytes > fileArchiveMaximumObjectBytes ||
		config.MaximumContentBytes < config.MaximumObjectBytes ||
		config.MaximumContentBytes > fileArchiveMaximumTotalBytes ||
		len(config.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("prediction file archive configuration is invalid")
	}
	operatorID, err := ArchiveOperatorID(config.SigningKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	lock, err := openPrivateLockedDirectory(config.Directory)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(config.Directory)
	if err != nil {
		_ = releaseBookLock(lock)
		return nil, errors.New("open prediction file archive root")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	replica := &FileEvidenceArchiveReplica{
		root: root, lock: lock, signingKey: append(ed25519.PrivateKey(nil), config.SigningKey...),
		operatorID: operatorID, maximumObjects: config.MaximumObjects,
		maximumObjectBytes: config.MaximumObjectBytes, maximumContentBytes: config.MaximumContentBytes,
		now: now,
	}
	if err := replica.loadOrInitialize(); err != nil {
		_ = root.Close()
		_ = releaseBookLock(lock)
		return nil, err
	}
	return replica, nil
}

func (replica *FileEvidenceArchiveReplica) Close() error {
	if replica == nil {
		return nil
	}
	replica.mu.Lock()
	defer replica.mu.Unlock()
	if replica.lock == nil {
		return nil
	}
	for index := range replica.signingKey {
		replica.signingKey[index] = 0
	}
	rootErr := replica.root.Close()
	lockErr := releaseBookLock(replica.lock)
	replica.root = nil
	replica.lock = nil
	return errors.Join(rootErr, lockErr)
}

func (replica *FileEvidenceArchiveReplica) StorePredictionEvidence(
	ctx context.Context,
	object ArchiveObjectV1,
) (ArchiveReceipt, error) {
	if replica == nil || ctx == nil {
		return ArchiveReceipt{}, errors.New("prediction file archive is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveReceipt{}, err
	}
	replica.mu.Lock()
	defer replica.mu.Unlock()
	if replica.lock == nil || replica.root == nil {
		return ArchiveReceipt{}, errors.New("prediction file archive is closed")
	}
	now := replica.now().UTC()
	if now.IsZero() || now.Unix() <= 0 || object.RetainUntil <= uint64(now.Unix()) ||
		uint64(len(object.Content)) > replica.maximumObjectBytes ||
		validateFileArchiveObject(object) != nil {
		return ArchiveReceipt{}, errors.New("prediction file archive object is invalid")
	}
	name := fileArchiveObjectName(object.ContentDigest)
	prior, found, err := replica.readObject(name)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	if found {
		if prior.CanonicalSourceID != object.CanonicalSourceID || prior.ContentType != object.ContentType ||
			prior.ContentDigest != object.ContentDigest || prior.ArchiveLocator != object.ArchiveLocator ||
			!bytes.Equal(prior.Content, object.Content) {
			return ArchiveReceipt{}, errors.New("prediction file archive digest conflicts with durable content")
		}
		if object.RetainUntil > prior.RetainUntil {
			prior.RetainUntil = object.RetainUntil
			if err := replica.persistObject(name, prior); err != nil {
				return ArchiveReceipt{}, err
			}
		}
		return SignArchiveReceipt(
			replica.signingKey, object.ContentDigest, object.ArchiveLocator,
			uint64(now.Unix()), prior.RetainUntil,
		)
	}
	nextBytes, ok := add64(replica.contentBytes, uint64(len(object.Content)))
	if !ok || replica.objectCount >= replica.maximumObjects || nextBytes > replica.maximumContentBytes {
		return ArchiveReceipt{}, errors.New("prediction file archive capacity is exhausted")
	}
	envelope := fileArchiveEnvelope{
		SchemaVersion: 1, CanonicalSourceID: object.CanonicalSourceID, ContentType: object.ContentType,
		ContentDigest: object.ContentDigest, ArchiveLocator: object.ArchiveLocator,
		Content: append([]byte(nil), object.Content...), RetainUntil: object.RetainUntil,
	}
	// Reserve capacity before persistence. A storage error is ambiguous after a
	// possible rename, so the reservation remains consumed until a clean reopen.
	replica.objectCount++
	replica.contentBytes = nextBytes
	if err := replica.persistObject(name, envelope); err != nil {
		return ArchiveReceipt{}, err
	}
	return SignArchiveReceipt(
		replica.signingKey, object.ContentDigest, object.ArchiveLocator,
		uint64(now.Unix()), object.RetainUntil,
	)
}

func (replica *FileEvidenceArchiveReplica) LoadPredictionEvidence(
	ctx context.Context,
	locator string,
) (ArchiveObjectV1, error) {
	if replica == nil || ctx == nil {
		return ArchiveObjectV1{}, errors.New("prediction file archive is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ArchiveObjectV1{}, err
	}
	digest, err := parseFileArchiveLocator(locator)
	if err != nil {
		return ArchiveObjectV1{}, err
	}
	replica.mu.Lock()
	defer replica.mu.Unlock()
	if replica.lock == nil || replica.root == nil {
		return ArchiveObjectV1{}, errors.New("prediction file archive is closed")
	}
	envelope, found, err := replica.readObject(fileArchiveObjectName(digest))
	if err != nil || !found || envelope.ArchiveLocator != locator {
		return ArchiveObjectV1{}, errors.New("prediction file archive object is unavailable")
	}
	return ArchiveObjectV1{
		CanonicalSourceID: envelope.CanonicalSourceID, ContentType: envelope.ContentType,
		ContentDigest: envelope.ContentDigest, ArchiveLocator: envelope.ArchiveLocator,
		Content: append([]byte(nil), envelope.Content...), RetainUntil: envelope.RetainUntil,
	}, nil
}

// PruneExpiredPredictionEvidence removes only objects whose signed retention
// horizon is strictly in the past. Capacity is released only after the rooted
// directory metadata is durably synchronized.
func (replica *FileEvidenceArchiveReplica) PruneExpiredPredictionEvidence(
	ctx context.Context,
) (uint32, uint64, error) {
	if replica == nil || ctx == nil {
		return 0, 0, errors.New("prediction file archive is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	replica.mu.Lock()
	defer replica.mu.Unlock()
	if replica.lock == nil || replica.root == nil {
		return 0, 0, errors.New("prediction file archive is closed")
	}
	now := replica.now().UTC()
	if now.IsZero() || now.Unix() <= 0 {
		return 0, 0, errors.New("prediction file archive clock is invalid")
	}
	entries, err := readFileArchiveDirectory(replica.root)
	if err != nil {
		return 0, 0, err
	}
	var removedObjects uint32
	var removedBytes uint64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		name := entry.Name()
		if name == ".lock" || name == fileArchiveIdentityName {
			continue
		}
		if _, valid := parseFileArchiveObjectName(name); !valid || entry.IsDir() ||
			entry.Type()&os.ModeSymlink != 0 {
			return 0, 0, errors.New("prediction file archive contains an unexpected entry")
		}
		envelope, found, readErr := replica.readObject(name)
		if readErr != nil || !found {
			return 0, 0, errors.New("prediction file archive contains a corrupted object")
		}
		if envelope.RetainUntil >= uint64(now.Unix()) {
			continue
		}
		nextBytes, ok := add64(removedBytes, uint64(len(envelope.Content)))
		if !ok || removedObjects == ^uint32(0) {
			return 0, 0, errors.New("prediction file archive prune accounting overflowed")
		}
		if err := replica.root.Remove(name); err != nil {
			return 0, 0, err
		}
		removedObjects++
		removedBytes = nextBytes
	}
	if removedObjects == 0 {
		return 0, 0, nil
	}
	if err := syncFileArchiveRoot(replica.root); err != nil {
		return 0, 0, err
	}
	if removedObjects > replica.objectCount || removedBytes > replica.contentBytes {
		return 0, 0, errors.New("prediction file archive prune accounting is inconsistent")
	}
	replica.objectCount -= removedObjects
	replica.contentBytes -= removedBytes
	return removedObjects, removedBytes, nil
}

func (replica *FileEvidenceArchiveReplica) loadOrInitialize() error {
	identity := fileArchiveIdentity{SchemaVersion: 1, OperatorID: replica.operatorID}
	raw, err := readFileArchiveRoot(replica.root, fileArchiveIdentityName, 4096)
	if errors.Is(err, os.ErrNotExist) {
		empty, emptyErr := fileArchiveRootHasOnlyLock(replica.root)
		if emptyErr != nil || !empty {
			return errors.New("prediction file archive identity is missing from non-empty storage")
		}
		encoded, marshalErr := json.Marshal(identity)
		if marshalErr != nil {
			return errors.New("encode prediction file archive identity")
		}
		if writeErr := fileutil.WriteFileAtomicRoot(
			replica.root, fileArchiveIdentityName, encoded, 0o600,
		); writeErr != nil {
			return writeErr
		}
	} else if err != nil {
		return err
	} else {
		var loaded fileArchiveIdentity
		if decodeFileArchiveJSON(raw, &loaded) != nil || loaded != identity {
			return errors.New("prediction file archive identity conflicts with its signing key")
		}
	}
	entries, err := readFileArchiveDirectory(replica.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" || name == fileArchiveIdentityName {
			continue
		}
		digest, validName := parseFileArchiveObjectName(name)
		if !validName || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("prediction file archive contains an unexpected entry")
		}
		envelope, found, objectErr := replica.readObject(name)
		if objectErr != nil || !found || envelope.ContentDigest != digest {
			return errors.New("prediction file archive contains a corrupted object")
		}
		nextBytes, ok := add64(replica.contentBytes, uint64(len(envelope.Content)))
		if !ok || replica.objectCount >= replica.maximumObjects || nextBytes > replica.maximumContentBytes {
			return errors.New("prediction file archive exceeds configured capacity")
		}
		replica.objectCount++
		replica.contentBytes = nextBytes
	}
	return nil
}

func (replica *FileEvidenceArchiveReplica) readObject(
	name string,
) (fileArchiveEnvelope, bool, error) {
	limit, ok := fileArchiveEnvelopeLimit(replica.maximumObjectBytes)
	if !ok || limit > uint64(^uint(0)>>1) {
		return fileArchiveEnvelope{}, false, errors.New("prediction file archive read bound is invalid")
	}
	raw, err := readFileArchiveRoot(replica.root, name, int(limit))
	if errors.Is(err, os.ErrNotExist) {
		return fileArchiveEnvelope{}, false, nil
	}
	if err != nil {
		return fileArchiveEnvelope{}, false, err
	}
	var envelope fileArchiveEnvelope
	if decodeFileArchiveJSON(raw, &envelope) != nil || envelope.SchemaVersion != 1 {
		return fileArchiveEnvelope{}, false, errors.New("prediction file archive object encoding is invalid")
	}
	object := ArchiveObjectV1{
		CanonicalSourceID: envelope.CanonicalSourceID, ContentType: envelope.ContentType,
		ContentDigest: envelope.ContentDigest, ArchiveLocator: envelope.ArchiveLocator,
		Content: envelope.Content, RetainUntil: envelope.RetainUntil,
	}
	if uint64(len(envelope.Content)) > replica.maximumObjectBytes || validateFileArchiveObject(object) != nil ||
		fileArchiveObjectName(envelope.ContentDigest) != name {
		return fileArchiveEnvelope{}, false, errors.New("prediction file archive object integrity check failed")
	}
	return envelope, true, nil
}

func (replica *FileEvidenceArchiveReplica) persistObject(name string, envelope fileArchiveEnvelope) error {
	raw, err := json.Marshal(envelope)
	limit, ok := fileArchiveEnvelopeLimit(replica.maximumObjectBytes)
	if err != nil || !ok || uint64(len(raw)) > limit {
		return errors.New("prediction file archive object exceeds its durable bound")
	}
	return fileutil.WriteFileAtomicRoot(replica.root, name, raw, 0o600)
}

func fileArchiveEnvelopeLimit(contentBytes uint64) (uint64, bool) {
	withPadding, ok := add64(contentBytes, 2)
	if !ok {
		return 0, false
	}
	encodedGroups := withPadding / 3
	if encodedGroups > ^uint64(0)/4 {
		return 0, false
	}
	encodedBytes, ok := add64(encodedGroups*4, fileArchiveEnvelopeOverhead)
	return encodedBytes, ok
}

func fileArchiveRootHasOnlyLock(root *os.Root) (bool, error) {
	entries, err := readFileArchiveDirectory(root)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() != ".lock" {
			return false, nil
		}
	}
	return true, nil
}

func readFileArchiveDirectory(root *os.Root) ([]os.DirEntry, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, errors.New("open prediction file archive directory")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	return entries, nil
}

func syncFileArchiveRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func validateFileArchiveObject(object ArchiveObjectV1) error {
	if len(object.CanonicalSourceID) == 0 || len(object.CanonicalSourceID) > maxOracleSourceURLBytes ||
		strings.IndexFunc(object.CanonicalSourceID, func(value rune) bool {
			return value < 0x20 || value == 0x7f
		}) >= 0 ||
		len(object.ContentType) == 0 || len(object.ContentType) > 255 ||
		canonicalMediaType(object.ContentType) != object.ContentType || len(object.Content) == 0 ||
		object.RetainUntil == 0 || sha256.Sum256(object.Content) != object.ContentDigest {
		return errors.New("invalid prediction file archive object")
	}
	expected := "tos-cas-sha256:" + hex.EncodeToString(object.ContentDigest[:])
	if object.ArchiveLocator != expected {
		return errors.New("prediction file archive locator is not content addressed")
	}
	return nil
}

func parseFileArchiveLocator(locator string) (protocol.Hash32, error) {
	const prefix = "tos-cas-sha256:"
	var digest protocol.Hash32
	if len(locator) != len(prefix)+64 || !strings.HasPrefix(locator, prefix) {
		return digest, errors.New("prediction file archive locator is invalid")
	}
	raw, err := hex.DecodeString(locator[len(prefix):])
	if err != nil || hex.EncodeToString(raw) != locator[len(prefix):] {
		return digest, errors.New("prediction file archive locator is invalid")
	}
	copy(digest[:], raw)
	return digest, nil
}

func fileArchiveObjectName(digest protocol.Hash32) string {
	return fileArchiveObjectPrefix + hex.EncodeToString(digest[:]) + fileArchiveObjectSuffix
}

func parseFileArchiveObjectName(name string) (protocol.Hash32, bool) {
	var digest protocol.Hash32
	if len(name) != len(fileArchiveObjectPrefix)+64+len(fileArchiveObjectSuffix) ||
		!strings.HasPrefix(name, fileArchiveObjectPrefix) || !strings.HasSuffix(name, fileArchiveObjectSuffix) {
		return digest, false
	}
	rawHex := name[len(fileArchiveObjectPrefix) : len(name)-len(fileArchiveObjectSuffix)]
	raw, err := hex.DecodeString(rawHex)
	if err != nil || hex.EncodeToString(raw) != rawHex {
		return digest, false
	}
	copy(digest[:], raw)
	return digest, true
}

func readFileArchiveRoot(root *os.Root, name string, maximum int) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 0 ||
		info.Size() > int64(maximum) {
		_ = file.Close()
		return nil, errors.New("prediction file archive file is not owner-private and bounded")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) > maximum {
		return nil, errors.Join(readErr, closeErr, errors.New("prediction file archive read failed"))
	}
	return raw, nil
}

func decodeFileArchiveJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("prediction file archive JSON has trailing data")
	}
	return nil
}
