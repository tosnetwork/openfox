package prediction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

func fileArchiveTestObject(content string, retainUntil uint64) ArchiveObjectV1 {
	digest := protocol.Hash32(sha256.Sum256([]byte(content)))
	return ArchiveObjectV1{
		CanonicalSourceID: "https://results.example.test/final.json",
		ContentType:       "application/json",
		ContentDigest:     digest,
		ArchiveLocator:    "tos-cas-sha256:" + hex.EncodeToString(digest[:]),
		Content:           []byte(content),
		RetainUntil:       retainUntil,
	}
}

func openFileArchiveTestReplica(
	t *testing.T,
	directory string,
	key ed25519.PrivateKey,
	maximumObjects uint32,
	maximumBytes uint64,
) *FileEvidenceArchiveReplica {
	t.Helper()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	replica, err := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
		Directory: directory, SigningKey: key, MaximumObjects: maximumObjects,
		MaximumObjectBytes: 1024, MaximumContentBytes: maximumBytes,
		Now: func() time.Time { return time.Unix(20_000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return replica
}

func TestFileEvidenceArchivePersistsExactContentAndExtendsRetention(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	replica := openFileArchiveTestReplica(t, directory, key, 4, 4096)
	object := fileArchiveTestObject(`{"winner":"YES"}`, 30_000)
	receipt, err := replica.StorePredictionEvidence(t.Context(), object)
	if err != nil || receipt.ContentDigest != object.ContentDigest || receipt.ArchiveLocator != object.ArchiveLocator ||
		receipt.StoredAt != 20_000 || receipt.RetainUntil != 30_000 {
		t.Fatalf("unexpected archive receipt: %+v err=%v", receipt, err)
	}
	digest, err := archiveReceiptDigest(receipt)
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), digest[:], receipt.Signature[:]) {
		t.Fatal("archive receipt was not signed by the pinned operator")
	}
	object.RetainUntil = 40_000
	extended, err := replica.StorePredictionEvidence(t.Context(), object)
	if err != nil || extended.RetainUntil != 40_000 {
		t.Fatalf("idempotent retention extension failed: %+v err=%v", extended, err)
	}
	if closeErr := replica.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	reopened := openFileArchiveTestReplica(t, directory, key, 4, 4096)
	defer func() { _ = reopened.Close() }()
	loaded, err := reopened.LoadPredictionEvidence(t.Context(), object.ArchiveLocator)
	if err != nil || loaded.RetainUntil != 40_000 || !bytes.Equal(loaded.Content, object.Content) {
		t.Fatalf("reopened archive lost exact content: %+v err=%v", loaded, err)
	}
	loaded.Content[0] ^= 1
	again, err := reopened.LoadPredictionEvidence(t.Context(), object.ArchiveLocator)
	if err != nil || bytes.Equal(loaded.Content, again.Content) {
		t.Fatal("loaded archive content aliases durable state")
	}
}

func TestFileEvidenceArchiveFailsClosedAtObjectAndByteCapacity(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	objectLimited := openFileArchiveTestReplica(t, t.TempDir(), key, 1, 4096)
	defer func() { _ = objectLimited.Close() }()
	if _, err := objectLimited.StorePredictionEvidence(
		t.Context(), fileArchiveTestObject(`{"result":1}`, 30_000),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := objectLimited.StorePredictionEvidence(
		t.Context(), fileArchiveTestObject(`{"result":2}`, 30_000),
	); err == nil {
		t.Fatal("archive accepted an object above its configured count")
	}

	byteLimited := openFileArchiveTestReplica(t, t.TempDir(), key, 4, 1024)
	defer func() { _ = byteLimited.Close() }()
	large := fileArchiveTestObject(string(bytes.Repeat([]byte{'x'}, 700)), 30_000)
	if _, err := byteLimited.StorePredictionEvidence(t.Context(), large); err != nil {
		t.Fatal(err)
	}
	second := fileArchiveTestObject(string(bytes.Repeat([]byte{'y'}, 700)), 30_000)
	if _, err := byteLimited.StorePredictionEvidence(t.Context(), second); err == nil {
		t.Fatal("archive accepted content above its configured byte capacity")
	}
}

func TestFileEvidenceArchiveAcceptsItsExactConfiguredObjectMaximum(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x56}, ed25519.SeedSize))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	replica, err := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
		Directory: directory, SigningKey: key, MaximumObjects: 1,
		MaximumObjectBytes:  fileArchiveMaximumObjectBytes,
		MaximumContentBytes: fileArchiveMaximumObjectBytes,
		Now:                 func() time.Time { return time.Unix(20_000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replica.Close() }()
	object := fileArchiveTestObject(
		string(bytes.Repeat([]byte{'z'}, fileArchiveMaximumObjectBytes)), 30_000,
	)
	if _, err := replica.StorePredictionEvidence(t.Context(), object); err != nil {
		t.Fatalf("archive rejected its exact configured object maximum: %v", err)
	}
}

func TestFileEvidenceArchiveRejectsTamperingAndOperatorReplacement(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	replica := openFileArchiveTestReplica(t, directory, key, 4, 4096)
	object := fileArchiveTestObject(`{"result":"NO"}`, 30_000)
	if _, err := replica.StorePredictionEvidence(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	if err := replica.Close(); err != nil {
		t.Fatal(err)
	}

	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, ed25519.SeedSize))
	if replacement, err := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
		Directory: directory, SigningKey: otherKey, MaximumObjects: 4,
		MaximumObjectBytes: 1024, MaximumContentBytes: 4096,
	}); err == nil {
		_ = replacement.Close()
		t.Fatal("archive accepted a replacement operator key")
	}

	name := filepath.Join(directory, fileArchiveObjectName(object.ContentDigest))
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
		Directory: directory, SigningKey: key, MaximumObjects: 4,
		MaximumObjectBytes: 1024, MaximumContentBytes: 4096,
	}); err == nil {
		_ = reopened.Close()
		t.Fatal("archive reopened corrupted durable content")
	}
}

func TestFileEvidenceArchiveRejectsIdentityReplacementWithExistingObjects(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x57}, ed25519.SeedSize))
	replica := openFileArchiveTestReplica(t, directory, key, 4, 4096)
	if _, err := replica.StorePredictionEvidence(
		t.Context(), fileArchiveTestObject(`{"result":"YES"}`, 30_000),
	); err != nil {
		t.Fatal(err)
	}
	if err := replica.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, fileArchiveIdentityName)); err != nil {
		t.Fatal(err)
	}
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x58}, ed25519.SeedSize))
	if replacement, err := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
		Directory: directory, SigningKey: otherKey, MaximumObjects: 4,
		MaximumObjectBytes: 1024, MaximumContentBytes: 4096,
	}); err == nil {
		_ = replacement.Close()
		t.Fatal("archive replaced a missing identity despite existing durable objects")
	}
}

func TestFileEvidenceArchiveHonorsCanceledContext(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	replica := openFileArchiveTestReplica(t, t.TempDir(), key, 4, 4096)
	defer func() { _ = replica.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := replica.StorePredictionEvidence(ctx, fileArchiveTestObject("{}", 30_000)); err == nil {
		t.Fatal("archive ignored cancellation before persistence")
	}
}

func TestFileEvidenceArchivePrunesOnlyPastRetentionAndRestoresCapacity(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x59}, ed25519.SeedSize))
	now := int64(20_000)
	replica, err := OpenFileEvidenceArchiveReplica(FileEvidenceArchiveConfig{
		Directory: directory, SigningKey: key, MaximumObjects: 2,
		MaximumObjectBytes: 1024, MaximumContentBytes: 1024,
		Now: func() time.Time { return time.Unix(now, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replica.Close() }()
	expires := fileArchiveTestObject(string(bytes.Repeat([]byte{'a'}, 500)), 21_000)
	retained := fileArchiveTestObject(string(bytes.Repeat([]byte{'b'}, 500)), 22_000)
	if _, storeErr := replica.StorePredictionEvidence(t.Context(), expires); storeErr != nil {
		t.Fatal(storeErr)
	}
	if _, storeErr := replica.StorePredictionEvidence(t.Context(), retained); storeErr != nil {
		t.Fatal(storeErr)
	}
	now = 21_000
	if count, size, pruneErr := replica.PruneExpiredPredictionEvidence(t.Context()); pruneErr != nil || count != 0 || size != 0 {
		t.Fatalf(
			"archive pruned at the inclusive retention boundary: count=%d size=%d err=%v",
			count, size, pruneErr,
		)
	}
	now = 21_001
	count, size, err := replica.PruneExpiredPredictionEvidence(t.Context())
	if err != nil || count != 1 || size != 500 {
		t.Fatalf("archive did not prune the expired object: count=%d size=%d err=%v", count, size, err)
	}
	if _, err := replica.LoadPredictionEvidence(t.Context(), expires.ArchiveLocator); err == nil {
		t.Fatal("archive returned pruned content")
	}
	if _, err := replica.LoadPredictionEvidence(t.Context(), retained.ArchiveLocator); err != nil {
		t.Fatal("archive pruned content before its retention horizon")
	}
	replacement := fileArchiveTestObject(string(bytes.Repeat([]byte{'c'}, 500)), 23_000)
	if _, err := replica.StorePredictionEvidence(t.Context(), replacement); err != nil {
		t.Fatalf("archive did not restore capacity after durable pruning: %v", err)
	}
}
