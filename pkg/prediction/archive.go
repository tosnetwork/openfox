package prediction

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"time"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
)

type EvidenceMetadataV1 struct {
	PublicationTimeSeconds uint64
	EventTimeSeconds       uint64
	ParserProfileVersion   string
}

type ArchiveObjectV1 struct {
	CanonicalSourceID string
	ContentType       string
	ContentDigest     protocol.Hash32
	ArchiveLocator    string
	Content           []byte
	RetainUntil       uint64
}

// EvidenceArchiveReplica is an independently operated content-addressed
// archive. Its receipt is verified against the immutable journal authority
// set before the evidence can enter a vote plan.
type EvidenceArchiveReplica interface {
	StorePredictionEvidence(ctx context.Context, object ArchiveObjectV1) (ArchiveReceipt, error)
}

// FetchAndArchiveEvidence obtains exact HTTPS bytes and requires every
// configured independent replica to acknowledge the same content-addressed
// object. The caller should configure at least two replicas in distinct
// failure domains.
func (journal *OracleJournal) FetchAndArchiveEvidence(
	ctx context.Context,
	source *HTTPSOracleSource,
	metadata EvidenceMetadataV1,
	replicas []EvidenceArchiveReplica,
	now uint64,
) (ArchivedEvidence, error) {
	if journal == nil || ctx == nil || source == nil || now == 0 || now > math.MaxInt64 ||
		len(replicas) < 2 || len(replicas) > 16 || metadata.PublicationTimeSeconds == 0 ||
		metadata.EventTimeSeconds == 0 || metadata.EventTimeSeconds > metadata.PublicationTimeSeconds ||
		metadata.PublicationTimeSeconds > now || len(metadata.ParserProfileVersion) == 0 ||
		len(metadata.ParserProfileVersion) > 128 {
		return ArchivedEvidence{}, errors.New("prediction evidence acquisition input is invalid")
	}
	journal.mu.Lock()
	if journal.lock == nil {
		journal.mu.Unlock()
		return ArchivedEvidence{}, errors.New("prediction oracle journal is closed")
	}
	profile := journal.doc.Profile
	journal.mu.Unlock()
	if len(replicas) > len(profile.ArchiveAuthorities) {
		return ArchivedEvidence{}, errors.New("prediction evidence has more replicas than admitted authorities")
	}
	retainUntil, ok := add64(profile.ClaimDeadline, profile.AuditRetention)
	if !ok {
		return ArchivedEvidence{}, errors.New("prediction evidence retention overflows")
	}
	snapshot, err := source.Fetch(ctx, time.Unix(int64(now), 0).UTC())
	if err != nil {
		return ArchivedEvidence{}, err
	}
	digest := protocol.Hash32(snapshot.ContentDigest)
	locator := "tos-cas-sha256:" + hex.EncodeToString(digest[:])
	object := ArchiveObjectV1{
		CanonicalSourceID: snapshot.CanonicalSourceID,
		ContentType:       snapshot.ContentType,
		ContentDigest:     digest,
		ArchiveLocator:    locator,
		Content:           append([]byte(nil), snapshot.Content...),
		RetainUntil:       retainUntil,
	}
	receipts := make([]ArchiveReceipt, 0, len(replicas))
	for _, replica := range replicas {
		if replica == nil {
			return ArchivedEvidence{}, errors.New("prediction evidence archive replica is unavailable")
		}
		request := object
		request.Content = append([]byte(nil), object.Content...)
		receipt, storeErr := replica.StorePredictionEvidence(ctx, request)
		if storeErr != nil {
			return ArchivedEvidence{}, storeErr
		}
		receipts = append(receipts, receipt)
	}
	evidence := ArchivedEvidence{
		Entry: protocol.EvidenceEntryV1{
			SourceKind:             protocol.SourceHTTPS,
			CanonicalSourceID:      snapshot.CanonicalSourceID,
			ContentDigest:          digest,
			ArchiveLocator:         locator,
			PublicationTimeSeconds: metadata.PublicationTimeSeconds,
			EventTimeSeconds:       metadata.EventTimeSeconds,
			ParserProfileVersion:   metadata.ParserProfileVersion,
		},
		Content:  append([]byte(nil), snapshot.Content...),
		Receipts: receipts,
	}
	marketID, marketErr := protocol.ParseHash32(profile.MarketID)
	rulesHash, rulesErr := protocol.ParseHash32(profile.RulesHash)
	contextHash := protocol.Hash32{1}
	if marketErr != nil || rulesErr != nil {
		return ArchivedEvidence{}, errors.New("prediction oracle profile hashes are unavailable")
	}
	if _, err := protocol.BuildPredictionEvidenceManifestCell(protocol.PredictionEvidenceManifestV1{
		MarketID:         marketID,
		RulesHash:        rulesHash,
		RoundContextHash: contextHash,
		Outcome:          protocol.OutcomeYes,
		Entries:          []protocol.EvidenceEntryV1{evidence.Entry},
	}); err != nil {
		return ArchivedEvidence{}, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return ArchivedEvidence{}, errors.New("prediction oracle journal closed during evidence acquisition")
	}
	if _, _, err := journal.verifyArchivedEvidence([]ArchivedEvidence{evidence}, now); err != nil {
		return ArchivedEvidence{}, err
	}
	return cloneArchivedEvidence(evidence), nil
}

func cloneArchivedEvidence(value ArchivedEvidence) ArchivedEvidence {
	value.Content = append([]byte(nil), value.Content...)
	value.Receipts = append([]ArchiveReceipt(nil), value.Receipts...)
	return value
}
