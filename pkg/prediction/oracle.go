package prediction

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const oracleStateFile = "oracle-votes.json"

type ArchiveAuthority struct {
	OperatorID string                      `json:"operator_id"`
	PublicKey  [ed25519.PublicKeySize]byte `json:"public_key"`
}

type OracleProfile struct {
	GlobalID           int32              `json:"global_id"`
	MarketAddress      string             `json:"market_address"`
	MarketID           string             `json:"market_id"`
	RulesHash          string             `json:"rules_hash"`
	RoundPolicyHash    string             `json:"round_policy_hash"`
	ReporterAddress    string             `json:"reporter_address"`
	Round              protocol.Round     `json:"round"`
	ClaimDeadline      uint64             `json:"claim_deadline"`
	AuditRetention     uint64             `json:"audit_retention_seconds"`
	ArchiveAuthorities []ArchiveAuthority `json:"archive_authorities"`
}

type ArchiveReceipt struct {
	OperatorID     string                      `json:"operator_id"`
	ContentDigest  protocol.Hash32             `json:"content_digest"`
	ArchiveLocator string                      `json:"archive_locator"`
	StoredAt       uint64                      `json:"stored_at"`
	RetainUntil    uint64                      `json:"retain_until"`
	Signature      [ed25519.SignatureSize]byte `json:"signature"`
}

type ArchivedEvidence struct {
	Entry    protocol.EvidenceEntryV1
	Content  []byte
	Receipts []ArchiveReceipt
}

type OracleVotePlan struct {
	Round                 protocol.Round
	Outcome               protocol.Outcome
	RoundContextHash      string
	EvidenceRoot          string
	StatementHash         string
	EvidenceManifestBOC   []byte
	StatementBOC          []byte
	StatementCreatedAt    uint64
	StatementExpiry       uint64
	ArchiveReceiptDigests []string
}

type oracleVoteRecord struct {
	Round                 protocol.Round   `json:"round"`
	Outcome               protocol.Outcome `json:"outcome"`
	RoundContextHash      string           `json:"round_context_hash"`
	EvidenceRoot          string           `json:"evidence_root"`
	StatementHash         string           `json:"statement_hash"`
	EvidenceManifestBOC   string           `json:"evidence_manifest_boc_base64"`
	StatementBOC          string           `json:"statement_boc_base64"`
	StatementCreatedAt    uint64           `json:"statement_created_at"`
	StatementExpiry       uint64           `json:"statement_expiry"`
	ArchiveReceiptDigests []string         `json:"archive_receipt_digests"`
}

type oracleDocument struct {
	SchemaVersion uint16                      `json:"schema_version"`
	Revision      uint64                      `json:"revision"`
	Profile       OracleProfile               `json:"profile"`
	Votes         map[string]oracleVoteRecord `json:"votes"`
}

type OracleJournal struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	doc       oracleDocument
}

func ArchiveOperatorID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize || protocol.ValidateTradingPublicKey(publicKey) != nil {
		return "", errors.New("archive operator key is invalid")
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func SignArchiveReceipt(privateKey ed25519.PrivateKey, contentDigest protocol.Hash32,
	locator string, storedAt, retainUntil uint64) (ArchiveReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ArchiveReceipt{}, errors.New("archive receipt key is invalid")
	}
	operator, err := ArchiveOperatorID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return ArchiveReceipt{}, err
	}
	receipt := ArchiveReceipt{OperatorID: operator, ContentDigest: contentDigest,
		ArchiveLocator: locator, StoredAt: storedAt, RetainUntil: retainUntil}
	digest, err := archiveReceiptDigest(receipt)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	copy(receipt.Signature[:], ed25519.Sign(privateKey, digest[:]))
	return receipt, nil
}

func OpenOracleJournal(directory string, profile OracleProfile) (*OracleJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || validateOracleProfile(profile) != nil {
		return nil, errors.New("prediction oracle journal configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("prediction oracle journal directory must be owner-private")
	}
	lock, err := acquireBookLock(directory)
	if err != nil {
		return nil, err
	}
	journal := &OracleJournal{directory: directory, lock: lock,
		doc: oracleDocument{SchemaVersion: 1, Profile: profile, Votes: map[string]oracleVoteRecord{}}}
	if err := journal.loadOrInitialize(); err != nil {
		_ = releaseBookLock(lock)
		return nil, err
	}
	return journal, nil
}

func (journal *OracleJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return nil
	}
	err := releaseBookLock(journal.lock)
	journal.lock = nil
	return err
}

// PrepareVote verifies and commits the evidence/statement before returning a
// plan. A crash after return can therefore only replay the same statement; a
// different outcome or evidence root for the same round context is rejected.
func (journal *OracleJournal) PrepareVote(roundContextBOC, reviewBaseBOC []byte,
	outcome protocol.Outcome, evidence []ArchivedEvidence, now uint64) (OracleVotePlan, error) {
	if journal == nil || now == 0 || len(roundContextBOC) == 0 || len(roundContextBOC) > 8192 || len(evidence) == 0 {
		return OracleVotePlan{}, errors.New("prediction oracle vote input is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return OracleVotePlan{}, errors.New("prediction oracle journal is closed")
	}
	context, err := canonicalCell(roundContextBOC, 8192)
	if err != nil {
		return OracleVotePlan{}, err
	}
	profile := journal.doc.Profile
	marketID, _ := protocol.ParseHash32(profile.MarketID)
	rulesHash, _ := protocol.ParseHash32(profile.RulesHash)
	policyHash, _ := protocol.ParseHash32(profile.RoundPolicyHash)
	contextHash := hash32(context.Hash())
	expiry := uint64(0)
	if profile.Round == protocol.RoundNormal {
		if len(reviewBaseBOC) != 0 {
			return OracleVotePlan{}, errors.New("normal oracle vote must not carry a review base")
		}
		decoded, decodeErr := protocol.DecodePredictionNormalContextV1(context)
		if decodeErr != nil || decoded.MarketID != marketID || decoded.RulesHash != rulesHash ||
			now < decoded.ResolveNotBefore || now < decoded.NormalRoundOpenedAt || now >= decoded.OracleVoteDeadline {
			return OracleVotePlan{}, errors.New("normal oracle context is stale or outside the admitted market")
		}
		expiry = decoded.OracleVoteDeadline
	} else {
		if len(reviewBaseBOC) == 0 || len(reviewBaseBOC) > 8192 {
			return OracleVotePlan{}, errors.New("appellate vote requires the exact review base context")
		}
		base, baseErr := canonicalCell(reviewBaseBOC, 8192)
		vote, voteErr := protocol.DecodePredictionReviewVoteContextV1(context)
		decodedBase, decodeErr := protocol.DecodePredictionReviewBaseContextV1(base)
		if baseErr != nil || voteErr != nil || decodeErr != nil || decodedBase.MarketID != marketID ||
			decodedBase.RulesHash != rulesHash || vote.ReviewBaseContextHash != hash32(base.Hash()) ||
			now < decodedBase.ReviewVoteNotBefore || now < vote.ReviewRoundOpenedAt || now >= decodedBase.AppealDeadline {
			return OracleVotePlan{}, errors.New("appellate oracle context is stale or outside the admitted review")
		}
		expiry = decodedBase.AppealDeadline
	}
	entries, receiptDigests, err := journal.verifyArchivedEvidence(evidence, now)
	if err != nil {
		return OracleVotePlan{}, err
	}
	manifest, err := protocol.BuildPredictionEvidenceManifestCell(protocol.PredictionEvidenceManifestV1{
		MarketID: marketID, RulesHash: rulesHash, RoundContextHash: contextHash, Outcome: outcome, Entries: entries})
	if err != nil {
		return OracleVotePlan{}, err
	}
	evidenceRoot := hash32(manifest.Hash())
	key := contextHash.CellHashString()
	if prior, ok := journal.doc.Votes[key]; ok {
		if prior.Round != profile.Round || prior.Outcome != outcome ||
			prior.EvidenceRoot != evidenceRoot.CellHashString() {
			return OracleVotePlan{}, errors.New("oracle equivocation: round context already committed to another statement")
		}
		return votePlan(prior), nil
	}
	statement, err := protocol.BuildPredictionResolutionStatementCell(protocol.PredictionResolutionStatementV1{
		GlobalID: profile.GlobalID, MarketAddress: profile.MarketAddress, MarketID: marketID,
		RulesHash: rulesHash, RoundPolicyHash: policyHash, RoundContextHash: contextHash,
		Round: profile.Round, Outcome: outcome, EvidenceRoot: evidenceRoot,
		StatementCreatedAt: now, StatementExpiry: expiry})
	if err != nil {
		return OracleVotePlan{}, err
	}
	record := oracleVoteRecord{Round: profile.Round, Outcome: outcome,
		RoundContextHash: contextHash.CellHashString(), EvidenceRoot: evidenceRoot.CellHashString(),
		StatementHash:       hash32(statement.Hash()).CellHashString(),
		EvidenceManifestBOC: base64.StdEncoding.EncodeToString(manifest.ToBOC()),
		StatementBOC:        base64.StdEncoding.EncodeToString(statement.ToBOC()), StatementCreatedAt: now,
		StatementExpiry: expiry, ArchiveReceiptDigests: receiptDigests}
	next := cloneOracleDocument(journal.doc)
	next.Revision++
	next.Votes[key] = record
	if err := journal.persist(next); err != nil {
		return OracleVotePlan{}, err
	}
	journal.doc = next
	return votePlan(record), nil
}

func (journal *OracleJournal) verifyArchivedEvidence(values []ArchivedEvidence, now uint64) ([]protocol.EvidenceEntryV1, []string, error) {
	if len(values) > protocol.MaxEvidenceEntries {
		return nil, nil, errors.New("oracle evidence entry capacity exceeded")
	}
	authorities := make(map[string]ed25519.PublicKey, len(journal.doc.Profile.ArchiveAuthorities))
	for _, authority := range journal.doc.Profile.ArchiveAuthorities {
		authorities[authority.OperatorID] = ed25519.PublicKey(authority.PublicKey[:])
	}
	minimumRetention, carry := add64(journal.doc.Profile.ClaimDeadline, journal.doc.Profile.AuditRetention)
	if !carry {
		return nil, nil, errors.New("oracle archive retention overflows")
	}
	totalBytes := 0
	entries := make([]protocol.EvidenceEntryV1, 0, len(values))
	receiptDigests := make([]string, 0, len(values)*2)
	for _, value := range values {
		totalBytes += len(value.Content)
		if len(value.Content) == 0 || len(value.Content) > 2<<20 || totalBytes > 16<<20 ||
			sha256.Sum256(value.Content) != value.Entry.ContentDigest {
			return nil, nil, errors.New("oracle evidence content does not match its bounded digest")
		}
		if len(value.Receipts) > len(authorities) {
			return nil, nil, errors.New("evidence contains duplicate or excessive archive receipts")
		}
		validOperators := make(map[string]struct{})
		for _, receipt := range value.Receipts {
			if _, duplicate := validOperators[receipt.OperatorID]; duplicate {
				return nil, nil, errors.New("evidence repeats an archive operator receipt")
			}
			key, ok := authorities[receipt.OperatorID]
			digest, digestErr := archiveReceiptDigest(receipt)
			if !ok || digestErr != nil || receipt.ContentDigest != value.Entry.ContentDigest ||
				receipt.ArchiveLocator != value.Entry.ArchiveLocator ||
				receipt.StoredAt < value.Entry.PublicationTimeSeconds ||
				receipt.StoredAt > now || receipt.RetainUntil < minimumRetention ||
				!ed25519.Verify(key, digest[:], receipt.Signature[:]) {
				return nil, nil, errors.New("oracle archive receipt is invalid or insufficiently retained")
			}
			validOperators[receipt.OperatorID] = struct{}{}
			receiptID := sha256.New()
			receiptID.Write([]byte("TOS_OPENFOX_PREDICTION_ARCHIVE_RECEIPT_ID_V1\x00"))
			receiptID.Write(digest[:])
			receiptID.Write(receipt.Signature[:])
			receiptDigests = append(receiptDigests, "sha256:"+hex.EncodeToString(receiptID.Sum(nil)))
		}
		if len(validOperators) < 2 {
			return nil, nil, errors.New("each evidence snapshot requires two independent archive operators")
		}
		entries = append(entries, value.Entry)
	}
	sort.Strings(receiptDigests)
	return entries, receiptDigests, nil
}

func archiveReceiptDigest(receipt ArchiveReceipt) ([32]byte, error) {
	if !canonicalDigest(receipt.OperatorID, "sha256:") || receipt.ContentDigest.IsZero() ||
		receipt.ArchiveLocator != "tos-cas-sha256:"+hex.EncodeToString(receipt.ContentDigest[:]) ||
		receipt.StoredAt == 0 || receipt.RetainUntil < receipt.StoredAt {
		return [32]byte{}, errors.New("invalid archive receipt fields")
	}
	buffer := bytes.NewBufferString("TOS_OPENFOX_PREDICTION_ARCHIVE_RECEIPT_V1\x00")
	buffer.WriteString(receipt.OperatorID)
	buffer.WriteByte(0)
	buffer.Write(receipt.ContentDigest[:])
	buffer.WriteByte(0)
	buffer.WriteString(receipt.ArchiveLocator)
	var times [16]byte
	binary.BigEndian.PutUint64(times[:8], receipt.StoredAt)
	binary.BigEndian.PutUint64(times[8:], receipt.RetainUntil)
	buffer.Write(times[:])
	return sha256.Sum256(buffer.Bytes()), nil
}

func validateOracleProfile(profile OracleProfile) error {
	market, marketErr := address.ParseRawAddr(profile.MarketAddress)
	marketID, marketIDErr := protocol.ParseHash32(profile.MarketID)
	rules, rulesErr := protocol.ParseHash32(profile.RulesHash)
	policy, policyErr := protocol.ParseHash32(profile.RoundPolicyHash)
	reporter, reporterErr := address.ParseRawAddr(profile.ReporterAddress)
	if marketErr != nil || reporterErr != nil || market == nil || reporter == nil || market.Type() != address.StdAddress ||
		reporter.Type() != address.StdAddress || market.StringRaw() != profile.MarketAddress ||
		reporter.StringRaw() != profile.ReporterAddress || marketIDErr != nil || rulesErr != nil || policyErr != nil ||
		marketID.IsZero() || rules.IsZero() || policy.IsZero() ||
		!canonicalDigest(profile.MarketID, "tvm-cell-sha256:") || !canonicalDigest(profile.RulesHash, "sha256:") ||
		!canonicalDigest(profile.RoundPolicyHash, "tvm-cell-sha256:") ||
		(profile.Round != protocol.RoundNormal && profile.Round != protocol.RoundAppeal) ||
		profile.ClaimDeadline == 0 || profile.AuditRetention == 0 || profile.AuditRetention > 31_536_000 ||
		len(profile.ArchiveAuthorities) < 2 || len(profile.ArchiveAuthorities) > 16 {
		return errors.New("invalid immutable oracle profile")
	}
	seen := make(map[string]struct{}, len(profile.ArchiveAuthorities))
	previous := ""
	for _, authority := range profile.ArchiveAuthorities {
		expected, err := ArchiveOperatorID(ed25519.PublicKey(authority.PublicKey[:]))
		if err != nil || authority.OperatorID != expected {
			return errors.New("archive authority id does not bind its key")
		}
		if _, exists := seen[authority.OperatorID]; exists {
			return errors.New("archive authorities must be independent unique keys")
		}
		if previous != "" && authority.OperatorID <= previous {
			return errors.New("archive authorities must be canonically sorted")
		}
		seen[authority.OperatorID] = struct{}{}
		previous = authority.OperatorID
	}
	return nil
}

func canonicalCell(raw []byte, maximum int) (*cell.Cell, error) {
	if len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("canonical cell BOC exceeds its bound")
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil || !bytes.Equal(raw, root.ToBOC()) {
		return nil, errors.New("cell BOC is not canonical")
	}
	return root, nil
}

func hash32(value []byte) protocol.Hash32 {
	var result protocol.Hash32
	copy(result[:], value)
	return result
}

func add64(left, right uint64) (uint64, bool) {
	if left > ^uint64(0)-right {
		return 0, false
	}
	return left + right, true
}

func votePlan(record oracleVoteRecord) OracleVotePlan {
	manifest, _ := base64.StdEncoding.DecodeString(record.EvidenceManifestBOC)
	statement, _ := base64.StdEncoding.DecodeString(record.StatementBOC)
	return OracleVotePlan{Round: record.Round, Outcome: record.Outcome,
		RoundContextHash: record.RoundContextHash, EvidenceRoot: record.EvidenceRoot,
		StatementHash: record.StatementHash, EvidenceManifestBOC: manifest, StatementBOC: statement,
		StatementCreatedAt: record.StatementCreatedAt, StatementExpiry: record.StatementExpiry,
		ArchiveReceiptDigests: append([]string(nil), record.ArchiveReceiptDigests...)}
}

func (journal *OracleJournal) loadOrInitialize() error {
	path := filepath.Join(journal.directory, oracleStateFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal.persist(journal.doc)
	}
	if err != nil || len(raw) > 8<<20 {
		return errors.New("prediction oracle journal is unavailable")
	}
	var loaded oracleDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&loaded) != nil || decoder.Decode(&struct{}{}) != io.EOF || loaded.SchemaVersion != 1 ||
		loaded.Votes == nil || len(loaded.Votes) > 1 || !reflect.DeepEqual(loaded.Profile, journal.doc.Profile) {
		return errors.New("prediction oracle journal identity or shape is invalid")
	}
	marketID, _ := protocol.ParseHash32(loaded.Profile.MarketID)
	rulesHash, _ := protocol.ParseHash32(loaded.Profile.RulesHash)
	policyHash, _ := protocol.ParseHash32(loaded.Profile.RoundPolicyHash)
	for key, record := range loaded.Votes {
		manifestRaw, manifestErr := base64.StdEncoding.DecodeString(record.EvidenceManifestBOC)
		statementRaw, statementErr := base64.StdEncoding.DecodeString(record.StatementBOC)
		manifest, manifestCellErr := canonicalCell(manifestRaw, 64<<10)
		statement, statementCellErr := canonicalCell(statementRaw, 8192)
		decodedManifest, decodeManifestErr := protocol.DecodePredictionEvidenceManifestV1(manifest)
		decodedStatement, decodeStatementErr := protocol.DecodePredictionResolutionStatementV1(statement)
		if key != record.RoundContextHash || !canonicalDigest(key, "tvm-cell-sha256:") ||
			manifestErr != nil || statementErr != nil || manifestCellErr != nil || statementCellErr != nil ||
			decodeManifestErr != nil || decodeStatementErr != nil ||
			hash32(manifest.Hash()).CellHashString() != record.EvidenceRoot ||
			hash32(statement.Hash()).CellHashString() != record.StatementHash ||
			decodedManifest.RoundContextHash.CellHashString() != record.RoundContextHash ||
			decodedManifest.MarketID != marketID || decodedManifest.RulesHash != rulesHash ||
			decodedManifest.Outcome != record.Outcome || decodedStatement.GlobalID != loaded.Profile.GlobalID ||
			decodedStatement.MarketAddress != loaded.Profile.MarketAddress || decodedStatement.MarketID != marketID ||
			decodedStatement.RulesHash != rulesHash || decodedStatement.RoundPolicyHash != policyHash ||
			decodedStatement.RoundContextHash.CellHashString() != record.RoundContextHash ||
			decodedStatement.Round != record.Round || record.Round != loaded.Profile.Round ||
			decodedStatement.Outcome != record.Outcome || decodedStatement.EvidenceRoot != decodedManifestHash(manifest) ||
			decodedStatement.StatementCreatedAt != record.StatementCreatedAt || decodedStatement.StatementExpiry != record.StatementExpiry {
			return errors.New("prediction oracle journal contains a corrupted vote")
		}
		if len(record.ArchiveReceiptDigests) < 2*len(decodedManifest.Entries) {
			return errors.New("prediction oracle journal lacks independent archive receipts")
		}
		previous := ""
		for _, digest := range record.ArchiveReceiptDigests {
			if !canonicalDigest(digest, "sha256:") {
				return errors.New("prediction oracle receipt digest is invalid")
			}
			if previous != "" && digest <= previous {
				return errors.New("prediction oracle receipt digests are not unique and sorted")
			}
			previous = digest
		}
	}
	journal.doc = loaded
	return nil
}

func decodedManifestHash(manifest *cell.Cell) protocol.Hash32 { return hash32(manifest.Hash()) }

func (journal *OracleJournal) persist(next oracleDocument) error {
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > 8<<20 {
		return errors.New("prediction oracle journal exceeds its durable bound")
	}
	return fileutil.WriteFileAtomic(filepath.Join(journal.directory, oracleStateFile), raw, 0o600)
}

func cloneOracleDocument(value oracleDocument) oracleDocument {
	next := value
	next.Votes = make(map[string]oracleVoteRecord, len(value.Votes))
	for key, record := range value.Votes {
		record.ArchiveReceiptDigests = append([]string(nil), record.ArchiveReceiptDigests...)
		next.Votes[key] = record
	}
	return next
}
