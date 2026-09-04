package prediction

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"sort"
	"testing"

	protocol "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func oracleFixture(t *testing.T, round protocol.Round) (OracleProfile, []ed25519.PrivateKey) {
	t.Helper()
	keys := []ed25519.PrivateKey{
		ed25519.NewKeyFromSeed(bytesOf(0x71, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytesOf(0x72, ed25519.SeedSize)),
	}
	authorities := make([]ArchiveAuthority, 0, len(keys))
	for _, key := range keys {
		operator, err := ArchiveOperatorID(key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		var public [ed25519.PublicKeySize]byte
		copy(public[:], key.Public().(ed25519.PublicKey))
		authorities = append(authorities, ArchiveAuthority{OperatorID: operator, PublicKey: public})
	}
	sort.Slice(authorities, func(i, j int) bool { return authorities[i].OperatorID < authorities[j].OperatorID })
	return OracleProfile{GlobalID: 42, MarketAddress: rawAddress(0x11),
		MarketID: testHash(0x22).CellHashString(), RulesHash: testHash(0x44).SHA256String(),
		RoundPolicyHash: testHash(0x55).CellHashString(), ReporterAddress: rawAddress(0x77),
		Round: round, ClaimDeadline: 30_000, AuditRetention: 1_000,
		ArchiveAuthorities: authorities}, keys
}

func archivedEvidence(t *testing.T, keys []ed25519.PrivateKey) []ArchivedEvidence {
	t.Helper()
	content := []byte(`{"winner":"yes","precincts_reporting":100}`)
	digest := protocol.Hash32(sha256.Sum256(content))
	locator := "tos-cas-sha256:" + bytesToHex(digest[:])
	entry := protocol.EvidenceEntryV1{SourceKind: protocol.SourceHTTPS,
		CanonicalSourceID: "https://example.gov/results", ContentDigest: digest,
		ArchiveLocator: locator, PublicationTimeSeconds: 10_900, EventTimeSeconds: 10_800,
		ParserProfileVersion: "election-json/v1"}
	receipts := make([]ArchiveReceipt, 0, len(keys))
	for _, key := range keys {
		receipt, err := SignArchiveReceipt(key, digest, locator, 10_950, 31_000)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	return []ArchivedEvidence{{Entry: entry, Content: content, Receipts: receipts}}
}

func TestOracleJournalCommitsEvidenceBeforeVoteAndRejectsEquivocation(t *testing.T) {
	profile, archiveKeys := oracleFixture(t, protocol.RoundNormal)
	directory := filepath.Join(t.TempDir(), "oracle")
	journal, err := OpenOracleJournal(directory, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	context, err := protocol.BuildPredictionNormalContextCell(protocol.PredictionNormalContextV1{
		MarketID: testHash(0x22), RulesHash: testHash(0x44), NormalRoundNonce: testHash(0x66),
		NormalRoundOpenedAt: 10_500, ResolveNotBefore: 10_000, OracleVoteDeadline: 12_000})
	if err != nil {
		t.Fatal(err)
	}
	evidence := archivedEvidence(t, archiveKeys)
	plan, err := journal.PrepareVote(context.ToBOC(), nil, protocol.OutcomeYes, evidence, 11_000)
	if err != nil {
		t.Fatal(err)
	}
	if plan.StatementExpiry != 12_000 || plan.StatementCreatedAt != 11_000 || len(plan.ArchiveReceiptDigests) != 2 {
		t.Fatalf("unexpected vote plan: %+v", plan)
	}
	statementCell, err := cell.FromBOC(plan.StatementBOC)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := protocol.DecodePredictionResolutionStatementV1(statementCell)
	if err != nil || statement.Round != protocol.RoundNormal || statement.Outcome != protocol.OutcomeYes ||
		statement.EvidenceRoot.CellHashString() != plan.EvidenceRoot {
		t.Fatalf("statement does not bind the verified evidence: %+v err=%v", statement, err)
	}

	// A retry at a later wall-clock second must return the originally committed
	// bytes, not manufacture a new created_at and falsely flag itself.
	retry, err := journal.PrepareVote(context.ToBOC(), nil, protocol.OutcomeYes, evidence, 11_001)
	if err != nil || !bytes.Equal(retry.StatementBOC, plan.StatementBOC) {
		t.Fatalf("exact vote recovery failed: %v", err)
	}
	if _, err := journal.PrepareVote(context.ToBOC(), nil, protocol.OutcomeNo, evidence, 11_001); err == nil {
		t.Fatal("same reporter journal equivocated for one round context")
	}

	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenOracleJournal(directory, profile)
	if err != nil {
		t.Fatalf("durable oracle vote did not recover: %v", err)
	}
	recovered, err := journal.PrepareVote(context.ToBOC(), nil, protocol.OutcomeYes, evidence, 11_002)
	if err != nil || !bytes.Equal(recovered.StatementBOC, plan.StatementBOC) {
		t.Fatalf("recovered journal changed exact vote bytes: %v", err)
	}
}

func TestOracleRequiresTwoIndependentSignedArchivesAndExactReviewBase(t *testing.T) {
	profile, archiveKeys := oracleFixture(t, protocol.RoundAppeal)
	journal, err := OpenOracleJournal(filepath.Join(t.TempDir(), "oracle"), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	base, err := protocol.BuildPredictionReviewBaseContextCell(protocol.PredictionReviewBaseContextV1{
		MarketID: testHash(0x22), RulesHash: testHash(0x44), Reason: protocol.ReviewNormalTimeout,
		ReviewStartedAt: 10_500, ReviewVoteNotBefore: 10_600, AppealDeadline: 12_000})
	if err != nil {
		t.Fatal(err)
	}
	vote, err := protocol.BuildPredictionReviewVoteContextCell(protocol.PredictionReviewVoteContextV1{
		ReviewBaseContextHash: hash32(base.Hash()), ReviewRoundNonce: testHash(0x88), ReviewRoundOpenedAt: 10_700})
	if err != nil {
		t.Fatal(err)
	}
	evidence := archivedEvidence(t, archiveKeys)
	oneArchive := archivedEvidence(t, archiveKeys)
	oneArchive[0].Receipts = oneArchive[0].Receipts[:1]
	if _, err := journal.PrepareVote(vote.ToBOC(), base.ToBOC(), protocol.OutcomeInvalid, oneArchive, 11_000); err == nil {
		t.Fatal("one archive operator was treated as durable evidence")
	}
	tampered := archivedEvidence(t, archiveKeys)
	tampered[0].Receipts[0].Signature[0] ^= 1
	if _, err := journal.PrepareVote(vote.ToBOC(), base.ToBOC(), protocol.OutcomeInvalid, tampered, 11_000); err == nil {
		t.Fatal("tampered archive receipt signature was accepted")
	}
	wrongBase, _ := protocol.BuildPredictionReviewBaseContextCell(protocol.PredictionReviewBaseContextV1{
		MarketID: testHash(0x22), RulesHash: testHash(0x44), Reason: protocol.ReviewNormalTimeout,
		ReviewStartedAt: 10_501, ReviewVoteNotBefore: 10_600, AppealDeadline: 12_000})
	if _, err := journal.PrepareVote(vote.ToBOC(), wrongBase.ToBOC(), protocol.OutcomeInvalid, evidence, 11_000); err == nil {
		t.Fatal("review vote was detached from its exact base context")
	}
	if _, err := journal.PrepareVote(vote.ToBOC(), base.ToBOC(), protocol.OutcomeInvalid, evidence, 11_000); err != nil {
		t.Fatalf("valid appellate vote rejected: %v", err)
	}
}

func bytesToHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, octet := range value {
		encoded[index*2] = alphabet[octet>>4]
		encoded[index*2+1] = alphabet[octet&15]
	}
	return string(encoded)
}
