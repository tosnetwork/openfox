package earning

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const outcomeCheckpointHead = "checkpoint-head"

type OutcomeJournalCheckpointBodyV1 struct {
	SchemaVersion            uint16 `json:"schema_version"`
	OwnerID                  string `json:"owner_id"`
	AgentID                  string `json:"agent_id"`
	AuthorityID              string `json:"authority_id"`
	OrderingDomain           string `json:"ordering_domain"`
	WriterGeneration         uint64 `json:"writer_generation"`
	LastSequence             uint64 `json:"last_sequence"`
	LastOperationEnvelope    string `json:"last_operation_envelope_digest"`
	LastRecordChecksum       string `json:"last_record_checksum"`
	GapSetDigest             string `json:"gap_set_digest"`
	PreviousCheckpointDigest string `json:"previous_checkpoint_digest"`
	CreatedAtUnix            uint64 `json:"created_at_unix"`
}

type SignedOutcomeJournalCheckpointV1 struct {
	Body             OutcomeJournalCheckpointBodyV1 `json:"body"`
	AuthorizationRef commerce.ProfileRefV1          `json:"authorization_ref"`
	HistoricalProof  []byte                         `json:"historical_proof"`
	PublicKey        string                         `json:"public_key"`
	Signature        string                         `json:"signature"`
}

func (journal *OutcomeJournal) CreateCheckpoint(key ed25519.PrivateKey, authorization commerce.ProfileRefV1,
	historicalProof []byte, resolver commerce.AgentOperationAuthorityResolver, now time.Time) (SignedOutcomeJournalCheckpointV1, string, error) {
	if journal == nil || len(key) != ed25519.PrivateKeySize || commerce.ValidateProfileRefV1(authorization) != nil ||
		len(historicalProof) == 0 || len(historicalProof) > 64<<10 || resolver == nil || now.IsZero() {
		return SignedOutcomeJournalCheckpointV1{}, "", errors.New("outcome checkpoint request is invalid")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.lock == nil {
		return SignedOutcomeJournalCheckpointV1{}, "", errors.New("outcome journal is closed")
	}
	if journal.head.LastSequence == 0 {
		return SignedOutcomeJournalCheckpointV1{}, "", errors.New("empty outcome journal cannot be checkpointed")
	}
	if err := journal.validateRecordChainLocked(resolver, now.UTC()); err != nil {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	previous := "sha256:" + strings.Repeat("0", 64)
	if raw, err := journal.root.ReadFile(outcomeCheckpointHead); err == nil {
		candidate := strings.TrimSpace(string(raw))
		if !canonicalSHA256(candidate) {
			return SignedOutcomeJournalCheckpointV1{}, "", errors.New("outcome checkpoint head is invalid")
		}
		previous = candidate
	} else if !errors.Is(err, os.ErrNotExist) {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	gapDigest, err := codec.Digest("tos.openfox.outcome-journal-gap-set.v1", journal.head.GapSequences)
	if err != nil {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	body := OutcomeJournalCheckpointBodyV1{SchemaVersion: 1, OwnerID: journal.head.OwnerID, AgentID: journal.head.AgentID,
		AuthorityID: journal.head.AuthorityID, OrderingDomain: journal.head.OrderingDomain, WriterGeneration: journal.head.WriterGeneration,
		LastSequence: journal.head.LastSequence, LastOperationEnvelope: journal.head.LastEnvelopeDigest,
		LastRecordChecksum: journal.head.LastRecordChecksum, GapSetDigest: gapDigest, PreviousCheckpointDigest: previous,
		CreatedAtUnix: uint64(now.UTC().Unix())}
	public := key.Public().(ed25519.PublicKey)
	if err := resolver.AuthorizeAgentOperationKey(body.AgentID, authorization, public, now.UTC(), historicalProof); err != nil {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	message, err := outcomeCheckpointMessage(body)
	if err != nil {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	signed := SignedOutcomeJournalCheckpointV1{Body: body, AuthorizationRef: authorization,
		HistoricalProof: append([]byte(nil), historicalProof...), PublicKey: "ed25519:" + hex.EncodeToString(public),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}
	digest, err := OutcomeJournalCheckpointDigestV1(signed)
	if err != nil {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	raw, err := json.Marshal(signed)
	if err != nil || len(raw) > 256<<10 {
		return SignedOutcomeJournalCheckpointV1{}, "", errors.New("outcome checkpoint is oversized")
	}
	if err := writeOutcomeRootExclusive(journal.root, "checkpoint-"+strings.TrimPrefix(digest, "sha256:")+".json", raw); err != nil && !errors.Is(err, os.ErrExist) {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	if err := fileutil.WriteFileAtomicRoot(journal.root, outcomeCheckpointHead, []byte(digest+"\n"), 0o600); err != nil {
		return SignedOutcomeJournalCheckpointV1{}, "", err
	}
	return signed, digest, nil
}

func VerifyOutcomeJournalCheckpointV1(checkpoint SignedOutcomeJournalCheckpointV1,
	resolver commerce.AgentOperationAuthorityResolver, now time.Time) error {
	body := checkpoint.Body
	if body.SchemaVersion != 1 || body.OwnerID == "" || body.AgentID == "" || body.AuthorityID == "" ||
		!canonicalSHA256(body.OrderingDomain) || !canonicalSHA256(body.LastOperationEnvelope) || !canonicalSHA256(body.LastRecordChecksum) ||
		!canonicalSHA256(body.GapSetDigest) || !canonicalSHA256(body.PreviousCheckpointDigest) || body.WriterGeneration == 0 || body.CreatedAtUnix == 0 ||
		commerce.ValidateProfileRefV1(checkpoint.AuthorizationRef) != nil || len(checkpoint.HistoricalProof) == 0 || resolver == nil || now.IsZero() {
		return errors.New("outcome journal checkpoint is invalid")
	}
	publicRaw, err := hex.DecodeString(strings.TrimPrefix(checkpoint.PublicKey, "ed25519:"))
	signature, signatureErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(checkpoint.Signature, "ed25519:"))
	if !strings.HasPrefix(checkpoint.PublicKey, "ed25519:") || !strings.HasPrefix(checkpoint.Signature, "ed25519:") ||
		err != nil || signatureErr != nil || len(publicRaw) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return errors.New("outcome journal checkpoint signature encoding is invalid")
	}
	public := ed25519.PublicKey(publicRaw)
	created := time.Unix(int64(body.CreatedAtUnix), 0).UTC()
	if created.After(now.UTC()) || resolver.AuthorizeAgentOperationKey(body.AgentID, checkpoint.AuthorizationRef, public, created, checkpoint.HistoricalProof) != nil {
		return errors.New("outcome journal checkpoint authority is invalid")
	}
	message, err := outcomeCheckpointMessage(body)
	if err != nil || !ed25519.Verify(public, message, signature) {
		return errors.New("outcome journal checkpoint signature is invalid")
	}
	return nil
}

func OutcomeJournalCheckpointDigestV1(checkpoint SignedOutcomeJournalCheckpointV1) (string, error) {
	if checkpoint.Signature == "" || checkpoint.PublicKey == "" {
		return "", errors.New("unsigned outcome checkpoint")
	}
	return codec.Digest("tos.openfox.outcome-journal-checkpoint-envelope.v1", checkpoint)
}

func outcomeCheckpointMessage(body OutcomeJournalCheckpointBodyV1) ([]byte, error) {
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	return append([]byte("tos.openfox.outcome-journal-checkpoint.v1\x00"), canonical...), nil
}

func (journal *OutcomeJournal) validateRecordChainLocked(resolver commerce.AgentOperationAuthorityResolver, now time.Time) error {
	// Records already owns the journal mutex, so duplicate the minimum chain
	// pass by temporarily reading through a lock-free helper.
	entries, err := readOutcomeRootDirectory(journal.root)
	if err != nil {
		return err
	}
	records := make([]OutcomeJournalRecord, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "record-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, readErr := journal.root.ReadFile(entry.Name())
		var record OutcomeJournalRecord
		if readErr != nil || decodeStrictJSON(raw, &record) != nil {
			return errors.New("outcome checkpoint cannot read the complete journal")
		}
		records = append(records, record)
	}
	sortOutcomeRecords(records)
	previous := ""
	var sequence uint64
	for _, record := range records {
		checksum, checksumErr := outcomeRecordChecksum(record)
		if checksumErr != nil || checksum != record.RecordChecksum || record.PreviousRecordChecksum != previous || record.Sequence <= sequence {
			return errors.New("outcome checkpoint journal chain is invalid")
		}
		for gap := sequence + 1; gap < record.Sequence; gap++ {
			if !containsUint64(journal.head.GapSequences, gap) {
				return errors.New("outcome checkpoint journal has a hidden gap")
			}
		}
		fields, fieldsErr := commerce.OperationJournalAppendSemanticFieldsV1(journal.head.OwnerID, journal.head.AgentID,
			journal.head.OrderingDomain, record.Epoch, record.Sequence, record.EventContentID)
		actionID, _, actionErr := commerce.DeriveStableActionID(outcomeJournalScope, fields)
		var event commerce.OperationOutcomeEventBodyV1
		verified, envelopeErr := commerce.VerifyOperationOutcomeEnvelopeV1(record.Envelope, record.Payload, resolver, now)
		if codec.Unmarshal(record.Payload, &event) != nil || fieldsErr != nil || actionErr != nil || actionID != record.JournalAppendActionID ||
			journal.validateAppendAdmission(record, fields, actionID, journal.head.GapSequences) != nil || envelopeErr != nil || !reflect.DeepEqual(verified, event) ||
			commerce.VerifyOperationOutcomeArtifactBundleV1(event, record.Artifacts) != nil {
			return errors.New("outcome checkpoint journal record authority is invalid")
		}
		previous, sequence = checksum, record.Sequence
	}
	if sequence != journal.head.LastSequence || previous != journal.head.LastRecordChecksum {
		return errors.New("outcome checkpoint does not cover the current head")
	}
	return nil
}

func sortOutcomeRecords(records []OutcomeJournalRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Epoch == records[j].Epoch {
			return records[i].Sequence < records[j].Sequence
		}
		return records[i].Epoch < records[j].Epoch
	})
}

func (journal *OutcomeJournal) validateLatestCheckpointAgainstHeadLocked() error {
	rawHead, err := journal.root.ReadFile(outcomeCheckpointHead)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	digest := strings.TrimSpace(string(rawHead))
	if !canonicalSHA256(digest) {
		return errors.New("outcome checkpoint head is malformed")
	}
	raw, err := journal.root.ReadFile("checkpoint-" + strings.TrimPrefix(digest, "sha256:") + ".json")
	if err != nil || len(raw) > 256<<10 {
		return errors.New("outcome checkpoint head lacks its signed checkpoint")
	}
	var checkpoint SignedOutcomeJournalCheckpointV1
	if decodeStrictJSON(raw, &checkpoint) != nil {
		return errors.New("outcome checkpoint bytes are invalid")
	}
	computed, err := OutcomeJournalCheckpointDigestV1(checkpoint)
	if err != nil || computed != digest {
		return errors.New("outcome checkpoint digest mismatch")
	}
	publicRaw, keyErr := hex.DecodeString(strings.TrimPrefix(checkpoint.PublicKey, "ed25519:"))
	signature, signatureErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(checkpoint.Signature, "ed25519:"))
	message, messageErr := outcomeCheckpointMessage(checkpoint.Body)
	if keyErr != nil || signatureErr != nil || messageErr != nil || len(publicRaw) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(publicRaw), message, signature) {
		return errors.New("outcome checkpoint self-signature is invalid")
	}
	body := checkpoint.Body
	gapsAtCheckpoint := make([]uint64, 0, len(journal.head.GapSequences))
	for _, sequence := range journal.head.GapSequences {
		if sequence <= body.LastSequence {
			gapsAtCheckpoint = append(gapsAtCheckpoint, sequence)
		}
	}
	gapDigest, gapErr := codec.Digest("tos.openfox.outcome-journal-gap-set.v1", gapsAtCheckpoint)
	if body.OwnerID != journal.head.OwnerID || body.AgentID != journal.head.AgentID || body.AuthorityID != journal.head.AuthorityID ||
		body.OrderingDomain != journal.head.OrderingDomain || body.LastSequence > journal.head.LastSequence ||
		gapErr != nil || body.GapSetDigest != gapDigest ||
		body.LastSequence == journal.head.LastSequence && (body.LastRecordChecksum != journal.head.LastRecordChecksum || body.LastOperationEnvelope != journal.head.LastEnvelopeDigest) {
		return errors.New("outcome journal rolled back behind or conflicts with its checkpoint")
	}
	return nil
}
