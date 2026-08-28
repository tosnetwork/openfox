package earning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/openfox/pkg/fileutil"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type directoryOutcomeSelfResolver struct{}

func (directoryOutcomeSelfResolver) AuthorizeAgentOperationKey(string, commerce.ProfileRefV1,
	ed25519.PublicKey, time.Time, []byte) error {
	return nil
}

const maxDirectoryOutcomeRecords = 1_000_000

// DirectoryOutcomeCarrier is an independent owner-private Carrier
// implementation. It shares the wire objects but no database or HTTP server
// with tos-service-gateway, making it useful as the second bounded retention
// path and for database-loss recovery campaigns.
type DirectoryOutcomeCarrier struct {
	mu         sync.Mutex
	carrierID  string
	root       *os.Root
	lock       *os.File
	authority  EconomicAuthority
	carrierKey ed25519.PrivateKey
	now        func() time.Time
}

func OpenDirectoryOutcomeCarrier(directory, carrierID string, authority EconomicAuthority) (*DirectoryOutcomeCarrier, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || carrierID == "" || authority == nil {
		return nil, errors.New("directory outcome Carrier configuration is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("directory outcome Carrier root is not owner-private")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	lock, err := acquireAuthorityLockRoot(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	carrierKey, err := loadOrCreateDirectoryOutcomeKey(root)
	if err != nil {
		_ = releaseAuthorityLock(lock)
		_ = root.Close()
		return nil, err
	}
	return &DirectoryOutcomeCarrier{carrierID: carrierID, root: root, lock: lock, authority: authority,
		carrierKey: carrierKey, now: time.Now}, nil
}

func (carrier *DirectoryOutcomeCarrier) ID() string {
	if carrier == nil {
		return ""
	}
	return carrier.carrierID
}

func (carrier *DirectoryOutcomeCarrier) Close() error {
	if carrier == nil {
		return nil
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	var lockErr, rootErr error
	if carrier.lock != nil {
		lockErr = releaseAuthorityLock(carrier.lock)
		carrier.lock = nil
	}
	if carrier.root != nil {
		rootErr = carrier.root.Close()
		carrier.root = nil
	}
	for index := range carrier.carrierKey {
		carrier.carrierKey[index] = 0
	}
	carrier.carrierKey = nil
	if lockErr != nil {
		return lockErr
	}
	return rootErr
}

func (carrier *DirectoryOutcomeCarrier) PublishOperation(ctx context.Context, action commerce.AuthorizedAction,
	fence commerce.WriterFence, request commerce.OperationCarrierRequestV1) (commerce.ActionResolution, error) {
	if carrier == nil || carrier.root == nil || ctx == nil || ctx.Err() != nil || action.ActionKind != "operation.publish" ||
		request.CarrierID != carrier.carrierID || commerce.ValidateOperationCarrierRequestV1(request) != nil {
		return commerce.ActionResolution{}, errors.New("directory outcome publication is invalid")
	}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields, err := commerce.OperationPublishSemanticFieldsV1(action.OwnerID, action.AgentID, request)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	now := carrier.authority.AuthorityNow()
	if commerce.VerifyAuthorizedAction(action, fields, canonical, fence, carrier.authority, now) != nil ||
		carrier.authority.ConfirmCurrentWriterFence(fence, now) != nil {
		return commerce.ActionResolution{}, errors.New("directory outcome publication Action is not current and exact")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != action.AgentID {
		return commerce.ActionResolution{}, errors.New("directory outcome publisher identity mismatch")
	}
	if _, err := commerce.VerifyOperationOutcomeEnvelopeV1(envelope, request.EventPayload, directoryOutcomeSelfResolver{}, now); err != nil {
		return commerce.ActionResolution{}, errors.New("directory outcome outer signature is invalid")
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if prior, resolveErr := carrier.resolveLocked(action.StableActionID, action.ExactRequestDigest); resolveErr == nil && prior.State != commerce.ActionUnknown {
		if prior.State == commerce.ActionTerminal {
			if _, retainedErr := carrier.readOutcomeLocked(request.OperationEnvelopeDigest); retainedErr != nil {
				return commerce.ActionResolution{}, errors.New("directory outcome Action is terminal but its retained bytes are unavailable")
			}
		}
		return prior, nil
	}
	name := directoryOutcomeName(request.OperationEnvelopeDigest)
	if raw, readErr := carrier.root.ReadFile(name); readErr == nil {
		_, decodeErr := carrier.decodeOutcomeRecord(raw, request.OperationEnvelopeDigest)
		if decodeErr != nil {
			return commerce.ActionResolution{}, errors.New("directory outcome digest conflicts with retained bytes")
		}
		return carrier.completeLocked(action, request.OperationEnvelopeDigest)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return commerce.ActionResolution{}, readErr
	}
	sequence, err := carrier.nextSequenceLocked()
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var body commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(request.EventPayload, &body) != nil {
		return commerce.ActionResolution{}, errors.New("directory outcome body is invalid")
	}
	result := OutcomeCarrierResult{Request: request, EventBody: body, ActorAgentID: action.AgentID,
		StoredAtUnix: uint64(now.UTC().Unix()), CarrierSequence: sequence, Provenance: "carrier-retained-unverified-assertion",
		CarrierPublicKey: "ed25519:" + hex.EncodeToString(carrier.carrierKey.Public().(ed25519.PublicKey))}
	artifactDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", request.Artifacts)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	result.Receipt, err = commerce.SignOperationSubmissionReceiptV1(commerce.OperationSubmissionReceiptV1{SchemaVersion: 1,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest, State: commerce.ActionTerminal,
		SinkID: carrier.carrierID, SinkReference: request.OperationEnvelopeDigest, AuthorityTimeUnix: uint64(now.UTC().Unix()),
		StateRevision: 1, EvidenceDigest: artifactDigest}, carrier.carrierKey)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 4<<20 {
		return commerce.ActionResolution{}, errors.New("directory outcome record is oversized")
	}
	if err := writeOutcomeRootExclusive(carrier.root, name, raw); err != nil {
		return commerce.ActionResolution{}, err
	}
	return carrier.completeLocked(action, request.OperationEnvelopeDigest)
}

func (carrier *DirectoryOutcomeCarrier) completeLocked(action commerce.AuthorizedAction, envelopeDigest string) (commerce.ActionResolution, error) {
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionTerminal, SinkReference: envelopeDigest, EvidenceRefs: []string{envelopeDigest}, StateRevision: 1}
	raw, _ := json.Marshal(resolution)
	if err := writeOutcomeRootExclusive(carrier.root, directoryOutcomeActionName(action.StableActionID), raw); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return commerce.ActionResolution{}, err
		}
		return carrier.resolveLocked(action.StableActionID, action.ExactRequestDigest)
	}
	return resolution, nil
}

func (carrier *DirectoryOutcomeCarrier) ResolveAction(ctx context.Context, actionID, requestDigest string) (commerce.ActionResolution, error) {
	if carrier == nil || carrier.root == nil || ctx == nil || ctx.Err() != nil || !canonicalSHA256(actionID) || !canonicalSHA256(requestDigest) {
		return commerce.ActionResolution{}, errors.New("directory outcome Action query is invalid")
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	return carrier.resolveLocked(actionID, requestDigest)
}

func (carrier *DirectoryOutcomeCarrier) resolveLocked(actionID, requestDigest string) (commerce.ActionResolution, error) {
	raw, err := carrier.root.ReadFile(directoryOutcomeActionName(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest, State: commerce.ActionUnknown, StateRevision: 1}, nil
	}
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	var resolution commerce.ActionResolution
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&resolution) != nil || ensureJSONEOF(decoder) != nil || commerce.ValidateActionResolution(resolution) != nil {
		return commerce.ActionResolution{}, errors.New("directory outcome Action record is invalid")
	}
	if resolution.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{StableActionID: actionID, ExactRequestDigest: requestDigest, State: commerce.ActionConflict,
			StateRevision: resolution.StateRevision + 1}, nil
	}
	if resolution.State == commerce.ActionTerminal {
		if _, retainedErr := carrier.readOutcomeLocked(resolution.SinkReference); retainedErr != nil {
			return commerce.ActionResolution{}, errors.New("directory outcome terminal Action has no valid retained record")
		}
	}
	return resolution, nil
}

func (carrier *DirectoryOutcomeCarrier) SearchOutcomes(ctx context.Context, query OutcomeCarrierQuery) (OutcomeCarrierPage, error) {
	if carrier == nil || carrier.root == nil || ctx == nil || ctx.Err() != nil || query.Limit == 0 || query.Limit > 1000 ||
		query.Wait < 0 || query.Wait > 25*time.Second {
		return OutcomeCarrierPage{}, errors.New("directory outcome query is invalid")
	}
	deadline := carrier.now().Add(query.Wait)
	for {
		page, err := carrier.searchOnce(query)
		if err != nil || len(page.Results) != 0 || query.Wait == 0 || !carrier.now().Before(deadline) {
			return page, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return OutcomeCarrierPage{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (carrier *DirectoryOutcomeCarrier) searchOnce(query OutcomeCarrierQuery) (OutcomeCarrierPage, error) {
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	entries, err := readOutcomeRootDirectory(carrier.root)
	if err != nil {
		return OutcomeCarrierPage{}, err
	}
	results := make([]OutcomeCarrierResult, 0)
	for _, entry := range entries {
		if entry.IsDir() || !isDirectoryOutcomeRecordName(entry.Name()) {
			continue
		}
		raw, readErr := carrier.root.ReadFile(entry.Name())
		if readErr != nil {
			return OutcomeCarrierPage{}, errors.New("directory outcome retained record is unavailable")
		}
		digest := "sha256:" + strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "outcome-"), ".json")
		result, decodeErr := carrier.decodeOutcomeRecord(raw, digest)
		if decodeErr != nil {
			return OutcomeCarrierPage{}, decodeErr
		}
		if !matchesDirectoryOutcome(result, query) {
			continue
		}
		if query.Cursor != "" {
			after, parseErr := parseDirectoryOutcomeCursor(query.Cursor)
			if parseErr != nil {
				return OutcomeCarrierPage{}, parseErr
			}
			if result.CarrierSequence <= after {
				continue
			}
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].CarrierSequence < results[j].CarrierSequence })
	page := OutcomeCarrierPage{CarrierID: carrier.carrierID}
	if len(results) > int(query.Limit) {
		results = results[:query.Limit]
	}
	page.Results = results
	if len(results) == int(query.Limit) {
		page.Next = fmt.Sprintf("seq:%d", results[len(results)-1].CarrierSequence)
	}
	return page, nil
}

func (carrier *DirectoryOutcomeCarrier) readOutcomeLocked(envelopeDigest string) (OutcomeCarrierResult, error) {
	if !canonicalSHA256(envelopeDigest) {
		return OutcomeCarrierResult{}, errors.New("directory outcome digest is invalid")
	}
	raw, err := carrier.root.ReadFile(directoryOutcomeName(envelopeDigest))
	if err != nil {
		return OutcomeCarrierResult{}, err
	}
	return carrier.decodeOutcomeRecord(raw, envelopeDigest)
}

func (carrier *DirectoryOutcomeCarrier) decodeOutcomeRecord(raw []byte, envelopeDigest string) (OutcomeCarrierResult, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return OutcomeCarrierResult{}, errors.New("directory outcome record is oversized")
	}
	var result OutcomeCarrierResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || ensureJSONEOF(decoder) != nil ||
		commerce.ValidateOperationCarrierRequestV1(result.Request) != nil || result.Request.CarrierID != carrier.carrierID ||
		result.Request.OperationEnvelopeDigest != envelopeDigest || result.ActorAgentID == "" || result.StoredAtUnix == 0 || result.CarrierSequence == 0 ||
		result.Provenance != "carrier-retained-unverified-assertion" ||
		commerce.VerifyOperationSubmissionReceiptV1(result.Receipt, carrier.carrierKey.Public().(ed25519.PublicKey)) != nil ||
		result.Receipt.State != commerce.ActionTerminal || result.Receipt.SinkID != carrier.carrierID || result.Receipt.SinkReference != envelopeDigest ||
		result.CarrierPublicKey != "ed25519:"+hex.EncodeToString(carrier.carrierKey.Public().(ed25519.PublicKey)) {
		return OutcomeCarrierResult{}, errors.New("directory outcome retained record is invalid")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	var body commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(result.Request.OperationEnvelope, &envelope) != nil || envelope.Body.ActorAgentID != result.ActorAgentID ||
		codec.Unmarshal(result.Request.EventPayload, &body) != nil || !reflect.DeepEqual(body, result.EventBody) {
		return OutcomeCarrierResult{}, errors.New("directory outcome retained binding is invalid")
	}
	artifactDigest, err := codec.Digest("tos.operation-outcome.artifact-bundle.v1", result.Request.Artifacts)
	if err != nil || artifactDigest != result.Receipt.EvidenceDigest {
		return OutcomeCarrierResult{}, errors.New("directory outcome receipt evidence binding is invalid")
	}
	return result, nil
}

func matchesDirectoryOutcome(result OutcomeCarrierResult, query OutcomeCarrierQuery) bool {
	if query.ActorAgentID != "" && result.ActorAgentID != query.ActorAgentID || query.SubjectProfileURI != "" && result.EventBody.PrimarySubjectRef.SubjectProfileURI != query.SubjectProfileURI ||
		query.SubjectID != "" && result.EventBody.PrimarySubjectRef.SubjectID != query.SubjectID {
		return false
	}
	if len(query.EventKinds) != 0 {
		found := false
		for _, value := range query.EventKinds {
			if value == result.EventBody.EventKind {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if len(query.AssertionProfileURIs) != 0 {
		found := false
		for _, value := range query.AssertionProfileURIs {
			if value == result.EventBody.AssertionProfileURI {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (carrier *DirectoryOutcomeCarrier) nextSequenceLocked() (uint64, error) {
	raw, err := carrier.root.ReadFile("outcome-sequence")
	current := uint64(0)
	if err == nil {
		current, err = strconv.ParseUint(string(raw), 10, 64)
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil || current >= maxDirectoryOutcomeRecords {
		return 0, errors.New("directory outcome sequence is exhausted")
	}
	next := current + 1
	if err := fileutil.WriteFileAtomicRoot(carrier.root, "outcome-sequence", []byte(strconv.FormatUint(next, 10)), 0o600); err != nil {
		return 0, err
	}
	return next, nil
}

func parseDirectoryOutcomeCursor(value string) (uint64, error) {
	if !strings.HasPrefix(value, "seq:") {
		return 0, errors.New("directory outcome cursor is invalid")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "seq:"), 10, 64)
	if err != nil {
		return 0, errors.New("directory outcome cursor is invalid")
	}
	return parsed, nil
}

func directoryOutcomeName(digest string) string {
	return "outcome-" + strings.TrimPrefix(digest, "sha256:") + ".json"
}
func directoryOutcomeActionName(digest string) string {
	return "outcome-action-" + strings.TrimPrefix(digest, "sha256:") + ".json"
}
func isDirectoryOutcomeRecordName(name string) bool {
	return len(name) == len("outcome-")+64+len(".json") && strings.HasPrefix(name, "outcome-") && strings.HasSuffix(name, ".json")
}

func loadOrCreateDirectoryOutcomeKey(root *os.Root) (ed25519.PrivateKey, error) {
	const name = ".outcome-carrier-ed25519"
	info, err := root.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != ed25519.PrivateKeySize {
			return nil, errors.New("directory outcome Carrier key is invalid")
		}
		raw, readErr := root.ReadFile(name)
		if readErr != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("directory outcome Carrier key is unavailable")
		}
		return ed25519.PrivateKey(raw), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeOutcomeRootExclusive(root, name, key); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateDirectoryOutcomeKey(root)
		}
		return nil, err
	}
	return key, nil
}

var _ OutcomePublicationSink = (*DirectoryOutcomeCarrier)(nil)
var _ OutcomeCarrier = (*DirectoryOutcomeCarrier)(nil)
