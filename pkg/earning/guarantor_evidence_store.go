package earning

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
	"github.com/tosnetwork/openfox/pkg/fileutil"
)

// GuarantorStoredEvidence is one immutable receipt the journal serves by its
// envelope digest. The document records its media type, length and SHA-256;
// the bytes live in their own file in the evidence directory, so a receipt is
// written once instead of with every later document commit. Wire carries the
// bytes only between being stored and being committed (and in prerequisite
// maps); it is never part of the document.
type GuarantorStoredEvidence struct {
	ContentType   string `json:"content_type"`
	ContentSize   uint64 `json:"content_size"`
	ContentSHA256 string `json:"content_sha256"`
	Wire          []byte `json:"-"`
}

// Media types of the receipts a compact proof or a fallback descriptor names.
const (
	guarantorClaimAdmissionMediaType       = "application/vnd.tos.service.agent-guarantor-claim-admission.v1+cbor"
	guarantorDecisionAdmissionMediaType    = "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor"
	guarantorDecisionApplicationMediaType  = "application/vnd.tos.service.agent-guarantor-decision-application.v1+cbor"
	guarantorClaimFilingCloseMediaType     = guarantor.ClaimFilingCloseReceiptMediaTypeV1
	maximumGuarantorStoredEvidenceReceipts = 4096
)

// storeImmutableEvidence records value's canonical bytes under digest. A
// different value under the same digest, or a full store, is refused.
func storeImmutableEvidence(position *GuarantorCoveragePosition, contentType, digest string, value any) error {
	wire, err := guarantor.Canonical(value)
	if err != nil {
		return fmt.Errorf("encode Guarantor immutable evidence: %w", err)
	}
	return storeImmutableWire(position, contentType, digest, wire)
}

// storeImmutableWire records exact canonical bytes under digest, with the same
// conflict and capacity refusals as storeImmutableEvidence.
func storeImmutableWire(position *GuarantorCoveragePosition, contentType, digest string, wire []byte) error {
	if !canonicalSHA256(digest) || contentType == "" || len(wire) == 0 ||
		uint64(len(wire)) > guarantor.MaxCanonicalObjectBytes {
		return errors.New("Guarantor immutable evidence is empty, oversized, or unnamed")
	}
	if position.ImmutableEvidence == nil {
		position.ImmutableEvidence = map[string]GuarantorStoredEvidence{}
	}
	sum := sha256.Sum256(wire)
	contentHash := "sha256:" + hex.EncodeToString(sum[:])
	if existing, found := position.ImmutableEvidence[digest]; found {
		if existing.ContentType != contentType || existing.ContentSize != uint64(len(wire)) ||
			existing.ContentSHA256 != contentHash {
			return errors.New("Guarantor immutable evidence conflicts with a stored receipt")
		}
		return nil
	}
	if len(position.ImmutableEvidence) >= maximumGuarantorStoredEvidenceReceipts {
		return fmt.Errorf("Guarantor immutable evidence store is full: a coverage holds at most %d receipts",
			maximumGuarantorStoredEvidenceReceipts)
	}
	position.ImmutableEvidence[digest] = GuarantorStoredEvidence{ContentType: contentType,
		ContentSize: uint64(len(wire)), ContentSHA256: contentHash, Wire: append([]byte(nil), wire...)}
	return nil
}

// guarantorEvidenceFile is the file holding the receipt stored under digest.
func guarantorEvidenceFile(digest string) (string, error) {
	if !canonicalSHA256(digest) {
		return "", errors.New("Guarantor immutable evidence digest is not canonical")
	}
	return path.Join(guarantorEvidenceDirectory, strings.TrimPrefix(digest, "sha256:")), nil
}

// writeStagedEvidence writes each receipt stored since the last commit to its
// own file and clears its staged bytes. An existing file must hold exactly
// the same bytes.
func (journal *GuarantorJournal) writeStagedEvidence(doc guarantorJournalDocument) error {
	for _, coverage := range doc.Coverages {
		for digest, stored := range coverage.ImmutableEvidence {
			if stored.Wire == nil {
				continue
			}
			name, err := guarantorEvidenceFile(digest)
			if err != nil {
				return err
			}
			if existing, readErr := journal.root.ReadFile(name); readErr == nil {
				if string(existing) != string(stored.Wire) {
					return errors.New("Guarantor immutable evidence file conflicts with a stored receipt")
				}
			} else if !errors.Is(readErr, fs.ErrNotExist) {
				return fmt.Errorf("read Guarantor immutable evidence file: %w", readErr)
			} else if err := fileutil.WriteFileAtomicRoot(journal.root, name, stored.Wire, 0o600); err != nil {
				return fmt.Errorf("write Guarantor immutable evidence file: %w", err)
			}
			stored.Wire = nil
			coverage.ImmutableEvidence[digest] = stored
		}
	}
	return nil
}

// readStoredEvidence returns a committed receipt's bytes after checking them
// against the length and hash the document records.
func (journal *GuarantorJournal) readStoredEvidence(digest string, stored GuarantorStoredEvidence) ([]byte, error) {
	if stored.Wire != nil {
		return nil, errors.New("Guarantor immutable evidence is not committed yet")
	}
	name, err := guarantorEvidenceFile(digest)
	if err != nil {
		return nil, err
	}
	info, err := journal.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || uint64(info.Size()) != stored.ContentSize {
		return nil, errors.New("Guarantor immutable evidence file is missing, insecure, or of another length")
	}
	wire, err := journal.root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read Guarantor immutable evidence file: %w", err)
	}
	sum := sha256.Sum256(wire)
	if uint64(len(wire)) != stored.ContentSize || "sha256:"+hex.EncodeToString(sum[:]) != stored.ContentSHA256 {
		return nil, errors.New("Guarantor immutable evidence file differs from the journal record")
	}
	return wire, nil
}

// checkStoredEvidenceFile is the load-time check of one stored receipt: a
// well-formed record whose file exists with the recorded length.
func (journal *GuarantorJournal) checkStoredEvidenceFile(digest string, stored GuarantorStoredEvidence) error {
	name, err := guarantorEvidenceFile(digest)
	if err != nil || stored.ContentType == "" || stored.ContentSize == 0 ||
		stored.ContentSize > guarantor.MaxCanonicalObjectBytes || !canonicalSHA256(stored.ContentSHA256) {
		return errors.New("Guarantor journal immutable evidence record is invalid")
	}
	info, err := journal.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != stored.ContentSize {
		return fmt.Errorf("Guarantor journal immutable evidence %s has no file of its recorded length", digest)
	}
	return nil
}

// guarantorActivationPrerequisites encodes the activation prerequisite objects
// the operator supplied, keyed by envelope digest, and requires every
// collateral, collateral-control and operational-independence item of the
// prerequisite set to name one of them, so the activation is verified, and
// later re-verified, from the journal alone. An item no supplied object
// matches, or a supplied object the set does not name, fails closed.
func guarantorActivationPrerequisites(set *guarantor.CanonicalGuarantorEvidenceSetV1,
	lock *guarantor.AuthorizedCollateralEvidenceV1, control *guarantor.AuthorizedCollateralControlEvidenceV1,
	independence *guarantor.AuthorizedGuarantorOperationalIndependenceEvidenceV1) (map[string]GuarantorStoredEvidence, error) {
	supplied := map[string]GuarantorStoredEvidence{}
	add := func(contentType string, value any, digest func() (string, error)) error {
		envelope, err := digest()
		if err != nil {
			return fmt.Errorf("Guarantor activation prerequisite %s has no envelope digest: %w", contentType, err)
		}
		wire, err := guarantor.Canonical(value)
		if err != nil {
			return fmt.Errorf("encode Guarantor activation prerequisite %s: %w", contentType, err)
		}
		supplied[envelope] = GuarantorStoredEvidence{ContentType: contentType, Wire: wire}
		return nil
	}
	if lock != nil {
		if err := add(guarantor.CollateralEvidenceContentTypeV1, *lock, func() (string, error) {
			return guarantor.CollateralEvidenceDigestV1(*lock)
		}); err != nil {
			return nil, err
		}
	}
	if control != nil {
		if err := add(guarantor.CollateralControlEvidenceContentTypeV1, *control, func() (string, error) {
			return guarantor.CollateralControlEvidenceDigestV1(*control)
		}); err != nil {
			return nil, err
		}
	}
	if independence != nil {
		if err := add(guarantor.OperationalIndependenceEvidenceContentTypeV1, *independence, func() (string, error) {
			return guarantor.OperationalIndependenceEvidenceDigestV1(*independence)
		}); err != nil {
			return nil, err
		}
	}
	return matchActivationPrerequisites(set, supplied)
}

// matchActivationPrerequisites requires the supplied prerequisite objects and
// the set's collateral, collateral-control and operational-independence items
// to name each other exactly: same envelope digest, media type and length.
func matchActivationPrerequisites(set *guarantor.CanonicalGuarantorEvidenceSetV1,
	supplied map[string]GuarantorStoredEvidence) (map[string]GuarantorStoredEvidence, error) {
	named := map[string]bool{}
	if set != nil {
		for _, item := range set.Items {
			switch item.ContentType {
			case guarantor.CollateralEvidenceContentTypeV1, guarantor.CollateralControlEvidenceContentTypeV1,
				guarantor.OperationalIndependenceEvidenceContentTypeV1:
			default:
				continue
			}
			stored, found := supplied[item.EvidenceEnvelopeDigest]
			if !found || stored.ContentType != item.ContentType || item.ImmutableDescriptor == nil ||
				item.ImmutableDescriptor.ContentSize != uint64(len(stored.Wire)) {
				return nil, fmt.Errorf("Guarantor activation prerequisite %s %s is not supplied with its exact bytes",
					item.ContentType, item.EvidenceEnvelopeDigest)
			}
			named[item.EvidenceEnvelopeDigest] = true
		}
	}
	for digest, stored := range supplied {
		if !named[digest] {
			return nil, fmt.Errorf("Guarantor activation prerequisite %s %s is not named by the prerequisite set",
				stored.ContentType, digest)
		}
	}
	return supplied, nil
}

// pendingEvidenceResolver serves immutable evidence about to be committed with
// the object being verified, ahead of the journal: an activation's
// prerequisites are verified before the commit that stores them. Anything
// else is served by the journal resolver underneath, or refused.
type pendingEvidenceResolver struct {
	guarantor.AuthorityKeyResolver
	pending map[string]GuarantorStoredEvidence
}

func (resolver pendingEvidenceResolver) ResolveImmutableGuarantorEvidence(
	descriptor guarantor.ImmutableEvidenceDescriptorV1) ([]byte, error) {
	if stored, found := resolver.pending[descriptor.ContentDigest]; found {
		if stored.ContentType != descriptor.ContentType || uint64(len(stored.Wire)) != descriptor.ContentSize {
			return nil, errors.New("Guarantor pending immutable evidence differs from its descriptor")
		}
		return append([]byte(nil), stored.Wire...), nil
	}
	base, serves := resolver.AuthorityKeyResolver.(guarantor.ImmutableEvidenceResolver)
	if !serves || base == nil {
		return nil, errors.New("Guarantor immutable evidence is not held")
	}
	return base.ResolveImmutableGuarantorEvidence(descriptor)
}

// ImmutableEvidence returns the stored receipt of agreementDigest's coverage
// that a descriptor names. It fails closed when the coverage or receipt is
// absent (including a receipt held only by another coverage), or the receipt
// has another media type or length, or the descriptor is empty or larger than
// a Guarantor object may be.
func (journal *GuarantorJournal) ImmutableEvidence(agreementDigest string,
	descriptor guarantor.ImmutableEvidenceDescriptorV1) ([]byte, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return nil, err
	}
	if descriptor.ContentSize == 0 || descriptor.ContentSize > guarantor.MaxCanonicalObjectBytes {
		return nil, errors.New("Guarantor immutable evidence descriptor size is out of bounds")
	}
	position, found := journal.doc.Coverages[agreementDigest]
	if !found {
		return nil, errors.New("Guarantor immutable evidence has no such coverage")
	}
	stored, found := position.ImmutableEvidence[descriptor.ContentDigest]
	if !found {
		return nil, errors.New("Guarantor immutable evidence is not held for this coverage")
	}
	if stored.ContentType != descriptor.ContentType || stored.ContentSize != descriptor.ContentSize {
		return nil, errors.New("Guarantor immutable evidence differs from its descriptor")
	}
	return journal.readStoredEvidence(descriptor.ContentDigest, stored)
}

// GuarantorJournalEvidenceResolver adds immutable-evidence retrieval from the
// Guarantor journal to an authority resolver, so compact proofs re-check
// their complete receipts and a late-recovery fallback resolves its
// filing-close receipt. It serves only the receipts of one Agreement's
// coverage. The protocol verifier then decodes the bytes and compares their
// digest with the descriptor.
type GuarantorJournalEvidenceResolver struct {
	guarantor.AuthorityKeyResolver
	Journal         *GuarantorJournal
	AgreementDigest string
}

// ResolveImmutableGuarantorEvidence implements the protocol's immutable
// evidence resolver.
func (resolver GuarantorJournalEvidenceResolver) ResolveImmutableGuarantorEvidence(
	descriptor guarantor.ImmutableEvidenceDescriptorV1) ([]byte, error) {
	if resolver.Journal == nil || !canonicalSHA256(resolver.AgreementDigest) {
		return nil, errors.New("Guarantor immutable evidence resolver has no journal or Agreement")
	}
	return resolver.Journal.ImmutableEvidence(resolver.AgreementDigest, descriptor)
}

// resolverFor is the resolver the coordinator verifies agreementDigest's
// claim lifecycle with: the operator's authority resolver plus immutable
// evidence served from this journal for that Agreement only. An operator
// resolver that already serves immutable evidence is used as it is.
func (coordinator *GuarantorProviderCoordinator) resolverFor(agreementDigest string) guarantor.AuthorityKeyResolver {
	if coordinator.Resolver == nil || coordinator.Journal == nil {
		return coordinator.Resolver
	}
	if _, serves := coordinator.Resolver.(guarantor.ImmutableEvidenceResolver); serves {
		return coordinator.Resolver
	}
	return GuarantorJournalEvidenceResolver{AuthorityKeyResolver: coordinator.Resolver, Journal: coordinator.Journal,
		AgreementDigest: agreementDigest}
}
