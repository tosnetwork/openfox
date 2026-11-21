package earning

import (
	"errors"
	"fmt"

	guarantor "github.com/tosnetwork/ai/protocol/pkg/agentguarantor"
)

// GuarantorStoredEvidence is one immutable receipt the journal serves by its
// envelope digest: its media type and exact canonical bytes.
type GuarantorStoredEvidence struct {
	ContentType string `json:"content_type"`
	Wire        []byte `json:"wire"`
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
	if position.ImmutableEvidence == nil {
		position.ImmutableEvidence = map[string]GuarantorStoredEvidence{}
	}
	if existing, found := position.ImmutableEvidence[digest]; found {
		if existing.ContentType != contentType || string(existing.Wire) != string(wire) {
			return errors.New("Guarantor immutable evidence conflicts with a stored receipt")
		}
		return nil
	}
	if len(position.ImmutableEvidence) >= maximumGuarantorStoredEvidenceReceipts {
		return errors.New("Guarantor immutable evidence store is full")
	}
	position.ImmutableEvidence[digest] = GuarantorStoredEvidence{ContentType: contentType, Wire: wire}
	return nil
}

// ImmutableEvidence returns the stored receipt a descriptor names. It fails
// closed when the receipt is absent, of another media type, of another
// length, or larger than a Guarantor object may be.
func (journal *GuarantorJournal) ImmutableEvidence(descriptor guarantor.ImmutableEvidenceDescriptorV1) ([]byte, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.ensureAttached(); err != nil {
		return nil, err
	}
	if descriptor.ContentSize == 0 || descriptor.ContentSize > guarantor.MaxCanonicalObjectBytes {
		return nil, errors.New("Guarantor immutable evidence descriptor size is out of bounds")
	}
	for _, position := range journal.doc.Coverages {
		stored, found := position.ImmutableEvidence[descriptor.ContentDigest]
		if !found {
			continue
		}
		if stored.ContentType != descriptor.ContentType || uint64(len(stored.Wire)) != descriptor.ContentSize {
			return nil, errors.New("Guarantor immutable evidence differs from its descriptor")
		}
		return append([]byte(nil), stored.Wire...), nil
	}
	return nil, errors.New("Guarantor immutable evidence is not held")
}

// GuarantorJournalEvidenceResolver adds immutable-evidence retrieval from the
// Guarantor journal to an authority resolver, so compact proofs re-check
// their complete receipts and a late-recovery fallback resolves its
// filing-close receipt. The protocol verifier then decodes the bytes and
// compares their digest with the descriptor.
type GuarantorJournalEvidenceResolver struct {
	guarantor.AuthorityKeyResolver
	Journal *GuarantorJournal
}

// ResolveImmutableGuarantorEvidence implements the protocol's immutable
// evidence resolver.
func (resolver GuarantorJournalEvidenceResolver) ResolveImmutableGuarantorEvidence(
	descriptor guarantor.ImmutableEvidenceDescriptorV1) ([]byte, error) {
	if resolver.Journal == nil {
		return nil, errors.New("Guarantor immutable evidence resolver has no journal")
	}
	return resolver.Journal.ImmutableEvidence(descriptor)
}
