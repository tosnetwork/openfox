package earning

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// OutcomeImportVerifier separates transport retention from the two authorities
// that make an Outcome usable as local evidence. A Carrier receipt proves only
// that the Carrier retained the bytes; it never satisfies either verifier.
type OutcomeImportVerifier struct {
	CarrierReceiptKey ed25519.PublicKey
	Operation         commerce.AgentOperationAuthorityResolver
	Evidence          commerce.OutcomeEvidenceAuthorityVerifierV1
	PayloadEvidence   OutcomePayloadEvidenceBindingVerifier
}

// OutcomePayloadEvidenceBindingVerifier is implemented by the selected
// finality, meter, invoice, Gate, delivery, or other source Adapter. Generic
// issuer qualification proves who was permitted to assert an evidence object;
// this separate pass must parse that exact object and prove it describes every
// authority-relevant field in the assertion payload. A Carrier receipt or a
// matching digest alone is insufficient.
type OutcomePayloadEvidenceBindingVerifier interface {
	VerifyOutcomePayloadEvidenceBinding(commerce.OperationOutcomeEventBodyV1, []byte,
		commerce.OutcomeEvidenceManifestV1, commerce.OutcomeAuthorityAssessmentV1, time.Time) error
}

type OutcomeImportRejection struct {
	Index                   int    `json:"index"`
	ActorAgentID            string `json:"actor_agent_id,omitempty"`
	OperationID             string `json:"operation_id,omitempty"`
	OperationEnvelopeDigest string `json:"operation_envelope_digest,omitempty"`
	Stage                   string `json:"stage"`
	Reason                  string `json:"reason"`
}

type OutcomePageImportResult struct {
	CarrierID string                     `json:"carrier_id"`
	Next      string                     `json:"next_cursor,omitempty"`
	Processed int                        `json:"processed"`
	Accepted  []VerifiedOutcomeAssertion `json:"accepted"`
	Rejected  []OutcomeImportRejection   `json:"rejected"`
}

// ImportOutcomeCarrierPage verifies every retained item independently and
// returns an audit result for the complete page. Per-item failures are data,
// not a fail-fast page error. Callers may persist page.Next only after they have
// durably retained this complete result.
func ImportOutcomeCarrierPage(page OutcomeCarrierPage, projection *OutcomeProjection,
	verifier OutcomeImportVerifier, now time.Time) (OutcomePageImportResult, error) {
	result := OutcomePageImportResult{CarrierID: page.CarrierID, Next: page.Next,
		Accepted: []VerifiedOutcomeAssertion{}, Rejected: []OutcomeImportRejection{}}
	if projection == nil || len(verifier.CarrierReceiptKey) != ed25519.PublicKeySize || verifier.Operation == nil ||
		verifier.Evidence == nil || verifier.PayloadEvidence == nil || now.IsZero() || page.CarrierID == "" {
		return result, errors.New("outcome page importer is incomplete")
	}
	result.Processed = len(page.Results)
	for index, retained := range page.Results {
		rejection := OutcomeImportRejection{Index: index, ActorAgentID: retained.ActorAgentID,
			OperationID: retained.Request.OperationID, OperationEnvelopeDigest: retained.Request.OperationEnvelopeDigest}
		if err := validateImportedCarrierResult(retained, page.CarrierID, verifier.CarrierReceiptKey); err != nil {
			rejection.Stage, rejection.Reason = "carrier_binding", err.Error()
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		var envelope commerce.AgentOperationEnvelopeV1
		if err := codec.Unmarshal(retained.Request.OperationEnvelope, &envelope); err != nil {
			rejection.Stage, rejection.Reason = "operation_envelope", "retained operation envelope is not canonical"
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		body, err := commerce.VerifyOperationOutcomeEnvelopeV1(envelope, retained.Request.EventPayload,
			verifier.Operation, now.UTC())
		if err != nil {
			rejection.Stage, rejection.Reason = "operation_authority", err.Error()
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		artifacts := retained.Request.Artifacts
		if err := verifyOperationOutcomeArtifactBundleForCurrentDependency(body, artifacts); err != nil {
			rejection.Stage, rejection.Reason = "artifacts", err.Error()
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		assessment, err := commerce.VerifyOperationOutcomeAuthorityV1(body, artifacts.EvidenceManifest,
			artifacts.AuthorityProofs, verifier.Evidence, now.UTC())
		if err != nil || !assessment.AuthorityQualified {
			rejection.Stage = "evidence_authority"
			if err != nil {
				rejection.Reason = err.Error()
			} else {
				rejection.Reason = "outcome assertion profile is not authority-qualifiable"
			}
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		if err := verifier.PayloadEvidence.VerifyOutcomePayloadEvidenceBinding(body, artifacts.AssertionPayload,
			artifacts.EvidenceManifest, assessment, now.UTC()); err != nil {
			rejection.Stage, rejection.Reason = "payload_evidence_binding", err.Error()
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		accepted, err := projection.ingestAuthorityQualified(envelope, retained.Request.EventPayload,
			artifacts.AssertionPayload, artifacts.EvidenceManifest, artifacts.ExtensionSet, verifier.Operation,
			artifacts.AuthorityProofs, verifier.Evidence, now.UTC(), true)
		if err != nil {
			rejection.Stage, rejection.Reason = "projection", err.Error()
			result.Rejected = append(result.Rejected, rejection)
			continue
		}
		result.Accepted = append(result.Accepted, accepted)
	}
	return result, nil
}

func verifyOperationOutcomeArtifactBundleForCurrentDependency(body commerce.OperationOutcomeEventBodyV1,
	bundle commerce.OperationOutcomeArtifactBundleV1) error {
	if err := commerce.VerifyOperationOutcomeArtifactBundleV1(body, bundle); err == nil {
		return nil
	}
	if err := verifyOperationOutcomeArtifactsForCurrentDependency(body, bundle.AssertionPayload,
		bundle.EvidenceManifest, bundle.ExtensionSet); err != nil {
		return err
	}
	if body.AssertionProfileURI != commerce.OutcomeProfileCost {
		return errors.New("outcome artifact bundle is invalid")
	}
	var value commerce.CostObservationPayloadV1
	if codec.Unmarshal(bundle.AssertionPayload, &value) != nil || value.CostClass == "contra" {
		return errors.New("cost artifact bundle is invalid")
	}
	value.OriginalCostAssertionRef = commerce.OutcomeAssertionRefV1{NetworkID: "compatibility:genesis",
		ActorAgentID: "compatibility:genesis", OperationID: zeroSHA256Digest(), OperationEnvelopeDigest: zeroSHA256Digest()}
	compatiblePayload, err := codec.Marshal(value)
	if err != nil {
		return err
	}
	compatibleBody := body
	compatibleBody.AssertionPayloadDigest, err = commerce.OutcomeAssertionPayloadDigestV1(body.AssertionProfileURI, compatiblePayload)
	if err != nil {
		return err
	}
	compatibleBody.AssertionPayloadSize = uint64(len(compatiblePayload))
	compatibleBundle := bundle
	compatibleBundle.AssertionPayload = compatiblePayload
	return commerce.VerifyOperationOutcomeArtifactBundleV1(compatibleBody, compatibleBundle)
}

func validateOperationCarrierRequestForCurrentDependency(request commerce.OperationCarrierRequestV1) error {
	if err := commerce.ValidateOperationCarrierRequestV1(request); err == nil {
		return nil
	}
	if request.SchemaVersion != 1 || !boundedOutcomeTransportToken(request.CarrierID, 256) ||
		commerce.ValidateProfileRefV1(request.CarrierProfile) != nil || !canonicalSHA256(request.AudiencePolicyDigest) ||
		!canonicalSHA256(request.OperationID) || !canonicalSHA256(request.OperationEnvelopeDigest) ||
		len(request.OperationEnvelope) == 0 || len(request.OperationEnvelope) > commerce.MaxAgentOperationEnvelopeBytes {
		return errors.New("operation Carrier request is invalid")
	}
	var envelope commerce.AgentOperationEnvelopeV1
	if codec.Unmarshal(request.OperationEnvelope, &envelope) != nil {
		return errors.New("operation envelope bytes are not canonical")
	}
	envelopeDigest, err := commerce.AgentOperationEnvelopeDigestV1(envelope)
	if err != nil || envelopeDigest != request.OperationEnvelopeDigest || envelope.Body.OperationID != request.OperationID {
		return errors.New("operation request envelope binding is invalid")
	}
	payloadDigest, err := commerce.AgentOperationPayloadDigest(envelope.Body.PayloadProfile, request.EventPayload)
	if err != nil || payloadDigest != envelope.Body.PayloadDigest || uint64(len(request.EventPayload)) != envelope.Body.PayloadSize {
		return errors.New("operation request event payload binding is invalid")
	}
	var body commerce.OperationOutcomeEventBodyV1
	if codec.Unmarshal(request.EventPayload, &body) != nil || body.AssertionProfileURI != commerce.OutcomeProfileCost {
		return errors.New("operation request event body is invalid")
	}
	return verifyOperationOutcomeArtifactBundleForCurrentDependency(body, request.Artifacts)
}

func boundedOutcomeTransportToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateImportedCarrierResult(retained OutcomeCarrierResult, carrierID string, receiptKey ed25519.PublicKey) error {
	if err := validateHTTPOutcomeResult(retained, carrierID, receiptKey); err != nil {
		return fmt.Errorf("Carrier retention binding is invalid: %w", err)
	}
	return nil
}
