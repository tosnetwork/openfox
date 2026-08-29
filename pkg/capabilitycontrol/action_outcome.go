package capabilitycontrol

import (
	"bytes"
	"encoding/hex"
	"errors"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func capabilityUseRequestDigest(domainKind uint8, domainID []byte, binding trusted.CapabilityUseBindingV1) ([]byte, error) {
	object, err := trusted.NewObject(trusted.DomainKind(domainKind), domainID, "capability-use-binding", binding)
	if err != nil {
		return nil, err
	}
	return trusted.ObjectDigest(object)
}

// RecoverAmbiguousAction applies a terminal observation only when it is a
// current-policy, profile-authorized signature over the exact ambiguous
// action. The evidence is not an execution authorization and cannot create a
// record that was not already ambiguous.
func (s *Store) RecoverAmbiguousAction(request ActionOutcomeRecoveryRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Initialized {
		return errors.New("owner trust root is not initialized")
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	var evidence trusted.ActionOutcomeEvidenceV1
	if err := trusted.DecodeBody(request.Object, "action-outcome-evidence", &evidence); err != nil || trusted.ValidateActionOutcomeEvidence(evidence, now) != nil {
		return errors.New("action outcome evidence is invalid")
	}
	if request.Object.DomainKind != s.state.DomainKind || !bytes.Equal(request.Object.DomainID, s.state.DomainID) ||
		!bytes.Equal(evidence.OwnerID, s.state.OwnerID) || !bytes.Equal(evidence.AgentID, s.state.AgentID) ||
		!bytes.Equal(evidence.SinkAuthorityID, request.Envelope.Body.IssuerSubject.Identifier) {
		return errors.New("action outcome domain, owner, Agent, or sink authority mismatch")
	}
	if err := trusted.VerifyAuthorization(request.Envelope, request.Object, now, s.state.AuthorityEpoch); err != nil {
		return err
	}
	if err := s.verifyPolicyAuthorizationLocked(request.Envelope, "action-outcome", evidence.AgentID); err != nil {
		return err
	}
	evidenceDigest, err := trusted.ObjectDigest(request.Object)
	if err != nil {
		return err
	}
	var mcpRecord MCPToolAction
	var useSlot UseSlot
	var recordKey string
	switch evidence.ActionKind {
	case "mcp-tool":
		key := hex.EncodeToString(evidence.ActionID)
		record, ok := s.state.MCPToolActions[key]
		if !ok || record.State != "ambiguous" || !bytes.Equal(record.ExactRequestDigest, evidence.ExactRequestDigest) ||
			!bytes.Equal(record.OutcomeAuthorityID, evidence.SinkAuthorityID) || record.OutcomeAuthorityEpoch != evidence.SinkEpoch {
			return errors.New("outcome does not bind the exact ambiguous MCP action")
		}
		recordKey, mcpRecord = key, record
	case "capability-use":
		key := hex.EncodeToString(*evidence.ExecutionID)
		slot, ok := s.state.UseSlots[key]
		if !ok || slot.State != "ambiguous" || !bytes.Equal(slot.ExecutionID, *evidence.ExecutionID) ||
			!bytes.Equal(slot.ActionID, evidence.ActionID) || !bytes.Equal(slot.ExactRequestDigest, evidence.ExactRequestDigest) ||
			!bytes.Equal(slot.OutcomeAuthorityID, evidence.SinkAuthorityID) || slot.OutcomeAuthorityEpoch != evidence.SinkEpoch {
			return errors.New("outcome does not bind the exact ambiguous capability execution")
		}
		recordKey, useSlot = key, slot
	default:
		return errors.New("unsupported ambiguous action kind")
	}
	if err := s.acceptAuthorityHeadLocked(request.Envelope); err != nil {
		return err
	}
	if evidence.ActionKind == "mcp-tool" {
		mcpRecord.State, mcpRecord.TerminalDisposition, mcpRecord.ResolvedAtUnix = "terminal", evidence.Disposition, now
		mcpRecord.ResultDigest = append([]byte(nil), evidence.ResultDigest...)
		mcpRecord.OutcomeEvidenceDigest = evidenceDigest
		s.state.MCPToolActions[recordKey] = mcpRecord
	} else {
		useSlot.State, useSlot.TerminalDisposition, useSlot.ResolvedAtUnix = "terminal", evidence.Disposition, now
		useSlot.ResultDigest = append([]byte(nil), evidence.ResultDigest...)
		useSlot.OutcomeEvidenceDigest = evidenceDigest
		s.state.UseSlots[recordKey] = useSlot
	}
	s.state.InventoryRevision++
	return s.commitAuthorityLocked()
}
