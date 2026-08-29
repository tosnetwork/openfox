package capabilitycontrol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var ErrAmbiguousMCPAction = errors.New("MCP action is prepared or ambiguous and cannot be replayed")

// PrepareMCPAction durably fences an exact MCP request before any bytes are
// written to the child process. A prior non-terminal request with the same
// digest blocks even when a caller attempts to allocate a different Action ID.
func (s *Store) PrepareMCPAction(actionID, exactRequestDigest []byte) ([]byte, error) {
	if len(actionID) != sha256.Size || len(exactRequestDigest) != sha256.Size {
		return nil, errors.New("MCP action identity is invalid")
	}
	resolutionToken := make([]byte, sha256.Size)
	if _, err := rand.Read(resolutionToken); err != nil {
		return nil, errors.New("MCP resolution capability generation failed")
	}
	tokenDigest := mcpResolutionTokenDigest(actionID, exactRequestDigest, resolutionToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireNewCapabilityWorkLocked(); err != nil {
		return nil, err
	}
	outcomeAuthority, err := s.singleOutcomeAuthorityLocked()
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(actionID)
	if prior, ok := s.state.MCPToolActions[key]; ok {
		if !bytes.Equal(prior.ExactRequestDigest, exactRequestDigest) {
			return nil, errors.New("MCP Action ID conflicts with another exact request")
		}
		return nil, ErrAmbiguousMCPAction
	}
	for _, prior := range s.state.MCPToolActions {
		if bytes.Equal(prior.ExactRequestDigest, exactRequestDigest) && (prior.State == "prepared" || prior.State == "ambiguous") {
			return nil, ErrAmbiguousMCPAction
		}
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return nil, err
	}
	s.state.MCPToolActions[key] = MCPToolAction{ActionID: append([]byte(nil), actionID...), ExactRequestDigest: append([]byte(nil), exactRequestDigest...),
		ResolutionTokenDigest: tokenDigest, State: "prepared", PreparedAtUnix: now,
		OutcomeAuthorityID: outcomeAuthority, OutcomeAuthorityEpoch: s.state.AuthorityEpoch}
	s.state.InventoryRevision++
	if err := s.commitAuthorityLocked(); err != nil {
		return nil, err
	}
	return resolutionToken, nil
}

func (s *Store) singleOutcomeAuthorityLocked() ([]byte, error) {
	values := s.state.AuthorizedSubjects["action-outcome"]
	if len(values) != 1 || len(values[0]) != sha256.Size {
		return nil, errors.New("exactly one policy-bound outcome authority is required at action admission")
	}
	return append([]byte(nil), values[0]...), nil
}

func (s *Store) ResolveMCPAction(actionID, exactRequestDigest, resolutionToken []byte, disposition string) error {
	if disposition != "succeeded" && disposition != "failed" && disposition != "ambiguous" {
		return errors.New("MCP action disposition is invalid")
	}
	if len(resolutionToken) != sha256.Size {
		return errors.New("MCP resolution capability is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(actionID)
	record, ok := s.state.MCPToolActions[key]
	if !ok || !bytes.Equal(record.ExactRequestDigest, exactRequestDigest) || !bytes.Equal(record.ResolutionTokenDigest, mcpResolutionTokenDigest(actionID, exactRequestDigest, resolutionToken)) || record.State != "prepared" && record.State != "ambiguous" {
		return errors.New("MCP action is absent, conflicting, or already terminal")
	}
	if record.State == "ambiguous" {
		if disposition == "ambiguous" {
			return nil
		}
		// A transport failure means the sink may already have performed the
		// effect. The launch-time capability proves who prepared the request,
		// not what the sink ultimately did, so it can never clear ambiguity.
		return errors.New("ambiguous MCP action requires authoritative sink evidence")
	}
	now, err := s.trustedNowLocked()
	if err != nil {
		return err
	}
	record.State, record.ResolvedAtUnix = disposition, now
	s.state.MCPToolActions[key] = record
	s.state.InventoryRevision++
	return s.commitAuthorityLocked()
}

func mcpResolutionTokenDigest(actionID, requestDigest, token []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte("openfox.mcp-resolution-capability.v1"))
	hash.Write([]byte{0})
	hash.Write(actionID)
	hash.Write(requestDigest)
	hash.Write(token)
	return hash.Sum(nil)
}

func (s *Store) MCPAction(actionID []byte) (MCPToolAction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.MCPToolActions[hex.EncodeToString(actionID)]
	record.ActionID = append([]byte(nil), record.ActionID...)
	record.ExactRequestDigest = append([]byte(nil), record.ExactRequestDigest...)
	record.ResolutionTokenDigest = append([]byte(nil), record.ResolutionTokenDigest...)
	return record, ok
}
