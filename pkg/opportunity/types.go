// Package opportunity owns OpenFox's bounded, non-authoritative opportunity
// projection. Finalized TOS state remains outside this package behind a narrow
// coordinator interface; scores and journal phases never authorize spending.
package opportunity

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Mode string

const (
	ModeOff         Mode = "off"
	ModeObserve     Mode = "observe"
	ModePolicyGated Mode = "policy-gated"
)

type Network struct {
	ID              string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

type CandidateKey struct {
	Network         Network `json:"network"`
	CapabilityID    string  `json:"capability_id"`
	Version         string  `json:"capability_version"`
	ManifestDigest  string  `json:"manifest_digest"`
	ProviderAgentID string  `json:"provider_agent_id"`
}

type CandidateHint struct {
	Key                CandidateKey `json:"key"`
	GatewayIDs         []string     `json:"gateway_ids"`
	GatewayMatchScore  uint32       `json:"gateway_match_score"`
	HintCheckpoint     uint64       `json:"hint_checkpoint"`
	DisplayName        string       `json:"display_name,omitempty"`
	DisplayDescription string       `json:"display_description,omitempty"`
	OperationHint      string       `json:"operation_hint,omitempty"`
}

type VerifiedCandidate struct {
	Key                 CandidateKey `json:"key"`
	FinalizedCheckpoint uint64       `json:"finalized_checkpoint"`
	TVMStateHash        string       `json:"tvm_state_hash"`
	Operation           string       `json:"operation"`
	ManifestName        string       `json:"manifest_name"`
	VerifiedAtUnix      int64        `json:"verified_at_unix"`
}

type Assessment struct {
	Eligible       bool   `json:"eligible"`
	Score          uint32 `json:"score"`
	Reason         string `json:"reason"`
	AssessedAtUnix int64  `json:"assessed_at_unix"`
}

type SearchRequest struct {
	RequestID      string `json:"request_id"`
	Query          string `json:"query"`
	PageSize       uint32 `json:"page_size"`
	MaxCandidates  uint32 `json:"max_candidates"`
	DeadlineUnixMS int64  `json:"deadline_unix_ms"`
}

type Coordinator interface {
	Search(ctx context.Context, request SearchRequest) ([]CandidateHint, error)
	Verify(ctx context.Context, hint CandidateHint) (VerifiedCandidate, error)
}

type Config struct {
	Mode              Mode
	Queries           []string
	Interval          time.Duration
	Jitter            time.Duration
	RequestTimeout    time.Duration
	PageSize          uint32
	MaxCandidates     uint32
	AllowedOperations []string
	AllowedProviders  []string
	DeniedProviders   []string
}

var (
	agentPattern      = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	capabilityPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	digestPattern     = regexp.MustCompile(`^(sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	requestPattern    = regexp.MustCompile(`^opp-request_[0-9a-f]{64}$`)
)

func (c Config) Validate() error {
	if c.Mode != ModeOff && c.Mode != ModeObserve && c.Mode != ModePolicyGated {
		return errors.New("opportunity mode must be off, observe, or policy-gated")
	}
	if c.Mode == ModeOff {
		if len(c.Queries) != 0 || c.Interval != 0 || c.Jitter != 0 || c.RequestTimeout != 0 ||
			c.PageSize != 0 || c.MaxCandidates != 0 || len(c.AllowedOperations) != 0 ||
			len(c.AllowedProviders) != 0 || len(c.DeniedProviders) != 0 {
			return errors.New("disabled opportunity mode carries unused settings")
		}
		return nil
	}
	if len(c.Queries) == 0 || len(c.Queries) > 16 || c.Interval < 5*time.Minute || c.Interval > 24*time.Hour ||
		c.Jitter < 0 || c.Jitter > c.Interval/2 || c.RequestTimeout < time.Second || c.RequestTimeout > time.Minute ||
		c.PageSize == 0 || c.PageSize > 100 || c.MaxCandidates == 0 || c.MaxCandidates > 1000 {
		return errors.New("opportunity scheduler bounds are invalid")
	}
	for _, query := range c.Queries {
		if !boundedText(query, 1, 256) {
			return errors.New("opportunity query is invalid")
		}
	}
	if err := validateSorted(c.AllowedOperations, 32, func(v string) bool { return boundedToken(v, 64) }); err != nil {
		return errors.New("allowed opportunity operations are invalid")
	}
	if err := validateSorted(c.AllowedProviders, 256, agentPattern.MatchString); err != nil {
		return errors.New("allowed opportunity providers are invalid")
	}
	if err := validateSorted(c.DeniedProviders, 256, agentPattern.MatchString); err != nil {
		return errors.New("denied opportunity providers are invalid")
	}
	for _, provider := range c.AllowedProviders {
		if index := sort.SearchStrings(c.DeniedProviders, provider); index < len(c.DeniedProviders) && c.DeniedProviders[index] == provider {
			return errors.New("opportunity provider is both allowed and denied")
		}
	}
	return nil
}

func validateKey(key CandidateKey) bool {
	return boundedToken(key.Network.ID, 128) && digestPattern.MatchString("sha256:"+key.Network.GenesisRootHash) &&
		digestPattern.MatchString("sha256:"+key.Network.GenesisFileHash) && capabilityPattern.MatchString(key.CapabilityID) &&
		versionPattern.MatchString(key.Version) && strings.HasPrefix(key.ManifestDigest, "sha256:") &&
		digestPattern.MatchString(key.ManifestDigest) && agentPattern.MatchString(key.ProviderAgentID)
}

func validateHint(h CandidateHint) bool {
	if !validateKey(h.Key) || h.HintCheckpoint == 0 || len(h.GatewayIDs) == 0 || len(h.GatewayIDs) > 32 ||
		!boundedText(h.DisplayName, 0, 128) || !boundedText(h.DisplayDescription, 0, 2048) ||
		!boundedText(h.OperationHint, 0, 64) {
		return false
	}
	return validateSorted(h.GatewayIDs, 32, func(v string) bool { return boundedToken(v, 128) }) == nil
}

func validateVerified(v VerifiedCandidate) bool {
	return validateKey(v.Key) && v.FinalizedCheckpoint > 0 && strings.HasPrefix(v.TVMStateHash, "tvm-cell-sha256:") &&
		digestPattern.MatchString(v.TVMStateHash) && boundedToken(v.Operation, 64) && boundedText(v.ManifestName, 1, 128) &&
		v.VerifiedAtUnix > 0
}

func boundedText(value string, min, max int) bool {
	return len(value) >= min && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r")
}

func boundedToken(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func validateSorted(values []string, max int, valid func(string) bool) error {
	if len(values) > max {
		return errors.New("too many values")
	}
	for i, value := range values {
		if !valid(value) || (i > 0 && values[i-1] >= value) {
			return errors.New("values must be valid, sorted, and unique")
		}
	}
	return nil
}
