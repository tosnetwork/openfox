package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

// sessionAgents resolves Agents at one finalized checkpoint.
type sessionAgents struct {
	ctx     context.Context
	session serviceactor.Session
}

func (s sessionAgents) ResolveAgent(agentID string) (*nativev1.AgentStateV1, bool, error) {
	state, found, err := s.session.ResolveRegistry(s.ctx, agentID)
	if err != nil || !found {
		return nil, false, err
	}
	agent := state.GetAgent()
	if agent == nil || agent.GetAgentId() != agentID {
		return nil, false, errors.New("servicebridge: the registry object is not that Agent")
	}
	return agent, true, nil
}

// sessionOwners reads Capability owners at the same checkpoint.
type sessionOwners struct{ session serviceactor.Session }

func (s sessionOwners) CapabilityOwner(ctx context.Context, capabilityID string) (string, error) {
	state, found, err := s.session.ResolveRegistry(ctx, capabilityID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errCardUnavailable, err)
	}
	capability := state.GetCapability()
	if !found || capability == nil || capability.GetTombstoned() ||
		!agentIDPattern.MatchString(capability.GetOwnerAgentId()) {
		return "", fmt.Errorf("%w: Capability %s has no finalized live owner", ErrCardRefused, capabilityID)
	}
	return capability.GetOwnerAgentId(), nil
}

// checkRelay checks the relay carrier: canonical relay URLs, reachable
// relays, a current own key whose card verifies against finalized state,
// and the held peer cards. It writes nothing into state_dir and signs
// nothing; a missing own key is issued by `serve` or `offer`.
func (p *preflight) checkRelay() {
	if len(p.config.RelayURLs) == 0 {
		// No relay check is reported for a node without relays, so its
		// report is the same as before relays existed.
		return
	}
	relays, err := canonicalRelayURLs(p.config.RelayURLs)
	if err != nil {
		p.addf("relay.config", CheckFail, "%v", err)
		return
	}
	if !slices.Equal(relays, p.config.RelayURLs) {
		p.addf("relay.config", CheckFail, "relay_urls must be in ascending byte order, as the key card lists them")
		return
	}
	p.addf("relay.config", CheckPass, "relays %s (https, or http only on loopback)", strings.Join(relays, ", "))
	dial := p.checkRelayTrust(relays)
	if dial == nil {
		p.addf("relay.reachable", CheckFail, "not run: the relay trust anchor cannot be used")
	} else {
		p.checkRelayReachable(relays, dial)
	}
	key := p.checkRelayKey(relays)
	if !p.requires("relay.card", "relay.key", "chain.finalized", "tosctl.pin") || key == nil {
		if key == nil && p.passed["relay.key"] {
			p.addf("relay.card", CheckUnknown, "not run: no own key card")
		}
		p.addf("relay.peers", CheckUnknown, "not run: the key card checks need finalized state and tosctl")
		return
	}
	verifier, err := p.env.PacketVerifier(p.config)
	if err != nil {
		p.addf("relay.card", CheckFail, "open the tosctl verifier: %v", err)
		return
	}
	agents := sessionAgents{ctx: p.ctx, session: p.session}
	packet, err := agentpacket.DecodeJSON(key.CardJSON)
	if err != nil {
		p.addf("relay.card", CheckFail, "the own key card does not decode")
	} else if _, _, err := agentpacketseal.VerifyKeyCard(p.ctx, verifier, agents, packet, p.env.Now()); err != nil {
		p.addf("relay.card", CheckFail, "the own key card does not verify against finalized checkpoint %d: %v; "+
			"a card signed by a controller no longer in the Agent's policy is unusable", p.session.Checkpoint(), err)
	} else {
		p.addf("relay.card", CheckPass, "the own key card %s verifies against finalized checkpoint %d",
			agentpacketseal.KeyIDText(key.KeyID), p.session.Checkpoint())
	}
	p.checkPeerCards(verifier, agents)
}

// checkChat checks the chat carriage section: its configuration, a current
// chat card that verifies against finalized state, and that the daemon's
// card path holds exactly that card. It writes and signs nothing.
func (p *preflight) checkChat() {
	if p.config.Chat == nil {
		return
	}
	if err := validateChatConfig(p.config); err != nil {
		p.addf("chat.config", CheckFail, "%v", err)
		return
	}
	relays, err := chatRelays(p.config)
	if err != nil {
		p.addf("chat.config", CheckFail, "%v", err)
		return
	}
	p.addf("chat.config", CheckPass, "chat relays %s; carrier socket %s; Messenger carrier socket %s; the "+
		"Messenger packet transport is not configured", strings.Join(relays, ", "), p.config.Chat.CarrierSocket,
		p.config.Chat.MessengerCarrierSocket)
	key, published, err := heldChatCard(p.config, p.env.Now())
	if err != nil {
		p.addf("chat.card", CheckFail, "%v", err)
		return
	}
	if !published {
		p.addf("chat.card", CheckFail, "the card path %s does not hold the current chat card %s; run `openfox "+
			"earning chat republish`", p.config.Chat.CardPath, agentpacketseal.KeyIDText(key.KeyID))
		return
	}
	if !p.requires("chat.card", "chain.finalized", "tosctl.pin") {
		return
	}
	verifier, err := p.env.PacketVerifier(p.config)
	if err != nil {
		p.addf("chat.card", CheckFail, "open the tosctl verifier: %v", err)
		return
	}
	packet, err := agentpacket.DecodeJSON(key.CardJSON)
	if err == nil {
		_, _, err = agentpacketseal.VerifyKeyCard(p.ctx, verifier, sessionAgents{ctx: p.ctx, session: p.session},
			packet, p.env.Now())
	}
	if err != nil {
		p.addf("chat.card", CheckFail, "the chat card %s does not verify against finalized checkpoint %d: %v",
			agentpacketseal.KeyIDText(key.KeyID), p.session.Checkpoint(), err)
		return
	}
	p.addf("chat.card", CheckPass, "the chat card %s, valid until %s, is published at %s and verifies against "+
		"finalized checkpoint %d", agentpacketseal.KeyIDText(key.KeyID),
		time.Unix(int64(key.NotAfterUnix), 0).UTC().Format(time.RFC3339), p.config.Chat.CardPath,
		p.session.Checkpoint())
}

// relayCAExpiryWarning is how close to its expiry a pinned certificate
// makes the trust check warn.
const relayCAExpiryWarning = 30 * 24 * time.Hour

// checkRelayTrust reports the trust anchor each relay is verified against
// and returns the dialer `serve` would use, or nil when a pinned CA file
// cannot be used: unreadable, changed since init, expired or not yet
// valid.
func (p *preflight) checkRelayTrust(relays []string) relayDialer {
	pinned, err := loadRelayCA(p.config)
	if err != nil {
		p.addf("relay.trust", CheckFail, "%v", err)
		return nil
	}
	now := p.env.Now()
	if pinned != nil {
		if err = pinned.checkValidAt(now); err != nil {
			p.addf("relay.trust", CheckFail, "%v; run init again with a current --relay-ca-file", err)
			return nil
		}
	}
	var lines []string
	for _, relay := range relays {
		switch relayTrustOf(p.config, relay) {
		case RelayTrustPinned:
			lines = append(lines, relay+": the pinned CA file only")
		case RelayTrustLoopback:
			lines = append(lines, relay+": plaintext loopback, no TLS")
		default:
			lines = append(lines, relay+": the system trust store")
		}
	}
	status, note := CheckPass, "relays named only by a peer's card use the system trust store"
	if pinned != nil {
		expiry := pinned.notAfter()
		note = fmt.Sprintf("pinned CA file %s (SHA-256 %s, %d certificates, valid until %s); %s", p.config.RelayCAFile,
			pinned.sha256, len(pinned.certificates), expiry.UTC().Format(time.RFC3339), note)
		if expiry.Sub(now) < relayCAExpiryWarning {
			status, note = CheckWarn, note+"; a pinned certificate expires within 30 days"
		}
	}
	p.addf("relay.trust", status, "%s; %s", strings.Join(lines, "; "), note)
	if p.env.RelayDial != nil {
		return p.env.RelayDial
	}
	dial, err := relayDialerFor(p.config)
	if err != nil {
		// The file changed between the two reads; relay.reachable says so.
		return nil
	}
	return dial
}

func (p *preflight) checkRelayReachable(relays []string, dial relayDialer) {
	reached := 0
	var lines []string
	for _, relay := range relays {
		client, err := dial(relay)
		if err != nil {
			lines = append(lines, relay+": the URL cannot be used")
			continue
		}
		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
		description, describeErr := client.Describe(ctx)
		var mailbox int
		var listErr error
		if describeErr == nil {
			listed, err := client.List(ctx, p.config.AgentID)
			listErr, mailbox = err, len(listed.Envelopes)
		}
		cancel()
		switch {
		case describeErr != nil:
			lines = append(lines, relay+": unreachable or not a relay")
		case listErr != nil:
			lines = append(lines, relay+": the mailbox cannot be listed")
		default:
			reached++
			lines = append(lines, fmt.Sprintf("%s: reachable, %d pending envelopes, envelopes up to %d bytes kept "+
				"up to %d s", relay, mailbox, description.MaxEnvelopeBytes, description.MaxTTLSeconds))
		}
	}
	status := CheckPass
	switch {
	case reached == 0:
		status = CheckFail
	case reached < len(relays):
		status = CheckWarn
	}
	p.addf("relay.reachable", status, "%s", strings.Join(lines, "; "))
}

// checkRelayKey reads the own keys without changing them and returns the
// one a peer seals to now.
func (p *preflight) checkRelayKey(relays []string) *OwnRelayKey {
	directory := filepath.Join(p.config.StateDir, relayStateDir, relayKeysDir)
	keys := &RelayKeys{directory: directory, agentID: p.config.AgentID, relays: relays}
	if err := checkPrivateDirectory(directory); err != nil {
		p.addf("relay.key", CheckFail, "no relay key directory; `offer` or `serve` issues the first key")
		return nil
	}
	if err := keys.load(); err != nil {
		p.addf("relay.key", CheckFail, "%v", err)
		return nil
	}
	now := uint64(p.env.Now().Unix())
	for _, key := range keys.keys {
		if key.NotBeforeUnix > now || now >= key.NotAfterUnix || !slices.Equal(key.Relays, relays) {
			continue
		}
		remaining := time.Duration(key.NotAfterUnix-now) * time.Second
		status := CheckPass
		note := "serve issues its successor " + RelaySuccessorLead.String() + " before expiry"
		if remaining < RelaySuccessorLead {
			status, note = CheckWarn, "it expires within the successor lead; serve issues a successor at its next "+
				"maintenance"
		}
		p.addf("relay.key", status, "own key %s is valid until %s (%s); %d keys are held",
			agentpacketseal.KeyIDText(key.KeyID), time.Unix(int64(key.NotAfterUnix), 0).UTC().Format(time.RFC3339),
			note, len(keys.keys))
		copied := key
		return &copied
	}
	p.addf("relay.key", CheckFail, "no held key card is valid now for the configured relays; `offer` or `serve` "+
		"issues one")
	return nil
}

// checkPeerCards verifies every held peer card at the preflight's
// checkpoint, without dropping any.
func (p *preflight) checkPeerCards(verifier mldsa44.Verifier, agents agentpacket.AgentResolver) {
	directory := filepath.Join(p.config.StateDir, relayStateDir, relayPeersDir)
	held, err := readPeerCards(directory)
	if err != nil {
		p.addf("relay.peers", CheckFail, "%v", err)
		return
	}
	if len(held) == 0 {
		p.addf("relay.peers", CheckPass, "no peer key card is held yet; a buyer takes one from an offer file, a "+
			"provider from a task")
		return
	}
	checker := &PeerCards{
		verifier: verifier, agents: agents, owners: sessionOwners{session: p.session},
		now: p.env.Now, loopback: ownRelaysOnLoopback(p.config.RelayURLs),
	}
	status := CheckPass
	var lines []string
	for _, card := range held {
		name := card.AgentID + " " + agentpacketseal.KeyIDText(card.Key.KeyID)
		err := checker.verify(p.ctx, card)
		switch {
		case err == nil:
			lines = append(lines, name+": verifies")
		case errors.Is(err, errCardUnavailable):
			status = CheckFail
			lines = append(lines, name+": cannot be checked now")
		default:
			if status == CheckPass {
				status = CheckWarn
			}
			lines = append(lines, name+": refused (expired or revoked); it is dropped at its next use")
		}
	}
	sort.Strings(lines)
	p.addf("relay.peers", status, "%s", strings.Join(lines, "; "))
}
