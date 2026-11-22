package servicebridge

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

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
	chat := ChatSection(p.config)
	p.addf("chat.config", CheckPass, "chat relays %s; carrier socket %s; Messenger carrier socket %s; the "+
		"Messenger packet transport is not configured", strings.Join(relays, ", "), chat.CarrierSocket,
		chat.MessengerCarrierSocket)
	p.checkChatRooms()
	p.checkChatOwner()
	key, published, err := heldChatCard(p.config, p.env.Now())
	if err != nil {
		p.addf("chat.card", CheckFail, "%v", err)
		return
	}
	if !published {
		p.addf("chat.card", CheckFail, "the card path %s does not hold the current chat card %s; run `openfox "+
			"earning chat republish`", chat.CardPath, agentpacketseal.KeyIDText(key.KeyID))
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
		time.Unix(int64(key.NotAfterUnix), 0).UTC().Format(time.RFC3339), chat.CardPath,
		p.session.Checkpoint())
}

// checkChatRooms reports the room card admissions and the per-peer
// envelope counts against the caps of 24 chat and 16 kind-3 envelopes. It
// reads state only. An unreadable admission record fails: the carrier
// answers every forget of that peer retry until it is repaired. A peer at a
// cap warns: its next envelope of that class is refused peer-cap until the
// peer acknowledges.
func (p *preflight) checkChatRooms() {
	root := filepath.Join(p.config.StateDir, relayStateDir)
	admissions, err := readRoomAdmissions(filepath.Join(root, relayChatRoomAdmissionsDir))
	if err != nil {
		p.addf("chat.rooms", CheckFail, "%v", err)
		return
	}
	var unreadable []string
	for _, admission := range admissions {
		if admission.Unreadable != "" {
			unreadable = append(unreadable, admission.Unreadable)
		}
	}
	if len(unreadable) > 0 {
		p.addf("chat.rooms", CheckFail, "room admission records %s are unreadable; the carrier cannot forget "+
			"those peers' cards until they are repaired or removed", strings.Join(unreadable, ", "))
	} else {
		rooms := roomCardsViews(admissions)
		p.addf("chat.rooms", CheckPass, "%d rooms admitted the chat cards of %d peers", len(rooms), len(admissions))
	}
	counts, err := ReadPeerEnvelopeCounts(filepath.Join(root, relayChatOutboxDir), p.env.Now())
	if err != nil {
		p.addf("chat.peer-caps", CheckFail, "%v", err)
		return
	}
	var full []string
	for _, count := range counts {
		if count.Envelopes >= count.EnvelopeCap || count.RoomEnvelopes >= count.RoomEnvelopeCap {
			full = append(full, fmt.Sprintf("%s (%d of %d chat, %d of %d kind 3)", count.AgentID, count.Envelopes,
				count.EnvelopeCap, count.RoomEnvelopes, count.RoomEnvelopeCap))
		}
	}
	if len(full) > 0 {
		p.addf("chat.peer-caps", CheckWarn, "the journal counts peers at a cap until they acknowledge: %s",
			strings.Join(full, "; "))
		return
	}
	p.addf("chat.peer-caps", CheckPass, "%d peers have envelopes in the journal, none at the cap of %d chat or "+
		"%d kind-3 envelopes; kind-3 deposits are paced to %d per minute per relay, burst %d", len(counts),
		ChatPeerEnvelopeCap, ChatPeerRoomEnvelopeCap, RoomDepositsPerMinute, RoomDepositBurst)
}

// checkChatOwner reports the daemon's private rooms and the room invites it
// holds, read from the owner socket (rooms.list needs no owner signature).
// An owner socket that is configured but does not answer fails: `chat room`
// and `chat invite` would fail the same way.
func (p *preflight) checkChatOwner() {
	chat := ChatSection(p.config)
	if chat == nil || chat.OwnerSocket == "" {
		p.addf("chat.owner", CheckPass, "chat.owner_socket is not configured; room management through openfox "+
			"is off")
		return
	}
	owner, err := chatOwnerClient(p.config)
	var rooms ChatRooms
	if err == nil {
		rooms, err = listChatRooms(p.ctx, owner)
	}
	if err != nil {
		p.addf("chat.owner", CheckFail, "the owner socket %s: %v", chat.OwnerSocket, err)
		return
	}
	authority := 0
	for _, held := range rooms.Rooms {
		if held.IsAuthority {
			authority++
		}
	}
	p.addf("chat.owner", CheckPass, "the owner socket %s answers: %d private rooms held (%d as authority), %d "+
		"room invites pending", chat.OwnerSocket, len(rooms.Rooms), authority, len(rooms.Invites))
}
