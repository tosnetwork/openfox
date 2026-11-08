package servicebridge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
)

// maxPacketJSON bounds one inbound packet body: the Messenger event bound.
const maxPacketJSON = 128 << 10

// RegistrySessions opens finalized sessions that resolve registry objects.
type RegistrySessions interface {
	BeginRegistrySession(ctx context.Context) (serviceactor.Session, error)
}

// FinalizedAgents resolves Agent state from one fresh finalized checkpoint
// per lookup.
type FinalizedAgents struct {
	Sessions RegistrySessions
	Timeout  time.Duration
}

// ResolveAgent implements agentpacket.AgentResolver.
func (f FinalizedAgents) ResolveAgent(agentID string) (*nativev1.AgentStateV1, bool, error) {
	if f.Sessions == nil || !agentIDPattern.MatchString(agentID) {
		return nil, false, errors.New("servicebridge: invalid Agent resolution")
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	session, err := f.Sessions.BeginRegistrySession(ctx)
	if err != nil {
		return nil, false, err
	}
	state, found, err := session.ResolveRegistry(ctx, agentID)
	if err != nil || !found {
		return nil, false, err
	}
	agent := state.GetAgent()
	if agent == nil || agent.GetAgentId() != agentID {
		return nil, false, errors.New("servicebridge: the registry object is not that Agent")
	}
	return agent, true, nil
}

// Receiver serves the owner-private socket the Messenger posts verified
// Agent Packets to. It verifies every packet again against finalized state,
// stores its frame durably, and only then answers 202, so the Messenger
// keeps any packet this process has not durably taken.
type Receiver struct {
	LocalAgentID string
	Resolver     agentpacket.AgentResolver
	Verifier     mldsa44.Verifier
	Inbox        *Inbox
	// Notify is called after a message completes or a duplicate frame of a
	// processed message arrives. It must not block for long.
	Notify func(InboxStatus, Message)
	Now    func() time.Time
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/v1/agent-packet" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	status, message, err := r.accept(request.Context(), request.Body)
	if err != nil {
		http.Error(w, "refused", http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	if r.Notify != nil && status != InboxPartial && message != nil {
		r.Notify(status, *message)
	}
}

func (r *Receiver) accept(ctx context.Context, body io.Reader) (InboxStatus, *Message, error) {
	if r == nil || r.Resolver == nil || r.Verifier == nil || r.Inbox == nil ||
		!agentIDPattern.MatchString(r.LocalAgentID) {
		return 0, nil, errors.New("servicebridge: receiver is not configured")
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxPacketJSON+1))
	if err != nil || len(raw) == 0 || len(raw) > maxPacketJSON {
		return 0, nil, errors.New("servicebridge: packet body is outside its bounds")
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return 0, nil, err
	}
	if packet.RecipientAgentID != r.LocalAgentID {
		return 0, nil, errors.New("servicebridge: the packet names another recipient")
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	// Replay is handled by the durable inbox; the guard here only lets
	// agentpacket.Verify run every signature and finalized-state check.
	if err = agentpacket.Verify(ctx, r.Verifier, r.Resolver, &agentpacket.ReplayGuard{}, packet, now()); err != nil {
		return 0, nil, err
	}
	frame, err := DecodeFrame(packet.Payload)
	if err != nil {
		return 0, nil, err
	}
	return r.Inbox.Put(packet.SenderAgentID, frame)
}
