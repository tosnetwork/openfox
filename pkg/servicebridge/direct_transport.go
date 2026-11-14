package servicebridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// DirectSendTimeout bounds one direct delivery, including the recipient's
// finalized-state check of the packet.
const DirectSendTimeout = 60 * time.Second

// maxDirectResponse bounds what is read of a receiver's answer.
const maxDirectResponse = 4 << 10

// Direct transport failures. They are fixed strings: a transport error is
// logged, and nothing a peer's socket answers is repeated.
var (
	ErrNoPacketRoute = errors.New(
		"servicebridge: no route to the recipient Agent: it is not a direct peer and no Messenger is configured",
	)
	ErrDirectSocketInvalid = errors.New(
		"servicebridge: the direct peer socket is missing, a symbolic link or not a socket",
	)
	ErrDirectPacketTooLarge = errors.New("servicebridge: the packet exceeds the receiver's bound")
	ErrDirectUnreachable    = errors.New("servicebridge: the direct peer's receiver could not be reached")
	ErrDirectRefused        = errors.New("servicebridge: the direct peer's receiver did not accept the packet")
)

// DirectTransport delivers a packet to a recipient on the same host by
// posting it to that node's receiver Unix socket, where the receiver
// verifies it against finalized state and stores it durably before it
// answers 202. It is a transport for one user on one host: it gives no
// confidentiality beyond the socket's file permissions and no carrier-level
// admission or rate limiting, and any process of that user can post to the
// socket. The packet's own signature is what the receiver trusts.
type DirectTransport struct {
	// Peers maps a recipient Agent id to its receiver socket.
	Peers   map[string]string
	Timeout time.Duration
}

// Send implements PacketTransport. A nil error means the recipient's
// receiver answered 202: the packet is in its durable inbox.
func (t DirectTransport) Send(ctx context.Context, packet OutboundPacket) error {
	if ctx == nil || !agentIDPattern.MatchString(packet.RecipientAgentID) || len(packet.JSON) == 0 {
		return errors.New("servicebridge: invalid direct packet send")
	}
	path, ok := t.Peers[packet.RecipientAgentID]
	if !ok {
		return ErrNoPacketRoute
	}
	if len(packet.JSON) > maxPacketJSON {
		return ErrDirectPacketTooLarge
	}
	// Lstat does not follow a link, so a link to a socket is refused too.
	info, err := os.Lstat(path)
	if err != nil || !cleanAbsolute(path) || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return ErrDirectSocketInvalid
	}
	timeout := t.Timeout
	if timeout <= 0 || timeout > DirectSendTimeout {
		timeout = DirectSendTimeout
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 8 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		// A receiver never redirects; a redirect is not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://rail-receiver/v1/agent-packet",
		bytes.NewReader(packet.JSON))
	if err != nil {
		return ErrDirectUnreachable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return ErrDirectUnreachable
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxDirectResponse))
	if response.StatusCode != http.StatusAccepted {
		return ErrDirectRefused
	}
	return nil
}

// RoutedTransport sends a packet directly when its recipient is a direct
// peer and through Fallback otherwise. Without a Fallback an unlisted
// recipient has no route, and the send fails rather than being dropped.
type RoutedTransport struct {
	Direct   DirectTransport
	Fallback PacketTransport
}

// Route names the transport a recipient's packets take.
func (t RoutedTransport) Route(recipient string) string {
	if _, ok := t.Direct.Peers[recipient]; ok {
		return RouteDirect
	}
	if t.Fallback != nil {
		return RouteMessenger
	}
	return RouteNone
}

// Packet routes.
const (
	RouteDirect    = "direct"
	RouteMessenger = "messenger"
	RouteNone      = "none"
)

// Send implements PacketTransport.
func (t RoutedTransport) Send(ctx context.Context, packet OutboundPacket) error {
	switch t.Route(packet.RecipientAgentID) {
	case RouteDirect:
		return t.Direct.Send(ctx, packet)
	case RouteMessenger:
		return t.Fallback.Send(ctx, packet)
	default:
		return ErrNoPacketRoute
	}
}

// openPacketTransport builds the node's transport from its configuration
// and fails closed when no recipient could ever be reached.
func openPacketTransport(config NodeConfig) (PacketTransport, error) {
	if err := validateDirectPeers(config.DirectPeers); err != nil {
		return nil, err
	}
	if _, self := config.DirectPeers[config.AgentID]; self {
		return nil, errors.New("servicebridge: direct_peers names this node's own Agent")
	}
	routed := RoutedTransport{Direct: DirectTransport{Peers: config.DirectPeers}}
	if config.MessengerSocket != "" {
		client, err := newMessengerClient(config.MessengerSocket)
		if err != nil {
			return nil, err
		}
		routed.Fallback = MessengerTransport{Client: client}
	}
	if routed.Fallback == nil && len(config.DirectPeers) == 0 {
		return nil, errors.New("servicebridge: the rail node has no packet transport: configure messenger_socket " +
			"or direct_peers")
	}
	return routed, nil
}
