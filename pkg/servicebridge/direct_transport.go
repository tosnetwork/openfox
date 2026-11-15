package servicebridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
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
		"servicebridge: the direct peer socket is missing, a symbolic link, not a socket, owned by another user " +
			"or in a directory other users can write",
	)
	ErrDirectPeerUser       = errors.New("servicebridge: the direct peer's receiver runs as another user")
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
	// socketUser and peerUser are the user the socket must belong to and
	// the user its listener must run as. Both are this process's effective
	// user; tests set them to stand in for another user.
	socketUser, peerUser func() int
}

// Reasons a direct peer socket is not used.
const (
	directSocketAbsent   = "is not present"
	directSocketNotOne   = "is a symbolic link or not a socket"
	directSocketOwner    = "is owned by another user"
	directSocketParent   = "is in a directory that is a symbolic link or that other users can write"
	directSocketUnread   = "cannot be inspected"
	directSocketNotClean = "is not an absolute clean path"
)

// inspectDirectSocket says why a peer's receiver socket is outside the
// direct transport's scope, without connecting to it; "" when it is
// inside. The scope is one user on one host: the socket is a socket (a
// link to one is refused), this user owns it, and nobody else can replace
// it, which a directory writable by group or others would allow.
func inspectDirectSocket(path string, user int) string {
	if !cleanAbsolute(path) {
		return directSocketNotClean
	}
	// Lstat does not follow a link, so a link to a socket is refused too.
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return directSocketAbsent
	case err != nil:
		return directSocketUnread
	case info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0:
		return directSocketNotOne
	}
	if owner, ownerErr := fileOwnerID(info); ownerErr == nil && owner != user {
		return directSocketOwner
	} else if ownerErr != nil && !errors.Is(ownerErr, errOwnerUnsupported) {
		return directSocketUnread
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return directSocketUnread
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return directSocketParent
	}
	return ""
}

func (t DirectTransport) users() (socket, peer int) {
	socket, peer = os.Geteuid(), os.Geteuid()
	if t.socketUser != nil {
		socket = t.socketUser()
	}
	if t.peerUser != nil {
		peer = t.peerUser()
	}
	return socket, peer
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
	socketUser, peerUser := t.users()
	if inspectDirectSocket(path, socketUser) != "" {
		return ErrDirectSocketInvalid
	}
	timeout := t.Timeout
	if timeout <= 0 || timeout > DirectSendTimeout {
		timeout = DirectSendTimeout
	}
	// The file checks above are of a path; the listener that answers is
	// asked who it is. A receiver of another user is not written to.
	var wrongUser atomic.Bool
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			connection, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if dialErr != nil {
				return nil, dialErr
			}
			user, userErr := peerUserID(connection)
			if errors.Is(userErr, errPeerUserUnsupported) {
				return connection, nil
			}
			if userErr != nil || user != peerUser {
				wrongUser.Store(true)
				_ = connection.Close()
				return nil, ErrDirectPeerUser
			}
			return connection, nil
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
	if wrongUser.Load() {
		return ErrDirectPeerUser
	}
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
// peer, through the relay carrier when a key card of the recipient is held,
// and through Fallback otherwise. Without a route the send fails rather than
// being dropped.
type RoutedTransport struct {
	Direct   DirectTransport
	Relay    *RelayTransport
	Fallback PacketTransport
}

// Route names the transport a recipient's packets take.
func (t RoutedTransport) Route(recipient string) string {
	if _, ok := t.Direct.Peers[recipient]; ok {
		return RouteDirect
	}
	if t.Relay.Reaches(recipient) {
		return RouteRelay
	}
	if t.Fallback != nil {
		return RouteMessenger
	}
	return RouteNone
}

// Packet routes.
const (
	RouteDirect    = "direct"
	RouteRelay     = "relay"
	RouteMessenger = "messenger"
	RouteNone      = "none"
)

// Send implements PacketTransport.
func (t RoutedTransport) Send(ctx context.Context, packet OutboundPacket) error {
	switch t.Route(packet.RecipientAgentID) {
	case RouteDirect:
		return t.Direct.Send(ctx, packet)
	case RouteRelay:
		return t.Relay.Send(ctx, packet)
	case RouteMessenger:
		return t.Fallback.Send(ctx, packet)
	default:
		return ErrNoPacketRoute
	}
}

// openPacketTransport builds the node's transport from its configuration
// and fails closed when no recipient could ever be reached.
func openPacketTransport(config NodeConfig, relay *RelayTransport) (PacketTransport, error) {
	if err := validateDirectPeers(config.DirectPeers); err != nil {
		return nil, err
	}
	if _, self := config.DirectPeers[config.AgentID]; self {
		return nil, errors.New("servicebridge: direct_peers names this node's own Agent")
	}
	routed := RoutedTransport{Direct: DirectTransport{Peers: config.DirectPeers}, Relay: relay}
	if config.MessengerSocket != "" {
		client, err := newMessengerClient(config.MessengerSocket)
		if err != nil {
			return nil, err
		}
		routed.Fallback = MessengerTransport{Client: client}
	}
	if routed.Fallback == nil && len(config.DirectPeers) == 0 && relay == nil {
		return nil, errors.New("servicebridge: the rail node has no packet transport: configure messenger_socket, " +
			"direct_peers or relay_urls")
	}
	return routed, nil
}
