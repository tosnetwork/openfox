package servicebridge

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

// relayAPI is one relay's HTTP API as the node uses it. The relay holds no
// authority: every value it returns is an unauthenticated hint the node
// checks. *agentpacketrelay.Client implements it.
type relayAPI interface {
	Deposit(ctx context.Context, envelope []byte) (agentpacketrelay.DepositOutcome, error)
	List(ctx context.Context, agentID string) (agentpacketrelay.Mailbox, error)
	Download(ctx context.Context, agentID string, envelopeID [32]byte) ([]byte, error)
	Ack(ctx context.Context, agentID string, envelopeID, secret [32]byte) error
	Describe(ctx context.Context) (agentpacketrelay.RelayDescription, error)
}

// RelayRequestTimeout bounds one relay request, body included.
const RelayRequestTimeout = agentpacketrelay.DefaultClientTimeout

// relayDialer opens the client of one relay base URL.
type relayDialer func(base string) (relayAPI, error)

// dialRelay opens a client that never follows redirects, never consults the
// proxy environment and refuses plaintext http outside loopback.
func dialRelay(base string) (relayAPI, error) {
	client, err := agentpacketrelay.NewClient(
		agentpacketrelay.ClientConfig{BaseURL: base, Timeout: RelayRequestTimeout},
	)
	if err != nil {
		return nil, errors.New("servicebridge: the relay URL is not a canonical https (or loopback http) base URL")
	}
	return client, nil
}

// relayPool keeps one client per relay base URL.
type relayPool struct {
	dial    relayDialer
	mutex   sync.Mutex
	clients map[string]relayAPI
	// now is the clock of the relay descriptions' refresh; nil is time.Now.
	now func() time.Time
	// ttlMutex guards ttls, each relay's advertised retention.
	ttlMutex sync.Mutex
	ttls     map[string]relayTTLEntry
}

func newRelayPool(dial relayDialer) *relayPool {
	if dial == nil {
		dial = dialRelay
	}
	return &relayPool{dial: dial, clients: map[string]relayAPI{}, ttls: map[string]relayTTLEntry{}}
}

func (p *relayPool) client(base string) (relayAPI, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if client, ok := p.clients[base]; ok {
		return client, nil
	}
	client, err := p.dial(base)
	if err != nil {
		return nil, err
	}
	p.clients[base] = client
	return client, nil
}

// relayRetryAfter is the relay's Retry-After hint of an error, if any.
func relayRetryAfter(err error) time.Duration {
	if after, ok := agentpacketrelay.RetryAfter(err); ok {
		return after
	}
	return 0
}
