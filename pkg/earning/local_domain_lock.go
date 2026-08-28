package earning

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
)

// localEconomicDomainLock is a kernel-namespaced, unlink-proof single-host
// lock. A filesystem lock alone is insufficient because an owner-writable
// journal directory can be renamed and replaced with a second inode carrying
// a second lock file. Binding a deterministic loopback UDP endpoint makes the
// logical authority unique even while its pathname is being replaced.
//
// The local durable implementations already decline rollback-resistant and
// cross-host claims. Network namespaces are therefore separate authority
// hosts; deployments sharing journals across namespaces must use the external
// monotonic authority implementation instead.
type localEconomicDomainLock struct {
	connection *net.UDPConn
}

func acquireLocalEconomicDomainLock(domain string) (*localEconomicDomainLock, error) {
	if domain == "" {
		return nil, errors.New("economic authority lock domain is empty")
	}
	digest := sha256.Sum256([]byte("tos.openfox.local-economic-domain-lock.v1\x00" + domain))
	// 127/8 is loopback on supported hosts. Using three address octets plus a
	// private-range port gives a deterministic 38-bit namespace and makes
	// unrelated-service collision a fail-closed availability event, not a split.
	address := &net.UDPAddr{IP: net.IPv4(127, 1+digest[0]%254, 1+digest[1]%254, 1+digest[2]%254),
		Port: 49152 + int(binary.BigEndian.Uint16(digest[3:5])%16384)}
	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		return nil, errors.New("economic authority domain is already active on this host")
	}
	return &localEconomicDomainLock{connection: connection}, nil
}

func (lock *localEconomicDomainLock) Close() error {
	if lock == nil || lock.connection == nil {
		return nil
	}
	err := lock.connection.Close()
	lock.connection = nil
	if err != nil {
		return errors.New("close economic authority domain lock")
	}
	return nil
}
