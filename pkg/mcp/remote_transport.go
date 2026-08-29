package mcp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func safeMCPHTTPClient(rawURL string, headers map[string]string) (*http.Client, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Hostname() == "" {
		return nil, errors.New("remote MCP endpoint must be an absolute credential-free HTTPS URL")
	}
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, errors.New("remote MCP endpoint port is invalid")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host},
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		answers, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(answers) == 0 || len(answers) > 32 {
			return nil, errors.New("remote MCP DNS resolution failed policy")
		}
		for _, answer := range answers {
			if prohibitedMCPAddress(answer.IP) {
				return nil, errors.New("remote MCP DNS answer is in a prohibited address class")
			}
		}
		var last error
		for _, answer := range answers {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(answer.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			last = dialErr
		}
		return nil, last
	}
	var base http.RoundTripper = transport
	if len(headers) > 0 {
		base = &headerTransport{base: base, headers: headers}
	}
	return &http.Client{
		Transport: base,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("remote MCP redirects are disabled")
		},
	}, nil
}

func prohibitedMCPAddress(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}
