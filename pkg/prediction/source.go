package prediction

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	maxOracleSourceURLBytes = 2048
	maxOracleSnapshotBytes  = 2 << 20
	maxOracleSourceTypes    = 16
)

type HTTPSOracleSourceProfile struct {
	CanonicalURL        string        `json:"canonical_url"`
	AllowedContentTypes []string      `json:"allowed_content_types"`
	MaximumBytes        int64         `json:"maximum_bytes"`
	RequestTimeout      time.Duration `json:"request_timeout"`
}

type HTTPSOracleSnapshot struct {
	CanonicalSourceID string
	ContentType       string
	Content           []byte
	ContentDigest     [sha256.Size]byte
	FetchedAt         time.Time
	LeafSPKIDigest    string
}

type sourceIPResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type sourceHTTPClientFactory func(host string, ips []net.IP, timeout time.Duration) *http.Client

// HTTPSOracleSource fetches exact bounded source bytes. Redirects and
// transparent decompression are disabled so the bytes hashed, parsed, and
// archived are identical.
type HTTPSOracleSource struct {
	profile  HTTPSOracleSourceProfile
	url      *url.URL
	resolver sourceIPResolver
	client   sourceHTTPClientFactory
}

func NewHTTPSOracleSource(profile HTTPSOracleSourceProfile) (*HTTPSOracleSource, error) {
	return newHTTPSOracleSource(profile, net.DefaultResolver, productionSourceClient)
}

func newHTTPSOracleSource(
	profile HTTPSOracleSourceProfile,
	resolver sourceIPResolver,
	client sourceHTTPClientFactory,
) (*HTTPSOracleSource, error) {
	parsed, err := validateHTTPSOracleSourceProfile(profile)
	if err != nil || resolver == nil || client == nil {
		return nil, errors.New("prediction HTTPS source profile is invalid")
	}
	return &HTTPSOracleSource{profile: profile, url: parsed, resolver: resolver, client: client}, nil
}

func (source *HTTPSOracleSource) Fetch(ctx context.Context, fetchedAt time.Time) (HTTPSOracleSnapshot, error) {
	if source == nil || ctx == nil || fetchedAt.IsZero() {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source is unavailable")
	}
	host := source.url.Hostname()
	ips, err := source.resolvePublicIPs(ctx, host)
	if err != nil {
		return HTTPSOracleSnapshot{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, source.profile.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, source.url.String(), nil)
	if err != nil {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source request is invalid")
	}
	request.Header.Set("Accept", strings.Join(source.profile.AllowedContentTypes, ", "))
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "OpenFox-Prediction-Oracle/1")
	response, err := source.client(host, ips, source.profile.RequestTimeout).Do(request)
	if err != nil {
		return HTTPSOracleSnapshot{}, fmt.Errorf("prediction HTTPS source fetch failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil ||
		response.Request.URL.String() != source.url.String() {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source returned an inadmissible response")
	}
	if encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding"))); encoding != "" &&
		encoding != "identity" {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source content encoding is not identity")
	}
	contentType := canonicalMediaType(response.Header.Get("Content-Type"))
	if !containsSortedString(source.profile.AllowedContentTypes, contentType) {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source content type is not admitted")
	}
	if response.ContentLength < -1 || response.ContentLength > source.profile.MaximumBytes {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source content length exceeds its bound")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, source.profile.MaximumBytes+1))
	if err != nil || len(content) == 0 || int64(len(content)) > source.profile.MaximumBytes {
		return HTTPSOracleSnapshot{}, errors.New("prediction HTTPS source body is empty or exceeds its bound")
	}
	result := HTTPSOracleSnapshot{
		CanonicalSourceID: source.profile.CanonicalURL,
		ContentType:       contentType,
		Content:           append([]byte(nil), content...),
		ContentDigest:     sha256.Sum256(content),
		FetchedAt:         fetchedAt.UTC(),
	}
	if response.TLS != nil && len(response.TLS.PeerCertificates) != 0 {
		result.LeafSPKIDigest = spkiDigest(response.TLS.PeerCertificates[0])
	}
	return result, nil
}

func (source *HTTPSOracleSource) resolvePublicIPs(ctx context.Context, host string) ([]net.IP, error) {
	if literal := net.ParseIP(host); literal != nil {
		if !publicOracleIP(literal) {
			return nil, errors.New("prediction HTTPS source resolves outside the public Internet")
		}
		return []net.IP{append(net.IP(nil), literal...)}, nil
	}
	ips, err := source.resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 || len(ips) > 32 {
		return nil, errors.New("prediction HTTPS source DNS resolution is unavailable or excessive")
	}
	result := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if !publicOracleIP(ip) {
			return nil, errors.New("prediction HTTPS source DNS answer contains a non-public address")
		}
		canonical := ip.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, append(net.IP(nil), ip...))
	}
	if len(result) == 0 {
		return nil, errors.New("prediction HTTPS source DNS answer is empty")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

func productionSourceClient(host string, ips []net.IP, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:              nil,
		DisableCompression: true,
		DisableKeepAlives:  true,
		ForceAttemptHTTP2:  true,
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var failures []error
			for _, ip := range ips {
				connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), "443"))
				if err == nil {
					return connection, nil
				}
				failures = append(failures, err)
			}
			return nil, errors.Join(failures...)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("prediction HTTPS source redirects are disabled")
		},
	}
}

func validateHTTPSOracleSourceProfile(profile HTTPSOracleSourceProfile) (*url.URL, error) {
	if len(profile.CanonicalURL) == 0 || len(profile.CanonicalURL) > maxOracleSourceURLBytes ||
		profile.MaximumBytes <= 0 || profile.MaximumBytes > maxOracleSnapshotBytes ||
		profile.RequestTimeout < time.Second || profile.RequestTimeout > 30*time.Second ||
		len(profile.AllowedContentTypes) == 0 || len(profile.AllowedContentTypes) > maxOracleSourceTypes {
		return nil, errors.New("invalid bounded source profile")
	}
	parsed, err := url.Parse(profile.CanonicalURL)
	host := ""
	if parsed != nil {
		host = parsed.Hostname()
	}
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" ||
		host == "" || host != strings.ToLower(host) || !canonicalASCIIHostname(host) ||
		strings.HasSuffix(host, ".") || parsed.Port() != "" || parsed.RawQuery != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && (path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//"))) ||
		parsed.String() != profile.CanonicalURL {
		return nil, errors.New("source URL is not canonical HTTPS")
	}
	previous := ""
	for _, mediaType := range profile.AllowedContentTypes {
		if mediaType != canonicalMediaType(mediaType) || mediaType == "" || mediaType <= previous {
			return nil, errors.New("source media types are not canonical sorted and unique")
		}
		previous = mediaType
	}
	return parsed, nil
}

func canonicalMediaType(value string) string {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil || strings.Count(mediaType, "/") != 1 || strings.HasPrefix(mediaType, "/") ||
		strings.HasSuffix(mediaType, "/") {
		return ""
	}
	return strings.ToLower(mediaType)
}

func canonicalASCIIHostname(host string) bool {
	for _, character := range []byte(host) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '-' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func publicOracleIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// net.IP.IsGlobalUnicast deliberately includes several non-public ranges
	// (for example RFC 6598 CGNAT and RFC 2544 benchmarking addresses).  They
	// are unacceptable for an external-fact Oracle: allowing them turns DNS
	// resolution into an SSRF path into an operator or provider network.
	if ipv4 := ip.To4(); ipv4 != nil {
		return publicOracleIPv4(ipv4)
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok || !address.Is6() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() {
		return false
	}
	return !oracleIPv6SpecialUse(address)
}

func publicOracleIPv4(ip net.IP) bool {
	if len(ip) != net.IPv4len || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	value := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	return !oracleIPv4SpecialUse(value)
}

func oracleIPv4SpecialUse(value uint32) bool {
	for _, prefix := range []struct {
		network uint32
		mask    uint32
	}{
		{0x00000000, 0xff000000}, // 0.0.0.0/8: "this" network
		{0x64400000, 0xffc00000}, // 100.64.0.0/10: shared CGNAT
		{0xc0000000, 0xffffff00}, // 192.0.0.0/24: IETF protocol assignments
		{0xc0000200, 0xffffff00}, // 192.0.2.0/24: documentation
		{0xc0586300, 0xffffff00}, // 192.88.99.0/24: deprecated 6to4 relay
		{0xc6120000, 0xfffe0000}, // 198.18.0.0/15: benchmarking
		{0xc6336400, 0xffffff00}, // 198.51.100.0/24: documentation
		{0xcb007100, 0xffffff00}, // 203.0.113.0/24: documentation
		{0xf0000000, 0xf0000000}, // 240.0.0.0/4: reserved
	} {
		if value&prefix.mask == prefix.network {
			return true
		}
	}
	return false
}

func oracleIPv6SpecialUse(address netip.Addr) bool {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("100::/64"),      // discard-only
		netip.MustParsePrefix("2001:2::/48"),   // benchmarking
		netip.MustParsePrefix("2001:db8::/32"), // documentation
	} {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func containsSortedString(values []string, candidate string) bool {
	index := sort.SearchStrings(values, candidate)
	return index < len(values) && values[index] == candidate
}

func spkiDigest(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(digest[:])
}
