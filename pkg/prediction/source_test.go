package prediction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type fixedSourceResolver struct {
	ips []net.IP
	err error
}

func (resolver fixedSourceResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return resolver.ips, resolver.err
}

type sourceRoundTripper func(*http.Request) (*http.Response, error)

func (transport sourceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func sourceProfile() HTTPSOracleSourceProfile {
	return HTTPSOracleSourceProfile{
		CanonicalURL:        "https://results.example.gov/final.json",
		AllowedContentTypes: []string{"application/json", "text/plain"},
		MaximumBytes:        128,
		RequestTimeout:      time.Second,
	}
}

func sourceClient(response func(*http.Request) (*http.Response, error)) sourceHTTPClientFactory {
	return func(string, []net.IP, time.Duration) *http.Client {
		return &http.Client{Transport: sourceRoundTripper(response)}
	}
}

func TestHTTPSOracleSourceHashesOnlyExactBoundedAdmittedBytes(t *testing.T) {
	content := []byte(`{"winner":"YES"}`)
	source, err := newHTTPSOracleSource(
		sourceProfile(),
		fixedSourceResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}},
		sourceClient(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Accept-Encoding") != "identity" {
				t.Fatal("source request allowed transparent decompression")
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
				Body:          io.NopCloser(bytes.NewReader(content)),
				ContentLength: int64(len(content)),
				Request:       request,
			}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	fetchedAt := time.Unix(20_000, 0).UTC()
	snapshot, err := source.Fetch(t.Context(), fetchedAt)
	if err != nil || snapshot.ContentType != "application/json" ||
		snapshot.ContentDigest != sha256.Sum256(content) || !bytes.Equal(snapshot.Content, content) ||
		!snapshot.FetchedAt.Equal(fetchedAt) {
		t.Fatalf("unexpected exact source snapshot: %+v err=%v", snapshot, err)
	}
	snapshot.Content[0] ^= 1
	again, err := source.Fetch(t.Context(), fetchedAt)
	if err != nil || !bytes.Equal(again.Content, content) {
		t.Fatal("source snapshot exposed aliases to fetched content")
	}
}

func TestHTTPSOracleSourceRejectsSSRFRedirectEncodingAndOversize(t *testing.T) {
	profile := sourceProfile()
	clientCalls := 0
	privateSource, err := newHTTPSOracleSource(
		profile,
		fixedSourceResolver{ips: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}},
		sourceClient(func(*http.Request) (*http.Response, error) {
			clientCalls++
			return nil, errors.New("must not fetch")
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := privateSource.Fetch(t.Context(), time.Now().UTC()); err == nil || clientCalls != 0 {
		t.Fatal("mixed public/private DNS answer reached the network")
	}
	for name, ip := range map[string]string{
		"CGNAT":              "100.64.0.1",
		"benchmark IPv4":     "198.18.0.1",
		"documentation IPv4": "203.0.113.1",
		"reserved IPv4":      "240.0.0.1",
		"benchmark IPv6":     "2001:2::1",
		"documentation IPv6": "2001:db8::1",
		"IPv4 mapped CGNAT":  "::ffff:100.64.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			source, sourceErr := newHTTPSOracleSource(
				profile,
				fixedSourceResolver{ips: []net.IP{net.ParseIP(ip)}},
				sourceClient(func(*http.Request) (*http.Response, error) {
					calls++
					return nil, errors.New("must not fetch a special-use address")
				}),
			)
			if sourceErr != nil {
				t.Fatal(sourceErr)
			}
			if _, fetchErr := source.Fetch(t.Context(), time.Now().UTC()); fetchErr == nil || calls != 0 {
				t.Fatal("special-use DNS answer reached the network")
			}
		})
	}

	for name, mutate := range map[string]func(*http.Response){
		"redirect":          func(response *http.Response) { response.StatusCode = http.StatusFound },
		"encoding":          func(response *http.Response) { response.Header.Set("Content-Encoding", "gzip") },
		"content type":      func(response *http.Response) { response.Header.Set("Content-Type", "text/html") },
		"declared oversize": func(response *http.Response) { response.ContentLength = profile.MaximumBytes + 1 },
		"streamed oversize": func(response *http.Response) {
			response.ContentLength = -1
			response.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, int(profile.MaximumBytes+1))))
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, sourceErr := newHTTPSOracleSource(
				profile,
				fixedSourceResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}},
				sourceClient(func(request *http.Request) (*http.Response, error) {
					response := &http.Response{
						StatusCode:    http.StatusOK,
						Header:        http.Header{"Content-Type": []string{"application/json"}},
						Body:          io.NopCloser(bytes.NewReader([]byte(`{}`))),
						ContentLength: 2,
						Request:       request,
					}
					mutate(response)
					return response, nil
				}),
			)
			if sourceErr != nil {
				t.Fatal(sourceErr)
			}
			if _, fetchErr := source.Fetch(t.Context(), time.Now().UTC()); fetchErr == nil {
				t.Fatal("inadmissible source response was accepted")
			}
		})
	}
}

func TestHTTPSOracleSourceProfileIsCanonicalAndBounded(t *testing.T) {
	for _, mutate := range []func(*HTTPSOracleSourceProfile){
		func(profile *HTTPSOracleSourceProfile) {
			profile.CanonicalURL = "http://results.example.gov/final.json"
		},
		func(profile *HTTPSOracleSourceProfile) { profile.CanonicalURL += "?latest=true" },
		func(profile *HTTPSOracleSourceProfile) {
			profile.CanonicalURL = "https://results.example.gov/a/../final.json"
		},
		func(profile *HTTPSOracleSourceProfile) { profile.CanonicalURL = "https://127.0.0.1/final.json" },
		func(profile *HTTPSOracleSourceProfile) {
			profile.AllowedContentTypes = []string{"text/plain", "application/json"}
		},
		func(profile *HTTPSOracleSourceProfile) { profile.MaximumBytes = maxOracleSnapshotBytes + 1 },
		func(profile *HTTPSOracleSourceProfile) { profile.RequestTimeout = 31 * time.Second },
	} {
		profile := sourceProfile()
		mutate(&profile)
		source, err := NewHTTPSOracleSource(profile)
		if profile.CanonicalURL == "https://127.0.0.1/final.json" {
			if err != nil {
				t.Fatal("literal address should be rejected at fetch time, not profile construction")
			}
			if _, fetchErr := source.Fetch(t.Context(), time.Now().UTC()); fetchErr == nil {
				t.Fatal("private literal source was fetched")
			}
			continue
		}
		if err == nil {
			t.Fatal("non-canonical or unbounded source profile was accepted")
		}
	}
}
