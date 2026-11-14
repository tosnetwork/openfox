package servicebridge

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// redactEndpoints replaces every spelling of a configured endpoint URL in
// message with its position. A URL path may carry an access token, and an
// HTTP client error quotes the URL as it re-encodes it, not as configured:
// an empty fragment, for example, is dropped. So the configured text, the
// parsed URL's own rendering, its authority-and-path forms and the path
// itself are all replaced, longest first so a longer spelling is never left
// half-replaced.
func redactEndpoints(message string, endpoints []string) string {
	type spelling struct{ text, replacement string }
	var spellings []spelling
	for index, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}
		name := fmt.Sprintf("rpc_endpoints[%d]", index)
		spellings = append(spellings, spelling{endpoint, name})
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		for _, text := range []string{
			parsed.String(),
			strings.TrimSuffix(endpoint, "#"),
			parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath(),
			parsed.Host + parsed.EscapedPath(),
			parsed.Host + parsed.Path,
		} {
			spellings = append(spellings, spelling{text, name})
		}
		if parsed.User != nil {
			spellings = append(spellings, spelling{parsed.User.String(), name + ".userinfo"})
		}
		for _, path := range []string{parsed.EscapedPath(), parsed.Path} {
			if strings.Trim(path, "/") != "" {
				spellings = append(spellings, spelling{path, name + ".path"})
			}
		}
	}
	sort.SliceStable(spellings, func(i, j int) bool { return len(spellings[i].text) > len(spellings[j].text) })
	for _, candidate := range spellings {
		if candidate.text != "" {
			message = strings.ReplaceAll(message, candidate.text, candidate.replacement)
		}
	}
	return message
}
