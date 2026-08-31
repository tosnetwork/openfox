package earning

import "testing"

func TestCanonicalTOSZeroStateHash(t *testing.T) {
	const canonical = "sha256:f7000620e854e84b22d54ab295763b559e0f00923aaada1181196dfc70e9c0cc"
	for _, test := range []struct {
		name, input, want string
		valid             bool
	}{
		{name: "chain base64", input: "9wAGIOhU6Esi1UqylXY7VZ4PAJI6qtoRgRlt/HDpwMw=", want: canonical, valid: true},
		{name: "canonical", input: canonical, want: canonical, valid: true},
		{name: "uppercase hex", input: "sha256:F7000620E354E84B22D54AB295763B559E0F00923AAADA1181196DFC70E9C0CC"},
		{name: "short base64", input: "AQIDBA=="},
		{name: "arbitrary text", input: "not-a-network-hash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalTOSZeroStateHash(test.input)
			if test.valid && (err != nil || got != test.want) {
				t.Fatalf("canonicalTOSZeroStateHash() = %q, %v; want %q, nil", got, err, test.want)
			}
			if !test.valid && err == nil {
				t.Fatalf("canonicalTOSZeroStateHash() = %q, nil; want error", got)
			}
		})
	}
}
