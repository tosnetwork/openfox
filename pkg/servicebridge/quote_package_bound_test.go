package servicebridge

import (
	"bytes"
	"math"
	"math/big"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

// largestQuotePackage is the largest Quote package OpenFox's offer can
// produce: every variable field at its maximum (a 64-byte version, the
// manifest version syntax's limit; the 30-day retention; prices just below
// 2^120; the gateway's 256-byte proposal ID limit; the largest expiry).
func largestQuotePackage(t *testing.T) []byte {
	t.Helper()
	version := strings.Repeat("9", 64)
	attestor := "mldsa44:" + strings.Repeat("99", 32)
	manifestCBOR, digest, _, err := BuildManifest(ManifestInput{
		ProviderAgentID: testSeller, Actor: "0:" + strings.Repeat("77", 32),
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), Attestor: attestor,
		Version: version, RetentionSeconds: 30 * 24 * 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, _, err := RailTransport(testSeller)
	if err != nil {
		t.Fatal(err)
	}
	root, transportDigest, err := nativecore.BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	largest := new(big.Int).Sub(nativecore.MaxServiceActorCoins, big.NewInt(1)).String()
	pkg := &nativev1.QuoteProposalPackageV1{
		Proposal: &nativev1.QuoteProposalV1{
			ProposalId: strings.Repeat("p", 256), CapabilityId: "cap_" + strings.Repeat("33", 32),
			CapabilityVersion: version, ProviderAgentId: testSeller, ManifestDigest: digest,
			TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: math.MaxUint64,
			Actor:         &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
			ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), PolicyVersion: math.MaxUint32,
			TermsHash: strings.Repeat("ab", 32), PriceNanotos: largest, StorageFeeNanotos: largest,
			AttestorKeyId: attestor,
		},
		CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: root.ToBOC(),
	}
	raw, err := proto.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The rail work frame spec bounds a task's package_base64 at 8,192 decoded
// bytes (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 5.1), set from this
// measurement (2,195 bytes) with headroom. Every package an OpenFox offer
// produces must stay within it.
func TestTheLargestOpenFoxQuotePackageFitsTheRailBound(t *testing.T) {
	const railPackageBound = 8192
	raw := largestQuotePackage(t)
	t.Logf("largest OpenFox Quote package: %d bytes", len(raw))
	if len(raw) > railPackageBound {
		t.Fatalf("the largest Quote package is %d bytes, over the %d-byte rail bound", len(raw), railPackageBound)
	}
}
