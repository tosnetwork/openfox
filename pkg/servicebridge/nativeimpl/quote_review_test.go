package nativeimpl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type quoteReviewFields struct {
	CapabilityVersion   string `json:"capability_version"`
	ManifestDigest      string `json:"manifest_digest"`
	AssetMaster         string `json:"asset_master"`
	AssetWalletCodeHash string `json:"asset_wallet_code_hash"`
	AmountAtomic        string `json:"amount_atomic"`
	EscrowAddress       string `json:"escrow_address"`
	QuoteCommitment     string `json:"quote_commitment"`
	FeePayer            string `json:"fee_payer"`
	ExpiryUnix          uint64 `json:"expiry_unix"`
}

type quoteReviewCase struct {
	Name   string            `json:"name"`
	Review quoteReviewFields `json:"review"`
	Expect string            `json:"expect"`
}

type quoteReviewVectors struct {
	Schema  string            `json:"schema"`
	NowUnix uint64            `json:"now_unix"`
	Cases   []quoteReviewCase `json:"cases"`
}

func TestMobileQuoteReviewVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "mobile_buyer_quote_review_v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors quoteReviewVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if vectors.Schema != "tos.service.mobile-buyer-quote-review.v1" || len(vectors.Cases) == 0 {
		t.Fatalf("unexpected vector schema/shape: %q", vectors.Schema)
	}

	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			review := QuoteReview{
				CapabilityVersion: c.Review.CapabilityVersion, ManifestDigest: c.Review.ManifestDigest,
				AssetMaster: c.Review.AssetMaster, AssetWalletCodeHash: c.Review.AssetWalletCodeHash,
				AmountAtomic: c.Review.AmountAtomic, EscrowAddress: c.Review.EscrowAddress,
				QuoteCommitment: c.Review.QuoteCommitment, FeePayer: c.Review.FeePayer, ExpiryUnix: c.Review.ExpiryUnix,
			}
			if got := review.Review(vectors.NowUnix); string(got) != c.Expect {
				t.Fatalf("case %s: got reason %q, want %q", c.Name, got, c.Expect)
			}
		})
	}
}
