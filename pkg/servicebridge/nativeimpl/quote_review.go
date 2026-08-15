package nativeimpl

import "strings"

// QuoteReview is the set of canonical Accepted Quote facts a buyer must see and
// validate before approving a spend. It is exactly what the mobile confirmation
// screen displays: the buyer approves these fields, not a ticker or a Gateway
// claim. Every field is a finalized commitment, not a human label.
type QuoteReview struct {
	CapabilityVersion   string
	ManifestDigest      string
	AssetMaster         string
	AssetWalletCodeHash string
	AmountAtomic        string
	EscrowAddress       string
	QuoteCommitment     string
	FeePayer            string
	ExpiryUnix          uint64
}

// ReviewReason is the verdict of reviewing a Quote. "ok" means safe to display
// for approval; every other value is a specific, deterministic rejection so the
// same malformed Quote is rejected for the same reason on every platform.
type ReviewReason string

const (
	ReviewOK                  ReviewReason = "ok"
	ReviewCapabilityVersion   ReviewReason = "capability_version_missing"
	ReviewManifestDigest      ReviewReason = "manifest_digest_malformed"
	ReviewAssetMaster         ReviewReason = "asset_master_malformed"
	ReviewAssetWalletCodeHash ReviewReason = "asset_wallet_code_hash_malformed"
	ReviewAmountNotPositive   ReviewReason = "amount_not_positive"
	ReviewEscrowAddress       ReviewReason = "escrow_address_malformed"
	ReviewQuoteCommitment     ReviewReason = "quote_commitment_malformed"
	ReviewFeePayerUnknown     ReviewReason = "fee_payer_unknown"
	ReviewExpired             ReviewReason = "expired"
)

// Review validates the Quote facts against the current time. The checks run in a
// fixed order so the reason is deterministic. A Gateway response or a friendly
// asset ticker can never substitute for these commitments: a missing or
// malformed commitment is a rejection, not a warning.
func (q QuoteReview) Review(nowUnix uint64) ReviewReason {
	if q.CapabilityVersion == "" {
		return ReviewCapabilityVersion
	}
	if !shaDigest(q.ManifestDigest) {
		return ReviewManifestDigest
	}
	if !isRawWorkchainZero(q.AssetMaster) {
		return ReviewAssetMaster
	}
	if !cellDigest(q.AssetWalletCodeHash) {
		return ReviewAssetWalletCodeHash
	}
	if amount, err := parsePositiveAtomic(q.AmountAtomic); err != nil || amount == 0 {
		return ReviewAmountNotPositive
	}
	if !isRawWorkchainZero(q.EscrowAddress) {
		return ReviewEscrowAddress
	}
	if !cellDigest(q.QuoteCommitment) {
		return ReviewQuoteCommitment
	}
	if q.FeePayer != "buyer" && q.FeePayer != "provider" {
		return ReviewFeePayerUnknown
	}
	if q.ExpiryUnix <= nowUnix {
		return ReviewExpired
	}
	return ReviewOK
}

// parsePositiveAtomic reuses the atomic-amount decoder; a zero or malformed
// amount is not a spendable Quote.
func parsePositiveAtomic(value string) (uint64, error) {
	return atomicUint64(value)
}

// cellDigest reports whether value is a canonical tvm-cell-sha256 digest.
func cellDigest(value string) bool {
	return hexDigest(value, "tvm-cell-sha256:")
}

// shaDigest reports whether value is a canonical sha256 digest.
func shaDigest(value string) bool {
	return hexDigest(value, "sha256:")
}

func hexDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	body := value[len(prefix):]
	if len(body) != 64 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
