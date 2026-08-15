package nativeimpl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tosnetwork/openfox/pkg/atosbridge"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
)

// The mobile buyer projection vectors are the shared iOS/Android ground truth.
// This test proves they match the real EscrowSettlementReader, so the Swift and
// Kotlin decoders can be checked against the same file with confidence that the
// vectors themselves encode canonical behaviour.

type mobileEscrow struct {
	Status              uint8  `json:"status"`
	QuoteCommitment     string `json:"quote_commitment"`
	FundedAtomicAmount  string `json:"funded_atomic_amount"`
	SettledAtomicAmount string `json:"settled_atomic_amount"`
	ReceiptCommitment   string `json:"receipt_commitment"`
}

type mobileFundingView struct {
	Found             bool   `json:"found"`
	AwaitingFunding   bool   `json:"awaiting_funding"`
	FundedAtomic      string `json:"funded_atomic"`
	SettledAtomic     string `json:"settled_atomic"`
	ReceiptCommitment string `json:"receipt_commitment"`
}

type mobileSettlementView struct {
	Released             bool   `json:"released"`
	Refunded             bool   `json:"refunded"`
	ProviderCreditAtomic string `json:"provider_credit_atomic"`
}

type mobileProjectionCase struct {
	Name            string                `json:"name"`
	Present         bool                  `json:"present"`
	Escrow          *mobileEscrow         `json:"escrow"`
	FundingView     *mobileFundingView    `json:"funding_view"`
	SettlementView  *mobileSettlementView `json:"settlement_view"`
	ExpectDecodeErr bool                  `json:"expect_decode_error"`
}

type mobileProjectionVectors struct {
	Schema string                 `json:"schema"`
	Cases  []mobileProjectionCase `json:"cases"`
}

func loadMobileVectors(t *testing.T) mobileProjectionVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "mobile_buyer_escrow_projection_v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors mobileProjectionVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if vectors.Schema != "atos.native.mobile-buyer-escrow-projection.v1" || len(vectors.Cases) == 0 {
		t.Fatalf("unexpected vector schema/shape: %+v", vectors.Schema)
	}
	return vectors
}

func projectionReader(c mobileProjectionCase) *EscrowSettlementReader {
	var reader fakeFinalized
	if !c.Present {
		reader = fakeFinalized{found: false}
	} else {
		reader = fakeFinalized{found: true, cp: 100, state: &nativecore.EscrowStateV1{
			Status: c.Escrow.Status, QuoteCommitment: c.Escrow.QuoteCommitment,
			FundedAtomicAmount: c.Escrow.FundedAtomicAmount, SettledAtomicAmount: c.Escrow.SettledAtomicAmount,
			ReceiptCommitment: c.Escrow.ReceiptCommitment,
		}}
	}
	r, _ := NewEscrowSettlementReader(reader)
	return r
}

func atoi64(t *testing.T, value string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatalf("bad expected amount %q: %v", value, err)
	}
	return n
}

func TestMobileBuyerVectorsMatchEscrowReader(t *testing.T) {
	vectors := loadMobileVectors(t)
	const escrowAddr = "0:" + hex64
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			reader := projectionReader(c)

			funding, fundingErr := reader.ResolveEscrow(context.Background(), escrowAddr)
			settlement, settlementErr := reader.VerifySettlement(context.Background(), atosbridge.AcceptedQuote{EscrowAddress: escrowAddr})

			if c.ExpectDecodeErr {
				if fundingErr == nil {
					t.Fatalf("case %s: expected a decode error, funding resolved as %+v", c.Name, funding)
				}
				return
			}
			if fundingErr != nil || settlementErr != nil {
				t.Fatalf("case %s: unexpected error funding=%v settlement=%v", c.Name, fundingErr, settlementErr)
			}

			if funding.Found != c.FundingView.Found || funding.AwaitingFunding != c.FundingView.AwaitingFunding ||
				funding.FundedAtomic != atoi64(t, c.FundingView.FundedAtomic) ||
				funding.SettledAtomic != atoi64(t, c.FundingView.SettledAtomic) ||
				funding.ReceiptCommit != c.FundingView.ReceiptCommitment {
				t.Fatalf("case %s: funding view mismatch\n got:  %+v\n want: %+v", c.Name, funding, c.FundingView)
			}
			if settlement.Released != c.SettlementView.Released || settlement.Refunded != c.SettlementView.Refunded ||
				settlement.ProviderCreditAtomic != atoi64(t, c.SettlementView.ProviderCreditAtomic) {
				t.Fatalf("case %s: settlement view mismatch\n got:  %+v\n want: %+v", c.Name, settlement, c.SettlementView)
			}
		})
	}
}
