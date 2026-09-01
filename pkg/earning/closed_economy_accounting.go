package earning

import (
	"errors"
	"math/big"
	"strings"
	"unicode/utf8"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	maxOwnerLocalClosedEconomyParticipants = 4096
	maxOwnerLocalClosedEconomyTransfers    = 100000
)

// OwnerLocalClosedEconomyScope is an OpenFox-local accounting perimeter. It
// is not an Outcome profile, protocol object, evidence of transfer finality,
// or authority to recognize revenue. ParticipantAgentIDs must be the complete,
// sorted set selected by one exact Owner accounting-policy revision.
type OwnerLocalClosedEconomyScope struct {
	AccountingPolicyDigest string                   `json:"accounting_policy_digest"`
	EconomicPerimeterID    string                   `json:"economic_perimeter_id"`
	Asset                  commerce.AssetIdentityV1 `json:"asset"`
	ParticipantAgentIDs    []string                 `json:"participant_agent_ids"`
}

// OwnerLocalClosedEconomyTransfer is one caller-selected internal transfer and
// the conservative Owner reserve attached to the seller's work. The reserve is
// a planning bound, not an invoice, metered cost, or cash outflow.
type OwnerLocalClosedEconomyTransfer struct {
	TransferReference   string                  `json:"transfer_reference"`
	BuyerAgentID        string                  `json:"buyer_agent_id"`
	SellerAgentID       string                  `json:"seller_agent_id"`
	Amount              commerce.AtomicAmountV1 `json:"amount"`
	ConservativeReserve commerce.AtomicAmountV1 `json:"conservative_reserve"`
}

// OwnerLocalClosedEconomyProjection keeps the two views of internal transfers
// visible instead of presenting seller gross receipts as new external wealth.
// ProjectedClosedEconomyNetAtomic subtracts only the explicitly supplied
// conservative reserve; it is not realized profit or an Outcome cost claim.
type OwnerLocalClosedEconomyProjection struct {
	AccountingPolicyDigest            string                   `json:"accounting_policy_digest"`
	EconomicPerimeterID               string                   `json:"economic_perimeter_id"`
	Asset                             commerce.AssetIdentityV1 `json:"asset"`
	TransferCount                     uint64                   `json:"transfer_count"`
	InternalSellerGrossReceiptsAtomic string                   `json:"internal_seller_gross_receipts_atomic"`
	InternalBuyerSpendAtomic          string                   `json:"internal_buyer_spend_atomic"`
	IntraPerimeterTransferNetAtomic   string                   `json:"intra_perimeter_transfer_net_atomic"`
	ConservativeReserveAtomic         string                   `json:"conservative_reserve_atomic"`
	ProjectedClosedEconomyNetAtomic   string                   `json:"projected_closed_economy_net_atomic"`
}

// ProjectOwnerLocalClosedEconomy computes an observe-only, same-asset local
// projection. Exact replay of an identical transfer is idempotent; a reused
// transfer reference with different accounting fields fails closed. Inputs
// crossing the declared perimeter or asset must be projected separately.
func ProjectOwnerLocalClosedEconomy(scope OwnerLocalClosedEconomyScope,
	transfers []OwnerLocalClosedEconomyTransfer) (OwnerLocalClosedEconomyProjection, error) {
	projection := OwnerLocalClosedEconomyProjection{AccountingPolicyDigest: scope.AccountingPolicyDigest,
		EconomicPerimeterID: scope.EconomicPerimeterID, Asset: scope.Asset,
		InternalSellerGrossReceiptsAtomic: "0", InternalBuyerSpendAtomic: "0",
		IntraPerimeterTransferNetAtomic: "0", ConservativeReserveAtomic: "0",
		ProjectedClosedEconomyNetAtomic: "0"}
	if !canonicalSHA256(scope.AccountingPolicyDigest) ||
		!boundedOwnerLocalAccountingIdentifier(scope.EconomicPerimeterID, 256) ||
		commerce.ValidateAssetIdentityV1(scope.Asset) != nil || len(scope.ParticipantAgentIDs) < 2 ||
		len(scope.ParticipantAgentIDs) > maxOwnerLocalClosedEconomyParticipants ||
		len(transfers) > maxOwnerLocalClosedEconomyTransfers {
		return projection, errors.New("Owner-local closed-economy accounting scope is invalid or unbounded")
	}
	participants := make(map[string]struct{}, len(scope.ParticipantAgentIDs))
	for index, participant := range scope.ParticipantAgentIDs {
		if !boundedOwnerLocalAccountingIdentifier(participant, 256) ||
			index > 0 && scope.ParticipantAgentIDs[index-1] >= participant {
			return projection, errors.New("Owner-local closed-economy participants are invalid or non-canonical")
		}
		participants[participant] = struct{}{}
	}

	retained := make(map[string]OwnerLocalClosedEconomyTransfer, len(transfers))
	for _, transfer := range transfers {
		if !canonicalSHA256(transfer.TransferReference) ||
			!boundedOwnerLocalAccountingIdentifier(transfer.BuyerAgentID, 256) ||
			!boundedOwnerLocalAccountingIdentifier(transfer.SellerAgentID, 256) ||
			transfer.BuyerAgentID == transfer.SellerAgentID ||
			commerce.ValidateAtomicAmountV1(transfer.Amount, true) != nil ||
			commerce.ValidateAtomicAmountV1(transfer.ConservativeReserve, false) != nil ||
			transfer.Amount.Asset != scope.Asset || transfer.ConservativeReserve.Asset != scope.Asset {
			return projection, errors.New("Owner-local closed-economy transfer is invalid or changes asset")
		}
		if _, found := participants[transfer.BuyerAgentID]; !found {
			return projection, errors.New("Owner-local closed-economy transfer crosses the declared perimeter")
		}
		if _, found := participants[transfer.SellerAgentID]; !found {
			return projection, errors.New("Owner-local closed-economy transfer crosses the declared perimeter")
		}
		if prior, found := retained[transfer.TransferReference]; found {
			if prior != transfer {
				return projection, errors.New("Owner-local closed-economy transfer reference conflicts")
			}
			continue
		}
		retained[transfer.TransferReference] = transfer
	}

	gross, spend, reserve := new(big.Int), new(big.Int), new(big.Int)
	for _, transfer := range retained {
		amount, amountOK := new(big.Int).SetString(transfer.Amount.AmountAtomic, 10)
		bound, boundOK := new(big.Int).SetString(transfer.ConservativeReserve.AmountAtomic, 10)
		if !amountOK || !boundOK {
			return projection, errors.New("Owner-local closed-economy amount is not canonical")
		}
		gross.Add(gross, amount)
		spend.Add(spend, amount)
		reserve.Add(reserve, bound)
	}
	transferNet := new(big.Int).Sub(new(big.Int).Set(gross), spend)
	projectedNet := new(big.Int).Sub(new(big.Int).Set(transferNet), reserve)
	projection.TransferCount = uint64(len(retained))
	projection.InternalSellerGrossReceiptsAtomic = gross.String()
	projection.InternalBuyerSpendAtomic = spend.String()
	projection.IntraPerimeterTransferNetAtomic = transferNet.String()
	projection.ConservativeReserveAtomic = reserve.String()
	projection.ProjectedClosedEconomyNetAtomic = projectedNet.String()
	return projection, nil
}

func boundedOwnerLocalAccountingIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
