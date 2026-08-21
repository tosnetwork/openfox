package nativeimpl

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"google.golang.org/protobuf/encoding/protojson"
)

const preparedPurchaseSchema = "tos.openfox.prepared-purchase.v1"

type preparedPurchaseEnvelope struct {
	Schema          string          `json:"schema"`
	Payload         json.RawMessage `json:"payload"`
	IntegrityDigest string          `json:"integrity_digest"`
}

type preparedPurchasePayload struct {
	Proposal                 json.RawMessage `json:"proposal"`
	ManifestCBORBase64       string          `json:"manifest_cbor_base64"`
	ManifestDigest           string          `json:"manifest_digest"`
	QuoteCommitment          string          `json:"quote_commitment"`
	QuoteBOCBase64           string          `json:"quote_boc_base64"`
	EscrowAddress            string          `json:"escrow_address"`
	EscrowCodeHash           string          `json:"escrow_code_hash"`
	EscrowTermsDigest        string          `json:"escrow_terms_digest"`
	AuthorizationDigest      string          `json:"authorization_digest"`
	TransportDigest          string          `json:"transport_digest"`
	DisputePolicyDigest      string          `json:"dispute_policy_digest"`
	EscrowStateInitBOCBase64 string          `json:"escrow_state_init_boc_base64"`
	EscrowDataBOCBase64      string          `json:"escrow_data_boc_base64"`
	AssetMasterAddress       string          `json:"asset_master_address"`
	BuyerWalletAddress       string          `json:"buyer_wallet_address"`
	AmountAtomic             string          `json:"amount_atomic"`
}

// MarshalPreparedPurchase creates the owner-review artifact shared by the
// separate escrow-deploy and funding stages. The digest covers canonical JSON
// payload; the Buyer SDK still independently reconstructs everything before a
// later payment, so this file is durable workflow state rather than authority.
func MarshalPreparedPurchase(purchase *buyersdk.PreparedPurchase) ([]byte, error) {
	if purchase == nil || purchase.Proposal == nil || purchase.Escrow.Data == nil {
		return nil, errors.New("nativeimpl: invalid prepared purchase")
	}
	proposal, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(purchase.Proposal)
	if err != nil {
		return nil, err
	}
	payload := preparedPurchasePayload{
		Proposal: proposal, ManifestCBORBase64: base64.StdEncoding.EncodeToString(purchase.ManifestCBOR),
		ManifestDigest: purchase.ManifestDigest, QuoteCommitment: purchase.QuoteCommitment,
		QuoteBOCBase64: purchase.QuoteBOCBase64, EscrowAddress: purchase.Escrow.Address,
		EscrowCodeHash: purchase.Escrow.CodeHash, EscrowTermsDigest: purchase.Escrow.EscrowTermsDigest,
		AuthorizationDigest: purchase.Escrow.AuthorizationDigest, TransportDigest: purchase.Escrow.TransportDigest,
		DisputePolicyDigest:      purchase.Escrow.DisputePolicyDigest,
		EscrowStateInitBOCBase64: purchase.Escrow.StateInitBOC,
		EscrowDataBOCBase64:      base64.StdEncoding.EncodeToString(purchase.Escrow.Data.ToBOC()),
		AssetMasterAddress:       purchase.AssetMasterAddress, BuyerWalletAddress: purchase.BuyerWalletAddress,
		AmountAtomic: purchase.AmountAtomic,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if _, err := decodePreparedPurchasePayload(payloadJSON); err != nil {
		return nil, err
	}
	digest, err := preparedPayloadDigest(payloadJSON)
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(preparedPurchaseEnvelope{Schema: preparedPurchaseSchema,
		Payload: payloadJSON, IntegrityDigest: digest}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// UnmarshalPreparedPurchase strictly decodes and verifies a staged artifact.
// Unknown fields, trailing JSON, non-canonical BOCs and any linked-identity
// substitution fail before the object can reach the Buyer SDK.
func UnmarshalPreparedPurchase(encoded []byte) (*buyersdk.PreparedPurchase, error) {
	if len(encoded) == 0 || len(encoded) > 4<<20 {
		return nil, errors.New("nativeimpl: invalid prepared-purchase artifact size")
	}
	var envelope preparedPurchaseEnvelope
	if err := decodeStrictJSON(encoded, &envelope); err != nil || envelope.Schema != preparedPurchaseSchema || len(envelope.Payload) == 0 {
		return nil, errors.New("nativeimpl: invalid prepared-purchase envelope")
	}
	digest, err := preparedPayloadDigest(envelope.Payload)
	if err != nil || envelope.IntegrityDigest != digest {
		return nil, errors.New("nativeimpl: prepared-purchase integrity mismatch")
	}
	return decodePreparedPurchasePayload(envelope.Payload)
}

func preparedPayloadDigest(encoded []byte) (string, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, encoded); err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("tos.openfox.prepared-purchase.v1\x00"), compact.Bytes()...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func decodePreparedPurchasePayload(encoded []byte) (*buyersdk.PreparedPurchase, error) {
	var payload preparedPurchasePayload
	if err := decodeStrictJSON(encoded, &payload); err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase payload")
	}
	var proposal nativev1.QuoteProposalV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload.Proposal, &proposal); err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase proposal")
	}
	manifest, err := decodeCanonicalBOC(payload.ManifestCBORBase64, 1<<20, false)
	if err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase manifest")
	}
	manifestHash := sha256.Sum256(manifest)
	if payload.ManifestDigest != "sha256:"+hex.EncodeToString(manifestHash[:]) || proposal.ManifestDigest != payload.ManifestDigest {
		return nil, errors.New("nativeimpl: prepared-purchase manifest changed")
	}
	quoteBOC, err := decodeCanonicalBOC(payload.QuoteBOCBase64, 1<<20, true)
	if err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase Quote")
	}
	quote, err := cell.FromBOC(quoteBOC)
	if err != nil || payload.QuoteCommitment != cellHashDigest(quote) {
		return nil, errors.New("nativeimpl: prepared-purchase Quote changed")
	}
	dataBOC, err := decodeCanonicalBOC(payload.EscrowDataBOCBase64, 1<<20, true)
	if err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase escrow data")
	}
	data, err := cell.FromBOC(dataBOC)
	if err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase escrow data")
	}
	state, err := nativecore.DecodeEscrowDataV1(data)
	if err != nil || state.QuoteCommitment != payload.QuoteCommitment || state.EscrowTermsDigest != payload.EscrowTermsDigest ||
		state.AuthorizationDigest != payload.AuthorizationDigest || state.TransportDigest != payload.TransportDigest ||
		state.DisputePolicyDigest != payload.DisputePolicyDigest || state.AssetMasterAddress != payload.AssetMasterAddress ||
		state.AcceptedQuote == nil || cellHashDigest(state.AcceptedQuote) != payload.QuoteCommitment ||
		!bytes.Equal(state.AcceptedQuote.ToBOC(), quote.ToBOC()) {
		return nil, errors.New("nativeimpl: prepared-purchase escrow links changed")
	}
	stateInitBOC, err := decodeCanonicalBOC(payload.EscrowStateInitBOCBase64, 2<<20, true)
	if err != nil {
		return nil, errors.New("nativeimpl: invalid prepared-purchase StateInit")
	}
	stateInit, err := cell.FromBOC(stateInitBOC)
	if err != nil || payload.EscrowAddress != "0:"+hex.EncodeToString(stateInit.Hash()) ||
		proposal.MaximumPrice == nil || proposal.MaximumPrice.Asset == nil || proposal.MaximumPrice.Asset.Master == nil ||
		proposal.MaximumPrice.AtomicAmount != payload.AmountAtomic {
		return nil, errors.New("nativeimpl: prepared-purchase identity changed")
	}
	expectedMaster := fmt.Sprintf("%d:%x", proposal.MaximumPrice.Asset.Master.Workchain,
		proposal.MaximumPrice.Asset.Master.AccountId)
	if payload.AssetMasterAddress != expectedMaster || payload.BuyerWalletAddress == "" || payload.EscrowCodeHash == "" {
		return nil, errors.New("nativeimpl: prepared-purchase asset route changed")
	}
	return &buyersdk.PreparedPurchase{Proposal: &proposal, ManifestCBOR: manifest,
		ManifestDigest: payload.ManifestDigest, QuoteCommitment: payload.QuoteCommitment,
		QuoteBOCBase64: payload.QuoteBOCBase64, Escrow: nativecore.EscrowIdentityV1{
			Address: payload.EscrowAddress, CodeHash: payload.EscrowCodeHash,
			QuoteCommitment: payload.QuoteCommitment, EscrowTermsDigest: payload.EscrowTermsDigest,
			AuthorizationDigest: payload.AuthorizationDigest, TransportDigest: payload.TransportDigest,
			DisputePolicyDigest: payload.DisputePolicyDigest, StateInitBOC: payload.EscrowStateInitBOCBase64, Data: data,
		}, AssetMasterAddress: payload.AssetMasterAddress, BuyerWalletAddress: payload.BuyerWalletAddress,
		AmountAtomic: payload.AmountAtomic}, nil
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeCanonicalBOC(value string, maximum int, requireCell bool) ([]byte, error) {
	if value == "" || strings.Join(strings.Fields(value), "") != value {
		return nil, errors.New("non-canonical Base64")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("invalid Base64")
	}
	if requireCell {
		parsed, err := cell.FromBOC(raw)
		if err != nil || !bytes.Equal(parsed.ToBOC(), raw) {
			return nil, errors.New("non-canonical cell BOC")
		}
	}
	return raw, nil
}

func cellHashDigest(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}
