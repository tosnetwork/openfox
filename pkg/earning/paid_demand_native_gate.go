package earning

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/executiongate"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// PaidDemandNativeGate reconstructs the exact escrow address from the
// Agreement package and claims the chain-backed, one-shot execution identity.
// It is business-neutral: the work payload remains opaque; only its committed
// input and source digests cross this boundary.
type PaidDemandNativeGate struct {
	Directory        string
	Store            *PaidDemandNegotiationStore
	PublicTerms      paiddemand.PublicTermsV1
	Network          *nativev1.NetworkDomain
	EscrowResolver   *toschain.EscrowResolver
	NativeResolver   executiongate.NativeResolver
	RegistryCodeHash string
	EscrowCode       *cell.Cell
	AssetWalletCode  *cell.Cell
	OfferAuthorities commerce.ProviderOfferKeyResolver
}

func (gate PaidDemandNativeGate) AdmitNativeExecution(ctx context.Context, record EngagementRecord,
	plan commercegate.Plan) (bool, []string, error) {
	if !agreementUsesPaidDemand(record.Agreement.Body, plan.ExecutionObligationID) {
		return false, nil, nil
	}
	if gate.Store == nil || gate.Network == nil || gate.EscrowResolver == nil || gate.NativeResolver == nil ||
		gate.EscrowCode == nil || gate.AssetWalletCode == nil || gate.OfferAuthorities == nil ||
		!filepath.IsAbs(gate.Directory) || filepath.Clean(gate.Directory) != gate.Directory {
		return true, nil, errors.New("Paid Demand Native Gate is incomplete")
	}
	packageValue, found, err := gate.Store.Get(record.AgreementDigest)
	if err != nil || !found {
		if err == nil {
			err = errors.New("Paid Demand execution has no retained negotiation package")
		}
		return true, nil, err
	}
	proposal, err := paiddemand.ValidateNegotiationPackageOnNetwork(record.Agreement.Body, gate.PublicTerms,
		packageValue, gate.Network, paidDemandOfferVerificationTime(record, packageValue.Binding))
	if err != nil {
		return true, nil, err
	}
	offer, found, err := paidDemandProviderOffer(record, packageValue.Binding.ProviderAgentID)
	if err != nil || !found {
		if err == nil {
			err = errors.New("Paid Demand execution has no verified Provider Offer")
		}
		return true, nil, err
	}
	offerTime := time.Unix(int64(offer.Context.ValidFromUnix), 0).UTC()
	if !offerTime.Before(time.Unix(int64(packageValue.Binding.AcceptByUnix), 0).UTC()) {
		return true, nil, errors.New("Paid Demand Provider Offer has no valid pre-acceptance instant")
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(packageValue.ExecutionSignerEd25519)
	if err != nil {
		return true, nil, err
	}
	quote, commitment, err := paiddemand.BuildAcceptedQuote(paiddemand.QuoteBuildInput{Agreement: record.Agreement.Body,
		ProviderOffer: offer, ProviderOfferResolver: gate.OfferAuthorities, Network: gate.Network, Proposal: proposal,
		ExecutionSignerAuthorization: "sha256:" + hex.EncodeToString(authorization.Hash()), EscrowTerms: packageValue.EscrowTerms,
		ExecutionDeadlineUnix: packageValue.ExecutionDeadlineUnix, Now: offerTime})
	if err != nil {
		return true, nil, err
	}
	escrow, err := nativecore.BuildEscrowStateInitV2(0, gate.EscrowCode, nativecore.EscrowInitV2{Network: gate.Network,
		AcceptedQuote: quote, Terms: packageValue.EscrowTerms, ExecutionSignerEd25519: packageValue.ExecutionSignerEd25519,
		TransportBinding: packageValue.TransportBinding, AssetMasterAddress: gate.PublicTerms.AssetMasterAddress,
		AssetWalletCode: gate.AssetWalletCode})
	if err != nil || escrow.QuoteCommitment != commitment {
		return true, nil, errors.New("Paid Demand execution could not reconstruct the exact escrow")
	}
	inputDigest, sourceDigest, err := paidDemandExecutionInputs(record.Agreement.Body, plan.ExecutionObligationID)
	if err != nil {
		return true, nil, err
	}
	manifest, err := paiddemand.DecodeCanonicalExecutionManifest(packageValue.ManifestCanonical)
	if err != nil || manifest.AgreementBodyDigest != record.AgreementDigest {
		return true, nil, errors.New("Paid Demand execution manifest is not Agreement-bound")
	}
	_, manifestDigest, err := paiddemand.CanonicalExecutionManifest(manifest)
	if err != nil {
		return true, nil, err
	}
	_, transportDigest, err := nativecore.BuildTransportBindingCellV1(packageValue.TransportBinding)
	if err != nil {
		return true, nil, err
	}
	agreementDirectory := filepath.Join(gate.Directory, strings.TrimPrefix(record.AgreementDigest, "sha256:"))
	if err := ensurePrivateGateDirectory(agreementDirectory); err != nil {
		return true, nil, err
	}
	nativeGate, err := executiongate.NewPaidDemand(executiongate.PaidDemandConfig{Directory: agreementDirectory,
		EscrowResolver: gate.EscrowResolver, NativeResolver: gate.NativeResolver, Network: gate.Network,
		RegistryCodeHash: gate.RegistryCodeHash, ProviderAgentID: packageValue.Binding.ProviderAgentID,
		ProviderAddress: packageValue.Binding.ProviderWallet, ManifestDigest: manifestDigest, TransportDigest: transportDigest,
		ExecutionSignerAuthorization: "sha256:" + hex.EncodeToString(authorization.Hash()), Agreement: record.Agreement.Body,
		ProviderOfferResolver: gate.OfferAuthorities, Timeout: 30 * time.Second})
	if err != nil {
		return true, nil, err
	}
	evidence, err := nativeGate.ClaimPaidDemandExecution(ctx, executiongate.Request{EscrowAddress: escrow.Address,
		QuoteCommitment: commitment, ExecutionID: plan.ExecutionID, InputDigest: inputDigest, SourceDigest: sourceDigest})
	if err != nil {
		return true, nil, err
	}
	evidenceDigest, err := codec.Digest("tos.paid-demand-native-execution-evidence.v1", evidence)
	if err != nil {
		return true, nil, err
	}
	return true, []string{evidenceDigest}, nil
}

func agreementUsesPaidDemand(body commerce.AgentAgreementBody, executionObligationID string) bool {
	for _, obligation := range body.Obligations {
		if obligation.Amount != nil && obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI {
			for _, dependency := range obligation.DependsOnObligationIDs {
				if dependency == executionObligationID {
					return true
				}
			}
		}
	}
	return false
}

func paidDemandOfferVerificationTime(record EngagementRecord, binding commerce.PaidDemandQuoteBindingBody) time.Time {
	value := record.Agreement.Body.ValidFromUnix
	if value < binding.AcceptByUnix {
		value++
	}
	return time.Unix(int64(value), 0).UTC()
}

func paidDemandExecutionInputs(body commerce.AgentAgreementBody, obligationID string) (string, string, error) {
	for _, obligation := range body.Obligations {
		if obligation.ObligationID != obligationID {
			continue
		}
		var input, source string
		for _, extension := range obligation.RequiredExtensions {
			switch {
			case strings.HasPrefix(extension, "tos.input."):
				input = "sha256:" + strings.TrimPrefix(extension, "tos.input.")
			case strings.HasPrefix(extension, "tos.source."):
				source = "sha256:" + strings.TrimPrefix(extension, "tos.source.")
			}
		}
		attachments := append([]string(nil), obligation.AttachmentDigests...)
		sort.Strings(attachments)
		if input == "" || source == "" || input == source || !containsString(attachments, input) || !containsString(attachments, source) {
			return "", "", errors.New("Paid Demand work obligation lacks exact input/source commitments")
		}
		return input, source, nil
	}
	return "", "", errors.New("Paid Demand execution obligation is absent")
}

func ensurePrivateGateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("Paid Demand Native Gate directory is not owner-private")
	}
	return nil
}

var _ NativeExecutionAdmission = PaidDemandNativeGate{}
