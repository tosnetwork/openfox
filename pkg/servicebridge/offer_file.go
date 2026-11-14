package servicebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteprovider"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
)

// OfferFileSchema names the offer file a provider hands a buyer.
const OfferFileSchema = "tos.openfox.rail-offer.v1"

// maxOfferFile bounds an offer file: a manifest is at most 1 MiB before
// base64.
const maxOfferFile = 2 << 20

// OfferFile is what a buyer needs to buy from a published Capability
// without a gateway: which Capability version, and the manifest bytes its
// finalized digest commits to. It holds nothing secret and carries no
// authority: every field is checked against finalized state.
type OfferFile struct {
	Schema          string `json:"schema"`
	CapabilityID    string `json:"capability_id"`
	Version         string `json:"version"`
	ProviderAgentID string `json:"provider_agent_id"`
	ManifestDigest  string `json:"manifest_digest"`
	ManifestCBOR    string `json:"manifest_cbor_base64"`
	UpdatedUnix     int64  `json:"updated_unix"`
}

// Offer is a decoded offer file whose manifest bytes are canonical and hash
// to the digest it states.
type Offer struct {
	CapabilityID    string
	Version         string
	ProviderAgentID string
	ManifestDigest  string
	ManifestCBOR    []byte
}

// EncodeOfferFile renders an offer file.
func EncodeOfferFile(offer Offer, now time.Time) ([]byte, error) {
	if _, err := checkOffer(offer); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(OfferFile{
		Schema: OfferFileSchema, CapabilityID: offer.CapabilityID, Version: offer.Version,
		ProviderAgentID: offer.ProviderAgentID, ManifestDigest: offer.ManifestDigest,
		ManifestCBOR: base64.StdEncoding.EncodeToString(offer.ManifestCBOR), UpdatedUnix: now.Unix(),
	}, "", "  ")
	if err != nil {
		return nil, errors.New("servicebridge: encode the offer file")
	}
	return append(encoded, '\n'), nil
}

// checkOffer requires well-formed ids and manifest bytes that are the
// canonical encoding of a manifest of the stated version and digest.
func checkOffer(offer Offer) (nativecore.SoftwareWorkManifestV1, error) {
	var none nativecore.SoftwareWorkManifestV1
	if !capabilityPattern.MatchString(offer.CapabilityID) || !agentIDPattern.MatchString(offer.ProviderAgentID) ||
		offer.Version == "" {
		return none, errors.New("servicebridge: the offer names an invalid Capability, version or provider")
	}
	if len(offer.ManifestCBOR) == 0 || len(offer.ManifestCBOR) > 1<<20 {
		return none, errors.New("servicebridge: the offer's manifest is outside its bounds")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(offer.ManifestCBOR)
	if err != nil {
		return none, errors.New("servicebridge: the offer's manifest is not a canonical software-work manifest")
	}
	canonical, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, offer.ManifestCBOR) {
		return none, errors.New("servicebridge: the offer's manifest is not in canonical encoding")
	}
	if digest != offer.ManifestDigest {
		return none, errors.New("servicebridge: the offer's manifest does not hash to the digest the offer states")
	}
	if manifest.Version != offer.Version {
		return none, errors.New("servicebridge: the offer's manifest is for another version than the offer states")
	}
	return manifest, nil
}

// DecodeOfferFile strictly decodes an offer file: unknown fields, trailing
// data, another schema, and manifest bytes that do not hash to the stated
// digest are all refused.
func DecodeOfferFile(raw []byte) (Offer, error) {
	if len(raw) == 0 || len(raw) > maxOfferFile {
		return Offer{}, errors.New("servicebridge: the offer file is outside its bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file OfferFile
	if err := decoder.Decode(&file); err != nil {
		return Offer{}, errors.New("servicebridge: the offer file is not a strict offer record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Offer{}, errors.New("servicebridge: the offer file has trailing data")
	}
	if file.Schema != OfferFileSchema {
		return Offer{}, errors.New("servicebridge: the offer file has another schema")
	}
	manifest, err := base64.StdEncoding.Strict().DecodeString(file.ManifestCBOR)
	if err != nil {
		return Offer{}, errors.New("servicebridge: the offer's manifest is not standard base64")
	}
	offer := Offer{
		CapabilityID: file.CapabilityID, Version: file.Version, ProviderAgentID: file.ProviderAgentID,
		ManifestDigest: file.ManifestDigest, ManifestCBOR: manifest,
	}
	if _, err := checkOffer(offer); err != nil {
		return Offer{}, err
	}
	return offer, nil
}

// ReadOfferFile reads a bounded regular offer file. It is public input, so
// it need not be owner-only.
func ReadOfferFile(path string) (Offer, error) {
	if !cleanAbsolute(path) {
		return Offer{}, errors.New("servicebridge: the offer file path must be absolute and clean")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxOfferFile {
		return Offer{}, errors.New("servicebridge: the offer file is not a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Offer{}, errors.New("servicebridge: read the offer file")
	}
	return DecodeOfferFile(raw)
}

// writeOfferFile publishes the offer file in an owner-private directory.
func writeOfferFile(path string, offer Offer, now time.Time) error {
	encoded, err := EncodeOfferFile(offer, now)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("servicebridge: create the offer file directory")
	}
	return replaceSynced(path, encoded)
}

// OfferQuoteTTL is how long a Quote built from an offer file is valid.
const OfferQuoteTTL = 15 * time.Minute

const offerCallerID = "openfox-offer"

// OfferQuotes builds the Quote Proposal package locally from an offer file
// and finalized state, where a gateway would otherwise serve it. A package
// needs no provider secret and no signature, and it carries no authority:
// the purchase path validates it and compares it with the finalized offer
// exactly as it does a package from anywhere else.
//
// The provider Agent is the Capability's finalized owner, never the offer
// file's word; the manifest bytes must hash to the finalized digest of the
// version; the transport is the rail's deterministic Agent Packet binding
// to that owner.
type OfferQuotes struct {
	Sessions         quoteprovider.SessionSource
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	Offer            Offer
	Now              func() time.Time
	Random           func([]byte) error
}

// ErrOfferMismatch reports an offer file that finalized state contradicts.
var ErrOfferMismatch = errors.New("servicebridge: the offer file does not match finalized state")

// Quote implements QuoteSource.
func (o OfferQuotes) Quote(
	ctx context.Context,
	request *nativev1.RequestQuoteProposalRequest,
) (*nativev1.QuoteProposalPackageV1, error) {
	if o.Sessions == nil || o.Network == nil || request == nil || ctx == nil {
		return nil, errors.New("servicebridge: the offer quote source is not configured")
	}
	if _, err := checkOffer(o.Offer); err != nil {
		return nil, err
	}
	if request.GetCapabilityId() != o.Offer.CapabilityID || request.GetCapabilityVersion() != o.Offer.Version {
		return nil, fmt.Errorf("%w: the offer is for Capability %s version %q", ErrOfferMismatch,
			o.Offer.CapabilityID, o.Offer.Version)
	}
	session, err := o.Sessions.BeginSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: finalized state is unavailable: %w", err)
	}
	owner, err := finalizedOfferOwner(ctx, session, o.Offer)
	if err != nil {
		return nil, err
	}
	transport, _, err := RailTransport(owner)
	if err != nil {
		return nil, err
	}
	provider, err := quoteprovider.New(quoteprovider.Config{
		// The proposal is built at the checkpoint the offer was checked at.
		Sessions: fixedSession{session: session}, Network: o.Network, RegistryCodeHash: o.RegistryCodeHash,
		ProviderAgentID: owner, ManifestCBOR: o.Offer.ManifestCBOR, Transport: transport,
		ProposalTTL: OfferQuoteTTL, CallerID: offerCallerID, Now: o.Now, Random: o.Random,
	})
	if err != nil {
		return nil, fmt.Errorf("servicebridge: build the Quote from the offer: %w", err)
	}
	stamped := &nativev1.RequestQuoteProposalRequest{
		CapabilityId: request.GetCapabilityId(), CapabilityVersion: request.GetCapabilityVersion(),
		BuyerAddress: request.GetBuyerAddress(), Context: &nativev1.RequestContext{
			RequestId: request.GetCapabilityId() + "/" + request.GetCapabilityVersion(), CallerId: offerCallerID,
		},
	}
	pkg, err := provider.RequestQuoteProposal(ctx, stamped)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: build the Quote from the offer: %w", err)
	}
	return pkg, nil
}

// finalizedOfferOwner returns the Capability's finalized owner after
// requiring that the offered version is live and commits to the offer's
// manifest bytes.
func finalizedOfferOwner(ctx context.Context, session serviceactor.Session, offer Offer) (string, error) {
	state, found, err := session.ResolveRegistry(ctx, offer.CapabilityID)
	if err != nil {
		return "", fmt.Errorf("servicebridge: read Capability %s: %w", offer.CapabilityID, err)
	}
	capability := state.GetCapability()
	if !found || capability == nil || capability.GetCapabilityId() != offer.CapabilityID {
		return "", fmt.Errorf("%w: Capability %s is not in finalized state", ErrOfferMismatch, offer.CapabilityID)
	}
	if capability.GetTombstoned() {
		return "", fmt.Errorf("%w: Capability %s is revoked", ErrOfferMismatch, offer.CapabilityID)
	}
	owner := capability.GetOwnerAgentId()
	if !agentIDPattern.MatchString(owner) {
		return "", fmt.Errorf("%w: the Capability has no valid owner", ErrOfferMismatch)
	}
	if owner != offer.ProviderAgentID {
		return "", fmt.Errorf("%w: the Capability's finalized owner is %s, not the provider %s the offer names",
			ErrOfferMismatch, owner, offer.ProviderAgentID)
	}
	for _, version := range capability.GetVersions() {
		if version.GetVersion() != offer.Version {
			continue
		}
		if version.GetRevoked() {
			return "", fmt.Errorf("%w: version %q is revoked", ErrOfferMismatch, offer.Version)
		}
		if version.GetManifestDigest() != offer.ManifestDigest {
			return "", fmt.Errorf("%w: the finalized manifest digest of version %q is %s, but the offer's manifest "+
				"hashes to %s", ErrOfferMismatch, offer.Version, version.GetManifestDigest(), offer.ManifestDigest)
		}
		return owner, nil
	}
	return "", fmt.Errorf("%w: the Capability has no version %q", ErrOfferMismatch, offer.Version)
}

// fixedSession hands out one already opened finalized session.
type fixedSession struct{ session serviceactor.Session }

func (f fixedSession) BeginSession(context.Context) (serviceactor.Session, error) {
	if f.session == nil {
		return nil, errors.New("servicebridge: no finalized session")
	}
	return f.session, nil
}
