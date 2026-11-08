package earning

import (
	"bytes"
	"context"
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const (
	// ActionAuthorityController is the custody controller that signs every
	// Action Authority object: AuthorizedActionV1, WriterFenceV1 and relay
	// side-effect admission receipts.
	ActionAuthorityController = "action-authority"
	// CustodyAuthorizationController is the custody controller that signs the
	// TOS-EAA, TOS-CEA and TOS-PCEA custody authorizations.
	CustodyAuthorizationController = "custody-authorization"
)

// AuthorityCustody signs with named ML-DSA-44 controllers held in key
// custody and verifies ML-DSA-44 signatures. Production uses the pinned
// tosctl helper; no private key ever enters this process.
type AuthorityCustody interface {
	mldsa44.Signer
	mldsa44.Verifier
}

// AuthorityKeys pins the two owner authority keys by key ID and public key.
// The public keys are read from custody once, when the authority is
// initialized, and every later signature must come from exactly these keys.
type AuthorityKeys struct {
	Custody          AuthorityCustody
	ActionKeyID      string
	ActionPublicKey  []byte
	CustodyKeyID     string
	CustodyPublicKey []byte
}

func (keys AuthorityKeys) validate() error {
	if keys.Custody == nil {
		return errors.New("owner authority custody is unavailable")
	}
	actionID, err := commerce.ParseActionAuthorityKeyID(keys.ActionKeyID)
	if err != nil {
		return err
	}
	custodyID, err := commerce.ParseCustodyAuthorizationKeyID(keys.CustodyKeyID)
	if err != nil {
		return err
	}
	if derived, err := mldsa44.KeyID(keys.ActionPublicKey); err != nil || derived != actionID {
		return errors.New("Action Authority public key does not derive its key ID")
	}
	if derived, err := mldsa44.KeyID(keys.CustodyPublicKey); err != nil || derived != custodyID {
		return errors.New("custody authorization public key does not derive its key ID")
	}
	if actionID == custodyID {
		return errors.New("Action Authority and custody authorization must use distinct keys")
	}
	return nil
}

func (keys AuthorityKeys) clone() AuthorityKeys {
	keys.ActionPublicKey = append([]byte(nil), keys.ActionPublicKey...)
	keys.CustodyPublicKey = append([]byte(nil), keys.CustodyPublicKey...)
	return keys
}

// pinnedActionAuthority resolves exactly one Action Authority key for exactly
// one authority ID. It is the only way a local sink learns which key may sign
// for the owner authority.
type pinnedActionAuthority struct {
	authorityID string
	keyID       [mldsa44.KeyIDSize]byte
	publicKey   []byte
	verifier    mldsa44.Verifier
}

func newPinnedActionAuthority(authorityID, keyIDText string, publicKey []byte, verifier mldsa44.Verifier) (pinnedActionAuthority, error) {
	if authorityID == "" || verifier == nil {
		return pinnedActionAuthority{}, errors.New("Action Authority pin is incomplete")
	}
	keyID, err := commerce.ParseActionAuthorityKeyID(keyIDText)
	if err != nil {
		return pinnedActionAuthority{}, err
	}
	if derived, err := mldsa44.KeyID(publicKey); err != nil || derived != keyID {
		return pinnedActionAuthority{}, errors.New("Action Authority public key does not derive its key ID")
	}
	return pinnedActionAuthority{authorityID: authorityID, keyID: keyID, publicKey: append([]byte(nil), publicKey...),
		verifier: verifier}, nil
}

func (pin pinnedActionAuthority) ResolveActionAuthorityKey(authorityID string, keyID [mldsa44.KeyIDSize]byte, _ time.Time) ([]byte, error) {
	if pin.verifier == nil || authorityID != pin.authorityID || keyID != pin.keyID {
		return nil, errors.New("Action Authority key is not the pinned owner authority key")
	}
	return append([]byte(nil), pin.publicKey...), nil
}

func (pin pinnedActionAuthority) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if pin.verifier == nil {
		return mldsa44.ErrUnavailable
	}
	return pin.verifier.Verify(ctx, use, payload, publicKey, signature)
}

// pinnedCustodyAuthority resolves the one custody authorization key of an
// owner authority, for its exact owner and Agent.
type pinnedCustodyAuthority struct {
	authorityID, ownerID, agentID string
	keyID                         [mldsa44.KeyIDSize]byte
	publicKey                     []byte
	verifier                      mldsa44.Verifier
}

func (pin pinnedCustodyAuthority) ResolveCustodyAuthorizationKey(authorityID, ownerID, agentID string,
	keyID [mldsa44.KeyIDSize]byte, _ time.Time) ([]byte, error) {
	if pin.verifier == nil || authorityID != pin.authorityID || ownerID != pin.ownerID || agentID != pin.agentID ||
		keyID != pin.keyID {
		return nil, errors.New("custody authorization key is not the pinned owner custody key")
	}
	return append([]byte(nil), pin.publicKey...), nil
}

func (pin pinnedCustodyAuthority) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if pin.verifier == nil {
		return mldsa44.ErrUnavailable
	}
	return pin.verifier.Verify(ctx, use, payload, publicKey, signature)
}

// sameAuthorityPins reports whether a stored journal pin equals the keys an
// authority is opened with.
func sameAuthorityPins(document authorityDocument, keys AuthorityKeys) bool {
	return document.ActionAuthorityKeyID == keys.ActionKeyID &&
		bytes.Equal(document.ActionAuthorityPublicKey, keys.ActionPublicKey) &&
		document.CustodyAuthorizationKeyID == keys.CustodyKeyID &&
		bytes.Equal(document.CustodyAuthorizationPublicKey, keys.CustodyPublicKey)
}

func (authority *PersonalAuthority) actionAuthorityResolver() pinnedActionAuthority {
	resolver, err := newPinnedActionAuthority(authority.doc.AuthorityID, authority.keys.ActionKeyID,
		authority.keys.ActionPublicKey, authority.keys.Custody)
	if err != nil {
		// A resolver without a verifier refuses every key.
		return pinnedActionAuthority{}
	}
	return resolver
}

func (authority *PersonalAuthority) custodyAuthorityResolver() (pinnedCustodyAuthority, error) {
	keyID, err := commerce.ParseCustodyAuthorizationKeyID(authority.keys.CustodyKeyID)
	if err != nil || authority.keys.Custody == nil {
		return pinnedCustodyAuthority{}, errors.New("custody authorization pin is unavailable")
	}
	return pinnedCustodyAuthority{authorityID: authority.doc.AuthorityID, ownerID: authority.doc.OwnerID,
		agentID: authority.doc.AgentID, keyID: keyID, publicKey: authority.keys.CustodyPublicKey,
		verifier: authority.keys.Custody}, nil
}

func (authority *PersonalAuthority) signWriterFence(body commerce.WriterFenceBody) (commerce.WriterFence, error) {
	fence, err := commerce.SignWriterFence(context.Background(), body, authority.keys.Custody, ActionAuthorityController)
	if err != nil {
		return commerce.WriterFence{}, err
	}
	if fence.KeyID != authority.keys.ActionKeyID {
		return commerce.WriterFence{}, errors.New("custody signed the writer fence with a key other than the pinned Action Authority key")
	}
	return fence, nil
}

func (authority *PersonalAuthority) signAuthorizedAction(action commerce.AuthorizedAction) (commerce.AuthorizedAction, error) {
	return commerce.SignAuthorizedAction(context.Background(), action, authority.keys.ActionKeyID, authority.keys.Custody,
		ActionAuthorityController)
}

func (authority *PersonalAuthority) signRelayAdmissionReceipt(body agentrelay.RelaySideEffectAdmissionReceiptBody) (
	agentrelay.SignedRelaySideEffectAdmissionReceipt, error) {
	receipt, err := agentrelay.SignRelaySideEffectAdmissionReceipt(context.Background(), body, authority.keys.Custody,
		ActionAuthorityController)
	if err != nil {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if receipt.KeyID != authority.keys.ActionKeyID {
		return agentrelay.SignedRelaySideEffectAdmissionReceipt{}, errors.New(
			"custody signed the relay admission receipt with a key other than the pinned Action Authority key")
	}
	return receipt, nil
}

func (authority *PersonalAuthority) signCustodyAuthorization(body commerce.CustodyActionAuthorization) (
	commerce.CustodyActionAuthorization, error) {
	signed, err := commerce.SignCustodyActionAuthorization(context.Background(), body, authority.keys.Custody,
		CustodyAuthorizationController)
	if err != nil {
		return commerce.CustodyActionAuthorization{}, err
	}
	if signed.KeyID != authority.keys.CustodyKeyID {
		return commerce.CustodyActionAuthorization{}, errors.New(
			"custody signed the authorization with a key other than the pinned custody authorization key")
	}
	return signed, nil
}

func (authority *PersonalAuthority) signPredictionCustodyEffect(body commerce.PredictionCustodyEffectAuthorizationV1) (
	commerce.PredictionCustodyEffectAuthorizationV1, error) {
	signed, err := commerce.SignPredictionCustodyEffectAuthorizationV1(context.Background(), body, authority.keys.Custody,
		CustodyAuthorizationController)
	if err != nil {
		return commerce.PredictionCustodyEffectAuthorizationV1{}, err
	}
	if signed.KeyID != authority.keys.CustodyKeyID {
		return commerce.PredictionCustodyEffectAuthorizationV1{}, errors.New(
			"custody signed the prediction effect with a key other than the pinned custody authorization key")
	}
	return signed, nil
}

// verifyStoredCustodyAuthorization re-verifies a journaled custody
// authorization's proof against the pinned custody key. Its expiry is judged
// separately by the caller, so the proof is checked at an instant inside the
// authorization's own validity window.
func (authority *PersonalAuthority) verifyStoredCustodyAuthorization(value commerce.CustodyActionAuthorization) error {
	if value.ExpiresAtUnix == 0 || value.ExpiresAtUnix > uint64(1<<63-1) || value.KeyID != authority.keys.CustodyKeyID {
		return errors.New("stored custody authorization is not under the pinned custody key")
	}
	resolver, err := authority.custodyAuthorityResolver()
	if err != nil {
		return err
	}
	return commerce.VerifyCustodyActionAuthorization(value, resolver, time.Unix(int64(value.ExpiresAtUnix)-1, 0).UTC())
}

// verifyStoredRelayAdmissionReceipt re-verifies a journaled relay admission
// receipt's Action Authority signature against the pinned key.
func (authority *PersonalAuthority) verifyStoredRelayAdmissionReceipt(receipt agentrelay.SignedRelaySideEffectAdmissionReceipt) error {
	_, err := agentrelay.VerifyRelaySideEffectAdmissionReceiptAuthority(receipt, authority.actionAuthorityResolver())
	return err
}

func (pin pinnedActionAuthority) keyIDText() string {
	if pin.verifier == nil {
		return ""
	}
	return mldsa44.KeyIDText(pin.keyID)
}

// ActionAuthorityKey returns the pinned Action Authority key ID and public
// key. Both are public; no signing material leaves custody.
func (authority *PersonalAuthority) ActionAuthorityKey() (string, []byte) {
	if authority == nil {
		return "", nil
	}
	return authority.keys.ActionKeyID, append([]byte(nil), authority.keys.ActionPublicKey...)
}

// AuthorityID returns the authority identity this journal serves.
func (authority *PersonalAuthority) AuthorityID() string {
	if authority == nil {
		return ""
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.doc.AuthorityID
}
