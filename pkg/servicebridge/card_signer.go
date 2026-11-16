package servicebridge

import (
	"context"
	"errors"
	"fmt"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// The card-signing controller is a second ML-DSA-44 controller of the
// Agent's finalized policy, held in the tosctl vault, that signs the chat key
// cards and nothing else. Removing it from the finalized policy revokes every
// card it signed without stopping the node's packets, which the packet
// controller keeps signing. It is registered without authority of its own:
// its weight is below the policy threshold and it holds no recovery purpose,
// so it can neither act on the Agent nor recover it alone.
const (
	// agentPolicyThreshold is the threshold of every purpose (and of
	// recovery) of the policy `init` registers.
	agentPolicyThreshold = 2
	// packetControllerWeight lets the packet controller meet the threshold
	// alone, as the only controller with authority.
	packetControllerWeight = agentPolicyThreshold
	// cardControllerWeight keeps the card controller below the threshold.
	cardControllerWeight = 1
	// cardControllerPurposes is the one purpose bit the card controller
	// carries: the registry requires a non-empty purpose set, and with a
	// weight below the threshold this bit authorizes nothing alone.
	cardControllerPurposes = 2
	// cardControllerSuffix names the default card controller after the
	// packet controller.
	cardControllerSuffix = "-card"
)

// Typed refusals of the card-signing controller checks.
var (
	// ErrCardControllerMissing refuses chat card issuance on a node whose
	// configuration names no card-signing controller.
	ErrCardControllerMissing = errors.New("servicebridge: no card-signing controller is configured")
	// ErrCardControllerIsPacketController refuses a card controller that is
	// the packet controller: revoking it would stop every packet.
	ErrCardControllerIsPacketController = errors.New("servicebridge: the card-signing controller is the packet " +
		"controller")
	// ErrCardControllerNotInPolicy refuses a card controller the Agent's
	// finalized policy does not hold: every card it signs is unusable.
	ErrCardControllerNotInPolicy = errors.New("servicebridge: the card-signing controller is not in the Agent's " +
		"finalized policy")
	// ErrCardControllerHasAuthority refuses a card controller that could
	// act on the Agent alone: its key would be as valuable as the packet
	// controller's.
	ErrCardControllerHasAuthority = errors.New("servicebridge: the card-signing controller holds authority over " +
		"the Agent")
)

// defaultCardController names the card controller `init` provisions when
// none is given.
func defaultCardController(packetController string) (string, error) {
	name := packetController + cardControllerSuffix
	if !walletNamePattern.MatchString(name) {
		return "", errors.New("servicebridge: the default card controller name (the packet controller name with " +
			cardControllerSuffix + ") is not a valid controller name; pass --card-controller")
	}
	return name, nil
}

// CardSigner signs key cards, and only key cards, with the card-signing
// controller. It offers no way to sign any other packet.
type CardSigner struct {
	packet *PacketSigner
}

// NewCardSigner binds the card-signing controller to the local Agent. It
// refuses a controller whose key is the packet controller's.
func NewCardSigner(signer mldsa44.Signer, controller, keyIDText, agentID, packetKeyIDText string) (*CardSigner,
	error,
) {
	if controller == "" || keyIDText == "" {
		return nil, ErrCardControllerMissing
	}
	if !walletNamePattern.MatchString(controller) {
		return nil, errors.New("servicebridge: card_controller is not a valid controller name")
	}
	packetKey, err := mldsa44.ParseKeyIDText(packetKeyIDText)
	if err != nil {
		return nil, errors.New("servicebridge: packet_key_id is not a key id")
	}
	inner, err := NewPacketSigner(signer, controller, keyIDText, agentID)
	if err != nil {
		return nil, fmt.Errorf("servicebridge: invalid card signer: %w", err)
	}
	if inner.KeyID == packetKey {
		return nil, ErrCardControllerIsPacketController
	}
	return &CardSigner{packet: inner}, nil
}

// validateCardConfig checks the card-signing controller a configuration
// names, without the vault or the chain.
func validateCardConfig(config NodeConfig) error {
	if config.CardController == "" || config.CardKeyID == "" {
		return fmt.Errorf("%w: card_controller and card_key_id are not both set; run `openfox earning service "+
			"init` for a new Agent (it provisions the card controller), or name a controller the Agent's "+
			"finalized policy already holds with `openfox earning chat card-controller`", ErrCardControllerMissing)
	}
	if !walletNamePattern.MatchString(config.CardController) {
		return errors.New("servicebridge: card_controller is not a valid controller name")
	}
	cardKey, err := mldsa44.ParseKeyIDText(config.CardKeyID)
	if err != nil {
		return errors.New("servicebridge: card_key_id is not a key id")
	}
	packetKey, err := mldsa44.ParseKeyIDText(config.PacketKeyID)
	if err != nil {
		return errors.New("servicebridge: packet_key_id is not a key id")
	}
	if cardKey == packetKey || config.CardController == config.PacketController {
		return ErrCardControllerIsPacketController
	}
	return nil
}

// newConfigCardSigner opens the card signer a configuration names.
func newConfigCardSigner(signer mldsa44.Signer, config NodeConfig) (*CardSigner, error) {
	if err := validateCardConfig(config); err != nil {
		return nil, err
	}
	return NewCardSigner(signer, config.CardController, config.CardKeyID, config.AgentID, config.PacketKeyID)
}

// AgentID is the Agent the cards are signed for.
func (s *CardSigner) AgentID() string { return s.packet.AgentID }

// KeyID is the card controller's key id.
func (s *CardSigner) KeyID() [mldsa44.KeyIDSize]byte { return s.packet.KeyID }

func (s *CardSigner) signKeyCard(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
	return s.packet.signKeyCard(ctx, card)
}

func (s *CardSigner) cardKeyID() [mldsa44.KeyIDSize]byte { return s.packet.KeyID }

// checkCardController checks the card controller against the Agent's
// finalized policy: it is a controller of the policy, it is not the packet
// controller, and it cannot act on the Agent alone.
func checkCardController(agent *nativev1.AgentStateV1, cardKeyID, packetKeyID string) error {
	if agent == nil || agent.GetPolicy() == nil || agent.GetTombstoned() {
		return errors.New("servicebridge: the Agent is not finalized and live")
	}
	if cardKeyID == packetKeyID {
		return ErrCardControllerIsPacketController
	}
	policy := agent.GetPolicy()
	for _, controller := range policy.GetControllers() {
		if controller.GetKeyId() != cardKeyID {
			continue
		}
		if controller.GetRecovery() || controller.GetWeight() >= policy.GetThreshold() {
			return fmt.Errorf("%w: key %s has weight %d against threshold %d (recovery %t); it must stay below "+
				"the threshold without the recovery purpose", ErrCardControllerHasAuthority, cardKeyID,
				controller.GetWeight(), policy.GetThreshold(), controller.GetRecovery())
		}
		return nil
	}
	return fmt.Errorf("%w: key %s is not a controller of Agent %s", ErrCardControllerNotInPolicy, cardKeyID,
		agent.GetAgentId())
}
