package servicebridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/localapi"
)

// Owner decisions for private rooms and invites go to the Messenger daemon's
// owner socket in the daemon's offline ceremony: openfox prepares a decision
// (a fresh single-use challenge, the exact request and its signing bytes),
// the owner signs it away from the Agent runtime (`tos-messenger-owner sign`
// or a hardware signer), and openfox submits the signed decision. openfox
// never reads the owner's private key: holding it would let the Agent
// runtime approve its own requests.

// ChatOwnerDecisionSchema is the daemon's owner decision envelope, so a
// decision openfox prepares is signed by the daemon's own owner tool.
const ChatOwnerDecisionSchema = "tos.messaging.owner-decision.v1"

// maxChatOwnerDecisionBytes bounds a decision file read back.
const maxChatOwnerDecisionBytes = 64 << 10

// maxInviteTokenBytes bounds an invite token file: the token and a newline.
const maxInviteTokenBytes = 128

// maxInviteLifetime is the longest an invite lasts: the daemon refuses an
// expiry further out.
const maxInviteLifetime = 30 * 24 * time.Hour

// ChatOwnerDecision is one prepared or signed owner decision.
type ChatOwnerDecision struct {
	Schema          string           `json:"schema"`
	Request         localapi.Request `json:"request"`
	SigningBytesHex string           `json:"signing_bytes_hex"`
}

var (
	errChatOwnerSocket = errors.New("servicebridge: chat.owner_socket is not configured; room management " +
		"through openfox is off")
	errChatOwnerDecision = errors.New("servicebridge: the owner decision does not match its request")
)

// chatOwnerCaller is the daemon's owner socket; *localapi.Client is the
// production one.
type chatOwnerCaller interface {
	Call(ctx context.Context, request localapi.Request) (localapi.Response, error)
}

// chatOwnerClient connects to the owner socket the configuration names.
func chatOwnerClient(config NodeConfig) (*localapi.Client, error) {
	if config.Chat == nil || config.Chat.OwnerSocket == "" {
		return nil, errChatOwnerSocket
	}
	return localapi.NewClient(config.Chat.OwnerSocket, localapi.DefaultClientTimeout)
}

// prepareOwnerDecision takes a fresh challenge from the owner socket and
// binds the request to it. Only an owner decision is prepared.
func prepareOwnerDecision(ctx context.Context, owner chatOwnerCaller, request localapi.Request,
) (ChatOwnerDecision, error) {
	if owner == nil || ctx == nil || !localapi.Deciding(request.Op) {
		return ChatOwnerDecision{}, errors.New("servicebridge: not an owner decision")
	}
	request.Schema = localapi.RequestSchema
	if err := validateDecisionTerms(request); err != nil {
		return ChatOwnerDecision{}, err
	}
	issued, err := owner.Call(ctx, localapi.Request{Schema: localapi.RequestSchema, Op: localapi.OpChallenge})
	if err != nil {
		return ChatOwnerDecision{}, fmt.Errorf("servicebridge: take an owner challenge: %w", err)
	}
	request.Challenge = issued.Challenge
	preimage, err := localapi.DecisionBytes(request, issued.Challenge)
	if err != nil {
		return ChatOwnerDecision{}, fmt.Errorf("servicebridge: the daemon's challenge is unusable: %w", err)
	}
	return ChatOwnerDecision{
		Schema: ChatOwnerDecisionSchema, Request: request, SigningBytesHex: hex.EncodeToString(preimage),
	}, nil
}

// validateDecisionTerms checks a decision's terms with the daemon's own
// request validation. That validation also requires the challenge and the
// signature a decision carries once prepared and signed; before then they
// are stood in for, so only the terms are judged here.
func validateDecisionTerms(request localapi.Request) error {
	if request.Challenge == "" {
		request.Challenge = strings.Repeat("0", 2*localapi.ChallengeBytes)
	}
	if request.OwnerSignature == "" {
		request.OwnerSignature = strings.Repeat("0", 2*ed25519.SignatureSize)
	}
	if err := localapi.ValidateRequest(request); err != nil {
		return fmt.Errorf("servicebridge: invalid owner decision: %w", err)
	}
	return nil
}

// validOwnerDecision checks a decision envelope: an owner decision whose
// signing bytes are exactly its request's, signed (a canonical Ed25519
// signature) or not as required.
func validOwnerDecision(decision ChatOwnerDecision, signed bool) error {
	if decision.Schema != ChatOwnerDecisionSchema || !localapi.Deciding(decision.Request.Op) ||
		decision.Request.Schema != localapi.RequestSchema {
		return errors.New("servicebridge: not an owner decision of this daemon version")
	}
	if err := validateDecisionTerms(decision.Request); err != nil {
		return err
	}
	preimage, err := localapi.DecisionBytes(decision.Request, decision.Request.Challenge)
	if err != nil || decision.SigningBytesHex != hex.EncodeToString(preimage) {
		return errChatOwnerDecision
	}
	signature := decision.Request.OwnerSignature
	if !signed {
		if signature != "" {
			return errors.New("servicebridge: the prepared owner decision is already signed")
		}
		return nil
	}
	raw, err := hex.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize || signature != strings.ToLower(signature) {
		return errors.New("servicebridge: the owner decision has no canonical Ed25519 signature")
	}
	return nil
}

// writeOwnerDecision writes a prepared decision to a new owner-only file. A
// decision can carry a bearer (a presented invite token), so it is never
// printed and never replaces an existing file.
func writeOwnerDecision(path string, decision ChatOwnerDecision) error {
	if !cleanAbsolute(path) {
		return errors.New("servicebridge: --out must be an absolute clean path")
	}
	if err := validOwnerDecision(decision, false); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return errors.New("servicebridge: encode the owner decision")
	}
	if len(encoded) > maxChatOwnerDecisionBytes {
		return errors.New("servicebridge: the owner decision exceeds its bound")
	}
	if err := writeSynced(path, encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("servicebridge: --out names an existing file; it is never replaced")
		}
		return err
	}
	return nil
}

// readOwnerDecision strictly reads a decision file.
func readOwnerDecision(path string) (ChatOwnerDecision, error) {
	if !cleanAbsolute(path) {
		return ChatOwnerDecision{}, errors.New("servicebridge: --decision must be an absolute clean path")
	}
	raw, err := readBoundedFile(path, maxChatOwnerDecisionBytes)
	if err != nil {
		return ChatOwnerDecision{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decision ChatOwnerDecision
	if err := decoder.Decode(&decision); err != nil {
		return ChatOwnerDecision{}, errors.New("servicebridge: decode the owner decision")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ChatOwnerDecision{}, errors.New("servicebridge: the owner decision has trailing data")
	}
	return decision, nil
}

// readInviteToken reads an invite_ token from an owner-only file: it is a
// bearer, so it is never taken from the command line.
func readInviteToken(path string) (string, error) {
	if !cleanAbsolute(path) {
		return "", errors.New("servicebridge: the invite token file must be an absolute clean path")
	}
	raw, err := readPrivateFile(path, maxInviteTokenBytes)
	if err != nil {
		return "", fmt.Errorf("servicebridge: the invite token file must be an owner-only (0600) file of at "+
			"most %d bytes: %w", maxInviteTokenBytes, err)
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if !validInviteToken(token) {
		return "", errors.New("servicebridge: the invite token file must hold one invite_ token")
	}
	return token, nil
}

// validInviteToken checks the daemon's invite encoding: invite_ and 32
// non-zero random bytes in unpadded base64url.
func validInviteToken(token string) bool {
	const prefix = "invite_"
	if len(token) != len(prefix)+base64.RawURLEncoding.EncodedLen(32) || !strings.HasPrefix(token, prefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[len(prefix):])
	return err == nil && len(raw) == 32 && !bytes.Equal(raw, make([]byte, 32))
}

// ChatInvite is an invite another Agent's owner issued to this one: the
// token in an owner-only file and its expiry.
type ChatInvite struct {
	TokenFile     string
	ExpiresAtUnix uint64
}

// presentInviteRequest is the invites.present decision for recipient.
func presentInviteRequest(recipient string, invite ChatInvite, now time.Time) (localapi.Request, error) {
	if !agentIDPattern.MatchString(recipient) {
		return localapi.Request{}, errors.New("servicebridge: the invite's recipient must be an Agent id")
	}
	unix := now.Unix()
	if unix <= 0 || invite.ExpiresAtUnix <= uint64(unix) {
		return localapi.Request{}, errors.New("servicebridge: the invite has expired or names no expiry")
	}
	if invite.ExpiresAtUnix-uint64(unix) > uint64(maxInviteLifetime/time.Second) {
		return localapi.Request{}, errors.New("servicebridge: an invite expires at most 30 days ahead")
	}
	token, err := readInviteToken(invite.TokenFile)
	if err != nil {
		return localapi.Request{}, err
	}
	return localapi.Request{
		Op: localapi.OpPresentInvite, InviteRecipientAgentID: recipient, InviteToken: token,
		InviteExpiresAtUnix: invite.ExpiresAtUnix,
	}, nil
}

// ChatRoomOp names one room membership decision.
type ChatRoomOp string

// The room membership decisions, each the owner's (D13).
const (
	ChatRoomCreate ChatRoomOp = "create"
	ChatRoomAdd    ChatRoomOp = "add"
	ChatRoomRemove ChatRoomOp = "remove"
	ChatRoomJoin   ChatRoomOp = "join"
)

// roomRequest is the rooms.* decision for one membership change. agentID is
// the member to add or remove, or the authority whose invite is joined.
func roomRequest(op ChatRoomOp, roomID, agentID string) (localapi.Request, error) {
	if !roomIDPattern.MatchString(roomID) {
		return localapi.Request{}, errors.New("servicebridge: --room must be a room id (room_<64 hex>)")
	}
	needsAgent := op != ChatRoomCreate
	if needsAgent != (agentID != "") || (needsAgent && !agentIDPattern.MatchString(agentID)) {
		return localapi.Request{}, errors.New("servicebridge: create names no Agent; add, remove and join " +
			"name one Agent id (agent_<64 hex>)")
	}
	switch op {
	case ChatRoomCreate:
		return localapi.Request{Op: localapi.OpCreateRoom, RoomID: roomID}, nil
	case ChatRoomAdd:
		return localapi.Request{Op: localapi.OpAddRoomMember, RoomID: roomID, RoomMemberAgentID: agentID}, nil
	case ChatRoomRemove:
		return localapi.Request{Op: localapi.OpRemoveRoomMember, RoomID: roomID, RoomMemberAgentID: agentID}, nil
	case ChatRoomJoin:
		return localapi.Request{Op: localapi.OpJoinRoom, RoomID: roomID, RoomAuthorityAgentID: agentID}, nil
	default:
		return localapi.Request{}, errors.New("servicebridge: unknown room operation")
	}
}

// ChatPrepared reports a prepared decision.
type ChatPrepared struct {
	Op           localapi.Operation `json:"op"`
	DecisionFile string             `json:"decision_file"`
	// SignedFile is where Next has the owner's tool write the signed
	// decision: a new owner-only file, since a signed decision can carry an
	// invite bearer token.
	SignedFile string `json:"signed_file"`
	// Next is what the owner runs, exactly.
	Next string `json:"next"`
}

// signedDecisionSuffix names the signed decision beside the prepared one.
const signedDecisionSuffix = ".signed"

// chatPreparedNext is the exact commands that take a prepared decision to
// the daemon. The daemon's owner tool reads -out as a global flag, before
// its command, and writes a new 0600 file there instead of standard output.
func chatPreparedNext(configPath, decisionFile, signedFile string) string {
	return fmt.Sprintf("sign it away from the Agent runtime with `tos-messenger-owner -out %s sign -key "+
		"OWNER_KEY_FILE -decision %s` (-out goes before sign and writes a new 0600 file), then within two "+
		"minutes of preparing it run `openfox earning chat owner submit --rail-config %s --decision %s`",
		signedFile, decisionFile, configPath, signedFile)
}

// prepareToFile prepares a decision, writes it to out and says how the
// owner signs and submits it under the configuration at configPath.
func prepareToFile(ctx context.Context, owner chatOwnerCaller, request localapi.Request, configPath, out string,
) (ChatPrepared, error) {
	decision, err := prepareOwnerDecision(ctx, owner, request)
	if err != nil {
		return ChatPrepared{}, err
	}
	if err := writeOwnerDecision(out, decision); err != nil {
		return ChatPrepared{}, err
	}
	signed := out + signedDecisionSuffix
	return ChatPrepared{
		Op: request.Op, DecisionFile: out, SignedFile: signed, Next: chatPreparedNext(configPath, out, signed),
	}, nil
}

// ChatRoomPrepare prepares one room membership decision into out.
func ChatRoomPrepare(ctx context.Context, configPath string, op ChatRoomOp, roomID, agentID, out string,
) (*ChatPrepared, error) {
	request, err := roomRequest(op, roomID, agentID)
	if err != nil {
		return nil, err
	}
	owner, err := ownerFromConfig(configPath)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareToFile(ctx, owner, request, configPath, out)
	if err != nil {
		return nil, err
	}
	return &prepared, nil
}

// ChatInvitePresent prepares the invites.present decision of an invite the
// recipient Agent's owner issued to this one.
func ChatInvitePresent(ctx context.Context, configPath, recipient string, invite ChatInvite, out string,
	now time.Time,
) (*ChatPrepared, error) {
	request, err := presentInviteRequest(recipient, invite, now)
	if err != nil {
		return nil, err
	}
	owner, err := ownerFromConfig(configPath)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareToFile(ctx, owner, request, configPath, out)
	if err != nil {
		return nil, err
	}
	return &prepared, nil
}

// submitOwnerDecision sends a signed decision; the daemon verifies the
// signature and spends the challenge.
func submitOwnerDecision(ctx context.Context, owner chatOwnerCaller, decision ChatOwnerDecision,
) (localapi.Response, error) {
	if owner == nil || ctx == nil {
		return localapi.Response{}, errChatOwnerSocket
	}
	if err := validOwnerDecision(decision, true); err != nil {
		return localapi.Response{}, err
	}
	response, err := owner.Call(ctx, decision.Request)
	if err != nil {
		return response, fmt.Errorf("servicebridge: the daemon refused the owner decision: %w", err)
	}
	return response, nil
}

// ChatOwnerSubmitted reports a decision the daemon accepted.
type ChatOwnerSubmitted struct {
	Op     localapi.Operation `json:"op"`
	RoomID string             `json:"room_id,omitempty"`
}

// ChatOwnerSubmit submits a signed decision file.
func ChatOwnerSubmit(ctx context.Context, configPath, decisionFile string) (*ChatOwnerSubmitted, error) {
	decision, err := readOwnerDecision(decisionFile)
	if err != nil {
		return nil, err
	}
	owner, err := ownerFromConfig(configPath)
	if err != nil {
		return nil, err
	}
	response, err := submitOwnerDecision(ctx, owner, decision)
	if err != nil {
		return nil, err
	}
	return &ChatOwnerSubmitted{Op: decision.Request.Op, RoomID: response.RoomID}, nil
}

// ChatRooms is the daemon's private rooms: those held, and the pending joins
// a received room.invite opened (the invites this node may join).
type ChatRooms struct {
	Rooms   []localapi.RoomSummary `json:"rooms"`
	Invites []localapi.RoomSummary `json:"invites"`
}

// listChatRooms reads rooms.list, which needs no owner signature.
func listChatRooms(ctx context.Context, owner chatOwnerCaller) (ChatRooms, error) {
	if owner == nil || ctx == nil {
		return ChatRooms{}, errChatOwnerSocket
	}
	response, err := owner.Call(ctx, localapi.Request{Schema: localapi.RequestSchema, Op: localapi.OpListRooms})
	if err != nil {
		return ChatRooms{}, fmt.Errorf("servicebridge: list the daemon's rooms: %w", err)
	}
	out := ChatRooms{Rooms: []localapi.RoomSummary{}, Invites: []localapi.RoomSummary{}}
	for _, summary := range response.Rooms {
		if summary.State == "joined" {
			out.Rooms = append(out.Rooms, summary)
		} else {
			out.Invites = append(out.Invites, summary)
		}
	}
	return out, nil
}

// ChatRoomList lists the daemon's rooms and pending room invites.
func ChatRoomList(ctx context.Context, configPath string) (*ChatRooms, error) {
	owner, err := ownerFromConfig(configPath)
	if err != nil {
		return nil, err
	}
	rooms, err := listChatRooms(ctx, owner)
	if err != nil {
		return nil, err
	}
	return &rooms, nil
}

// ownerFromConfig opens the owner socket client a configuration names.
func ownerFromConfig(configPath string) (*localapi.Client, error) {
	config, err := loadChatConfig(configPath)
	if err != nil {
		return nil, err
	}
	return chatOwnerClient(config)
}
