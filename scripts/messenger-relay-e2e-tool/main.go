// Command messenger-relay-e2e-tool is the test-only helper of
// scripts/messenger-relay-two-host-e2e.py. It is not part of OpenFox and no
// OpenFox code path runs it. It covers what the acceptance run needs and no
// shipped tool provides:
//
//   - identity: a Messaging Endpoint key, an owner key, a device and an ADNL
//     identity, the Endpoint delegation and the descriptor policy it commits,
//     and the delegation digest the Agent commits on chain;
//   - signer: a software Endpoint signer serving the Messenger's signer
//     socket protocol for one test key (the repository ships only the client,
//     because a production signer must not load an exportable key);
//   - call: one request on a Messenger runtime or owner socket;
//   - inspect: decode a signed packet and the relay frame it carries, or a
//     sealed envelope's public header;
//   - craft: sign a packet as a given Agent through tosctl custody, seal it to
//     a key card and write the envelope, for the run's adversarial cases;
//   - room-frames: build one room object of a given type and size and cut it
//     into its kind-3 frames, each written as a payload file for craft, for
//     the private-room run's crafted objects (a production-cut 6-part object,
//     a Commit from a non-authority).
//
// Private keys are written only to files of mode 0600 that this tool reads
// back; no key is printed.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/signerapi"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

func main() {
	if len(os.Args) < 2 {
		fail(
			errors.New(
				"usage: messenger-relay-e2e-tool identity|signer|call|inspect|craft|room-frames [flags]",
			),
		)
	}
	var err error
	switch os.Args[1] {
	case "identity":
		err = identityCommand(os.Args[2:])
	case "signer":
		err = signerCommand(os.Args[2:])
	case "call":
		err = callCommand(os.Args[2:])
	case "inspect":
		err = inspectCommand(os.Args[2:])
	case "craft":
		err = craftCommand(os.Args[2:])
	case "room-frames":
		err = roomFramesCommand(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "messenger-relay-e2e-tool: "+err.Error())
	os.Exit(1)
}

func printJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(encoded))
	return err
}

func randomHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("draw random bytes")
	}
	return hex.EncodeToString(raw), nil
}

// writePrivate writes a new owner-only file; an existing file is refused so
// a run never overwrites a key.
func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// --- identity ------------------------------------------------------------------

func identityCommand(args []string) error {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	agentID := flags.String("agent", "", "the finalized Agent the Endpoint speaks for")
	networkID := flags.String("network-id", "", "network label, as the registry domain names it")
	genesisRoot := flags.String("genesis-root", "", "64 hex genesis root hash")
	genesisFile := flags.String("genesis-file", "", "64 hex genesis file hash")
	rule := flags.String(
		"rule",
		string(admission.RuleAllowList),
		"inbox rule the delegation commits",
	)
	unknown := flags.String(
		"unknown",
		string(admission.InviteOrAskOwner),
		"unknown-sender rule the delegation commits",
	)
	descriptorLifetime := flags.Uint64(
		"descriptor-lifetime",
		3600,
		"descriptor policy max_lifetime_seconds",
	)
	delegationLifetime := flags.Uint64(
		"delegation-lifetime",
		7*24*3600,
		"delegation validity window in seconds",
	)
	sessionLifetime := flags.Uint64(
		"session-lifetime",
		24*3600,
		"maximum session lifetime in seconds",
	)
	classes := flags.String(
		"classes",
		"agent.packet,text",
		"comma-separated outbound event classes, sorted",
	)
	privateDir := flags.String(
		"private-dir",
		"",
		"owner-only directory for the Endpoint and owner keys",
	)
	publicDir := flags.String(
		"public-dir",
		"",
		"directory for the delegation and descriptor policy",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	network := &nativev1.NetworkDomain{
		NetworkId:       *networkID,
		GenesisRootHash: *genesisRoot,
		GenesisFileHash: *genesisFile,
	}
	if *privateDir == "" || *publicDir == "" {
		return errors.New("identity needs --private-dir and --public-dir")
	}
	public, endpointKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate the Endpoint key")
	}
	ownerPublic, ownerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate the owner key")
	}
	endpointID, err := identity.DeriveEndpointID(network, *agentID, public)
	if err != nil {
		return err
	}
	deviceHex, err := randomHex(32)
	if err != nil {
		return err
	}
	adnlHex, err := randomHex(32)
	if err != nil {
		return err
	}
	descriptorPolicy := directory.DescriptorPolicy{
		MaxEnvelopeBytes: 256 << 10, MaxLifetimeSeconds: *descriptorLifetime,
		RequireADNL: true,
	}
	descriptorDigest, err := descriptorPolicy.Digest()
	if err != nil {
		return err
	}
	descriptorJSON, err := directory.EncodeDescriptorPolicyJSON(descriptorPolicy)
	if err != nil {
		return err
	}
	inbox, err := admission.NewContactPolicy(admission.InboxPolicyDocument{
		Rule:    admission.InboxRule(*rule),
		Unknown: admission.UnknownSenderRule(*unknown),
	}, admission.Roster{})
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	delegation := identity.Delegation{
		Network: network, AgentID: *agentID, EndpointID: endpointID, IdentityPublicKey: public,
		ADNLID: "adnl:" + adnlHex, AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: strings.Split(*classes, ","),
		NotBeforeUnix:               now - 60, ExpiresAtUnix: now - 60 + *delegationLifetime,
		MaximumSessionLifetimeSeconds: *sessionLifetime, ContactDescriptorPolicyDigest: descriptorDigest,
		InboxAdmissionPolicyDigest: inbox.Digest(),
	}
	delegationJSON, err := identity.EncodeJSON(delegation)
	if err != nil {
		return err
	}
	digest, err := identity.Digest(delegation)
	if err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(*privateDir, "endpoint.key"),
		[]byte(hex.EncodeToString(endpointKey.Seed())+"\n")); err != nil {
		return err
	}
	// The owner tool reads a 64-byte Ed25519 private key as 128 hex digits.
	if err = writePrivate(filepath.Join(*privateDir, "owner.key"), []byte(hex.EncodeToString(ownerKey))); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*publicDir, "delegation.json"), delegationJSON, 0o600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*publicDir, "descriptor-policy.json"), descriptorJSON, 0o600); err != nil {
		return err
	}
	clear(endpointKey)
	clear(ownerKey)
	return printJSON(map[string]any{
		"agent_id": *agentID, "endpoint_id": endpointID, "device_id": "dev_" + deviceHex, "adnl_id": "adnl:" + adnlHex,
		"endpoint_public_key": hex.EncodeToString(
			public,
		), "owner_public_key": hex.EncodeToString(ownerPublic),
		"delegation_digest": digest, "delegation_digest_hex": strings.TrimPrefix(digest, "sha256:"),
		"descriptor_policy_digest": descriptorDigest, "inbox_policy_digest": inbox.Digest(),
		"not_before_unix": delegation.NotBeforeUnix, "expires_at_unix": delegation.ExpiresAtUnix,
	})
}

// --- signer --------------------------------------------------------------------

type signRequest struct {
	Schema  string `json:"schema"`
	Message []byte `json:"message_base64"`
}

type signResponse struct {
	Schema    string `json:"schema"`
	OK        bool   `json:"ok"`
	Signature []byte `json:"signature_base64,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func readKeyFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the Endpoint key file is not a 32-byte hex seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return key, nil
}

func readFrame(reader io.Reader, maximum uint32) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maximum {
		return nil, errors.New("frame length outside its bound")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeFrame(writer io.Writer, body []byte) error {
	framed := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(framed, uint32(len(body)))
	_, err := writer.Write(append(framed, body...))
	return err
}

func signerCommand(args []string) error {
	flags := flag.NewFlagSet("signer", flag.ContinueOnError)
	keyPath := flags.String("key", "", "owner-only file holding the Endpoint seed")
	socketPath := flags.String("socket", "", "Unix socket to serve")
	logPath := flags.String(
		"count-file",
		"",
		"optional file the number of signatures is written to",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := readKeyFile(*keyPath)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(*socketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(*socketPath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socketPath, 0o600); err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		_ = listener.Close()
	}()
	fmt.Println("ready")
	count := 0
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			_ = os.Remove(*socketPath)
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return acceptErr
		}
		count++
		if *logPath != "" {
			_ = os.WriteFile(*logPath, []byte(fmt.Sprintf("%d\n", count)), 0o600)
		}
		go serveSign(connection, key)
	}
}

func serveSign(connection net.Conn, key ed25519.PrivateKey) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	body, err := readFrame(connection, signerapi.MaxFrameBytes)
	if err != nil {
		return
	}
	var request signRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	answer := signResponse{Schema: signerapi.ResponseSchema}
	if err = decoder.Decode(&request); err != nil || request.Schema != signerapi.RequestSchema ||
		len(request.Message) == 0 {
		answer.Detail = "malformed request"
	} else {
		answer.OK = true
		answer.Signature = ed25519.Sign(key, request.Message)
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return
	}
	_ = writeFrame(connection, encoded)
}

// --- call ----------------------------------------------------------------------

func callCommand(args []string) error {
	flags := flag.NewFlagSet("call", flag.ContinueOnError)
	socketPath := flags.String("socket", "", "Messenger runtime or owner socket")
	timeout := flags.Duration("timeout", 50*time.Second, "bound of the call")
	if err := flags.Parse(args); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, localapi.MaxFrameBytes))
	if err != nil {
		return err
	}
	var request localapi.Request
	if err = json.Unmarshal(raw, &request); err != nil {
		return err
	}
	if request.Schema == "" {
		request.Schema = localapi.RequestSchema
	}
	client, err := localapi.NewClient(*socketPath, *timeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := client.Call(ctx, request)
	if err != nil {
		return err
	}
	return printJSON(response)
}

// --- inspect -------------------------------------------------------------------

type frameView struct {
	Kind            uint8  `json:"kind"`
	PartIndex       uint8  `json:"part_index"`
	PartCount       uint8  `json:"part_count"`
	FrameBytes      int    `json:"frame_bytes"`
	IsBucket        bool   `json:"is_bucket"`
	SmallestBucket  int    `json:"smallest_bucket"`
	CardBytes       int    `json:"card_bytes"`
	EvidenceBytes   int    `json:"evidence_bytes"`
	EvidenceDigest  string `json:"evidence_digest,omitempty"`
	PartBytes       int    `json:"part_bytes"`
	CardSenderAgent string `json:"card_sender_agent_id,omitempty"`
	CardKeyID       string `json:"card_key_id,omitempty"`
	// Copy and ack fields are what the relays must never see in clear.
	EventID             string `json:"event_id,omitempty"`
	SessionID           string `json:"session_id,omitempty"`
	ConversationID      string `json:"conversation_id,omitempty"`
	RecipientEndpointID string `json:"recipient_endpoint_id,omitempty"`
	RecipientDeviceID   string `json:"recipient_device_id,omitempty"`
	AdmissionToken      bool   `json:"carries_admission_token,omitempty"`
	BootstrapBytes      int    `json:"bootstrap_bytes,omitempty"`
	CiphertextBytes     int    `json:"ciphertext_bytes,omitempty"`
	CiphertextHex       string `json:"ciphertext_sha_prefix_hex,omitempty"`
	AckOutcome          string `json:"ack_outcome,omitempty"`
	AckCode             string `json:"ack_code,omitempty"`
	EvidenceObject      string `json:"evidence_object,omitempty"`
	DescriptorDigest    string `json:"descriptor_digest,omitempty"`
	DescriptorIssued    uint64 `json:"descriptor_issued_at_unix,omitempty"`
	DescriptorExpires   uint64 `json:"descriptor_expires_at_unix,omitempty"`
	EvidenceAgentID     string `json:"evidence_agent_id,omitempty"`
	// Room fields: the object digest of every kind-3 part, the object's
	// public prefix in part 0, and a room ack in kind 2.
	ObjectDigest    string `json:"object_digest,omitempty"`
	PartSHA256      string `json:"part_sha256,omitempty"`
	RoomObjectType  uint8  `json:"room_object_type,omitempty"`
	RoomID          string `json:"room_id,omitempty"`
	RoomEpoch       uint64 `json:"room_epoch,omitempty"`
	MLSEpoch        uint64 `json:"mls_epoch,omitempty"`
	RoomHeader      bool   `json:"room_header,omitempty"`
	RoomAck         bool   `json:"room_ack,omitempty"`
	RoomAckObject   string `json:"room_ack_object_digest,omitempty"`
	RoomAckMLSEpoch uint64 `json:"room_ack_mls_epoch,omitempty"`
}

type packetView struct {
	SenderAgentID    string     `json:"sender_agent_id"`
	RecipientAgentID string     `json:"recipient_agent_id"`
	CapabilityID     string     `json:"capability_id"`
	QuoteCommitment  string     `json:"quote_commitment"`
	CreatedAtUnix    uint64     `json:"created_at_unix"`
	Sequence         uint64     `json:"sequence"`
	PacketJSONBytes  int        `json:"packet_json_bytes"`
	PayloadBytes     int        `json:"payload_bytes"`
	FixedFieldBytes  int        `json:"fixed_field_bytes"`
	PayloadDomain    string     `json:"payload_domain"`
	Frame            *frameView `json:"frame,omitempty"`
	FrameError       string     `json:"frame_error,omitempty"`
	ExpectedEnvelope int        `json:"expected_envelope_bytes,omitempty"`
}

func inspectFrame(raw []byte) (*frameView, error) {
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return nil, err
	}
	view := &frameView{
		Kind: frame.Kind, PartIndex: frame.PartIndex, PartCount: frame.PartCount, FrameBytes: len(raw),
		CardBytes: len(frame.Card), EvidenceBytes: len(frame.Evidence), PartBytes: len(frame.Part),
	}
	for _, bucket := range relayframe.Buckets() {
		view.IsBucket = view.IsBucket || bucket == len(raw)
	}
	unpadded, err := relayframe.UnpaddedSize(len(frame.Card), len(frame.Evidence), len(frame.Part))
	if err == nil {
		view.SmallestBucket, _ = relayframe.BucketFor(unpadded)
	}
	if len(frame.Evidence) != 0 {
		view.EvidenceDigest = relayframe.EvidenceDigest(frame.Evidence)
		if evidence, err := relayframe.DecodeEvidence(frame.Evidence); err == nil {
			if descriptor, err := directory.DecodeDescriptorJSON(evidence.Descriptor); err == nil {
				view.DescriptorDigest, _ = directory.DescriptorDigest(descriptor)
				view.DescriptorIssued, view.DescriptorExpires = descriptor.IssuedAtUnix, descriptor.ExpiresAtUnix
				view.EvidenceAgentID = descriptor.AgentID
			}
		}
	}
	if len(frame.Card) != 0 {
		if card, err := agentpacket.DecodeJSON(frame.Card); err == nil {
			view.CardSenderAgent = card.SenderAgentID
			if body, err := agentpacketseal.DecodeKeyCard(card.Payload); err == nil {
				view.CardKeyID = agentpacketseal.KeyIDText(body.KeyID)
			}
		}
	}
	switch frame.Kind {
	case 1:
		value, err := relayframe.DecodeCopy(frame.Part)
		if err != nil {
			return view, err
		}
		view.EventID, view.SessionID, view.ConversationID = value.EventID, value.SessionID, value.ConversationID
		view.RecipientEndpointID, view.RecipientDeviceID = value.RecipientEndpointID, value.RecipientDeviceID
		view.AdmissionToken, view.BootstrapBytes = value.AdmissionToken != "", len(value.Bootstrap)
		view.CiphertextBytes = len(value.Ciphertext)
		view.CiphertextHex = hex.EncodeToString(value.Ciphertext[:min(24, len(value.Ciphertext))])
	case 2:
		if relayframe.IsRoomAck(frame.Part) {
			ack, err := relayframe.DecodeRoomAck(frame.Part)
			if err != nil {
				return view, err
			}
			view.RoomAck, view.RoomID = true, ack.RoomID
			view.RoomAckObject = hex.EncodeToString(ack.ObjectDigest[:])
			view.RecipientEndpointID, view.RecipientDeviceID = ack.RecipientEndpointID, ack.RecipientDeviceID
			view.RoomAckMLSEpoch, view.AckOutcome, view.AckCode = ack.MLSEpoch, ack.Outcome, string(ack.Code)
			return view, nil
		}
		ack, err := relayframe.DecodeAck(frame.Part)
		if err != nil {
			return view, err
		}
		view.EventID, view.SessionID = ack.EventID, ack.SessionID
		view.RecipientEndpointID, view.RecipientDeviceID = ack.RecipientEndpointID, ack.RecipientDeviceID
		view.AckOutcome, view.AckCode = ack.Outcome, string(ack.Code)
	case relayframe.KindRoom:
		view.ObjectDigest = hex.EncodeToString(frame.ObjectDigest[:])
		partDigest := sha256.Sum256(frame.Part)
		view.PartSHA256 = hex.EncodeToString(partDigest[:])
		if frame.PartIndex == 0 {
			prefix, err := roomObjectPrefix(frame.Part)
			if err != nil {
				return view, err
			}
			view.RoomObjectType, view.RoomID = prefix.objectType, prefix.roomID
			view.RoomEpoch, view.MLSEpoch, view.RoomHeader = prefix.roomEpoch, prefix.mlsEpoch, prefix.header
		}
	case 4:
		if len(frame.Part) == 1 {
			view.EvidenceObject = map[byte]string{1: "request", 2: "response"}[frame.Part[0]]
		}
	}
	return view, nil
}

func inspectCommand(args []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	packetFile := flags.String("packet", "", "a signed packet JSON file")
	packetBase64 := flags.String(
		"packet-base64-file",
		"",
		"a file holding a signed packet JSON in base64",
	)
	envelopeFile := flags.String("envelope", "", "a sealed envelope file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *envelopeFile != "" {
		raw, err := os.ReadFile(*envelopeFile)
		if err != nil {
			return err
		}
		header, err := agentpacketseal.ParseEnvelope(raw)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{
			"envelope_id":        hex.EncodeToString(header.EnvelopeID[:]),
			"recipient_agent_id": header.RecipientAgentID,
			"recipient_key_id":   agentpacketseal.KeyIDText(header.RecipientKeyID),
			"expires_at_unix":    header.ExpiresAtUnix,
			"bytes":              len(raw),
		})
	}
	var raw []byte
	var err error
	switch {
	case *packetFile != "":
		raw, err = os.ReadFile(*packetFile)
	case *packetBase64 != "":
		var text []byte
		text, err = os.ReadFile(*packetBase64)
		if err == nil {
			raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(text)))
		}
	default:
		err = errors.New("inspect needs --packet, --packet-base64-file or --envelope")
	}
	if err != nil {
		return err
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return err
	}
	view := packetView{
		SenderAgentID: packet.SenderAgentID, RecipientAgentID: packet.RecipientAgentID,
		CapabilityID: packet.CapabilityID, QuoteCommitment: packet.QuoteCommitment, CreatedAtUnix: packet.CreatedAtUnix,
		Sequence: packet.Sequence, PacketJSONBytes: len(raw), PayloadBytes: len(packet.Payload),
		FixedFieldBytes: len(raw) - base64.StdEncoding.EncodedLen(len(packet.Payload)),
	}
	switch {
	case bytes.HasPrefix(packet.Payload, []byte("OFR1")):
		view.PayloadDomain = "OFR1"
	case bytes.HasPrefix(packet.Payload, []byte("tos.messaging.relay-frame.v1")):
		view.PayloadDomain = "relay-frame"
	default:
		view.PayloadDomain = "other"
	}
	frame, err := inspectFrame(packet.Payload)
	if err != nil {
		view.FrameError = err.Error()
	}
	view.Frame = frame
	if frame != nil && frame.IsBucket {
		view.ExpectedEnvelope, _ = relayframe.EnvelopeSize(frame.FrameBytes, view.FixedFieldBytes)
	}
	return printJSON(view)
}

// --- craft ---------------------------------------------------------------------

func craftCommand(args []string) error {
	flags := flag.NewFlagSet("craft", flag.ContinueOnError)
	tosctl := flags.String("tosctl", "", "tosctl binary holding the sender's controller")
	tosctlSHA := flags.String("tosctl-sha256", "", "its SHA-256")
	tosctlConfig := flags.String(
		"tosctl-config",
		"",
		"the sender's tosctl configuration (VAULT_URL from the environment)",
	)
	controller := flags.String("controller", "", "the sender's packet controller name")
	keyIDText := flags.String("key-id", "", "the sender's packet controller key id")
	sender := flags.String("sender", "", "the sender Agent")
	recipient := flags.String("recipient", "", "the recipient Agent")
	payloadFile := flags.String("payload", "", "file holding the exact payload bytes")
	ofr1 := flags.Bool(
		"ofr1-payload",
		false,
		"use a rail OFR1 frame of random bytes as the payload",
	)
	cardFile := flags.String(
		"card",
		"",
		"the recipient's key card packet JSON the envelope is sealed to",
	)
	out := flags.String("out", "", "where the envelope is written")
	packetOut := flags.String("packet-out", "", "optional: where the signed packet JSON is written")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var payload []byte
	var err error
	switch {
	case *ofr1:
		payload = append([]byte("OFR1"), make([]byte, 64)...)
		_, err = rand.Read(payload[4:])
	case *payloadFile != "":
		payload, err = os.ReadFile(*payloadFile)
	default:
		err = errors.New("craft needs --payload or --ofr1-payload")
	}
	if err != nil {
		return err
	}
	cardRaw, err := os.ReadFile(*cardFile)
	if err != nil {
		return err
	}
	cardPacket, err := agentpacket.DecodeJSON(cardRaw)
	if err != nil {
		return err
	}
	card, err := agentpacketseal.DecodeKeyCard(cardPacket.Payload)
	if err != nil {
		return err
	}
	if cardPacket.SenderAgentID != *recipient {
		return errors.New("the card is not the recipient's")
	}
	signer, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{
		Binary: *tosctl, SHA256: *tosctlSHA, ConfigPath: *tosctlConfig,
		VaultURL: os.Getenv("VAULT_URL"),
	})
	if err != nil {
		return err
	}
	keyID, err := mldsa44.ParseKeyIDText(*keyIDText)
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now()
	packet, err := agentpacket.Sign(ctx, signer, *controller, agentpacket.Packet{
		SenderAgentID:    *sender,
		RecipientAgentID: *recipient, CapabilityID: "cap_" + strings.Repeat("0", 64), Sequence: now << 16, Nonce: nonce,
		Payload: payload, CreatedAtUnix: now, SenderKeyID: keyID,
	})
	if err != nil {
		return err
	}
	signSeconds := time.Since(started).Seconds()
	packetJSON, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		return err
	}
	var secret [agentpacketseal.AckSecretSize]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return err
	}
	envelope, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{
		AgentID: *recipient, KeyID: card.KeyID,
		PublicKey: card.PublicKey,
	}, secret, packetJSON, now+3600)
	clear(secret[:])
	if err != nil {
		return err
	}
	header, err := agentpacketseal.ParseEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, envelope, 0o600); err != nil {
		return err
	}
	if *packetOut != "" {
		if err := os.WriteFile(*packetOut, packetJSON, 0o600); err != nil {
			return err
		}
	}
	return printJSON(map[string]any{
		"envelope_id": hex.EncodeToString(header.EnvelopeID[:]),
		"recipient_key_id": agentpacketseal.KeyIDText(
			header.RecipientKeyID,
		), "bytes": len(envelope),
		"sign_seconds": signSeconds, "relays": card.Relays,
	})
}

// --- room-frames -----------------------------------------------------------------

// roomPrefix is the public start of a room object (section 11.1), which part
// 0 always holds whole: its domain, type, room, epochs and header length.
type roomPrefix struct {
	objectType          uint8
	roomID              string
	roomEpoch, mlsEpoch uint64
	header              bool
}

// roomObjectPrefix decodes the fixed start of a room object from part 0.
func roomObjectPrefix(part []byte) (roomPrefix, error) {
	domain := []byte("tos.messaging.relay-room-object.v1\x00")
	fixed := len(domain) + 1 + 32 + 8 + 8 + 2
	if len(part) < fixed || !bytes.Equal(part[:len(domain)], domain) {
		return roomPrefix{}, errors.New("part 0 does not start with a room object")
	}
	at := len(domain)
	prefix := roomPrefix{objectType: part[at], roomID: "room_" + hex.EncodeToString(part[at+1:at+33])}
	prefix.roomEpoch = binary.BigEndian.Uint64(part[at+33 : at+41])
	prefix.mlsEpoch = binary.BigEndian.Uint64(part[at+41 : at+49])
	prefix.header = binary.BigEndian.Uint16(part[at+49:at+51]) != 0
	return prefix, nil
}

// roomFramesCommand builds a room object with an empty header and a random
// body, the shape of an MLS-only refresh Commit or an application object,
// and writes each kind-3 frame of its cut to <out-dir>/part-<i>.bin. Part 0
// carries the sender's card and evidence from its exported relay contact.
func roomFramesCommand(args []string) error {
	flags := flag.NewFlagSet("room-frames", flag.ContinueOnError)
	objectType := flags.Uint("type", uint(relayframe.RoomCommit), "room object type: 1 Commit, 3 application")
	roomID := flags.String("room", "", "the room id (room_<64 hex>)")
	roomEpoch := flags.Uint64("room-epoch", 1, "the object's room epoch")
	mlsEpoch := flags.Uint64("mls-epoch", 1, "the object's MLS epoch")
	bodyBytes := flags.Int("body-bytes", 1024, "random body bytes, 1 .. 1,048,576")
	partBytes := flags.Int("part-bytes", 0, "test part size P; 0 is the production cut")
	contactFile := flags.String("contact", "", "the sender's exported relay contact (card and evidence)")
	outDir := flags.String("out-dir", "", "a new directory the frames are written to")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *bodyBytes < 1 || *bodyBytes > relayframe.MaxRoomBodyBytes {
		return errors.New("room-frames: --body-bytes is outside 1 .. 1,048,576")
	}
	if *objectType != uint(relayframe.RoomCommit) && *objectType != uint(relayframe.RoomApplication) {
		return errors.New("room-frames: only a Commit or an application object has an empty header")
	}
	raw, err := os.ReadFile(*contactFile)
	if err != nil {
		return err
	}
	contact, err := relayframe.DecodeContactJSON(raw)
	if err != nil {
		return err
	}
	body := make([]byte, *bodyBytes)
	if _, err := rand.Read(body); err != nil {
		return err
	}
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{
		Type: uint8(*objectType), RoomID: *roomID, RoomEpoch: *roomEpoch, MLSEpoch: *mlsEpoch, Body: body,
	})
	if err != nil {
		return err
	}
	frames, err := relayframe.SplitRoomObject(object, contact.Card, contact.Evidence, *partBytes)
	if err != nil {
		return err
	}
	if err := os.Mkdir(*outDir, 0o700); err != nil {
		return err
	}
	sizes := make([]int, 0, len(frames))
	for index, frame := range frames {
		if err := os.WriteFile(filepath.Join(*outDir, fmt.Sprintf("part-%d.bin", index)), frame, 0o600); err != nil {
			return err
		}
		sizes = append(sizes, len(frame))
	}
	digest := relayframe.ObjectDigest(object)
	return printJSON(map[string]any{
		"object_digest": hex.EncodeToString(digest[:]), "object_bytes": len(object), "parts": len(frames),
		"frame_bytes": sizes,
	})
}
