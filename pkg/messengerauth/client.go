// Package messengerauth implements OpenFox action authorization over the TOS
// Messenger runtime socket. It intentionally duplicates only the bounded wire
// envelope; Messenger remains the policy, mandate, budget, and grant authority.
package messengerauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
)

const (
	requestSchema  = "tos.messaging.local-request.v6"
	responseSchema = "tos.messaging.local-response.v5"
	maxFrameBytes  = 2 << 20
	defaultTimeout = 30 * time.Second
)

var (
	ErrApprovalRequired = errors.New("Messenger owner approval is required")
	ErrRefused          = errors.New("Messenger refused the action")
	ErrQuoteUnverified  = errors.New("Messenger did not verify the finalized Accepted Quote")
)

type Client struct {
	socket  string
	timeout time.Duration
}

func NewClient(socket string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, errors.New("Messenger runtime socket must be a clean absolute path")
	}
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 || timeout > time.Minute {
		return nil, errors.New("invalid Messenger authorization timeout")
	}
	return &Client{socket: socket, timeout: timeout}, nil
}

type request struct {
	Schema             string                    `json:"schema"`
	Op                 string                    `json:"op"`
	Action             *proposedAction           `json:"action,omitempty"`
	ActionID           string                    `json:"action_id,omitempty"`
	MandateID          string                    `json:"mandate_id,omitempty"`
	QuoteCommitment    string                    `json:"quote_commitment,omitempty"`
	EscrowAddress      string                    `json:"escrow_address,omitempty"`
	CapabilityClass    string                    `json:"capability_class,omitempty"`
	ExpectedQuoteTerms *actionauth.PurchaseTerms `json:"expected_quote_terms,omitempty"`
}

type proposedAction struct {
	Effect         string                        `json:"effect"`
	Summary        string                        `json:"summary"`
	IdempotencyKey string                        `json:"idempotency_key,omitempty"`
	Derived        []actionauth.Origin           `json:"derived_from,omitempty"`
	Terms          *actionauth.PurchaseTerms     `json:"terms,omitempty"`
	Physical       *actionauth.PhysicalOperation `json:"physical,omitempty"`
}

type response struct {
	Schema         string                  `json:"schema"`
	OK             bool                    `json:"ok"`
	Code           string                  `json:"code,omitempty"`
	Detail         string                  `json:"detail,omitempty"`
	ActionID       string                  `json:"action_id,omitempty"`
	Decision       string                  `json:"decision,omitempty"`
	Authorized     bool                    `json:"authorised,omitempty"` //nolint:misspell // Protocol spelling is frozen.
	State          string                  `json:"approval_state,omitempty"`
	FinalizedQuote *finalizedQuoteEvidence `json:"finalized_quote,omitempty"`
}

type finalizedQuoteEvidence struct {
	Commitment          string `json:"quote_commitment"`
	EscrowAccount       string `json:"escrow_account"`
	TransactionHash     string `json:"transaction_hash"`
	ContractCodeHash    string `json:"contract_code_hash"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	FinalizedAtUnix     uint64 `json:"finalized_at_unix"`
}

// VerifyAcceptedQuote uses Messenger's chain resolver as a read-only second
// authority after escrow funding. Success does not authorize another action;
// it proves only that the finalized Accepted Quote exactly matches expected.
func (c *Client) VerifyAcceptedQuote(
	ctx context.Context,
	commitment, escrowAddress string,
	expected actionauth.PurchaseTerms,
) error {
	verified, err := c.call(ctx, request{
		Op: "quotes.verify", QuoteCommitment: commitment, EscrowAddress: escrowAddress,
		CapabilityClass: expected.CapabilityClass, ExpectedQuoteTerms: &expected,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQuoteUnverified, err)
	}
	evidence := verified.FinalizedQuote
	if evidence == nil || evidence.Commitment != commitment || evidence.EscrowAccount != escrowAddress ||
		evidence.TransactionHash == "" || evidence.ContractCodeHash == "" ||
		evidence.FinalizedCheckpoint == 0 || evidence.FinalizedAtUnix == 0 {
		return fmt.Errorf("%w: Messenger returned incomplete evidence", ErrQuoteUnverified)
	}
	return nil
}

func (c *Client) Authorize(ctx context.Context, action actionauth.Action) error {
	if !action.Effect.Known() || action.Summary == "" || len(action.Summary) > 512 ||
		len(action.DerivedFrom) > actionauth.MaxProvenance {
		return fmt.Errorf("%w: malformed OpenFox action", ErrRefused)
	}
	if (action.Effect == actionauth.EffectToolCall || action.Effect == actionauth.EffectPhysicalIO) &&
		len(action.IdempotencyKey) != len("idem_")+64 {
		return fmt.Errorf("%w: tool call has no canonical invocation key", ErrRefused)
	}
	if action.Effect == actionauth.EffectPhysicalIO && (action.Physical == nil || !action.Physical.Valid()) {
		return fmt.Errorf("%w: physical I/O has no local Capability binding", ErrRefused)
	}
	if action.Effect != actionauth.EffectPhysicalIO && action.Physical != nil {
		return fmt.Errorf("%w: only physical I/O carries a physical operation", ErrRefused)
	}
	if action.Effect == actionauth.EffectSpend && (action.Terms == nil || action.MandateID == "") {
		return fmt.Errorf("%w: spend has no exact terms or mandate", ErrRefused)
	}
	if action.Effect != actionauth.EffectSpend && (action.Terms != nil || action.MandateID != "") {
		return fmt.Errorf("%w: only a spend carries terms and a mandate", ErrRefused)
	}
	asked, err := c.call(ctx, request{Op: "actions.request", Action: &proposedAction{
		Effect: string(action.Effect), Summary: action.Summary,
		IdempotencyKey: action.IdempotencyKey, Derived: action.DerivedFrom, Terms: action.Terms,
		Physical: action.Physical,
	}, MandateID: action.MandateID})
	if err != nil {
		return err
	}
	if asked.Decision == "refuse" {
		return fmt.Errorf("%w: %s", ErrRefused, asked.Detail)
	}
	if asked.Authorized {
		if action.Effect == actionauth.EffectToolCall || action.Effect == actionauth.EffectPhysicalIO ||
			action.Effect == actionauth.EffectSpend ||
			action.Effect == actionauth.EffectKeyUse ||
			action.Effect == actionauth.EffectConfiguration {
			return fmt.Errorf("%w: Messenger returned an inline authorization for a one-shot effect", ErrRefused)
		}
		return nil
	}
	switch asked.State {
	case "granted":
		// Continue below and atomically consume the one-shot grant.
	case "pending", "":
		asked, err = c.awaitDecision(ctx, asked)
		if err != nil {
			return err
		}
		if asked.State != "granted" {
			return fmt.Errorf("%w: action %s is %s", ErrRefused, asked.ActionID, asked.State)
		}
	default:
		return fmt.Errorf("%w: action %s is %s", ErrRefused, asked.ActionID, asked.State)
	}
	claimed, err := c.call(ctx, request{Op: "actions.claim", ActionID: asked.ActionID})
	if err != nil {
		return err
	}
	if !claimed.Authorized {
		return fmt.Errorf("%w: one-shot grant was unavailable: %s", ErrRefused, claimed.Detail)
	}
	return nil
}

func (c *Client) awaitDecision(ctx context.Context, pending response) (response, error) {
	if pending.ActionID == "" {
		return response{}, fmt.Errorf("%w: Messenger returned no action ID", ErrRefused)
	}
	waitCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return response{}, fmt.Errorf("%w: action %s: %s", ErrApprovalRequired, pending.ActionID, pending.Detail)
		case <-ticker.C:
			status, err := c.call(waitCtx, request{Op: "actions.status", ActionID: pending.ActionID})
			if err != nil {
				if waitCtx.Err() != nil {
					return response{}, fmt.Errorf(
						"%w: action %s: %s",
						ErrApprovalRequired,
						pending.ActionID,
						pending.Detail,
					)
				}
				return response{}, err
			}
			switch status.State {
			case "pending", "":
				continue
			case "granted":
				return status, nil
			default:
				return status, fmt.Errorf("%w: action %s is %s", ErrRefused, pending.ActionID, status.State)
			}
		}
	}
}

func (c *Client) call(ctx context.Context, value request) (response, error) {
	value.Schema = requestSchema
	body, err := json.Marshal(value)
	if err != nil {
		return response{}, err
	}
	if len(body) == 0 || len(body) > maxFrameBytes {
		return response{}, errors.New("Messenger authorization request exceeds its bound")
	}
	dialer := net.Dialer{Timeout: c.timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return response{}, fmt.Errorf("connect to Messenger authorization: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return response{}, err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeAll(connection, header[:]); err != nil {
		return response{}, err
	}
	if err := writeAll(connection, body); err != nil {
		return response{}, err
	}
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return response{}, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxFrameBytes {
		return response{}, errors.New("invalid Messenger authorization response length")
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(connection, raw); err != nil {
		return response{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result response
	if err := decoder.Decode(&result); err != nil {
		return response{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return response{}, errors.New("Messenger authorization response has trailing JSON")
	}
	if result.Schema != responseSchema {
		return response{}, errors.New("unsupported Messenger authorization response schema")
	}
	if !result.OK {
		return response{}, fmt.Errorf("Messenger authorization failed (%s): %s", result.Code, result.Detail)
	}
	return result, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		value = value[written:]
	}
	return nil
}
