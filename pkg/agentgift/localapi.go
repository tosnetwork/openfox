package agentgift

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	LocalRequestSchema  = "tos.openfox.agent-gift.local-request.v1"
	LocalResponseSchema = "tos.openfox.agent-gift.local-response.v1"
	maxLocalFrameBytes  = 256 << 10
	localIOTimeout      = 10 * time.Second
	// LocalOperationTimeout exceeds the maximum custody subprocess timeout and
	// still bounds a disconnected or stalled owner operation.
	LocalOperationTimeout = 3 * time.Minute
	maxLocalClientTimeout = LocalOperationTimeout + 2*localIOTimeout
)

type LocalOperation string

const (
	LocalStartSender             LocalOperation = "sender.start"
	LocalRequestAddress          LocalOperation = "sender.request-address"
	LocalObserveAddressResponse  LocalOperation = "sender.observe-address-response"
	LocalAuthorize               LocalOperation = "sender.authorize"
	LocalSign                    LocalOperation = "sender.sign"
	LocalDeliver                 LocalOperation = "sender.deliver"
	LocalObserveRecipientRequest LocalOperation = "recipient.observe-address-request"
	LocalRespondAddress          LocalOperation = "recipient.respond-address"
	LocalObserveAndBroadcast     LocalOperation = "recipient.observe-and-broadcast"
	LocalRefresh                 LocalOperation = "gift.refresh"
	LocalCancel                  LocalOperation = "gift.cancel"
	LocalGet                     LocalOperation = "gift.get"
	LocalList                    LocalOperation = "gift.list"
)

type LocalRequest struct {
	Schema              string         `json:"schema"`
	Operation           LocalOperation `json:"operation"`
	IntentID            string         `json:"intent_id,omitempty"`
	Proposal            *ModelProposal `json:"proposal,omitempty"`
	AuthenticatedSender string         `json:"authenticated_sender,omitempty"`
	Canonical           []byte         `json:"canonical_base64,omitempty"`
	ResponseNotAfter    uint32         `json:"response_not_after,omitempty"`
	Greeting            string         `json:"greeting,omitempty"`
}

type LocalResponse struct {
	Schema  string            `json:"schema"`
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Record  *LocalRecordView  `json:"record,omitempty"`
	Records []LocalRecordView `json:"records,omitempty"`
}

type LocalRecordView struct {
	IntentID            string `json:"intent_id"`
	Role                string `json:"role"`
	State               string `json:"state"`
	AmountAtomic        string `json:"amount_atomic"`
	DisplayMessage      string `json:"display_message,omitempty"`
	RequestedValidUntil uint32 `json:"requested_valid_until"`
	ValidUntil          uint32 `json:"valid_until,omitempty"`
	FundsLocked         bool   `json:"funds_locked"`
}

type LocalPrincipal string

const (
	LocalPrincipalModel   LocalPrincipal = "model"
	LocalPrincipalRuntime LocalPrincipal = "runtime"
)

type LocalServer struct {
	service               *Service
	principal             LocalPrincipal
	network, localAgentID string
	globalID              int32
}

func NewLocalServer(service *Service, principal LocalPrincipal, network string, globalID int32, localAgentID string) (*LocalServer, error) {
	if service == nil || (principal != LocalPrincipalModel && principal != LocalPrincipalRuntime) || network == "" || globalID == 0 || localAgentID == "" {
		return nil, errors.New("Agent Gift local server requires complete fixed authority")
	}
	return &LocalServer{service: service, principal: principal, network: network, globalID: globalID, localAgentID: localAgentID}, nil
}

func ListenLocalUnix(path string) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Agent Gift socket path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("Agent Gift socket parent must be an owner-private directory")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("Agent Gift socket path already exists")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *LocalServer) Serve(ctx context.Context, listener *net.UnixListener) error {
	if s == nil || s.service == nil || ctx == nil || listener == nil {
		return errors.New("invalid Agent Gift local server")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, connection)
	}
}

func (s *LocalServer) handle(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(localIOTimeout))
	raw, err := readLocalFrame(bufio.NewReader(connection))
	if err != nil {
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	request, err := decodeLocalRequest(raw)
	response := LocalResponse{Schema: LocalResponseSchema}
	if err == nil {
		operationCtx, cancel := context.WithTimeout(ctx, LocalOperationTimeout)
		response, err = s.call(operationCtx, request)
		cancel()
	}
	if err != nil {
		response = LocalResponse{Schema: LocalResponseSchema, Error: "request refused"}
	} else {
		response.OK = true
	}
	encoded, _ := json.Marshal(response)
	_ = connection.SetWriteDeadline(time.Now().Add(localIOTimeout))
	_ = writeLocalFrame(connection, encoded)
}

func (s *LocalServer) call(ctx context.Context, request LocalRequest) (LocalResponse, error) {
	if s.principal == LocalPrincipalModel && request.Operation != LocalStartSender && request.Operation != LocalGet && request.Operation != LocalList {
		return LocalResponse{}, errors.New("model principal cannot invoke Gift authority operations")
	}
	var record Record
	var err error
	switch request.Operation {
	case LocalStartSender:
		record, err = s.service.StartSender(ctx, *request.Proposal, s.network, s.globalID, s.localAgentID)
	case LocalRequestAddress:
		record, err = s.service.RequestAddress(ctx, request.IntentID)
	case LocalObserveAddressResponse:
		record, err = s.service.ObserveAddressResponse(ctx, request.IntentID, request.Canonical)
	case LocalAuthorize:
		record, err = s.service.Authorize(ctx, request.IntentID)
	case LocalSign:
		record, err = s.service.Sign(ctx, request.IntentID, request.Greeting)
	case LocalDeliver:
		record, err = s.service.DeliverOffer(ctx, request.IntentID)
	case LocalObserveRecipientRequest:
		record, err = s.service.ObserveRecipientRequest(ctx, request.Canonical, s.localAgentID, request.AuthenticatedSender)
	case LocalRespondAddress:
		record, err = s.service.RespondAddress(ctx, request.IntentID, request.ResponseNotAfter)
	case LocalObserveAndBroadcast:
		record, err = s.service.ObserveAndBroadcastOffer(ctx, request.IntentID, request.Canonical)
	case LocalRefresh:
		record, err = s.service.Refresh(ctx, request.IntentID)
	case LocalCancel:
		record, err = s.service.Cancel(ctx, request.IntentID)
	case LocalGet:
		var found bool
		record, found = s.service.journal.Get(request.IntentID)
		if !found {
			err = errors.New("Gift not found")
		}
	case LocalList:
		values := s.service.journal.List()
		views := make([]LocalRecordView, len(values))
		for index := range values {
			views[index] = localRecordView(values[index])
		}
		return LocalResponse{Schema: LocalResponseSchema, Records: views}, nil
	default:
		err = errors.New("unknown Agent Gift operation")
	}
	if err != nil {
		return LocalResponse{}, err
	}
	view := localRecordView(record)
	return LocalResponse{Schema: LocalResponseSchema, Record: &view}, nil
}

type LocalClient struct {
	path    string
	timeout time.Duration
}

func NewLocalClient(path string, timeout time.Duration) (*LocalClient, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Agent Gift local client path must be absolute and clean")
	}
	if timeout == 0 {
		timeout = maxLocalClientTimeout
	}
	if timeout < time.Second || timeout > maxLocalClientTimeout {
		return nil, errors.New("Agent Gift local client timeout is invalid")
	}
	return &LocalClient{path: path, timeout: timeout}, nil
}

func (c *LocalClient) Call(ctx context.Context, request LocalRequest) (LocalResponse, error) {
	if c == nil || ctx == nil {
		return LocalResponse{}, errors.New("invalid Agent Gift local client")
	}
	request.Schema = LocalRequestSchema
	if err := validateLocalRequest(request); err != nil {
		return LocalResponse{}, err
	}
	raw, _ := json.Marshal(request)
	dialer := net.Dialer{Timeout: c.timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return LocalResponse{}, errors.New("connect Agent Gift local API")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(c.timeout))
	if err := writeLocalFrame(connection, raw); err != nil {
		return LocalResponse{}, err
	}
	responseRaw, err := readLocalFrame(bufio.NewReader(connection))
	if err != nil {
		return LocalResponse{}, err
	}
	var response LocalResponse
	decoder := json.NewDecoder(bytes.NewReader(responseRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || response.Schema != LocalResponseSchema {
		return LocalResponse{}, errors.New("invalid Agent Gift local response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LocalResponse{}, errors.New("trailing Agent Gift local response")
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func decodeLocalRequest(raw []byte) (LocalRequest, error) {
	var request LocalRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return request, errors.New("trailing Agent Gift local request")
	}
	return request, validateLocalRequest(request)
}

func validateLocalRequest(v LocalRequest) error {
	if v.Schema != LocalRequestSchema {
		return errors.New("invalid Agent Gift local request schema")
	}
	hasIntent := len(v.IntentID) == 64
	if hasIntent {
		decoded, err := hex.DecodeString(v.IntentID)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != v.IntentID {
			return errors.New("Gift intent ID must be canonical lowercase hex")
		}
	}
	if v.Operation != LocalStartSender && v.Proposal != nil {
		return errors.New("only sender start carries a model proposal")
	}
	if v.Operation != LocalObserveRecipientRequest && v.AuthenticatedSender != "" {
		return errors.New("only recipient observation carries authenticated sender context")
	}
	if v.Operation != LocalObserveRecipientRequest && v.Operation != LocalObserveAddressResponse && v.Operation != LocalObserveAndBroadcast && len(v.Canonical) != 0 {
		return errors.New("only Gift observations carry canonical private bytes")
	}
	if v.Operation != LocalRespondAddress && v.ResponseNotAfter != 0 {
		return errors.New("only address response carries response validity")
	}
	if v.Operation != LocalSign && v.Greeting != "" {
		return errors.New("only Gift signing carries display text")
	}
	switch v.Operation {
	case LocalStartSender:
		if v.Proposal == nil || hasIntent || len(v.Canonical) != 0 {
			return errors.New("invalid sender start request")
		}
	case LocalObserveRecipientRequest:
		if v.Proposal != nil || len(v.Canonical) == 0 || v.AuthenticatedSender == "" || hasIntent {
			return errors.New("invalid recipient observation request")
		}
	case LocalObserveAddressResponse, LocalObserveAndBroadcast:
		if !hasIntent || len(v.Canonical) == 0 || v.Proposal != nil {
			return errors.New("invalid canonical Gift observation request")
		}
	case LocalRespondAddress:
		if !hasIntent || v.ResponseNotAfter == 0 {
			return errors.New("invalid address response request")
		}
	case LocalSign:
		if !hasIntent || len(v.Greeting) > 512 {
			return errors.New("invalid Gift signing request")
		}
	case LocalRequestAddress, LocalAuthorize, LocalDeliver, LocalRefresh, LocalCancel, LocalGet:
		if !hasIntent {
			return errors.New("Gift intent ID is required")
		}
	case LocalList:
		if hasIntent || v.Proposal != nil || len(v.Canonical) != 0 {
			return errors.New("Gift list has no parameters")
		}
	default:
		return errors.New("unknown Agent Gift local operation")
	}
	if len(v.Canonical) > 64<<10 {
		return errors.New("Agent Gift canonical object exceeds local bound")
	}
	return nil
}

func localRecordView(record Record) LocalRecordView {
	return LocalRecordView{IntentID: record.IntentID, Role: string(record.Role), State: string(record.State), AmountAtomic: record.AmountAtomic, DisplayMessage: record.DisplayMessage, RequestedValidUntil: record.RequestedValidUntil, ValidUntil: record.ValidUntil, FundsLocked: false}
}

func frameLocal(raw []byte) []byte {
	framed := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(framed, uint32(len(raw)))
	copy(framed[4:], raw)
	return framed
}

func writeLocalFrame(writer io.Writer, raw []byte) error {
	framed := frameLocal(raw)
	for len(framed) > 0 {
		written, err := writer.Write(framed)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(framed) {
			return errors.New("short Agent Gift local write")
		}
		framed = framed[written:]
	}
	return nil
}

func readLocalFrame(reader *bufio.Reader) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxLocalFrameBytes {
		return nil, errors.New("Agent Gift local frame exceeds bound")
	}
	raw := make([]byte, length)
	_, err := io.ReadFull(reader, raw)
	return raw, err
}
