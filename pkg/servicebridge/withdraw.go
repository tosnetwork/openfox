package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Withdrawal states. Only finalized, failed and not_included are final.
const (
	// WithdrawalSubmitted: the record was written and the message handed to
	// tosctl; its outcome is not yet read from finalized state.
	WithdrawalSubmitted = "submitted"
	// WithdrawalFinalized: a finalized withdraw_revenue transaction carrying
	// this withdrawal's query id paid the amount out of the actor.
	WithdrawalFinalized = "finalized"
	// WithdrawalFailed: the finalized transaction carrying this query id
	// did not succeed; credited revenue was not debited by it.
	WithdrawalFailed = "failed"
	// WithdrawalNotIncluded: no transaction carries this query id and the
	// message's inclusion window has passed on finalized chain time.
	WithdrawalNotIncluded = "not_included"
	// WithdrawalUnknown: finalized state does not yet say.
	WithdrawalUnknown = "unknown"
)

// WalletCreditNotVerified is the only statement made about the wallet: a
// finalized withdrawal is the actor paying out, which this node does not
// follow into the wallet's own account.
const WalletCreditNotVerified = "not_verified"

const (
	withdrawalSchema    = "tos.openfox.rail-withdrawal.v1"
	withdrawalDirectory = "withdrawals"
	// maxListedWithdrawals bounds what status lists.
	maxListedWithdrawals = 10
)

// WithdrawalRecord is one withdrawal as this node knows it.
type WithdrawalRecord struct {
	Schema      string `json:"schema"`
	QueryID     uint64 `json:"query_id,string"`
	Actor       string `json:"actor"`
	Destination string `json:"destination"`
	AmountNano  string `json:"amount_nanotos"`
	// AttachedNano is the value sent with the message to pay its fees.
	AttachedNano       string `json:"attached_nanotos"`
	CreditedBeforeNano string `json:"credited_before_nanotos"`
	// Anchor is the actor's last finalized transaction before the send; the
	// withdrawal's transaction is looked for after it.
	Anchor      toschain.ActorTxID `json:"anchor"`
	State       string             `json:"state"`
	StartedUnix int64              `json:"started_unix"`
	// Set once finalized state decided.
	Checkpoint        uint64 `json:"finalized_checkpoint,omitempty"`
	TransactionHash   string `json:"transaction_hash,omitempty"`
	PayoutNano        string `json:"payout_nanotos,omitempty"`
	CreditedAfterNano string `json:"credited_after_nanotos,omitempty"`
	Detail            string `json:"detail,omitempty"`
	WalletCredit      string `json:"wallet_credit"`
	UpdatedUnix       int64  `json:"updated_unix"`
}

func (r WithdrawalRecord) terminal() bool {
	return r.State == WithdrawalFinalized || r.State == WithdrawalFailed || r.State == WithdrawalNotIncluded
}

var withdrawalFilePattern = regexp.MustCompile(`^[0-9]{20}-[0-9]{20}\.json$`)

func withdrawalFile(record WithdrawalRecord) string {
	return fmt.Sprintf("%020d-%020d.json", record.StartedUnix, record.QueryID)
}

func saveWithdrawal(stateDir string, record WithdrawalRecord, create bool, now time.Time) error {
	record.Schema, record.UpdatedUnix, record.WalletCredit = withdrawalSchema, now.Unix(), WalletCreditNotVerified
	return writeJSON(filepath.Join(stateDir, withdrawalDirectory, withdrawalFile(record)), record, create)
}

// ReadWithdrawals lists the withdrawal records, newest first. A missing
// directory means none was ever made.
func ReadWithdrawals(stateDir string) ([]WithdrawalRecord, error) {
	if !cleanAbsolute(stateDir) {
		return nil, errors.New("servicebridge: state_dir must be clean and absolute")
	}
	directory := filepath.Join(stateDir, withdrawalDirectory)
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.New("servicebridge: read the withdrawal directory")
	}
	var records []WithdrawalRecord
	for _, entry := range entries {
		if !withdrawalFilePattern.MatchString(entry.Name()) {
			continue
		}
		var record WithdrawalRecord
		if err := readJSON(filepath.Join(directory, entry.Name()), 16<<10, &record); err != nil {
			return nil, fmt.Errorf("servicebridge: withdrawal %s: %w", entry.Name(), err)
		}
		if record.Schema != withdrawalSchema || record.QueryID == 0 || withdrawalFile(record) != entry.Name() ||
			!rawAddressPattern.MatchString(record.Actor) {
			return nil, fmt.Errorf("servicebridge: withdrawal %s is not a withdrawal record", entry.Name())
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].StartedUnix > records[j].StartedUnix })
	return records, nil
}

// resolveWithdrawal reads what finalized state says about a withdrawal. It
// returns the record unchanged, in state unknown, when nothing is decided.
func resolveWithdrawal(
	ctx context.Context,
	session withdrawalSession,
	record WithdrawalRecord,
) (WithdrawalRecord, error) {
	history, err := session.History(ctx, record.Actor, &record.Anchor)
	if err != nil {
		return record, fmt.Errorf("servicebridge: read the actor history since the withdrawal: %w", err)
	}
	if history.Result != toschain.HistoryAnchorReached {
		return record, errors.New("servicebridge: the actor history does not reach the withdrawal's anchor")
	}
	for _, transaction := range history.Transactions {
		switch {
		case transaction.Sender != record.Destination:
			continue
		case transaction.Kind == toschain.ActorTxOwner && transaction.Opcode == nativecore.ServiceActorWithdrawOpcode &&
			transaction.QueryID == record.QueryID:
			paid := false
			for _, payout := range transaction.Payouts {
				if payout.Destination == record.Destination && payout.AmountNano == record.AmountNano {
					paid = true
				}
			}
			record.Checkpoint, record.TransactionHash = session.Checkpoint(), transaction.Hash
			if !paid {
				record.State = WithdrawalUnknown
				record.Detail = "a finalized withdraw_revenue transaction carries this query id but no payout of " +
					"exactly the amount to the owner wallet"
				return record, nil
			}
			record.State, record.PayoutNano = WithdrawalFinalized, record.AmountNano
			record.Detail = "finalized withdraw_revenue paid the amount out of the actor to the owner wallet"
			return record, nil
		case transaction.Kind == toschain.ActorTxFailed && failedWithdrawal(transaction, record.QueryID):
			record.State, record.Checkpoint = WithdrawalFailed, session.Checkpoint()
			record.TransactionHash = transaction.Hash
			record.Detail = "the withdraw_revenue transaction failed with exit code " +
				strconv.FormatInt(int64(transaction.ExitCode), 10) + "; credited revenue was not debited"
			return record, nil
		}
	}
	if session.ChainTime().After(time.Unix(record.StartedUnix, 0).Add(sendResolutionWindow)) {
		record.State, record.Checkpoint = WithdrawalNotIncluded, session.Checkpoint()
		record.Detail = "no transaction carries this query id and the message's inclusion window has passed"
		return record, nil
	}
	record.State = WithdrawalUnknown
	record.Detail = "not in finalized state yet"
	return record, nil
}

// failedWithdrawal reports whether a failed transaction's inbound body is
// the withdraw_revenue message with this query id.
func failedWithdrawal(transaction toschain.ActorTransaction, queryID uint64) bool {
	body, err := decodeCellBOCText(transaction.BodyBOC)
	if err != nil {
		return false
	}
	decoded, err := nativecore.DecodeServiceActorInbound(body)
	return err == nil && decoded.Opcode == nativecore.ServiceActorWithdrawOpcode && decoded.QueryID == queryID
}

// WithdrawInput is one withdrawal request: exactly one of AmountNano and
// All.
type WithdrawInput struct {
	RailConfigPath string `json:"rail_config"`
	AmountNano     uint64 `json:"amount_nanotos"`
	All            bool   `json:"all"`
	Yes            bool   `json:"yes"`
}

// WithdrawPreview is what a withdrawal sends.
type WithdrawPreview struct {
	Actor            string `json:"actor"`
	Destination      string `json:"destination"`
	CreditedNano     string `json:"credited_revenue_nanotos"`
	AmountNano       string `json:"amount_nanotos"`
	AttachedNano     string `json:"attached_nanotos"`
	RemainingNano    string `json:"credited_after_nanotos"`
	Checkpoint       uint64 `json:"checkpoint"`
	DestinationNote  string `json:"destination_note"`
	AttachedNanoNote string `json:"attached_note"`
}

// WithdrawResult is the report of `withdraw`.
type WithdrawResult struct {
	Schema     string            `json:"schema"`
	Confirmed  bool              `json:"confirmed"`
	Preview    *WithdrawPreview  `json:"preview,omitempty"`
	Withdrawal *WithdrawalRecord `json:"withdrawal,omitempty"`
}

// WithdrawResultSchema names the withdraw report.
const WithdrawResultSchema = "tos.openfox.rail-withdraw.v1"

// Withdrawal refusals.
var (
	ErrWithdrawZero       = errors.New("servicebridge: the withdrawal amount must be greater than zero")
	ErrWithdrawOverCredit = errors.New("servicebridge: the withdrawal exceeds the actor's credited revenue")
	ErrNothingToWithdraw  = errors.New("servicebridge: the actor has no credited revenue to withdraw")
	ErrWithdrawalPending  = errors.New("servicebridge: an earlier withdrawal is not yet resolved in finalized state")
)

func creditedRevenue(account *toschain.ActorAccount) (uint64, error) {
	if account == nil || account.Data == nil || account.Data.Accounting.WithdrawableRevenue == nil {
		return 0, errors.New("servicebridge: the actor's accounting did not read")
	}
	revenue := account.Data.Accounting.WithdrawableRevenue
	if revenue.Sign() < 0 || !revenue.IsUint64() {
		return 0, ErrAmountOverflow
	}
	return revenue.Uint64(), nil
}

func drawQueryID(random func([]byte) error) (uint64, error) {
	var raw [8]byte
	for attempt := 0; attempt < 4; attempt++ {
		if err := random(raw[:]); err != nil {
			return 0, errors.New("servicebridge: draw a withdrawal query id")
		}
		if id := binary.BigEndian.Uint64(raw[:]); id != 0 {
			return id, nil
		}
	}
	return 0, errors.New("servicebridge: the random source returned zero query ids")
}

// RunWithdraw withdraws credited revenue to the owner wallet. It reads the
// credit at a finalized checkpoint, previews, sends only with Yes, records
// the withdrawal before sending and then reads its finalized outcome. An
// earlier withdrawal that is not resolved blocks a new one: the two could
// otherwise both be included.
func RunWithdraw(ctx context.Context, in WithdrawInput, env SetupEnv) (*WithdrawResult, error) {
	env.fill()
	result := &WithdrawResult{Schema: WithdrawResultSchema}
	if ctx == nil {
		return result, errors.New("servicebridge: no context")
	}
	if in.All == (in.AmountNano != 0) {
		if !in.All {
			return result, ErrWithdrawZero
		}
		return result, errors.New("servicebridge: give exactly one of --amount and --all")
	}
	config, err := LoadNodeConfig(in.RailConfigPath)
	if err != nil {
		return result, err
	}
	actor, err := providerActor(config)
	if err != nil {
		return result, err
	}
	if !rawAddressPattern.MatchString(config.WalletAddress) || !cleanAbsolute(config.StateDir) {
		return result, errors.New("servicebridge: the rail configuration names no owner wallet address or state_dir")
	}
	if err = ensurePrivateDirectory(filepath.Join(config.StateDir, withdrawalDirectory)); err != nil {
		return result, err
	}
	run := &setupRun{ctx: ctx, env: env, stateDir: config.StateDir, endpoints: config.RPCEndpoints}
	run.chain, err = env.OpenChain(config)
	if err != nil {
		return result, fmt.Errorf("servicebridge: open the finalized reader: %s",
			redactEndpoints(err.Error(), run.endpoints))
	}
	session, err := run.begin()
	if err != nil {
		return result, err
	}
	// An unresolved earlier withdrawal is resolved first, never raced.
	earlier, err := ReadWithdrawals(config.StateDir)
	if err != nil {
		return result, err
	}
	for _, record := range earlier {
		if record.terminal() {
			continue
		}
		resolved, resolveErr := resolveWithdrawal(ctx, session, record)
		if resolveErr != nil {
			return result, run.chainError("resolve the earlier withdrawal", resolveErr)
		}
		if saveErr := saveWithdrawal(config.StateDir, resolved, false, env.Now()); saveErr != nil {
			return result, saveErr
		}
		if !resolved.terminal() {
			result.Withdrawal = &resolved
			return result, fmt.Errorf("%w: the withdrawal of %s nanoTOS started at %s; run the command again later",
				ErrWithdrawalPending, resolved.AmountNano,
				time.Unix(resolved.StartedUnix, 0).UTC().Format(time.RFC3339))
		}
		env.reportf("withdraw: the earlier withdrawal of %s nanoTOS is %s", resolved.AmountNano, resolved.State)
	}
	account, found, err := session.ReadActor(ctx, actor)
	if err != nil {
		return result, run.chainError("read the actor", err)
	}
	if !found || account == nil || account.Data == nil {
		return result, fmt.Errorf("servicebridge: the actor %s is not an active account at checkpoint %d", actor,
			session.Checkpoint())
	}
	if owner := account.Data.Owner.Text(); owner != config.WalletAddress {
		return result, fmt.Errorf("servicebridge: the actor is owned by %s, not wallet_address %s; only the owner "+
			"can withdraw", owner, config.WalletAddress)
	}
	credited, err := creditedRevenue(account)
	if err != nil {
		return result, err
	}
	amount := in.AmountNano
	if in.All {
		amount = credited
	}
	switch {
	case credited == 0:
		return result, ErrNothingToWithdraw
	case amount == 0:
		return result, ErrWithdrawZero
	case amount > credited:
		return result, fmt.Errorf("%w: %s TOS asked, %s TOS credited at checkpoint %d", ErrWithdrawOverCredit,
			FormatTOSAmount(amount), FormatTOSAmount(credited), session.Checkpoint())
	}
	if _, err = tosctlAmount(amount, "the withdrawal", false); err != nil {
		return result, fmt.Errorf("%w; withdraw in smaller parts", err)
	}
	remaining, err := checkedSub(credited, amount)
	if err != nil {
		return result, err
	}
	result.Preview = &WithdrawPreview{
		Actor: actor, Destination: config.WalletAddress, CreditedNano: fmt.Sprint(credited),
		AmountNano: fmt.Sprint(amount), AttachedNano: fmt.Sprint(PayoutMessageValueNano),
		RemainingNano: fmt.Sprint(remaining), Checkpoint: session.Checkpoint(),
		DestinationNote:  "the contract pays a withdrawal to the actor's owner, which is this wallet",
		AttachedNanoNote: "sent with the message to pay its fees; the contract returns what is unused",
	}
	env.reportf("withdraw: %s TOS of %s TOS credited (checkpoint %d) from actor %s to owner wallet %s, attaching "+
		"%s TOS for fees", FormatTOSAmount(amount), FormatTOSAmount(credited), session.Checkpoint(), actor,
		config.WalletAddress, FormatTOSAmount(PayoutMessageValueNano))
	if !in.Yes {
		return result, ErrConfirmationRequired
	}
	queryID, err := drawQueryID(env.Random)
	if err != nil {
		return result, err
	}
	record := WithdrawalRecord{
		QueryID: queryID, Actor: actor, Destination: config.WalletAddress, AmountNano: fmt.Sprint(amount),
		AttachedNano: fmt.Sprint(PayoutMessageValueNano), CreditedBeforeNano: fmt.Sprint(credited),
		Anchor: account.LastTransaction, State: WithdrawalSubmitted, StartedUnix: env.Now().Unix(),
	}
	// The record is durable before the message is handed to tosctl.
	if err = saveWithdrawal(config.StateDir, record, true, env.Now()); err != nil {
		return result, err
	}
	result.Withdrawal = &record
	runner, err := env.Runner(config.TOSCTL, env.vaultURL(config.TOSCTL))
	if err != nil {
		record.State, record.Detail = WithdrawalNotIncluded, "tosctl could not be opened; nothing was sent"
		return result, errors.Join(err, saveWithdrawal(config.StateDir, record, false, env.Now()))
	}
	ops := tosctlOps{runner: runner}
	if sendErr := ops.withdrawRevenue(ctx, config.WalletName, actor, amount, queryID); sendErr != nil {
		if refusedBeforeBroadcast(sendErr) {
			record.State, record.Detail = WithdrawalNotIncluded, "tosctl refused before broadcasting; nothing was sent"
			return result, errors.Join(sendErr, saveWithdrawal(config.StateDir, record, false, env.Now()))
		}
		env.reportf("withdraw: %v; the message may still have been broadcast, reading finalized state", sendErr)
	}
	result.Confirmed = true
	decided, _, err := run.awaitEffect(func(session RailSession) (bool, error) {
		resolved, resolveErr := resolveWithdrawal(ctx, session, record)
		if resolveErr != nil {
			// A history that cannot be read yet is waited on.
			return false, nil //nolint:nilerr // the wait continues; an unresolved record is reported below
		}
		if resolved.State == WithdrawalFinalized {
			after, found, readErr := session.ReadActor(ctx, actor)
			if readErr != nil || !found {
				return false, nil //nolint:nilerr // the wait continues with the next finalized session
			}
			if value, creditErr := creditedRevenue(after); creditErr == nil {
				resolved.CreditedAfterNano = new(big.Int).SetUint64(value).String()
			}
		}
		record = resolved
		return record.terminal(), nil
	}, nil)
	if saveErr := saveWithdrawal(config.StateDir, record, false, env.Now()); saveErr != nil {
		return result, saveErr
	}
	switch {
	case err != nil:
		return result, err
	case !decided:
		return result, fmt.Errorf("%w: the withdrawal was sent and is not in finalized state yet; it is recorded, "+
			"and `status` or the next `withdraw` resolves it", ErrOutcomeUnknown)
	case record.State != WithdrawalFinalized:
		return result, fmt.Errorf("servicebridge: the withdrawal is %s: %s", record.State, record.Detail)
	}
	env.reportf("withdraw: finalized at checkpoint %d; the wallet credit itself is %s", record.Checkpoint,
		WalletCreditNotVerified)
	return result, nil
}

// viewWithdrawals returns the newest withdrawal records as status shows
// them. With a session, an unresolved record is shown as finalized state
// decides it at that checkpoint; nothing is written, so status stays a
// read. A record status could not resolve keeps its recorded state.
func viewWithdrawals(ctx context.Context, stateDir string, session withdrawalSession) ([]WithdrawalRecord, error) {
	records, err := ReadWithdrawals(stateDir)
	if err != nil {
		return nil, err
	}
	if len(records) > maxListedWithdrawals {
		records = records[:maxListedWithdrawals]
	}
	for index, record := range records {
		if record.terminal() || session == nil {
			continue
		}
		if resolved, resolveErr := resolveWithdrawal(ctx, session, record); resolveErr == nil {
			records[index] = resolved
		}
	}
	return records, nil
}

// withdrawalSession is the part of a finalized session a withdrawal is
// resolved from.
type withdrawalSession interface {
	Checkpoint() uint64
	ChainTime() time.Time
	History(ctx context.Context, actor string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error)
}

func decodeCellBOCText(value string) (*cell.Cell, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return nil, errors.New("servicebridge: invalid BOC text")
	}
	return cell.FromBOC(raw)
}
