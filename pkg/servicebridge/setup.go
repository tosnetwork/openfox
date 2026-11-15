package servicebridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// RailSession is one finalized checkpoint as the setup and withdrawal
// commands read it.
type RailSession interface {
	serviceactor.Session
	History(ctx context.Context, actor string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error)
}

// RailChain opens finalized sessions and checks endpoint genesis.
type RailChain interface {
	Endpoints() []string
	CheckEndpointGenesis(ctx context.Context, endpoint string) error
	BeginRail(ctx context.Context) (RailSession, error)
}

// ReaderRailChain adapts the finalized Service Actor reader.
type ReaderRailChain struct{ Reader *toschain.ServiceActorReader }

// Endpoints implements RailChain.
func (c ReaderRailChain) Endpoints() []string { return c.Reader.Endpoints() }

// CheckEndpointGenesis implements RailChain.
func (c ReaderRailChain) CheckEndpointGenesis(ctx context.Context, endpoint string) error {
	return c.Reader.CheckEndpointGenesis(ctx, endpoint)
}

// BeginRail implements RailChain.
func (c ReaderRailChain) BeginRail(ctx context.Context) (RailSession, error) {
	return c.Reader.Begin(ctx)
}

// OpenRailChain opens the configuration's finalized reader with the node's
// own checkpoint fences, so a setup step never acts on a checkpoint older
// than one the node already acted on.
func OpenRailChain(config NodeConfig) (RailChain, error) {
	if err := ensurePrivateDirectory(config.StateDir); err != nil {
		return nil, err
	}
	reader, err := openServiceActorReader(config, networkOf(config), config.StateDir)
	if err != nil {
		return nil, err
	}
	return ReaderRailChain{Reader: reader}, nil
}

// SetupEnv supplies the effects of the setup and withdrawal commands; zero
// fields take the real implementations.
type SetupEnv struct {
	Now    func() time.Time
	Sleep  func(ctx context.Context, wait time.Duration) error
	Getenv func(name string) string
	Random func(value []byte) error
	// Runner opens the pinned tosctl.
	Runner func(config TOSCTLConfig, vaultURL string) (TOSCTLRunner, error)
	// OpenChain opens the finalized reader.
	OpenChain func(config NodeConfig) (RailChain, error)
	// ExecutorService opens the client of the executor service socket.
	ExecutorService func(socket string) (ExecutorService, error)
	// Report prints one diagnostic line (previews, progress) for the owner.
	Report func(line string)
	// WaitBudget bounds how long one run waits for a sent message to
	// finalize; PollInterval is the pause between finalized reads.
	WaitBudget   time.Duration
	PollInterval time.Duration
}

func (e *SetupEnv) fill() {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Sleep == nil {
		e.Sleep = func(ctx context.Context, wait time.Duration) error {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.ExecutorService == nil {
		e.ExecutorService = OpenExecutorService
	}
	if e.Random == nil {
		e.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	if e.Runner == nil {
		e.Runner = func(config TOSCTLConfig, vaultURL string) (TOSCTLRunner, error) {
			return NewSealedTOSCTL(config, vaultURL)
		}
	}
	if e.OpenChain == nil {
		e.OpenChain = OpenRailChain
	}
	if e.Report == nil {
		e.Report = func(string) {}
	}
	if e.WaitBudget == 0 {
		e.WaitBudget = 5 * time.Minute
	}
	if e.PollInterval == 0 {
		e.PollInterval = 3 * time.Second
	}
}

func (e *SetupEnv) reportf(format string, arguments ...any) {
	e.Report(fmt.Sprintf(format, arguments...))
}

func (e *SetupEnv) vaultURL(config TOSCTLConfig) string {
	if config.VaultURLEnv == "" {
		return ""
	}
	return e.Getenv(config.VaultURLEnv)
}

func (e *SetupEnv) nonce() (string, error) {
	value := make([]byte, 32)
	if err := e.Random(value); err != nil {
		return "", errors.New("servicebridge: draw a nonce")
	}
	if hex.EncodeToString(value) == zeroHash64 {
		return "", errors.New("servicebridge: the random source returned an all-zero nonce")
	}
	return hex.EncodeToString(value), nil
}

// ErrConfirmationRequired reports that the previewed actions were not run
// because the owner did not pass --yes.
var ErrConfirmationRequired = errors.New("servicebridge: nothing was signed or sent; review the preview and " +
	"re-run with --yes")

// ErrOutcomeUnknown reports a sent chain message whose effect is not yet in
// finalized state. It is never answered by sending again: a later run reads
// finalized state first.
var ErrOutcomeUnknown = errors.New("servicebridge: the outcome of a sent message is not yet established")

// ErrSetupInputChanged reports an identity-determining input that differs
// from the one an already sent step used.
var ErrSetupInputChanged = errors.New("servicebridge: an input that determines an on-chain identity changed after " +
	"a step was sent")

// sendResolutionWindow is how long after a send began its wallet message
// can still be included: tosctl's own bound on the send (two minutes), the
// wallet message lifetime it signs (two minutes) and one more minute. Past
// it, on finalized chain time, a message whose effect is absent can no
// longer take effect.
//
// The last minute covers two things the first four do not. The start is
// stamped with this host's clock while expiry is judged on chain time, so
// a host clock that runs behind the chain makes the window end early by
// that difference. And every message here takes one more hop after the
// wallet's own transaction (wallet to registry or actor), which is
// included a few blocks after the wallet message itself. A minute is far
// more than either on a network whose blocks are seconds apart; a host
// whose clock is off by more than that is reported by preflight's
// clock.skew check.
const sendResolutionWindow = defaultLifecycleTime + 2*time.Minute + time.Minute

// Chain step states. A step is marked sending durably before its message is
// handed to tosctl, so a crash at any later point leaves a record that says
// a message may be in flight.
const (
	stepPending   = ""
	stepSending   = "sending"
	stepFinalized = "finalized"
)

// ChainStep is what the journal knows about one chain message.
type ChainStep struct {
	State       string `json:"state,omitempty"`
	StartedUnix int64  `json:"started_unix,omitempty"`
	Attempts    int    `json:"attempts,omitempty"`
	// Included is set when tosctl saw the wallet's sequence number move.
	Included   bool   `json:"wallet_sequence_moved,omitempty"`
	Checkpoint uint64 `json:"finalized_checkpoint,omitempty"`
}

func (s ChainStep) sent() bool { return s.State != stepPending || s.Attempts > 0 }

const (
	setupJournalSchema = "tos.openfox.rail-setup.v1"
	setupDirectory     = "setup"
	setupJournalFile   = "journal.json"
	maxSetupJournal    = 1 << 20
)

// SetupJournal is the one durable record of `init` and `offer`. It holds
// the inputs that determine on-chain identities, the nonces drawn for them
// (stored before any action is built, so a re-run rebuilds the same
// object) and the state of every chain message.
type SetupJournal struct {
	Schema      string        `json:"schema"`
	UpdatedUnix int64         `json:"updated_unix"`
	Init        *InitJournal  `json:"init,omitempty"`
	Offer       *OfferJournal `json:"offer,omitempty"`
}

func setupJournalPath(stateDir string) string {
	return filepath.Join(stateDir, setupDirectory, setupJournalFile)
}

// loadSetupJournal reads the journal; a missing journal is an empty one.
func loadSetupJournal(stateDir string) (*SetupJournal, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("servicebridge: state_dir must be absolute and clean")
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Join(stateDir, setupDirectory)); err != nil {
		return nil, err
	}
	journal := &SetupJournal{}
	if err := readJSON(setupJournalPath(stateDir), maxSetupJournal, journal); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &SetupJournal{Schema: setupJournalSchema}, nil
		}
		return nil, fmt.Errorf("servicebridge: setup journal: %w", err)
	}
	if journal.Schema != setupJournalSchema {
		return nil, errors.New("servicebridge: the setup journal has another schema")
	}
	return journal, nil
}

func saveSetupJournal(stateDir string, journal *SetupJournal, now time.Time) error {
	journal.Schema, journal.UpdatedUnix = setupJournalSchema, now.Unix()
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return errors.New("servicebridge: encode the setup journal")
	}
	return replaceSynced(setupJournalPath(stateDir), encoded)
}

// SetupStep is one line of a setup command's report.
type SetupStep struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Setup step outcomes.
const (
	SetupDone    = "done"
	SetupAlready = "already_done"
	SetupPlanned = "planned"
	// SetupMissing marks something the command does not do and the owner
	// still has to supply.
	SetupMissing = "missing"
)

// setupRun carries what `init` and `offer` share while they run.
type setupRun struct {
	ctx      context.Context
	env      SetupEnv
	stateDir string
	journal  *SetupJournal
	chain    RailChain
	yes      bool
	steps    []SetupStep
	// wallet is the owner wallet every step sends from. A step is sent
	// only from a wallet whose messages expire.
	wallet *WalletView
	// endpoints are redacted from every chain error.
	endpoints []string
}

func (r *setupRun) save() error {
	return saveSetupJournal(r.stateDir, r.journal, r.env.Now())
}

func (r *setupRun) notef(id, status, format string, arguments ...any) {
	detail := redactEndpoints(fmt.Sprintf(format, arguments...), r.endpoints)
	r.steps = append(r.steps, SetupStep{ID: id, Status: status, Detail: detail})
	r.env.reportf("%s: %s: %s", id, status, detail)
}

func (r *setupRun) chainError(what string, err error) error {
	return fmt.Errorf("servicebridge: %s: %s", what, redactEndpoints(err.Error(), r.endpoints))
}

func (r *setupRun) begin() (RailSession, error) {
	session, err := r.chain.BeginRail(r.ctx)
	if err != nil {
		return nil, r.chainError("no finalized checkpoint by strict majority", err)
	}
	return session, nil
}

// refusedBeforeBroadcast reports the tosctl failures that are checks tosctl
// makes before it broadcasts anything: after one of them no message is in
// flight.
func refusedBeforeBroadcast(err error) bool {
	var unsent *notSentError
	if errors.As(err, &unsent) {
		return true
	}
	switch tosctlFailure(err) {
	case TOSCTLFailureBalance, TOSCTLFailureWalletState, TOSCTLFailureNotFound, TOSCTLFailureAlreadyExists,
		TOSCTLFailureOccupied, TOSCTLFailureWrongChain:
		return true
	default:
		return false
	}
}

// effectFunc reports whether a step's effect is in finalized state at the
// session's checkpoint. It returns an error when finalized state holds
// something that contradicts the step (another owner, another attestor).
type effectFunc func(session RailSession) (bool, error)

// awaitEffect polls finalized state until the effect is present, stop
// reports true for a checkpoint, or the wait budget ends.
func (r *setupRun) awaitEffect(effect effectFunc, stop func(RailSession) bool) (bool, RailSession, error) {
	deadline := r.env.Now().Add(r.env.WaitBudget)
	for {
		session, err := r.begin()
		if err == nil {
			done, effectErr := effect(session)
			if effectErr != nil {
				return false, session, effectErr
			}
			if done || (stop != nil && stop(session)) {
				return done, session, nil
			}
		}
		if !r.env.Now().Before(deadline) {
			if err != nil {
				return false, nil, err
			}
			return false, session, nil
		}
		if sleepErr := r.env.Sleep(r.ctx, r.env.PollInterval); sleepErr != nil {
			return false, nil, sleepErr
		}
	}
}

// runStep drives one chain message: finalized state is read first; a
// message that may be in flight is resolved or waited on; only a message
// that is known not to be in flight is sent, after the step is durably
// marked as sending.
func (r *setupRun) runStep(id, what string, step *ChainStep, effect effectFunc, send func() error) error {
	session, err := r.begin()
	if err != nil {
		return err
	}
	done, err := effect(session)
	if err != nil {
		return err
	}
	if done {
		status := SetupAlready
		if step.State == stepSending {
			status = SetupDone
		}
		step.State, step.Checkpoint = stepFinalized, session.Checkpoint()
		if saveErr := r.save(); saveErr != nil {
			return saveErr
		}
		r.notef(id, status, "%s is in finalized state at checkpoint %d", what, session.Checkpoint())
		return nil
	}
	if step.State == stepSending {
		expiry := time.Unix(step.StartedUnix, 0).Add(sendResolutionWindow)
		expired := func(session RailSession) bool { return session.ChainTime().After(expiry) }
		if !expired(session) {
			r.env.reportf("%s: an earlier send (attempt %d) may still be included; waiting for finalized state",
				id, step.Attempts)
			done, session, err = r.awaitEffect(effect, expired)
			if err != nil {
				return err
			}
			if done {
				step.State, step.Checkpoint = stepFinalized, session.Checkpoint()
				if saveErr := r.save(); saveErr != nil {
					return saveErr
				}
				r.notef(id, SetupDone, "%s is in finalized state at checkpoint %d", what, session.Checkpoint())
				return nil
			}
			if session == nil || !expired(session) {
				return fmt.Errorf("%w: %s was sent at %s and is neither finalized nor expired; nothing was "+
					"re-sent, run the command again later", ErrOutcomeUnknown, what,
					time.Unix(step.StartedUnix, 0).UTC().Format(time.RFC3339))
			}
		}
		r.env.reportf("%s: the send of %s is past its inclusion window on finalized chain time and its effect is "+
			"absent, so that message can no longer take effect", id,
			time.Unix(step.StartedUnix, 0).UTC().Format(time.RFC3339))
	}
	// "Past its window an absent message cannot land" is only true of a
	// wallet whose messages expire, so no other wallet sends a step.
	if r.wallet == nil {
		return errors.New("servicebridge: the owner wallet was not resolved before a send")
	}
	if walletErr := requireExpiringWallet(*r.wallet); walletErr != nil {
		return walletErr
	}
	if !r.yes {
		r.notef(id, SetupPlanned, "%s will be sent", what)
		return ErrConfirmationRequired
	}
	// The record says a message may be in flight before tosctl is run.
	step.State, step.StartedUnix, step.Included = stepSending, r.env.Now().Unix(), false
	step.Attempts++
	if saveErr := r.save(); saveErr != nil {
		return saveErr
	}
	if sendErr := send(); sendErr != nil {
		var contradiction *contradictionError
		if errors.As(sendErr, &contradiction) {
			// The step stays recorded as sending; the caller records the
			// contradiction so no later run sends again.
			return sendErr
		}
		if refusedBeforeBroadcast(sendErr) {
			step.State = stepPending
			if saveErr := r.save(); saveErr != nil {
				return errors.Join(sendErr, saveErr)
			}
			return sendErr
		}
		r.env.reportf("%s: %v; the message may still have been broadcast, waiting for finalized state", id, sendErr)
	} else {
		step.Included = true
		if saveErr := r.save(); saveErr != nil {
			return saveErr
		}
	}
	done, session, err = r.awaitEffect(effect, nil)
	if err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("%w: %s was sent and is not in finalized state yet; nothing will be re-sent, run the "+
			"command again to resume", ErrOutcomeUnknown, what)
	}
	step.State, step.Checkpoint = stepFinalized, session.Checkpoint()
	if saveErr := r.save(); saveErr != nil {
		return saveErr
	}
	r.notef(id, SetupDone, "%s is in finalized state at checkpoint %d", what, session.Checkpoint())
	return nil
}

// handoff stamps a step at the moment its message is handed to the wallet.
// A send that first builds or signs something calls it right before the
// wallet send, so the inclusion window is counted from the instant the
// wallet message can be signed, not from the start of what preceded it.
func (r *setupRun) handoff(step *ChainStep) error {
	step.StartedUnix = r.env.Now().Unix()
	return r.save()
}

// checkGenesis requires that no endpoint serves another network and that a
// quorum serves the configured genesis.
func checkEndpointGenesis(ctx context.Context, chain RailChain, config NodeConfig) error {
	endpoints := chain.Endpoints()
	matched := 0
	var failures []error
	wrongNetwork := false
	for index, endpoint := range endpoints {
		if err := chain.CheckEndpointGenesis(ctx, endpoint); err != nil {
			var protocolErr *nativecore.ProtocolError
			if errors.As(err, &protocolErr) && protocolErr.Code == nativecore.ErrWrongNetwork {
				wrongNetwork = true
			}
			failures = append(failures, fmt.Errorf("rpc_endpoints[%d]: %s", index,
				redactEndpoints(err.Error(), endpoints)))
			continue
		}
		matched++
	}
	if quorum := effectiveQuorum(config); wrongNetwork || matched < quorum || matched == 0 {
		return fmt.Errorf("servicebridge: %d of %d RPC endpoints serve the genesis of the chain global config "+
			"(quorum %d): %w", matched, len(endpoints), quorum, errors.Join(failures...))
	}
	return nil
}

// notSentError marks a failure that happened before anything was handed to
// a wallet: building a message, or a local check.
type notSentError struct{ err error }

func (e *notSentError) Error() string { return e.err.Error() }
func (e *notSentError) Unwrap() error { return e.err }

func notSent(err error) error {
	if err == nil {
		return nil
	}
	return &notSentError{err: err}
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// contradictionError marks a send whose result contradicts the plan in a
// way finalized state cannot repair: waiting or sending again would only
// repeat it.
type contradictionError struct{ err error }

func (e *contradictionError) Error() string { return e.err.Error() }
func (e *contradictionError) Unwrap() error { return e.err }
