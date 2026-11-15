package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/railgate"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// objectSweepInterval is how often the provider deletes stored objects whose
// retention ended.
const objectSweepInterval = 10 * time.Minute

// objectSweeper is a store that deletes objects whose retention ended.
type objectSweeper interface {
	Sweep(ctx context.Context, now time.Time) error
}

// respondCutoff is the unix second from which waiting for an outcome no
// longer leaves the respond budget before the response deadline.
func respondCutoff(responseDeadline uint64, budget time.Duration) (int64, bool) {
	if budget <= 0 {
		return 0, false
	}
	seconds := uint64((budget + time.Second - 1) / time.Second)
	if responseDeadline <= seconds || responseDeadline-seconds > math.MaxInt64 {
		return 0, false
	}
	return int64(responseDeadline - seconds), true
}

func recordKey(record ProviderRecord) railgate.SlotKey {
	return railgate.SlotKey{QuoteCommitment: record.QuoteCommitment, Actor: record.Actor, RequestID: record.RequestID}
}

// sourcePath is where an executing request's source archive is kept, so the
// same request can be sent to the executor service again after a restart.
func (p *Provider) sourcePath(key railgate.SlotKey) string {
	return strings.TrimSuffix(p.recordPath(key), ".json") + ".source"
}

// startService records an admitted request as executing, with everything a
// restarted node needs to send the same request again, before the gate
// starts it.
func (p *Provider) startService(
	ctx context.Context,
	key railgate.SlotKey,
	record ProviderRecord,
	archive []byte,
) error {
	record.State = ProviderExecuting
	if err := writeSynced(p.sourcePath(key), archive); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := p.store(key, record, true); err != nil {
		return err
	}
	return p.advanceExecuting(ctx, p.recordPath(key), record)
}

// advanceExecuting sends an executing request to the executor service, for
// the first time or again, and acts on the answer. The gate decides whether
// the execution may start; the service runs an execution id at most once, so
// asking again for a started one only ever reads its outcome.
//
//   - A verified success is attested and moves on to respond.
//   - A failed run is recorded failed and never attested.
//   - An execution the service cannot account for is recorded unknown and
//     never attested.
//   - Anything else leaves the record executing; the next round asks again,
//     until the respond budget no longer fits before the response deadline.
func (p *Provider) advanceExecuting(ctx context.Context, path string, record ProviderRecord) error {
	key := recordKey(record)
	cutoff, ok := respondCutoff(record.ResponseDeadline, p.config.RespondBudget)
	if !ok || p.config.Now().Unix() >= cutoff {
		// Too late to respond: stop asking. The request resolves by refund.
		return p.endExecuting(key, record, ProviderAbandoned)
	}
	claim, expected, err := claimOf(record)
	if err != nil {
		return err
	}
	slot, found, err := p.config.Gate.Lookup(key)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("servicebridge: the request has no execution slot")
	}
	var outcome softwarework.Outcome
	var runErr error
	switch slot.State {
	case railgate.SlotAdmitted:
		asked := false
		runErr = p.config.Gate.Run(ctx, slot, claim, func(runCtx context.Context, _ *railgate.Verified) error {
			asked = true
			var askErr error
			outcome, askErr = p.askService(runCtx, key, record, cutoff)
			return askErr
		})
		if errors.Is(runErr, railgate.ErrNotPendingNow) {
			return errors.Join(runErr, p.endExecuting(key, record, ProviderAbandoned))
		}
		if !asked {
			if runErr == nil {
				runErr = errors.New("servicebridge: the gate started nothing")
			}
			return runErr
		}
	case railgate.SlotStarted, railgate.SlotAmbiguous, railgate.SlotCompleted:
		// The gate already let this execution start; asking the service
		// again only reads the outcome of that one run.
		outcome, runErr = p.askService(ctx, key, record, cutoff)
	case railgate.SlotFailed:
		return p.endExecuting(key, record, ProviderFailed)
	case railgate.SlotAbandoned:
		return p.endExecuting(key, record, ProviderAbandoned)
	default:
		return fmt.Errorf("servicebridge: the execution slot is in the unrecognized state %q", slot.State)
	}
	switch {
	case runErr == nil:
	case errors.Is(runErr, ErrExecutionFailed):
		return errors.Join(runErr, p.failSlot(key), p.endExecuting(key, record, ProviderFailed))
	case errors.Is(runErr, ErrExecutionUnknown):
		return errors.Join(runErr, p.endExecuting(key, record, ProviderUnknown))
	default:
		return runErr
	}
	binding := ReceiptBinding{
		QuoteCommitment: record.QuoteCommitment, ExecutionID: claim.ExecutionID, InputDigest: claim.InputDigest,
		SourceDigest: record.SourceDigest, Price: expected.Price, ProviderAgentID: p.config.AgentID,
		ToolchainDigest: record.ToolchainDigest, SandboxDigest: record.SandboxDigest,
	}
	receipt, responseHash, err := BuildReceipt(binding, outcome)
	var boc []byte
	if err == nil {
		boc = receipt.ToBOC()
		_, err = CheckAttestable(boc, binding, outcome)
	}
	if err != nil {
		return errors.Join(err, p.failSlot(key), p.endExecuting(key, record, ProviderFailed))
	}
	response := hex.EncodeToString(responseHash[:])
	slot, found, err = p.config.Gate.Lookup(key)
	if err != nil {
		return err
	}
	switch {
	case !found:
		return errors.New("servicebridge: the request has no execution slot")
	case slot.State == railgate.SlotStarted:
		if err = p.config.Gate.Complete(key, response); err != nil {
			return err
		}
	default:
		// The gate no longer holds the execution started: the node
		// restarted during the run, or died after the gate recorded the
		// result. Only the gate decides whether this outcome may still be
		// attested.
		if err = p.reconcile(ctx, key, record, claim, response); err != nil {
			return err
		}
	}
	record.State, record.ResponseHash = ProviderExecuted, response
	record.ReceiptBOCBase64, record.ArtifactDigest = base64.StdEncoding.EncodeToString(boc), outcome.Artifact.Digest
	if err = p.store(key, record, false); err != nil {
		return err
	}
	return errors.Join(p.dropSource(key), p.resumeExecuted(ctx, path, record, p.config.Now()))
}

// reconcile hands the gate the response hash of an outcome the service
// recorded for an execution the gate lost track of. The gate verifies the
// request afresh and completes the slot only if it was left ambiguous by a
// restart, or already holds this very hash.
//
//   - No finalized checkpoint: nothing was decided; the record stays
//     executing and the next round asks again.
//   - The gate refuses the slot or holds another response hash: the record
//     is unknown, with the gate's reason, and is never attested.
//   - The verifier refuses the request (no longer pending, no respond
//     budget left): nothing is attested and the record stays executing
//     until the respond cut-off abandons it, as a failed pre-respond check
//     leaves an executed record.
func (p *Provider) reconcile(
	ctx context.Context,
	key railgate.SlotKey,
	record ProviderRecord,
	claim railgate.Claim,
	response string,
) error {
	_, _, err := p.config.Gate.Reconcile(ctx, claim, response)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, railgate.ErrNotReconcilable), errors.Is(err, railgate.ErrReconcileConflict):
		record.Detail = err.Error()
		return errors.Join(err, p.endExecuting(key, record, ProviderUnknown))
	default:
		return fmt.Errorf("servicebridge: the outcome is not recorded by the gate yet: %w", err)
	}
}

// askService sends the request with its staged source and waits no longer
// than the respond cut-off.
func (p *Provider) askService(
	ctx context.Context,
	key railgate.SlotKey,
	record ProviderRecord,
	cutoff int64,
) (softwarework.Outcome, error) {
	if record.ResponseDeadline > math.MaxInt64 || record.RetentionEndUnix > math.MaxInt64 {
		return softwarework.Outcome{}, errors.New("servicebridge: the request deadlines are out of range")
	}
	if record.ExecutionLimits == nil {
		return softwarework.Outcome{}, errors.New("servicebridge: the record holds no execution limits")
	}
	limits := *record.ExecutionLimits
	remaining := time.Duration(cutoff-p.config.Now().Unix()) * time.Second
	if remaining <= 0 {
		return softwarework.Outcome{}, fmt.Errorf("%w: the respond cut-off has passed", ErrExecutionPending)
	}
	archive, err := readPrivateFile(p.sourcePath(key), MaxInlineInputBytes)
	if err != nil {
		return softwarework.Outcome{}, fmt.Errorf("servicebridge: the staged source archive: %w", err)
	}
	wait, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	return p.config.Service.Execute(wait, ServiceExecution{
		Request: softwarework.Request{
			QuoteCommitment: record.QuoteCommitment, ExecutionID: "sha256:" + record.ExecutionID,
			InputDigest: "sha256:" + record.InputDigest, SourceDigest: record.SourceDigest, SourceArchive: archive,
		},
		ManifestDigest: record.SandboxDigest, ToolchainDigest: record.ToolchainDigest,
		Limits: nativecore.SoftwareWorkLimitsV1{
			CPUMillis: limits.CPUMillis, MemoryBytes: limits.MemoryBytes, ScratchBytes: limits.ScratchBytes,
			OutputBytes: limits.OutputBytes, WallClockMillis: limits.WallClockMillis,
		},
		ServiceRetainUntilUnix: int64(record.ResponseDeadline), RetainUntilUnix: int64(record.RetentionEndUnix),
	})
}

// endExecuting records the terminal state of an execution that is never
// attested and drops its staged source.
func (p *Provider) endExecuting(key railgate.SlotKey, record ProviderRecord, state string) error {
	record.State = state
	if err := p.store(key, record, false); err != nil {
		return err
	}
	return p.dropSource(key)
}

func (p *Provider) dropSource(key railgate.SlotKey) error {
	if err := os.Remove(p.sourcePath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("servicebridge: remove the staged source archive")
	}
	return nil
}

// failSlot records a run that did not succeed in a slot the gate still
// holds started. A slot the gate already calls ambiguous stays so.
func (p *Provider) failSlot(key railgate.SlotKey) error {
	slot, found, err := p.config.Gate.Lookup(key)
	if err != nil || !found || slot.State != railgate.SlotStarted {
		return err
	}
	return p.config.Gate.Fail(key)
}

// sweepObjects deletes stored objects whose retention ended, at most once
// per objectSweepInterval.
func (p *Provider) sweepObjects(ctx context.Context, now time.Time) error {
	sweeper, ok := p.config.Store.(objectSweeper)
	if !ok || (!p.lastSweep.IsZero() && now.Sub(p.lastSweep) < objectSweepInterval) {
		return nil
	}
	p.lastSweep = now
	return sweeper.Sweep(ctx, now)
}
