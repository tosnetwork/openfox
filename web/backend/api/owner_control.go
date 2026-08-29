package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/web/backend/authcontext"
	ownercontrol "github.com/tosnetwork/tos-messenger/pkg/ownercontrol"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

func (h *Handler) registerOwnerControlRoutes(mux *http.ServeMux) {
	mux.Handle("/api/owner-control/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		service, store, err := h.ownerControlService()
		if err != nil {
			http.Error(w, "owner control unavailable", http.StatusServiceUnavailable)
			return
		}
		authenticate := func(request *http.Request, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1) (ownercontrol.AuthenticatedPrincipal, error) {
			claims, ok := authcontext.DashboardClaimsFrom(request.Context())
			if !ok {
				return ownercontrol.AuthenticatedPrincipal{}, errors.New("owner control requires an authenticated server channel")
			}
			snapshot := store.Snapshot()
			sessionDigest := attempt.DeviceSessionDigest
			if len(sessionDigest) == 0 {
				now, timeErr := store.TrustedNow()
				if timeErr != nil {
					return ownercontrol.AuthenticatedPrincipal{}, timeErr
				}
				var sessionErr error
				sessionDigest, sessionErr = store.DeviceSessionForAuthenticatedChannel(claims.Audience, claims.ChannelBindingDigest, now)
				if sessionErr != nil {
					return ownercontrol.AuthenticatedPrincipal{}, sessionErr
				}
			}
			return ownercontrol.AuthenticatedPrincipal{DomainKind: snapshot.DomainKind, DomainID: snapshot.DomainID, OwnerID: snapshot.OwnerID,
				Audience: claims.Audience, SessionDigest: sessionDigest, ChannelBindingDigest: claims.ChannelBindingDigest, MayReadEvidence: claims.MayReadEvidence}, nil
		}
		http.StripPrefix("/api/owner-control", ownercontrol.Handler(service, authenticate)).ServeHTTP(w, r)
	}))
}

func (h *Handler) ownerControlService() (*ownercontrol.Service, *capabilitycontrol.Store, error) {
	store, err := h.capabilityStore()
	if err != nil {
		return nil, nil, err
	}
	h.capabilityMu.Lock()
	defer h.capabilityMu.Unlock()
	if h.ownerCommandService != nil {
		return h.ownerCommandService, store, nil
	}
	cfg, err := config.LoadConfig(h.configPath)
	if err != nil {
		return nil, nil, err
	}
	if h.capabilityAuthority == nil {
		return nil, nil, errors.New("capability monotonic authority is unavailable")
	}
	snapshot := store.Snapshot()
	sinkHash := sha256.Sum256(bytes.Join([][]byte{[]byte("openfox.owner-command-sink.v1\x00"), snapshot.OwnerID, snapshot.AgentID, snapshot.InstallationID}, nil))
	authority := journalAuthority{authority: h.capabilityAuthority, installationID: sha256.Sum256(append([]byte("openfox.owner-command-journal.v1\x00"), snapshot.InstallationID...))}
	journal, err := ownercontrol.OpenFileJournal(filepath.Join(cfg.Earning.TrustedCapability.SinkJournalDirectory, "owner-command"), authority)
	if err != nil {
		return nil, nil, err
	}
	adapter := ownerCommandAdapter{store: store, sinkID: sinkHash[:], epoch: snapshot.DeploymentFormatEpoch}
	service, err := ownercontrol.New(adapter, adapter, journal, adapter, sinkHash[:], false, adapter)
	if err != nil {
		_ = journal.Close()
		return nil, nil, err
	}
	h.ownerCommandJournal, h.ownerCommandService = journal, service
	return service, store, nil
}

type journalAuthority struct {
	authority      capabilitycontrol.ProductionAuthority
	installationID [32]byte
}

func (a journalAuthority) InstallationID(context.Context) ([]byte, error) {
	return append([]byte(nil), a.installationID[:]...), nil
}
func (a journalAuthority) Read(ctx context.Context, scope []byte) (uint64, []byte, error) {
	return a.authority.Read(ctx, scope)
}
func (a journalAuthority) Check(ctx context.Context, scope []byte, revision uint64, commitment []byte) error {
	return a.authority.Check(ctx, scope, revision, commitment)
}
func (a journalAuthority) CompareAndAdvance(ctx context.Context, scope []byte, prior, next uint64, commitment []byte) error {
	return a.authority.CompareAndAdvance(ctx, scope, prior, next, commitment)
}

type ownerCommandAdapter struct {
	store  *capabilitycontrol.Store
	sinkID []byte
	epoch  uint64
}

func (a ownerCommandAdapter) VerifyOwnerCommand(_ context.Context, principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence) error {
	now, err := a.store.TrustedNow()
	if err != nil {
		return err
	}
	return a.store.VerifyOwnerCommand(principal, effect, attempt, evidence, now)
}
func (a ownerCommandAdapter) VerifyOwnerCommandRecovery(ctx context.Context, principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence) error {
	return a.store.VerifyOwnerCommandRecovery(ctx, principal, effect, attempt, evidence)
}
func (a ownerCommandAdapter) VerifyOwnerCommandQuery(_ context.Context, principal ownercontrol.AuthenticatedPrincipal, _, _ []byte) error {
	now, err := a.store.TrustedNow()
	if err != nil {
		return err
	}
	return a.store.VerifyOwnerCommandQuery(principal, now)
}
func (a ownerCommandAdapter) ApplyOwnerCommand(_ context.Context, principal ownercontrol.AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence ownercontrol.SubmissionEvidence, fence []byte) (uint64, []trusted.ImmutableObjectReferenceV1, error) {
	revision, err := a.store.ApplySignedOwnerCommand(principal, effect, attempt, evidence, fence)
	return revision, nil, err
}
func (a ownerCommandAdapter) ReconcileOwnerCommand(_ context.Context, _ ownercontrol.AuthenticatedPrincipal, _ trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, _ ownercontrol.SubmissionEvidence, fence []byte) (string, uint64, []trusted.ImmutableObjectReferenceV1, error) {
	state, revision, err := a.store.ResolveOwnerCommand(attempt, fence)
	return state, revision, nil, err
}
func (a ownerCommandAdapter) CurrentOwnerCommandSink(context.Context) ([]byte, uint64, error) {
	return append([]byte(nil), a.sinkID...), a.epoch, nil
}
func (a ownerCommandAdapter) ObserveTrustedTime(ctx context.Context) (ownercontrol.TrustedTimeObservation, error) {
	observation, err := a.store.ObserveTrustedTime(ctx)
	if err != nil {
		return ownercontrol.TrustedTimeObservation{}, err
	}
	return ownercontrol.TrustedTimeObservation{UnixSeconds: observation.UnixSeconds, Epoch: observation.Epoch,
		EvidenceDigest: append([]byte(nil), observation.EvidenceDigest...)}, nil
}
