package earning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/openfox/pkg/capabilitycontrol"
	"github.com/tosnetwork/tos-ai/pkg/capabilitygate"
	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type TrustedCapabilityExecutionBundle struct {
	SchemaVersion uint16                 `json:"schema_version"`
	PlanDigest    string                 `json:"plan_digest"`
	Request       capabilitygate.Request `json:"request"`
}

type ProductionTrustedCapabilityAdmission struct {
	Store           *capabilitycontrol.Store
	BundleDirectory string
}

func (admission ProductionTrustedCapabilityAdmission) StartTrustedCapabilityExecution(ctx context.Context, _ EngagementRecord, plan commercegate.Plan) (TrustedCapabilityExecutionPermit, error) {
	if admission.Store == nil || !filepath.IsAbs(admission.BundleDirectory) || !isDigestText(plan.ExecutionID) || !isDigestText(plan.CanonicalPlanDigest) {
		return TrustedCapabilityExecutionPermit{}, errors.New("production trusted capability admission is unavailable")
	}
	path := filepath.Join(admission.BundleDirectory, strings.TrimPrefix(plan.ExecutionID, "sha256:")+".json")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8<<20 {
		return TrustedCapabilityExecutionPermit{}, errors.New("execution capability authorization bundle is unavailable or unbounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle TrustedCapabilityExecutionBundle
	if decoder.Decode(&bundle) != nil || decoder.Decode(&struct{}{}) != io.EOF || bundle.SchemaVersion != 1 || bundle.PlanDigest != plan.CanonicalPlanDigest {
		return TrustedCapabilityExecutionPermit{}, errors.New("execution capability authorization bundle is invalid")
	}
	executionID, _ := hex.DecodeString(strings.TrimPrefix(plan.ExecutionID, "sha256:"))
	if !bytes.Equal(bundle.Request.Binding.ExecutionID, executionID) || string(bundle.Request.Binding.OwnerID) != plan.OwnerID || string(bundle.Request.Binding.AgentID) != plan.AgentID {
		return TrustedCapabilityExecutionPermit{}, errors.New("execution capability bundle is cross-plan or cross-principal")
	}
	planDigest, _ := parseDigestText(plan.CanonicalPlanDigest)
	if !bytes.Equal(bundle.Request.Binding.InvocationDescriptorDigest, planDigest) {
		return TrustedCapabilityExecutionPermit{}, errors.New("execution plan is not committed by the signed capability lease")
	}
	sealed, err := admission.Store.SealLLMSkill(bundle.Request.Binding.ArtifactVersionDigest)
	if err != nil {
		return TrustedCapabilityExecutionPermit{}, err
	}
	loaded, installationRevision, err := admission.Store.MeasureInstalledArtifact(bundle.Request.Binding.ArtifactVersionDigest)
	if err != nil {
		return TrustedCapabilityExecutionPermit{}, err
	}
	observed, err := observedPlanResources(plan, loaded, installationRevision, bundle.Request.Binding.RemoteSessionHandshakeDigest)
	if err != nil {
		return TrustedCapabilityExecutionPermit{}, err
	}
	bundle.Request.Observed = observed
	snapshot, err := admission.Store.ResolveExecutionAuthority(bundle.Request.Binding.ArtifactVersionDigest, bundle.Request.LeaseEnvelope)
	if err != nil {
		return TrustedCapabilityExecutionPermit{}, err
	}
	heads := capabilitygate.AuthorityHeads{AuthorityEpoch: snapshot.AuthorityEpoch, PolicyRevision: snapshot.PolicyRevision,
		AdmissionRevocationGeneration: snapshot.AdmissionRevocationGeneration, PromotionRevocationGeneration: snapshot.PromotionRevocationGeneration,
		ControlScopeGeneration: snapshot.ControlScopeGeneration, AdmissionRevision: snapshot.AdmissionRevision, PromotionRevision: snapshot.PromotionRevision,
		InstallationRevision: snapshot.InstallationRevision, InventoryRevision: snapshot.InventoryRevision, PolicyDigest: snapshot.PolicyDigest,
		AdmissionEnvelopeDigest: snapshot.AdmissionEnvelopeDigest, PromotionEnvelopeDigest: snapshot.PromotionEnvelopeDigest,
		PermissionManifestDigest: snapshot.PermissionManifestDigest, AdmittedPermissionManifest: snapshot.AdmittedPermissionManifest,
		LeaseIssuerSubject: snapshot.LeaseIssuerSubject, LeaseAuthorityID: snapshot.LeaseAuthorityID, LeaseProofProfileURI: snapshot.LeaseProofProfileURI,
		OwnerID: snapshot.OwnerID, AgentID: snapshot.AgentID}
	resolver := fixedCapabilityHeads{heads: heads, artifact: append([]byte(nil), bundle.Request.Binding.ArtifactVersionDigest...)}
	journal := &storeCapabilityStartJournal{store: admission.Store, request: bundle.Request}
	gate, err := capabilitygate.New(trusted.DomainKind(bundle.Request.LeaseObject.DomainKind), bundle.Request.LeaseObject.DomainID, snapshot.InstallationID, resolver, journal, storeTrustedClock{store: admission.Store})
	if err != nil {
		return TrustedCapabilityExecutionPermit{}, err
	}
	if err := gate.Admit(ctx, bundle.Request); err != nil {
		return TrustedCapabilityExecutionPermit{}, err
	}
	if len(journal.resolutionToken) != sha256.Size {
		return TrustedCapabilityExecutionPermit{}, errors.New("execution start did not return a resolution capability")
	}
	evidence := sha256.Sum256(append([]byte("tos.openfox-capability-admission-evidence.v1\x00"), raw...))
	return TrustedCapabilityExecutionPermit{ExecutionID: plan.ExecutionID, ArtifactDigest: sealed.ArtifactDigest,
		Instructions: sealed.Instructions, Evidence: []string{"sha256:" + hex.EncodeToString(evidence[:])},
		RevocationPolicy: snapshot.InFlightRevocationPolicy,
		resolutionToken:  append([]byte(nil), journal.resolutionToken...),
		startRequest: capabilitycontrol.StartRequest{Binding: bundle.Request.Binding, LeaseObject: bundle.Request.LeaseObject,
			LeaseEnvelope: bundle.Request.LeaseEnvelope, PermissionSubsetObject: bundle.Request.PermissionSubsetObject, Remote: bundle.Request.Remote,
			Observed: capabilitycontrol.ObservedUseContext{LoadedObjectDigest: bundle.Request.Observed.LoadedObjectDigest,
				InstallationRevision: bundle.Request.Observed.InstallationRevision, RuntimeAndSandboxDigest: bundle.Request.Observed.RuntimeAndSandboxDigest,
				EffectiveEnvironmentDigest: bundle.Request.Observed.EffectiveEnvironmentDigest, CredentialCapabilityReferenceSetDigest: bundle.Request.Observed.CredentialCapabilityReferenceSetDigest,
				FilesystemHandleSetDigest: bundle.Request.Observed.FilesystemHandleSetDigest, NetworkBrokerPolicyDigest: bundle.Request.Observed.NetworkBrokerPolicyDigest,
				RemoteSessionHandshakeDigest: bundle.Request.Observed.RemoteSessionHandshakeDigest}}}, nil
}

func (admission ProductionTrustedCapabilityAdmission) RevalidateTrustedCapabilityExecution(_ context.Context, permit TrustedCapabilityExecutionPermit) error {
	if admission.Store == nil || !isDigestText(permit.ExecutionID) || len(permit.ArtifactDigest) != sha256.Size {
		return errors.New("trusted capability permit is invalid")
	}
	if !bytes.Equal(permit.startRequest.Binding.ArtifactVersionDigest, permit.ArtifactDigest) {
		return errors.New("trusted capability permit is cross-artifact")
	}
	return admission.Store.RevalidateUse(permit.startRequest)
}

func (admission ProductionTrustedCapabilityAdmission) ResolveTrustedCapabilityExecution(_ context.Context, permit TrustedCapabilityExecutionPermit, disposition string) error {
	executionID, err := parseDigestText(permit.ExecutionID)
	if err != nil {
		return err
	}
	return admission.Store.ResolveUse(executionID, permit.resolutionToken, disposition)
}

type fixedCapabilityHeads struct {
	heads    capabilitygate.AuthorityHeads
	artifact []byte
}

func (resolver fixedCapabilityHeads) ResolveCapabilityHeads(_ context.Context, owner, agent, artifact []byte) (capabilitygate.AuthorityHeads, error) {
	if !bytes.Equal(owner, resolver.heads.OwnerID) || !bytes.Equal(agent, resolver.heads.AgentID) || !bytes.Equal(artifact, resolver.artifact) {
		return capabilitygate.AuthorityHeads{}, errors.New("capability head query is cross-scope")
	}
	return resolver.heads, nil
}

type storeCapabilityStartJournal struct {
	store           *capabilitycontrol.Store
	request         capabilitygate.Request
	resolutionToken []byte
}

func (journal *storeCapabilityStartJournal) LinearizeCapabilityStart(_ context.Context, _ []byte, _ capabilitygate.AuthorityHeads, executionID, actionID, exactRequestDigest []byte, _ capabilitygate.TrustedTimeObservation) error {
	if !bytes.Equal(executionID, journal.request.Binding.ExecutionID) || !bytes.Equal(actionID, journal.request.Binding.ActionID) {
		return errors.New("capability start journal identity mismatch")
	}
	want, err := trusted.NewObject(trusted.DomainKind(journal.request.LeaseObject.DomainKind), journal.request.LeaseObject.DomainID, "capability-use-binding", journal.request.Binding)
	if err != nil {
		return err
	}
	wantDigest, err := trusted.ObjectDigest(want)
	if err != nil || !bytes.Equal(wantDigest, exactRequestDigest) {
		return errors.New("capability start journal exact request mismatch")
	}
	token, err := journal.store.PrepareUse(capabilitycontrol.StartRequest{Binding: journal.request.Binding, LeaseObject: journal.request.LeaseObject,
		LeaseEnvelope: journal.request.LeaseEnvelope, PermissionSubsetObject: journal.request.PermissionSubsetObject, Remote: journal.request.Remote,
		Observed: capabilitycontrol.ObservedUseContext{LoadedObjectDigest: journal.request.Observed.LoadedObjectDigest,
			InstallationRevision: journal.request.Observed.InstallationRevision, RuntimeAndSandboxDigest: journal.request.Observed.RuntimeAndSandboxDigest,
			EffectiveEnvironmentDigest:             journal.request.Observed.EffectiveEnvironmentDigest,
			CredentialCapabilityReferenceSetDigest: journal.request.Observed.CredentialCapabilityReferenceSetDigest,
			FilesystemHandleSetDigest:              journal.request.Observed.FilesystemHandleSetDigest, NetworkBrokerPolicyDigest: journal.request.Observed.NetworkBrokerPolicyDigest,
			RemoteSessionHandshakeDigest: journal.request.Observed.RemoteSessionHandshakeDigest}})
	if err == nil {
		journal.resolutionToken = append([]byte(nil), token...)
	}
	return err
}

type storeTrustedClock struct {
	store *capabilitycontrol.Store
}

func (clock storeTrustedClock) ObserveTrustedTime(ctx context.Context) (capabilitygate.TrustedTimeObservation, error) {
	if clock.store == nil {
		return capabilitygate.TrustedTimeObservation{}, errors.New("external trusted time is unavailable")
	}
	observation, err := clock.store.ObserveTrustedTime(ctx)
	if err != nil {
		return capabilitygate.TrustedTimeObservation{}, err
	}
	return capabilitygate.TrustedTimeObservation{UnixSeconds: observation.UnixSeconds, Epoch: observation.Epoch, EvidenceDigest: observation.EvidenceDigest}, nil
}

func observedPlanResources(plan commercegate.Plan, loaded []byte, installationRevision uint64, remoteHandshake *[]byte) (capabilitygate.ObservedUseContext, error) {
	digest := func(domain string, value any) ([]byte, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(append([]byte(domain+"\x00"), raw...))
		return sum[:], nil
	}
	runtime, err := parseDigestText(plan.CanonicalPlanDigest)
	if err != nil {
		return capabilitygate.ObservedUseContext{}, err
	}
	environment, _ := digest("tos.empty-capability-environment.v1", []string{})
	credentials, err := digest("tos.plan-credential-handles.v1", plan.CredentialBindings)
	if err != nil {
		return capabilitygate.ObservedUseContext{}, err
	}
	files, err := digest("tos.plan-filesystem-handles.v1", plan.Files)
	if err != nil {
		return capabilitygate.ObservedUseContext{}, err
	}
	network, err := digest("tos.plan-network-broker.v1", plan.NetworkBindings)
	if err != nil {
		return capabilitygate.ObservedUseContext{}, err
	}
	return capabilitygate.ObservedUseContext{LoadedObjectDigest: loaded, InstallationRevision: installationRevision,
		RuntimeAndSandboxDigest: runtime, EffectiveEnvironmentDigest: environment, CredentialCapabilityReferenceSetDigest: credentials,
		FilesystemHandleSetDigest: files, NetworkBrokerPolicyDigest: network, RemoteSessionHandshakeDigest: remoteHandshake}, nil
}

func isDigestText(value string) bool { _, err := parseDigestText(value); return err == nil }

func parseDigestText(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return nil, errors.New("digest is not canonical sha256 text")
	}
	value = strings.TrimPrefix(value, "sha256:")
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return nil, errors.New("digest is not canonical sha256 text")
	}
	return raw, nil
}
