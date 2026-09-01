package earning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/config"
	"github.com/tosnetwork/openfox/pkg/providers"
	"github.com/tosnetwork/tos-ai/pkg/commercegate"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type threeRolePilotSpec struct {
	Name, ConfigDirectory, Target, Amount, MaximumCost, Task string
}

type threeRolePilotResult struct {
	Role                       string   `json:"role"`
	AgentID                    string   `json:"agent_id"`
	AIModel                    string   `json:"ai_model"`
	AgreementDigest            string   `json:"agreement_digest"`
	ExecutionID                string   `json:"execution_id"`
	DeliverableDigest          string   `json:"deliverable_digest"`
	GrossRevenueNanoTOS        string   `json:"gross_revenue_nanotos"`
	MaximumInternalCostNanoTOS string   `json:"maximum_internal_cost_nanotos"`
	ProjectedNetNanoTOS        string   `json:"projected_net_nanotos"`
	PaymentTransaction         string   `json:"payment_transaction"`
	FinalityReference          string   `json:"finality_reference"`
	FinalEngagementState       string   `json:"final_engagement_state"`
	ExecutionElapsedMillis     int64    `json:"execution_elapsed_millis"`
	SettlementElapsedMillis    int64    `json:"settlement_elapsed_millis"`
	CarrierIDs                 []string `json:"carrier_ids"`
}

type threeRolePilotReport struct {
	Schema      string                 `json:"schema"`
	Network     string                 `json:"network"`
	CompletedAt string                 `json:"completed_at"`
	Results     []threeRolePilotResult `json:"results"`
}

// TestThreeOpenFoxRoleEarningPilot exercises three actual subscription-backed
// OpenFox providers through canonical Agreement authorization, portfolio
// reservation, the local one-shot Execution Gate, bounded LLM execution,
// delivery, billing, an Agreement-bound TOS Agent Account payment, independent
// three-node finality resolution, and provider-side accounting reconciliation.
// It is opt-in because it consumes personal subscription quota and local-chain
// test funds.
func TestThreeOpenFoxRoleEarningPilot(t *testing.T) {
	if os.Getenv("OPENFOX_THREE_ROLE_EARNING_PILOT") != "1" {
		t.Skip("set OPENFOX_THREE_ROLE_EARNING_PILOT=1 for the live pilot")
	}
	root := mustEnv(t, "OPENFOX_THREE_ROLE_PILOT_ROOT")
	outputDirectory := filepath.Join(root, "reports", time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	specs := []threeRolePilotSpec{
		{Name: "security-auditor", ConfigDirectory: filepath.Join(root, "agents/security-auditor"),
			Target: "0:e4de18a15c4a008f582bdf1bc3ca572539644cee2932c8548f6819add2a14f4e",
			Amount: "500000", MaximumCost: "80000",
			Task: "Review this bounded Go snippet and return a concise severity-ranked security report: func copyToken(dst []byte, token string) { copy(dst, token) }. Cover truncation, secret lifetime, validation, and a safer API."},
		{Name: "software-builder", ConfigDirectory: filepath.Join(root, "agents/software-builder"),
			Target: "0:5a4a3b85ecae084b971b9d71deb5632bf8e1ff279d62bc1c05f573183a945116",
			Amount: "750000", MaximumCost: "150000",
			Task: "Deliver a self-contained Go implementation and table-driven tests for NormalizeTag: trim surrounding ASCII whitespace, lowercase ASCII letters, allow only a-z 0-9 dash, reject empty or more than 32 bytes. Return code and short rationale as text."},
		{Name: "evidence-verifier", ConfigDirectory: filepath.Join(root, "agents/evidence-verifier"),
			Target: "0:e48ef3dd5917c736eec8d57d8e9c8bed4be490bcdee6202fff39f2577a3958bc",
			Amount: "200000", MaximumCost: "30000",
			Task: "Verify this release claim and return PASS or FAIL with missing evidence: source commit is pinned; Linux tests passed; Windows compile passed; artifact digest is absent; signer identity is pinned; no reproducible build command is recorded."},
	}

	payerKey := lifecycleKey("openfox-three-role-pilot-payer-authority")
	payerDirectory := privateTempDir(t)
	payerAuthority, err := OpenPersonalAuthority(payerDirectory, "owner:pilot-buyer", "agent:pilot-buyer",
		"authority:pilot-buyer", payerKey, PortfolioLimits{SpendAtomic: 1_000_000_000, MaximumLossAtomic: 1_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	defer payerAuthority.Close()
	payerFence, err := payerAuthority.AcquireWriter(t.Context(), "writer:pilot-buyer", []string{"payment.direct"}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tosctl := mustEnv(t, "OPENFOX_TOSCTL")
	primary := mustEnv(t, "OPENFOX_TOSCTL_PRIMARY_CONFIG")
	quorum2 := mustEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_2")
	quorum3 := mustEnv(t, "OPENFOX_TOSCTL_QUORUM_CONFIG_3")
	vaultURL := mustEnv(t, "OPENFOX_TOS_VAULT_URL")
	custodyDirectory := filepath.Join(outputDirectory, "payer-custody")
	if err := os.MkdirAll(custodyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	bindPilotPayer(t, tosctl, primary, vaultURL, payerKey, custodyDirectory)
	paymentSink := &TOSCTLPaymentSink{Authority: payerAuthority, Executable: tosctl, ConfigPath: primary,
		Wallet: "payer-agent", SourceAccount: threeNodeBuyerAccount, NetworkGlobalID: 3, FeeReserveNanoTOS: 50_000_000,
		RelayNetworkDomain: liveTOSCustodyNetworkDomain(t, "tos:local-three-node", 3),
		QuorumConfigPaths:  []string{quorum2, quorum3}, MaximumTransactions: 1000, VaultURL: vaultURL,
		EvidenceDirectory: filepath.Join(outputDirectory, "payment-authorizations"), ResolveAttempts: 60, ResolveInterval: time.Second}

	results := make([]threeRolePilotResult, 0, len(specs))
	for _, spec := range specs {
		if !pilotRoleSelected(spec.Name, os.Getenv("OPENFOX_THREE_ROLE_PILOT_ROLES")) {
			continue
		}
		results = append(results, runThreeRoleSeller(t, spec, outputDirectory, payerAuthority, payerFence, paymentSink))
	}
	report := threeRolePilotReport{Schema: "tos.openfox.three-role-earning-pilot.v1", Network: "tos:local-three-node",
		CompletedAt: time.Now().UTC().Format(time.RFC3339), Results: results}
	path := filepath.Join(outputDirectory, "financial-report.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(report); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("three-role-pilot report=%s", path)
}

func runThreeRoleSeller(t *testing.T, spec threeRolePilotSpec, outputDirectory string, payerAuthority *PersonalAuthority,
	payerFence commerce.WriterFence, paymentSink *TOSCTLPaymentSink) threeRolePilotResult {
	t.Helper()
	cfg, err := config.LoadConfig(filepath.Join(spec.ConfigDirectory, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	provider, model, err := providers.CreateProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if closeable, ok := provider.(providers.StatefulProvider); ok {
		defer closeable.Close()
	}
	state := cfg.Earning.StateDir
	authorityKey := readPilotPrivateKey(t, filepath.Join(state, "authority/authority-ed25519.key"))
	identityKey := readPilotPrivateKey(t, filepath.Join(state, "identity/agent-ed25519.key"))
	authority, err := OpenPersonalAuthority(filepath.Join(state, "authority"), cfg.Earning.OwnerID, cfg.Earning.AgentID,
		cfg.Earning.AuthorityID, authorityKey, PortfolioLimits{ComputeUnits: cfg.Earning.Resources.CPUUnits,
			ReceivableAtomic: 1_000_000_000, MaximumLossAtomic: 1_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	now := time.Now().UTC().Truncate(time.Second)
	buyerKey := lifecycleKey("three-role-buyer:" + spec.Name)
	body := pilotAgreement(t, cfg.Earning.AgentID, spec, now)
	digest, _ := commerce.AgreementBodyDigest(body)
	if _, err = authority.RecordAgreementProposal(body, "agent:pilot-buyer", "evt_"+strings.TrimPrefix(threeNodeDigest("proposal:"+digest), "sha256:"),
		threeNodeDigest("envelope:"+digest)); err != nil {
		t.Fatal(err)
	}
	resolver := agreementKeyResolver{cfg.Earning.AgentID: identityKey.Public().(ed25519.PublicKey),
		"agent:pilot-buyer": buyerKey.Public().(ed25519.PublicKey)}
	verifier := AgreementEvidenceRouter{AgentAuthority: resolver}
	keys := map[string]ed25519.PrivateKey{"agent:pilot-buyer": buyerKey, cfg.Earning.AgentID: identityKey}
	for _, predicate := range body.AuthorizationPredicates {
		acceptance, signErr := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
			AgreementVersion: body.Version, AgreementBodyDigest: digest, AcceptingSubject: predicate.AuthoritySubject,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: body.ExpiresAtUnix}, keys[predicate.AuthoritySubject.SubjectIdentifier])
		if signErr != nil {
			t.Fatal(signErr)
		}
		evidence, evidenceErr := commerce.AgentSignatureEvidence(body, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		if _, evidenceErr = authority.RecordAgreementEvidence(digest, evidence, verifier); evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
	}
	scopes := []string{"billing.materialize", "billing.resolve", "delivery.release", "execution.prepare", "execution.start", "portfolio.reserve"}
	fence, err := authority.AcquireWriter(t.Context(), "writer:"+spec.Name, scopes, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID, MandateDigest: cfg.Earning.MandateDigest,
		Gates: FeatureGates{Execution: true}, Authority: authority}
	amount := parsePilotUint64(t, spec.Amount)
	reservation := ExposureReservation{ReservationID: threeNodeDigest("reservation:" + digest), AgreementDigest: digest,
		ComputeUnits: 1, ReceivableAtomic: amount, MaximumLossAtomic: parsePilotUint64(t, spec.MaximumCost)}
	_, record, err := engine.ReserveAgreement(t.Context(), digest, reservation, allowSettlement{}, 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	gateDirectory := filepath.Join(outputDirectory, spec.Name+"-execution-gate")
	if err := os.MkdirAll(gateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	gate, err := commercegate.Open(gateDirectory, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	acceptedInputDigest, _, _, err := AcceptedExecutionInputSetDigest(record, "work")
	if err != nil {
		t.Fatal(err)
	}
	plan := commercegate.Plan{OwnerID: cfg.Earning.OwnerID, AgentID: cfg.Earning.AgentID, AgreementBodyDigest: digest,
		ExecutionObligationID: "work", AcceptedInputManifestDigest: acceptedInputDigest, AttemptIndex: 0,
		PredecessorTerminalResolutionDigest: "sha256:" + strings.Repeat("0", 64), ReservationID: reservation.ReservationID,
		PolicyRevision: 1, LeaseLossPolicy: commercegate.LeaseLossKill}
	deliverableDirectory := filepath.Join(outputDirectory, spec.Name+"-deliverables")
	started := time.Now()
	record, err = (ExecutionService{Engine: engine, Gate: gate, Prerequisite: funded{}, Capability: trustedCapabilityForTest{},
		Runner: LLMTaskRunner{Provider: provider, Model: model, Agreement: body, OutputDirectory: deliverableDirectory}}).
		Execute(context.Background(), digest, plan, 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	executionElapsed := time.Since(started)
	manifest := record.ObligationRuntime["work"].ExecutionEvidence[0]
	record, err = engine.Deliver(t.Context(), digest, "work", "agent:pilot-buyer", manifest, acceptedDelivery{}, 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	ledgers, record, err := (BillingService{Engine: engine}).MaterializeAfterDelivery(digest, 1, fence)
	if err != nil || len(ledgers) != 1 {
		t.Fatalf("billing ledgers=%d state=%s err=%v", len(ledgers), record.State, err)
	}
	seedDirectPaymentCustodyStateForTest(t, payerAuthority, body, ledgers[0].Obligation)
	request, err := commerce.BuildAgreementPaymentRequest("owner:pilot-buyer", "agent:pilot-buyer", "tos:local-three-node",
		[]byte(spec.Target), ledgers[0].Obligation)
	if err != nil {
		t.Fatal(err)
	}
	canonical, fields, err := commerce.PaymentAuthorizationMaterial(request)
	if err != nil {
		t.Fatal(err)
	}
	action, err := commerce.BuildAuthorizedAction("owner:pilot-buyer", "agent:pilot-buyer", "payment.direct", fields, canonical,
		payerFence, 1, ledgers[0].Obligation.MandateDigest, "", "pending", request.ExpiresAtUnix)
	if err == nil {
		action, err = payerAuthority.SignAction(action, payerFence)
	}
	if err != nil || action.StableActionID != request.StableActionID {
		t.Fatalf("payment action identity: action=%s request=%s err=%v", action.StableActionID, request.StableActionID, err)
	}
	if resolution, admitErr := payerAuthority.Admit(action, fields, canonical, payerFence, nil); admitErr != nil ||
		resolution.State != commerce.ActionPrepared {
		t.Fatalf("payment admission=%+v err=%v", resolution, admitErr)
	}
	settlementStarted := time.Now()
	paymentEvidence, err := paymentSink.SubmitPayment(t.Context(), action, payerFence, fields, canonical, request)
	if err != nil {
		t.Fatal(err)
	}
	settlementElapsed := time.Since(settlementStarted)
	if _, err = payerAuthority.Transition(action.StableActionID, action.ExactRequestDigest, commerce.ActionAccepted,
		paymentEvidence.ExactTransferReference, []string{paymentEvidence.FinalityReference}); err != nil {
		t.Fatal(err)
	}
	_, record, err = (BillingService{Engine: engine}).ApplyPayment(request, paymentEvidence, paymentSink, 1, fence)
	if err != nil || record.State != EngagementSettled {
		t.Fatalf("provider payment reconciliation state=%s err=%v", record.State, err)
	}
	return threeRolePilotResult{Role: spec.Name, AgentID: cfg.Earning.AgentID, AIModel: model, AgreementDigest: digest,
		ExecutionID: record.ExecutionID, DeliverableDigest: manifest, GrossRevenueNanoTOS: spec.Amount,
		MaximumInternalCostNanoTOS: spec.MaximumCost,
		ProjectedNetNanoTOS:        fmt.Sprintf("%d", amount-parsePilotUint64(t, spec.MaximumCost)),
		PaymentTransaction:         paymentEvidence.ExactTransferReference, FinalityReference: paymentEvidence.FinalityReference,
		FinalEngagementState: string(record.State), ExecutionElapsedMillis: executionElapsed.Milliseconds(),
		SettlementElapsedMillis: settlementElapsed.Milliseconds(),
		CarrierIDs:              []string{"carrier:gateway-local-pilot", "carrier:messenger-local-pilot"}}
}

func pilotAgreement(t *testing.T, providerID string, spec threeRolePilotSpec, now time.Time) commerce.AgentAgreementBody {
	return pilotAgreementForBuyer(t, "agent:pilot-buyer", providerID, spec, now)
}

func pilotAgreementForBuyer(t *testing.T, buyerID, providerID string, spec threeRolePilotSpec,
	now time.Time) commerce.AgentAgreementBody {
	t.Helper()
	profile := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1,
		AgreementID: "agreement:" + strings.TrimPrefix(threeNodeDigest(spec.Name+now.String()), "sha256:"), Version: 1,
		NetworkContext: "tos:local-three-node", Participants: []commerce.AgreementParticipant{
			{AgentID: buyerID, Roles: []string{"buyer"}}, {AgentID: providerID, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte(spec.Task), ValidFromUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix()), Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: buyerID, BeneficiaryAgentID: providerID,
				DependsOnObligationIDs: []string{"work"}, SubjectContentType: "text/plain", Subject: []byte("pay after verified delivery"),
				Amount:    &commerce.AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: spec.Amount, Unit: "nanotos"},
				DueAtUnix: uint64(now.Add(30 * time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(45 * time.Minute).Unix()),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-due", DisputePolicy: "evidence",
				SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte(spec.Target),
				AuthorizationPredicateIDs: []string{"buyer-payment"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: providerID, BeneficiaryAgentID: buyerID,
				SubjectContentType: "text/plain", Subject: []byte(spec.Task), ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-start", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"provider-work"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "buyer-payment", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent",
				SubjectNamespace: "tos.agent", SubjectIdentifier: buyerID}, ObligationIDs: []string{"pay"},
				EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
				EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix())},
			{PredicateID: "provider-work", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent",
				SubjectNamespace: "tos.agent", SubjectIdentifier: providerID}, ObligationIDs: []string{"work"},
				EvidenceProfileURI: commerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
				EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(50 * time.Minute).Unix())}}}
	sort.Slice(body.Participants, func(i, j int) bool { return body.Participants[i].AgentID < body.Participants[j].AgentID })
	body, err := commerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func pilotRoleSelected(role, configured string) bool {
	if configured == "" {
		return true
	}
	for _, candidate := range strings.Split(configured, ",") {
		if strings.TrimSpace(candidate) == role {
			return true
		}
	}
	return false
}

func bindPilotPayer(t *testing.T, tosctl, configPath, vaultURL string, key ed25519.PrivateKey, journal string) {
	t.Helper()
	command := exec.Command(tosctl, "agent", "wallet", "bind-runtime", "--name", "payer-agent",
		"--runner-id", "openfox-three-role-pilot", "--endpoint", "local://openfox/three-role-pilot",
		"--economic-authority-id", "authority:pilot-buyer", "--economic-authority-public-key",
		hex.EncodeToString(key.Public().(ed25519.PublicKey)), "--economic-custody-journal-directory", journal,
		"-c", configPath, "--format", "json")
	command.Env = append(os.Environ(), "VAULT_URL="+vaultURL)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bind pilot payer runtime: %v: %s", err, output)
	}
}

func readPilotPrivateKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() != ed25519.PrivateKeySize {
		t.Fatalf("invalid pilot private key: %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PrivateKey(raw)
}

func parsePilotUint64(t *testing.T, value string) uint64 {
	t.Helper()
	var result uint64
	for _, character := range value {
		if character < '0' || character > '9' || result > (^uint64(0)-uint64(character-'0'))/10 {
			t.Fatalf("invalid pilot amount %q", value)
		}
		result = result*10 + uint64(character-'0')
	}
	return result
}

func pilotDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
