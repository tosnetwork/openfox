package servicebridge

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var offerSendLabels = []string{"agent service deploy", "wallet send", "agent service send update-policy"}

func TestOfferPublishesAnOfferThePreflightChecksAccept(t *testing.T) {
	f := newSetupFixture(t)
	initResult := f.mustInit(t)
	result := f.mustOffer(t)
	world := f.world()
	if world.count("agent service deploy") != 1 || world.count("wallet send") != 2 ||
		world.count("agent service send update-policy") != 1 ||
		world.count("agent native-registry new-controller") != 2 {
		t.Fatalf("calls = %+v", world.Calls)
	}
	preview := result.Preview
	if world.Actor == nil || world.Actor.Address != preview.Actor || world.Actor.Metadata != preview.MetadataHash ||
		world.Actor.Terms != f.offer.Terms {
		t.Fatalf("the actor is not as previewed: %+v vs %+v", world.Actor, preview)
	}
	capability, registered := world.Capabilities[preview.CapabilityID]
	if !registered || capability.Owner != initResult.AgentID || capability.Digest != preview.ManifestDigest {
		t.Fatalf("the Capability is not as previewed: %+v", world.Capabilities)
	}
	if preview.TotalAttachedNano != "3210000000" || preview.BuyerAttachesNano != "750000000" ||
		preview.DeployFundingNano != "1200000000" || preview.OwnerWallet != fakeWalletAddress {
		t.Fatalf("preview amounts = %+v", preview)
	}
	// Exactly the previewed values were handed to tosctl.
	deploy := world.last("agent service deploy")
	for flag, want := range map[string]string{
		"--price-per-call": "0.300000000", "--storage-fee": "0.250000000", "--cleanup-bounty": "0.100000000",
		"--response-sla": "3600", "--refund-claim-window": "7200", "--amount": "1.200000000",
		"--metadata-hash": zeroHash64, "--attestor-controller": DefaultAttestorController, "--owner": fakeWalletAddress,
	} {
		if got := fakeArgument(deploy.Args, flag); got != want {
			t.Fatalf("deploy %s = %q, want %q", flag, got, want)
		}
	}
	policy := world.last("agent service send update-policy")
	if fakeArgument(policy.Args, "--metadata-hash") != preview.MetadataHash ||
		fakeArgument(policy.Args, "--proof-scheme-hash") != preview.ProofSchemeHash ||
		fakeArgument(policy.Args, "--active") != "true" || fakeArgument(policy.Args, "--address") != preview.Actor {
		t.Fatalf("update-policy = %v", policy.Args)
	}
	for _, id := range offerChecks {
		passed := false
		for _, check := range result.Verification {
			passed = passed || (check.ID == id && check.Status == CheckPass)
		}
		if !passed {
			t.Fatalf("preflight check %s did not pass: %+v", id, result.Verification)
		}
	}
	config, err := LoadNodeConfig(f.offer.RailConfigPath)
	if err != nil || config.Provider == nil {
		t.Fatalf("provider section: %v", err)
	}
	if config.Provider.CapabilityID != preview.CapabilityID ||
		config.Provider.ExecutorSHA256 != result.ExecutorSHA256 ||
		config.Provider.AttestorController != DefaultAttestorController ||
		config.Provider.RespondBudgetSecond != 120 {
		t.Fatalf("provider = %+v", config.Provider)
	}
	offer, err := ReadOfferFile(result.OfferFile)
	if err != nil {
		t.Fatalf("the offer file does not decode: %v", err)
	}
	if offer.CapabilityID != preview.CapabilityID || offer.ManifestDigest != preview.ManifestDigest ||
		offer.ProviderAgentID != initResult.AgentID {
		t.Fatalf("offer = %+v", offer)
	}
	raw, _ := os.ReadFile(result.OfferFile)
	if strings.Contains(string(raw), "vault") || strings.Contains(string(raw), "token") {
		t.Fatal("the offer file holds custody details")
	}
	// A second run sends nothing.
	sends := world.sends()
	f.mustOffer(t)
	if after := f.world(); after.sends() != sends || after.count("agent native-registry new-controller") != 2 {
		t.Fatalf("a re-run was not idempotent: %+v", after.Calls[len(world.Calls):])
	}
}

func TestOfferRefusesEveryOutOfBoundTermBeforeAnyTOSCTLCall(t *testing.T) {
	cases := map[string]func(*OfferInput){
		"zero price":       func(in *OfferInput) { in.Terms.PriceNano = 0 },
		"bounty below 0.1": func(in *OfferInput) { in.Terms.CleanupBountyNano = MinCleanupBountyNano - 1 },
		"bounty above 1": func(in *OfferInput) {
			in.Terms.CleanupBountyNano, in.Terms.StorageFeeNano = MaxCleanupBountyNano+1, 5*NanoPerTOS
		},
		"storage below floor":     func(in *OfferInput) { in.Terms.StorageFeeNano = MinStorageFeeBaseNano + in.Terms.CleanupBountyNano - 1 },
		"sla below an hour":       func(in *OfferInput) { in.Terms.ResponseSLA = MinPolicyWindowSecs - 1 },
		"sla above 30 days":       func(in *OfferInput) { in.Terms.ResponseSLA = MaxPolicyWindowSecs + 1 },
		"window below an hour":    func(in *OfferInput) { in.Terms.RefundClaimWindow = MinPolicyWindowSecs - 1 },
		"window above 30 days":    func(in *OfferInput) { in.Terms.RefundClaimWindow = MaxPolicyWindowSecs + 1 },
		"price beyond exact":      func(in *OfferInput) { in.Terms.PriceNano = MaxTOSCTLAmountNano + 1 },
		"funding below minimum":   func(in *OfferInput) { in.DeployFundingNano = MinimumDeployFundingNano - 1 },
		"version with a space":    func(in *OfferInput) { in.Version = "1.0 beta" },
		"version that is a flag":  func(in *OfferInput) { in.Version = "--yes" },
		"relative executor":       func(in *OfferInput) { in.ExecutorBinary = "executor" },
		"bad attestor name":       func(in *OfferInput) { in.AttestorController = "a/b" },
		"non-positive respond":    func(in *OfferInput) { in.RespondBudgetSeconds = -1 },
		"relative containerd":     func(in *OfferInput) { in.ContainerdSocket = "containerd.sock" },
		"malformed executor pin":  func(in *OfferInput) { in.ExecutorSHA256 = "abc" },
		"executor is another one": func(in *OfferInput) { in.ExecutorSHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			f.mustInit(t)
			calls := len(f.world().Calls)
			mutate(&f.offer)
			if _, err := RunOffer(context.Background(), f.offer, f.env()); err == nil {
				t.Fatal("accepted")
			}
			if len(f.world().Calls) != calls {
				t.Fatalf("tosctl was run for an offer out of bounds: %+v", f.world().Calls[calls:])
			}
		})
	}
	// The bounds themselves are accepted.
	f := newSetupFixture(t)
	f.mustInit(t)
	f.offer.Terms = ActorTerms{
		PriceNano:         1,
		StorageFeeNano:    MinStorageFeeBaseNano + MaxCleanupBountyNano,
		CleanupBountyNano: MaxCleanupBountyNano,
		ResponseSLA:       MaxPolicyWindowSecs,
		RefundClaimWindow: MinPolicyWindowSecs,
	}
	f.mustOffer(t)
}

func TestOfferWithoutYesShowsTheWholePreviewAndSendsNothing(t *testing.T) {
	f := newSetupFixture(t)
	f.mustInit(t)
	f.offer.Yes = false
	before := f.world()
	// The attestor does not exist: it is not created without --yes.
	result, err := RunOffer(context.Background(), f.offer, f.env())
	mustFail(t, err, ErrConfirmationRequired)
	if world := f.world(); world.count(
		"agent native-registry new-controller",
	) != before.count(
		"agent native-registry new-controller",
	) ||
		world.sends() != before.sends() ||
		result.Confirmed {
		t.Fatalf("something ran without --yes: %+v", world.Calls[len(before.Calls):])
	}
	// The run with --yes creates the key and sends in one go, so this run
	// already shows everything the owner decides or pays: the terms, every
	// attached value, the totals and what will be created. Only what
	// derives from the key is left open, and is said to be.
	early := result.Preview
	if early == nil || early.Terms != f.offer.Terms || early.DeployFundingNano != "1200000000" ||
		early.RegistryValueNano != "2000000000" || early.PolicyValueNano != "10000000" ||
		early.TotalAttachedNano != "3210000000" || early.BuyerAttachesNano != "750000000" ||
		early.OwnerWallet != fakeWalletAddress || early.AttestorController != DefaultAttestorController ||
		len(early.ToBeCreated) == 0 || !strings.Contains(early.ToBeCreated[0], DefaultAttestorController) ||
		early.Actor != "" || early.AttestorKeyID != "" || early.CapabilityID != "" {
		t.Fatalf("the preview before the attestor key exists is incomplete: %+v", early)
	}
	shown := strings.Join(*f.reports, "\n")
	for _, line := range []string{
		"to be created: attestor controller", "price 0.300000000 TOS", "funded with 1.200000000 TOS",
		"total attached 3.210000000 TOS", "a buyer attaches 0.750000000 TOS", "derived once the attestor key exists",
	} {
		if !strings.Contains(shown, line) {
			t.Fatalf("the preview before the attestor key exists does not print %q:\n%s", line, shown)
		}
	}
	for _, line := range *f.reports {
		if strings.HasPrefix(line, "executor.pin:") &&
			(strings.Contains(line, "--tosctl-sha256") || !strings.Contains(line, "--executor-sha256")) {
			t.Fatalf("the executor pin note names the wrong flag: %s", line)
		}
	}
	f.change(func(w *fakeWorld) { w.Controllers[DefaultAttestorController] = true })
	result, err = RunOffer(context.Background(), f.offer, f.env())
	mustFail(t, err, ErrConfirmationRequired)
	world := f.world()
	if world.sends() != before.sends() || world.count("agent native-registry action") != 0 || world.Actor != nil {
		t.Fatalf("signed or sent without --yes: %+v", world.Calls[len(before.Calls):])
	}
	preview := result.Preview
	if preview == nil || !rawAddressPattern.MatchString(preview.Actor) ||
		!capabilityPattern.MatchString(preview.CapabilityID) ||
		!hex64Pattern.MatchString(preview.MetadataHash) ||
		preview.AttestorKeyID != fakeKey(DefaultAttestorController).Text() ||
		preview.TotalAttachedNano == "" ||
		preview.Terms != f.offer.Terms {
		t.Fatalf("the preview is incomplete: %+v", preview)
	}
	if config, _ := LoadNodeConfig(f.offer.RailConfigPath); config.Provider != nil {
		t.Fatal("a provider section was written for an unpublished offer")
	}
	// The run with --yes publishes exactly what was previewed.
	f.offer.Yes = true
	published := f.mustOffer(t)
	if !reflect.DeepEqual(published.Preview, preview) || len(preview.ToBeCreated) != 0 {
		t.Fatalf("published %+v, previewed %+v", published.Preview, preview)
	}
}

// Every chain step of offer, crossed with every way its send can end. The
// kill cases run the command in a process that is really killed.
func TestOfferNeverResendsAStepWhoseOutcomeIsUnknown(t *testing.T) {
	stepOf := func(journal *SetupJournal, index int) ChainStep {
		return []ChainStep{journal.Offer.Deploy, journal.Offer.Capability, journal.Offer.Policy}[index]
	}
	for index, label := range offerSendLabels {
		prepare := func(t *testing.T) (*setupFixture, int) {
			f := newSetupFixture(t)
			f.mustInit(t)
			return f, f.world().count(label)
		}
		t.Run(label+"/killed after the message landed", func(t *testing.T) {
			f, base := prepare(t)
			f.script(label, fakeKillAfter)
			f.runKilled(t, "offer", f.offer)
			if step := stepOf(f.journal(t), index); step.State != stepSending || step.Attempts != 1 {
				t.Fatalf("the journal does not say a message may be in flight: %+v", step)
			}
			f.mustOffer(t)
			if got := f.world().count(label) - base; got != 1 {
				t.Fatalf("%s was sent %d times", label, got)
			}
		})
		t.Run(label+"/killed before the message had any effect", func(t *testing.T) {
			f, base := prepare(t)
			f.script(label, fakeKillBefore)
			f.runKilled(t, "offer", f.offer)
			planned := *f.journal(t).Offer
			_, err := RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, ErrOutcomeUnknown, "nothing was re-sent")
			if got := f.world().count(label) - base; got != 1 {
				t.Fatalf("an unknown outcome was answered by sending: %d", got)
			}
			f.change(func(w *fakeWorld) { w.Clock += int64(sendResolutionWindow.Seconds()) })
			result := f.mustOffer(t)
			world := f.world()
			if got := world.count(label) - base; got != 2 {
				t.Fatalf("after the window %s was sent %d times", label, got)
			}
			// The same actor and the same Capability, exactly one of each.
			if world.Actor.Address != planned.Actor || len(world.Capabilities) != 1 ||
				result.Preview.CapabilityID != planned.CapabilityID {
				t.Fatalf("the restart published other objects: %+v %v", world.Actor, world.Capabilities)
			}
		})
		t.Run(label+"/the send fails but the message landed", func(t *testing.T) {
			f, base := prepare(t)
			f.script(label, fakeLandedError)
			f.mustOffer(t)
			if got := f.world().count(label) - base; got != 1 {
				t.Fatalf("%s was sent %d times", label, got)
			}
		})
		t.Run(label+"/the send fails and nothing lands", func(t *testing.T) {
			f, base := prepare(t)
			f.script(label, fakeLost)
			_, err := RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, ErrOutcomeUnknown)
			_, err = RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, ErrOutcomeUnknown)
			if got := f.world().count(label) - base; got != 1 {
				t.Fatalf("the unknown outcome was answered by sending again: %d", got)
			}
			if config, _ := LoadNodeConfig(f.offer.RailConfigPath); config.Provider != nil {
				t.Fatal("a provider section was written before the offer was finalized")
			}
		})
		t.Run(label+"/tosctl refuses before broadcasting", func(t *testing.T) {
			f, base := prepare(t)
			f.script(label, fakeRefuseBalance)
			_, err := RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, nil, string(TOSCTLFailureBalance))
			if step := stepOf(f.journal(t), index); step.State != stepPending {
				t.Fatalf("a refused send is recorded as in flight: %+v", step)
			}
			f.mustOffer(t)
			if got := f.world().count(label) - base; got != 2 {
				t.Fatalf("the refused send was not retried: %d", got)
			}
		})
	}
}

func TestOfferKilledWhileBuildingTheCapabilityRebuildsTheSameCapability(t *testing.T) {
	f := newSetupFixture(t)
	f.mustInit(t)
	f.script("agent native-registry action", fakeKillBefore)
	f.runKilled(t, "offer", f.offer)
	journal := f.journal(t).Offer
	first := f.world().last("agent native-registry action")
	if journal.CapabilityObjectNonce == "" ||
		fakeArgument(first.Args, "--object-nonce") != journal.CapabilityObjectNonce ||
		fakeArgument(first.Args, "--nonce") != journal.CapabilityNonce {
		t.Fatalf("the nonces handed to tosctl were not durable first: %+v", journal)
	}
	// Nothing was handed to a wallet, but the journal cannot know that the
	// process died inside the build: it waits out the window.
	_, err := RunOffer(context.Background(), f.offer, f.env())
	mustFail(t, err, ErrOutcomeUnknown)
	f.change(func(w *fakeWorld) { w.Clock += int64(sendResolutionWindow.Seconds()) })
	result := f.mustOffer(t)
	world := f.world()
	second := world.last("agent native-registry action")
	if fakeArgument(second.Args, "--object-nonce") != journal.CapabilityObjectNonce || len(world.Capabilities) != 1 ||
		result.Preview.CapabilityID != journal.CapabilityID {
		t.Fatalf("the restart did not rebuild the same Capability: %v", world.Capabilities)
	}
}

func TestOfferRefusesChangedTermsOnlyAfterAStepWasSent(t *testing.T) {
	changes := map[string]func(*OfferInput){
		"the price":               func(in *OfferInput) { in.Terms.PriceNano++ },
		"the storage fee":         func(in *OfferInput) { in.Terms.StorageFeeNano++ },
		"the cleanup bounty":      func(in *OfferInput) { in.Terms.CleanupBountyNano++ },
		"the response SLA":        func(in *OfferInput) { in.Terms.ResponseSLA++ },
		"the refund-claim window": func(in *OfferInput) { in.Terms.RefundClaimWindow++ },
		"the version":             func(in *OfferInput) { in.Version = "2.0.0" },
		"the retention":           func(in *OfferInput) { in.RetentionSeconds = 3600 },
		"the attestor controller": func(in *OfferInput) { in.AttestorController = "other-attestor" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			f.mustInit(t)
			// The deployment is sent; its outcome does not matter here.
			f.script("agent service deploy", fakeLost)
			if _, err := RunOffer(context.Background(), f.offer, f.env()); err == nil {
				t.Fatal("the scripted failure did not happen")
			}
			planned := f.journal(t).Offer.Actor
			f.change(func(w *fakeWorld) { w.Controllers["other-attestor"] = true })
			sends := f.world().sends()
			change(&f.offer)
			_, err := RunOffer(context.Background(), f.offer, f.env())
			mustFail(t, err, ErrSetupInputChanged, name, planned)
			if world := f.world(); world.sends() != sends {
				t.Fatal("a second actor was deployed for the changed terms")
			}
			if f.journal(t).Offer.Actor != planned {
				t.Fatal("the journal's plan was replaced")
			}
		})
	}
	// Before any send the plan follows the inputs.
	f := newSetupFixture(t)
	f.mustInit(t)
	f.offer.Yes = false
	f.change(func(w *fakeWorld) { w.Controllers[DefaultAttestorController] = true })
	first, _ := RunOffer(context.Background(), f.offer, f.env())
	f.offer.Terms.PriceNano++
	second, err := RunOffer(context.Background(), f.offer, f.env())
	mustFail(t, err, ErrConfirmationRequired)
	if first.Preview.Actor == second.Preview.Actor {
		t.Fatal("the unsent plan did not follow the new price")
	}
}

func TestOfferStopsWhenTOSCTLOrFinalizedStateContradictThePlan(t *testing.T) {
	t.Run("tosctl deployed another address", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.script("agent service deploy", fakeWrongTarget)
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "not the planned actor", "stopped")
		// No later run deploys again, even past the inclusion window.
		f.change(func(w *fakeWorld) { w.Clock += int64(sendResolutionWindow.Seconds()) })
		_, err = RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "stopped")
		if world := f.world(); world.count("wallet send") != 1 || world.count("agent service deploy") != 1 {
			t.Fatalf("a contradicted deployment was followed by more sends: %+v", world.Calls)
		}
	})
	t.Run("tosctl built the registration for another Capability", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.script("agent native-registry action", fakeWrongTarget)
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "nothing was sent")
		if f.world().count("wallet send") != 1 || f.journal(t).Offer.Capability.State != stepPending {
			t.Fatal("a registration for an underived address was sent or recorded as in flight")
		}
	})
	t.Run("the actor at the planned address has another attestor", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.mustOffer(t)
		f.change(func(w *fakeWorld) { w.Controllers["rogue"], w.Actor.Attestor = true, "rogue" })
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "does not hold attestor")
	})
	t.Run("the actor runs other code", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.mustOffer(t)
		f.change(func(w *fakeWorld) { w.Actor.CodeHash = "tvm-cell-sha256:" + strings.Repeat("99", 32) })
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "not the pinned actor code")
	})
	t.Run("the actor is owned by another wallet", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.mustOffer(t)
		f.change(func(w *fakeWorld) { w.Actor.Owner = "0:" + strings.Repeat("31", 32) })
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "not the owner wallet")
	})
	t.Run("the Capability commits to another manifest", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		result := f.mustOffer(t)
		f.change(func(w *fakeWorld) {
			capability := w.Capabilities[result.Preview.CapabilityID]
			capability.Digest = "sha256:" + strings.Repeat("ab", 32)
			w.Capabilities[result.Preview.CapabilityID] = capability
		})
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "commits to another manifest")
	})
	t.Run("the finalized policy is not the offer", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.mustOffer(t)
		// The price on chain drifts: the policy step is not done, and the
		// update is sent again rather than reported as published.
		f.change(func(w *fakeWorld) { w.Actor.Terms.PriceNano++ })
		before := f.world().count("agent service send update-policy")
		f.mustOffer(t)
		world := f.world()
		if world.count("agent service send update-policy") != before+1 || world.Actor.Terms != f.offer.Terms {
			t.Fatalf("a drifted policy was accepted: %+v", world.Actor.Terms)
		}
		// The same for a metadata hash that names another Capability, with
		// every other field as offered.
		published := world.Actor.Metadata
		f.change(func(w *fakeWorld) { w.Actor.Metadata = strings.Repeat("ab", 32) })
		f.mustOffer(t)
		world = f.world()
		if world.count("agent service send update-policy") != before+2 || world.Actor.Metadata != published {
			t.Fatalf("a policy bound to another Capability was accepted: %s", world.Actor.Metadata)
		}
	})
	t.Run("the wallet cannot pay", func(t *testing.T) {
		f := newSetupFixture(t)
		f.mustInit(t)
		f.change(func(w *fakeWorld) { w.WalletBalance = "3.3599" })
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, fakeWalletAddress, "3.360000000 TOS")
		if world := f.world(); world.count("agent service deploy") != 0 {
			t.Fatal("deployed from a wallet that cannot pay for the whole offer")
		}
		if f.journal(t).Offer.Deploy.State != stepPending {
			t.Fatal("an unsent deployment is recorded as in flight")
		}
	})
	t.Run("the published offer fails the preflight's admission check", func(t *testing.T) {
		f := newSetupFixture(t)
		initResult := f.mustInit(t)
		// Every step's own effect is present, but once the policy is set
		// the owner Agent is gone from finalized state: only the preflight
		// checks see that.
		if _, err := RunOffer(
			context.Background(),
			f.offer,
			hookedEnv(f, "agent service send update-policy", func(w *fakeWorld) {
				delete(w.Agents, initResult.AgentID)
			}),
		); err == nil ||
			!strings.Contains(err.Error(), "does not pass the preflight's chain checks") {
			t.Fatalf("an offer the preflight refuses was published: %v", err)
		}
		if config, _ := LoadNodeConfig(f.offer.RailConfigPath); config.Provider != nil {
			t.Fatal("the provider section was written for an offer that does not verify")
		}
		if _, statErr := os.Stat(filepath.Join(f.init.StateDir, setupDirectory, "offer.json")); statErr == nil {
			t.Fatal("an offer file was written for an offer that does not verify")
		}
	})
	t.Run("offer before init", func(t *testing.T) {
		f := newSetupFixture(t)
		_, err := RunOffer(context.Background(), f.offer, f.env())
		mustFail(t, err, nil, "init")
	})
}
