package servicebridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/openfox/pkg/actionauth"
)

type recordingCustodySigner struct {
	funds int
	signs int
}

func (s *recordingCustodySigner) SignAndFundEscrow(context.Context, AcceptedQuote) error {
	s.funds++
	return nil
}

func (s *recordingCustodySigner) SignSettlementIntent(context.Context, string) ([]byte, error) {
	s.signs++
	return []byte("signature"), nil
}

type recordingActionAuthorizer struct {
	actions []actionauth.Action
	err     error
}

func (a *recordingActionAuthorizer) Authorize(_ context.Context, action actionauth.Action) error {
	a.actions = append(a.actions, action)
	return a.err
}

func completeAcceptedQuote() AcceptedQuote {
	digest := "sha256:" + strings.Repeat("a", 64)
	return AcceptedQuote{
		QuoteCommitment: digest,
		Proposal: QuoteProposal{
			Capability: CapabilityRef{
				AgentID:      "agent_" + strings.Repeat("1", 64),
				CapabilityID: "cap_" + strings.Repeat("2", 64),
				Version:      "1", ManifestDigest: digest, CapabilityClass: "compute.inference",
			},
			Asset: AssetIdentity{
				Master:         strings.Repeat("3", 64),
				WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("4", 64),
				MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("5", 64),
				Decimals:       9,
				Network: Network{
					ID:              "tos-mainnet",
					GenesisRootHash: strings.Repeat("6", 64),
					GenesisFileHash: strings.Repeat("7", 64),
				},
			},
			AtomicAmount: "184467440737095516160", Expiry: time.Unix(2_000_000_000, 0),
			TransportBindingDigest: digest, EscrowTermsDigest: digest, DisputeTerms: digest,
		},
	}
}

func authorizedSignerContext() context.Context {
	return actionauth.WithInvocation(context.Background(), actionauth.Invocation{
		LineageComplete: true,
		DerivedFrom:     []actionauth.Origin{{EventID: "evt_" + strings.Repeat("8", 64)}},
	})
}

func TestAuthorizedCustodySignerCommitsExactTermsBeforeFunding(t *testing.T) {
	inner := &recordingCustodySigner{}
	authorizer := &recordingActionAuthorizer{}
	signer := AuthorizedCustodySigner{
		Signer:     inner,
		Authorizer: authorizer,
		MandateID:  "mdt_" + strings.Repeat("9", 64),
	}
	if err := signer.SignAndFundEscrow(authorizedSignerContext(), completeAcceptedQuote()); err != nil {
		t.Fatal(err)
	}
	if inner.funds != 1 || len(authorizer.actions) != 1 {
		t.Fatalf("funds=%d actions=%+v", inner.funds, authorizer.actions)
	}
	action := authorizer.actions[0]
	if action.Effect != actionauth.EffectSpend || action.Terms == nil ||
		action.Terms.PriceAtomic != "184467440737095516160" || len(action.DerivedFrom) != 1 {
		t.Fatalf("action = %+v", action)
	}
}

func TestAuthorizedCustodySignerRefusalAndIncompleteLineageNeverReachCustody(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"missing":    context.Background(),
		"incomplete": actionauth.WithInvocation(context.Background(), actionauth.Invocation{}),
	} {
		t.Run(name, func(t *testing.T) {
			inner := &recordingCustodySigner{}
			signer := AuthorizedCustodySigner{
				Signer:     inner,
				Authorizer: &recordingActionAuthorizer{},
				MandateID:  "mandate",
			}
			if err := signer.SignAndFundEscrow(
				ctx,
				completeAcceptedQuote(),
			); !errors.Is(
				err,
				ErrIncompletePurchaseAuthority,
			) {
				t.Fatalf("error = %v", err)
			}
			if inner.funds != 0 {
				t.Fatal("custody ran without complete runtime provenance")
			}
		})
	}

	inner := &recordingCustodySigner{}
	denied := errors.New("owner denied")
	authorizer := &recordingActionAuthorizer{err: denied}
	signer := AuthorizedCustodySigner{Signer: inner, Authorizer: authorizer, MandateID: "mandate"}
	if err := signer.SignAndFundEscrow(authorizedSignerContext(), completeAcceptedQuote()); !errors.Is(err, denied) {
		t.Fatalf("error = %v", err)
	}
	if inner.funds != 0 {
		t.Fatal("custody ran after Messenger refusal")
	}
}

func TestAuthorizedCustodySignerProtectsSettlementKeyUse(t *testing.T) {
	inner := &recordingCustodySigner{}
	authorizer := &recordingActionAuthorizer{}
	signer := AuthorizedCustodySigner{Signer: inner, Authorizer: authorizer, MandateID: "mandate"}
	if _, err := signer.SignSettlementIntent(authorizedSignerContext(), "intent"); err != nil {
		t.Fatal(err)
	}
	if inner.signs != 1 || len(authorizer.actions) != 1 || authorizer.actions[0].Effect != actionauth.EffectKeyUse {
		t.Fatalf("signs=%d actions=%+v", inner.signs, authorizer.actions)
	}
}
