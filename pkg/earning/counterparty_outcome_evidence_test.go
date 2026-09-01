package earning

import (
	"encoding/json"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestCounterpartyAgreementPaymentSummaryDeduplicatesAndFailsClosed(t *testing.T) {
	txOne := digestTestValue(t, "transaction-one")
	txTwo := digestTestValue(t, "transaction-two")
	txThree := digestTestValue(t, "transaction-three")
	txFour := digestTestValue(t, "transaction-four")
	assertions := []VerifiedOutcomeAssertion{
		paymentAssertion(t, "issuer:a", txOne, "validator_finalized", "25", true, "agent:buyer", "agent:local", 7),
		paymentAssertion(t, "issuer:b", txOne, "corroborated_terminal", "25", true, "agent:buyer", "agent:local", 9),
		paymentAssertion(t, "issuer:a", txTwo, "reversed", "10", true, "agent:buyer", "agent:local", 8),
		paymentAssertion(t, "issuer:a", txThree, "validator_finalized", "5", true, "agent:buyer", "agent:local", 10),
		paymentAssertion(t, "issuer:b", txThree, "reversed", "5", true, "agent:buyer", "agent:local", 11),
		paymentAssertion(t, "issuer:a", txFour, "validator_finalized", "1", false, "agent:buyer", "agent:local", 12),
		paymentAssertion(t, "issuer:a", digestTestValue(t, "outbound"), "validator_finalized", "1", true, "agent:local", "agent:buyer", 12),
	}
	unbound := paymentAssertion(t, "issuer:a", digestTestValue(t, "unbound-finality"), "validator_finalized", "1", true,
		"agent:buyer", "agent:local", 12)
	unbound.Authority.VerifiedEvidenceDigests = []string{zeroSHA256Digest()}
	payloadUnbound := paymentAssertion(t, "issuer:a", digestTestValue(t, "payload-unbound"), "validator_finalized", "1", true,
		"agent:buyer", "agent:local", 12)
	payloadUnbound.payloadEvidenceBound = false
	assertions = append(assertions, unbound, payloadUnbound)
	summary, err := SummarizeCounterpartyAgreementPayments("agent:local", "agent:buyer", assertions)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Sufficient || summary.InsufficiencyReason != "no_closed_counterparty_attempt_denominator" {
		t.Fatalf("success-only observations became sufficient risk evidence: %+v", summary)
	}
	if len(summary.Transactions) != 3 || summary.FinalizedTransactions != 1 || summary.ReversedTransactions != 1 ||
		summary.IndeterminateTransactions != 1 {
		t.Fatalf("transaction outcomes were counted incorrectly: %+v", summary)
	}
	one := paymentTransactionByDigest(t, summary, txOne)
	if one.State != CounterpartyPaymentFinalized || len(one.PublishingActorAgentIDs) != 2 ||
		len(one.QualifiedEvidenceIssuerDescriptors) != 1 || one.AuthorityTimeHighWater != 9 {
		t.Fatalf("multi-issuer evidence inflated or lost corroboration: %+v", one)
	}
	three := paymentTransactionByDigest(t, summary, txThree)
	if three.State != CounterpartyPaymentIndeterminate {
		t.Fatalf("conflicting transaction reports were not indeterminate: %+v", three)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "probability") {
		t.Fatalf("advisory evidence summary exposed a probability: %s", raw)
	}
}

func TestCounterpartyAgreementPaymentSummaryKeepsNetworksSeparate(t *testing.T) {
	tx := digestTestValue(t, "same-transaction-different-networks")
	first := paymentAssertion(t, "publisher:a", tx, "validator_finalized", "5", true,
		"agent:buyer", "agent:local", 4)
	second := paymentAssertion(t, "publisher:b", tx, "validator_finalized", "5", true,
		"agent:buyer", "agent:local", 5)
	var transfer commerce.TransferObservationV1
	if codec.Unmarshal(second.AssertionPayload, &transfer) != nil {
		t.Fatal("decode second transfer")
	}
	transfer.NetworkID = "tos:other"
	second.Key.NetworkID = transfer.NetworkID
	var err error
	second.AssertionPayload, err = codec.Marshal(transfer)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := SummarizeCounterpartyAgreementPayments("agent:local", "agent:buyer",
		[]VerifiedOutcomeAssertion{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Transactions) != 2 || summary.Transactions[0].NetworkID != "tos:other" ||
		summary.Transactions[1].NetworkID != "tos:test" {
		t.Fatalf("same transaction digest was conflated across networks: %+v", summary.Transactions)
	}
}

func paymentTransactionByDigest(t *testing.T, summary CounterpartyOutcomeEvidenceSummary,
	digest string) CounterpartyPaymentTransactionEvidence {
	t.Helper()
	for _, transaction := range summary.Transactions {
		if transaction.TransactionDigest == digest {
			return transaction
		}
	}
	t.Fatalf("payment transaction %s is absent: %+v", digest, summary)
	return CounterpartyPaymentTransactionEvidence{}
}

func TestCounterpartyAgreementPaymentSummaryTreatsBindingConflictAsIndeterminate(t *testing.T) {
	tx := digestTestValue(t, "binding-conflict")
	left := paymentAssertion(t, "issuer:a", tx, "validator_finalized", "5", true, "agent:buyer", "agent:local", 4)
	right := paymentAssertion(t, "issuer:b", tx, "validator_finalized", "6", true, "agent:buyer", "agent:local", 5)
	summary, err := SummarizeCounterpartyAgreementPayments("agent:local", "agent:buyer", []VerifiedOutcomeAssertion{left, right})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Transactions) != 1 || summary.Transactions[0].State != CounterpartyPaymentIndeterminate ||
		summary.IndeterminateTransactions != 1 {
		t.Fatalf("conflicting payment bindings were accepted: %+v", summary)
	}
}

func paymentAssertion(t *testing.T, actor, transaction, state, amount string, qualified bool,
	payer, payee string, highWater uint64) VerifiedOutcomeAssertion {
	t.Helper()
	transfer := commerce.TransferObservationV1{TransferClass: "agreement_bound", NetworkID: "tos:test",
		TransactionDigest: transaction, FinalityEvidenceDigest: testDigest, PayerID: payer, PayeeID: payee,
		AssetIdentityDigest: zeroSHA256Digest(), AmountAtomic: amount, DestinationDigest: testDigest,
		AgreementBodyDigest: testDigest, ObligationInstanceID: zeroSHA256Digest(), PaymentRequestDigest: testDigest,
		StableActionID: zeroSHA256Digest(), ExactRequestDigest: testDigest, AdapterProfileURI: "tos.payment.direct.v1",
		ResolutionState: state, ObservedAtUnix: 1_900_000_000}
	payload, err := codec.Marshal(transfer)
	if err != nil {
		t.Fatal(err)
	}
	operationID := digestTestValue(t, actor+transaction+state+amount)
	return VerifiedOutcomeAssertion{Key: OutcomeAssertionKey{NetworkID: "tos:test", ActorAgentID: actor,
		OperationID: operationID, OperationEnvelopeDigest: digestTestValue(t, "envelope:"+operationID)},
		Body:             commerce.OperationOutcomeEventBodyV1{AssertionProfileURI: commerce.OutcomeProfileTransferAgreementPayment},
		AssertionPayload: payload, Manifest: commerce.OutcomeEvidenceManifestV1{EvidenceItems: []commerce.OutcomeEvidenceItemV1{{
			EvidenceRole: "finalized_transfer", ObjectDigest: transfer.FinalityEvidenceDigest,
			IssuerDescriptor: "qualified-source:payment-finality"}}},
		Authority: commerce.OutcomeAuthorityAssessmentV1{AuthorityQualified: qualified,
			VerifiedEvidenceDigests: []string{transfer.FinalityEvidenceDigest}, AuthorityTimeHighWater: highWater},
		payloadEvidenceBound: true}
}

func digestTestValue(t *testing.T, value string) string {
	t.Helper()
	digest, err := codec.Digest("tos.openfox.test-value.v1", value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
