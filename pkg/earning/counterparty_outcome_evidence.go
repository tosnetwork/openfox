package earning

import (
	"errors"
	"sort"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type CounterpartyPaymentEvidenceState string

const (
	CounterpartyPaymentFinalized     CounterpartyPaymentEvidenceState = "finalized"
	CounterpartyPaymentReversed      CounterpartyPaymentEvidenceState = "reversed"
	CounterpartyPaymentIndeterminate CounterpartyPaymentEvidenceState = "indeterminate"
)

type CounterpartyPaymentTransactionEvidence struct {
	NetworkID                          string                           `json:"network_id"`
	TransactionDigest                  string                           `json:"transaction_digest"`
	State                              CounterpartyPaymentEvidenceState `json:"state"`
	PublishingActorAgentIDs            []string                         `json:"publishing_actor_agent_ids"`
	QualifiedEvidenceIssuerDescriptors []string                         `json:"qualified_evidence_issuer_descriptors"`
	Assertions                         []OutcomeAssertionKey            `json:"assertions"`
	AuthorityTimeHighWater             uint64                           `json:"authority_time_high_water"`
}

// CounterpartyOutcomeEvidenceSummary is deliberately descriptive rather than
// predictive. V1 has no closed counterparty attempt denominator, so it exposes
// no probability and can never be sufficient for an admission decision.
type CounterpartyOutcomeEvidenceSummary struct {
	LocalAgentID              string                                   `json:"local_agent_id"`
	CounterpartyAgentID       string                                   `json:"counterparty_agent_id"`
	Transactions              []CounterpartyPaymentTransactionEvidence `json:"transactions"`
	FinalizedTransactions     uint64                                   `json:"finalized_transactions"`
	ReversedTransactions      uint64                                   `json:"reversed_transactions"`
	IndeterminateTransactions uint64                                   `json:"indeterminate_transactions"`
	Sufficient                bool                                     `json:"sufficient"`
	InsufficiencyReason       string                                   `json:"insufficiency_reason"`
}

type counterpartyPaymentAccumulator struct {
	transaction commerce.TransferObservationV1
	states      map[CounterpartyPaymentEvidenceState]struct{}
	publishers  map[string]struct{}
	issuers     map[string]struct{}
	assertions  map[OutcomeAssertionKey]struct{}
	highWater   uint64
	conflict    bool
}

// SummarizeCounterpartyAgreementPayments consumes only authority-qualified
// agreement-payment observations where the local Agent is the payee. Multiple
// publishers of one transaction are distinct assertion publishers, never
// additional payments or proof that the publishers are independent.
func SummarizeCounterpartyAgreementPayments(localAgentID, counterpartyAgentID string,
	assertions []VerifiedOutcomeAssertion) (CounterpartyOutcomeEvidenceSummary, error) {
	summary := CounterpartyOutcomeEvidenceSummary{LocalAgentID: localAgentID, CounterpartyAgentID: counterpartyAgentID,
		Transactions: []CounterpartyPaymentTransactionEvidence{}, Sufficient: false,
		InsufficiencyReason: "no_closed_counterparty_attempt_denominator"}
	if localAgentID == "" || counterpartyAgentID == "" || localAgentID == counterpartyAgentID {
		return summary, errors.New("counterparty outcome evidence subject is invalid")
	}
	byTransaction := make(map[string]*counterpartyPaymentAccumulator)
	for _, assertion := range assertions {
		if !assertion.Authority.AuthorityQualified ||
			!assertion.payloadEvidenceBound || assertion.Body.AssertionProfileURI != commerce.OutcomeProfileTransferAgreementPayment {
			continue
		}
		var transfer commerce.TransferObservationV1
		if codec.Unmarshal(assertion.AssertionPayload, &transfer) != nil ||
			commerce.ValidateTransferObservationV1(transfer) != nil || transfer.TransferClass != "agreement_bound" ||
			transfer.NetworkID != assertion.Key.NetworkID ||
			transfer.PayeeID != localAgentID || transfer.PayerID != counterpartyAgentID ||
			!containsEvidenceDigest(assertion.Authority.VerifiedEvidenceDigests, transfer.FinalityEvidenceDigest) {
			continue
		}
		source, sourceFound := exactOutcomeEvidenceItem(assertion, "finalized_transfer", transfer.FinalityEvidenceDigest)
		if !sourceFound {
			continue
		}
		state := paymentEvidenceState(transfer.ResolutionState)
		transactionKey := transfer.NetworkID + "\x00" + transfer.TransactionDigest
		entry := byTransaction[transactionKey]
		if entry == nil {
			entry = &counterpartyPaymentAccumulator{transaction: transfer,
				states: make(map[CounterpartyPaymentEvidenceState]struct{}), publishers: make(map[string]struct{}),
				issuers:    make(map[string]struct{}),
				assertions: make(map[OutcomeAssertionKey]struct{})}
			byTransaction[transactionKey] = entry
		} else if !samePaymentBinding(entry.transaction, transfer) {
			entry.conflict = true
		}
		entry.states[state] = struct{}{}
		entry.publishers[assertion.Key.ActorAgentID] = struct{}{}
		entry.issuers[source.IssuerDescriptor] = struct{}{}
		entry.assertions[assertion.Key] = struct{}{}
		if assertion.Authority.AuthorityTimeHighWater > entry.highWater {
			entry.highWater = assertion.Authority.AuthorityTimeHighWater
		}
	}
	transactions := make([]string, 0, len(byTransaction))
	for key := range byTransaction {
		transactions = append(transactions, key)
	}
	sort.Strings(transactions)
	for _, transactionKey := range transactions {
		acc := byTransaction[transactionKey]
		state := CounterpartyPaymentIndeterminate
		if !acc.conflict && len(acc.states) == 1 {
			for candidate := range acc.states {
				state = candidate
			}
		}
		issuers := make([]string, 0, len(acc.issuers))
		for issuer := range acc.issuers {
			issuers = append(issuers, issuer)
		}
		sort.Strings(issuers)
		publishers := make([]string, 0, len(acc.publishers))
		for publisher := range acc.publishers {
			publishers = append(publishers, publisher)
		}
		sort.Strings(publishers)
		keys := make([]OutcomeAssertionKey, 0, len(acc.assertions))
		for key := range acc.assertions {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].ActorAgentID != keys[j].ActorAgentID {
				return keys[i].ActorAgentID < keys[j].ActorAgentID
			}
			if keys[i].OperationID != keys[j].OperationID {
				return keys[i].OperationID < keys[j].OperationID
			}
			return keys[i].OperationEnvelopeDigest < keys[j].OperationEnvelopeDigest
		})
		summary.Transactions = append(summary.Transactions, CounterpartyPaymentTransactionEvidence{
			NetworkID: acc.transaction.NetworkID, TransactionDigest: acc.transaction.TransactionDigest, State: state,
			PublishingActorAgentIDs: publishers, QualifiedEvidenceIssuerDescriptors: issuers,
			Assertions: keys, AuthorityTimeHighWater: acc.highWater})
		switch state {
		case CounterpartyPaymentFinalized:
			summary.FinalizedTransactions++
		case CounterpartyPaymentReversed:
			summary.ReversedTransactions++
		default:
			summary.IndeterminateTransactions++
		}
	}
	return summary, nil
}

func containsEvidenceDigest(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func paymentEvidenceState(value string) CounterpartyPaymentEvidenceState {
	switch value {
	case "validator_finalized", "corroborated_terminal":
		return CounterpartyPaymentFinalized
	case "reversed":
		return CounterpartyPaymentReversed
	default:
		return CounterpartyPaymentIndeterminate
	}
}

func samePaymentBinding(left, right commerce.TransferObservationV1) bool {
	return left.TransferClass == right.TransferClass && left.NetworkID == right.NetworkID && left.TransactionDigest == right.TransactionDigest &&
		left.PayerID == right.PayerID && left.PayeeID == right.PayeeID &&
		left.AssetIdentityDigest == right.AssetIdentityDigest && left.AmountAtomic == right.AmountAtomic &&
		left.DestinationDigest == right.DestinationDigest && left.AgreementBodyDigest == right.AgreementBodyDigest &&
		left.ObligationInstanceID == right.ObligationInstanceID && left.PaymentRequestDigest == right.PaymentRequestDigest &&
		left.AdapterProfileURI == right.AdapterProfileURI && left.StableActionID == right.StableActionID &&
		left.ExactRequestDigest == right.ExactRequestDigest
}

func exactOutcomeEvidenceItem(assertion VerifiedOutcomeAssertion, role, objectDigest string) (commerce.OutcomeEvidenceItemV1, bool) {
	if !containsEvidenceDigest(assertion.Authority.VerifiedEvidenceDigests, objectDigest) {
		return commerce.OutcomeEvidenceItemV1{}, false
	}
	var matched commerce.OutcomeEvidenceItemV1
	found := false
	for _, item := range assertion.Manifest.EvidenceItems {
		if item.EvidenceRole != role || item.ObjectDigest != objectDigest {
			continue
		}
		if found {
			return commerce.OutcomeEvidenceItemV1{}, false
		}
		matched, found = item, true
	}
	return matched, found
}
