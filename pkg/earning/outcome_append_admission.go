package earning

import (
	"errors"
	"reflect"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type OutcomeJournalAuthorityHeadV1 struct {
	Epoch                   uint64 `json:"epoch"`
	Sequence                uint64 `json:"sequence"`
	EventContentID          string `json:"event_content_id"`
	OperationEnvelopeDigest string `json:"operation_envelope_digest"`
	GapSetDigest            string `json:"gap_set_digest"`
	StableActionID          string `json:"stable_action_id"`
	ExactRequestDigest      string `json:"exact_request_digest"`
}

func validateAndAdvanceOutcomeJournalAuthorityHead(document *authorityDocument, action commerce.AuthorizedAction,
	fields map[string]commerce.SemanticValue, canonicalRequest []byte, fence commerce.WriterFence) error {
	if action.ActionKind != outcomeJournalScope {
		return nil
	}
	var request commerce.OperationJournalAppendAdmissionRequestV1
	if decodeStrictCBOR(canonicalRequest, &request) != nil {
		return errors.New("outcome journal append admission request is not canonical")
	}
	canonical, err := codec.Marshal(request)
	if err != nil || !reflect.DeepEqual(canonical, canonicalRequest) || commerce.ValidateOperationJournalAppendAdmissionRequestV1(request) != nil ||
		request.Epoch != fence.Body.WriterGeneration {
		return errors.New("outcome journal append admission request is invalid")
	}
	expected, err := commerce.OperationJournalAppendSemanticFieldsV1(document.OwnerID, document.AgentID, request.OrderingDomain,
		request.Epoch, request.Sequence, request.EventContentID)
	if err != nil || !reflect.DeepEqual(fields, expected) {
		return errors.New("outcome journal append semantic fields differ from the request")
	}
	if document.OutcomeJournalHeads == nil {
		document.OutcomeJournalHeads = make(map[string]OutcomeJournalAuthorityHeadV1)
	}
	prior, found := document.OutcomeJournalHeads[request.OrderingDomain]
	if found {
		if request.Sequence <= prior.Sequence || request.Epoch < prior.Epoch {
			return errors.New("outcome journal sequence conflicts with the authority high-water")
		}
		if request.Epoch == prior.Epoch && request.Sequence != prior.Sequence+1 {
			// A skipped reservation is permitted only when the exact gap-set
			// commitment changes. The signed checkpoint later reveals the set.
			if request.GapSetDigest == prior.GapSetDigest {
				return errors.New("outcome journal sequence skips without an explicit gap commitment")
			}
		}
	}
	document.OutcomeJournalHeads[request.OrderingDomain] = OutcomeJournalAuthorityHeadV1{Epoch: request.Epoch, Sequence: request.Sequence,
		EventContentID: request.EventContentID, OperationEnvelopeDigest: request.OperationEnvelopeDigest, GapSetDigest: request.GapSetDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest}
	return nil
}

func decodeStrictCBOR(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return errors.New("canonical CBOR is empty or oversized")
	}
	return codec.Unmarshal(raw, target)
}
