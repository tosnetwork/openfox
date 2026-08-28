package earning

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type profileInboxVerifier struct{ reject bool }

func (verifier profileInboxVerifier) VerifyCommerceObject(_ string, _ uint64, _, _, _ string, _ []byte) error {
	if verifier.reject {
		return context.Canceled
	}
	return nil
}

type profileInboxRetriever struct {
	content []byte
	err     error
	request commerce.ContentFetchRequest
}

func (retriever *profileInboxRetriever) Fetch(_ context.Context, request commerce.ContentFetchRequest) ([]byte, error) {
	retriever.request = request
	return append([]byte(nil), retriever.content...), retriever.err
}

type profileInboxCaller struct {
	pending  localapi.PendingEvent
	claimed  bool
	reject   bool
	complete bool
}

func (caller *profileInboxCaller) Call(_ context.Context, request localapi.Request) (localapi.Response, error) {
	switch request.Op {
	case localapi.OpPendingCommerceProfileEvents:
		if caller.complete || caller.reject {
			return localapi.Response{OK: true}, nil
		}
		return localapi.Response{OK: true, Events: []localapi.PendingEvent{caller.pending}}, nil
	case localapi.OpClaimCommerceProfileEvent:
		caller.claimed = true
		event := caller.pending
		return localapi.Response{OK: true, Event: &event}, nil
	case localapi.OpReject:
		caller.reject = true
		return localapi.Response{OK: true}, nil
	case localapi.OpComplete:
		caller.complete = true
		return localapi.Response{OK: true}, nil
	default:
		return localapi.Response{}, context.Canceled
	}
}

func newProfileInboxFixture(t *testing.T, now time.Time) (*profileInboxCaller, CommerceProfileInbox) {
	t.Helper()
	object := []byte{0xa1, 0x01, 0x02}
	profileEvent := commerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "test.object", ObjectContentType: "application/vnd.tos.test+cbor",
		ObjectDigest: "sha256:" + strings.Repeat("a", 64), ObjectSizeBytes: uint64(len(object)), CarriageKind: "inline",
		CanonicalObjectBytes: object, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	canonical, err := commerce.CanonicalCommerceProfileEventV1(profileEvent, now)
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.CommerceProfileEvent{ObjectDigest: profileEvent.ObjectDigest, CanonicalEvent: canonical})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: &nativev1.NetworkDomain{NetworkId: "tos:test",
		GenesisRootHash: strings.Repeat("1", 64), GenesisFileHash: strings.Repeat("2", 64)},
		ConversationID: "conv_" + strings.Repeat("1", 64), SenderAgentID: "agent_" + strings.Repeat("2", 64),
		SenderEndpointID: "mep_" + strings.Repeat("3", 64), SenderDeviceID: "dev_" + strings.Repeat("4", 64),
		CreatedAtUnix: uint64(now.Unix()), Kind: "commerce.profile-event", IdempotencyKey: strings.Repeat("5", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	caller := &profileInboxCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: raw}}
	return caller, CommerceProfileInbox{Client: caller, Verifier: profileInboxVerifier{}, Now: func() time.Time { return now }}
}

func TestCommerceProfileInboxVerifiesBeforeRelease(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	object := []byte{0xa1, 0x01, 0x02}
	profileEvent := commerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "test.object", ObjectContentType: "application/vnd.tos.test+cbor",
		ObjectDigest: "sha256:" + strings.Repeat("a", 64), ObjectSizeBytes: uint64(len(object)), CarriageKind: "inline",
		CanonicalObjectBytes: object, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	canonical, err := commerce.CanonicalCommerceProfileEventV1(profileEvent, now)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := payload.Encode(payload.CommerceProfileEvent{ObjectDigest: profileEvent.ObjectDigest, CanonicalEvent: canonical})
	event, err := envelope.NewEvent(envelope.Event{Network: &nativev1.NetworkDomain{NetworkId: "tos:test", GenesisRootHash: strings.Repeat("1", 64), GenesisFileHash: strings.Repeat("2", 64)},
		ConversationID: "conv_" + strings.Repeat("1", 64), SenderAgentID: "agent_" + strings.Repeat("2", 64),
		SenderEndpointID: "mep_" + strings.Repeat("3", 64), SenderDeviceID: "dev_" + strings.Repeat("4", 64),
		CreatedAtUnix: uint64(now.Unix()), Kind: "commerce.profile-event", IdempotencyKey: strings.Repeat("5", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := envelope.EncodeEventJSON(event)
	caller := &profileInboxCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: raw}}
	inbox := CommerceProfileInbox{Client: caller, Verifier: profileInboxVerifier{}, Now: func() time.Time { return now }}
	claimed, err := inbox.ClaimNext(context.Background())
	if err != nil || claimed == nil || claimed.ProfileEvent.ObjectDigest != profileEvent.ObjectDigest || !caller.claimed {
		t.Fatalf("verified event was not released: %#v %v", claimed, err)
	}

	caller = &profileInboxCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: raw}}
	inbox.Client, inbox.Verifier = caller, profileInboxVerifier{reject: true}
	if claimed, err := inbox.ClaimNext(context.Background()); err == nil || claimed != nil || !caller.reject {
		t.Fatalf("unverified object escaped the typed inbox: %#v %v", claimed, err)
	}
}

func TestCommerceProfileInboxFetchesDescriptorThroughOwnerRetriever(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	object := []byte{0xa1, 0x01, 0x02}
	digest := "sha256:" + strings.Repeat("a", 64)
	profileEvent := commerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "test.object", ObjectContentType: "application/vnd.tos.test+cbor", ObjectDigest: digest,
		ObjectSizeBytes: uint64(len(object)), CarriageKind: "content_addressed",
		ObjectDescriptor: &commerce.CommerceObjectDescriptorV1{ContentType: "application/vnd.tos.test+cbor",
			ContentDigest: digest, ContentSize: uint64(len(object)), RetrievalHints: []string{"https://objects.example/test"}},
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	canonical, err := commerce.CanonicalCommerceProfileEventV1(profileEvent, now)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := payload.Encode(payload.CommerceProfileEvent{ObjectDigest: digest, CanonicalEvent: canonical})
	event, err := envelope.NewEvent(envelope.Event{Network: &nativev1.NetworkDomain{NetworkId: "tos:test",
		GenesisRootHash: strings.Repeat("1", 64), GenesisFileHash: strings.Repeat("2", 64)},
		ConversationID: "conv_" + strings.Repeat("1", 64), SenderAgentID: "agent_" + strings.Repeat("2", 64),
		SenderEndpointID: "mep_" + strings.Repeat("3", 64), SenderDeviceID: "dev_" + strings.Repeat("4", 64),
		CreatedAtUnix: uint64(now.Unix()), Kind: "commerce.profile-event", IdempotencyKey: strings.Repeat("5", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := envelope.EncodeEventJSON(event)
	withoutRetriever := &profileInboxCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: raw}}
	inbox := CommerceProfileInbox{Client: withoutRetriever, Verifier: profileInboxVerifier{}, Now: func() time.Time { return now }}
	if claimed, claimErr := inbox.ClaimNext(context.Background()); claimErr == nil || claimed != nil || !withoutRetriever.reject {
		t.Fatalf("descriptor escaped without an owner retriever: claimed=%#v err=%v", claimed, claimErr)
	}
	retriever := &profileInboxRetriever{content: object}
	caller := &profileInboxCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: raw}}
	inbox.Client, inbox.Retriever = caller, retriever
	claimed, err := inbox.ClaimNext(context.Background())
	if err != nil || claimed == nil || string(claimed.CanonicalObjectBytes) != string(object) ||
		retriever.request.CandidateURL != "https://objects.example/test" || retriever.request.ContentDigest != digest {
		t.Fatalf("descriptor was not resolved through the bounded retriever: claimed=%#v request=%#v err=%v", claimed, retriever.request, err)
	}

	transient := &profileInboxRetriever{err: context.DeadlineExceeded}
	caller = &profileInboxCaller{pending: localapi.PendingEvent{EventID: event.EventID, Event: raw}}
	inbox.Client, inbox.Retriever = caller, transient
	if claimed, claimErr := inbox.ClaimNext(context.Background()); claimErr == nil || claimed != nil || caller.reject {
		t.Fatalf("transient immutable retrieval failure was incorrectly rejected: claimed=%#v err=%v", claimed, claimErr)
	}
}
