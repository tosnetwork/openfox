package earning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type IntentContentResolver interface {
	ResolveIntentContent(context.Context, commerce.ContentDescriptor) ([]byte, error)
}

// SecureIntentContentResolver delegates every hostile locator to the protocol
// retriever whose owner policy fixes origins, DNS/address classes, redirects,
// credentials, byte limits and timeout. Retrieval hints are candidates only.
type SecureIntentContentResolver struct {
	Retriever commerce.SecureContentRetriever
}

func (resolver SecureIntentContentResolver) ResolveIntentContent(ctx context.Context, descriptor commerce.ContentDescriptor) ([]byte, error) {
	if len(descriptor.InlineContent) > 0 {
		if uint64(len(descriptor.InlineContent)) != descriptor.ContentSize {
			return nil, errors.New("inline Intent content size mismatch")
		}
		digest := sha256.Sum256(descriptor.InlineContent)
		if "sha256:"+hex.EncodeToString(digest[:]) != descriptor.ContentDigest {
			return nil, errors.New("inline Intent content digest mismatch")
		}
		return append([]byte(nil), descriptor.InlineContent...), nil
	}
	var failures []error
	for _, hint := range descriptor.RetrievalHints {
		content, err := resolver.Retriever.Fetch(ctx, commerce.ContentFetchRequest{CandidateURL: hint,
			ContentDigest: descriptor.ContentDigest, ContentSize: descriptor.ContentSize})
		if err == nil {
			return content, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil, errors.New("Intent content has no retrievable owner-allowed locator")
	}
	return nil, errors.Join(failures...)
}
