package earning

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type PrivateContentUploaderSet map[string]PrivateContentUploader

func (set PrivateContentUploaderSet) Upload(ctx context.Context, challenge commerce.SignedPrivateHandoffChallenge,
	authorization commerce.SignedPrivateHandoffAuthorization, ciphertext []byte) (commerce.SignedPrivateHandoffAcknowledgement, error) {
	uploader := set[challenge.Body.IngressInstanceID]
	if uploader == nil {
		return commerce.SignedPrivateHandoffAcknowledgement{}, errors.New("private ingress instance is not owner-configured")
	}
	return uploader.Upload(ctx, challenge, authorization, ciphertext)
}

type FilePrivateHandoffInput struct {
	ObligationID         string
	Path                 string
	MediaType            string
	CanonicalPath        string
	MaximumBytes         uint64
	MaximumExpandedBytes uint64
	CompressionProfile   string
}

type FilePrivateHandoffContentSource struct {
	Inputs map[string]FilePrivateHandoffInput
}

func (source FilePrivateHandoffContentSource) ContentForChallenge(ctx context.Context,
	challenge commerce.SignedPrivateHandoffChallenge) (PrivateHandoffContent, error) {
	if err := ctx.Err(); err != nil {
		return PrivateHandoffContent{}, err
	}
	input, found := source.Inputs[challenge.Body.ObligationID]
	if !found || input.ObligationID != challenge.Body.ObligationID || !filepath.IsAbs(input.Path) || filepath.Clean(input.Path) != input.Path ||
		input.MediaType == "" || input.CanonicalPath == "" || input.MaximumBytes == 0 || input.MaximumBytes > 1<<30 ||
		input.MaximumExpandedBytes < input.MaximumBytes || input.MaximumExpandedBytes > 4<<30 {
		return PrivateHandoffContent{}, errors.New("private input obligation has no valid owner-configured file")
	}
	accepted := false
	for _, mediaType := range challenge.Body.AcceptedMediaTypes {
		accepted = accepted || mediaType == input.MediaType
	}
	if !accepted || input.MaximumBytes > challenge.Body.MaximumPlaintextBytes {
		return PrivateHandoffContent{}, errors.New("owner-configured private input exceeds receiver challenge policy")
	}
	pathInfo, err := os.Lstat(input.Path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() <= 0 ||
		uint64(pathInfo.Size()) > input.MaximumBytes || uint64(pathInfo.Size()) > challenge.Body.MaximumPlaintextBytes {
		return PrivateHandoffContent{}, errors.New("private input is not a bounded regular file")
	}
	file, err := os.Open(input.Path)
	if err != nil {
		return PrivateHandoffContent{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, opened) {
		return PrivateHandoffContent{}, errors.New("private input changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(input.MaximumBytes)+1))
	if err != nil || len(raw) == 0 || uint64(len(raw)) > input.MaximumBytes || uint64(len(raw)) > challenge.Body.MaximumPlaintextBytes {
		zeroPrivateContent(raw)
		return PrivateHandoffContent{}, errors.New("private input changed or exceeded its byte bound")
	}
	return PrivateHandoffContent{MediaType: input.MediaType, CanonicalPaths: []string{input.CanonicalPath}, Plaintext: raw,
		MaximumExpandedBytes: input.MaximumExpandedBytes, CompressionProfileURI: input.CompressionProfile}, nil
}
