package earning

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
)

type PaidDemandNegotiationStore struct {
	directory string
	mu        sync.Mutex
}

func OpenPaidDemandNegotiationStore(directory string) (*PaidDemandNegotiationStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Paid Demand negotiation store path must be canonical and absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("Paid Demand negotiation store must be a private real directory")
	}
	return &PaidDemandNegotiationStore{directory: directory}, nil
}

func (store *PaidDemandNegotiationStore) Put(agreementDigest string, canonical []byte) error {
	if store == nil || !canonicalDigest(agreementDigest) || len(canonical) == 0 || len(canonical) > 2<<20 {
		return errors.New("invalid Paid Demand negotiation record")
	}
	value, err := paiddemand.DecodeCanonicalNegotiationPackage(canonical)
	if err != nil || value.AgreementBodyDigest != agreementDigest {
		return errors.New("Paid Demand negotiation bytes target another Agreement")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := filepath.Join(store.directory, strings.TrimPrefix(agreementDigest, "sha256:")+".cbor")
	if existing, readErr := readPrivateNegotiation(path); readErr == nil {
		if bytes.Equal(existing, canonical) {
			return nil
		}
		return errors.New("conflicting Paid Demand negotiation package")
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	temporary, err := os.CreateTemp(store.directory, ".negotiation-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(canonical); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(store.directory)
	if err != nil {
		return err
	}
	err = directory.Sync()
	_ = directory.Close()
	return err
}

func (store *PaidDemandNegotiationStore) Get(agreementDigest string) (paiddemand.NegotiationPackageV1, bool, error) {
	if store == nil || !canonicalDigest(agreementDigest) {
		return paiddemand.NegotiationPackageV1{}, false, errors.New("invalid Paid Demand negotiation lookup")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := filepath.Join(store.directory, strings.TrimPrefix(agreementDigest, "sha256:")+".cbor")
	raw, err := readPrivateNegotiation(path)
	if errors.Is(err, os.ErrNotExist) {
		return paiddemand.NegotiationPackageV1{}, false, nil
	}
	if err != nil {
		return paiddemand.NegotiationPackageV1{}, false, err
	}
	value, err := paiddemand.DecodeCanonicalNegotiationPackage(raw)
	if err != nil || value.AgreementBodyDigest != agreementDigest {
		return paiddemand.NegotiationPackageV1{}, false, errors.New("stored Paid Demand negotiation record is invalid")
	}
	return value, true, nil
}

func readPrivateNegotiation(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 2<<20 {
		return nil, errors.New("invalid Paid Demand negotiation store record")
	}
	return os.ReadFile(path)
}

func canonicalDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
