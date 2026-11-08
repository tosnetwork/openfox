package servicebridge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func publishTestBuyer(t *testing.T) (*Buyer, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "purchases")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	return &Buyer{config: BuyerConfig{Directory: directory, Now: time.Now}}, directory
}

func publishTestRecord(hash string) PurchaseRecord {
	return PurchaseRecord{Phase: PurchaseCalled, RequestHash: hash, CreatedUnix: time.Now().Unix()}
}

// A preparation interrupted before its rename leaves at most a staging
// directory holding some of the files; that is the only state a crash at any
// point of publishPurchase can leave behind.
func TestAnInterruptedPurchasePreparationDoesNotBlockTheListing(t *testing.T) {
	buyer, directory := publishTestBuyer(t)
	existing := strings.Repeat("ab", 32)
	if err := buyer.publishPurchase(publishTestRecord(existing), []byte("source"), []byte("package")); err != nil {
		t.Fatal(err)
	}
	interrupted := strings.Repeat("cd", 32)
	leftover := filepath.Join(directory, purchaseStagingPrefix+interrupted)
	if err := os.Mkdir(leftover, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(filepath.Join(leftover, "source"), []byte("partial")); err != nil {
		t.Fatal(err)
	}
	purchases, err := buyer.Purchases()
	if err != nil || len(purchases) != 1 || purchases[0].RequestHash != existing {
		t.Fatalf("an interrupted preparation blocks the purchase listing: %d %v", len(purchases), err)
	}
	if err = removePurchaseStaging(directory); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the interrupted staging directory survived a restart: %v", err)
	}
	if err = buyer.publishPurchase(publishTestRecord(interrupted), []byte("source"), []byte("package")); err != nil {
		t.Fatal(err)
	}
	purchases, err = buyer.Purchases()
	if err != nil || len(purchases) != 2 {
		t.Fatalf("the retried purchase is not listed: %d %v", len(purchases), err)
	}
	for _, name := range []string{"source", "quote-package", "record.json"} {
		if _, err := readPrivateFile(filepath.Join(buyer.purchaseDir(interrupted), name), 1<<20); err != nil {
			t.Fatalf("published purchase lacks %s: %v", name, err)
		}
	}
}

func TestPublishingAPurchaseTwiceKeepsTheFirstAndLeavesNoStaging(t *testing.T) {
	buyer, directory := publishTestBuyer(t)
	hash := strings.Repeat("ef", 32)
	if err := buyer.publishPurchase(publishTestRecord(hash), []byte("first"), []byte("package")); err != nil {
		t.Fatal(err)
	}
	if err := buyer.publishPurchase(
		publishTestRecord(hash),
		[]byte("second"),
		[]byte("package"),
	); !errors.Is(
		err,
		os.ErrExist,
	) {
		t.Fatalf("a second publish of one request hash: %v", err)
	}
	source, err := readPrivateFile(filepath.Join(buyer.purchaseDir(hash), "source"), 64)
	if err != nil || string(source) != "first" {
		t.Fatalf("the first purchase was overwritten: %q %v", source, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), purchaseStagingPrefix) {
			t.Fatalf("a refused publish left staging behind: %s", entry.Name())
		}
	}
}
