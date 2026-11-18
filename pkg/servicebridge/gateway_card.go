package servicebridge

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
)

// The gateway card file is the provider's current encryption key card as a
// gateway's quote profile names it (`provider_key_card_file`). The gateway
// reads it for every Quote and serves it next to the Quote package, so a
// buyer whose first purchase is quoted by the gateway can reach a provider
// that receives only through a relay. The file holds exactly the signed key
// card packet JSON and nothing else.
//
// The gateway accepts the file only when it is a regular file of 1 to 16,384
// bytes with mode 0600, owned by the user the gateway runs as, at an absolute
// clean path; it re-checks the card (a key card packet of the profile's
// provider, valid now) on every Quote and stops at startup when a configured
// card is missing or invalid. The node therefore runs as the gateway's user
// and never writes a card the gateway would refuse.

// errGatewayCardRefused reports a card the node will not publish to the
// gateway card file.
var errGatewayCardRefused = errors.New("servicebridge: the key card is not publishable to the gateway card file")

// gatewayCardCommitHook, when set, runs after the card is written and synced
// to its temporary file and before that file is renamed into place. Tests
// use it to stop the process at that point; it is nil in production.
var gatewayCardCommitHook func(temporary string)

// checkGatewayCard requires a card the gateway serves now: the gateway's own
// check (quoteexchange.CheckProviderKeyCard: the bound, a key card packet of
// agentID, a canonical body valid now). On top of it the card's window must
// already have started: the gateway tolerates a not_before slightly ahead of
// its clock, but the node never publishes a card that is not yet valid.
func checkGatewayCard(agentID string, cardJSON []byte, now time.Time) error {
	if err := quoteexchange.CheckProviderKeyCard(cardJSON, agentID, now); err != nil {
		return fmt.Errorf("%w: %w", errGatewayCardRefused, err)
	}
	card, err := decodeOwnCard(agentID, cardJSON)
	if err != nil {
		return fmt.Errorf("%w: %w", errGatewayCardRefused, err)
	}
	if card.NotBeforeUnix > uint64(now.Unix()) {
		return fmt.Errorf("%w: the card is not valid before %d", errGatewayCardRefused, card.NotBeforeUnix)
	}
	return nil
}

// publishGatewayCard replaces the gateway card file with cardJSON when the
// file does not already hold exactly those bytes as an owner-only file. The
// card is written to a temporary file in the same directory, synced, given
// mode 0600 and renamed over the file, so a reader sees the previous card or
// the new one and never a partial file. The directory is created owner-only
// when it does not exist; an existing directory is left as it is.
func publishGatewayCard(path, agentID string, cardJSON []byte, now time.Time) error {
	if !cleanAbsolute(path) {
		return errors.New("servicebridge: the gateway card file path must be absolute and clean")
	}
	if err := checkGatewayCard(agentID, cardJSON, now); err != nil {
		return err
	}
	if gatewayCardPublished(path, cardJSON) {
		return nil
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("servicebridge: create the gateway card file directory")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("servicebridge: the gateway card file path names something other than a regular file")
	}
	prefix := gatewayCardTemporaryPrefix(path)
	removeGatewayCardTemporaries(directory, prefix)
	temporary, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return errors.New("servicebridge: create the gateway card update")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("servicebridge: protect the gateway card update")
	}
	if _, err := temporary.Write(cardJSON); err != nil {
		_ = temporary.Close()
		return errors.New("servicebridge: write the gateway card update")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("servicebridge: sync the gateway card update")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("servicebridge: close the gateway card update")
	}
	if gatewayCardCommitHook != nil {
		gatewayCardCommitHook(name)
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("servicebridge: commit the gateway card update")
	}
	return syncDirectory(directory)
}

// gatewayCardPublished reports whether path already holds exactly cardJSON
// as a file the gateway accepts: regular, mode 0600 and owned by this user.
// Anything else is replaced.
func gatewayCardPublished(path string, cardJSON []byte) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	if owned, ownerErr := ownedByCurrentUser(info); ownerErr != nil || !owned {
		return false
	}
	published, err := readPrivateFile(path, quoteexchange.MaxProviderKeyCardBytes)
	return err == nil && bytes.Equal(published, cardJSON)
}

// gatewayCardTemporaryLeft is how old a temporary card file must be before
// a writer removes it as left by a crash. A younger one may belong to a
// concurrent writer (`offer` while `serve` runs) that is about to rename it.
const gatewayCardTemporaryLeft = time.Minute

// gatewayCardTemporaryPrefix names the temporary files of one card file. It
// starts with a dot and differs from the card file's own name, so it never
// collides with the file the gateway reads.
func gatewayCardTemporaryPrefix(path string) string {
	return "." + filepath.Base(path) + ".tmp-"
}

// removeGatewayCardTemporaries deletes temporary card files a crash left
// between writing and renaming. Nothing in one was ever published. A file
// that cannot be removed, or is too young to be a crash's, is left for a
// later pass.
func removeGatewayCardTemporaries(directory, prefix string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || time.Since(info.ModTime()) < gatewayCardTemporaryLeft {
			continue
		}
		_ = os.Remove(filepath.Join(directory, entry.Name()))
	}
}
