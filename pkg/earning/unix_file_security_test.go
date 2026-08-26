//go:build !windows

package earning

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type unixSecurityFileInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info unixSecurityFileInfo) Sys() any { return &info.stat }

func TestUnixOwnerPrivatePredicatesRejectForeignUIDAndMultipleLinks(t *testing.T) {
	directory := privateTempDir(t)
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("directory did not expose Unix ownership metadata")
	}
	foreignDirectory := unixSecurityFileInfo{FileInfo: directoryInfo, stat: *directoryStat}
	foreignDirectory.stat.Uid = uint32(os.Geteuid()) + 1
	if unixOwnerPrivateDirectoryInfo(foreignDirectory) || relayPinnedDirectoryInfoSecure(foreignDirectory) {
		t.Fatal("0700 directory owned by another UID was accepted as owner-private")
	}

	path := filepath.Join(directory, "journal")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	fileStat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file did not expose Unix ownership metadata")
	}
	foreignFile := unixSecurityFileInfo{FileInfo: fileInfo, stat: *fileStat}
	foreignFile.stat.Uid = uint32(os.Geteuid()) + 1
	if unixOwnerOnlyRegularFileInfo(foreignFile) || relayJournalFileInfoSecure(foreignFile) {
		t.Fatal("0600 regular file owned by another UID was accepted")
	}
	multiLinked := unixSecurityFileInfo{FileInfo: fileInfo, stat: *fileStat}
	multiLinked.stat.Nlink = 2
	if unixOwnerOnlyRegularFileInfo(multiLinked) || relayJournalFileInfoSecure(multiLinked) {
		t.Fatal("multiply-linked regular file was accepted as a private journal")
	}
}

func TestPersonalAuthorityRejectsHardLinkedLockAndJournal(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	lockDirectory := privateTempDir(t)
	lockPath := filepath.Join(lockDirectory, authorityLock)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(lockPath, filepath.Join(lockDirectory, "lock-alias")); err != nil {
		t.Fatal(err)
	}
	if authority, err := OpenPersonalAuthority(lockDirectory, "owner:lock", "agent:lock", "authority:lock",
		key, PortfolioLimits{}); err == nil {
		_ = authority.Close()
		t.Fatal("hard-linked economic authority lock was accepted")
	}

	journalDirectory := privateTempDir(t)
	authority, err := OpenPersonalAuthority(journalDirectory, "owner:journal", "agent:journal",
		"authority:journal", key, PortfolioLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(journalDirectory, authorityFile)
	if err := os.Link(journalPath, filepath.Join(journalDirectory, "journal-alias")); err != nil {
		t.Fatal(err)
	}
	if authority, err := OpenPersonalAuthority(journalDirectory, "owner:journal", "agent:journal",
		"authority:journal", key, PortfolioLimits{}); err == nil {
		_ = authority.Close()
		t.Fatal("hard-linked economic authority journal was accepted")
	}
}

func TestDurableRelayJournalRejectsHardLinkedState(t *testing.T) {
	directory := privateTempDir(t)
	journal, err := OpenDurableRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(directory, relayJournalFile)
	if err := os.Link(journalPath, filepath.Join(directory, "relay-journal-alias")); err != nil {
		t.Fatal(err)
	}
	if journal, err := OpenDurableRelayJournal(directory); err == nil {
		_ = journal.Close()
		t.Fatal("hard-linked provider relay journal was accepted")
	}
}
