//go:build linux

package capabilitycontrol

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const quarantineResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// captureQuarantineSnapshot walks only through pinned directory descriptors.
func captureQuarantineSnapshot(rootFD int, childName string) (quarantineSnapshot, error) {
	fd, err := unix.Openat2(rootFD, childName, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: quarantineResolveFlags})
	if err != nil {
		return quarantineSnapshot{}, err
	}
	rootFile := os.NewFile(uintptr(fd), childName)
	if rootFile == nil {
		_ = unix.Close(fd)
		return quarantineSnapshot{}, errors.New("open quarantine snapshot root handle")
	}
	defer rootFile.Close()
	result := quarantineSnapshot{Entries: make([]quarantineSnapshotEntry, 0)}
	if err := captureQuarantineDirectory(rootFile, "", &result); err != nil {
		return quarantineSnapshot{}, err
	}
	return result, nil
}

func captureQuarantineDirectory(directory *os.File, prefix string, result *quarantineSnapshot) error {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if name == ".skill-origin.json" {
			continue
		}
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return errors.New("quarantine snapshot contains an invalid name")
		}
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		fd, err := unix.Openat2(int(directory.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: quarantineResolveFlags})
		if err != nil {
			return err
		}
		child := os.NewFile(uintptr(fd), relative)
		if child == nil {
			_ = unix.Close(fd)
			return errors.New("open quarantine snapshot child handle")
		}
		info, statErr := child.Stat()
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			_ = child.Close()
			return errors.New("quarantine snapshot contains an unsupported object")
		}
		result.Files++
		if result.Files > QuarantineReservationFiles {
			_ = child.Close()
			return errors.New("quarantine snapshot exceeds file limit")
		}
		item := quarantineSnapshotEntry{Relative: relative, Directory: info.IsDir(), Mode: info.Mode().Perm() & 0o555}
		if info.IsDir() {
			// The broker retains directory mutation authority for garbage
			// collection; all file bytes are read-only and every later transition
			// rehashes the complete tree through descriptor-relative traversal.
			item.Mode = 0o700
			result.Entries = append(result.Entries, item)
			err = captureQuarantineDirectory(child, relative, result)
			_ = child.Close()
			if err != nil {
				return err
			}
			continue
		}
		if fileLinkCount(info) != 1 || info.Size() < 0 || uint64(info.Size()) > QuarantineReservationBytes-result.Bytes {
			_ = child.Close()
			return errors.New("quarantine source is hard-linked, changed, or exceeds the snapshot bound")
		}
		raw, readErr := io.ReadAll(io.LimitReader(child, int64(QuarantineReservationBytes-result.Bytes)+1))
		closeErr := child.Close()
		if readErr != nil || closeErr != nil || uint64(len(raw)) != uint64(info.Size()) || uint64(len(raw)) > QuarantineReservationBytes-result.Bytes {
			return errors.Join(errors.New("quarantine source changed during snapshot"), readErr, closeErr)
		}
		result.Bytes += uint64(len(raw))
		item.Data = raw
		result.Entries = append(result.Entries, item)
	}
	return nil
}

// stageQuarantineSnapshot builds one fsynced read-only tree below a pinned
// ledger-root descriptor before external acknowledgement.
func stageQuarantineSnapshot(ledgerRootFD int, storageRoot string, snapshot quarantineSnapshot) (name string, returnErr error) {
	parentFD, err := unix.Dup(ledgerRootFD)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	name = ".commit-snapshot-" + hex.EncodeToString(random)
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil {
		return "", err
	}
	defer func() {
		if returnErr != nil {
			_ = os.RemoveAll(filepath.Join(storageRoot, name))
		}
	}()
	rootFD, err := unix.Openat2(parentFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: quarantineResolveFlags})
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)
	for _, item := range snapshot.Entries {
		parent, base, err := openQuarantineParent(rootFD, item.Relative)
		if err != nil {
			return "", err
		}
		if item.Directory {
			err = unix.Mkdirat(parent, base, 0o700)
			_ = unix.Close(parent)
			if err != nil {
				return "", err
			}
			continue
		}
		fd, openErr := unix.Openat2(parent, base, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC, Mode: 0o600, Resolve: quarantineResolveFlags})
		_ = unix.Close(parent)
		if openErr != nil {
			return "", openErr
		}
		file := os.NewFile(uintptr(fd), item.Relative)
		if file == nil {
			_ = unix.Close(fd)
			return "", errors.New("create quarantine snapshot file handle")
		}
		written, writeErr := file.Write(item.Data)
		syncErr := file.Sync()
		chmodErr := file.Chmod(item.Mode)
		closeErr := file.Close()
		if writeErr != nil || written != len(item.Data) || syncErr != nil || chmodErr != nil || closeErr != nil {
			return "", errors.Join(writeErr, syncErr, chmodErr, closeErr)
		}
	}
	for index := len(snapshot.Entries) - 1; index >= 0; index-- {
		item := snapshot.Entries[index]
		if !item.Directory {
			continue
		}
		fd, err := unix.Openat2(rootFD, item.Relative, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: quarantineResolveFlags})
		if err != nil {
			return "", err
		}
		chmodErr := unix.Fchmod(fd, uint32(item.Mode))
		syncErr := unix.Fsync(fd)
		_ = unix.Close(fd)
		if chmodErr != nil || syncErr != nil {
			return "", errors.Join(chmodErr, syncErr)
		}
	}
	if err := unix.Fchmod(rootFD, 0o700); err != nil {
		return "", err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return "", err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return "", err
	}
	return name, nil
}

func openQuarantineParent(rootFD int, relative string) (int, string, error) {
	clean := filepath.ToSlash(filepath.Clean(relative))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return -1, "", errors.New("quarantine destination escapes root")
	}
	parts := strings.Split(clean, "/")
	base := parts[len(parts)-1]
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat2(current, part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: quarantineResolveFlags})
		_ = unix.Close(current)
		if openErr != nil {
			return -1, "", openErr
		}
		current = next
	}
	return current, base, nil
}

func publishStagedQuarantineSnapshot(rootFD int, temporaryName, digestName string) error {
	if !strings.HasPrefix(temporaryName, ".commit-snapshot-") || len(digestName) != 64 {
		return errors.New("invalid prepared quarantine publication identity")
	}
	parentFD, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	stagedFD, err := unix.Openat2(parentFD, temporaryName, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: quarantineResolveFlags})
	if err != nil {
		return err
	}
	defer unix.Close(stagedFD)
	var before unix.Stat_t
	if err := unix.Fstat(stagedFD, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("prepared quarantine snapshot is not a directory")
	}
	if err := unix.Renameat2(parentFD, temporaryName, parentFD, digestName, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	publishedFD, err := unix.Openat2(parentFD, digestName, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: quarantineResolveFlags})
	if err != nil {
		return err
	}
	defer unix.Close(publishedFD)
	var after unix.Stat_t
	if err := unix.Fstat(publishedFD, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		return errors.New("quarantine publication pathname was substituted")
	}
	return unix.Fsync(parentFD)
}
