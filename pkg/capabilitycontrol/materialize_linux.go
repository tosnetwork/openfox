//go:build linux

package capabilitycontrol

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// secureMaterializeTree pins the destination root and performs every create
// beneath it with openat2 RESOLVE_BENEATH|NO_SYMLINKS. A same-UID process can
// race the source (the final closure check catches that), but cannot redirect
// an authorized installation write outside the object store.
func secureMaterializeTree(source, target string) error {
	parentPath, targetName := filepath.Dir(target), filepath.Base(target)
	if targetName == "" || targetName == "." || targetName == ".." || strings.ContainsRune(targetName, '/') {
		return errors.New("invalid capability object target")
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	created := true
	if err := unix.Mkdirat(parentFD, targetName, 0o700); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		created = false
	}
	rootFD, err := unix.Openat2(parentFD, targetName, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	if !created {
		return nil
	}
	sourceRootFD, err := unix.Open(source, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sourceRootFD)
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			return errors.New("copy path escapes source")
		}
		if rel == "." || entry.Name() == ".skill-origin.json" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !info.Mode().IsRegular() {
			return errors.New("copy source contains unsupported file")
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			mode := uint32(info.Mode().Perm() & 0o755)
			if err := unix.Mkdirat(rootFD, rel, mode); err != nil {
				return err
			}
			fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
			if err != nil {
				return err
			}
			chmodErr := unix.Fchmod(fd, mode)
			return errors.Join(chmodErr, unix.Close(fd))
		}
		if info.Size() > 64<<20 || fileLinkCount(info) != 1 {
			return errors.New("capability file is oversized or hard-linked")
		}
		sourceFD, err := unix.Openat2(sourceRootFD, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return err
		}
		sourceFile := os.NewFile(uintptr(sourceFD), rel)
		if sourceFile == nil {
			unix.Close(sourceFD)
			return errors.New("open pinned capability source")
		}
		pinnedInfo, err := sourceFile.Stat()
		if err != nil || !pinnedInfo.Mode().IsRegular() || pinnedInfo.Size() != info.Size() || fileLinkCount(pinnedInfo) != 1 {
			sourceFile.Close()
			return errors.New("capability source changed during pinned open")
		}
		mode := uint64(info.Mode().Perm() & 0o755)
		fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC, Mode: mode, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			sourceFile.Close()
			return err
		}
		destination := os.NewFile(uintptr(fd), rel)
		if destination == nil {
			sourceFile.Close()
			unix.Close(fd)
			return errors.New("create pinned destination")
		}
		if err := unix.Fchmod(fd, uint32(mode)); err != nil {
			sourceFile.Close()
			destination.Close()
			return err
		}
		_, copyErr := io.Copy(destination, io.LimitReader(sourceFile, 64<<20+1))
		syncErr := destination.Sync()
		closeErr := destination.Close()
		sourceCloseErr := sourceFile.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || sourceCloseErr != nil {
			return errors.Join(copyErr, syncErr, closeErr, sourceCloseErr)
		}
		return nil
	})
}
