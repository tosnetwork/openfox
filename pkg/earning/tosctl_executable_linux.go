//go:build linux

package earning

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maximumTOSCTLExecutableBytes = 256 << 20

var (
	errTOSCTLProcessExited                 = errors.New("tosctl process leader exited")
	errTOSCTLProcessContainmentUnavailable = errors.New("secure tosctl process containment is unavailable")
)

// tosctlProcessContainment uses a fresh user/PID namespace for every custody
// command. The launched tosctl is PID 1 in that namespace, so Linux kills all
// remaining namespace members when it exits or is killed. Unlike a process
// group, this boundary also contains descendants that call setsid, create a
// new process group, or double-fork. The user namespace permits an unprivileged
// OpenFox process to create the PID namespace without granting capabilities in
// the host namespace. Kernels that disable this facility fail command.Start;
// custody then remains fail closed instead of silently degrading to a
// process-group-only claim.
func tosctlProcessContainment() *syscall.SysProcAttr {
	effectiveUID, effectiveGID := os.Geteuid(), os.Getegid()
	return &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWPID,
		// Preserve the caller's numeric effective IDs inside the namespace. This
		// maps exactly one host identity and avoids changing tosctl behavior by
		// presenting the command as namespace UID/GID zero.
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: effectiveUID, HostID: effectiveUID, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: effectiveGID, HostID: effectiveGID, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
}

// pinTOSCTLExecutable enrolls the exact executable identity before an
// authority-backed operation can proceed. Every launch compares a fresh
// descriptor snapshot against this enrollment.
func (sink *TOSCTLPaymentSink) pinTOSCTLExecutable() error {
	if sink == nil {
		return errors.New("tosctl sink is unavailable")
	}
	sink.executableMu.Lock()
	if sink.executableSnapshot == nil {
		executable, identity, err := snapshotTOSCTLExecutable(sink.Executable)
		if err != nil {
			sink.executableMu.Unlock()
			return err
		}
		copy := identity
		sink.executableIdentity = &copy
		sink.executableSnapshot = executable
		if sink.executableLaunches == nil {
			sink.executableLaunches = make(chan struct{}, maximumConcurrentTOSCTLCommands)
		}
		sink.executableMu.Unlock()
		return nil
	}
	enrolled := *sink.executableIdentity
	sink.executableMu.Unlock()
	identity, err := identifyTOSCTLExecutable(sink.Executable)
	if err != nil || enrolled != identity {
		return errors.New("enrolled tosctl executable identity changed")
	}
	return nil
}

func (sink *TOSCTLPaymentSink) runPinnedTOSCTL(ctx context.Context, args, environment []string) ([]byte, error) {
	if sink == nil || ctx == nil {
		return nil, errors.New("tosctl command is unavailable")
	}
	sink.executableMu.Lock()
	if sink.executableLaunches == nil {
		sink.executableLaunches = make(chan struct{}, maximumConcurrentTOSCTLCommands)
	}
	launches := sink.executableLaunches
	sink.executableMu.Unlock()
	select {
	case launches <- struct{}{}:
		defer func() { <-launches }()
	case <-ctx.Done():
		return nil, errors.New("tosctl command did not acquire a bounded launch slot")
	}
	if err := sink.pinTOSCTLExecutable(); err != nil {
		return nil, errors.New("tosctl executable is untrusted")
	}
	sink.executableMu.Lock()
	fd, duplicateErr := unix.FcntlInt(sink.executableSnapshot.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	sink.executableMu.Unlock()
	if duplicateErr != nil {
		return nil, errors.New("duplicate sealed tosctl launch image")
	}
	executable := os.NewFile(uintptr(fd), "openfox-tosctl-launch")
	defer executable.Close()

	// Execute the sealed snapshot, not the pathname. A rename, symlink swap or
	// in-place write after verification therefore cannot change the bytes the
	// kernel starts.
	command := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	command.ExtraFiles = []*os.File{executable}
	command.Env = append([]string(nil), environment...)
	command.SysProcAttr = tosctlProcessContainment()
	command.WaitDelay = 2 * time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		// Killing namespace PID 1 is the containment operation: the kernel then
		// kills every process remaining in the PID namespace, including detached
		// sessions that no longer share the leader's process group.
		if err := unix.Kill(command.Process.Pid, unix.SIGKILL); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	output := &tosctlSharedOutput{}
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.New("create bounded tosctl stdout pipe")
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		return nil, errors.New("create bounded tosctl stderr pipe")
	}
	command.Stdout, command.Stderr = stdoutWrite, stderrWrite
	if err := command.Start(); err != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		_ = stderrRead.Close()
		_ = stderrWrite.Close()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
			errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, errTOSCTLProcessContainmentUnavailable
		}
		return nil, errors.New("sealed tosctl command failed to start")
	}
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	copyDone := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(tosctlOutputWriter{output: output}, stdoutRead)
		copyDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(tosctlOutputWriter{output: output, stderr: true}, stderrRead)
		copyDone <- copyErr
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	var runErr error
	readersDone := 0
	waitConsumed := false
	contextDone := ctx.Done()
	for runErr == nil {
		select {
		case waitErr := <-waitDone:
			waitConsumed = true
			runErr = waitErr
			if runErr == nil {
				runErr = errTOSCTLProcessExited
			}
		case copyErr := <-copyDone:
			readersDone++
			if copyErr != nil {
				runErr = copyErr
			}
		case <-contextDone:
			_ = command.Cancel()
			contextDone = nil
		}
	}
	// A successful namespace-leader exit is represented by the private sentinel
	// above. Linux tears down its PID namespace before any detached descendant
	// can retain output pipes or continue a custody side effect.
	_ = command.Cancel()
	if errors.Is(runErr, errTOSCTLProcessExited) {
		runErr = nil
	}
	if runErr != nil && !waitConsumed {
		select {
		case waitErr := <-waitDone:
			if runErr == nil {
				runErr = waitErr
			}
		case <-time.After(command.WaitDelay):
		}
	}
	deadline := time.NewTimer(command.WaitDelay)
	for readersDone < 2 {
		select {
		case <-copyDone:
			readersDone++
		case <-deadline.C:
			_ = stdoutRead.Close()
			_ = stderrRead.Close()
			readersDone = 2
		}
	}
	if !deadline.Stop() {
		select {
		case <-deadline.C:
		default:
		}
	}
	_ = stdoutRead.Close()
	_ = stderrRead.Close()
	stdout, stderrSeen, exceeded := output.result()
	if exceeded {
		return nil, errors.New("tosctl output exceeded its shared byte budget")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, errors.New("tosctl command did not complete before its deadline")
	}
	if runErr != nil {
		return nil, errors.New("tosctl command failed")
	}
	if stderrSeen {
		return nil, errors.New("tosctl emitted unexpected stderr")
	}
	return stdout, nil
}

// identifyTOSCTLExecutable re-verifies the live pathname immediately before a
// launch without allocating another executable image. The actual launch still
// uses the single enrolled sealed snapshot retained by the sink.
func identifyTOSCTLExecutable(path string) (tosctlExecutableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 ||
		pathInfo.Mode().Perm()&0o022 != 0 || pathInfo.Size() <= 0 || pathInfo.Size() > maximumTOSCTLExecutableBytes {
		return tosctlExecutableIdentity{}, errors.New("invalid tosctl executable")
	}
	if err := validateTOSCTLExecutableAncestry(path); err != nil {
		return tosctlExecutableIdentity{}, err
	}
	source, err := os.Open(path)
	if err != nil {
		return tosctlExecutableIdentity{}, errors.New("open tosctl executable")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return tosctlExecutableIdentity{}, errors.New("stat tosctl executable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(pathInfo, info) || !trustedTOSCTLUID(stat.Uid) ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return tosctlExecutableIdentity{}, errors.New("tosctl executable identity is untrusted")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(source, maximumTOSCTLExecutableBytes+1))
	if err != nil || written != info.Size() || written > maximumTOSCTLExecutableBytes {
		return tosctlExecutableIdentity{}, errors.New("hash bounded tosctl executable")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return tosctlExecutableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: written, digest: digest}, nil
}

// snapshotTOSCTLExecutable verifies the complete pathname, opens the exact
// inode, hashes it, and copies it into a sealed anonymous executable. The
// returned descriptor is an immutable launch image even if the enrolled path
// is replaced immediately afterwards.
func snapshotTOSCTLExecutable(path string) (*os.File, tosctlExecutableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 ||
		pathInfo.Mode().Perm()&0o022 != 0 || pathInfo.Size() <= 0 || pathInfo.Size() > maximumTOSCTLExecutableBytes {
		return nil, tosctlExecutableIdentity{}, errors.New("invalid tosctl executable")
	}
	if err := validateTOSCTLExecutableAncestry(path); err != nil {
		return nil, tosctlExecutableIdentity{}, err
	}
	source, err := os.Open(path)
	if err != nil {
		return nil, tosctlExecutableIdentity{}, errors.New("open tosctl executable")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return nil, tosctlExecutableIdentity{}, errors.New("stat tosctl executable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(pathInfo, info) || !trustedTOSCTLUID(stat.Uid) ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, tosctlExecutableIdentity{}, errors.New("tosctl executable identity is untrusted")
	}

	fd, err := unix.MemfdCreate("openfox-tosctl", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, tosctlExecutableIdentity{}, errors.New("create sealed tosctl launch image")
	}
	snapshot := os.NewFile(uintptr(fd), "openfox-tosctl")
	closeSnapshot := true
	defer func() {
		if closeSnapshot {
			_ = snapshot.Close()
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(snapshot, hash), io.LimitReader(source, maximumTOSCTLExecutableBytes+1))
	if err != nil || written != info.Size() || written > maximumTOSCTLExecutableBytes {
		return nil, tosctlExecutableIdentity{}, errors.New("snapshot bounded tosctl executable")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	identity := tosctlExecutableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: written, digest: digest}
	if err := snapshot.Chmod(0o500); err != nil {
		return nil, tosctlExecutableIdentity{}, errors.New("protect tosctl launch image")
	}
	if _, err := unix.FcntlInt(snapshot.Fd(), unix.F_ADD_SEALS,
		unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		return nil, tosctlExecutableIdentity{}, errors.New("seal tosctl launch image")
	}
	if _, err := snapshot.Seek(0, 0); err != nil {
		return nil, tosctlExecutableIdentity{}, errors.New("rewind tosctl launch image")
	}
	closeSnapshot = false
	return snapshot, identity, nil
}

func validateTOSCTLExecutableAncestry(path string) error {
	directories := make([]string, 0, 16)
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		directories = append(directories, directory)
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	restrictedToOwner := false
	for index := len(directories) - 1; index >= 0; index-- {
		directory := directories[index]
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("tosctl executable ancestry is indirect")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !trustedTOSCTLUID(stat.Uid) {
			return errors.New("tosctl executable ancestry has an untrusted owner")
		}
		if info.Mode().Perm()&0o022 != 0 && !restrictedToOwner &&
			!(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return errors.New("tosctl executable ancestry is writable by another principal")
		}
		// Once an owner-controlled ancestor denies execute/search permission to
		// group and other users, less restrictive descendant mode bits cannot be
		// reached by another non-root principal.
		if stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o011 == 0 {
			restrictedToOwner = true
		}
	}
	return nil
}

func trustedTOSCTLUID(uid uint32) bool {
	return uid == 0 || uid == uint32(os.Geteuid())
}
