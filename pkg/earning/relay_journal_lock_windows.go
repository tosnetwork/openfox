//go:build windows

package earning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateRelayJournalDirectorySecurity(directory string) error {
	encoded, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return errors.New("encode relay journal directory path")
	}
	handle, err := windows.CreateFile(encoded, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("open relay journal directory security")
	}
	defer windows.CloseHandle(handle)
	if err := validateRelayWindowsHandle(handle, true); err != nil {
		return err
	}
	return protectRelayWindowsHandle(handle, true)
}

func acquireRelayJournalLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, relayJournalLockFile)
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("encode relay journal lock path")
	}
	handle, err := windows.CreateFile(encoded, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("open relay journal process lock")
	}
	if err := validateRelayWindowsHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("relay journal lock is not a regular non-reparse file")
	}
	if err := protectRelayWindowsHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("relay journal lock DACL is not owner-only")
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("relay journal is already open by another process")
	}
	lock := os.NewFile(uintptr(handle), path)
	if lock == nil {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap relay journal process lock")
	}
	return lock, nil
}

func acquireRelayJournalLockRoot(root *os.Root) (*os.File, error) {
	return acquireRootedWindowsLock(root, relayJournalLockFile, "relay journal")
}

func releaseRelayJournalLock(lock *os.File) error {
	handle := windows.Handle(lock.Fd())
	var overlapped windows.Overlapped
	if err := windows.UnlockFileEx(handle, 0, 1, 0, &overlapped); err != nil {
		_ = lock.Close()
		return errors.New("unlock relay journal")
	}
	if err := lock.Close(); err != nil {
		return errors.New("close relay journal lock")
	}
	return nil
}

func openRelayJournalFile(path string) (*os.File, error) {
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("encode relay journal path")
	}
	handle, err := windows.CreateFile(encoded, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("open relay journal")
	}
	if err := validateRelayWindowsHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("relay journal is not a regular non-reparse file")
	}
	if err := protectRelayWindowsHandle(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("relay journal DACL is not owner-only")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap relay journal file")
	}
	return file, nil
}

func relayJournalFileInfoSecure(info os.FileInfo) bool {
	// DACL and reparse-point validation are performed on the opened handle in
	// openRelayJournalFile. Windows FileMode permission bits do not encode ACLs.
	return info != nil && info.Mode().IsRegular()
}

func validateRelayJournalOpenedFile(file *os.File, info os.FileInfo) error {
	if file == nil || !relayJournalFileInfoSecure(info) ||
		validateRelayWindowsHandle(windows.Handle(file.Fd()), false) != nil ||
		verifyRelayWindowsHandleProtection(windows.Handle(file.Fd()), false) != nil {
		return errors.New("relay journal DACL is not owner-only")
	}
	return nil
}

func protectRootedJournalFile(root *os.Root, name string) error {
	if root == nil || name == "" {
		return errors.New("rooted relay journal path is unavailable")
	}
	// Windows prevents renaming an opened os.Root directory. Protect through
	// its verified name, then re-open through the retained root and prove that
	// the exact resulting file carries the protected owner-only DACL.
	if err := protectRelayWindowsPath(filepath.Join(root.Name(), name), false); err != nil {
		return err
	}
	file, err := openRelayJournalRootFile(root, name)
	if err != nil {
		return err
	}
	return file.Close()
}

func writeRelayJournalAtomic(directory, path string, data []byte) error {
	temporary := filepath.Join(directory, fmt.Sprintf(".agent-relay-%d-%d.tmp", os.Getpid(), time.Now().UnixNano()))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create relay journal temporary file")
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if err := protectRelayWindowsPath(temporary, false); err != nil {
		return errors.New("protect relay journal temporary file DACL")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("write relay journal temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("flush relay journal temporary file")
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.New("protect relay journal temporary file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close relay journal temporary file")
	}
	from, fromErr := windows.UTF16PtrFromString(temporary)
	to, toErr := windows.UTF16PtrFromString(path)
	if fromErr != nil || toErr != nil || windows.MoveFileEx(from, to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH) != nil {
		return errors.New("atomically replace and flush relay journal")
	}
	cleanup = false
	encodedDirectory, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return errors.New("encode relay journal directory path")
	}
	directoryHandle, err := windows.CreateFile(encodedDirectory, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("open relay journal directory for flush")
	}
	if err := validateRelayWindowsHandle(directoryHandle, true); err != nil {
		_ = windows.CloseHandle(directoryHandle)
		return errors.New("relay journal directory is a reparse point")
	}
	if err := protectRelayWindowsHandle(directoryHandle, true); err != nil {
		_ = windows.CloseHandle(directoryHandle)
		return errors.New("relay journal directory DACL is not owner-only")
	}
	if err := windows.FlushFileBuffers(directoryHandle); err != nil {
		_ = windows.CloseHandle(directoryHandle)
		return errors.New("flush relay journal directory")
	}
	if err := windows.CloseHandle(directoryHandle); err != nil {
		return errors.New("close flushed relay journal directory")
	}
	return nil
}

func validateRelayWindowsHandle(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("relay path is unavailable or a reparse point")
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		return errors.New("relay path type is invalid")
	}
	return nil
}

func protectRelayWindowsPath(path string, directory bool) error {
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	handle, err := windows.CreateFile(encoded, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		flags, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := validateRelayWindowsHandle(handle, directory); err != nil {
		return err
	}
	return protectRelayWindowsHandle(handle, directory)
}

// protectRelayWindowsHandle installs and then re-reads a protected DACL with
// exactly one ACE for the effective process owner. Windows does not implement
// POSIX 0600/0700 semantics through os.Chmod, so any inability to prove this
// boundary fails closed before protected BOC or recovery-token bytes are used.
func protectRelayWindowsHandle(handle windows.Handle, directory bool) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.New("resolve relay journal owner SID")
	}
	ownerDescriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil || ownerDescriptor == nil {
		return errors.New("read relay journal owner")
	}
	owner, _, err := ownerDescriptor.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return errors.New("relay journal path is owned by another principal")
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID,
			TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)},
	}}, nil)
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return err
	}
	return verifyRelayWindowsHandleProtection(handle, directory)
}

// verifyRelayWindowsHandleProtection proves the owner-only DACL without
// mutating it. It is safe for read-only os.Root.Open handles, unlike
// protectRelayWindowsHandle which legitimately requires WRITE_DAC.
func verifyRelayWindowsHandleProtection(handle windows.Handle, directory bool) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.New("resolve relay journal owner SID")
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return errors.New("re-read relay journal DACL")
	}
	verifiedOwner, _, err := descriptor.Owner()
	if err != nil || verifiedOwner == nil || !windows.EqualSid(verifiedOwner, user.User.Sid) {
		return errors.New("relay journal owner changed while protecting DACL")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("relay journal DACL inheritance remains enabled")
	}
	verifiedACL, _, err := descriptor.DACL()
	if err != nil || verifiedACL == nil || verifiedACL.AceCount != 1 {
		return errors.New("relay journal DACL contains additional principals")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(verifiedACL, 0, &ace); err != nil || ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != windows.GENERIC_ALL ||
		uint32(ace.Header.AceFlags) != inheritance {
		return errors.New("relay journal owner ACE is invalid")
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !windows.EqualSid(aceSID, user.User.Sid) {
		return errors.New("relay journal DACL grants another principal")
	}
	return nil
}
