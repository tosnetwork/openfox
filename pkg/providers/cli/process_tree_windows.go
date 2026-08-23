//go:build windows

package cliprovider

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/tosnetwork/openfox/pkg/isolation"
)

var backendJobs sync.Map // process ID -> windows.Handle

func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB
}

func configureCommandCancellation(cmd *exec.Cmd) {
	configureProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessTree(cmd) }
}

// attachProcessTree installs a kill-on-close Job Object even when OpenFox's
// optional global isolation is disabled. When global isolation is enabled its
// stricter Job Object already owns the process tree.
func attachProcessTree(cmd *exec.Cmd) error {
	if isolation.CurrentConfig().Enabled {
		return nil
	}
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("backend process is not started")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return err
	}
	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|
			windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		_ = windows.CloseHandle(job)
		return err
	}
	if err = windows.AssignProcessToJobObject(job, process); err != nil {
		_ = windows.CloseHandle(process)
		_ = windows.CloseHandle(job)
		return err
	}
	backendJobs.Store(cmd.Process.Pid, job)
	go func(pid int, processHandle, jobHandle windows.Handle) {
		_, _ = windows.WaitForSingleObject(processHandle, windows.INFINITE)
		_ = windows.CloseHandle(processHandle)
		if stored, loaded := backendJobs.LoadAndDelete(pid); loaded && stored == jobHandle {
			_ = windows.CloseHandle(jobHandle)
		}
	}(cmd.Process.Pid, process, job)
	return nil
}

func killProcessTree(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return os.ErrProcessDone
	}
	if stored, loaded := backendJobs.LoadAndDelete(cmd.Process.Pid); loaded {
		job, _ := stored.(windows.Handle)
		err := windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(job)
		if err == nil || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil
		}
		return err
	}
	err := cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return os.ErrProcessDone
	}
	return err
}
