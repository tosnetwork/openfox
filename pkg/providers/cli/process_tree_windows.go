//go:build windows

package cliprovider

import (
	"os"
	"os/exec"
)

func configureProcessGroup(cmd *exec.Cmd) {}

func configureCommandCancellation(cmd *exec.Cmd) {}

func killProcessTree(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}
