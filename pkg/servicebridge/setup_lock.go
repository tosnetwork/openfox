package servicebridge

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrSetupBusy reports that another init, offer or withdraw run holds the
// state directory.
var ErrSetupBusy = errors.New("servicebridge: another init, offer or withdraw run is in progress for this state " +
	"directory; this run read nothing, signed nothing and sent nothing")

const setupLockFile = "run.lock"

// lockSetup takes the state directory's exclusive run lock without
// waiting. init, offer, withdraw and withdraw --acknowledge each read a
// journal or a record, decide, and then send or write; two of them running
// at once would both read the same "nothing sent yet", draw different
// nonces or query ids, and both send. The lock is taken before the rail
// configuration and the journal are read and is held until the command
// returns. The kernel drops it when the process dies, so a killed run
// never leaves it behind.
//
// serve does not take it: it never reads or writes the setup journal or a
// withdrawal record, and withdrawing beside a serving node is the intended
// use.
func lockSetup(stateDir string) (release func(), err error) {
	if !cleanAbsolute(stateDir) {
		return nil, errors.New("servicebridge: state_dir must be absolute and clean")
	}
	if err = ensurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	directory := filepath.Join(stateDir, setupDirectory)
	if err = ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	lock, err := acquireRunLock(filepath.Join(directory, setupLockFile))
	if err != nil {
		return nil, err
	}
	return func() { releaseRunLock(lock) }, nil
}

// loadConfigLocked reads the rail configuration under its state
// directory's run lock. The configuration names the state directory, so it
// is read once to find the lock and again once the lock is held; the second
// read is the one the command uses.
func loadConfigLocked(path string) (NodeConfig, func(), error) {
	located, err := LoadNodeConfig(path)
	if err != nil {
		return NodeConfig{}, nil, err
	}
	release, err := lockSetup(located.StateDir)
	if err != nil {
		return NodeConfig{}, nil, err
	}
	config, err := LoadNodeConfig(path)
	if err == nil && config.StateDir != located.StateDir {
		err = errors.New("servicebridge: the rail configuration's state_dir changed while its lock was taken")
	}
	if err != nil {
		release()
		return NodeConfig{}, nil, err
	}
	return config, release, nil
}

func lockFileProblem(info os.FileInfo, statErr error) bool {
	return statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600
}
