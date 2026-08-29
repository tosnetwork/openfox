//go:build !linux

package capabilitycontrol

import "errors"

func captureQuarantineSnapshot(int, string) (quarantineSnapshot, error) {
	return quarantineSnapshot{}, errors.New("trusted quarantine snapshot capture requires Linux descriptor-relative traversal")
}

func stageQuarantineSnapshot(int, string, quarantineSnapshot) (string, error) {
	return "", errors.New("trusted quarantine publication requires Linux descriptor-relative traversal")
}

func publishStagedQuarantineSnapshot(int, string, string) error {
	return errors.New("trusted quarantine publication requires Linux descriptor-relative traversal")
}
