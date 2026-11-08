package servicebridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ensurePrivateDirectory creates directory if needed and requires an
// owner-only, non-symlink directory.
func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("servicebridge: create state directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("servicebridge: state directory must be owner-private")
	}
	return nil
}

// checkPrivateDirectory requires an existing owner-private directory that is
// not a symbolic link, without creating anything.
func checkPrivateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("servicebridge: state directory must be an existing owner-private directory")
	}
	return nil
}

// writeSynced creates a new owner-only file (never replacing one) and syncs
// it and its directory before returning.
func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist
		}
		return errors.New("servicebridge: create state file")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("servicebridge: write state file")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("servicebridge: sync state file")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("servicebridge: close state file")
	}
	return syncDirectory(filepath.Dir(path))
}

// replaceSynced atomically replaces path with data.
func replaceSynced(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".tmp-")
	if err != nil {
		return errors.New("servicebridge: create state update")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("servicebridge: protect state update")
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return errors.New("servicebridge: write state update")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("servicebridge: sync state update")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("servicebridge: close state update")
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("servicebridge: commit state update")
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("servicebridge: open state directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("servicebridge: sync state directory")
	}
	return nil
}

// readPrivateFile reads an owner-only regular file of at most limit bytes.
// A missing file is reported as os.ErrNotExist.
func readPrivateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("servicebridge: stat state file")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > limit {
		return nil, errors.New("servicebridge: state file is not an owner-only bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("servicebridge: read state file")
	}
	return data, nil
}

// readJSON strictly decodes one owner-only JSON record.
func readJSON(path string, limit int64, value any) error {
	data, err := readPrivateFile(path, limit)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("servicebridge: decode state record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("servicebridge: trailing state record data")
	}
	return nil
}
