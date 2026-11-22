package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestWriteFileAtomicTemporaryNamesNeverCollide: many writers to one directory
// at once never fail because two of them chose the same temporary name, by
// path and through a directory capability.
func TestWriteFileAtomicTemporaryNamesNeverCollide(t *testing.T) {
	const writers, rounds = 64, 200
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, write := range map[string]func(data []byte) error{
		"by path": func(data []byte) error {
			return WriteFileAtomic(filepath.Join(directory, "by-path.txt"), data, 0o600)
		},
		"through a root": func(data []byte) error { return WriteFileAtomicRoot(root, "rooted.txt", data, 0o600) },
	} {
		failures := make(chan error, writers*rounds)
		var group sync.WaitGroup
		for writer := range writers {
			group.Add(1)
			go func() {
				defer group.Done()
				for range rounds {
					if writeErr := write([]byte{byte(writer)}); writeErr != nil {
						failures <- writeErr
					}
				}
			}()
		}
		group.Wait()
		close(failures)
		count := 0
		var first error
		for failure := range failures {
			if first == nil {
				first = failure
			}
			count++
		}
		if count != 0 {
			t.Errorf("%s: %d of %d concurrent writes failed, the first with: %v", name, count, writers*rounds, first)
		}
	}
}

// useTemporaryNames makes the atomic writes of this test choose the given
// temporary names in order, and then names of their own again.
func useTemporaryNames(t *testing.T, names ...string) {
	t.Helper()
	original := temporaryName
	t.Cleanup(func() { temporaryName = original })
	temporaryName = func() (string, error) {
		if len(names) == 0 {
			return original()
		}
		name := names[0]
		names = names[1:]
		return name, nil
	}
}

// TestAtomicWriteChoosesAnotherNameWhenItsTemporaryNameIsTaken: a temporary
// name another writer already holds does not fail the write and does not
// touch that writer's file; the write takes another name. When every name it
// tries is taken, the write fails with the name collision and leaves the
// target and the other writers' files as they were.
func TestAtomicWriteChoosesAnotherNameWhenItsTemporaryNameIsTaken(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	taken := []string{".tmp-1-1-0000000000000001", ".tmp-1-1-0000000000000002"}
	for _, name := range taken {
		if err = os.WriteFile(filepath.Join(directory, name), []byte("another writer's"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	othersUntouched := func(when string) {
		t.Helper()
		for _, name := range taken {
			content, readErr := os.ReadFile(filepath.Join(directory, name))
			if readErr != nil || string(content) != "another writer's" {
				t.Fatalf("%s: another writer's temporary file %s was touched: %q %v", when, name, content, readErr)
			}
		}
	}
	target := filepath.Join(directory, "target.txt")
	for name, write := range map[string]func(data []byte) error{
		"by path":        func(data []byte) error { return WriteFileAtomic(target, data, 0o600) },
		"through a root": func(data []byte) error { return WriteFileAtomicRoot(root, "target.txt", data, 0o600) },
	} {
		useTemporaryNames(t, taken...)
		if err = write([]byte("written " + name)); err != nil {
			t.Fatalf("%s: a write whose first two temporary names were taken: %v", name, err)
		}
		if content, readErr := os.ReadFile(target); readErr != nil || string(content) != "written "+name {
			t.Fatalf("%s: the target holds %q: %v", name, content, readErr)
		}
		othersUntouched(name)

		// Exactly as many taken names as the write tries.
		always := make([]string, 0, temporaryNameAttempts)
		for len(always) < temporaryNameAttempts {
			always = append(always, taken[0])
		}
		useTemporaryNames(t, always...)
		if err = write([]byte("never written")); !errors.Is(err, os.ErrExist) {
			t.Fatalf("%s: a write whose every temporary name was taken: got %v, want the name collision", name, err)
		}
		if content, readErr := os.ReadFile(target); readErr != nil || string(content) != "written "+name {
			t.Fatalf("%s: the failed write changed the target to %q: %v", name, content, readErr)
		}
		othersUntouched(name + ", every name taken")
	}
}

// TestAtomicWriteTemporaryNamesAreRecognized: the name an atomic write gives
// its temporary file is the shape IsAtomicWriteTemporaryName recognizes, so
// what an interrupted write leaves behind can be found, and nothing else is
// mistaken for it.
func TestAtomicWriteTemporaryNamesAreRecognized(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		name, err := temporaryName()
		if err != nil {
			t.Fatal(err)
		}
		if !IsAtomicWriteTemporaryName(name) {
			t.Fatalf("the temporary name %q is not recognized", name)
		}
		if seen[name] {
			t.Fatalf("the temporary name %q was chosen twice", name)
		}
		seen[name] = true
	}
	// The name is also the one a write really uses: a write interrupted before
	// its rename leaves a file of that shape.
	directory := t.TempDir()
	var used string
	file, name, err := createTemporaryFile(directory, func(name string) (*os.File, error) {
		used = name
		return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if name != used || filepath.Dir(name) != directory || !IsAtomicWriteTemporaryName(filepath.Base(name)) {
		t.Fatalf("the temporary file %q is not a recognized name in %s", name, directory)
	}
	for _, other := range []string{
		"", ".tmp-", ".tmp-notes", ".tmp-1-2", ".tmp-1-2-", ".tmp--2-ab", ".tmp-1--ab", ".tmp-1-2-AB", ".tmp-1-2-xyz",
		".tmp-1-2-ab-cd", ".tmp-a-2-ab", ".tmp-1-b-ab", "tmp-1-2-ab", "x.tmp-1-2-ab", ".tmp-1-2-ab.json",
	} {
		if IsAtomicWriteTemporaryName(other) {
			t.Errorf("%q is recognized as an atomic-write temporary name", other)
		}
	}
}
