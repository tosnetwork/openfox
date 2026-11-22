package fstools

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

// TestSandboxWritesNeverCollideOnTheirTemporaryName: many writers to one
// workspace at once never fail because two of them chose the same temporary
// name, and none leaves a temporary file behind.
func TestSandboxWritesNeverCollideOnTheirTemporaryName(t *testing.T) {
	const writers, rounds = 64, 200
	workspace := t.TempDir()
	sandbox := &sandboxFs{workspace: workspace}
	failures := make(chan error, writers*rounds)
	var group sync.WaitGroup
	for writer := range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			for range rounds {
				if err := sandbox.WriteFile("shared.txt", []byte{byte(writer)}); err != nil {
					failures <- err
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
		t.Fatalf("%d of %d concurrent sandbox writes failed, the first with: %v", count, writers*rounds, first)
	}
	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "shared.txt" {
		t.Fatalf("the workspace holds %d entries after the writes, want only shared.txt", len(entries))
	}
}

// TestSandboxTemporaryFileHasTheAtomicWriteName: the helper a sandbox write
// creates its temporary file with chooses the name an atomic write chooses, so
// whoever sweeps what an interrupted write left behind recognizes it, creates
// the file owner-only, and refuses a missing root or directory.
func TestSandboxTemporaryFileHasTheAtomicWriteName(t *testing.T) {
	workspace := t.TempDir()
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, name, err := fileutil.CreateTemporaryFileRoot(root, ".", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if !fileutil.IsAtomicWriteTemporaryName(filepath.Base(name)) {
		t.Fatalf("the temporary name %q is not recognized as an atomic write's", name)
	}
	info, err := os.Stat(filepath.Join(workspace, name))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the temporary file: mode %v err %v, want 0600", info, err)
	}
	if _, _, err = fileutil.CreateTemporaryFileRoot(nil, ".", 0o600); err == nil {
		t.Fatal("a temporary file was created without a root")
	}
	if _, _, err = fileutil.CreateTemporaryFileRoot(root, "", 0o600); err == nil {
		t.Fatal("a temporary file was created without a directory")
	}
	if _, _, err = fileutil.CreateTemporaryFileRoot(root, workspace, 0o600); err == nil {
		t.Fatal("a temporary file was created in an absolute directory")
	}
}
