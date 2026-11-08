package servicebridge

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const (
	crashChildEnv   = "SERVICEBRIDGE_WRITE_SYNCED_CHILD"
	crashChildBytes = 64 << 20
)

func crashPayload() []byte {
	return bytes.Repeat([]byte("0123456789abcdef"), crashChildBytes/16)
}

// The child half: write the payload and exit; the parent kills it midway.
func TestWriteSyncedCrashChild(t *testing.T) {
	path := os.Getenv(crashChildEnv)
	if path == "" {
		t.Skip("runs only as the child of TestAKilledWriteNeverLeavesATruncatedStateFile")
	}
	if err := writeSynced(path, crashPayload()); err != nil {
		t.Fatal(err)
	}
}

// A process killed while it creates a state file must leave either no file
// or the whole file, never an empty or truncated one a retry cannot repair.
func TestAKilledWriteNeverLeavesATruncatedStateFile(t *testing.T) {
	if os.Getenv(crashChildEnv) != "" {
		t.Skip("the child does not recurse")
	}
	want := crashPayload()
	killed := 0
	for round := 0; round < 12; round++ {
		directory := t.TempDir()
		path := filepath.Join(directory, "result")
		child := exec.Command(os.Args[0], "-test.run=^TestWriteSyncedCrashChild$", "-test.count=1")
		child.Env = append(os.Environ(), crashChildEnv+"="+path)
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		// Kill once the write has started: some file exists in the directory.
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if entries, err := os.ReadDir(directory); err == nil && len(entries) > 0 {
				break
			}
			time.Sleep(200 * time.Microsecond)
		}
		time.Sleep(time.Duration(rand.IntN(25_000)) * time.Microsecond)
		if err := child.Process.Signal(syscall.SIGKILL); err == nil {
			killed++
		}
		_ = child.Wait()
		got, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d: a killed write left %d of %d bytes at the final path", round, len(got), len(want))
		}
	}
	if killed == 0 {
		t.Fatal("no child was killed before it finished; the test exercised nothing")
	}
}

func TestWriteSyncedRefusesToReplaceAndLeavesNoTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "record")
	if err := writeSynced(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(path, []byte("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("an existing file was not refused: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "first" {
		t.Fatalf("the existing file changed: %q %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v %v", info.Mode(), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files were left behind: %d %v", len(entries), err)
	}
}
