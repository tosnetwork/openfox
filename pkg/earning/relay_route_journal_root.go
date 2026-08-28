package earning

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/tosnetwork/openfox/pkg/fileutil"
)

// relayPinnedDirectory is a retained directory capability. The absolute path
// is used only to prove that the operator-configured namespace still names the
// retained directory; all data operations are relative to root. A rename or a
// transient replacement can therefore only make an operation fail closed --
// it can never redirect journal bytes into another directory.
type relayPinnedDirectory struct {
	path     string
	root     *os.Root
	poisoned atomic.Bool
}

func openRelayPinnedDirectory(path string) (*relayPinnedDirectory, error) {
	before, err := os.Lstat(path)
	if err != nil || !relayPinnedDirectoryInfoSecure(before) || before.Mode()&os.ModeSymlink != 0 ||
		validateRelayJournalDirectorySecurity(path) != nil {
		return nil, errors.New("relay journal directory identity is invalid")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("open relay journal directory capability")
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) || secureRelayPinnedDirectory(root, ".") != nil {
		_ = root.Close()
		return nil, errors.New("relay journal directory changed while opening")
	}
	return &relayPinnedDirectory{path: path, root: root}, nil
}

func (directory *relayPinnedDirectory) close() error {
	if directory == nil || directory.root == nil {
		return nil
	}
	err := directory.root.Close()
	directory.root = nil
	if err != nil {
		return errors.New("close relay journal directory capability")
	}
	return nil
}

func (directory *relayPinnedDirectory) ensureAttached() error {
	if directory != nil && directory.poisoned.Load() {
		return errors.New("relay journal storage identity is permanently unavailable")
	}
	if directory == nil || directory.root == nil || !filepath.IsAbs(directory.path) ||
		filepath.Clean(directory.path) != directory.path {
		if directory != nil {
			directory.poisoned.Store(true)
		}
		return errors.New("relay journal storage identity is unavailable")
	}
	opened, openErr := directory.root.Stat(".")
	current, pathErr := os.Lstat(directory.path)
	if openErr != nil || pathErr != nil || opened == nil || current == nil || !opened.IsDir() ||
		!current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		directory.poisoned.Store(true)
		return errors.New("relay journal storage directory was replaced")
	}
	if !relayPinnedDirectoryInfoSecure(opened) || !relayPinnedDirectoryInfoSecure(current) ||
		secureRelayPinnedDirectory(directory.root, ".") != nil {
		return errors.New("relay journal storage directory is not owner-private")
	}
	return nil
}

func (directory *relayPinnedDirectory) poison() {
	if directory != nil {
		directory.poisoned.Store(true)
	}
}

func relayPinnedName(name string, allowDot bool) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name ||
		(!allowDot && name == ".") || !filepath.IsLocal(name) {
		return "", errors.New("relay journal rooted name is invalid")
	}
	return name, nil
}

func (directory *relayPinnedDirectory) ensureChild(name string, child *relayPinnedDirectory) error {
	name, err := relayPinnedName(name, false)
	if err != nil || child == nil || directory.ensureAttached() != nil || child.ensureAttached() != nil {
		return errors.New("relay journal child directory identity is unavailable")
	}
	parentInfo, parentErr := directory.root.Lstat(name)
	childInfo, childErr := child.root.Stat(".")
	if parentErr != nil || childErr != nil || parentInfo == nil || childInfo == nil ||
		!parentInfo.IsDir() || !childInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(parentInfo, childInfo) {
		directory.poison()
		child.poison()
		return errors.New("relay journal child directory was replaced")
	}
	if !relayPinnedDirectoryInfoSecure(parentInfo) || !relayPinnedDirectoryInfoSecure(childInfo) ||
		secureRelayPinnedDirectory(child.root, ".") != nil {
		return errors.New("relay journal child directory is not owner-private")
	}
	return nil
}

func (directory *relayPinnedDirectory) mkdir(name string) error {
	name, err := relayPinnedName(name, false)
	if err != nil || directory.ensureAttached() != nil {
		return errors.New("relay journal storage identity is unavailable")
	}
	if err := directory.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		directory.poison()
		return errors.New("create rooted relay journal directory")
	}
	info, err := directory.root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !relayPinnedDirectoryInfoSecure(info) ||
		protectRelayPinnedDirectory(directory.root, name) != nil {
		directory.poison()
		return errors.New("rooted relay journal directory is not owner-private")
	}
	return directory.ensureAttached()
}

func (directory *relayPinnedDirectory) openFile(name string) (*os.File, error) {
	name, err := relayPinnedName(name, false)
	if err != nil || directory.ensureAttached() != nil {
		return nil, errors.New("relay journal storage identity is unavailable")
	}
	before, err := directory.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !relayJournalFileInfoSecure(before) {
		return nil, errors.New("relay journal file identity is invalid")
	}
	file, err := openRelayJournalRootFile(directory.root, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errors.New("open rooted relay journal file")
	}
	opened, openErr := file.Stat()
	after, afterErr := directory.root.Lstat(name)
	if openErr != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 ||
		!relayJournalFileInfoSecure(opened) || !relayJournalFileInfoSecure(after) ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) || directory.ensureAttached() != nil {
		_ = file.Close()
		return nil, errors.New("relay journal file changed while opening")
	}
	return file, nil
}

func (directory *relayPinnedDirectory) lstat(name string) (os.FileInfo, error) {
	name, err := relayPinnedName(name, true)
	if err != nil || directory.ensureAttached() != nil {
		return nil, errors.New("relay journal storage identity is unavailable")
	}
	info, err := directory.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if directory.ensureAttached() != nil {
		return nil, errors.New("relay journal storage directory was replaced")
	}
	return info, nil
}

func (directory *relayPinnedDirectory) readDir(name string) ([]os.DirEntry, error) {
	name, err := relayPinnedName(name, true)
	if err != nil || directory.ensureAttached() != nil {
		return nil, errors.New("relay journal storage identity is unavailable")
	}
	before, err := directory.root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !relayPinnedDirectoryInfoSecure(before) {
		return nil, errors.New("relay journal directory identity is invalid")
	}
	file, err := directory.root.Open(name)
	if err != nil {
		return nil, errors.New("open rooted relay journal directory")
	}
	defer file.Close()
	opened, openErr := file.Stat()
	after, afterErr := directory.root.Lstat(name)
	if openErr != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 ||
		!relayPinnedDirectoryInfoSecure(opened) || !relayPinnedDirectoryInfoSecure(after) ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) ||
		secureRelayPinnedDirectory(directory.root, name) != nil {
		return nil, errors.New("relay journal directory changed while opening")
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, errors.New("read rooted relay journal directory")
	}
	final, finalErr := directory.root.Lstat(name)
	if finalErr != nil || !os.SameFile(opened, final) || directory.ensureAttached() != nil {
		return nil, errors.New("relay journal directory changed while reading")
	}
	return entries, nil
}

func (directory *relayPinnedDirectory) writeAtomic(name string, data []byte) error {
	name, err := relayPinnedName(name, false)
	if err != nil || directory.ensureAttached() != nil {
		return errors.New("relay journal storage identity is unavailable")
	}
	if err := fileutil.WriteFileAtomicRoot(directory.root, name, data, 0o600); err != nil {
		directory.poison()
		return errors.New("write rooted relay journal file")
	}
	if err := protectRootedJournalFile(directory.root, name); err != nil {
		directory.poison()
		return errors.New("protect rooted relay journal file")
	}
	file, err := directory.openFile(name)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return errors.New("close verified rooted relay journal file")
	}
	return directory.ensureAttached()
}

func (directory *relayPinnedDirectory) remove(name string) error {
	name, err := relayPinnedName(name, false)
	if err != nil || directory.ensureAttached() != nil {
		return errors.New("relay journal storage identity is unavailable")
	}
	if err := directory.root.Remove(name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		directory.poison()
		return err
	}
	return directory.ensureAttached()
}

func relayPinnedDirectoryInfoSecure(info os.FileInfo) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	return relayPinnedDirectoryOwnerSecure(info)
}
