package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/tosnetwork/openfox/pkg/logger"
)

// ExtractZipFile extracts a ZIP archive from disk to targetDir.
// It reads entries one at a time from disk, keeping memory usage minimal.
//
// Security: rejects path traversal attempts and symlinks.
func ExtractZipFile(zipPath string, targetDir string) error {
	const (
		maxEntries       = 4096
		maxExpandedBytes = 64 << 20
		maxDepth         = 16
	)
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("invalid ZIP: %w", err)
	}
	defer reader.Close()

	logger.DebugCF("zip", "Extracting ZIP", map[string]any{
		"zip_path":   zipPath,
		"target_dir": targetDir,
		"entries":    len(reader.File),
	})

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("failed to create target dir: %w", err)
	}

	if len(reader.File) > maxEntries {
		return fmt.Errorf("zip has too many entries: %d", len(reader.File))
	}
	seen := make(map[string]string, len(reader.File))
	var expanded uint64
	for _, f := range reader.File {
		if !utf8.ValidString(f.Name) || !norm.NFC.IsNormalString(f.Name) {
			return fmt.Errorf("zip entry name is not canonical UTF-8/NFC: %q", f.Name)
		}
		// Path traversal protection.
		cleanName := filepath.Clean(f.Name)
		if cleanName == "." || strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) ||
			strings.Contains(f.Name, "\\") || len(strings.Split(filepath.ToSlash(cleanName), "/")) > maxDepth {
			return fmt.Errorf("zip entry has unsafe path: %q", f.Name)
		}
		collisionKey := strings.ToLower(filepath.ToSlash(cleanName))
		if prior, exists := seen[collisionKey]; exists {
			return fmt.Errorf("zip entries collide: %q and %q", prior, f.Name)
		}
		seen[collisionKey] = f.Name
		if f.UncompressedSize64 > maxExpandedBytes-expanded {
			return fmt.Errorf("zip expanded data exceeds %d bytes", maxExpandedBytes)
		}
		expanded += f.UncompressedSize64

		destPath := filepath.Join(targetDir, cleanName)

		// Double-check the resolved path is within target directory (defense-in-depth).
		targetDirClean := filepath.Clean(targetDir)
		if !strings.HasPrefix(filepath.Clean(destPath), targetDirClean+string(filepath.Separator)) &&
			filepath.Clean(destPath) != targetDirClean {
			return fmt.Errorf("zip entry escapes target dir: %q", f.Name)
		}

		mode := f.FileInfo().Mode()

		// Reject any symlink.
		if mode&os.ModeType != 0 && !mode.IsDir() || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return fmt.Errorf("zip contains unsupported file mode for %q", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return err
			}
			continue
		}

		// Ensure parent directory exists.
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return err
		}

		if err := extractSingleFile(f, destPath); err != nil {
			return err
		}
	}

	return nil
}

// extractSingleFile extracts one zip.File entry to destPath, with a size check.
func extractSingleFile(f *zip.File, destPath string) error {
	const maxFileSize = 5 * 1024 * 1024 // 5MB, adjust as appropriate

	// Check the uncompressed size from the header, if available.
	if f.UncompressedSize64 > maxFileSize {
		return fmt.Errorf("zip entry %q is too large (%d bytes)", f.Name, f.UncompressedSize64)
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("failed to open zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file %q: %w", destPath, err)
	}
	// We don't return the close error via return, since it's not a named error return.
	// Instead, we log to stderr and remove the partially written file as defensive cleanup.
	defer func() {
		if cerr := outFile.Close(); cerr != nil {
			_ = os.Remove(destPath)
			logger.ErrorCF("zip", "Failed to close file", map[string]any{
				"dest_path": destPath,
				"error":     cerr.Error(),
			})
		}
	}()

	// Streamed size check: prevent overruns and malicious/corrupt headers.
	written, err := io.CopyN(outFile, rc, maxFileSize+1)
	if err != nil && err != io.EOF {
		_ = os.Remove(destPath)
		return fmt.Errorf("failed to extract %q: %w", f.Name, err)
	}
	if written > maxFileSize {
		_ = os.Remove(destPath)
		return fmt.Errorf("zip entry %q exceeds max size (%d bytes)", f.Name, written)
	}

	return nil
}
