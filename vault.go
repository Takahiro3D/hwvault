package hwvault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// filePerm is the permission enforced on saved vault files.
const filePerm fs.FileMode = 0o600

// dirPerm is the permission used when creating the parent directory of a
// vault file, if it does not already exist.
const dirPerm fs.FileMode = 0o700

// Save encrypts plainText using a key derived from the local hardware ID
// and salt, and writes it to filePath with permission 0600.
//
// If the parent directory of filePath does not exist, it is created
// automatically with permission 0700.
//
// Save writes to a temporary file in the same directory as filePath and
// then atomically renames it into place, so that a crash or full disk
// during the write cannot corrupt or lose an existing, valid vault file.
func Save(filePath string, plainText string, salt string) error {
	data, err := Encrypt(plainText, salt)
	if err != nil {
		return err
	}

	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return fmt.Errorf("hwvault: failed to create directory %q: %w", dir, err)
		}
	}

	tmpPath := filePath + ".tmp"

	if err := os.WriteFile(tmpPath, data, filePerm); err != nil {
		return fmt.Errorf("hwvault: failed to write temp file: %w", err)
	}

	// Ensure permission is exactly filePerm even if an existing file/umask
	// caused WriteFile to apply a different mode.
	if err := os.Chmod(tmpPath, filePerm); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("hwvault: failed to set permissions: %w", err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("hwvault: failed to finalize save: %w", err)
	}

	return nil
}

// Load reads the file at filePath and returns the decrypted string.
//
// Decryption fails (ErrDecryptionFailed) if the file was copied from
// another machine, if the hardware configuration changed since it was
// saved, or if the file was corrupted/tampered with.
//
// If the file's permissions are not 0600, Load emits a warning to stderr
// rather than failing, since strict enforcement on read could break
// legitimate use cases (e.g. files restored from backup).
func Load(filePath string, salt string) (string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("hwvault: failed to stat file: %w", err)
	}

	if info.Mode().Perm() != filePerm {
		fmt.Fprintf(os.Stderr,
			"hwvault: warning: %q has permission %04o, expected %04o\n",
			filePath, info.Mode().Perm(), filePerm)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("hwvault: failed to read file: %w", err)
	}

	return Decrypt(data, salt)
}
