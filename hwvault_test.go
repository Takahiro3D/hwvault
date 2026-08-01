package hwvault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const testSalt = "hwvault-test-salt"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	plain := "my-secret-api-key"

	data, err := Encrypt(plain, testSalt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := Decrypt(data, testSalt)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if got != plain {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plain)
	}
}

func TestEncrypt_EmptyPlainText(t *testing.T) {
	data, err := Encrypt("", testSalt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := Decrypt(data, testSalt)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestEncrypt_OutputFormat(t *testing.T) {
	data, err := Encrypt("x", testSalt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(data) < headerSize+gcmTagSize {
		t.Fatalf("output too short: %d bytes", len(data))
	}
	if data[0] != currentVersion {
		t.Fatalf("version byte = %d, want %d", data[0], currentVersion)
	}
}

func TestDecrypt_WrongSalt(t *testing.T) {
	data, err := Encrypt("secret", testSalt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(data, "different-salt")
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_TamperedData(t *testing.T) {
	data, err := Encrypt("secret", testSalt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Flip a bit in the ciphertext to trigger GCM authentication failure.
	data[len(data)-1] ^= 0xFF

	_, err = Decrypt(data, testSalt)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_UnsupportedVersion(t *testing.T) {
	data, err := Encrypt("secret", testSalt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	data[0] = 0xFF // unknown version

	_, err = Decrypt(data, testSalt)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestDecrypt_InvalidData(t *testing.T) {
	cases := [][]byte{
		{},
		{currentVersion},
		append([]byte{currentVersion}, make([]byte, nonceSize)...), // no ciphertext/tag
	}

	for i, c := range cases {
		_, err := Decrypt(c, testSalt)
		if !errors.Is(err, ErrInvalidData) {
			t.Fatalf("case %d: expected ErrInvalidData, got %v", i, err)
		}
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "credentials.vault")

	plain := "my-secret-api-key"

	if err := Save(path, plain, testSalt); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir failed: %v", err)
	}

	// Windows does not have a POSIX-style permission bit model; os.Chmod
	// on Windows can only toggle the read-only attribute, so a saved file
	// will report as 0666 (or 0444 if read-only) rather than exactly
	// 0600. Strict permission-bit checks are therefore only meaningful on
	// POSIX-like platforms (Linux/macOS). See docs/ARCHITECTURE.md for
	// details.
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != filePerm {
			t.Fatalf("file permission = %o, want %o", info.Mode().Perm(), filePerm)
		}
		if dirInfo.Mode().Perm() != dirPerm {
			t.Fatalf("dir permission = %o, want %o", dirInfo.Mode().Perm(), dirPerm)
		}
	}

	got, err := Load(path, testSalt)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got != plain {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plain)
	}

	// No leftover temp file.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected temp file to be removed, stat err = %v", err)
	}
}

func TestSave_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.vault")

	if err := Save(path, "first", testSalt); err != nil {
		t.Fatalf("first Save failed: %v", err)
	}
	if err := Save(path, "second", testSalt); err != nil {
		t.Fatalf("second Save failed: %v", err)
	}

	got, err := Load(path, testSalt)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
}

func TestLoad_WrongSalt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.vault")

	if err := Save(path, "secret", testSalt); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	_, err := Load(path, "different-salt")
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.vault")

	_, err := Load(path, testSalt)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestLoad_BadPermission_WarnsButSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.vault")

	if err := Save(path, "secret", testSalt); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	got, err := Load(path, testSalt)
	if err != nil {
		t.Fatalf("Load failed despite permission warning policy: %v", err)
	}
	if got != "secret" {
		t.Fatalf("got %q, want %q", got, "secret")
	}
}
