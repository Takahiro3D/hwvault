package hwvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/denisbrodbeck/machineid"
)

// currentVersion is the on-disk format version written by Encrypt/Save.
// See docs/ARCHITECTURE.md "version フィールドの運用方針" for the policy
// governing when this value is incremented.
const currentVersion byte = 0x01

// nonceSize is the size (in bytes) of the AES-GCM nonce.
const nonceSize = 12

// gcmTagSize is the size (in bytes) of the AES-GCM authentication tag.
const gcmTagSize = 16

// headerSize is the number of bytes preceding the ciphertext:
// 1 byte version + nonceSize bytes nonce.
const headerSize = 1 + nonceSize

// hwID retrieves the hardware-unique ID for the current machine.
func hwID() (string, error) {
	id, err := machineid.ID()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHWIDUnavailable, err)
	}
	return id, nil
}

// deriveKey derives a 256-bit AES key from the hardware ID and the
// application-provided salt using HMAC-SHA256.
func deriveKey(salt string) ([]byte, error) {
	id, err := hwID()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(id))
	return mac.Sum(nil), nil
}

// newGCM builds an AES-256-GCM AEAD cipher from the given key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

// Encrypt encrypts plainText using a key derived from the local hardware ID
// and salt, and returns the resulting bytes in the on-disk format:
//
//	[ version(1byte) | nonce(12byte) | ciphertext+tag(...byte) ]
//
// Decryption is only possible on the same machine (see ErrHWIDUnavailable /
// ErrDecryptionFailed).
func Encrypt(plainText string, salt string) ([]byte, error) {
	key, err := deriveKey(salt)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("hwvault: failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plainText), nil)

	out := make([]byte, 0, headerSize+len(ciphertext))
	out = append(out, currentVersion)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt decrypts data previously produced by Encrypt (or Save), using a
// key derived from the local hardware ID and salt.
//
// It returns ErrUnsupportedVersion if the data's version byte is not
// recognized, ErrInvalidData if the data is malformed, and
// ErrDecryptionFailed if authentication/decryption fails (e.g. the data was
// encrypted on a different machine, the hardware changed, or the data was
// tampered with).
func Decrypt(cipherData []byte, salt string) (string, error) {
	if len(cipherData) < 1 {
		return "", ErrInvalidData
	}

	version := cipherData[0]
	if version != currentVersion {
		return "", ErrUnsupportedVersion
	}

	if len(cipherData) < headerSize+gcmTagSize {
		return "", ErrInvalidData
	}

	nonce := cipherData[1:headerSize]
	ciphertext := cipherData[headerSize:]

	key, err := deriveKey(salt)
	if err != nil {
		return "", err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plain), nil
}
