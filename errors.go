package hwvault

import "errors"

// Sentinel errors returned by hwvault. Callers should use errors.Is to
// check for these, since they may be wrapped with additional context.
var (
	// ErrDecryptionFailed is returned when decryption fails, typically
	// because the file was copied to a different machine, the hardware
	// configuration changed, or the file was corrupted/tampered with.
	ErrDecryptionFailed = errors.New("hwvault: decryption failed")

	// ErrHWIDUnavailable is returned when the hardware ID could not be
	// retrieved (e.g. insufficient permissions or unsupported environment).
	ErrHWIDUnavailable = errors.New("hwvault: hardware id unavailable")

	// ErrInvalidData is returned when the encrypted data format is
	// malformed (e.g. too short to contain the required header fields).
	ErrInvalidData = errors.New("hwvault: invalid data")

	// ErrUnsupportedVersion is returned when the stored data's version
	// byte is not supported by this version of hwvault. Callers should
	// treat this the same as ErrDecryptionFailed (delete data, prompt
	// re-login).
	ErrUnsupportedVersion = errors.New("hwvault: unsupported version")
)
