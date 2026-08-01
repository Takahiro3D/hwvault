# hwvault

> **Hardware-bound credential vault for Go** — Encrypts and stores credentials tied to the local machine's hardware.

[![Go Reference](https://pkg.go.dev/badge/github.com/Takahiro3D/hwvault.svg)](https://pkg.go.dev/github.com/Takahiro3D/hwvault)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 📐 For design philosophy, threat model, and architecture details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Overview

`hwvault` is a library for Go-based local CLI and desktop tools that **encrypts and stores credentials (API keys, passwords, etc.) bound to the hardware of the running machine**.

Even if the encrypted file is copied or leaked to another PC, it cannot be decrypted there (**node-lock**).

Developers can achieve secure credential storage by simply calling two APIs — `Save` and `Load` — without needing to understand the underlying security details.

---

## Features

- 🔒 **Node-locked encryption** — Uses HW-unique ID as key material; decryption on another PC is impossible
- 🛡️ **AES-256-GCM** — Industry-standard authenticated encryption with tamper detection
- 📁 **Automatic permission control** — Enforces `0600` on saved files and `0700` on directories
- 🖥️ **Cross-platform** — Supports Linux and Windows
- ✅ **Secure by Default** — API design prevents insecure usage

---

## Installation

```bash
go get github.com/Takahiro3D/hwvault
```

---

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "github.com/Takahiro3D/hwvault"
)

const appSalt = "myapp-v1-credential-salt"

func main() {
    // hwvault does not perform path resolution (e.g. "~" expansion).
    // Callers must resolve the path themselves, e.g. using os.UserHomeDir().
    home, err := os.UserHomeDir()
    if err != nil {
        log.Fatal(err)
    }
    vaultPath := filepath.Join(home, ".myapp", "credentials.vault")

    // Encrypt and save credentials to a file
    err = hwvault.Save(vaultPath, "my-secret-api-key", appSalt)
    if err != nil {
        log.Fatal(err)
    }

    // Load and decrypt credentials from the file
    secret, err := hwvault.Load(vaultPath, appSalt)
    if err != nil {
        // Reached here on HW change or file corruption → prompt user to re-login
        log.Fatal(err)
    }

    fmt.Println("Loaded credential:", secret)
}
```

> ℹ️ **Note:** `hwvault` does not perform any path resolution such as `~` expansion.
> Callers are responsible for passing an absolute (or otherwise resolvable) path.


---

## API Reference

### High-level API (Recommended)

Handles file I/O, permission management, and encryption/decryption in one call.

```go
// Save encrypts plainText and saves it to filePath with permission 0600.
// If the parent directory does not exist, it is created automatically with permission 0700.
func Save(filePath string, plainText string, salt string) error

// Load reads the file at filePath and returns the decrypted string.
// Decryption will fail after the file is copied to another PC or after a HW configuration change.
func Load(filePath string, salt string) (string, error)
```

> ℹ️ **Note on relative paths:** `hwvault` does not apply any special handling to `filePath`.
> A relative path is resolved relative to the current working directory, following standard Go (`os` package) behavior.

> ℹ️ **Note on file permission checks:** On `Load`, if the file's permissions are not `0600`, `hwvault` emits a warning (does not fail) rather than an error, since strict enforcement on read could break legitimate use cases (e.g. files restored from backup).

### Low-level API


Performs encryption/decryption in memory only, without any file operations.

```go
// Encrypt encrypts plainText using HW info + salt and returns the ciphertext as bytes.
func Encrypt(plainText string, salt string) ([]byte, error)

// Decrypt decrypts the encrypted byte slice and returns the plaintext string.
func Decrypt(cipherData []byte, salt string) (string, error)
```

---

## About `salt` (Application-specific Salt)

Specify a fixed string per application for `salt`.

- Even on the same HW, a different `salt` produces a different key.
- Prevents reuse of encrypted data across different applications.
- **`salt` may be embedded in source code or config files.** It acts as an application identifier, not a secret.
- However, changing `salt` after deployment will make existing saved data unrecoverable.
- There are no library-imposed constraints on the length or content of `salt` / `plainText` beyond what the underlying Go standard cryptography packages (`crypto/hmac`, `crypto/aes`, etc.) require.


---

## Error Handling

```go
secret, err := hwvault.Load(filePath, appSalt)
if err != nil {
    switch {
    case errors.Is(err, hwvault.ErrDecryptionFailed):
        // HW change, copy to another PC, or file corruption
        // → Delete saved data and prompt user to re-login
        promptReLogin()
    case errors.Is(err, hwvault.ErrHWIDUnavailable):
        // Failed to retrieve HW ID (insufficient permissions, unsupported environment, etc.)
        log.Fatal("This machine is not supported by hwvault:", err)
    case errors.Is(err, hwvault.ErrUnsupportedVersion):
        // The file was created by a newer/incompatible version of hwvault.
        // Treat the same as decryption failure → prompt user to re-login.
        promptReLogin()
    default:
        log.Fatal("Unexpected error:", err)
    }
}
```

| Error | Condition | Recommended Action |
|---|---|---|
| `ErrDecryptionFailed` | Copy to another PC, HW change, file corruption | Delete saved data → prompt re-login |
| `ErrHWIDUnavailable` | HW ID retrieval failed (insufficient permissions, unsupported env) | Notify user at startup |
| `ErrInvalidData` | Saved data format is invalid | Delete saved data → prompt re-login |
| `ErrUnsupportedVersion` | File's format `version` byte is not supported by this version of hwvault | Delete saved data → prompt re-login |

> ℹ️ **Note on concurrency:** `hwvault` is intended for single-process, occasional use (e.g. CLI login flows).
> Concurrent `Save`/`Load` calls to the same file from multiple processes or goroutines are not supported.


---

## ⚠️ Security Boundaries (Important)

**Please understand clearly what this library does and does not protect against before use.**

### ✅ In-Scope (Protected)

| Threat | Countermeasure |
|---|---|
| Unauthorized use after encrypted file is copied/leaked to another PC | HW-unique ID is used as key material; decryption on a different machine is impossible |
| Reading by other users on the same PC due to improper file permissions | `0600` / `0700` enforced automatically |
| Tampering with saved data | Detected via AES-256-GCM authentication tag; decryption fails |

### ❌ Out-of-Scope (Not Protected)

| Threat | Reason / Notes |
|---|---|
| **Decryption by malware or malicious processes running on the same PC** | Any process running on the same HW can generate the same key in principle. Delegate to PC-level defenses (EDR, antivirus) as the first layer. |
| **Physical memory dump / cold boot attacks** | Out of scope for this library. |
| **Key inference from `salt` leakage** | `salt` alone cannot generate the key (HW ID is also required). Management of `salt` is the application's responsibility. |
| **HW ID spoofing (e.g., in virtual machines)** | HW ID spoofing in VM environments is not addressed. Applications should account for VM behavior. |

> **Position in a defense-in-depth strategy:**
> ```
> Layer 1: EDR / Antivirus (malware defense)
> Layer 2: hwvault (protection against unauthorized use after file leakage)  ← here
> Layer 3: Application-level authentication and authorization logic
> ```

---

## Technical Specifications

| Item | Specification |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | HMAC-SHA256(HW_ID + salt) |
| HW ID source (Linux) | `/etc/machine-id` (via [`machineid`](https://github.com/denisbrodbeck/machineid) package) |
| HW ID source (Windows) | `MachineGuid` (registry, via [`machineid`](https://github.com/denisbrodbeck/machineid) package) |
| Nonce | 12 bytes (generated per encryption via `crypto/rand`) |
| Storage format | `version(1byte) \| nonce(12byte) \| ciphertext+tag` |
| File permissions | `0600` (file) / `0700` (directory) |

> ⚠️ **Note on containers (Docker, etc.):** hwvault relies on the [`machineid`](https://github.com/denisbrodbeck/machineid) package's ID resolution (`/etc/machine-id` on Linux). In containerized environments, this file's presence/value is not guaranteed by hwvault — depending on the container runtime and image, it may be absent, may differ between container instances, or may persist/change across container recreation. This library was designed primarily for on-premise / bare-metal or VM use cases; container-specific behavior has not been formally verified.


### Version Field Policy

The `version` byte identifies the on-disk file format generation, and follows the library's SemVer as follows:

| Library SemVer change | Meaning | Effect on `version` byte |
|---|---|---|
| **Major** (e.g. v1→v2) | Breaking API change | May introduce a new format |
| **Minor** (e.g. v1.1→v1.2) | API-compatible, but existing vault files must be regenerated | **Incremented** (e.g. `0x01`→`0x02`) |
| **Patch** (e.g. v1.1.0→v1.1.1) | Bug fixes, no format change | Unchanged |

`Save` always writes the current, latest supported `version`. `Load` rejects any `version` it does not recognize (including older, superseded versions) with `ErrUnsupportedVersion` — callers should treat this the same as `ErrDecryptionFailed` (delete data, prompt re-login). Backward-compatible reading of older formats is intentionally not supported, in order to keep the implementation simple.

### Atomic Save

`Save` writes to a temporary file in the same directory as `filePath` (e.g. `filePath + ".tmp"`) and then uses `os.Rename` to atomically replace the target file. This ensures that if the process crashes or the disk is full during a write, the previous (valid) vault file is not corrupted or lost — only the new write attempt fails.


---

## Comparison with `go-keyring`

[`go-keyring`](https://github.com/zalando/go-keyring) is a library that uses the OS-native credential manager (macOS Keychain, Windows Credential Manager, Linux Secret Service) as its backend.

### Comparison Table

| Item | `hwvault` | `go-keyring` |
|---|---|---|
| **Storage backend** | HW-ID-encrypted file (arbitrary path) | OS-native credential manager |
| **Node-lock (prevent decryption on another PC)** | ✅ Different HW ID → decryption impossible | ✅ Tied to OS credential store → not accessible on another PC |
| **Headless Linux support** | ✅ No daemon required; file-only operation | ❌ May require `gnome-keyring` or similar daemon |
| **CI/CD pipeline / server environments** | ✅ Works | ⚠️ Environment-dependent (Secret Service may be unavailable) |
| **Portability of storage location** | ✅ File path freely configurable (easy backup/migration) | ❌ Stored in OS-managed store; location not easily controlled |
| **macOS support** | ⚠️ Not verified | ✅ Stable via Keychain |
| **Windows support** | ✅ Supported | ✅ Supported via Credential Manager |
| **External daemon / service dependency** | ❌ None (zero dependency) | ⚠️ Depends on OS credential service |
| **Encryption transparency** | ✅ Implementation fully visible in code | ❌ Depends on OS implementation (black box) |
| **File permission control** | ✅ `0600` / `0700` enforced | — (not needed; OS-managed) |


### Which Should You Choose?

**Choose `hwvault` when:**

- You need it to work on headless Linux servers or CI/CD environments
- You want to manage, back up, or migrate the storage file yourself
- You want to avoid dependency on the OS credential manager
- You need to audit or understand the encryption implementation at the code level
- You are building a local tool for non-engineer users and need to absorb environment differences

**Choose `go-keyring` when:**

- macOS is your primary platform and you need stable credential management
- Integration with the OS-native credential manager is required (e.g., corporate policy)
- You need OS lock-screen integration in a GUI application
- A desktop environment with Secret Service is guaranteed

---

## Behavior on HW Change

If the HW ID changes due to hardware replacement or OS reinstallation, existing saved data can no longer be decrypted.

**Recommended flow:**

```
Decryption failure (ErrDecryptionFailed)
    ↓
Delete the old vault file
    ↓
Prompt the user to re-login (re-enter credentials)
    ↓
Re-encrypt and save with the new HW ID
```

This is expected behavior by design. Please implement this flow on the application side.

---

## Supported Platforms

| OS | Status |
|---|---|
| Linux | ✅ Supported |
| Windows | ✅ Supported |
| macOS | ⚠️ Not verified |

> **On macOS:** The underlying [`machineid`](https://github.com/denisbrodbeck/machineid) package supports macOS (`IOPlatformUUID`), so it is expected to work in principle. However, it has not been verified in practice, as doing so would require a macOS CI runner, which is considered too costly to maintain at this time.


---

## License

MIT License — see [LICENSE](LICENSE) for details.
