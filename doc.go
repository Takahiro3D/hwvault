// Package hwvault provides a hardware-bound credential vault for Go.
//
// It encrypts and stores credentials (API keys, passwords, etc.) using a
// key derived from the local machine's hardware ID, so that even if the
// encrypted file is copied to another machine, it cannot be decrypted
// there (node-lock).
//
// See docs/ARCHITECTURE.md in the source repository for the full design
// rationale and threat model.
package hwvault
