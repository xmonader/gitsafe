// Package identity manages a user's keypair: an age (X25519) key for receiving
// encrypted secrets and an Ed25519 key for signing policy. The private material
// lives outside any repository (in ~/.config/gitsafe/identity by default) and
// never touches the repo.
//
// The on-disk identity is either plaintext JSON or, when protected, an age
// scrypt (passphrase) encryption of that same JSON. Load auto-detects which.
// The passphrase is resolved from the GITSAFE_PASSPHRASE environment variable
// (the non-interactive path that git filters need) or, failing that, from the
// Prompter hook the CLI installs for interactive commands.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// Identity is a user's keypair.
type Identity struct {
	X25519 *age.X25519Identity // encryption (receives secrets)
	Sign   ed25519.PrivateKey  // signing (policy)
}

// onDisk is the serialized form.
type onDisk struct {
	Enc  string `json:"enc"`  // age secret key
	Sign string `json:"sign"` // hex-encoded ed25519 private key
}

// Prompter, when set by the caller, supplies the passphrase for an encrypted
// identity if GITSAFE_PASSPHRASE is not set. confirm asks for a second entry to
// guard against typos (used only when writing a new encrypted identity). The
// CLI installs a /dev/tty prompter for interactive commands and leaves it unset
// for the git filters (which have no usable terminal).
var Prompter func(confirm bool) (string, error)

// Path returns the on-disk location of the private key, honoring
// GITSAFE_IDENTITY, then $XDG_CONFIG_HOME/gitsafe/identity, then
// ~/.config/gitsafe/identity.
func Path() string {
	if p := os.Getenv("GITSAFE_IDENTITY"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "gitsafe", "identity")
}

// Exists reports whether an identity file is present.
func Exists() bool {
	_, err := os.Stat(Path())
	return err == nil
}

// IsEncrypted reports whether the on-disk identity is passphrase-encrypted.
func IsEncrypted() bool {
	data, err := os.ReadFile(Path())
	if err != nil {
		return false
	}
	return looksEncrypted(data)
}

// looksEncrypted distinguishes the two on-disk forms: plaintext JSON begins with
// '{', while an age file begins with its "age-encryption.org/v1" header.
func looksEncrypted(data []byte) bool {
	t := bytes.TrimSpace(data)
	return len(t) > 0 && t[0] != '{'
}

// Generate creates a new plaintext identity and writes it to Path (0600). It
// refuses to overwrite an existing identity. Use GenerateEncrypted to protect
// the key at rest with a passphrase.
func Generate() (*Identity, error) {
	return create("")
}

// GenerateEncrypted creates a new identity encrypted at rest with passphrase.
func GenerateEncrypted(passphrase string) (*Identity, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	return create(passphrase)
}

// create generates a keypair and writes it, encrypting at rest when passphrase
// is non-empty. It refuses to overwrite an existing identity.
func create(passphrase string) (*Identity, error) {
	if Exists() {
		return nil, fmt.Errorf("identity already exists at %s", Path())
	}
	enc, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	id := &Identity{X25519: enc, Sign: priv}

	plain, _ := json.Marshal(onDisk{Enc: enc.String(), Sign: hex.EncodeToString(priv)})
	data := plain
	if passphrase != "" {
		if data, err = encryptIdentity(plain, passphrase); err != nil {
			return nil, err
		}
	}

	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

// Lock encrypts an existing plaintext identity at rest with passphrase,
// migrating an unprotected key in place. It errors if the identity is already
// encrypted or does not exist.
func Lock(passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("passphrase must not be empty")
	}
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no identity at %s (run 'gitsafe key gen')", Path())
		}
		return err
	}
	if looksEncrypted(data) {
		return fmt.Errorf("identity at %s is already passphrase-encrypted", Path())
	}
	if _, err := parseOnDisk(data); err != nil {
		return err
	}
	enc, err := encryptIdentity(data, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(), enc, 0o600); err != nil {
		return err
	}
	// WriteFile does not change the mode of an existing file, so if the identity
	// already existed with looser permissions, enforce 0600 explicitly — the
	// private key must never be group/world-readable.
	return os.Chmod(Path(), 0o600)
}

// Load reads the identity from Path, decrypting it first if it is
// passphrase-encrypted. It errors if none exists.
func Load() (*Identity, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no identity at %s (run 'gitsafe key gen')", Path())
		}
		return nil, err
	}
	if looksEncrypted(data) {
		pass, err := resolvePassphrase(false)
		if err != nil {
			return nil, err
		}
		data, err = decryptIdentity(data, pass)
		if err != nil {
			return nil, fmt.Errorf("unlock identity: %w", err)
		}
	}
	return parseOnDisk(data)
}

// parseOnDisk decodes the plaintext JSON form into an Identity.
func parseOnDisk(data []byte) (*Identity, error) {
	var d onDisk
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	enc, err := age.ParseX25519Identity(strings.TrimSpace(d.Enc))
	if err != nil {
		return nil, fmt.Errorf("parse encryption key: %w", err)
	}
	raw, err := hex.DecodeString(d.Sign)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("parse signing key")
	}
	return &Identity{X25519: enc, Sign: ed25519.PrivateKey(raw)}, nil
}

// resolvePassphrase obtains the passphrase for an encrypted identity from
// GITSAFE_PASSPHRASE, or the installed Prompter, or errors.
func resolvePassphrase(confirm bool) (string, error) {
	if p := os.Getenv("GITSAFE_PASSPHRASE"); p != "" {
		return p, nil
	}
	if Prompter != nil {
		return Prompter(confirm)
	}
	return "", fmt.Errorf("identity at %s is passphrase-encrypted; set GITSAFE_PASSPHRASE or run interactively", Path())
}

// encryptIdentity wraps plain in an age scrypt (passphrase) encryption.
func encryptIdentity(plain []byte, passphrase string) ([]byte, error) {
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decryptIdentity reverses encryptIdentity.
func decryptIdentity(enc []byte, passphrase string) ([]byte, error) {
	i, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(enc), i)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// LoadOrNil returns the identity, or nil if none exists or it cannot be
// unlocked (without erroring).
func LoadOrNil() *Identity {
	if !Exists() {
		return nil
	}
	id, err := Load()
	if err != nil {
		return nil
	}
	return id
}

// Recipient returns the public age recipient string ("age1...").
func (i *Identity) Recipient() string { return i.X25519.Recipient().String() }

// SignPub returns the hex-encoded Ed25519 public key.
func (i *Identity) SignPub() string {
	return hex.EncodeToString(i.Sign.Public().(ed25519.PublicKey))
}
