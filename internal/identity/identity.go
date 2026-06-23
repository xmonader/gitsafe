// Package identity manages a user's keypair: an age (X25519) key for receiving
// encrypted secrets and an Ed25519 key for signing policy. The private material
// lives outside any repository (in ~/.config/gitsafe/identity by default) and
// never touches the repo. Ported from Haven.
package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// Generate creates a new identity and writes it to Path (0600). It refuses to
// overwrite an existing identity.
func Generate() (*Identity, error) {
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

	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(onDisk{Enc: enc.String(), Sign: hex.EncodeToString(priv)})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

// Load reads the identity from Path. It errors if none exists.
func Load() (*Identity, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no identity at %s (run 'gitsafe key gen')", Path())
		}
		return nil, err
	}
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

// LoadOrNil returns the identity, or nil if none exists (without erroring).
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
