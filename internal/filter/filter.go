// Package filter holds the pure decision logic of gitsafe's clean and smudge
// git filters, separated from the CLI's argument parsing and stdin/stdout
// plumbing (SRP) and from the concrete git/identity/trust implementations (DIP).
//
// Clean and Smudge take their environment through a small Deps struct of
// function values, so the security-critical behavior — what gets encrypted, to
// whom, and when the stored ciphertext is preserved — is unit-testable with
// trivial fakes, instead of only through a real git repository.
package filter

import (
	"bytes"
	"fmt"
	"slices"

	"gitsafe/internal/format"
	"gitsafe/internal/secret"
)

// Deps are the environment-dependent operations the filters need. Everything
// else the filters do (envelope parsing, age encryption, placeholders) is pure
// and called directly — only these four touch git, the policy/trust layer, or
// the local identity, so only these are injected.
type Deps struct {
	// StoredBlob returns the blob git currently stores for path (index, then
	// HEAD), and whether one exists.
	StoredBlob func(path string) (data []byte, found bool, err error)
	// Resource returns the policy resource for the current branch, e.g.
	// "refs/heads/main". It errors when the branch is ambiguous.
	Resource func() (string, error)
	// Recipients returns the trusted age recipients for resource — i.e. the
	// readers of that branch, after the policy chain and root pin are verified.
	Recipients func(resource string) ([]string, error)
	// Decrypt attempts to decrypt ciphertext with the local identity; ok is
	// false when there is no identity or it is not a recipient.
	Decrypt func(ciphertext []byte) (plaintext []byte, ok bool)
}

// Clean produces the blob git should store for a working-tree file. It encrypts
// plaintext to the current branch's readers, but first handles two safety cases
// that must never reach the encryptor:
//
//   - a locked placeholder (a non-reader's working copy) → preserve the stored
//     ciphertext, so re-staging can't overwrite the real secret;
//   - already-encrypted input (smudge didn't decrypt for us) → preserve/pass it
//     through, so we never double-wrap.
//
// For genuinely changed plaintext it encrypts to the verified recipient set,
// reusing the stored ciphertext byte-for-byte when nothing relevant changed so
// git sees no spurious diff.
func Clean(input []byte, path string, d Deps) ([]byte, error) {
	if format.IsLockedPlaceholder(input) {
		stored, found, err := d.StoredBlob(path)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("refusing to encrypt a locked placeholder for %q with no stored secret behind it", path)
		}
		return stored, nil
	}

	if format.IsWrapped(input) {
		stored, found, err := d.StoredBlob(path)
		if err != nil {
			return nil, err
		}
		if found {
			return stored, nil
		}
		return input, nil
	}

	res, err := d.Resource()
	if err != nil {
		return nil, err
	}
	recipients, err := d.Recipients(res)
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no readers for %s; grant read access before committing secrets there", res)
	}

	if blob := reuseStored(d, path, input, recipients); blob != nil {
		return blob, nil
	}

	ct, err := secret.Encrypt(input, recipients)
	if err != nil {
		return nil, err
	}
	return format.Wrap(recipients, ct), nil
}

// reuseStored returns the stored blob when it is an envelope encrypted to
// exactly recipients that decrypts to plaintext — meaning nothing changed — so
// clean can re-emit it instead of producing fresh randomized ciphertext.
func reuseStored(d Deps, path string, plaintext []byte, recipients []string) []byte {
	stored, found, err := d.StoredBlob(path)
	if err != nil || !found || !format.IsWrapped(stored) {
		return nil
	}
	env, err := format.Parse(stored)
	if err != nil || !slices.Equal(env.Recipients, recipients) {
		return nil
	}
	got, ok := d.Decrypt(env.Ciphertext)
	if !ok || !bytes.Equal(got, plaintext) {
		return nil
	}
	return stored
}

// Smudge produces the working-tree content for a stored blob. A recipient gets
// plaintext; everyone else gets a clear locked placeholder. It never returns an
// error for an unreadable secret — a checkout must not fail — and passes
// non-envelope blobs (e.g. committed before gitsafe) through untouched. It does
// not consult the policy: decryption depends only on the local identity, so a
// tampered policy cannot affect it.
func Smudge(input []byte, path string, d Deps) []byte {
	if !format.IsWrapped(input) {
		return input
	}
	env, err := format.Parse(input)
	if err != nil {
		return format.LockedPlaceholder(path)
	}
	if plain, ok := d.Decrypt(env.Ciphertext); ok {
		return plain
	}
	return format.LockedPlaceholder(path)
}
