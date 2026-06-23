package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gitsafe/internal/format"
	"gitsafe/internal/gitx"
	"gitsafe/internal/identity"
	"gitsafe/internal/secret"
)

// cmdClean is the git clean filter: it reads a working-tree file from stdin and
// writes the blob git should store. It encrypts the plaintext to the recipients
// the signed policy says can read the current branch.
//
// Two safety properties beyond plain encryption:
//   - Deterministic re-staging: if the file is unchanged and the readers are
//     unchanged, it re-emits the already-stored ciphertext byte-for-byte, so
//     `git status` stays clean instead of churning on age's randomized output.
//   - Placeholder protection: if a locked user (who sees a placeholder, not the
//     secret) re-stages the file, clean detects the placeholder and re-emits the
//     stored ciphertext, never encrypting the placeholder over the real secret.
func cmdClean(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe clean PATH")
	}
	path := args[0]
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	// Locked user re-staging a placeholder: preserve the stored ciphertext.
	if format.IsLockedPlaceholder(input) {
		stored, found, err := gitx.StoredBlob(path)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("refusing to encrypt a locked placeholder for %q with no stored secret behind it", path)
		}
		_, err = os.Stdout.Write(stored)
		return err
	}

	// Already-encrypted input: smudge did not decrypt for us (a locked user, or
	// a clone whose working tree still holds ciphertext because filters were not
	// configured at checkout time). Never re-encrypt an envelope — that would
	// double-wrap the secret and, for unchanged content, churn status. Preserve
	// the stored blob (authoritative), or pass the envelope through if this is a
	// genuinely new pre-encrypted file. This path needs no policy/trust because
	// there is no plaintext to protect.
	if format.IsWrapped(input) {
		if stored, found, err := gitx.StoredBlob(path); err != nil {
			return err
		} else if found {
			_, err = os.Stdout.Write(stored)
			return err
		}
		_, err = os.Stdout.Write(input)
		return err
	}

	res, err := gitx.BranchResource()
	if err != nil {
		return err
	}
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	// Verify the signed chain and that its root matches this clone's pin BEFORE
	// trusting any recipient it names — otherwise a poisoned or replaced policy
	// could redirect this secret's encryption to an attacker's key.
	pol, err := trustedPolicy(rc)
	if err != nil {
		return err
	}
	recipients := pol.Recipients(res)
	if len(recipients) == 0 {
		return fmt.Errorf("no readers for %s; grant read access before committing secrets there", res)
	}

	// Determinism: reuse the stored blob if readers and plaintext are unchanged.
	if blob := reuseStored(path, input, recipients); blob != nil {
		_, err = os.Stdout.Write(blob)
		return err
	}

	ct, err := secret.Encrypt(input, recipients)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(format.Wrap(recipients, ct))
	return err
}

// reuseStored returns the currently-stored blob if it is a gitsafe envelope
// encrypted to exactly recipients and decrypts to plaintext; otherwise nil.
// Keeping the blob stable avoids spurious diffs from age's randomized output.
func reuseStored(path string, plaintext []byte, recipients []string) []byte {
	stored, found, err := gitx.StoredBlob(path)
	if err != nil || !found || !format.IsWrapped(stored) {
		return nil
	}
	env, err := format.Parse(stored)
	if err != nil || !equalStrings(env.Recipients, recipients) {
		return nil
	}
	id := identity.LoadOrNil()
	if id == nil {
		return nil
	}
	got, err := secret.Decrypt(env.Ciphertext, id.X25519)
	if err != nil || !bytes.Equal(got, plaintext) {
		return nil
	}
	return stored
}

// cmdSmudge is the git smudge filter: it reads a stored blob from stdin and
// writes what should appear in the working tree. Recipients get plaintext;
// everyone else gets a clear locked placeholder. It never errors a checkout.
func cmdSmudge(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe smudge PATH")
	}
	path := args[0]
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	// Not gitsafe-encrypted (e.g. committed before gitsafe, or non-secret):
	// pass through untouched.
	if !format.IsWrapped(input) {
		_, err = os.Stdout.Write(input)
		return err
	}

	env, err := format.Parse(input)
	if err != nil {
		// Corrupt envelope: show a placeholder rather than break the checkout.
		_, werr := os.Stdout.Write(format.LockedPlaceholder(path))
		return werr
	}

	id := identity.LoadOrNil()
	if id != nil {
		if plain, derr := secret.Decrypt(env.Ciphertext, id.X25519); derr == nil {
			_, werr := os.Stdout.Write(plain)
			return werr
		}
	}
	// No identity, or not a recipient: locked placeholder.
	_, err = os.Stdout.Write(format.LockedPlaceholder(path))
	return err
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
