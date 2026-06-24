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
		// Only restore the stored secret for the VERBATIM placeholder (an
		// unchanged non-reader working copy). If the input merely starts with the
		// marker but differs, it is either an edited placeholder (a non-reader must
		// not clobber the secret) or — vanishingly rarely — real content that
		// begins with the marker line. We can't tell which from content alone, so
		// refuse: silently restoring would drop a genuine edit, and falling through
		// to encrypt would overwrite the secret with placeholder text. Both are
		// data loss; an explicit error is the only safe outcome.
		if !bytes.Equal(input, format.LockedPlaceholder(path)) {
			return nil, fmt.Errorf("content for %q begins with the gitsafe locked-placeholder marker but is not the verbatim placeholder; if you edited a locked placeholder, discard it and re-checkout (a real secret must not start with that marker line)", path)
		}
		return stored, nil
	}

	// Treat input as already-encrypted only if it is a STRUCTURALLY VALID
	// envelope, not merely one starting with the magic bytes. A prefix-only check
	// (IsWrapped) would let a plaintext/binary secret that happens to begin with
	// the magic pass through unencrypted into git. Parse validates header length,
	// JSON, and version, so a coincidental or crafted prefix falls through to
	// encryption below.
	if env, perr := format.Parse(input); perr == nil {
		stored, found, err := d.StoredBlob(path)
		if err != nil {
			return nil, err
		}
		if found {
			// An existing path: the authoritative stored blob wins, so a crafted
			// working-tree envelope can never swap a committed secret's recipients.
			// This needs no policy lookup, so it still works under a detached HEAD.
			return stored, nil
		}
		// A NEW path whose content is a pre-encrypted envelope. Accept it only if it
		// is encrypted to EXACTLY the branch's current readers. Otherwise a writer
		// could introduce a secret encrypted to an unauthorized or stale set —
		// locking out the real readers, or addressing an outsider — which the clean
		// filter exists to prevent. (The recipient header is plaintext and could
		// lie; this still blocks the accidental/stale case and forces a deliberate
		// attacker into a blob the real readers cannot decrypt, which they notice.)
		recipients, err := branchRecipients(d)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(env.Recipients, recipients) {
			return nil, fmt.Errorf("refusing to commit a pre-encrypted secret for %q whose recipients are not the current readers; stage plaintext and let gitsafe encrypt it", path)
		}
		return input, nil
	}

	recipients, err := branchRecipients(d)
	if err != nil {
		return nil, err
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

// branchRecipients resolves the current branch's verified reader set, erroring
// if the branch is ambiguous or has no readers (so a secret is never committed
// with no one able to read it).
func branchRecipients(d Deps) ([]string, error) {
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
	return recipients, nil
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
