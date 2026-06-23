package main

import (
	"fmt"
	"os"
	"os/exec"

	"gitsafe/internal/format"
	"gitsafe/internal/gitx"
	"gitsafe/internal/secret"
)

// cmdMerge is gitsafe's git merge driver for encrypted files. git invokes it as
//
//	gitsafe merge %O %A %B %P
//
// with the ancestor (%O), our (%A), and their (%B) versions of the blob, plus
// the pathname (%P). It decrypts the three versions, performs a normal 3-way
// merge on the plaintexts via `git merge-file`, re-encrypts the result to the
// current branch's readers, and writes it back to %A — git's merge result.
//
// Exit status mirrors the merge: 0 for a clean merge, non-zero when conflict
// markers remain (so git flags the path conflicted). On conflict the written
// %A still holds the re-encrypted merged-with-markers content, so smudge shows
// the markers in the working tree for the reader to resolve and re-stage.
func cmdMerge(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: gitsafe merge %%O %%A %%B [%%P] (configured as a git merge driver)")
	}
	ancestorPath, oursPath, theirsPath := args[0], args[1], args[2]
	name := oursPath
	if len(args) >= 4 && args[3] != "" {
		name = args[3]
	}

	ancestor, encA, err := readMergeSide(ancestorPath)
	if err != nil {
		return err
	}
	ours, encO, err := readMergeSide(oursPath)
	if err != nil {
		return err
	}
	theirs, encT, err := readMergeSide(theirsPath)
	if err != nil {
		return err
	}
	encrypted := encA || encO || encT

	merged, conflict, err := mergeFile3(ours, ancestor, theirs)
	if err != nil {
		return err
	}

	out := merged
	if encrypted {
		res, err := gitx.BranchResource()
		if err != nil {
			return fmt.Errorf("cannot determine branch to re-encrypt the merge for %q: %w", name, err)
		}
		recipients, err := trustedRecipients(res)
		if err != nil {
			return err
		}
		if len(recipients) == 0 {
			return fmt.Errorf("no readers for %s; cannot re-encrypt merged secret %q", res, name)
		}
		ct, err := secret.Encrypt(merged, recipients)
		if err != nil {
			return err
		}
		out = format.Wrap(recipients, ct)
	}

	if err := os.WriteFile(oursPath, out, 0o644); err != nil {
		return err
	}
	if conflict {
		// Non-zero exit tells git the merge is conflicted (markers are in the
		// re-encrypted result). This is an expected outcome, not an error.
		os.Exit(1)
	}
	return nil
}

// readMergeSide reads one merge input and returns its plaintext plus whether it
// was a gitsafe envelope. A non-envelope (e.g. an empty side, or a file not yet
// encrypted) is returned as-is. An envelope we cannot decrypt is a hard error —
// we must not silently merge around an unreadable secret.
func readMergeSide(path string) (plaintext []byte, wasEncrypted bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	// A locked placeholder is what a non-reader's working tree holds in place of a
	// secret. It is not an envelope, so treating it as plaintext would merge the
	// placeholder text into the secret and re-encrypt that — silently destroying
	// the file. Refuse: this merge must be resolved by someone who can read it.
	if format.IsLockedPlaceholder(data) {
		return nil, true, fmt.Errorf("merge: %q is locked (you lack read access); resolve this merge as a reader", path)
	}
	if !format.IsWrapped(data) {
		return data, false, nil
	}
	env, err := format.Parse(data)
	if err != nil {
		return nil, true, fmt.Errorf("merge: corrupt envelope in %q: %w", path, err)
	}
	plain, ok := decryptWithLocalIdentity(env.Ciphertext)
	if !ok {
		return nil, true, fmt.Errorf("merge: you cannot decrypt %q (no read access); resolve this merge as a reader", path)
	}
	return plain, true, nil
}

// mergeFile3 runs a 3-way merge of ours/ancestor/theirs via `git merge-file -p`
// and returns the merged bytes and whether conflict markers remain. The decrypted
// plaintexts are written into a private (0700) temp directory that is removed
// before returning, so secrets never touch world-readable /tmp.
func mergeFile3(ours, ancestor, theirs []byte) (merged []byte, conflict bool, err error) {
	dir, err := os.MkdirTemp("", "gitsafe-merge-")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(dir)

	o, err := writeTemp(dir, "ours", ours)
	if err != nil {
		return nil, false, err
	}
	b, err := writeTemp(dir, "base", ancestor)
	if err != nil {
		return nil, false, err
	}
	t, err := writeTemp(dir, "theirs", theirs)
	if err != nil {
		return nil, false, err
	}

	cmd := exec.Command("git", "merge-file", "-p", "-L", "ours", "-L", "base", "-L", "theirs", o, b, t)
	var stdout []byte
	stdout, err = cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code := ee.ExitCode()
			if code > 0 && code < 128 {
				return stdout, true, nil // conflicts remain; stdout holds markers
			}
		}
		return nil, false, fmt.Errorf("git merge-file: %w", err)
	}
	return stdout, false, nil
}

// writeTemp writes data to a uniquely-named temp file inside dir and returns its
// path. dir is expected to be a private (0700) directory created by the caller.
func writeTemp(dir, label string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, label+"-*")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
