package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEndToEnd drives a real git repository through the full gitsafe flow:
// init, encrypt-on-add, deterministic status, multi-member rotation, and the
// reader / locked-non-reader split on checkout. This is the integration test
// that proves the git-overlay model works against actual git plumbing.
func TestEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Build the gitsafe binary into a temp dir and put it on PATH so git's
	// filter invocation ("gitsafe clean %f") resolves to it.
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gitsafe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build gitsafe: %v\n%s", err, out)
	}

	repo := t.TempDir()
	aliceID := filepath.Join(t.TempDir(), "alice")
	bobID := filepath.Join(t.TempDir(), "bob")
	strangerID := filepath.Join(t.TempDir(), "stranger")

	env := func(idPath string) []string {
		e := append([]string{}, os.Environ()...)
		e = append(e,
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GITSAFE_IDENTITY="+idPath,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		)
		return e
	}

	// run executes a command in the repo with the given identity env.
	run := func(t *testing.T, idPath, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = repo
		cmd.Env = env(idPath)
		var out, errb bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s %s: %v\nstdout: %s\nstderr: %s", name, strings.Join(args, " "), err, out.String(), errb.String())
		}
		return out.String()
	}

	gitsafe := func(t *testing.T, idPath string, args ...string) string {
		return run(t, idPath, bin, args...)
	}

	// --- Setup: real repo on branch main, alice as founder. ---
	run(t, aliceID, "git", "init", "-b", "main")
	gitsafe(t, aliceID, "key", "gen")
	gitsafe(t, aliceID, "init", "--user", "alice")

	// Alice writes a secret and commits it.
	secret := "DB_PASSWORD=hunter2\nAPI_KEY=sk-live-xyz\n"
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, aliceID, "git", "add", ".gitsafe", ".gitattributes", ".env")
	run(t, aliceID, "git", "commit", "-m", "add secret")

	// 1. The stored blob must be ciphertext, not the plaintext.
	stored := run(t, aliceID, "git", "cat-file", "blob", "HEAD:.env")
	if strings.Contains(stored, "hunter2") {
		t.Fatal("the committed blob leaks plaintext — encryption did not run")
	}
	if !strings.HasPrefix(stored, "\x00gitsafe\x00") {
		t.Fatalf("stored blob is not a gitsafe envelope: %q", stored[:min(20, len(stored))])
	}

	// 2. The working tree still has plaintext (smudge decrypted for alice).
	if got, _ := os.ReadFile(filepath.Join(repo, ".env")); string(got) != secret {
		t.Fatalf("working tree .env should be plaintext for alice, got %q", got)
	}

	// 3. Determinism: status is clean even though age output is randomized.
	if st := run(t, aliceID, "git", "status", "--porcelain"); strings.TrimSpace(st) != "" {
		t.Fatalf("status should be clean after commit (determinism), got:\n%s", st)
	}

	// --- Add bob: before a grant he is locked; after grant+rotate he reads. ---
	bobSign := gitsafeKeyGenPub(t, gitsafe, bobID)
	gitsafe(t, aliceID, "member", "add", "bob", "--sign", bobSign.sign, "--enc", bobSign.enc)
	run(t, aliceID, "git", "add", ".gitsafe")
	run(t, aliceID, "git", "commit", "-m", "keyring: add bob")

	// Before granting bob, switch to bob's identity and re-checkout: locked.
	os.Remove(filepath.Join(repo, ".env"))
	run(t, bobID, "git", "checkout", "--", ".env")
	if got, _ := os.ReadFile(filepath.Join(repo, ".env")); !strings.Contains(string(got), "locked-placeholder") {
		t.Fatalf("bob without read access should see a locked placeholder, got %q", got)
	}
	// Critical: bob (locked) running status must NOT corrupt the secret — clean
	// re-emits the stored ciphertext when it sees the placeholder.
	if st := run(t, bobID, "git", "status", "--porcelain"); strings.TrimSpace(st) != "" {
		t.Fatalf("locked bob's status must stay clean (no placeholder corruption), got:\n%s", st)
	}

	// Alice grants bob read on main and rotates.
	gitsafe(t, aliceID, "grant", "bob", "read", "main")
	// Restore alice's plaintext working tree before rotating (renormalize cleans
	// the working file; alice can read it).
	os.Remove(filepath.Join(repo, ".env"))
	run(t, aliceID, "git", "checkout", "--", ".env")
	gitsafe(t, aliceID, "rotate")
	run(t, aliceID, "git", "add", ".gitsafe")
	run(t, aliceID, "git", "commit", "-m", "rotate: add bob")

	// Now bob can decrypt on checkout.
	os.Remove(filepath.Join(repo, ".env"))
	run(t, bobID, "git", "checkout", "--", ".env")
	if got, _ := os.ReadFile(filepath.Join(repo, ".env")); string(got) != secret {
		t.Fatalf("after grant+rotate, bob should read plaintext, got %q", got)
	}

	// 4. A stranger (valid identity, not in keyring) stays locked.
	gitsafeKeyGenPub(t, gitsafe, strangerID) // generate only
	os.Remove(filepath.Join(repo, ".env"))
	run(t, strangerID, "git", "checkout", "--", ".env")
	if got, _ := os.ReadFile(filepath.Join(repo, ".env")); !strings.Contains(string(got), "locked-placeholder") {
		t.Fatalf("a stranger must see a locked placeholder, got %q", got)
	}

	// 5. Policy chain verifies offline.
	out := gitsafe(t, aliceID, "policy", "verify")
	if !strings.Contains(out, "valid") {
		t.Fatalf("policy verify should report a valid chain, got %q", out)
	}
}

type pubKeys struct{ sign, enc string }

// gitsafeKeyGenPub generates an identity at idPath and returns its public keys
// by parsing `gitsafe key gen` output.
func gitsafeKeyGenPub(t *testing.T, gitsafe func(*testing.T, string, ...string) string, idPath string) pubKeys {
	t.Helper()
	out := gitsafe(t, idPath, "key", "gen")
	var k pubKeys
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "sign (ed25519):"):
			k.sign = strings.TrimSpace(strings.TrimPrefix(line, "sign (ed25519):"))
		case strings.HasPrefix(line, "enc  (age):"):
			k.enc = strings.TrimSpace(strings.TrimPrefix(line, "enc  (age):"))
		}
	}
	if k.sign == "" || k.enc == "" {
		t.Fatalf("could not parse public keys from key gen output:\n%s", out)
	}
	return k
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
