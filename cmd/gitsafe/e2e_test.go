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

	// Locked bob must NOT be able to rotate (he can't re-encrypt what he can't
	// read); rotate must refuse rather than silently no-op.
	{
		cmd := exec.Command(bin, "rotate")
		cmd.Dir = repo
		cmd.Env = env(bobID)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("locked bob's rotate must fail, but succeeded:\n%s", out)
		} else if !strings.Contains(string(out), "locked") {
			t.Fatalf("expected a 'locked' refusal from bob's rotate, got:\n%s", out)
		}
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

// TestTrustGate proves the encrypt path refuses to act on an untrusted policy:
// an unpinned clone won't encrypt, and a content-only attacker who replaces the
// policy root (without access to your local .git pin) is detected and refused.
func TestTrustGate(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gitsafe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build gitsafe: %v\n%s", err, out)
	}

	env := func(idPath string) []string {
		e := append([]string{}, os.Environ()...)
		return append(e,
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GITSAFE_IDENTITY="+idPath,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		)
	}
	// runIn runs a command and returns combined stderr+stdout plus the error.
	runIn := func(dir, idPath, name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = env(idPath)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return out.String(), err
	}
	mustRun := func(t *testing.T, dir, idPath, name string, args ...string) string {
		t.Helper()
		out, err := runIn(dir, idPath, name, args...)
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return out
	}

	origin := t.TempDir()
	adminID := filepath.Join(t.TempDir(), "admin")
	victimID := filepath.Join(t.TempDir(), "victim")
	attackerID := filepath.Join(t.TempDir(), "attacker")

	// Origin repo: admin bootstraps (auto-pins) and commits a secret.
	mustRun(t, origin, adminID, "git", "init", "-b", "main")
	mustRun(t, origin, adminID, bin, "key", "gen")
	mustRun(t, origin, adminID, bin, "init", "--user", "admin")
	os.WriteFile(filepath.Join(origin, ".env"), []byte("SECRET=1\n"), 0o644)
	mustRun(t, origin, adminID, "git", "add", ".gitsafe", ".gitattributes", ".env")
	mustRun(t, origin, adminID, "git", "commit", "-m", "init")

	// Fresh clone: victim wires filters via init, which must NOT auto-pin.
	clone := filepath.Join(t.TempDir(), "clone")
	mustRun(t, "", adminID, "git", "clone", origin, clone)
	mustRun(t, clone, victimID, bin, "key", "gen")
	initOut := mustRun(t, clone, victimID, bin, "init", "--user", "victim")
	if strings.Contains(initOut, "Pinned policy root") {
		t.Fatal("init on a cloned policy must NOT auto-pin; trust must be deliberate")
	}

	// 0. An unpinned clone whose working tree still holds ciphertext must not
	//    break everyday git: status runs clean on the un-smudged .env, which is
	//    an envelope and must pass through (no trust needed, no churn).
	if out, err := runIn(clone, victimID, "git", "status", "--porcelain"); err != nil {
		t.Fatalf("git status must work in an unpinned clone, got error:\n%s", out)
	} else if strings.Contains(out, ".env") {
		t.Fatalf("unchanged encrypted .env must not show as modified, got:\n%s", out)
	}

	// 1. Unpinned clone refuses to encrypt a new secret.
	os.WriteFile(filepath.Join(clone, "svc.pem"), []byte("K=v\n"), 0o644)
	if out, err := runIn(clone, victimID, "git", "add", "svc.pem"); err == nil {
		t.Fatalf("git add must fail in an unpinned clone, but succeeded:\n%s", out)
	} else if !strings.Contains(out, "not trusted") {
		t.Fatalf("expected a 'not trusted' error, got:\n%s", out)
	}

	// 2. After deliberate trust, encryption works.
	mustRun(t, clone, victimID, bin, "trust")
	mustRun(t, clone, victimID, "git", "add", "svc.pem")
	stored := mustRun(t, clone, victimID, "git", "cat-file", "blob", ":svc.pem")
	if !strings.HasPrefix(stored, "\x00gitsafe\x00") {
		t.Fatal("after trust, the staged secret must be encrypted")
	}

	// 3. Content-only attacker replaces the policy root (no access to the local
	//    .git pin). Simulate by re-bootstrapping the committed policy under a new
	//    key, then restoring the victim's pin (the attacker never touched .git).
	pinPath := filepath.Join(clone, ".git", "gitsafe", "root")
	victimPin, _ := os.ReadFile(pinPath)
	os.RemoveAll(filepath.Join(clone, ".gitsafe", "policy"))
	mustRun(t, clone, attackerID, bin, "key", "gen")
	mustRun(t, clone, attackerID, bin, "init", "--user", "attacker")
	os.WriteFile(pinPath, victimPin, 0o644) // attacker couldn't touch your .git

	// 4. Victim now refuses: the policy root no longer matches the pin.
	os.WriteFile(filepath.Join(clone, "other.pem"), []byte("X=y\n"), 0o644)
	if out, err := runIn(clone, victimID, "git", "add", "other.pem"); err == nil {
		t.Fatalf("git add must fail after a root replacement, but succeeded:\n%s", out)
	} else if !strings.Contains(out, "root changed") && !strings.Contains(out, "REFUSING") {
		t.Fatalf("expected a root-mismatch refusal, got:\n%s", out)
	}
}

// TestWorktree verifies gitsafe works in a linked git worktree: smudge decrypts
// there, and clean works without re-trusting because the pin is shared via git's
// common dir. This covers a slice of git's long tail that overlays often break.
func TestWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gitsafe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build gitsafe: %v\n%s", err, out)
	}

	repo := t.TempDir()
	id := filepath.Join(t.TempDir(), "id")
	environ := append(append([]string{}, os.Environ()...),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITSAFE_IDENTITY="+id,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
	)
	run := func(t *testing.T, dir, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = environ
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}

	run(t, repo, "git", "init", "-b", "main")
	run(t, repo, bin, "key", "gen")
	run(t, repo, bin, "init", "--user", "alice")
	os.WriteFile(filepath.Join(repo, ".env"), []byte("SECRET=1\n"), 0o644)
	run(t, repo, "git", "add", ".gitsafe", ".gitattributes", ".env")
	run(t, repo, "git", "commit", "-m", "secret")

	// Linked worktree on a new branch.
	wt := filepath.Join(t.TempDir(), "wt")
	run(t, repo, "git", "worktree", "add", "-b", "staging", wt)

	// smudge in the worktree: alice (a reader) sees plaintext.
	if got, _ := os.ReadFile(filepath.Join(wt, ".env")); string(got) != "SECRET=1\n" {
		t.Fatalf("worktree should decrypt for alice, got %q", got)
	}
	// clean in the worktree works without re-trusting (pin shared via common dir).
	os.WriteFile(filepath.Join(wt, ".env"), []byte("SECRET=2\n"), 0o644)
	run(t, wt, "git", "add", ".env")
	stored := run(t, wt, "git", "cat-file", "blob", ":.env")
	if !strings.HasPrefix(stored, "\x00gitsafe\x00") {
		t.Fatal("worktree clean must encrypt without a separate trust step")
	}
}

// TestMergeDriver proves the encrypted-file merge driver: two branches editing
// the same secret in non-conflicting ways merge cleanly into correct decrypted
// plaintext, and a real content conflict is surfaced (not silently lost).
func TestMergeDriver(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gitsafe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build gitsafe: %v\n%s", err, out)
	}

	repo := t.TempDir()
	id := filepath.Join(t.TempDir(), "id")
	environ := append(append([]string{}, os.Environ()...),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITSAFE_IDENTITY="+id,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
	)
	run := func(t *testing.T, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = repo
		cmd.Env = environ
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	tryRun := func(name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		cmd.Dir = repo
		cmd.Env = environ
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	writeEnv := func(s string) {
		if err := os.WriteFile(filepath.Join(repo, ".env"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Base secret on main.
	run(t, "git", "init", "-b", "main")
	run(t, bin, "key", "gen")
	run(t, bin, "init", "--user", "alice")
	writeEnv("A=1\nB=2\nC=3\n")
	run(t, "git", "add", ".gitsafe", ".gitattributes", ".env")
	run(t, "git", "commit", "-m", "base secret")

	// feature changes the first line.
	run(t, "git", "checkout", "-b", "feature")
	writeEnv("A=10\nB=2\nC=3\n")
	run(t, "git", "add", ".env")
	run(t, "git", "commit", "-m", "feature: A=10")

	// main changes the last line (non-conflicting with feature).
	run(t, "git", "checkout", "main")
	writeEnv("A=1\nB=2\nC=30\n")
	run(t, "git", "add", ".env")
	run(t, "git", "commit", "-m", "main: C=30")

	// Merge feature -> main: the driver must produce a clean, correct merge.
	run(t, "git", "merge", "feature", "-m", "merge feature")

	// The merged blob in the index must be ciphertext (no plaintext leak).
	stored := run(t, "git", "cat-file", "blob", ":.env")
	if !strings.HasPrefix(stored, "\x00gitsafe\x00") {
		t.Fatalf("merged blob is not a gitsafe envelope: %q", stored[:min(20, len(stored))])
	}
	if strings.Contains(stored, "A=10") || strings.Contains(stored, "C=30") {
		t.Fatal("merged blob leaks plaintext")
	}

	// Re-checkout to force smudge; the decrypted merge must carry both changes.
	os.Remove(filepath.Join(repo, ".env"))
	run(t, "git", "checkout", "--", ".env")
	got, _ := os.ReadFile(filepath.Join(repo, ".env"))
	if string(got) != "A=10\nB=2\nC=30\n" {
		t.Fatalf("merged plaintext wrong, got %q", got)
	}

	// --- Conflict path: both branches change the same line differently. ---
	run(t, "git", "checkout", "-b", "feature2")
	writeEnv("A=111\nB=2\nC=30\n")
	run(t, "git", "add", ".env")
	run(t, "git", "commit", "-m", "feature2: A=111")

	run(t, "git", "checkout", "main")
	writeEnv("A=222\nB=2\nC=30\n")
	run(t, "git", "add", ".env")
	run(t, "git", "commit", "-m", "main: A=222")

	out, err := tryRun("git", "merge", "feature2", "-m", "merge feature2")
	if err == nil {
		t.Fatalf("a conflicting merge must fail, but succeeded:\n%s", out)
	}
	st, _ := tryRun("git", "status", "--porcelain")
	if !strings.Contains(st, "UU .env") && !strings.Contains(st, "AA .env") {
		t.Fatalf("conflicting merge must leave .env unmerged, status:\n%s", st)
	}
}

// TestOnboardGroupsAuditCheck exercises the convenience and audit commands end
// to end against real git: onboard (add+grant+rotate in one step), group
// management, the audit history, and the pre-commit plaintext-leak check.
func TestOnboardGroupsAuditCheck(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gitsafe")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build gitsafe: %v\n%s", err, out)
	}

	repo := t.TempDir()
	aliceID := filepath.Join(t.TempDir(), "alice")
	bobID := filepath.Join(t.TempDir(), "bob")
	carolID := filepath.Join(t.TempDir(), "carol")

	env := func(idPath string) []string {
		return append(append([]string{}, os.Environ()...),
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GITSAFE_IDENTITY="+idPath,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		)
	}
	run := func(t *testing.T, idPath, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = repo
		cmd.Env = env(idPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	tryRun := func(idPath, name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		cmd.Dir = repo
		cmd.Env = env(idPath)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	gitsafe := func(t *testing.T, idPath string, args ...string) string {
		return run(t, idPath, bin, args...)
	}

	// Setup: alice founder, a base secret on main.
	run(t, aliceID, "git", "init", "-b", "main")
	gitsafe(t, aliceID, "key", "gen")
	gitsafe(t, aliceID, "init", "--user", "alice")
	os.WriteFile(filepath.Join(repo, ".env"), []byte("DB=secret\n"), 0o644)
	run(t, aliceID, "git", "add", ".gitsafe", ".gitattributes", ".env")
	run(t, aliceID, "git", "commit", "-m", "base secret")

	// onboard bob on main in one step (add + grant + rotate). Read-only members
	// need only their enc key — no --sign.
	bob := gitsafeKeyGenPub(t, gitsafe, bobID)
	gitsafe(t, aliceID, "onboard", "bob", "main", "--enc", bob.enc)
	run(t, aliceID, "git", "add", ".gitsafe", ".env")
	run(t, aliceID, "git", "commit", "-m", "onboard bob")

	// bob can now read main's secret on checkout.
	os.Remove(filepath.Join(repo, ".env"))
	run(t, bobID, "git", "checkout", "--", ".env")
	if got, _ := os.ReadFile(filepath.Join(repo, ".env")); string(got) != "DB=secret\n" {
		t.Fatalf("after onboard, bob should read plaintext, got %q", got)
	}

	// groups: add carol to the keyring, then a "devs" group, grant it read staging.
	carol := gitsafeKeyGenPub(t, gitsafe, carolID)
	gitsafe(t, aliceID, "member", "add", "carol", "--enc", carol.enc) // enc only, no sign
	gitsafe(t, aliceID, "group", "add", "devs", "bob", "carol")
	gitsafe(t, aliceID, "grant", "devs", "read", "staging")

	if out := gitsafe(t, aliceID, "group", "list"); !strings.Contains(out, "devs") ||
		!strings.Contains(out, "bob") || !strings.Contains(out, "carol") {
		t.Fatalf("group list missing devs/bob/carol:\n%s", out)
	}
	// access on staging expands the group to its members.
	access := gitsafe(t, aliceID, "access", "staging")
	if !strings.Contains(access, "bob") || !strings.Contains(access, "carol") {
		t.Fatalf("access staging should list group members bob+carol:\n%s", access)
	}

	// group remove drops carol.
	gitsafe(t, aliceID, "group", "remove", "devs", "carol")
	if out := gitsafe(t, aliceID, "access", "staging"); strings.Contains(out, "carol") {
		t.Fatalf("after group remove, carol must not read staging:\n%s", out)
	}

	// audit: bob's access on main changed from absent to present across versions.
	audit := gitsafe(t, aliceID, "audit", "main")
	if !strings.Contains(audit, "bob") || !strings.Contains(audit, "changed") {
		t.Fatalf("audit main should show bob's access change:\n%s", audit)
	}

	// check: clean state passes.
	if out, err := tryRun(aliceID, bin, "check"); err != nil {
		t.Fatalf("check should pass on a clean staged tree:\n%s", out)
	}
	// Simulate the footgun: stage a marked file (*.pem) as PLAINTEXT (filter
	// bypassed, as in a fresh clone before init).
	os.WriteFile(filepath.Join(repo, "leak.pem"), []byte("TOKEN=plain\n"), 0o644)
	run(t, aliceID, "git", "-c", "filter.gitsafe.clean=cat", "add", "leak.pem")
	stored := run(t, aliceID, "git", "cat-file", "blob", ":leak.pem")
	if !strings.Contains(stored, "TOKEN=plain") {
		t.Fatal("setup: leak.pem should be staged as plaintext for this check")
	}
	if out, err := tryRun(aliceID, bin, "check"); err == nil {
		t.Fatalf("check must FAIL when a marked secret is staged as plaintext:\n%s", out)
	} else if !strings.Contains(out, "leak.pem") {
		t.Fatalf("check failure should name the leaking file:\n%s", out)
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
