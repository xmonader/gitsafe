// Package gitx wraps the handful of real-git operations gitsafe needs: locating
// the repo, resolving the current branch (the security-critical input to the
// clean filter), reading config, and fetching the currently-stored blob for a
// path (used to keep encryption deterministic across re-staging).
package gitx

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// run executes git with args and returns stdout bytes. stderr is folded into
// the error for diagnostics.
func run(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return out.Bytes(), nil
}

// runStr runs git and returns trimmed stdout as a string.
func runStr(args ...string) (string, error) {
	b, err := run(args...)
	return strings.TrimSpace(string(b)), err
}

// Root returns the absolute path of the repository's top level.
func Root() (string, error) {
	return runStr("rev-parse", "--show-toplevel")
}

// InRepo reports whether the current directory is inside a git work tree.
func InRepo() bool {
	out, err := runStr("rev-parse", "--is-inside-work-tree")
	return err == nil && out == "true"
}

// CurrentBranch returns the short name of the checked-out branch. It errors on
// a detached HEAD — recipient resolution must never be ambiguous, so the clean
// filter refuses rather than guess.
func CurrentBranch() (string, error) {
	b, err := runStr("symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || b == "" {
		return "", fmt.Errorf("cannot resolve current branch (detached HEAD, rebase, or unborn branch); " +
			"gitsafe needs an unambiguous branch to choose recipients")
	}
	return b, nil
}

// BranchResource returns the policy resource for the current branch, e.g.
// "refs/heads/staging".
func BranchResource() (string, error) {
	b, err := CurrentBranch()
	if err != nil {
		return "", err
	}
	return "refs/heads/" + b, nil
}

// ConfigGet reads a local git config value; returns ("", nil) when unset.
func ConfigGet(key string) (string, error) {
	cmd := exec.Command("git", "config", "--local", "--get", key)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		// exit status 1 == key not found; treat as empty, not an error.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("git config get %s: %w", key, err)
	}
	return strings.TrimSpace(out.String()), nil
}

// ConfigSet writes a local git config value.
func ConfigSet(key, value string) error {
	_, err := run("config", "--local", key, value)
	return err
}

// StoredBlob returns the bytes currently stored for path: the staged (index)
// blob if present, otherwise the HEAD blob. found is false when the path is in
// neither — a brand-new secret being added for the first time.
func StoredBlob(path string) (data []byte, found bool, err error) {
	if b, e := run("cat-file", "blob", ":"+path); e == nil {
		return b, true, nil
	}
	if b, e := run("cat-file", "blob", "HEAD:"+path); e == nil {
		return b, true, nil
	}
	return nil, false, nil
}

// FilteredFiles returns every tracked file whose `filter` attribute is gitsafe.
// Used by rotate to know which files to re-encrypt.
func FilteredFiles() ([]string, error) {
	files, err := runStr("ls-files", "-z")
	if err != nil {
		return nil, err
	}
	if files == "" {
		return nil, nil
	}
	var paths []string
	for _, f := range strings.Split(strings.TrimRight(files, "\x00"), "\x00") {
		if f == "" {
			continue
		}
		paths = append(paths, f)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	// git check-attr filter -z -- <paths...> emits NUL-separated triples:
	// path, attr, value.
	args := append([]string{"check-attr", "filter", "-z", "--"}, paths...)
	out, err := run(args...)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	var marked []string
	for i := 0; i+2 < len(fields); i += 3 {
		path, value := fields[i], fields[i+2]
		if value == "gitsafe" {
			marked = append(marked, path)
		}
	}
	return marked, nil
}
