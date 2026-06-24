package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTrustFile is the atomic writer behind the per-clone trust records
// (root pin, verified-head cache, rollback high-water). A torn write to any of
// them silently drops protection, so the writer must leave either the old file
// or the complete new one — never a partial — and must not leak temp files.
func TestWriteTrustFileAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gitsafe", "root")

	if err := writeTrustFile(p, "first\n"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeTrustFile(p, "second\n"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second\n" {
		t.Fatalf("content = %q, want %q", got, "second\n")
	}

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600 (trust files must not be group/world-readable)", perm)
	}

	// No .tmp-* leftover: the rename must consume the temp file, and a returning
	// writer must not leave scratch state that a reader could mistake for a record.
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %q after atomic write", e.Name())
		}
	}
}

// writeTrustFile creates its parent directory (0700) when absent — the
// .git/gitsafe/ dir does not exist on a fresh clone before the first trust.
func TestWriteTrustFileCreatesDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nope", "gitsafe", "highwater")
	if err := writeTrustFile(p, "3\n"); err != nil {
		t.Fatalf("write into missing dir: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}
