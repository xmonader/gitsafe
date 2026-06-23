package main

import (
	"os"
	"path/filepath"
	"testing"

	"gitsafe/internal/format"
)

// TestReadMergeSideRejectsPlaceholder guards C1: a non-reader's working tree
// holds a locked placeholder where a secret should be. The merge driver must
// refuse it, never treat it as plaintext to merge and re-encrypt (which would
// silently overwrite the real secret with the placeholder text).
func TestReadMergeSideRejectsPlaceholder(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, format.LockedPlaceholder(".env"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMergeSide(p); err == nil {
		t.Fatal("readMergeSide must reject a locked placeholder, not merge it as plaintext")
	}
}

// TestReadMergeSidePlainPasses confirms an ordinary (not-yet-encrypted) file is
// returned as plaintext, so first-time encryption merges still work.
func TestReadMergeSidePlainPasses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plain, enc, err := readMergeSide(p)
	if err != nil {
		t.Fatal(err)
	}
	if enc {
		t.Fatal("plain file must not be reported as encrypted")
	}
	if string(plain) != "hello\n" {
		t.Fatalf("plaintext = %q, want %q", plain, "hello\n")
	}
}
