package filter

import (
	"strings"
	"testing"

	"filippo.io/age"
	"gitsafe/internal/format"
	"gitsafe/internal/secret"
)

// A new marked file whose content is an envelope encrypted to recipients that
// are NOT the branch's readers must be REJECTED, not committed verbatim.
// Otherwise a writer could lock out the real readers or address an outsider,
// and `check` would miss it (the clean filter is the enforcement point).
func TestCleanRejectsEnvelopeWithUnauthorizedRecipients(t *testing.T) {
	e := newEnv(t)
	outsider, _ := age.GenerateX25519Identity()
	ct, _ := secret.Encrypt([]byte("DB_PASSWORD=hunter2"), []string{outsider.Recipient().String()})
	blob := format.Wrap([]string{outsider.Recipient().String()}, ct)

	_, err := Clean(blob, "new.env", e.deps())
	if err == nil {
		t.Fatal("clean must refuse a new-path envelope encrypted to non-readers")
	}
	if !strings.Contains(err.Error(), "recipients are not the current readers") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A pre-encrypted new file whose recipients DO match the branch readers passes
// through unchanged (the legitimate round-trip the original code allowed).
func TestCleanAcceptsEnvelopeWithCorrectRecipients(t *testing.T) {
	e := newEnv(t)
	blob := e.encrypt(t, []byte("DB=1")) // encrypted to e.recipients (authorized)
	out, err := Clean(blob, "new.env", e.deps())
	if err != nil {
		t.Fatalf("correctly-encrypted envelope must pass through, got %v", err)
	}
	if string(out) != string(blob) {
		t.Fatal("correctly-encrypted envelope must pass through unchanged")
	}
}

// An edited locked placeholder (starts with the marker but differs) must error,
// never silently restore the stored blob (dropping the edit) nor encrypt the
// placeholder text over the real secret.
func TestCleanRejectsEditedPlaceholder(t *testing.T) {
	e := newEnv(t)
	e.stored["a.env"] = e.encrypt(t, []byte("OLD=1"))
	edited := append(append([]byte{}, format.LockedPlaceholder("a.env")...), []byte("INJECTED=2\n")...)

	_, err := Clean(edited, "a.env", e.deps())
	if err == nil {
		t.Fatal("clean must refuse content that starts with the placeholder marker but is not verbatim")
	}
	if !strings.Contains(err.Error(), "locked-placeholder marker") {
		t.Fatalf("unexpected error: %v", err)
	}
}
