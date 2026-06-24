package filter

import (
	"bytes"
	"testing"

	"filippo.io/age"
	"gitsafe/internal/format"
	"gitsafe/internal/secret"
)

// REPRO 1 (CRITICAL): a new marked file whose content is an envelope encrypted
// to an UNAUTHORIZED outsider must be REFUSED. Passing it through verbatim would
// commit a secret the branch's real readers cannot decrypt while an outsider
// can. The contract is now an explicit error.
func TestRepro_CleanPassesThroughUnauthorizedRecipients(t *testing.T) {
	e := newEnv(t)
	outsider, _ := age.GenerateX25519Identity()
	// envelope encrypted ONLY to the outsider (NOT in e.recipients)
	ct, _ := secret.Encrypt([]byte("DB_PASSWORD=hunter2"), []string{outsider.Recipient().String()})
	blob := format.Wrap([]string{outsider.Recipient().String()}, ct)
	out, err := Clean(blob, "new.env", e.deps())
	if err == nil {
		env, _ := format.Parse(out)
		t.Fatalf("clean must REFUSE a pre-encrypted secret whose recipients aren't the branch readers; got recipients=%v", env.Recipients)
	}
}

// REPRO 2 (data-loss): an edited placeholder (starts with the marker but has
// extra content) must be REFUSED, not silently restored to the stored blob.
// Silent restore drops the edit; falling through to encrypt would overwrite the
// secret with placeholder text. Both are data loss, so the contract is an error.
func TestRepro_EditedPlaceholderSilentlyDropped(t *testing.T) {
	e := newEnv(t)
	old := e.encrypt(t, []byte("OLD=1"))
	e.stored["a.env"] = old
	edited := append(append([]byte{}, format.LockedPlaceholder("a.env")...), []byte("INJECTED=2\n")...)
	if _, err := Clean(edited, "a.env", e.deps()); err == nil {
		t.Fatal("clean must REFUSE an edited locked placeholder rather than silently restore the stored blob")
	}
}

// Companion to REPRO 2: the VERBATIM placeholder (an unchanged non-reader working
// copy) must still restore the stored secret, so a non-reader's `git add` is a
// no-op rather than an error. This is the line the edited-placeholder check must
// not cross.
func TestCleanVerbatimPlaceholderRestoresStored(t *testing.T) {
	e := newEnv(t)
	stored := e.encrypt(t, []byte("SECRET=1"))
	e.stored["a.env"] = stored
	out, err := Clean(format.LockedPlaceholder("a.env"), "a.env", e.deps())
	if err != nil {
		t.Fatalf("verbatim placeholder must restore the stored blob, got error: %v", err)
	}
	if !bytes.Equal(out, stored) {
		t.Fatal("verbatim placeholder must yield the stored blob unchanged")
	}
}
