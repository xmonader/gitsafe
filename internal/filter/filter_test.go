package filter

import (
	"bytes"
	"testing"

	"filippo.io/age"
	"gitsafe/internal/format"
	"gitsafe/internal/secret"
)

// testEnv builds a Deps backed by in-memory fakes plus a real age identity, so
// the security logic is exercised without git or the filesystem.
type testEnv struct {
	id         *age.X25519Identity
	recipients []string
	stored     map[string][]byte
	resErr     error
	recErr     error
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{
		id:         id,
		recipients: []string{id.Recipient().String()},
		stored:     map[string][]byte{},
	}
}

func (e *testEnv) deps() Deps {
	return Deps{
		StoredBlob: func(p string) ([]byte, bool, error) {
			b, ok := e.stored[p]
			return b, ok, nil
		},
		Resource: func() (string, error) { return "refs/heads/main", e.resErr },
		Recipients: func(string) ([]string, error) {
			if e.recErr != nil {
				return nil, e.recErr
			}
			return e.recipients, nil
		},
		Decrypt: func(ct []byte) ([]byte, bool) {
			pt, err := secret.Decrypt(ct, e.id)
			return pt, err == nil
		},
	}
}

// encrypt is a helper producing a real envelope for the env's recipients.
func (e *testEnv) encrypt(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	ct, err := secret.Encrypt(plaintext, e.recipients)
	if err != nil {
		t.Fatal(err)
	}
	return format.Wrap(e.recipients, ct)
}

// TestCleanEncryptsMagicPrefixedPlaintext guards the crown-jewel leak: a
// plaintext (or binary) secret whose first bytes happen to equal the envelope
// magic must still be ENCRYPTED, not passed through as "already wrapped". A
// prefix check alone would commit it in cleartext.
func TestCleanEncryptsMagicPrefixedPlaintext(t *testing.T) {
	e := newEnv(t)
	// Real secret content that merely starts with the 9-byte magic.
	input := append(append([]byte{}, format.Magic...), []byte("MY_REAL_SECRET=hunter2")...)
	out, err := Clean(input, "a.env", e.deps())
	if err != nil {
		t.Fatal(err)
	}
	// It must be a *valid* envelope that decrypts back to the input...
	env, perr := format.Parse(out)
	if perr != nil {
		t.Fatalf("output is not a valid envelope: %v", perr)
	}
	got, derr := secret.Decrypt(env.Ciphertext, e.id)
	if derr != nil {
		t.Fatalf("decrypt failed: %v", derr)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("round-trip mismatch")
	}
	// ...and the cleartext must NOT appear verbatim in the stored blob.
	if bytes.Contains(out, []byte("MY_REAL_SECRET=hunter2")) {
		t.Fatal("PLAINTEXT LEAK: secret content present unencrypted in the stored blob")
	}
}

func TestCleanEncryptsPlaintext(t *testing.T) {
	e := newEnv(t)
	out, err := Clean([]byte("SECRET=1"), "a.env", e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if !format.IsWrapped(out) {
		t.Fatal("clean must produce an envelope")
	}
	env, _ := format.Parse(out)
	got, err := secret.Decrypt(env.Ciphertext, e.id)
	if err != nil || string(got) != "SECRET=1" {
		t.Fatalf("roundtrip failed: %q %v", got, err)
	}
}

func TestCleanNoReadersErrors(t *testing.T) {
	e := newEnv(t)
	e.recipients = nil
	if _, err := Clean([]byte("x"), "a.env", e.deps()); err == nil {
		t.Fatal("clean must refuse when there are no readers")
	}
}

func TestCleanPropagatesTrustError(t *testing.T) {
	e := newEnv(t)
	e.recErr = errFake
	if _, err := Clean([]byte("x"), "a.env", e.deps()); err != errFake {
		t.Fatalf("clean must surface the trust/policy error, got %v", err)
	}
}

func TestCleanReusesStoredWhenUnchanged(t *testing.T) {
	e := newEnv(t)
	plain := []byte("DB=1")
	blob := e.encrypt(t, plain)
	e.stored["a.env"] = blob

	out, err := Clean(plain, "a.env", e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, blob) {
		t.Fatal("unchanged secret + readers must re-emit the stored blob byte-for-byte")
	}
}

func TestCleanReEncryptsWhenRecipientsChange(t *testing.T) {
	e := newEnv(t)
	plain := []byte("DB=1")
	e.stored["a.env"] = e.encrypt(t, plain)

	// A new reader joins: stored blob's recipients no longer match.
	other, _ := age.GenerateX25519Identity()
	e.recipients = sortedRecipients(e.id.Recipient().String(), other.Recipient().String())

	out, err := Clean(plain, "a.env", e.deps())
	if err != nil {
		t.Fatal(err)
	}
	env, _ := format.Parse(out)
	if len(env.Recipients) != 2 {
		t.Fatalf("changed reader set must trigger re-encryption, got %d recipients", len(env.Recipients))
	}
}

func TestCleanPreservesStoredForLockedPlaceholder(t *testing.T) {
	e := newEnv(t)
	blob := e.encrypt(t, []byte("DB=1"))
	e.stored["a.env"] = blob
	out, err := Clean(format.LockedPlaceholder("a.env"), "a.env", e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, blob) {
		t.Fatal("a placeholder must never be encrypted; the stored secret must be preserved")
	}
}

func TestCleanRefusesPlaceholderWithNoStoredSecret(t *testing.T) {
	e := newEnv(t)
	if _, err := Clean(format.LockedPlaceholder("a.env"), "a.env", e.deps()); err == nil {
		t.Fatal("a placeholder with no backing secret must error, not be encrypted")
	}
}

func TestCleanPassesThroughEnvelopeInput(t *testing.T) {
	e := newEnv(t)
	blob := e.encrypt(t, []byte("DB=1"))
	// No stored blob: a pre-encrypted file being added passes through unchanged.
	out, err := Clean(blob, "a.env", e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, blob) {
		t.Fatal("already-encrypted input with no stored blob must pass through unchanged")
	}
	// With a stored blob, the authoritative stored copy wins.
	stored := e.encrypt(t, []byte("DB=2"))
	e.stored["a.env"] = stored
	out, _ = Clean(blob, "a.env", e.deps())
	if !bytes.Equal(out, stored) {
		t.Fatal("already-encrypted input must yield the stored blob, not re-wrap")
	}
}

func TestSmudgeDecryptsForRecipient(t *testing.T) {
	e := newEnv(t)
	blob := e.encrypt(t, []byte("DB=secret"))
	out := Smudge(blob, "a.env", e.deps())
	if string(out) != "DB=secret" {
		t.Fatalf("recipient must get plaintext, got %q", out)
	}
}

func TestSmudgePlaceholderForNonRecipient(t *testing.T) {
	e := newEnv(t)
	blob := e.encrypt(t, []byte("DB=secret"))
	// Swap in an identity that is not a recipient.
	stranger, _ := age.GenerateX25519Identity()
	e.id = stranger
	out := Smudge(blob, "a.env", e.deps())
	if !format.IsLockedPlaceholder(out) {
		t.Fatalf("non-recipient must get a placeholder, got %q", out)
	}
}

func TestSmudgePassesThroughNonEnvelope(t *testing.T) {
	e := newEnv(t)
	plain := []byte("not encrypted")
	if out := Smudge(plain, "a.env", e.deps()); !bytes.Equal(out, plain) {
		t.Fatal("non-envelope input must pass through untouched")
	}
}

func TestSmudgePlaceholderForCorruptEnvelope(t *testing.T) {
	e := newEnv(t)
	corrupt := append(append([]byte(nil), format.Magic...), []byte("\x00\x00\x00\x05junk!")...)
	out := Smudge(corrupt, "a.env", e.deps())
	if !format.IsLockedPlaceholder(out) {
		t.Fatal("a corrupt envelope must degrade to a placeholder, never panic or fail the checkout")
	}
}

var errFake = fakeErr("boom")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func sortedRecipients(xs ...string) []string {
	// format.Wrap expects sorted recipients (policy.Recipients sorts); mirror it.
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
	return xs
}
