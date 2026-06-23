package format

import (
	"bytes"
	"testing"
)

func TestWrapParseRoundTrip(t *testing.T) {
	recips := []string{"age1aaa", "age1bbb"}
	ct := []byte("\x01\x02 not really age but binary \x00\xff")
	blob := Wrap(recips, ct)

	if !IsWrapped(blob) {
		t.Fatal("Wrap output must be recognized by IsWrapped")
	}
	env, err := Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(env.Ciphertext, ct) {
		t.Errorf("ciphertext mismatch: %q", env.Ciphertext)
	}
	if len(env.Recipients) != 2 || env.Recipients[0] != "age1aaa" || env.Recipients[1] != "age1bbb" {
		t.Errorf("recipients mismatch: %v", env.Recipients)
	}
}

func TestWrapIsDeterministic(t *testing.T) {
	recips := []string{"age1aaa", "age1bbb"}
	ct := []byte("same ciphertext")
	if !bytes.Equal(Wrap(recips, ct), Wrap(recips, ct)) {
		t.Fatal("Wrap must be deterministic for identical inputs")
	}
}

func TestParseRejectsNonEnvelope(t *testing.T) {
	if _, err := Parse([]byte("plain text file")); err == nil {
		t.Fatal("Parse must reject non-envelope data")
	}
	if IsWrapped([]byte("DB_PASSWORD=hunter2")) {
		t.Fatal("plaintext must not be detected as an envelope")
	}
}

func TestParseTruncated(t *testing.T) {
	blob := Wrap([]string{"age1aaa"}, []byte("ct"))
	if _, err := Parse(blob[:len(Magic)+2]); err == nil {
		t.Fatal("truncated header length must error")
	}
}

func TestLockedPlaceholder(t *testing.T) {
	p := LockedPlaceholder("secrets/db.env")
	if !IsLockedPlaceholder(p) {
		t.Fatal("LockedPlaceholder output must be detected")
	}
	if !bytes.Equal(p, LockedPlaceholder("secrets/db.env")) {
		t.Fatal("placeholder must be deterministic")
	}
	if IsLockedPlaceholder([]byte("DB_PASSWORD=hunter2")) {
		t.Fatal("real content must not look like a placeholder")
	}
	// A placeholder must never be mistaken for an envelope and vice-versa.
	if IsWrapped(p) {
		t.Fatal("placeholder must not be detected as an envelope")
	}
}

// FuzzParse ensures the envelope parser never panics on hostile input — it must
// only ever return a value or an error.
func FuzzParse(f *testing.F) {
	f.Add(Wrap([]string{"age1aaa"}, []byte("ciphertext")))
	f.Add([]byte("plain text"))
	f.Add(append([]byte(nil), Magic...))
	f.Add(LockedPlaceholder("x"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := Parse(data)
		if err == nil && env == nil {
			t.Fatal("Parse returned nil env and nil error")
		}
		// IsWrapped/IsLockedPlaceholder must also never panic.
		_ = IsWrapped(data)
		_ = IsLockedPlaceholder(data)
	})
}

// TestEnvelopeGoldenVector pins the exact wire layout: the magic, the header
// length encoding, and the precise header JSON (field names, order, version).
// A change here means existing repos may become unreadable — it must be
// deliberate, so it must break this test.
func TestEnvelopeGoldenVector(t *testing.T) {
	if len(Magic) != 9 || string(Magic) != "\x00gitsafe\x00" {
		t.Fatalf("magic drifted: %q (len %d)", Magic, len(Magic))
	}
	got := Wrap([]string{"age1aaa", "age1bbb"}, []byte("CIPHERTEXT"))

	if !bytes.HasPrefix(got, Magic) {
		t.Fatal("missing magic prefix")
	}
	rest := got[len(Magic):]
	hlen := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	rest = rest[4:]
	wantHeader := `{"v":1,"recipients":["age1aaa","age1bbb"]}`
	if hlen != len(wantHeader) {
		t.Fatalf("header length = %d, want %d", hlen, len(wantHeader))
	}
	if string(rest[:hlen]) != wantHeader {
		t.Fatalf("header JSON drifted:\n got: %s\nwant: %s", rest[:hlen], wantHeader)
	}
	if string(rest[hlen:]) != "CIPHERTEXT" {
		t.Fatalf("ciphertext not appended verbatim: %q", rest[hlen:])
	}
}
