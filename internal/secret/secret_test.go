package secret

import (
	"testing"

	"filippo.io/age"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("DB_PASSWORD=hunter2\n")
	ct, err := Encrypt(plain, []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) == string(plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := Decrypt(ct, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Errorf("roundtrip = %q, want %q", got, plain)
	}
}

func TestNonRecipientCannotDecrypt(t *testing.T) {
	owner, _ := age.GenerateX25519Identity()
	stranger, _ := age.GenerateX25519Identity()
	ct, err := Encrypt([]byte("secret"), []string{owner.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(ct, stranger); err == nil {
		t.Fatal("a non-recipient must not be able to decrypt")
	}
}

func TestMultiRecipient(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	ct, err := Encrypt([]byte("shared"), []string{a.Recipient().String(), b.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*age.X25519Identity{a, b} {
		got, err := Decrypt(ct, id)
		if err != nil || string(got) != "shared" {
			t.Errorf("recipient could not decrypt: %v", err)
		}
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("encrypting to zero recipients must error")
	}
}

func TestMatch(t *testing.T) {
	marks := []string{".env", ".env.*", "*.pem", "secrets/**", "**/credentials.json"}
	cases := map[string]bool{
		".env":                        true,
		".env.production":             true,
		"config/server.pem":           true, // basename glob
		"secrets/db/password.txt":     true, // ** across segments
		"app/config/credentials.json": true,
		"main.go":                     false,
		"env":                         false,
		"readme.env.md":               false,
	}
	for path, want := range cases {
		if got := Match(path, marks); got != want {
			t.Errorf("Match(%q) = %v, want %v", path, got, want)
		}
	}
}
