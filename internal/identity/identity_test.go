package identity

import (
	"path/filepath"
	"testing"
)

func TestGenerateLoadRoundTrip(t *testing.T) {
	t.Setenv("GITSAFE_IDENTITY", filepath.Join(t.TempDir(), "id"))

	if Exists() {
		t.Fatal("identity should not exist yet")
	}
	gen, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(); err == nil {
		t.Fatal("Generate must refuse to overwrite an existing identity")
	}
	if !Exists() {
		t.Fatal("Exists should be true after Generate")
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Recipient() != gen.Recipient() {
		t.Errorf("recipient mismatch: %s vs %s", loaded.Recipient(), gen.Recipient())
	}
	if loaded.SignPub() != gen.SignPub() {
		t.Errorf("sign pub mismatch")
	}
}

func TestEncryptedIdentityRoundTrip(t *testing.T) {
	t.Setenv("GITSAFE_IDENTITY", filepath.Join(t.TempDir(), "id"))
	t.Setenv("GITSAFE_PASSPHRASE", "correct horse battery staple")

	gen, err := GenerateEncrypted("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted() {
		t.Fatal("identity should be encrypted at rest")
	}

	loaded, err := Load() // passphrase comes from GITSAFE_PASSPHRASE
	if err != nil {
		t.Fatalf("load with env passphrase: %v", err)
	}
	if loaded.Recipient() != gen.Recipient() || loaded.SignPub() != gen.SignPub() {
		t.Fatal("decrypted identity does not match generated one")
	}
}

func TestEncryptedIdentityWrongPassphrase(t *testing.T) {
	t.Setenv("GITSAFE_IDENTITY", filepath.Join(t.TempDir(), "id"))
	t.Setenv("GITSAFE_PASSPHRASE", "right")
	if _, err := GenerateEncrypted("right"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITSAFE_PASSPHRASE", "wrong")
	if _, err := Load(); err == nil {
		t.Fatal("Load must fail with the wrong passphrase")
	}
}

func TestLockMigratesPlaintext(t *testing.T) {
	t.Setenv("GITSAFE_IDENTITY", filepath.Join(t.TempDir(), "id"))

	gen, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if IsEncrypted() {
		t.Fatal("fresh plaintext identity must not be reported as encrypted")
	}
	if err := Lock("s3cret"); err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted() {
		t.Fatal("identity should be encrypted after Lock")
	}
	if err := Lock("s3cret"); err == nil {
		t.Fatal("Lock must refuse an already-encrypted identity")
	}

	t.Setenv("GITSAFE_PASSPHRASE", "s3cret")
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SignPub() != gen.SignPub() {
		t.Fatal("locked identity decrypts to a different key")
	}
}

func TestEncryptedLoadWithoutPassphraseFails(t *testing.T) {
	t.Setenv("GITSAFE_IDENTITY", filepath.Join(t.TempDir(), "id"))
	t.Setenv("GITSAFE_PASSPHRASE", "p")
	if _, err := GenerateEncrypted("p"); err != nil {
		t.Fatal(err)
	}
	// No env passphrase and no Prompter installed -> Load must error, LoadOrNil nil.
	t.Setenv("GITSAFE_PASSPHRASE", "")
	Prompter = nil
	if _, err := Load(); err == nil {
		t.Fatal("Load must fail when locked and no passphrase source is available")
	}
	if LoadOrNil() != nil {
		t.Fatal("LoadOrNil must be nil for a locked identity with no passphrase")
	}
}
