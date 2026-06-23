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
