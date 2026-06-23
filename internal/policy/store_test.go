package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

type actor struct {
	name    string
	signPub string
	priv    ed25519.PrivateKey
	enc     string
}

func newActor(t *testing.T, name string) actor {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return actor{name: name, signPub: hex.EncodeToString(pub), priv: priv, enc: enc.Recipient().String()}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(t.TempDir())
}

func TestBootstrapAndVerify(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")

	if err := Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv); err != nil {
		t.Fatal(err)
	}
	// Re-bootstrap must fail.
	if err := Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv); err == nil {
		t.Fatal("second bootstrap must fail")
	}
	n, err := s.VerifyChain()
	if err != nil || n != 1 {
		t.Fatalf("VerifyChain = %d, %v; want 1 version", n, err)
	}
	p, _ := s.Load()
	if !p.Eval("alice", Read, "refs/heads/main") {
		t.Error("founder admin should be able to read any branch")
	}
}

func TestMemberAddGrantAndRecipients(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	bob := newActor(t, "bob")
	if err := Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv); err != nil {
		t.Fatal(err)
	}

	// Alice (admin) adds bob and grants him read on staging.
	_, err := s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Keyring["bob"] = Member{Sign: bob.signPub, Enc: bob.enc, Status: "active"}
		p.Grants = append(p.Grants, Grant{ID: "g1", Subject: "bob", Verb: Read, Resource: "refs/heads/staging"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.VerifyChain()
	if err != nil || n != 2 {
		t.Fatalf("VerifyChain = %d, %v; want 2", n, err)
	}

	// staging recipients = alice (admin) + bob.
	r, _ := RecipientsFor(s, "refs/heads/staging")
	if !hasStr(r, alice.enc) || !hasStr(r, bob.enc) {
		t.Errorf("staging recipients missing alice/bob: %v", r)
	}
	// main recipients = alice only (bob has no read on main).
	r, _ = RecipientsFor(s, "refs/heads/main")
	if !hasStr(r, alice.enc) || hasStr(r, bob.enc) {
		t.Errorf("main recipients wrong (bob must not be a reader): %v", r)
	}
}

func TestChainOrdersRootToHead(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	bob := newActor(t, "bob")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Keyring["bob"] = Member{Sign: bob.signPub, Enc: bob.enc, Status: "active"}
		return nil
	})
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Grants = append(p.Grants, Grant{ID: "g", Subject: "bob", Verb: Read, Resource: "refs/heads/main"})
		return nil
	})

	chain, err := s.Chain()
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("Chain len = %d, want 3", len(chain))
	}
	for i, p := range chain {
		if p.Version != i {
			t.Fatalf("chain[%d].Version = %d, want %d (root-first order)", i, p.Version, i)
		}
	}
	// Access for bob on main appears only at the last version.
	if got := chain[0].ReaderNames("refs/heads/main"); hasStr(got, "bob") {
		t.Error("bob should not read main at v0")
	}
	if got := chain[2].ReaderNames("refs/heads/main"); !hasStr(got, "bob") {
		t.Error("bob should read main at head")
	}
}

func TestReaderWithoutSignKey(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	bob := newActor(t, "bob")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)
	// Add bob as a read-only member with NO signing key — the common case.
	_, err := s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Keyring["bob"] = Member{Enc: bob.enc, Sign: "", Status: "active"}
		p.Grants = append(p.Grants, Grant{ID: "g", Subject: "bob", Verb: Read, Resource: "refs/heads/main"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := RecipientsFor(s, "refs/heads/main"); !hasStr(r, bob.enc) {
		t.Fatal("a sign-less reader must still be a recipient")
	}
}

func TestNonAdminCannotMutate(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	bob := newActor(t, "bob")
	if err := Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv); err != nil {
		t.Fatal(err)
	}
	// Add bob as a plain reader (no admin).
	_, err := s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Keyring["bob"] = Member{Sign: bob.signPub, Enc: bob.enc, Status: "active"}
		p.Grants = append(p.Grants, Grant{ID: "g1", Subject: "bob", Verb: Read, Resource: "refs/heads/**"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Bob tries to grant himself admin — must be refused at Verify time.
	_, err = s.Mutate(bob.name, bob.priv, func(p *Policy) error {
		p.Grants = append(p.Grants, Grant{ID: "evil", Subject: "bob", Verb: Admin, Resource: "refs/**"})
		return nil
	})
	if err == nil {
		t.Fatal("a non-admin must not be able to sign a new policy version")
	}
}

func TestRevokedMemberDroppedFromRecipients(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	bob := newActor(t, "bob")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Keyring["bob"] = Member{Sign: bob.signPub, Enc: bob.enc, Status: "active"}
		p.Grants = append(p.Grants, Grant{ID: "g1", Subject: "bob", Verb: Read, Resource: "refs/heads/**"})
		return nil
	})
	if r, _ := RecipientsFor(s, "refs/heads/main"); !hasStr(r, bob.enc) {
		t.Fatal("bob should be a reader before revocation")
	}
	// Revoke bob.
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		m := p.Keyring["bob"]
		m.Status = "revoked"
		p.Keyring["bob"] = m
		return nil
	})
	if r, _ := RecipientsFor(s, "refs/heads/main"); hasStr(r, bob.enc) {
		t.Fatal("revoked bob must not remain a recipient")
	}
}

func TestMutateRefusesWhenLocked(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)

	// Simulate a concurrent writer holding the lock.
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.Mutate(alice.name, alice.priv, func(p *Policy) error { return nil })
	if err == nil {
		t.Fatal("Mutate must refuse while the policy is locked")
	}
}

func TestMutateRefusesToBrickPolicy(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)

	// Revoking the only admin would leave no one able to sign the next version.
	_, err := s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		m := p.Keyring["alice"]
		m.Status = "revoked"
		p.Keyring["alice"] = m
		return nil
	})
	if err == nil {
		t.Fatal("Mutate must refuse to revoke the last usable admin")
	}
	// Stripping the only admin's sign key is equally fatal and must be refused.
	_, err = s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		m := p.Keyring["alice"]
		m.Sign = ""
		p.Keyring["alice"] = m
		return nil
	})
	if err == nil {
		t.Fatal("Mutate must refuse to strip the last usable admin's sign key")
	}
}

func TestReAddReactivatesRevokedMember(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	bob := newActor(t, "bob")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		p.Keyring["bob"] = Member{Enc: bob.enc, Status: "active"}
		p.Grants = append(p.Grants, Grant{ID: "g", Subject: "bob", Verb: Read, Resource: "refs/heads/main"})
		return nil
	})
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		m := p.Keyring["bob"]
		m.Status = "revoked"
		p.Keyring["bob"] = m
		return nil
	})
	// Re-adding bob (the un-revoke path) must restore him to active.
	s.Mutate(alice.name, alice.priv, func(p *Policy) error {
		m := Member{Enc: bob.enc, Status: "active"}
		p.Keyring["bob"] = m
		return nil
	})
	p, _ := s.Load()
	if p.Keyring["bob"].Status != "active" {
		t.Fatalf("re-added member status = %q, want active", p.Keyring["bob"].Status)
	}
	if r, _ := RecipientsFor(s, "refs/heads/main"); !hasStr(r, bob.enc) {
		t.Fatal("reactivated bob must be a recipient again")
	}
}

func TestCorruptObjectDetected(t *testing.T) {
	s := newStore(t)
	alice := newActor(t, "alice")
	Bootstrap(s, alice.name, alice.signPub, alice.enc, alice.priv)

	head, _ := s.HeadHash()
	objs := filepath.Join(s.dir, "objects", head+".json")
	data, _ := os.ReadFile(objs)
	// Flip a byte in the middle of the object file.
	data[len(data)/2] ^= 0xff
	os.WriteFile(objs, data, 0o644)

	if _, err := s.VerifyChain(); err == nil {
		t.Fatal("a corrupted policy object must fail verification")
	}
}
