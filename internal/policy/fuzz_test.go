package policy

import (
	"encoding/json"
	"os"
	"testing"
)

// FuzzPolicyMethods ensures the access-decision logic never panics on arbitrary
// policy content — the regex globbing, verb hierarchy, group/keyring traversal,
// and signature verification must only ever return a value or an error.
func FuzzPolicyMethods(f *testing.F) {
	f.Add([]byte(`{"version":0,"keyring":{},"grants":[]}`))
	f.Add([]byte(`{"grants":[{"subject":"*","verb":"read","resource":"refs/heads/**"}]}`))
	f.Add([]byte(`{"groups":{"devs":["a","b"]},"grants":[{"subject":"devs","verb":"admin","resource":"**"}]}`))
	f.Add([]byte(`{"restricted":["refs/**"],"grants":[{"subject":"*","verb":"read","resource":"refs/**"}]}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var p Policy
		if json.Unmarshal(data, &p) != nil {
			return
		}
		// Arbitrary well-typed policy content must not panic any of these.
		p.Eval("alice", "read", "refs/heads/main")
		p.Eval("", "admin", "")
		p.Recipients("refs/heads/main")
		p.Readers("refs/heads/main")
		p.ReaderNames("refs/heads/main")
		_ = p.Verify(nil)
		_ = p.Verify(&p)
	})
}

// FuzzStoreVerify writes arbitrary (correctly-hashed) bytes as a policy object
// and verifies the chain walker / loader never panics on a hostile object — and
// that content-addressing prevents parent cycles from looping.
func FuzzStoreVerify(f *testing.F) {
	f.Add([]byte(`{"version":0,"keyring":{},"grants":[],"signer":"a","sig":""}`))
	f.Add([]byte(`{"parent":"deadbeef"}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		s := NewStore(dir)
		if err := os.MkdirAll(s.objectsDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		h := hashOf(data)
		if err := os.WriteFile(s.objPath(h), data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.headPath(), []byte(h), 0o644); err != nil {
			t.Fatal(err)
		}
		// Must terminate and never panic, regardless of object content.
		_, _ = s.Load()
		_, _ = s.VerifyChain()
	})
}
