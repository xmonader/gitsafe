package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Store persists the signed policy chain as plain files committed in the repo
// under .gitsafe/policy/. This replaces Haven's SQLite object store: git is the
// distribution mechanism, so the chain travels on a normal push and verifies
// offline with nothing but these files.
//
// Layout:
//
//	.gitsafe/policy/HEAD              -> hex hash of the head version
//	.gitsafe/policy/objects/<hash>.json -> one signed Policy per version
type Store struct {
	dir string // .gitsafe/policy
}

// Dir is the policy subdirectory under the repo root.
const Dir = ".gitsafe/policy"

// NewStore returns a store rooted at repoRoot/.gitsafe/policy.
func NewStore(repoRoot string) *Store {
	return &Store{dir: filepath.Join(repoRoot, Dir)}
}

func (s *Store) headPath() string    { return filepath.Join(s.dir, "HEAD") }
func (s *Store) objectsDir() string  { return filepath.Join(s.dir, "objects") }
func (s *Store) objPath(h string) string {
	return filepath.Join(s.objectsDir(), h+".json")
}

// hash is the content address of a policy object: sha256 of its canonical JSON.
func hashOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// head returns the head hash, or "" if the repo has no policy yet.
func (s *Store) head() (string, error) {
	b, err := os.ReadFile(s.headPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(trimSpace(b)), nil
}

// loadObject reads and integrity-checks a single policy object.
func (s *Store) loadObject(hash string) (*Policy, error) {
	payload, err := os.ReadFile(s.objPath(hash))
	if err != nil {
		return nil, fmt.Errorf("read policy object %s: %w", hash, err)
	}
	if got := hashOf(payload); got != hash {
		return nil, fmt.Errorf("policy object %s is corrupt (hash mismatch %s)", hash, got)
	}
	var p Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", hash, err)
	}
	return &p, nil
}

// Load returns the current (head) policy, or nil if none exists.
func (s *Store) Load() (*Policy, error) {
	h, err := s.head()
	if err != nil || h == "" {
		return nil, err
	}
	return s.loadObject(h)
}

// HeadHash returns the head hash ("" if no policy).
func (s *Store) HeadHash() (string, error) { return s.head() }

// save writes a policy object and repoints HEAD at it; returns the new hash.
// Both writes are atomic (temp file + rename) and the object is durably written
// before HEAD is moved, so a crash can never leave HEAD pointing at a
// half-written or missing object.
func (s *Store) save(p *Policy) (string, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	h := hashOf(payload)
	if err := os.MkdirAll(s.objectsDir(), 0o755); err != nil {
		return "", err
	}
	if err := writeAtomic(s.objPath(h), payload, 0o644); err != nil {
		return "", err
	}
	if err := writeAtomic(s.headPath(), []byte(h+"\n"), 0o644); err != nil {
		return "", err
	}
	return h, nil
}

// writeAtomic writes data to path via a temp file in the same directory, fsync,
// and rename — so a reader sees either the old file or the complete new one.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// lock takes an exclusive on-disk lock so two concurrent gitsafe processes
// cannot race to extend the chain (which would silently drop one version).
// The returned release function must be called.
func (s *Store) lock() (func(), error) {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(s.dir, "lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("policy is locked by another gitsafe process (%s); retry, or remove the file if stale", lockPath)
		}
		return nil, err
	}
	f.Close()
	return func() { os.Remove(lockPath) }, nil
}

// Mutate creates the next signed policy version by applying fn to a copy of the
// current policy (or an empty v0 if none exists), signs it as signer, verifies
// it against its parent, and saves it. Returns the new head hash.
func (s *Store) Mutate(signer string, priv ed25519.PrivateKey, fn func(*Policy) error) (string, error) {
	release, err := s.lock()
	if err != nil {
		return "", err
	}
	defer release()

	cur, err := s.Load()
	if err != nil {
		return "", err
	}
	var next Policy
	if cur == nil {
		next = Policy{Keyring: map[string]Member{}, Groups: map[string][]string{}}
	} else {
		headHash, _ := s.head()
		next = clone(cur)
		next.Version = cur.Version + 1
		next.Parent = headHash
	}
	if err := fn(&next); err != nil {
		return "", err
	}
	next.Sign(signer, priv)
	if err := next.Verify(cur); err != nil {
		return "", err
	}
	return s.save(&next)
}

// clone deep-copies a policy via JSON round-trip, clearing the signature.
func clone(p *Policy) Policy {
	b, _ := json.Marshal(p)
	var out Policy
	json.Unmarshal(b, &out)
	out.Sig = ""
	out.Signer = ""
	return out
}

// VerifyChain walks the chain from head to root, verifying every version's
// signature and authority and that parent hashes link correctly. Returns the
// number of versions.
func (s *Store) VerifyChain() (int, error) {
	n, _, err := s.VerifyChainRoot()
	return n, err
}

// VerifyChainRoot verifies the whole chain and additionally returns the root
// version's signer public key (hex). That key is the trust anchor: a clone pins
// it (TOFU) so a wholesale chain replacement under a different root — which
// would otherwise verify as internally consistent — is detected.
func (s *Store) VerifyChainRoot() (int, string, error) {
	head, err := s.head()
	if err != nil {
		return 0, "", err
	}
	if head == "" {
		return 0, "", nil
	}
	var chain []*Policy
	h := head
	for h != "" {
		p, err := s.loadObject(h)
		if err != nil {
			return 0, "", err
		}
		chain = append(chain, p)
		h = p.Parent
	}
	// Verify from root upward so each has its parent available.
	for i := len(chain) - 1; i >= 0; i-- {
		var parent *Policy
		if i+1 < len(chain) {
			parent = chain[i+1]
		}
		if err := chain[i].Verify(parent); err != nil {
			return 0, "", err
		}
	}
	root := chain[len(chain)-1]
	rootPub := root.Keyring[root.Signer].Sign
	return len(chain), rootPub, nil
}

// trimSpace trims surrounding ASCII whitespace without importing strings.
func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
