package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitsafe/internal/gitx"
	"gitsafe/internal/policy"
)

// trustPath is where this clone pins the policy root's signing key. It lives in
// .git/ (per-clone, never committed) — the SSH known_hosts model: trust is
// established locally, out-of-band, not asserted by the repo about itself.
func trustPath() (string, error) {
	gitDir, err := gitx.GitDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(gitDir, "gitsafe", "root"), nil
}

// readPin returns the pinned root key hex, or "" if this clone has not pinned.
func readPin() (string, error) {
	p, err := trustPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// writePin records the trusted root key hex for this clone.
func writePin(rootPub string) error {
	p, err := trustPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(rootPub+"\n"), 0o644)
}

// verifiedPath is the per-clone cache of the last fully-verified policy head and
// its root key, used to skip re-walking an unchanged chain. Lives in .git/.
func verifiedPath() (string, error) {
	gitDir, err := gitx.GitDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(gitDir, "gitsafe", "verified"), nil
}

// readVerified returns the cached (head, rootPub), or ("","") if absent/unreadable.
func readVerified() (head, rootPub string) {
	p, err := verifiedPath()
	if err != nil {
		return "", ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", ""
	}
	parts := strings.Fields(string(b))
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// writeVerified records that head verified with root rootPub.
func writeVerified(head, rootPub string) error {
	p, err := verifiedPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(head+" "+rootPub+"\n"), 0o644)
}

// trustedPolicy verifies the signed chain AND that its root matches this clone's
// pin, then returns the current policy. This is the gate every operation that
// trusts policy-derived recipients (i.e. the clean filter) must pass through —
// without it, a poisoned or wholesale-replaced policy could redirect a secret's
// encryption to an attacker's key.
//
// Because a policy head hash is content-addressed, an unchanged head means the
// entire reachable chain is byte-identical to one already verified, so we cache
// the verified (head -> root) and skip the O(chain) walk on a hit. The cache
// lives in .git/ alongside the pin, so a content-only attacker (who can change
// the committed policy but not your .git) cannot forge a hit: changing the head
// misses the cache and forces a full re-verification.
func trustedPolicy(rc *repoCtx) (*policy.Policy, error) {
	head, err := rc.store.HeadHash()
	if err != nil {
		return nil, err
	}
	if head == "" {
		return nil, fmt.Errorf("no gitsafe policy in this repo (run 'gitsafe init')")
	}

	var rootPub string
	if cachedHead, cachedRoot := readVerified(); cachedHead == head && cachedRoot != "" {
		rootPub = cachedRoot // fast path: this exact chain already verified
	} else {
		n, rp, verr := rc.store.VerifyChainRoot()
		if verr != nil {
			return nil, fmt.Errorf("policy chain failed verification: %w", verr)
		}
		if n == 0 {
			return nil, fmt.Errorf("no gitsafe policy in this repo (run 'gitsafe init')")
		}
		rootPub = rp
		_ = writeVerified(head, rootPub)
	}

	pin, err := readPin()
	if err != nil {
		return nil, err
	}
	if pin == "" {
		return nil, fmt.Errorf("policy root is not trusted in this clone.\n"+
			"  Verify this fingerprint out-of-band, then run 'gitsafe trust':\n    %s", rootPub)
	}
	if pin != rootPub {
		return nil, fmt.Errorf("policy root changed — REFUSING to use it (possible tampering).\n"+
			"  pinned: %s\n  actual: %s\n"+
			"  If this is an intended re-bootstrap, run: gitsafe trust --fingerprint %s --force",
			pin, rootPub, rootPub)
	}
	return rc.store.Load()
}

func cmdTrust(args []string) error {
	var fingerprint string
	force := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--fingerprint":
			if i+1 >= len(args) {
				return fmt.Errorf("--fingerprint requires a value")
			}
			fingerprint = strings.TrimSpace(args[i+1])
			i++
		case "--force":
			force = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}

	rc, err := loadRepo()
	if err != nil {
		return err
	}
	n, rootPub, err := rc.store.VerifyChainRoot()
	if err != nil {
		return fmt.Errorf("policy chain failed verification: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("no gitsafe policy in this repo (run 'gitsafe init')")
	}
	if fingerprint != "" && fingerprint != rootPub {
		return fmt.Errorf("the current policy root is\n    %s\nnot the fingerprint you gave\n    %s\nrefusing to pin a mismatch", rootPub, fingerprint)
	}

	pin, err := readPin()
	if err != nil {
		return err
	}
	if pin == rootPub {
		fmt.Printf("Already trusting policy root %s\n", short(rootPub))
		return nil
	}
	if pin != "" && !force {
		return fmt.Errorf("this clone already pins a different root:\n  pinned: %s\n  current: %s\nuse --force to re-pin", pin, rootPub)
	}
	if err := writePin(rootPub); err != nil {
		return err
	}
	if head, herr := rc.store.HeadHash(); herr == nil && head != "" {
		_ = writeVerified(head, rootPub) // keep the fast-path cache consistent
	}
	fmt.Printf("Pinned policy root %s\n", rootPub)
	return nil
}
