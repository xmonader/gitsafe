package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"filippo.io/age"

	"gitsafe/internal/format"
	"gitsafe/internal/gitx"
	"gitsafe/internal/policy"
)

// signer loads the actor name and private signing key for a policy mutation.
func signer() (string, ed25519.PrivateKey, error) {
	name, err := actorName()
	if err != nil {
		return "", nil, err
	}
	id, err := loadIdentity()
	if err != nil {
		return "", nil, err
	}
	return name, id.Sign, nil
}

func cmdMember(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe member add|revoke ...")
	}
	switch args[0] {
	case "add":
		return memberAdd(args[1:])
	case "revoke":
		return memberRevoke(args[1:])
	default:
		return fmt.Errorf("usage: gitsafe member add|revoke ...")
	}
}

func memberAdd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe member add NAME --enc age1... [--sign HEX] [--update]")
	}
	name := args[0]
	var sign, enc string
	update := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--sign":
			if i+1 >= len(args) {
				return fmt.Errorf("--sign requires a value")
			}
			sign = args[i+1]
			i++
		case "--enc":
			if i+1 >= len(args) {
				return fmt.Errorf("--enc requires a value")
			}
			enc = args[i+1]
			i++
		case "--update":
			update = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if enc == "" {
		return fmt.Errorf("--enc is required (the teammate's age key from 'gitsafe key show')")
	}
	if err := validateMemberKeys(sign, enc); err != nil {
		return err
	}
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	who, priv, err := signer()
	if err != nil {
		return err
	}
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		existing, exists := p.Keyring[name]
		if exists && !update {
			return fmt.Errorf("member %q already exists; pass --update to replace their keys (e.g. after a key rotation)", name)
		}
		// Re-adding a member always (re-)activates them: 'member add --update' is
		// the un-revoke path. The existing sign key is preserved when no new one is
		// supplied, so rotating an admin's enc key alone never strips their ability
		// to sign.
		m := policy.Member{Enc: enc, Sign: sign, Status: "active"}
		if exists && sign == "" {
			m.Sign = existing.Sign
		}
		p.Keyring[name] = m
		return nil
	})
	if err != nil {
		return err
	}
	verb := "Added"
	if update {
		verb = "Updated"
	}
	fmt.Printf("%s member %q. Grant them access, then 'gitsafe rotate'.\n", verb, name)
	return nil
}

// validateMemberKeys rejects obviously malformed public keys before they enter
// the signed keyring, where a typo would silently produce undecryptable secrets.
// The sign key is optional (only signers/admins need one), so it is validated
// only when provided.
func validateMemberKeys(signHex, enc string) error {
	if _, err := age.ParseX25519Recipient(enc); err != nil {
		return fmt.Errorf("--enc must be a valid age recipient (age1...): %w", err)
	}
	if signHex != "" {
		raw, err := hex.DecodeString(signHex)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("--sign must be a %d-byte ed25519 public key in hex", ed25519.PublicKeySize)
		}
	}
	return nil
}

func memberRevoke(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe member revoke NAME")
	}
	name := args[0]
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	who, priv, err := signer()
	if err != nil {
		return err
	}
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		m, ok := p.Keyring[name]
		if !ok {
			return fmt.Errorf("no such member %q", name)
		}
		m.Status = "revoked"
		p.Keyring[name] = m
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Revoked %q. Run 'gitsafe rotate' to re-encrypt secrets without them.\n", name)
	return nil
}

var validVerbs = map[string]bool{
	policy.Read: true, policy.Write: true, policy.Force: true,
	policy.GrantV: true, policy.Admin: true,
}

func cmdGrant(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: gitsafe grant SUBJECT VERB RESOURCE")
	}
	subject, verb, res := args[0], args[1], resource(args[2])
	if !validVerbs[verb] {
		return fmt.Errorf("invalid verb %q (read|write|force|grant|admin)", verb)
	}
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	who, priv, err := signer()
	if err != nil {
		return err
	}
	id := grantID(subject, verb, res)
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		for _, g := range p.Grants {
			if g.ID == id {
				return fmt.Errorf("that grant already exists")
			}
		}
		// Admin authority is unusable without a signing key, and handing it out
		// can mislead operators into thinking the policy has another administrator
		// when it does not. Refuse for a concrete member who has no sign key.
		if verb == policy.Admin {
			if m, ok := p.Keyring[subject]; ok && m.Sign == "" {
				return fmt.Errorf("%q has no signing key, so admin would be unusable.\n"+
					"  Have them run 'gitsafe key show', then: gitsafe member add %s --update --sign <hex>", subject, subject)
			}
		}
		p.Grants = append(p.Grants, policy.Grant{ID: id, Subject: subject, Verb: verb, Resource: res})
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Granted %s %s on %s.\n", subject, verb, res)
	return nil
}

func cmdRevoke(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: gitsafe revoke SUBJECT VERB RESOURCE")
	}
	subject, verb, res := args[0], args[1], resource(args[2])
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	who, priv, err := signer()
	if err != nil {
		return err
	}
	id := grantID(subject, verb, res)
	removed := 0
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		var kept []policy.Grant
		for _, g := range p.Grants {
			if g.ID == id {
				removed++
				continue
			}
			kept = append(kept, g)
		}
		if removed == 0 {
			return fmt.Errorf("no matching grant for %s %s on %s", subject, verb, res)
		}
		p.Grants = kept
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Removed grant: %s %s on %s. Run 'gitsafe rotate' if this revoked read access.\n", subject, verb, res)
	return nil
}

// grantID is the stable identity of a grant, so a duplicate grant is a no-op and
// revoke can find the exact rule to remove.
func grantID(subject, verb, resource string) string {
	return subject + "|" + verb + "|" + resource
}

func cmdRotate(args []string) error {
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	files, err := gitx.FilteredFiles()
	if err != nil {
		return err
	}
	if len(files) == 0 {
		fmt.Println("No gitsafe-marked files tracked; nothing to rotate.")
		return nil
	}
	// Refuse if the working tree holds locked placeholders: a non-reader cannot
	// re-encrypt what they cannot decrypt, and silently preserving the old
	// ciphertext would make rotation a no-op disguised as success.
	for _, f := range files {
		data, rerr := os.ReadFile(filepath.Join(rc.root, f))
		if rerr != nil {
			continue // not in the working tree (e.g. deleted); skip
		}
		if format.IsLockedPlaceholder(data) {
			return fmt.Errorf("cannot rotate: %q is locked (you lack read access).\n"+
				"Rotation must be run by someone who can read these secrets", f)
		}
	}
	if err := gitx.AddRenormalize(files); err != nil {
		return err
	}
	changed, err := gitx.StagedChanges()
	if err != nil {
		return err
	}
	if len(changed) == 0 {
		fmt.Println("Secrets already match the current reader set; nothing to re-encrypt.")
		return nil
	}
	fmt.Printf("Re-encrypted and staged %d file(s) to the current reader set:\n", len(changed))
	for _, f := range changed {
		fmt.Printf("  %s\n", f)
	}
	fmt.Println("Commit to finish: git commit -m \"gitsafe: rotate secrets\"")
	return nil
}

func cmdPolicy(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe policy show|verify")
	}
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	switch args[0] {
	case "verify":
		n, rootPub, err := rc.store.VerifyChainRoot()
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Println("No policy in this repo.")
			return nil
		}
		head, _ := rc.store.HeadHash()
		fmt.Printf("Policy chain valid: %d version(s), head %s\n", n, short(head))
		fmt.Printf("Root fingerprint:  %s\n", rootPub)
		pin, _ := readPin()
		switch {
		case pin == "":
			fmt.Println("Trust:             NOT PINNED in this clone (run 'gitsafe trust')")
		case pin == rootPub:
			fmt.Println("Trust:             pinned and matches ✓")
		default:
			fmt.Printf("Trust:             MISMATCH — pinned %s (possible tampering)\n", short(pin))
		}
		return nil
	case "show":
		return policyShow(rc)
	default:
		return fmt.Errorf("usage: gitsafe policy show|verify")
	}
}

func policyShow(rc *repoCtx) error {
	p, err := rc.store.Load()
	if err != nil {
		return err
	}
	if p == nil {
		fmt.Println("No policy in this repo.")
		return nil
	}
	fmt.Printf("policy v%d (signed by %q)\n\n", p.Version, p.Signer)

	fmt.Println("members:")
	names := make([]string, 0, len(p.Keyring))
	for n := range p.Keyring {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m := p.Keyring[n]
		fmt.Printf("  %-16s %-8s %s\n", n, m.Status, m.Enc)
	}

	if len(p.Groups) > 0 {
		fmt.Println("\ngroups:")
		gnames := make([]string, 0, len(p.Groups))
		for g := range p.Groups {
			gnames = append(gnames, g)
		}
		sort.Strings(gnames)
		for _, g := range gnames {
			fmt.Printf("  %-16s %s\n", g, join(append([]string{}, p.Groups[g]...)))
		}
	}

	fmt.Println("\ngrants:")
	for _, g := range p.Grants {
		fmt.Printf("  %-12s %-6s %s\n", g.Subject, g.Verb, g.Resource)
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
