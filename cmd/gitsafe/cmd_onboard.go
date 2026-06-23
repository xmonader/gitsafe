package main

import (
	"fmt"
	"strings"

	"gitsafe/internal/policy"
)

// cmdOnboard is the one-shot teammate flow: it adds a member to the keyring and
// grants them read on a branch in a single signed policy version, then rotates
// so the branch's secrets are immediately re-encrypted to include them. It
// collapses the add → grant → rotate sequence that is otherwise easy to get
// half-done.
//
//	gitsafe onboard NAME BRANCH --sign HEX --enc age1... [--update]
func cmdOnboard(args []string) error {
	var positional []string
	var sign, enc string
	update := false
	for i := 0; i < len(args); i++ {
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
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			positional = append(positional, args[i])
		}
	}
	if len(positional) != 2 {
		return fmt.Errorf("usage: gitsafe onboard NAME BRANCH --sign HEX --enc age1... [--update]")
	}
	name, branch := positional[0], positional[1]
	res := resource(branch)
	if enc == "" {
		return fmt.Errorf("--enc is required (the teammate's age key from their 'gitsafe key show')")
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
	gid := grantID(name, policy.Read, res)
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		existing, exists := p.Keyring[name]
		if exists && !update {
			return fmt.Errorf("member %q already exists; pass --update to replace their keys", name)
		}
		// Onboarding always (re-)activates the member, so it doubles as the
		// un-revoke path; an existing sign key is preserved when none is supplied.
		m := policy.Member{Enc: enc, Sign: sign, Status: "active"}
		if exists && sign == "" {
			m.Sign = existing.Sign
		}
		p.Keyring[name] = m
		for _, g := range p.Grants {
			if g.ID == gid {
				return nil // already granted; member add still applied
			}
		}
		p.Grants = append(p.Grants, policy.Grant{ID: gid, Subject: name, Verb: policy.Read, Resource: res})
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Onboarded %q with read on %s.\n", name, res)

	// Re-encrypt the branch's secrets so the new member can read them now.
	if err := cmdRotate(nil); err != nil {
		return err
	}
	fmt.Printf("Commit to finish: git add .gitsafe && git commit -m \"onboard %s on %s\"\n", name, branch)
	return nil
}
