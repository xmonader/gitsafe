package main

import (
	"fmt"
	"sort"

	"gitsafe/internal/identity"
	"gitsafe/internal/policy"
)

// cmdAccess answers "who can decrypt the secrets on this resource?" — the core
// audit question. It resolves grants (including groups, admins, and public)
// down to concrete active members.
func cmdAccess(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: gitsafe access RESOURCE   (branch name or ref glob)")
	}
	res := resource(args[0])
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	pol, err := rc.store.Load()
	if err != nil {
		return err
	}
	if pol == nil {
		return fmt.Errorf("no gitsafe policy in this repo (run 'gitsafe init')")
	}

	names := pol.ReaderNames(res)
	_, public := pol.Readers(res)
	recipients := pol.Recipients(res)

	fmt.Printf("%s\n", res)
	if len(names) == 0 {
		fmt.Println("  readers:    (none — secrets here cannot be committed until someone is granted read)")
	} else if public {
		fmt.Printf("  readers:    * (public) → all %d active member(s): %s\n", len(names), join(names))
	} else {
		fmt.Printf("  readers:    %s\n", join(names))
	}
	fmt.Printf("  encrypts to %d age recipient(s)\n", len(recipients))
	return nil
}

// cmdWhoami reports the local identity, its policy membership, and an integrity
// check that the on-disk identity matches the keyring entry.
func cmdWhoami(args []string) error {
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	name, _ := actorName()
	if name == "" {
		name = "(unset — run 'gitsafe init --user NAME')"
	}
	fmt.Printf("user: %s\n", name)

	id := identity.LoadOrNil()
	if id == nil {
		fmt.Printf("identity: none on this machine (run 'gitsafe key gen')\n")
	} else {
		fmt.Printf("identity: %s\n  sign %s\n  enc  %s\n", identity.Path(), id.SignPub(), id.Recipient())
	}

	pol, err := rc.store.Load()
	if err != nil || pol == nil {
		return err
	}
	m, ok := pol.Keyring[name]
	if !ok {
		fmt.Printf("membership: not in the keyring under %q\n", name)
		return nil
	}
	fmt.Printf("membership: %s in keyring (status: %s)\n", name, m.Status)
	if id != nil {
		if m.Sign == id.SignPub() && m.Enc == id.Recipient() {
			fmt.Println("  keys match your local identity ✓")
		} else {
			fmt.Println("  WARNING: keyring keys do NOT match your local identity — signing will fail")
		}
	}

	// Grants where this user is the direct subject.
	var mine []policy.Grant
	for _, g := range pol.Grants {
		if g.Subject == name {
			mine = append(mine, g)
		}
	}
	if len(mine) > 0 {
		fmt.Println("grants (direct):")
		for _, g := range mine {
			fmt.Printf("  %-6s %s\n", g.Verb, g.Resource)
		}
	}
	return nil
}

// cmdAudit reports how access evolved across the signed policy chain — the
// "who could read what, and when did it change" query compliance reviewers ask.
// With a RESOURCE it shows the reader set of that branch at every version,
// flagging the versions where it changed. Without one it prints the grant
// history version-by-version.
func cmdAudit(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: gitsafe audit [RESOURCE]")
	}
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	chain, err := rc.store.Chain()
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		fmt.Println("No policy in this repo.")
		return nil
	}

	if len(args) == 1 {
		res := resource(args[0])
		fmt.Printf("access history for %s\n", res)
		prev := "\x00" // sentinel so v0 always prints
		for _, p := range chain {
			cur := join(p.ReaderNames(res))
			if cur == "" {
				cur = "(none)"
			}
			marker := ""
			if cur != prev {
				marker = "  <- changed"
			}
			fmt.Printf("  v%-3d by %-14s %s%s\n", p.Version, p.Signer, cur, marker)
			prev = cur
		}
		return nil
	}

	fmt.Println("policy change history (root -> head):")
	for _, p := range chain {
		fmt.Printf("  v%d  signed by %-14s  %d member(s), %d grant(s)\n",
			p.Version, p.Signer, len(p.Keyring), len(p.Grants))
		for _, g := range p.Grants {
			fmt.Printf("      %-12s %-6s %s\n", g.Subject, g.Verb, g.Resource)
		}
	}
	return nil
}

func join(xs []string) string {
	sort.Strings(xs)
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
