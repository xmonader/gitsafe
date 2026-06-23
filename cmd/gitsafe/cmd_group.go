package main

import (
	"fmt"
	"sort"

	"gitsafe/internal/policy"
)

// cmdGroup manages named groups of members. A group can be the subject of a
// grant (e.g. "grant devs read staging"), so teams manage access by role rather
// than per person. Groups are expanded to their members wherever access is
// evaluated.
func cmdGroup(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe group add|remove|list ...")
	}
	switch args[0] {
	case "add":
		return groupAdd(args[1:])
	case "remove", "rm":
		return groupRemove(args[1:])
	case "list", "show":
		return groupList()
	default:
		return fmt.Errorf("usage: gitsafe group add|remove|list ...")
	}
}

// groupAdd adds one or more members to a group, creating it if absent.
func groupAdd(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gitsafe group add GROUP NAME [NAME...]")
	}
	group, members := args[0], args[1:]
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	who, priv, err := signer()
	if err != nil {
		return err
	}
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		if _, isMember := p.Keyring[group]; isMember {
			return fmt.Errorf("%q is already a member name; a group cannot share a name with a member", group)
		}
		for _, m := range members {
			if _, ok := p.Keyring[m]; !ok {
				return fmt.Errorf("no such member %q (add them to the keyring first)", m)
			}
		}
		if p.Groups == nil {
			p.Groups = map[string][]string{}
		}
		p.Groups[group] = unionSorted(p.Groups[group], members)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Group %q now has: %s\n", group, join(append([]string{}, members...)))
	fmt.Println("If this group holds read access, run 'gitsafe rotate' to include the new members.")
	return nil
}

// groupRemove removes members from a group, or deletes the whole group when no
// member names are given. A group left empty is deleted.
func groupRemove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe group remove GROUP [NAME...]")
	}
	group, members := args[0], args[1:]
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	who, priv, err := signer()
	if err != nil {
		return err
	}
	_, err = rc.store.Mutate(who, priv, func(p *policy.Policy) error {
		cur, ok := p.Groups[group]
		if !ok {
			return fmt.Errorf("no such group %q", group)
		}
		if len(members) == 0 {
			delete(p.Groups, group)
			return nil
		}
		drop := map[string]bool{}
		for _, m := range members {
			drop[m] = true
		}
		var kept []string
		for _, m := range cur {
			if !drop[m] {
				kept = append(kept, m)
			}
		}
		if len(kept) == 0 {
			delete(p.Groups, group)
		} else {
			p.Groups[group] = kept
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Updated group %q. Run 'gitsafe rotate' if this removed read access.\n", group)
	return nil
}

// groupList prints the groups and their members.
func groupList() error {
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	p, err := rc.store.Load()
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("no gitsafe policy in this repo (run 'gitsafe init')")
	}
	if len(p.Groups) == 0 {
		fmt.Println("No groups defined.")
		return nil
	}
	names := make([]string, 0, len(p.Groups))
	for g := range p.Groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		fmt.Printf("  %-16s %s\n", g, join(append([]string{}, p.Groups[g]...)))
	}
	return nil
}

// unionSorted merges b into a, de-duplicated and sorted.
func unionSorted(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
