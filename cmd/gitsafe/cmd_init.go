package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitsafe/internal/gitx"
	"gitsafe/internal/identity"
	"gitsafe/internal/policy"
)

func cmdInit(args []string) error {
	user := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 >= len(args) {
				return fmt.Errorf("--user requires a value")
			}
			user = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}

	rc, err := loadRepo()
	if err != nil {
		return err
	}

	if user == "" {
		user, _ = gitx.ConfigGet("user.name")
	}
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		return fmt.Errorf("could not determine a user name; pass --user NAME")
	}

	// 1. Identity.
	id := identity.LoadOrNil()
	if id == nil {
		id, err = identity.Generate()
		if err != nil {
			return err
		}
		fmt.Printf("Generated identity at %s\n", identity.Path())
	}

	// 2. Register the filter in git config.
	for k, v := range map[string]string{
		"filter.gitsafe.clean":    "gitsafe clean %f",
		"filter.gitsafe.smudge":   "gitsafe smudge %f",
		"filter.gitsafe.required": "true",
		"merge.gitsafe.name":      "gitsafe encrypted-file 3-way merge",
		"merge.gitsafe.driver":    "gitsafe merge %O %A %B %P",
		"gitsafe.user":            user,
	} {
		if err := gitx.ConfigSet(k, v); err != nil {
			return err
		}
	}

	// 3. Default .gitattributes marks.
	if err := ensureAttributes(rc.root); err != nil {
		return err
	}

	// 4. Bootstrap policy v0 if absent.
	cur, err := rc.store.Load()
	if err != nil {
		return err
	}
	if cur == nil {
		if err := policy.Bootstrap(rc.store, user, id.SignPub(), id.Recipient(), id.Sign); err != nil {
			return err
		}
		fmt.Printf("Bootstrapped policy v0 with %q as admin.\n", user)
		// The founder is the root: pin it automatically (they trust themselves).
		if _, rootPub, verr := rc.store.VerifyChainRoot(); verr == nil && rootPub != "" {
			if err := writePin(rootPub); err != nil {
				return err
			}
			fmt.Printf("Pinned policy root %s\n", short(rootPub))
		}
	} else {
		// Existing policy (e.g. a fresh clone): wire up filters but do NOT pin
		// automatically — trust must be established deliberately, out-of-band.
		fmt.Printf("Policy already present (v%d); filters wired.\n", cur.Version)
		if pin, _ := readPin(); pin == "" {
			if _, rootPub, verr := rc.store.VerifyChainRoot(); verr == nil && rootPub != "" {
				fmt.Printf("Policy root fingerprint:\n  %s\nVerify it out-of-band, then run 'gitsafe trust' before committing secrets.\n", rootPub)
			}
		}
	}

	fmt.Printf(`
gitsafe is ready. Next steps:
  git add .gitsafe .gitattributes && git commit -m "enable gitsafe"
  # add a teammate:
  #   they run:  gitsafe key show
  #   you run:   gitsafe member add bob --sign <hex> --enc <age1...>
  #              gitsafe grant bob read %s
  #              gitsafe rotate
`, "<branch>")
	return nil
}

// attrLines are the default marks plus a guard keeping policy files unfiltered.
func attrLines() []string {
	lines := []string{"# gitsafe: encrypt marked secrets"}
	for _, m := range policy.DefaultSecretPaths() {
		lines = append(lines, m+" filter=gitsafe merge=gitsafe")
	}
	lines = append(lines, ".gitsafe/** -filter")
	return lines
}

// ensureAttributes appends the gitsafe block to .gitattributes if not present.
func ensureAttributes(root string) error {
	path := filepath.Join(root, ".gitattributes")
	existing, _ := os.ReadFile(path)
	if strings.Contains(string(existing), "filter=gitsafe") {
		return nil // already configured; don't duplicate
	}
	block := strings.Join(attrLines(), "\n") + "\n"
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		block = "\n" + block
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(block)
	return err
}
