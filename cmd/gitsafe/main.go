// Command gitsafe is git-crypt with access control: it encrypts marked files in
// a git repo to exactly the people the signed policy says can read the current
// branch, and verifies that policy offline with no server.
package main

import (
	"fmt"
	"os"

	"gitsafe/internal/gitx"
	"gitsafe/internal/identity"
	"gitsafe/internal/policy"
)

// filterCmds run non-interactively under git; they must not prompt on a tty and
// rely on GITSAFE_PASSPHRASE to unlock an encrypted identity.
var filterCmds = map[string]bool{"clean": true, "smudge": true, "merge": true}

// version is overridden at release time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

var usage = `gitsafe ` + version + ` — git-crypt with access control

Usage:
  gitsafe init [--user NAME]      Wire up filters, identity, and policy in this repo
  gitsafe key gen [--passphrase]  Generate your private identity (~/.config/gitsafe)
  gitsafe key show                Print your public keys (give these to an admin)
  gitsafe key lock                Encrypt an existing identity at rest with a passphrase

  gitsafe member add NAME --enc age1... [--sign HEX]   Add a member (--sign only for admins)
  gitsafe member revoke NAME                         Revoke a member (then rotate)
  gitsafe onboard NAME BRANCH --enc age1... [--sign HEX]  Add + grant read + rotate, in one step
  gitsafe group add|remove|list ...                  Manage named groups of members
  gitsafe grant SUBJECT VERB RESOURCE                Grant read|write|admin
  gitsafe revoke SUBJECT VERB RESOURCE               Remove matching grant(s)
  gitsafe rotate                                     Re-encrypt secrets to current readers

  gitsafe trust [--fingerprint HEX] [--force]        Pin this clone to the policy root (TOFU)
  gitsafe access RESOURCE          Show who can decrypt secrets on a branch/ref
  gitsafe audit [RESOURCE]         Show how access changed across policy versions
  gitsafe check                    Fail if a marked secret is staged as plaintext (pre-commit hook)
  gitsafe whoami                   Show your identity and policy membership
  gitsafe policy show             Show the current policy
  gitsafe policy verify           Verify the signed policy chain offline

  gitsafe clean PATH              (filter) encrypt stdin -> stdout
  gitsafe smudge PATH             (filter) decrypt stdin -> stdout
  gitsafe merge O A B [P]         (merge driver) 3-way merge of encrypted files

RESOURCE is a ref glob; a bare branch name is treated as refs/heads/<name>.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	// Interactive commands may prompt for the identity passphrase on the
	// terminal; the git filters must not (no usable tty), so they use the env.
	if !filterCmds[os.Args[1]] {
		identity.Prompter = promptPassphrase
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(args)
	case "key":
		err = cmdKey(args)
	case "clean":
		err = cmdClean(args)
	case "smudge":
		err = cmdSmudge(args)
	case "merge":
		err = cmdMerge(args)
	case "member":
		err = cmdMember(args)
	case "onboard":
		err = cmdOnboard(args)
	case "group":
		err = cmdGroup(args)
	case "grant":
		err = cmdGrant(args)
	case "revoke":
		err = cmdRevoke(args)
	case "rotate":
		err = cmdRotate(args)
	case "trust":
		err = cmdTrust(args)
	case "access":
		err = cmdAccess(args)
	case "audit":
		err = cmdAudit(args)
	case "check":
		err = cmdCheck(args)
	case "whoami":
		err = cmdWhoami(args)
	case "policy":
		err = cmdPolicy(args)
	case "version", "--version", "-v":
		fmt.Println("gitsafe", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitsafe:", err)
		os.Exit(1)
	}
}

// repoCtx bundles the per-repo state most commands need.
type repoCtx struct {
	root  string
	store *policy.Store
}

// loadRepo resolves the repo root and policy store.
func loadRepo() (*repoCtx, error) {
	if !gitx.InRepo() {
		return nil, fmt.Errorf("not inside a git repository")
	}
	root, err := gitx.Root()
	if err != nil {
		return nil, err
	}
	return &repoCtx{root: root, store: policy.NewStore(root)}, nil
}

// actorName returns the configured gitsafe user for this repo.
func actorName() (string, error) {
	name, err := gitx.ConfigGet("gitsafe.user")
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", fmt.Errorf("no gitsafe user set; run 'gitsafe init --user NAME'")
	}
	return name, nil
}

// loadIdentity loads the local private identity.
func loadIdentity() (*identity.Identity, error) {
	return identity.Load()
}

// resource normalizes a CLI resource argument: a bare branch name becomes
// refs/heads/<name>; anything already starting with "refs/" is used verbatim.
func resource(arg string) string {
	if len(arg) >= 5 && arg[:5] == "refs/" {
		return arg
	}
	return "refs/heads/" + arg
}
