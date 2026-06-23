package main

import (
	"fmt"
	"io"
	"os"

	"gitsafe/internal/filter"
	"gitsafe/internal/gitx"
	"gitsafe/internal/identity"
	"gitsafe/internal/secret"
)

// cmdClean is the thin CLI adapter for the git clean filter: it reads stdin,
// delegates the decision to filter.Clean (the testable core), and writes stdout.
func cmdClean(args []string) error {
	path, input, err := readFilterInput(args, "clean")
	if err != nil {
		return err
	}
	out, err := filter.Clean(input, path, prodDeps())
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

// cmdSmudge is the thin CLI adapter for the git smudge filter.
func cmdSmudge(args []string) error {
	path, input, err := readFilterInput(args, "smudge")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(filter.Smudge(input, path, prodDeps()))
	return err
}

// readFilterInput validates the path argument and slurps stdin.
func readFilterInput(args []string, name string) (path string, input []byte, err error) {
	if len(args) < 1 {
		return "", nil, fmt.Errorf("usage: gitsafe %s PATH", name)
	}
	input, err = io.ReadAll(os.Stdin)
	return args[0], input, err
}

// prodDeps wires the filter core to the real git, trust, and identity layers.
func prodDeps() filter.Deps {
	return filter.Deps{
		StoredBlob: gitx.StoredBlob,
		Resource:   gitx.BranchResource,
		Recipients: trustedRecipients,
		Decrypt:    decryptWithLocalIdentity,
	}
}

// trustedRecipients resolves the readers of resource only after the policy chain
// and root pin verify — the security gate on the encrypt path.
func trustedRecipients(resource string) ([]string, error) {
	rc, err := loadRepo()
	if err != nil {
		return nil, err
	}
	pol, err := trustedPolicy(rc)
	if err != nil {
		return nil, err
	}
	return pol.Recipients(resource), nil
}

// decryptWithLocalIdentity decrypts ciphertext with the local identity, if any.
func decryptWithLocalIdentity(ciphertext []byte) ([]byte, bool) {
	id := identity.LoadOrNil()
	if id == nil {
		return nil, false
	}
	plain, err := secret.Decrypt(ciphertext, id.X25519)
	if err != nil {
		return nil, false
	}
	return plain, true
}
