package main

import (
	"fmt"

	"gitsafe/internal/identity"
)

func cmdKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe key gen|show|lock")
	}
	switch args[0] {
	case "gen":
		return keyGen(args[1:])
	case "show":
		return keyShow()
	case "lock":
		return keyLock()
	default:
		return fmt.Errorf("usage: gitsafe key gen|show|lock")
	}
}

// keyGen creates a new identity. With --passphrase it is encrypted at rest.
func keyGen(args []string) error {
	encrypt := false
	for _, a := range args {
		switch a {
		case "--passphrase", "-p":
			encrypt = true
		default:
			return fmt.Errorf("unknown flag %q (usage: gitsafe key gen [--passphrase])", a)
		}
	}
	if identity.Exists() {
		return fmt.Errorf("identity already exists at %s", identity.Path())
	}

	var (
		id  *identity.Identity
		err error
	)
	if encrypt {
		pass, perr := identity.Prompter(true)
		if perr != nil {
			return perr
		}
		id, err = identity.GenerateEncrypted(pass)
	} else {
		id, err = identity.Generate()
	}
	if err != nil {
		return err
	}

	fmt.Printf("Generated identity at %s", identity.Path())
	if encrypt {
		fmt.Printf(" (passphrase-encrypted)")
	}
	fmt.Printf("\n\n")
	printPubKeys(id)
	return nil
}

func keyShow() error {
	id, err := identity.Load()
	if err != nil {
		return err
	}
	printPubKeys(id)
	return nil
}

// keyLock encrypts an existing plaintext identity at rest with a passphrase.
func keyLock() error {
	if !identity.Exists() {
		return fmt.Errorf("no identity at %s (run 'gitsafe key gen')", identity.Path())
	}
	if identity.IsEncrypted() {
		return fmt.Errorf("identity at %s is already passphrase-encrypted", identity.Path())
	}
	pass, err := identity.Prompter(true)
	if err != nil {
		return err
	}
	if err := identity.Lock(pass); err != nil {
		return err
	}
	fmt.Printf("Locked identity at %s (passphrase-encrypted).\n", identity.Path())
	fmt.Printf("git filters need the passphrase: set GITSAFE_PASSPHRASE in their environment.\n")
	return nil
}

// printPubKeys prints the public material and a ready-to-paste member-add line.
func printPubKeys(id *identity.Identity) {
	fmt.Printf("sign (ed25519):  %s\n", id.SignPub())
	fmt.Printf("enc  (age):      %s\n\n", id.Recipient())
	fmt.Printf("Give these to an admin, who runs:\n")
	fmt.Printf("  gitsafe member add <your-name> --sign %s --enc %s\n", id.SignPub(), id.Recipient())
}
