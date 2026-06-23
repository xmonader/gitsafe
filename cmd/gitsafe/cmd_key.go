package main

import (
	"fmt"

	"gitsafe/internal/identity"
)

func cmdKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitsafe key gen|show")
	}
	switch args[0] {
	case "gen":
		return keyGen()
	case "show":
		return keyShow()
	default:
		return fmt.Errorf("usage: gitsafe key gen|show")
	}
}

func keyGen() error {
	if identity.Exists() {
		return fmt.Errorf("identity already exists at %s", identity.Path())
	}
	id, err := identity.Generate()
	if err != nil {
		return err
	}
	fmt.Printf("Generated identity at %s\n\n", identity.Path())
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

// printPubKeys prints the public material and a ready-to-paste member-add line.
func printPubKeys(id *identity.Identity) {
	fmt.Printf("sign (ed25519):  %s\n", id.SignPub())
	fmt.Printf("enc  (age):      %s\n\n", id.Recipient())
	fmt.Printf("Give these to an admin, who runs:\n")
	fmt.Printf("  gitsafe member add <your-name> --sign %s --enc %s\n", id.SignPub(), id.Recipient())
}
