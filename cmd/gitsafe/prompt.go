package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// promptPassphrase reads a passphrase from the controlling terminal with echo
// disabled. When confirm is set it asks twice and checks the entries match. It
// is installed as identity.Prompter for interactive commands only — the git
// filters have no usable terminal and rely on GITSAFE_PASSPHRASE instead.
func promptPassphrase(confirm bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("cannot read passphrase: no terminal available; set GITSAFE_PASSPHRASE")
	}
	defer tty.Close()

	fmt.Fprint(tty, "gitsafe passphrase: ")
	p1, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	if len(p1) == 0 {
		return "", fmt.Errorf("empty passphrase")
	}
	if confirm {
		fmt.Fprint(tty, "confirm passphrase: ")
		p2, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", fmt.Errorf("passphrases do not match")
		}
	}
	return string(p1), nil
}
