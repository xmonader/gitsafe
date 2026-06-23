// Package secret provides end-to-end encryption of marked files: age
// multi-recipient encryption, decryption, and glob-based path classification.
// This is gitsafe's encryption primitive.
package secret

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"filippo.io/age"
)

// Encrypt encrypts plaintext to the given age recipient strings ("age1...").
// Any holder of a corresponding private key can decrypt.
func Encrypt(plaintext []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients to encrypt to")
	}
	var recips []age.Recipient
	for _, r := range recipients {
		x, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, fmt.Errorf("bad recipient %q: %w", r, err)
		}
		recips = append(recips, x)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recips...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext using one or more identities. It returns an error
// if none of the identities is a recipient.
func Decrypt(ciphertext []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Match reports whether a forward-slash path matches any of the mark globs.
// A pattern without a slash matches against the path's basename, so "*.pem"
// matches "config/server.pem". "**" matches across directory separators.
func Match(p string, marks []string) bool {
	base := path.Base(p)
	for _, m := range marks {
		if !strings.Contains(m, "/") {
			if globMatch(m, base) {
				return true
			}
			continue
		}
		if globMatch(m, p) {
			return true
		}
	}
	return false
}

// globMatch matches a glob (* within a segment, ** across segments) against s.
func globMatch(pattern, s string) bool {
	re, err := regexp.Compile("^" + globToRegexp(pattern) + "$")
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func globToRegexp(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(p[i])
		default:
			b.WriteByte(p[i])
		}
	}
	return b.String()
}
