package policy

import (
	"crypto/ed25519"
	"fmt"
)

// Bootstrap creates policy v0 for a fresh repo: the founding member as admin
// over everything (admin implies read, so they can decrypt every branch's
// secrets). No public grant is created — gitsafe's default is least-privilege;
// readers are added explicitly. Errors if a policy already exists.
func Bootstrap(s *Store, me, signPub, encPub string, priv ed25519.PrivateKey) error {
	cur, err := s.Load()
	if err != nil {
		return err
	}
	if cur != nil {
		return fmt.Errorf("policy already exists")
	}
	_, err = s.Mutate(me, priv, func(p *Policy) error {
		p.Keyring[me] = Member{Sign: signPub, Enc: encPub, Status: "active"}
		p.Grants = []Grant{
			{ID: "root-admin", Subject: me, Verb: Admin, Resource: "refs/**"},
		}
		p.SecretPaths = DefaultSecretPaths()
		return nil
	})
	return err
}

// DefaultSecretPaths is the starter mark set written into .gitattributes by
// `gitsafe init` and recorded in the policy for reference.
func DefaultSecretPaths() []string {
	return []string{".env", ".env.*", "*.pem", "*.key", "secrets/**"}
}

// RecipientsFor returns the age recipients a secret on resource must be
// encrypted to (the active readers). Returns nil if there is no policy.
func RecipientsFor(s *Store, resource string) ([]string, error) {
	p, err := s.Load()
	if err != nil || p == nil {
		return nil, err
	}
	return p.Recipients(resource), nil
}
