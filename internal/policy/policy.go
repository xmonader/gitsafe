// Package policy implements gitsafe's signed access policy: a keyring, groups,
// and signed capability grants, chained version-over-version so anyone can
// verify it offline but nobody can forge it. policy.Eval is the single access
// decision; policy.Recipients turns "who can read this branch" into the age
// recipient set a secret is encrypted to. Resources are git refs
// (e.g. refs/heads/<branch>).
package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Member is a keyring entry: an actor's public keys.
type Member struct {
	Sign   string `json:"sign"`   // ed25519 public key, hex
	Enc    string `json:"enc"`    // age recipient ("age1...")
	Status string `json:"status"` // "active" or "revoked"
}

// Grant is a capability. Verbs: read, write, force, grant, admin.
type Grant struct {
	ID       string `json:"id"`
	Subject  string `json:"subject"` // actor name, group name, or "*"
	Verb     string `json:"verb"`
	Resource string `json:"resource"` // ref glob, e.g. refs/heads/**
}

// Policy is one signed version in the chain.
type Policy struct {
	Version     int                 `json:"version"`
	Parent      string              `json:"parent"` // hash of previous policy object
	Keyring     map[string]Member   `json:"keyring"`
	Groups      map[string][]string `json:"groups"`
	Grants      []Grant             `json:"grants"`
	Restricted  []string            `json:"restricted"` // ref globs where public ("*") grants do NOT apply
	SecretPaths []string            `json:"secret_paths"`
	Signer      string              `json:"signer"` // actor who signed this version
	Sig         string              `json:"sig"`    // hex ed25519 signature over the unsigned form
}

// Verbs.
const (
	Read   = "read"
	Write  = "write"
	Force  = "force"
	GrantV = "grant"
	Admin  = "admin"
)

var rank = map[string]int{Read: 1, Write: 2, Force: 3, Admin: 4}

// PolicyResource is the reserved resource controlling who may change policy.
const PolicyResource = "refs/policy"

// signingBytes is the canonical JSON of the policy with an empty signature.
func (p *Policy) signingBytes() []byte {
	clone := *p
	clone.Sig = ""
	b, _ := json.Marshal(clone)
	return b
}

// Sign signs the policy version with the signer's private key and records the
// signer name.
func (p *Policy) Sign(signer string, priv ed25519.PrivateKey) {
	p.Signer = signer
	sig := ed25519.Sign(priv, p.signingBytes())
	p.Sig = hex.EncodeToString(sig)
}

// verifySig checks the signature against a given public key (hex).
func (p *Policy) verifySig(signPubHex string) bool {
	pub, err := hex.DecodeString(signPubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(p.Sig)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), p.signingBytes(), sig)
}

// Verify checks this version against its parent (nil for v0). It confirms the
// signature and that the signer was authorized to change policy.
func (p *Policy) Verify(parent *Policy) error {
	if parent == nil {
		// Root version: self-signed by a member in its own keyring.
		m, ok := p.Keyring[p.Signer]
		if !ok {
			return fmt.Errorf("policy v%d signer %q not in keyring", p.Version, p.Signer)
		}
		if !p.verifySig(m.Sign) {
			return fmt.Errorf("policy v%d signature invalid", p.Version)
		}
		return nil
	}
	// Later version: numbering must advance by exactly one over the parent, so the
	// version is a trustworthy monotonic counter (the anti-rollback high-water
	// mark in the trust gate relies on this).
	if p.Version != parent.Version+1 {
		return fmt.Errorf("policy v%d does not follow parent v%d (version must increase by exactly one)", p.Version, parent.Version)
	}
	// Signer must have held admin in the parent.
	m, ok := parent.Keyring[p.Signer]
	if !ok {
		return fmt.Errorf("policy v%d signer %q not in parent keyring", p.Version, p.Signer)
	}
	if !p.verifySig(m.Sign) {
		return fmt.Errorf("policy v%d signature invalid", p.Version)
	}
	if !parent.Eval(p.Signer, Admin, PolicyResource) {
		return fmt.Errorf("policy v%d signer %q lacked admin", p.Version, p.Signer)
	}
	return nil
}

// Eval is the access decision: may actor perform verb on resource?
func (p *Policy) Eval(actor, verb, resource string) bool {
	restricted := p.isRestricted(resource)
	for _, g := range p.Grants {
		// On a restricted ref, wildcard ("*") grants do not apply — only
		// concrete actors/groups can reach it.
		if g.Subject == "*" && restricted {
			continue
		}
		if !p.subjectMatches(g.Subject, actor) {
			continue
		}
		if !matchResource(g.Resource, resource) {
			continue
		}
		if verbSatisfies(g.Verb, verb) {
			return true
		}
	}
	return false
}

// isRestricted reports whether resource is a need-to-know ref (public grants
// suppressed). refs/policy is ALWAYS restricted: administering the policy must be
// granted to named subjects, never to "*", so a wildcard grant can never silently
// make every keyring member an admin.
func (p *Policy) isRestricted(resource string) bool {
	if resource == PolicyResource {
		return true
	}
	for _, pat := range p.Restricted {
		if matchResource(pat, resource) {
			return true
		}
	}
	return false
}

// Readers returns the set of actors that may read resource, and whether it is
// public (granted to "*").
func (p *Policy) Readers(resource string) (map[string]bool, bool) {
	set := map[string]bool{}
	public := false
	restricted := p.isRestricted(resource)
	for _, g := range p.Grants {
		if !matchResource(g.Resource, resource) || !verbSatisfies(g.Verb, Read) {
			continue
		}
		switch {
		case g.Subject == "*":
			if !restricted {
				public = true
			}
		case p.isGroup(g.Subject):
			for _, a := range p.Groups[g.Subject] {
				set[a] = true
			}
		default:
			set[g.Subject] = true
		}
	}
	return set, public
}

// Recipients returns the age recipients of every active reader of resource.
// If the resource is public, all active members are recipients (a secret on a
// public branch is readable by the whole team, never the anonymous public).
// The result is sorted for deterministic encryption headers.
func (p *Policy) Recipients(resource string) []string {
	readers, public := p.Readers(resource)
	var out []string
	for name, m := range p.Keyring {
		if m.Status == "revoked" || m.Enc == "" {
			// Skip a member with no encryption key: including "" would make
			// age.ParseX25519Recipient fail and block encrypting the secret to
			// everyone, so one malformed keyring entry can't break the whole branch.
			continue
		}
		if public || readers[name] {
			out = append(out, m.Enc)
		}
	}
	sort.Strings(out)
	return out
}

// ReaderNames returns the names of active members who can decrypt resource —
// the human-readable counterpart of Recipients, for auditing "who can read X".
func (p *Policy) ReaderNames(resource string) []string {
	readers, public := p.Readers(resource)
	var out []string
	for name, m := range p.Keyring {
		if m.Status == "revoked" {
			continue
		}
		if public || readers[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (p *Policy) subjectMatches(subject, actor string) bool {
	switch {
	case subject == "*":
		return true
	case subject == actor:
		return true
	case p.isGroup(subject):
		for _, a := range p.Groups[subject] {
			if a == actor {
				return true
			}
		}
	}
	return false
}

func (p *Policy) isGroup(name string) bool {
	_, ok := p.Groups[name]
	return ok
}

// HasUsableAdmin reports whether at least one active member with a signing key
// can administer the policy. It is the invariant that keeps the chain from being
// bricked: every version must retain someone who can sign the next one.
func (p *Policy) HasUsableAdmin() bool {
	for name, m := range p.Keyring {
		if m.Status != "active" || m.Sign == "" {
			continue
		}
		if p.Eval(name, Admin, PolicyResource) {
			return true
		}
	}
	return false
}

// verbSatisfies reports whether holding verb `have` authorizes `need`.
// admin > force > write > read; admin also implies grant. grant implies grant.
func verbSatisfies(have, need string) bool {
	if need == GrantV {
		return have == GrantV || have == Admin
	}
	if have == GrantV {
		return need == GrantV
	}
	return rank[have] >= rank[need] && rank[need] > 0
}

// matchResource matches a ref glob (* within a segment, ** across) against ref.
func matchResource(pattern, ref string) bool {
	// Anchor with \z (end of text), not $: in Go's regexp $ also matches just
	// before a trailing newline, so a ref ending in "\n" wouldn't over-match.
	re, err := regexp.Compile("^" + globToRegexp(pattern) + `\z`)
	if err != nil {
		return false
	}
	return re.MatchString(ref)
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
			// Single-character wildcard, consistent with path-glob matching in
			// internal/secret so '?' means the same thing in refs and paths.
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
