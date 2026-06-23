# Security Policy

gitsafe is a security tool: its entire job is to keep secrets in a git repo
readable only by the people you allow. We take vulnerability reports seriously
and want to make reporting them easy and safe.

## Supported versions

gitsafe is pre-1.0. Only the latest released version (and `main`) receive
security fixes. There are no backported patches for older tags.

| Version | Supported |
|---------|-----------|
| latest release / `main` | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through either:

1. **GitHub Security Advisories** (preferred):
   <https://github.com/xmonader/gitsafe/security/advisories/new> — this opens a
   private channel between you and the maintainers.
2. **Email:** xmonader@gmail.com with `[gitsafe security]` in the subject.

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce (a minimal repo or script is ideal).
- The gitsafe version (`gitsafe version`) and your OS.
- Any suggested fix, if you have one.

### What to expect

- **Acknowledgement** within 5 business days.
- An initial assessment (severity, whether we can reproduce) within 10 business
  days.
- We will keep you updated as we work on a fix and will credit you in the
  advisory and changelog unless you ask us not to.
- We follow **coordinated disclosure**: we ask that you give us a reasonable
  window (typically up to 90 days) to ship a fix before public disclosure.

## Scope — what is and isn't a vulnerability

gitsafe's [threat model](docs/threat-model.md) is the source of truth. In short:

**In scope** (please report):

- Any way to make the clean filter encrypt a secret to a key the verified,
  pinned policy does **not** authorize.
- Any way to bypass policy-chain verification or the root-pin (TOFU) check.
- Any way for a non-reader to recover plaintext they were never granted.
- Memory/crypto-handling bugs that could leak key material or plaintext.

**Out of scope** (documented limitations, not bugs):

- **Read-after-revocation.** A revoked reader who kept an old clone (or the
  packfiles) can still decrypt ciphertext that was previously encrypted to them.
  Rotate the *secret value* itself after revoking. This is inherent to
  encryption-at-rest in append-only history.
- **An attacker with write access to your local `.git/`.** At that point any
  tool on your machine is compromised.
- **Write/admin enforcement.** gitsafe is an overlay, not a git server; `write`
  and `admin` grants are policy metadata, not server-side push enforcement.
- A lost identity file with no backup (see the recovery runbook in the
  [User Guide](docs/userguide.md)).

When in doubt, report it — we would rather triage a non-issue than miss a real
one.
