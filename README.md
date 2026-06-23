# gitsafe

**git-crypt with access control.** Encrypt secrets in your git repo to exactly the people who can read the branch — enforced by a signed policy that verifies offline, with no vendor.

> Status: **planning**. This repo currently holds the product and go-to-market plan, not code. See [`docs/strategy.md`](docs/strategy.md) and [`docs/design.md`](docs/design.md).

---

## The problem

Teams that keep secrets near their code today pick from bad options:

- **`git-crypt`** — encrypts marked files in git, but the access list is "whoever has a GPG key in the repo." No notion of *who can read which branch*, no rotation story, no portable audit of who was granted what.
- **`SOPS`** — encrypts values to KMS/age/PGP recipients, but you manage the recipient list by hand in `.sops.yaml`, and it has no concept of branch-scoped access or a verifiable grant history.
- **Vault / Doppler / Infisical** — strong, but they pull secrets *out* of the repo into a vendor service. You trade "secret in git" for "hard dependency on a SaaS / cluster," and the access policy lives in their database, not with your code.

None of them answer the question **"who is allowed to read this, provably, and how do I rotate when that changes?"** in a way that travels with the repository.

## The wedge

gitsafe adds the one thing the file-based tools lack: a **portable, signed, offline-verifiable access policy** where a secret's decryption recipients are *derived from* who can read its branch. Grant someone read access to `staging` and they can decrypt `staging`'s secrets — you never maintain two lists. Revoke them and `gitsafe rotate` re-encrypts to the new reader set. Every grant is ed25519-signed and chained, so anyone can verify offline that the policy wasn't forged or rewritten — no server required, no vendor trusted.

It runs **on top of real git**: clean/smudge filters, a policy file committed in the repo, recipients resolved from refs. Your host, CI, IDE, and review flow are untouched.

## How it works (one paragraph)

Mark files as secret (`.env`, `*.pem`, …). On `git add`, a clean filter encrypts them with [age](https://age-encryption.org) to the recipients the signed policy says can read the current branch; on checkout, a smudge filter decrypts for holders of an authorized key. The policy — keyring, grants, branch→reader rules — lives as a signed object chain committed in the repo and verifies offline. Private keys never enter the repo.

## Heritage

The encryption + signed-policy engine is lifted from [Haven](../haven), a from-scratch VCS that proved the model (recipients = branch readers, portable ed25519 policy chain, age encryption). gitsafe is that engine **repositioned as a git overlay** — keeping the valuable idea, discarding the unwinnable "replace git" framing. See [`docs/design.md`](docs/design.md) for what's reused vs rebuilt.
