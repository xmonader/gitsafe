# gitsafe

**git-crypt with access control.** Encrypt secrets in your git repo to exactly the people who can read the branch — enforced by a signed policy that verifies offline, with no vendor.

> Status: **working MVP**. The CLI, clean/smudge filters, signed policy chain, and branch-scoped recipients are implemented and covered by a real-git end-to-end test (`make e2e`). See [`docs/design.md`](docs/design.md) for the architecture and [`docs/strategy.md`](docs/strategy.md) for positioning.

---

## The problem

Teams that keep secrets near their code today pick from bad options:

- **`git-crypt`** — encrypts marked files in git, but the access list is "whoever has a GPG key in the repo." No notion of *who can read which branch*, no rotation story, no portable audit of who was granted what.
- **`SOPS`** — encrypts values to KMS/age/PGP recipients, but you manage the recipient list by hand in `.sops.yaml`, and it has no concept of branch-scoped access or a verifiable grant history.
- **Vault / Doppler / Infisical** — strong, but they pull secrets *out* of the repo into a vendor service. You trade "secret in git" for "hard dependency on a SaaS / cluster," and the access policy lives in their database, not with your code.

None of them answer **"who is allowed to read this, provably, and how do I rotate when that changes?"** in a way that travels with the repository.

## The wedge

gitsafe adds the one thing the file-based tools lack: a **portable, signed, offline-verifiable access policy** where a secret's decryption recipients are *derived from* who can read its branch. Grant someone read access to `staging` and they can decrypt `staging`'s secrets — you never maintain two lists. Revoke them and `gitsafe rotate` re-encrypts to the new reader set. Every policy version is ed25519-signed and chained, so anyone can verify offline that it wasn't forged or rewritten — no server required, no vendor trusted.

It runs **on top of real git**: clean/smudge filters, a signed policy committed in the repo, recipients resolved from the current branch. Your host, CI, IDE, and review flow are untouched.

## Install

```bash
make build
sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
# or: make install DESTDIR=
```

Requires Go 1.25+ to build and `git` on PATH at runtime.

## Quick start

```bash
cd my-repo

gitsafe key gen                 # one-time: create your private identity (~/.config/gitsafe)
gitsafe init --user alice       # wire up filters, .gitattributes, and bootstrap the policy

echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env
git commit -m "enable gitsafe + add secret"

git cat-file blob HEAD:.env     # <- ciphertext in git
cat .env                        # <- plaintext in your working tree (you can read it)
```

Add a teammate:

```bash
# bob, on his machine:
gitsafe key gen
gitsafe key show                # prints his public sign + enc keys

# you (an admin):
gitsafe member add bob --sign <hex> --enc <age1...>
gitsafe grant bob read staging  # bare name => refs/heads/staging
gitsafe rotate                  # re-encrypt marked files to the new reader set
git add .gitsafe .env && git commit -m "grant bob read on staging"
```

Now bob, after a pull, sees plaintext for `staging`'s secrets; anyone without read access sees a clear locked placeholder and can't decrypt. Revoke bob (`gitsafe member revoke bob` or `gitsafe revoke bob read staging`) then `gitsafe rotate` to cut him out of future ciphertext.

## Commands

| Command | What it does |
|---------|--------------|
| `gitsafe key gen` / `key show` | Create / print your keypair (private key never enters the repo) |
| `gitsafe init [--user NAME]` | Register the git filter, write default marks, bootstrap policy v0 |
| `gitsafe member add NAME --sign HEX --enc age1...` | Add a member to the signed keyring |
| `gitsafe member revoke NAME` | Mark a member revoked (then `rotate`) |
| `gitsafe grant SUBJECT VERB RESOURCE` | Grant `read`/`write`/`admin` on a ref glob |
| `gitsafe revoke SUBJECT VERB RESOURCE` | Remove a matching grant |
| `gitsafe rotate` | Re-encrypt all marked files to the current readers and stage them |
| `gitsafe policy show` | Print the current keyring and grants |
| `gitsafe policy verify` | Verify the signed policy chain offline |
| `gitsafe clean` / `smudge` | The git filters (invoked by git, not by hand) |

`RESOURCE` is a ref glob; a bare branch name is shorthand for `refs/heads/<name>`. Verbs form a hierarchy: `admin > force > write > read`.

## How it works

Files matching the marks in `.gitattributes` (`*.env`, `*.pem`, `secrets/**`, …) get the `gitsafe` filter. On `git add`, the **clean** filter resolves the current branch, asks the signed policy for that branch's reader set, and encrypts the file with [age](https://age-encryption.org) to those recipients — git stores the ciphertext. On checkout, the **smudge** filter decrypts for an authorized identity, or writes a locked placeholder for everyone else (never failing the checkout).

The policy — keyring, grants, branch→reader rules — lives as an ed25519-signed object chain committed under `.gitsafe/policy/` and verifies offline with nothing but the repo. Private keys live in `~/.config/gitsafe/` and never touch the repo.

Two correctness details worth knowing:

- **Deterministic re-staging.** age output is randomized, which would make `git status` think every secret is always modified. The clean filter recognizes an unchanged secret with an unchanged reader set and re-emits the stored ciphertext byte-for-byte, so status stays clean.
- **Placeholder safety.** A locked user sees a placeholder, not the secret. If they re-stage it, the clean filter detects the placeholder and re-emits the stored ciphertext rather than encrypting the placeholder over the real secret — so a non-reader can never destroy data they can't see.

## Limitations (MVP)

- **No ciphertext merge driver.** Two branches editing the same secret produce conflicting age blobs git can't 3-way merge; resolve by decrypting, merging, and re-staging. A merge driver is future work.
- **Branch must be unambiguous at clean time.** On a detached HEAD / mid-rebase the clean filter refuses rather than guess recipients. Commit secrets from a normal branch checkout.
- **Local enforcement of *reads* is cryptographic; write/force grants are policy metadata**, not server-side push enforcement (gitsafe is an overlay, not a git server).
- Cut from the MVP: groups beyond read/write, whole-branch encryption, a hosted policy directory, and non-age backends (KMS/PGP).

## Development

```bash
make build   # build ./gitsafe
make test    # unit tests
make e2e     # real-git end-to-end test
make lint    # go vet
```

## Heritage

The encryption + signed-policy engine is lifted from [Haven](../haven), a from-scratch VCS that proved the model (recipients = branch readers, portable ed25519 policy chain, age encryption). gitsafe is that engine **repositioned as a git overlay** — keeping the valuable idea, discarding the unwinnable "replace git" framing. See [`docs/design.md`](docs/design.md) for what was reused vs rebuilt.
