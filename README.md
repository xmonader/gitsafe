# gitsafe

**git-crypt with access control.** Encrypt secrets in your git repo to exactly the people who can read the branch — enforced by a signed policy that verifies offline, with no vendor.

> Status: **v0.1 — hardened core.** The CLI, clean/smudge filters, signed policy chain, branch-scoped recipients, root-pinned offline verification, atomic policy writes, and key rotation are implemented and covered by unit, fuzz, race, and real-git end-to-end tests (CI runs all on every push). See the [Security model](#security-model--threat-boundaries) for the threat boundaries, [`docs/design.md`](docs/design.md) for the architecture, and [`docs/strategy.md`](docs/strategy.md) for positioning.

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

## Documentation

- **[Tutorial](docs/tutorial.md)** — learn by doing: protect your first secret, onboard a teammate, branch-scoped access, cloning, offboarding, CI, auditing.
- **[User Guide](docs/userguide.md)** — reference: concepts, on-disk layout, the policy & trust models, full command reference, troubleshooting.
- **[Threat Model](docs/threat-model.md)** — assets, trust boundaries, adversaries, residual risks, and where each gate is enforced.
- **[Design](docs/design.md)** · **[Strategy](docs/strategy.md)** — architecture and positioning.

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

### Cloning a gitsafe repo

git's filters and the trust pin are **per-clone** and do not travel in the repo (by design — a repo cannot vouch for itself). After cloning:

```bash
gitsafe key gen                 # if you don't already have an identity
gitsafe init --user bob         # wires the filters; prints the policy root fingerprint
gitsafe trust                   # pin the root AFTER verifying the fingerprint out-of-band
git checkout -- .               # re-run smudge now that filters are active
```

Until you pin the root with `gitsafe trust`, gitsafe **refuses to encrypt** (it won't commit a secret against a policy it hasn't been told to trust). This is the SSH `known_hosts` model: trust is established deliberately, once, and a later change to the policy root is treated as a possible attack.

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
| `gitsafe trust [--fingerprint HEX] [--force]` | Pin this clone to the policy root (TOFU) |
| `gitsafe access RESOURCE` | Show who can decrypt secrets on a branch/ref |
| `gitsafe whoami` | Show your identity and policy membership |
| `gitsafe policy show` | Print the current keyring and grants |
| `gitsafe policy verify` | Verify the signed chain offline + show root fingerprint and pin status |
| `gitsafe clean` / `smudge` | The git filters (invoked by git, not by hand) |

`RESOURCE` is a ref glob; a bare branch name is shorthand for `refs/heads/<name>`. Verbs form a hierarchy: `admin > force > write > read`.

## How it works

Files matching the marks in `.gitattributes` (`*.env`, `*.pem`, `secrets/**`, …) get the `gitsafe` filter. On `git add`, the **clean** filter resolves the current branch, asks the signed policy for that branch's reader set, and encrypts the file with [age](https://age-encryption.org) to those recipients — git stores the ciphertext. On checkout, the **smudge** filter decrypts for an authorized identity, or writes a locked placeholder for everyone else (never failing the checkout).

The policy — keyring, grants, branch→reader rules — lives as an ed25519-signed object chain committed under `.gitsafe/policy/` and verifies offline with nothing but the repo. Private keys live in `~/.config/gitsafe/` and never touch the repo.

Three correctness/security properties worth knowing:

- **Verified before trusted.** Before the clean filter uses any recipient the policy names, it verifies the whole ed25519 chain *and* that its root matches the fingerprint this clone pinned with `gitsafe trust`. A poisoned policy (a tampered or wholesale-replaced chain merged into the repo) is refused rather than used to redirect a secret's encryption to an attacker's key.
- **Deterministic re-staging.** age output is randomized, which would make `git status` think every secret is always modified. The clean filter recognizes an unchanged secret with an unchanged reader set and re-emits the stored ciphertext byte-for-byte, so status stays clean.
- **Placeholder safety.** A locked user sees a placeholder, not the secret. If they re-stage it, the clean filter detects the placeholder and re-emits the stored ciphertext rather than encrypting the placeholder over the real secret — so a non-reader can never destroy data they can't see.

## Security model & threat boundaries

- **Private keys** live in `~/.config/gitsafe/`, never in the repo. The policy carries only public keys.
- **Trust anchor:** the policy root is self-signed; each clone pins the root's public key locally (`.git/gitsafe/root`, TOFU). Verify the fingerprint out-of-band on first trust — `gitsafe policy verify` prints it and the pin status.
- **What an attacker who controls repo *contents* cannot do:** make you encrypt a new secret to their key. Tampering with `.gitsafe/policy/` either breaks chain verification or fails the root-pin check, and the clean filter refuses.
- **What is NOT in scope:** an attacker with write access to your local `.git/` (game over for any tool), and **read-after-revocation** — see below.
- **Revocation is forward-only.** `member revoke` + `rotate` re-encrypts *future* blobs without the revoked reader. It does **not** retroactively protect secrets already in git history: a revoked member who kept an old clone (or the packfiles) can still decrypt the ciphertext that was encrypted to them. **Treat any secret a revoked member could read as compromised and rotate the secret value itself**, exactly as you would after any key exposure. This is inherent to encryption-at-rest in an append-only history, not specific to gitsafe.

## Limitations (MVP)

- **No ciphertext merge driver.** Two branches editing the same secret produce conflicting age blobs git can't 3-way merge; resolve by decrypting, merging, and re-staging. A merge driver is future work.
- **Branch must be unambiguous at clean time.** On a detached HEAD / mid-rebase the clean filter refuses rather than guess recipients. Commit secrets from a normal branch checkout.
- **Local enforcement of *reads* is cryptographic; write/force grants are policy metadata**, not server-side push enforcement (gitsafe is an overlay, not a git server).
- Cut from the MVP: groups beyond read/write, whole-branch encryption, a hosted policy directory, and non-age backends (KMS/PGP).

## Development

```bash
make build   # build ./gitsafe
make test    # unit + real-git end-to-end tests
make e2e     # just the end-to-end test, verbose
make lint    # go vet
go test -race ./...                                          # race detector
go test ./internal/format -run xxx -fuzz FuzzParse          # fuzz the envelope parser
```

## How it's built

A single static Go binary on top of [age](https://age-encryption.org) and `crypto/ed25519`. The engine is small and focused: branch-derived recipients, a portable ed25519-signed policy chain, and age encryption, wired into git through clean/smudge filters. No database, no daemon, no server. See [`docs/design.md`](docs/design.md) for the architecture.
