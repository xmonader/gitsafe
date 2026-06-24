# gitsafe

### Your `.env` in git, readable only by the right people.

**git-crypt, with real access control.** Commit secrets straight into your repo — gitsafe encrypts them to exactly who can read the branch. The right people just `cat` the file; everyone else gets ciphertext. No server, no vault, no second list to keep.

The twist over [git-crypt](https://github.com/AGWA/git-crypt) / [SOPS](https://github.com/getsops/sops): **who can read a branch is who can decrypt its secrets.** Grant someone read on `staging` and they can read `staging`'s secrets — one list, not two. Who's allowed is a signed file in the repo, so anyone can verify it offline.

```bash
gitsafe key gen                 # one time: your private key (stays in ~/.config)
gitsafe init --user alice       # turn gitsafe on for this repo

echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env && git commit -m "add a secret"

git cat-file blob HEAD:.env     # what git stored  -> encrypted
cat .env                        # your working copy -> the real password
```

Add a teammate (they send you the one key from `gitsafe key show`):

```bash
gitsafe onboard bob staging --enc age1...
```

That's add + grant-read + re-encrypt in one step. Now bob reads `staging`'s secrets; anyone without access sees a locked placeholder. (Only admins who change the policy need a second `--sign` key.)

## Install

```bash
make build
sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
```

Needs Go 1.25+ to build and `git` at runtime.

## One thing to know

When you remove someone, future secrets exclude them — but they kept old clones, and git history still holds what was encrypted to them. So after offboarding, **change the secret value itself** (new password/key), like any leak. This is true of any "encrypted files in git" tool. Full procedure: [Offboarding: removing someone correctly](docs/userguide.md#offboarding-removing-someone-correctly).

## Learn more

- **[The Book](book/README.md)** — *Secrets in Git, Done Right*: a short, hands-on book that teaches gitsafe from first principles, with exercises and projects.
- **[Tutorial](docs/tutorial.md)** — step by step, by example.
- **[User Guide](docs/userguide.md)** — every command, the full picture.
- **[Threat Model](docs/threat-model.md)** — exactly what it protects, and what it doesn't.
- **[Design](docs/design.md)** · **[Strategy](docs/strategy.md)** — how and why it's built.

Built on [age](https://age-encryption.org) + ed25519. One static Go binary. Apache-2.0 — see [`LICENSE`](LICENSE).
