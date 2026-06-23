# gitsafe

**Keep secrets in your git repo — encrypted, readable only by the people you allow.**

Commit `.env`, keys, and certs straight into git. gitsafe stores them **encrypted**, so anyone who clones without permission sees scrambled bytes. People you've granted access decrypt them automatically. No server, no cloud service.

The twist over [git-crypt](https://github.com/AGWA/git-crypt) / [SOPS](https://github.com/getsops/sops): **who can read a branch is who can decrypt its secrets.** Grant someone read on `staging` and they can read `staging`'s secrets — one list, not two. Who's allowed is a signed file in the repo, so anyone can verify it offline.

```bash
gitsafe key gen                 # one time: your private key (stays in ~/.config)
gitsafe init --user alice       # turn gitsafe on for this repo

echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env && git commit -m "add a secret"

git cat-file blob HEAD:.env     # what git stored  -> encrypted
cat .env                        # your working copy -> the real password
```

Add a teammate (they send you their public keys from `gitsafe key show`):

```bash
gitsafe onboard bob staging --sign <hex> --enc age1...
```

That's add + grant-read + re-encrypt in one step. Now bob reads `staging`'s secrets; anyone without access sees a locked placeholder.

## Install

```bash
make build
sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
```

Needs Go 1.25+ to build and `git` at runtime.

## One thing to know

When you remove someone, future secrets exclude them — but they kept old clones, and git history still holds what was encrypted to them. So after offboarding, **change the secret value itself** (new password/key), like any leak. This is true of any "encrypted files in git" tool.

## Learn more

- **[Tutorial](docs/tutorial.md)** — step by step, by example.
- **[User Guide](docs/userguide.md)** — every command, the full picture.
- **[Threat Model](docs/threat-model.md)** — exactly what it protects, and what it doesn't.
- **[Design](docs/design.md)** · **[Strategy](docs/strategy.md)** — how and why it's built.

Built on [age](https://age-encryption.org) + ed25519. One static Go binary. Apache-2.0 — see [`LICENSE`](LICENSE).
