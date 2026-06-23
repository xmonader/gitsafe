# gitsafe

**Keep secrets in your git repo — encrypted, and readable only by the people you allow.**

gitsafe lets you commit secret files (like `.env`, API keys, or certificates) straight into your git repo. They're stored **encrypted**, so anyone who clones the repo without permission just sees scrambled bytes. The people you've granted access to see the real contents automatically — no extra steps, no separate password vault, no cloud service.

> Status: **v0.1 — working core.** The command-line tool, the encrypt/decrypt filters, the access rules, offline verification, and key rotation all work and are covered by automated tests that run on every change. Not yet independently security-audited. See [Is it safe?](#is-it-safe) for exactly what is and isn't protected.

---

## The problem in one sentence

You want to keep passwords and keys *next to your code* (handy, versioned, travels with the repo) — but you **don't** want everyone who can see the repo to be able to read them, and you want an easy way to cut someone off later.

Today you have to pick the lesser evil:

- **git-crypt** — encrypts files in git, but "who can read" is just "whoever has a key." No way to say *who can read which branch*, and no clean way to rotate keys when someone leaves.
- **SOPS** — encrypts files, but you hand-edit the list of who's allowed in a config file. No branch-based access, no record of who was granted what.
- **Vault / Doppler / Infisical** — powerful, but they pull your secrets *out* of git and into a paid cloud service you now depend on.

## What gitsafe adds

One simple idea: **the people who can read a branch are the people who can decrypt that branch's secrets.**

Grant someone read access to `staging`, and they can now decrypt `staging`'s secrets. You never keep two separate lists. Remove them, run one command, and the secrets get re-encrypted without them.

The list of who's allowed lives in the repo as a **signed file**, so anyone can check it's genuine and hasn't been tampered with — using nothing but the repo itself. No server, no account, no vendor.

It plugs into your existing git repo (using git's built-in "filters"). Your git host, CI, editor, and pull-request workflow keep working exactly as before.

## Documentation

- **[Tutorial](docs/tutorial.md)** — learn by doing: protect your first secret, add a teammate, branch-based access, cloning, removing someone, CI, auditing.
- **[User Guide](docs/userguide.md)** — the reference: concepts, where files live, how access and trust work, every command, and troubleshooting.
- **[Threat Model](docs/threat-model.md)** — exactly what gitsafe protects against, what it doesn't, and where each protection lives in the code.
- **[Design](docs/design.md)** · **[Strategy](docs/strategy.md)** — how it's built and why.

## Install

```bash
make build
sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
# or: make install DESTDIR=
```

Needs Go 1.25+ to build, and `git` available when you run it.

## Quick start

```bash
cd my-repo

gitsafe key gen                 # one time: create your private key (saved in ~/.config/gitsafe)
gitsafe init --user alice       # turn on gitsafe for this repo and set yourself as the first admin

echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env
git commit -m "turn on gitsafe + add a secret"

git cat-file blob HEAD:.env     # what git stored -> encrypted gibberish
cat .env                        # your working copy -> real password (you can read it)
```

Add a teammate:

```bash
# bob, on his machine:
gitsafe key gen
gitsafe key show                # prints his two public keys

# you (an admin):
gitsafe member add bob --sign <hex> --enc <age1...>
gitsafe grant bob read staging  # a bare branch name means refs/heads/staging
gitsafe rotate                  # re-encrypt the secret files so bob is now included
git add .gitsafe .env && git commit -m "give bob read access on staging"
```

After bob pulls, he sees the real secrets for `staging`. Anyone *without* access sees a clear "you're locked out" placeholder instead — and can't read the secret. To cut bob off later, run `gitsafe member revoke bob` (or `gitsafe revoke bob read staging`) and then `gitsafe rotate`.

### After you clone a gitsafe repo

A couple of things are deliberately **not** stored in the repo — your private key (obviously) and your decision to trust this repo's access list. So after cloning:

```bash
gitsafe key gen                 # if you don't already have a key
gitsafe init --user bob         # turn on the filters; prints the policy's fingerprint
gitsafe trust                   # confirm you trust this repo's access list (check the fingerprint first!)
git checkout -- .               # re-run decryption now that gitsafe is active
```

Until you run `gitsafe trust`, gitsafe **won't encrypt anything**. This is the same idea as SSH asking "are you sure?" the first time you connect to a server: you confirm trust once, on purpose. If the repo's access list later gets swapped out, gitsafe treats that as a possible attack and stops.

## Commands

| Command | What it does |
|---------|--------------|
| `gitsafe key gen` / `key show` | Create / print your keys (your private key never goes into the repo) |
| `gitsafe init [--user NAME]` | Turn gitsafe on for this repo and set up the first admin |
| `gitsafe member add NAME --sign HEX --enc age1...` | Add a person to the access list |
| `gitsafe member revoke NAME` | Remove a person (then run `rotate`) |
| `gitsafe grant SUBJECT VERB RESOURCE` | Give `read`/`write`/`admin` on a branch (or branch pattern) |
| `gitsafe revoke SUBJECT VERB RESOURCE` | Take away a matching grant |
| `gitsafe rotate` | Re-encrypt all secret files to the current set of allowed readers |
| `gitsafe trust [--fingerprint HEX] [--force]` | Confirm you trust this repo's access list (do this once after cloning) |
| `gitsafe access RESOURCE` | Show who can decrypt a branch's secrets |
| `gitsafe whoami` | Show your identity and what you have access to |
| `gitsafe policy show` | Print the current access list |
| `gitsafe policy verify` | Check the access list is genuine + show its fingerprint and trust status |
| `gitsafe clean` / `smudge` | The encrypt/decrypt steps git runs for you (you don't call these by hand) |

`RESOURCE` is a branch name or pattern; a bare name like `staging` means `refs/heads/staging`. Access levels go in order: `admin > force > write > read` (a higher level includes the ones below it).

## How it works

You mark which files are secret in `.gitattributes` (by default: `*.env`, `*.pem`, `secrets/**`, …). From then on, git runs gitsafe automatically:

- **On `git add`** — gitsafe looks at your current branch, finds who's allowed to read it, and encrypts the file to exactly those people using [age](https://age-encryption.org). Git stores the encrypted version.
- **On checkout** — if you're allowed, gitsafe decrypts the file for you. If you're not, you get a plain "locked" placeholder instead of the secret. Either way your checkout never breaks.

The access list (members, grants, branch rules) is stored in the repo under `.gitsafe/policy/` as a **signed, tamper-evident file**. It travels on a normal `git push` and can be verified offline with just the repo. Your private keys stay in `~/.config/gitsafe/` and never touch the repo.

Three details worth knowing:

- **Checked before trusted.** Before encrypting, gitsafe verifies the access list is genuine *and* matches the fingerprint you pinned with `gitsafe trust`. So a tampered or swapped-out access list can't trick you into encrypting a secret to an attacker's key — gitsafe refuses instead.
- **No noisy diffs.** Encryption normally produces different bytes every time, which would make git think your secrets changed on every save. gitsafe notices when a secret and its readers are unchanged and reuses the existing encrypted bytes, so `git status` stays clean.
- **Locked-out users can't break things.** Someone without access sees a placeholder, not the secret. If they accidentally re-stage that file, gitsafe detects the placeholder and keeps the real encrypted secret — so they can't overwrite data they were never able to see.

## Is it safe?

- **Private keys** stay in `~/.config/gitsafe/`, never in the repo. The repo only ever holds *public* keys. Protect the key on disk with `gitsafe key gen --passphrase` (or `gitsafe key lock` to encrypt an existing one); git filters then read the passphrase from `GITSAFE_PASSPHRASE`.
- **Trust is confirmed once, on purpose.** The access list is self-signed; each clone pins its fingerprint locally (`.git/gitsafe/root`). Check the fingerprint the first time with `gitsafe policy verify`.
- **What an attacker who edits the repo's contents *can't* do:** trick you into encrypting a new secret to their key. Tampering with the access list breaks verification or fails the fingerprint check, and gitsafe refuses to encrypt.
- **What gitsafe does *not* protect against:**
  - Someone who can write to your local `.git/` folder — at that point any tool on your machine is compromised.
  - **Reading old secrets after you remove someone.** This one matters: when you revoke someone and rotate, *future* secrets exclude them — but they may have kept an old copy of the repo, and git history still holds the version that *was* encrypted to them. So **treat any secret a removed person could have seen as compromised, and change the actual secret value** (rotate the real password/key), just like you would after any leak. This is true of any "encrypted files in git history" tool, not just gitsafe.

## Limitations (v0.1)

- **Merging encrypted files needs read access.** gitsafe installs a merge driver that decrypts, 3-way merges, and re-encrypts automatically — but only a reader of the secret can run it. A non-reader's merge is refused rather than mangling data.
- **Your branch must be clear when adding secrets.** During a detached checkout or mid-rebase, gitsafe refuses (it can't tell which branch's readers to use). Add secrets from a normal branch.
- **Read protection is real encryption; write/admin levels are policy, not server enforcement.** gitsafe is a tool layered on git, not a git server — it can't block a push, only record who's allowed.
- Not in v0.1: groups, encrypting a whole branch's files (not just marked ones), a hosted access-list directory, and key backends other than age (KMS/PGP).

## Development

```bash
make build   # build ./gitsafe
make test    # unit tests + real-git end-to-end tests
make e2e     # just the end-to-end test, verbose
make lint    # go vet
go test -race ./...                                          # race detector
go test ./internal/format -run xxx -fuzz FuzzParse          # fuzz the parser
```

## How it's built

One small static Go binary built on [age](https://age-encryption.org) (encryption) and `crypto/ed25519` (signing). The core idea is tiny: readers come from the branch, the access list is a signed file in the repo, and files are encrypted with age — all wired into git through its built-in filters. No database, no daemon, no server. See [`docs/design.md`](docs/design.md) for the architecture.
