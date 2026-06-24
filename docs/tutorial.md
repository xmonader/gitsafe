# gitsafe Tutorial

A hands-on walk through the workflows you'll actually hit: protecting your first
secret, onboarding a teammate, giving different branches different readers,
joining a project someone else set up, offboarding a leaver, and wiring a CI
pipeline. Each scenario is copy-pasteable and ends with **what just happened**
so the mechanics stick.

If you only want the reference (every command, every flag, the file layout), see
the [User Guide](userguide.md). This tutorial assumes gitsafe is installed and on
your `PATH`:

```bash
make build && sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
gitsafe version
```

You also need `git` on your `PATH`. Throughout, lines starting with `#` are
commentary, not commands.

---

## Scenario 1 — Protect your first secret (solo)

**Goal:** stop committing a plaintext `.env`. Encrypt it so the repo holds
ciphertext, while your working copy stays readable.

```bash
cd my-project

# 1. One-time on this machine: create your private identity.
gitsafe key gen
# Prefer to protect the key on disk? Use:  gitsafe key gen --passphrase
# (you'll then set GITSAFE_PASSPHRASE for git's filters; see the User Guide).

# 2. Wire gitsafe into this repo and become its first admin.
gitsafe init --user alice

# 3. Write a secret and commit it like normal.
echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env
git commit -m "enable gitsafe, add .env"
```

Now prove it worked:

```bash
git cat-file blob HEAD:.env   # what git actually stored -> ciphertext
cat .env                      # your working copy -> still plaintext
```

The stored blob starts with a `\x00gitsafe\x00` marker followed by binary
ciphertext. Your working tree is untouched.

**What just happened**

- `gitsafe key gen` created your keypair in `~/.config/gitsafe/identity` (an
  [age](https://age-encryption.org) encryption key + an ed25519 signing key).
  The **private** keys live there and never enter the repo.
- `gitsafe init` did four things: registered a git *filter* called `gitsafe` in
  `.git/config`, wrote default secret marks to `.gitattributes`, created the
  signed policy (you as admin) under `.gitsafe/policy/`, and **pinned** that
  policy's root key for this clone.
- On `git add`, git piped `.env` through `gitsafe clean`, which encrypted it to
  the people allowed to read the current branch — right now, just you.
- On checkout (and whenever git materializes the file), `gitsafe smudge`
  decrypts it back to plaintext because your identity is a recipient.

You committed `.gitsafe/` and `.gitattributes` so the policy and the marks
travel with the repo.

> **Safety net — block accidental plaintext.** If the filters ever aren't active
> (a fresh clone before `init`, a teammate who skipped setup), a marked secret
> could be committed as plaintext. Install a pre-commit hook that refuses that:
>
> ```bash
> printf '#!/bin/sh\nexec gitsafe check\n' > .git/hooks/pre-commit
> chmod +x .git/hooks/pre-commit
> ```
>
> `gitsafe check` fails the commit if any marked file is staged as plaintext.

---

## Scenario 2 — Give a teammate read access

**Goal:** let Bob decrypt the secrets on `main`. Bob never sends you a private
key; he sends you one **public** string — his `enc` (age) key.

**Bob, on his machine:**

```bash
gitsafe key gen
gitsafe key show
# enc  (age):      age1qz...k7      <- this is the one to send
# sign (ed25519):  3b9a...e1        (only needed if he'll administer the policy)
```

Bob sends you his `enc` line (Slack, email, carrier pigeon — it's public).

**You (an admin), in the repo:**

```bash
gitsafe member add bob --enc age1qz...k7
gitsafe grant bob read main          # bare name => refs/heads/main
gitsafe rotate                       # re-encrypt secrets to include bob
git add .gitsafe .env
git commit -m "grant bob read on main"
git push
```

> A read-only teammate needs only their `enc` key. The `sign` key is for admins
> who *change* the policy — add it with `--sign <hex>` (and grant `admin`) when
> you're promoting someone.

After Bob pulls and sets up his clone (see [Scenario 4](#scenario-4--join-a-project-someone-else-set-up)),
`cat .env` gives him plaintext. Anyone *not* granted sees a locked placeholder
instead and simply can't decrypt.

**What just happened**

- `member add` appended Bob's public key to the signed keyring as a new policy
  version (signed by you).
- `grant bob read main` added a capability: Bob may read `refs/heads/main`.
- `rotate` re-ran the clean filter over every marked file so the stored
  ciphertext is now encrypted to **you + Bob** instead of just you. Without
  `rotate`, the *policy* would list Bob but the existing blobs would still be
  encrypted only to you.
- You committed `.gitsafe` (the new policy version) and the re-encrypted `.env`
  together.

> **Why two steps (grant *then* rotate)?** Granting changes *who is allowed*;
> rotating changes *what the ciphertext is encrypted to*. Keeping them separate
> means you can stage several membership changes and rotate once.

> **Shortcut:** when you're onboarding one person to one branch, do it in a
> single step:
>
> ```bash
> gitsafe onboard bob main --enc age1qz...k7
> git add .gitsafe .env && git commit -m "onboard bob on main"
> ```
>
> `onboard` adds Bob, grants him `read` on `main`, and rotates — atomically, so
> you can't leave it half-done. The longhand above is worth understanding first.

---

## Scenario 3 — Different readers for different branches

**Goal:** everyone reads `staging` secrets, but only the on-call group reads
`production` secrets. gitsafe derives recipients from the branch, so you express
this purely as grants.

Assume Bob and Carol are already members (Scenario 2). You want:

- `staging`: Bob + Carol may read.
- `production`: only Carol may read.

```bash
gitsafe grant bob   read staging
gitsafe grant carol read staging
gitsafe grant carol read production
git add .gitsafe && git commit -m "branch-scoped read grants"
```

Now commit secrets on each branch:

```bash
git switch staging
echo "STRIPE_KEY=sk_test_123" > .env
git add .env && git commit -m "staging secret"   # encrypted to you+bob+carol

git switch production
echo "STRIPE_KEY=sk_live_999" > .env
git add .env && git commit -m "prod secret"       # encrypted to you+carol only
```

If Bob checks out `production`, his `.env` is a locked placeholder — he was
never granted read there.

**What just happened**

- The clean filter resolves `HEAD` to the current branch and asks the policy
  *"who can read `refs/heads/<branch>`?"*. The recipient set is computed
  per-branch, so the same filename encrypts to different people depending on the
  branch you commit from.
- A grant of `read` (or higher — `write`, `admin`) makes someone a recipient.
  Admin implies read, so admins can always decrypt.

> **Tip:** you can grant on globs, not just one branch:
> `gitsafe grant bob read 'refs/heads/feature/*'` lets Bob read every
> single-segment `feature/...` branch. Use `refs/heads/**` for all branches.

> **Grant by role with groups.** Instead of granting each person, make a group
> and grant the group:
>
> ```bash
> gitsafe group add oncall bob carol      # members must already be in the keyring
> gitsafe grant oncall read production
> gitsafe rotate
> git add .gitsafe && git commit -m "oncall reads production"
> ```
>
> Add or remove people with `gitsafe group add|remove oncall NAME` (then
> `rotate`); every grant to `oncall` follows automatically. `gitsafe group list`
> shows the membership.

---

## Scenario 4 — Join a project someone else set up

**Goal:** you cloned a repo that already uses gitsafe. git filters and trust are
**per-clone** and don't travel in the repository, so a fresh clone needs a short
setup — and gitsafe deliberately refuses to encrypt until you've established
trust.

```bash
git clone git@example.com:team/app.git
cd app

# 1. Have an identity (skip if you already ran key gen on this machine).
gitsafe key gen

# 2. Wire the filters into this clone. This prints the policy root fingerprint.
gitsafe init --user bob
# Policy already present (v7); filters wired.
# Policy root fingerprint:
#   a9c54ec928a3eefe1d26d62283999f9e6e34e04d7526e78d070bb352cf6de91d
# Verify it out-of-band, then run 'gitsafe trust' before committing secrets.

# 3. Confirm that fingerprint through a trusted channel (a colleague, your
#    onboarding doc), THEN pin it.
gitsafe trust

# 4. Re-materialize files now that the filter is active.
git checkout -- .
cat .env        # plaintext, if you've been granted read
```

If you try to commit a secret before `gitsafe trust`, gitsafe stops you:

```
gitsafe: policy root is not trusted in this clone.
  Verify this fingerprint out-of-band, then run 'gitsafe trust':
    a9c54ec928a3...
```

**What just happened**

- Cloning copied the *committed* policy (`.gitsafe/policy/`) and marks
  (`.gitattributes`), but **not** your local git filter config or any trust
  pin — those live in `.git/`, which isn't part of the repo's content.
- `gitsafe init` on an existing policy only wires filters; it does **not**
  auto-trust. Trust is something you do deliberately, once, after verifying the
  fingerprint — the same model as SSH's `known_hosts`.
- `gitsafe trust` records the policy root's public key in `.git/gitsafe/root`.
  From now on, if the repo's policy root ever changes, gitsafe treats it as a
  possible attack and refuses to encrypt until you re-pin.

> **Why the friction?** Without a pinned root, an attacker who could merge a
> tampered policy into the repo could redirect your *next* secret's encryption
> to their own key. Pinning closes that. See the
> [Security model](userguide.md#security-model--threat-boundaries).

---

## Scenario 5 — Offboard someone who's leaving

**Goal:** Carol is leaving. Remove her from future ciphertext.

```bash
gitsafe member revoke carol
gitsafe rotate
git add .gitsafe .env            # plus any other marked files rotate restaged
git commit -m "offboard carol"
git push
```

(You can instead remove a single grant with
`gitsafe revoke carol read production` if you only want to cut her access to one
branch.)

**What just happened**

- `member revoke` marked Carol's keyring entry `revoked`. Revoked members are
  never included as recipients again. To bring her back later, re-add her with
  `gitsafe member add carol --update --enc age1...` (this reactivates her), then
  `rotate`.
- `rotate` re-encrypted every marked file to the *current* reader set, which no
  longer includes Carol. Her key can't open the new blobs.

> ### Important: rotation is forward-only
>
> `rotate` protects **future** ciphertext. It does **not** retroactively scrub
> git history — Carol's old clone (or the packfiles she already has) can still
> decrypt the secrets that *were* encrypted to her at the time. After offboarding
> anyone with access to a real secret, **rotate the secret's value itself**
> (issue a new DB password, roll the API key), exactly as you would after any
> credential exposure. This is inherent to encryption-at-rest in an append-only
> history, not a gitsafe quirk. See the full step-by-step checklist:
> [Offboarding: removing someone correctly](userguide.md#offboarding-removing-someone-correctly).

---

## Scenario 6 — Let CI read secrets

**Goal:** your pipeline needs to decrypt `.env` to run. Treat CI as a member
with its own machine identity.

**Locally, mint a CI identity** (a throwaway file you'll hand to CI as a
secret):

```bash
GITSAFE_IDENTITY=./ci-identity gitsafe key gen
GITSAFE_IDENTITY=./ci-identity gitsafe key show
# enc  (age):      age1ci...zz
```

**Add CI as a read-only member and rotate** (read-only, so just the enc key):

```bash
gitsafe member add ci-bot --enc age1ci...zz
gitsafe grant ci-bot read main
gitsafe rotate
git add .gitsafe .env && git commit -m "grant ci-bot read on main"
```

**Store the contents of `./ci-identity` as a CI secret** (e.g. a GitHub Actions
secret named `GITSAFE_IDENTITY_FILE`), then in your pipeline:

```yaml
# .github/workflows/deploy.yml (excerpt)
- name: Decrypt secrets
  run: |
    printf '%s' "$GITSAFE_IDENTITY_FILE" > /tmp/gitsafe-id
    export GITSAFE_IDENTITY=/tmp/gitsafe-id
    gitsafe init --user ci-bot      # wire filters in the CI checkout
    gitsafe trust --fingerprint "$EXPECTED_ROOT"   # pin non-interactively
    git checkout -- .               # smudge decrypts .env for ci-bot
    gitsafe check                   # belt-and-braces: no plaintext secret staged
  env:
    GITSAFE_IDENTITY_FILE: ${{ secrets.GITSAFE_IDENTITY_FILE }}
    EXPECTED_ROOT: a9c54ec928a3eefe1d26d62283999f9e6e34e04d7526e78d070bb352cf6de91d
```

**What just happened**

- CI is just another member; its private identity is provisioned the way you
  provision any CI secret. Delete and re-issue it like any other credential.
- `gitsafe trust --fingerprint <hex>` pins non-interactively and **fails** if the
  repo's actual root doesn't match the value you baked into the pipeline — so a
  tampered policy breaks the build instead of silently leaking to an attacker.
- Give CI the narrowest grant it needs (`read` on the one branch it deploys).

---

## Scenario 7 — Mark additional secret paths

**Goal:** encrypt files that aren't covered by the defaults
(`.env`, `.env.*`, `*.pem`, `*.key`, `secrets/**`).

`gitsafe init` writes a block to `.gitattributes`. Add your own patterns there
the same way:

```gitattributes
# existing gitsafe block...
config/credentials.json filter=gitsafe
**/*.secret             filter=gitsafe
```

Then (re)stage so the new patterns take effect:

```bash
git add .gitattributes config/credentials.json
git commit -m "encrypt credentials.json"
git cat-file blob HEAD:config/credentials.json   # ciphertext
```

**What just happened**

- The `gitsafe` filter only runs on paths whose `filter` attribute is `gitsafe`.
  Adding a pattern to `.gitattributes` is how you extend coverage; it travels
  with the repo because `.gitattributes` is committed.
- A file already committed in plaintext **before** it was marked stays plaintext
  in history. Mark it, then rotate/re-add to encrypt the current version (and
  rotate the secret value if it was ever exposed).

---

## Scenario 8 — Audit and verify

**Goal:** answer "who can read what, and is the policy trustworthy?" offline.

```bash
gitsafe policy show
# policy v7 (signed by "alice")
#
# members:
#   alice            active   age1...
#   bob              active   age1...
#   carol            revoked  age1...
#
# grants:
#   alice        admin  refs/**
#   bob          read   refs/heads/main
#   carol        read   refs/heads/production

gitsafe policy verify
# Policy chain valid: 7 version(s), head 0e7bcb867859
# Root fingerprint:  a9c54ec928a3eefe1d26d62283999f9e6e34e04d7526e78d070bb352cf6de91d
# Trust:             pinned and matches ✓
```

Two more focused queries:

```bash
# Who can decrypt one branch's secrets right now?
gitsafe access production
# refs/heads/production
#   readers:    alice, carol
#   encrypts to 2 age recipient(s)

# How did access to a branch change over time? (compliance question)
gitsafe audit production
# access history for refs/heads/production
#   v0   by alice          alice  <- changed
#   v5   by alice          alice, carol  <- changed
#   v7   by alice          alice, carol
```

**What just happened**

- `policy show` prints the current keyring, groups, and grants — your audit of
  who's a member and who's granted what.
- `policy verify` walks the entire signed chain from head to root, checking
  every version's ed25519 signature and that each change was made by an admin,
  then reports the root fingerprint and whether it matches your local pin. A
  `MISMATCH` here means the policy root changed since you trusted it — stop and
  investigate before committing anything.
- `gitsafe access RESOURCE` answers "who can read this **now**," expanding
  groups, admins, and public grants to concrete active members.
- `gitsafe audit RESOURCE` replays the signed chain and shows the reader set at
  every version, flagging where it changed — "who could read this, and when did
  it change." Without a resource it prints the full grant history.

---

## Troubleshooting quick hits

| Symptom | Cause & fix |
|---|---|
| `git add` fails with **"policy root is not trusted"** | Fresh clone, not pinned yet. Verify the fingerprint, run `gitsafe trust`. |
| `git add` fails with **"root changed — REFUSING"** | The policy root differs from your pin (re-bootstrap or tampering). If intended, `gitsafe trust --fingerprint <hex> --force`; otherwise investigate. |
| `git add` fails with **"no readers for refs/heads/X"** | Nobody is granted read on this branch, so there's no one to encrypt to. `gitsafe grant <you> read X` first. |
| Teammate sees a **locked placeholder** instead of plaintext | They aren't granted read on that branch, or you granted but didn't `gitsafe rotate` + commit. |
| `.env` shows as **modified** in `git status` every time | Almost always means the filter isn't configured in that clone — run `gitsafe init`. (gitsafe makes unchanged secrets stable on purpose.) |
| `gitsafe rotate` says **"cannot rotate: X is locked"** | You don't have read access to a marked file; rotation must be run by a reader. |
| New clone shows **ciphertext** in the working tree | Filters weren't active at checkout. `gitsafe init`, `gitsafe trust`, then `git checkout -- .`. |

For deeper reference — the full command list, the policy model, the trust model,
and the exact file layout — continue to the [User Guide](userguide.md).
