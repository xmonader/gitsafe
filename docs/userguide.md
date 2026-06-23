# gitsafe User Guide

Reference documentation: the concepts, the command surface, the on-disk layout,
the policy and trust models, and troubleshooting. For a guided, learn-by-doing
introduction see the [Tutorial](tutorial.md); for the pitch and threat summary
see the [README](../README.md).

## Contents

- [Concepts](#concepts)
- [Installation & setup](#installation--setup)
- [On-disk layout](#on-disk-layout)
- [Identity](#identity)
- [The policy model](#the-policy-model)
- [Recipients: how readers become decryption keys](#recipients-how-readers-become-decryption-keys)
- [The git filters](#the-git-filters)
- [The trust model](#the-trust-model)
- [Rotation & key lifecycle](#rotation--key-lifecycle)
- [Command reference](#command-reference)
- [Using gitsafe in CI and as a pre-commit hook](#using-gitsafe-in-ci-and-as-a-pre-commit-hook)
- [Security model & threat boundaries](#security-model--threat-boundaries)
- [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Concepts

gitsafe encrypts marked files in a git repository so that only the people allowed
to **read a branch** can decrypt that branch's secrets. Four ideas carry the
whole tool:

1. **Identity** — your keypair: an age (X25519) key that *receives* encrypted
   secrets, and an ed25519 key that *signs* policy. Private keys live outside the
   repo.
2. **Policy** — a signed, versioned document committed in the repo: a keyring of
   members (public keys), and grants saying *who may do what on which ref*.
3. **Recipients = branch readers** — when a secret is encrypted, gitsafe asks the
   policy "who can read the current branch?" and encrypts to exactly those
   members' age keys. You never maintain a separate recipient list.
4. **Trust pin** — each clone records the policy's root signing key locally, so a
   later change to that root is detected as a possible attack.

The whole thing runs on stock git via **clean/smudge filters** — there is no
server and no daemon.

---

## Installation & setup

Build the single static binary and put it on your `PATH` as `gitsafe`:

```bash
make build
sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
```

Requirements: Go 1.25+ to build, and `git` on the `PATH` at runtime.

Per machine, once: `gitsafe key gen`.
Per repository (and per fresh clone): `gitsafe init`, then `gitsafe trust` if the
repo already had a policy.

---

## On-disk layout

gitsafe touches five locations. Knowing which travel with the repo and which are
local is the key to understanding setup and trust.

| Location | Travels in repo? | Purpose |
|---|:---:|---|
| `~/.config/gitsafe/identity` | **no** (private) | Your private age + ed25519 keys. Override with `GITSAFE_IDENTITY` or `XDG_CONFIG_HOME`. |
| `.gitsafe/policy/HEAD` | **yes** (committed) | Hash of the current policy version. |
| `.gitsafe/policy/objects/<hash>.json` | **yes** (committed) | One signed policy version each; the chain. |
| `.gitattributes` | **yes** (committed) | Which paths get the `gitsafe` filter. |
| `.git/config` (`filter.gitsafe.*`, `gitsafe.user`) | **no** (per-clone) | Wires git to call `gitsafe clean/smudge`; records your member name. |
| `.git/gitsafe/root` | **no** (per-clone) | The pinned policy-root public key (trust anchor). |

Because the policy and marks are committed, access rules and "what's a secret"
travel automatically on `git push`/`pull`. Because the filter config and trust
pin are *not* committed, every clone runs `gitsafe init` (and `gitsafe trust`)
once — by design: a repository cannot vouch for its own authenticity.

---

## Identity

Your identity holds two private keys (age X25519 for decryption, Ed25519 for
signing policy). Manage it with:

- `gitsafe key gen [--passphrase]` — generate it (refuses to overwrite). With
  `--passphrase` the file is encrypted at rest (see below).
- `gitsafe key show` — print the **public** halves to share with an admin.
- `gitsafe key lock` — encrypt an existing plaintext identity at rest.

Resolution order for the file path:

1. `$GITSAFE_IDENTITY` (an explicit file path — useful for CI and for managing
   multiple identities),
2. `$XDG_CONFIG_HOME/gitsafe/identity`,
3. `~/.config/gitsafe/identity`.

The file is written `0600`. Treat it like an SSH private key: back it up, never
commit it, and re-issue if exposed.

### Protecting your key at rest

By default the identity is stored as plaintext JSON (readable by anyone who can
read the file — a stolen laptop without disk encryption, a synced backup, or
malware). To protect it, encrypt it with a passphrase:

```bash
gitsafe key gen --passphrase   # new key, encrypted at rest
gitsafe key lock               # encrypt an existing key in place
```

gitsafe auto-detects the format on load. The passphrase is supplied via:

- **`GITSAFE_PASSPHRASE`** — the non-interactive path. The git filters
  (`clean`/`smudge`/`merge`) have no terminal, so **a passphrase-protected key
  only works under git if this variable is set** in that environment.
- an **interactive prompt** on `/dev/tty` for the other commands.

Trade-off: a passphrase truly protects the key on disk, but you must export
`GITSAFE_PASSPHRASE` (e.g. from your shell profile or a keychain helper) for
`git add`/`git checkout` to decrypt. If you skip that, a locked key simply
degrades to placeholders on checkout — your data is safe, just not visible until
the passphrase is available.

### Key loss & recovery

There is no master key and no escrow by default — this is deliberate (an escrow
key would be a single point of compromise). If you lose your identity file with
no backup, you cannot decrypt secrets you were a recipient of, and nobody can
recover it *for* you. Recovery is re-enrolment, not decryption:

1. **Generate a fresh identity:** `gitsafe key gen` (optionally `--passphrase`),
   then `gitsafe key show`.
2. **An admin re-adds you with the new keys:**
   `gitsafe member add <you> --sign <hex> --enc <age1...> --update` (the
   `--update` flag is required to replace an existing member's keys), then
   commits the policy change.
3. **An admin rotates** so current secrets are re-encrypted to your new key:
   `gitsafe rotate` → `git add .gitsafe <secrets> && git commit`.
4. After a pull you can read **current** secrets again. Note you still cannot
   read *historical* blobs that were encrypted only to your lost key — and a
   secret your lost key could read should be treated as exposed and its **value
   rotated** if the key itself may be compromised (lost ≠ destroyed).

**To make loss a non-event, back the key up:** copy `~/.config/gitsafe/identity`
to secure offline storage (a password manager, an encrypted USB key). Because
the file is small, a passphrase-encrypted copy is safe to store in more places.
For teams, ensure there is always **more than one admin** so a single lost admin
key cannot strand the policy (admins are the only ones who can re-enrol members
and rotate).

A member's **name** (set via `gitsafe init --user NAME`, stored as
`gitsafe.user`) must match the name they were added under in the keyring *and*
their identity's public keys must match that keyring entry — otherwise their
signed policy changes won't verify. For a read-only member the name is cosmetic;
for anyone who signs policy (admins) it must line up.

---

## The policy model

The policy is a chain of signed versions. Each version contains:

- **Keyring** — `name -> { sign: <ed25519 pub hex>, enc: <age recipient>, status: active|revoked }`.
- **Grants** — a list of `{ subject, verb, resource }` capabilities.
- **Signer / Sig** — who signed this version and the ed25519 signature over it.
- **Parent** — the hash of the previous version (the chain link).

### Verbs

`read`, `write`, `force`, `grant`, `admin`, with a hierarchy:

```
admin > force > write > read
```

A higher verb satisfies a lower one (admin satisfies read), and `admin` also
implies `grant`. Practically:

- **`read`** is what determines decryption recipients.
- **`admin`** is what lets someone change the policy (add members, grant, etc.).
  It is checked against the reserved resource `refs/policy`.
- `write`/`force` exist for completeness and as policy metadata; gitsafe is an
  overlay and does **not** enforce push/force-push server-side. Don't rely on
  them for access control.

Because a higher verb satisfies `read`, granting someone `write` or `admin` on a
ref **also makes them a recipient** of that ref's secrets.

### Resources

A resource is a ref glob. The CLI accepts a bare branch name as shorthand:

- `main` → `refs/heads/main`
- anything starting with `refs/` is used verbatim, e.g.
  `refs/heads/feature/*` or `refs/heads/**`.

Glob semantics: `*` matches within one path segment, `**` matches across
segments. So `refs/heads/feature/*` matches `refs/heads/feature/login` but not
`refs/heads/feature/login/v2`; use `**` for the latter.

### Who may change policy

Version 0 (the **root**) is self-signed by the founding admin. Every later
version must be signed by someone who held `admin` in the *parent* version, and
the signature must verify against their keyring public key. This is what makes
the chain forgery-resistant: you can't insert a version you weren't authorized
to make, and you can't tamper with an existing one without breaking its
signature. `gitsafe policy verify` checks all of this offline.

> **Note on groups & restricted refs.** The policy format reserves fields for
> named groups and need-to-know "restricted" refs, but the MVP CLI does not yet
> surface commands to manage them. Use individual grants for now.

---

## Recipients: how readers become decryption keys

When the clean filter encrypts a file on branch `B`, it computes the recipient
set as follows (`policy.Recipients("refs/heads/B")`):

1. Find every grant whose resource matches `refs/heads/B` and whose verb
   satisfies `read`.
2. Collect the subjects: a concrete member name adds that member; `*` (public)
   means *all active members*.
3. Drop any member whose status is `revoked`.
4. The result is the age recipients the file is encrypted to (sorted, for
   deterministic output).

Consequences worth internalizing:

- **No readers, no encryption.** If nobody is granted read on a branch, clean
  refuses (`no readers for refs/heads/B`) rather than encrypt to nobody and lose
  the data. Grant at least yourself first.
- **Admins can always read** (admin satisfies read).
- **Public (`*`) means the whole team, never the anonymous public** — a `*` read
  grant resolves to "every active member," because only members have keys.
- **Revocation takes effect on the next `rotate`**, not retroactively (see
  [Rotation](#rotation--key-lifecycle)).

---

## The git filters

`gitsafe init` registers a filter named `gitsafe` in `.git/config`:

```ini
[filter "gitsafe"]
    clean    = gitsafe clean %f
    smudge   = gitsafe smudge %f
    required = true
```

`required = true` means a filter failure aborts the git operation rather than
silently storing plaintext — a safety property you want.

### Clean (on `git add`, `git status`, `git commit`)

git pipes the working-tree file to `gitsafe clean <path>` on stdin. The filter
decides what blob git should store, in this order:

1. **Input is a locked placeholder** → re-emit the stored ciphertext. A
   non-reader who re-stages their placeholder can never overwrite the real
   secret.
2. **Input is already a gitsafe envelope** (the working copy wasn't decrypted —
   e.g. a clone before filters/trust were set up) → re-emit the stored blob
   (or pass the envelope through). Never double-encrypts. Needs no policy/trust
   because there's no plaintext at risk.
3. **Input is plaintext** → verify the signed policy chain *and* that its root
   matches this clone's pin, resolve the branch's recipients, and encrypt with
   age. If the policy can't be trusted, clean refuses.

To avoid spurious diffs (age output is randomized), clean recognizes an
unchanged secret encrypted to an unchanged reader set and re-emits the existing
stored ciphertext byte-for-byte, so `git status` stays clean.

### Smudge (on checkout)

git pipes the stored blob to `gitsafe smudge <path>`. The filter:

1. **Not a gitsafe envelope** (e.g. committed before gitsafe) → pass through
   unchanged.
2. **Envelope, and you're a recipient** → decrypt and write plaintext.
3. **Envelope, but you can't decrypt** (no identity, or not a recipient) → write
   a clear **locked placeholder**. Smudge never fails a checkout.

Smudge does **not** consult the policy — it only uses your private key against
the ciphertext — so a tampered policy cannot affect decryption.

---

## The trust model

The policy root is self-signed, which proves internal consistency but not
*identity*: an attacker could replace the whole chain with their own
self-consistent one. The defense is **trust-on-first-use (TOFU) root pinning**,
the same idea as SSH `known_hosts`.

- When you **bootstrap** a repo (`gitsafe init` with no existing policy), you are
  the root, so gitsafe pins your root key automatically.
- When you `gitsafe init` an **existing** policy (a clone), gitsafe wires filters
  but prints the root fingerprint and asks you to pin deliberately with
  `gitsafe trust` — after you've confirmed the fingerprint through a trusted
  channel.
- The pin lives in `.git/gitsafe/root` (per-clone, never committed).
- Before encrypting any plaintext, the clean filter checks the verified root
  against your pin. A mismatch is refused with a loud error; if the change is
  legitimate (an intended re-bootstrap), re-pin with
  `gitsafe trust --fingerprint <hex> --force`.

`gitsafe policy verify` always shows the current root fingerprint and whether it
matches your pin (`pinned and matches ✓`, `NOT PINNED`, or `MISMATCH`).

---

## Rotation & key lifecycle

`gitsafe rotate` re-applies the clean filter to every marked file, re-encrypting
each to the **current** reader set, and stages the results. You then commit.

Use it whenever the reader set changes:

- after `member add` + `grant` (so a new reader can actually decrypt),
- after `member revoke` or `revoke` (so a former reader is excluded going
  forward),
- after moving a branch's grants around.

Rotate **refuses** if any marked file in your working tree is a locked
placeholder — you can't re-encrypt what you can't read, so rotation must be run
by a reader. It reports only the files that actually changed.

**Forward-only:** rotation changes future blobs; it does not rewrite history.
Anyone who already had read access retains a decryptable copy of the old
ciphertext in their clone or in packfiles. After revoking access to a live
secret, **rotate the secret value itself** (new password/key), as you would after
any exposure.

To replace your own keys: `gitsafe key gen` on a new file, send the new public
keys to an admin, who runs `member add <you>` (updating your entry) and
`rotate`.

---

## Command reference

Global: `gitsafe version`, `gitsafe help`.

### `gitsafe key gen [--passphrase]`
Generate your identity at the resolved path. Refuses to overwrite. Prints your
public keys and a ready-to-paste `member add` line. With `--passphrase`, the
identity is encrypted at rest (prompts for a passphrase, confirmed twice).

### `gitsafe key show`
Print the public keys of your existing identity.

### `gitsafe key lock`
Encrypt an existing plaintext identity at rest with a passphrase (prompted).
Refuses if it is already encrypted. Afterwards the git filters need
`GITSAFE_PASSPHRASE` set in their environment to decrypt. See
[Protecting your key at rest](#protecting-your-key-at-rest).

### `gitsafe init [--user NAME]`
Set up gitsafe in the current repo:
- ensures you have an identity (generates one if absent),
- registers the `gitsafe` filter and `gitsafe.user` in `.git/config`,
- appends default secret marks to `.gitattributes` if not already present,
- **bootstraps** policy v0 with you as admin if there's no policy yet, pinning
  the root; otherwise wires filters and prints the root fingerprint to trust.

`NAME` defaults to git's `user.name`, then `$USER`. It must match your keyring
name for policy-signing operations.

Default marks written: `.env`, `.env.*`, `*.pem`, `*.key`, `secrets/**`, plus a
guard (`.gitsafe/** -filter`) keeping policy files unencrypted.

### `gitsafe member add NAME --sign HEX --enc age1...`
Add (or update) a keyring member with their ed25519 signing public key and age
recipient. Signs a new policy version. Requires you to be an admin.

### `gitsafe member revoke NAME`
Mark a member `revoked`. They're excluded from recipients after the next
`rotate`. Requires admin.

### `gitsafe onboard NAME BRANCH --sign HEX --enc age1... [--update]`
The one-shot teammate flow: adds (or `--update`s) the member **and** grants them
`read` on `BRANCH` in a single signed policy version, then runs `rotate` so the
branch's secrets are immediately re-encrypted to include them. Equivalent to
`member add` + `grant … read BRANCH` + `rotate`, but atomic and harder to leave
half-done. Commit `.gitsafe` and the re-encrypted secrets afterward. Requires
admin.

### `gitsafe group add GROUP NAME [NAME...]`
Add members to a named group, creating it if absent. A group can be the subject
of a grant (`gitsafe grant devs read staging`), so you manage access by role
instead of per person; groups are expanded to their members wherever access is
evaluated. Members must already exist in the keyring, and a group may not share a
name with a member. Requires admin. Run `rotate` if the group holds read access.

### `gitsafe group remove GROUP [NAME...]`
Remove the named members from a group, or delete the whole group when no names
are given. A group left empty is deleted. Requires admin. Run `rotate` if this
removed read access.

### `gitsafe group list`
Print the defined groups and their members.

### `gitsafe grant SUBJECT VERB RESOURCE`
Add a capability (`read`/`write`/`force`/`grant`/`admin`) for `SUBJECT` (a member
name, or `*` for all members) on `RESOURCE` (a ref glob; bare branch name
allowed). Idempotent — an identical grant is a no-op. Requires admin.

### `gitsafe revoke SUBJECT VERB RESOURCE`
Remove a previously-added grant matching exactly that subject/verb/resource.
Errors if there's no match. Requires admin. Follow with `rotate` if it removed
read access.

### `gitsafe rotate`
Re-encrypt all marked files to the current reader set and stage them. Refuses if
you hold locked placeholders. Commit afterward.

### `gitsafe trust [--fingerprint HEX] [--force]`
Pin this clone to the policy root.
- No flags: verify the chain and pin the current root (TOFU).
- `--fingerprint HEX`: assert the root is `HEX` and pin it; refuses if the actual
  root differs (a safety assertion, useful in scripts/CI).
- `--force`: re-pin even though a *different* root is already pinned.

### `gitsafe access RESOURCE`
Resolve who can decrypt secrets on a branch/ref: prints the active reader names
(expanding groups, admins, and public) and the age-recipient count. The core
audit query.

### `gitsafe audit [RESOURCE]`
Show how access evolved across the signed policy chain — the "who could read
what, and when did it change" query for compliance. With a `RESOURCE` it prints
the reader set of that branch at every version, flagging the versions where it
changed. Without one it prints the grant history version-by-version.

### `gitsafe check`
Inspect the staged tree and **fail** if any gitsafe-marked file is about to be
committed as plaintext — the footgun that happens when the filters aren't active
(a fresh clone before `gitsafe init`, an unpinned clone, or a misconfigured CI
runner). Intended as a pre-commit hook (see
[Using gitsafe in CI](#using-gitsafe-in-ci-and-as-a-pre-commit-hook)).

### `gitsafe whoami`
Print your configured user name, local identity public keys, your keyring status,
an integrity check that the keyring entry matches your local identity, and the
grants where you're the direct subject.

### `gitsafe policy show`
Print the current policy version, keyring (name, status, age key), and grants.

### `gitsafe policy verify`
Verify the entire signed chain offline. Prints the version count, head hash, root
fingerprint, and trust-pin status.

### `gitsafe clean PATH` / `gitsafe smudge PATH`
The git filters. You don't call these by hand — git invokes them. Documented in
[The git filters](#the-git-filters).

### `gitsafe merge %O %A %B %P`
The git **merge driver** for encrypted files, configured automatically by
`init`. When two branches change the same marked secret, git can't 3-way merge
the opaque ciphertext, so gitsafe decrypts ours/base/theirs, runs a normal
3-way merge on the plaintexts, and re-encrypts the result to the current
branch's readers. A genuine content conflict is surfaced as usual — the conflict
markers live inside the re-encrypted blob, so a reader sees them on checkout and
resolves by editing and re-staging. You don't call this by hand. You must be a
reader of the secret to merge it; a non-reader's merge is refused rather than
silently mangling data.

---

## Using gitsafe in CI and as a pre-commit hook

### Pre-commit hook (catch plaintext leaks locally)

The biggest operational footgun is committing a marked secret **as plaintext**
because the filters weren't active (a fresh clone before `gitsafe init`, or an
unpinned clone). `gitsafe check` fails when that's about to happen. Wire it as a
pre-commit hook so a mistake can't reach a commit:

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
exec gitsafe check
EOF
chmod +x .git/hooks/pre-commit
```

`.git/hooks/` is per-clone and not committed. For a shared hook, point git at a
tracked directory once: `git config core.hooksPath .githooks` and commit a
`.githooks/pre-commit` running `gitsafe check`.

### CI: pin trust deliberately

A CI runner is just another clone, so the same TOFU rule applies: it will refuse
to encrypt against a policy it hasn't been told to trust. Don't let CI blindly
trust — pin the **known** fingerprint so a tampered policy fails the build
instead of being silently accepted. A typical job:

```bash
# CI environment provides the runner's identity and (if encrypted) its passphrase
export GITSAFE_IDENTITY="$RUNNER_KEY_FILE"
export GITSAFE_PASSPHRASE="$RUNNER_KEY_PASSPHRASE"   # only if the key is locked

gitsafe init --user ci-runner
gitsafe trust --fingerprint "$EXPECTED_ROOT_FINGERPRINT"   # asserts, doesn't TOFU
git checkout -- .                                          # decrypt what CI may read
gitsafe check                                              # belt and braces
```

`gitsafe trust --fingerprint HEX` is the non-interactive, safe form: it pins only
if the policy root actually equals `HEX`, and fails otherwise — so a CI run can
never be tricked into trusting a swapped-out policy. Get the expected fingerprint
from `gitsafe policy verify` on a trusted machine and store it as a CI variable.

If the CI runner is only a **reader** (decrypts secrets to use them) it never
needs to encrypt, so trust is only needed for the `checkout`/decrypt path. If it
**writes** secrets back, pin as above before any `git add`.

---

## Security model & threat boundaries

- **Private keys** never enter the repo; the policy holds only public keys.
- **The policy is signed and chained**; tampering breaks verification.
- **The root is pinned per-clone (TOFU)**; a wholesale root replacement is
  detected.
- **Encryption is gated on verification**: the clean filter refuses to encrypt
  plaintext against an unverified or root-mismatched policy, so you can't be
  tricked into encrypting your secret to an attacker's key.
- **Out of scope:** an attacker with write access to your local `.git/` (game
  over for any tool); enforcement of write/force at the git-server layer
  (gitsafe is a client-side overlay); and **read-after-revocation** — a former
  reader keeps decryptable copies of old ciphertext, so rotate the secret value
  after offboarding.

See the [README security section](../README.md#security-model--threat-boundaries)
for the same boundaries in pitch form, and the full
[Threat Model](threat-model.md) for assets, adversaries, residual risks, and the
exact code gates that enforce each claim.

---

## Troubleshooting & FAQ

**`git add` fails: "policy root is not trusted in this clone."**
Fresh clone, not pinned. Verify the fingerprint (`gitsafe policy verify` shows
it), then `gitsafe trust`.

**`git add` fails: "policy root changed — REFUSING to use it."**
The repo's root differs from your pin. If it's a legitimate re-bootstrap,
`gitsafe trust --fingerprint <hex> --force`. Otherwise treat it as tampering and
investigate before proceeding.

**`git add` fails: "no readers for refs/heads/X."**
No member is granted read on branch X. `gitsafe grant <you> read X` (and any
teammates), then retry.

**My secret shows as modified on every `git status`.**
The `gitsafe` filter isn't configured in this clone. Run `gitsafe init`. (When
the filter *is* active, gitsafe deliberately keeps unchanged secrets stable.)

**A teammate sees a placeholder, not the secret.**
They aren't granted read on that branch, or you granted them but didn't
`gitsafe rotate` and commit. Check `gitsafe policy show`, then grant + rotate.

**A new clone has ciphertext sitting in the working tree.**
Filters weren't active at checkout. `gitsafe init`, `gitsafe trust`, then
`git checkout -- .` to re-run smudge.

**Can two branches edit the same secret and merge?**
Not automatically — two branches produce different ciphertext blobs git can't
3-way merge. Resolve by decrypting both sides, merging the plaintext, and
re-staging. A merge driver is future work.

**Does committing on a detached HEAD or mid-rebase work?**
No — the clean filter refuses when it can't unambiguously resolve the branch
(and therefore the recipients), rather than guess. Commit secrets from a normal
branch checkout.

**How do I see exactly who can decrypt branch X?**
`gitsafe access X` resolves it directly (expanding groups, admins, and public to
concrete active members). `gitsafe policy show` gives the raw keyring and grants.

**Do linked worktrees work?**
Yes. Git filter config and the trust pin live in the *common* git dir, so they're
shared across all worktrees of a clone — establish trust once and every worktree
inherits it. (See `TestWorktree`.)
