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

Your identity is a JSON file containing two private keys. Manage it with:

- `gitsafe key gen` — generate it (refuses to overwrite an existing one).
- `gitsafe key show` — print the **public** halves to share with an admin.

Resolution order for the file path:

1. `$GITSAFE_IDENTITY` (an explicit file path — useful for CI and for managing
   multiple identities),
2. `$XDG_CONFIG_HOME/gitsafe/identity`,
3. `~/.config/gitsafe/identity`.

The file is written `0600`. Treat it like an SSH private key: back it up, never
commit it, and re-issue if exposed. Losing it means you can no longer decrypt
secrets you were a recipient of (an admin re-adds your new key and rotates).

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

### `gitsafe key gen`
Generate your identity at the resolved path. Refuses to overwrite. Prints your
public keys and a ready-to-paste `member add` line.

### `gitsafe key show`
Print the public keys of your existing identity.

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

### `gitsafe policy show`
Print the current policy version, keyring (name, status, age key), and grants.

### `gitsafe policy verify`
Verify the entire signed chain offline. Prints the version count, head hash, root
fingerprint, and trust-pin status.

### `gitsafe clean PATH` / `gitsafe smudge PATH`
The git filters. You don't call these by hand — git invokes them. Documented in
[The git filters](#the-git-filters).

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
for the same boundaries in pitch form.

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
`gitsafe policy show` lists members and grants; recipients for X are the active
members with a read-satisfying grant matching `refs/heads/X` (admins included).
