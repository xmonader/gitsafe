# gitsafe — Technical Design (overlay architecture)

How to deliver the Haven secrets+policy engine on top of real git, and what to reuse vs rebuild. This is a design sketch for the MVP, not final.

## Principles

1. **Operate on a real `.git` repo.** Never replace git plumbing. Integrate through git's documented extension points (filters, attributes, refs, hooks).
2. **Reuse the engine, discard the VCS.** Keep Haven's crypto and policy code; throw away its object store, merge, and wire protocol.
3. **Offline-first, vendor-free.** The policy verifies with nothing but the repo and a public key. No server is required for the core tool.
4. **Private keys never touch the repo.** Identity lives in `~/.config/gitsafe/` (or reuses an existing age/SSH key).

## Reuse vs rebuild (from Haven)

| Haven component | Disposition in gitsafe |
|-----------------|------------------------|
| `internal/policy` (ed25519 signed chain, keyring, grants, `Eval`, `Recipients`) | **Reuse** — this is the crown jewel. Port nearly as-is. |
| `internal/identity` (age X25519 + ed25519) | **Reuse.** |
| `internal/secret` (mark globs, recipient resolution) | **Reuse**, re-point recipients at git branches. |
| `internal/object` (SQLite content store) | **Discard.** Git is the object store. |
| `internal/merge`, `internal/diff`, `internal/ref`, `internal/workspace` | **Discard.** Git does this. |
| `internal/protocol` (HTTP server/client) | **Discard** for the OSS core; may return in Phase 2 as the hosted policy directory. |
| `internal/store` (schema, migrations) | **Discard** (no DB). Policy state lives as committed files/objects. |

Net: roughly the two packages that hold the actual idea survive; the VCS plumbing is dropped. This is the whole point of the pivot.

## Components

### 1. Secret marking — git attributes
Marked paths get a filter via `.gitattributes`:
```
*.env    filter=gitsafe diff=gitsafe
*.pem    filter=gitsafe
secrets/** filter=gitsafe
```
`gitsafe init` registers the filter in the repo's git config:
```
[filter "gitsafe"]
    clean  = gitsafe clean %f
    smudge = gitsafe smudge %f
    required = true
```

### 2. Clean filter (on `git add`) — encrypt
git pipes the working-tree file to `gitsafe clean <path>` on stdin; gitsafe:
1. Resolves the **current branch** (`HEAD`) and asks the policy for that branch's reader recipients.
2. Encrypts stdin with age to those recipients.
3. Writes ciphertext (with a small header: format version, recipient fingerprints, source path) to stdout.
git stores that ciphertext as the blob. **This is exactly git-crypt's mechanism**, so it's proven compatible.

> Open question (de-risk first): clean filters are branch-*unaware* in edge cases (the index can be staged without a clear HEAD, e.g. detached HEAD, initial commit, rebase). Need a deterministic recipient resolution + a clear failure mode when the branch is ambiguous. **This is the riskiest assumption — prototype it before anything else.**

### 3. Smudge filter (on checkout) — decrypt
`gitsafe smudge <path>` reads ciphertext from stdin; if the local identity is an authorized recipient, decrypts and writes plaintext; otherwise writes a clear locked-notice placeholder (and never errors the checkout). Mirrors Haven's checkout behavior.

### 4. The signed policy — committed, not in a DB
Haven stored policy as signed objects in SQLite. In git, store it as committed files under a known path, e.g. `.gitsafe/policy/` (the signed JSON chain) plus a pointer. Options to evaluate:
- **Plain committed files** on the working branches (simplest; travels automatically; visible in diffs).
- **A dedicated ref** like `refs/gitsafe/policy` (keeps policy history off the main branch; needs explicit push config, à la `refs/notes`).

Decision deferred to the prototype; committed files are the MVP default for simplicity. Either way the chain is ed25519-signed and verifies offline exactly as in Haven.

### 5. Recipients = branch readers
`policy.Recipients(branch)` already exists in Haven. The only change: the resource being evaluated is a **git branch name** instead of a Haven ref. Grants map cleanly: `grant bob read 'refs/heads/staging'`.

### 6. Rotation
`gitsafe rotate` re-encrypts marked files in the working tree to the current reader set and stages them, producing a normal commit. Reuses Haven's rotate logic minus the bespoke storage rewrite (in git, re-encrypting = a new blob = a normal commit, which is *cleaner* than Haven's in-place rewrite).

### 7. Identity & onboarding
`gitsafe key gen` / `gitsafe key show` (port from Haven). Adding a member = an admin signs a policy extension adding their public keys + grants, then commits it. Verifies offline.

## MVP scope (and the cut list)

**In:** `init`, `clean`/`smudge` filters, `key gen/show`, `member add`, `grant`/`revoke`, branch-scoped recipients, `rotate`, `policy verify`, default secret marks.

**Cut for MVP (add only if users ask):** groups, restricted/need-to-know tiers beyond read/write, whole-tree (branch) encryption, the HTTP/hosted directory, GUI, non-age backends (KMS/PGP). Ship the wedge, not the platform.

## Riskiest assumptions — de-risk in this order

1. **Branch-aware clean filter** is reliable across detached HEAD / initial commit / rebase / `git stash`. If recipient resolution is ambiguous at clean time, the whole model wobbles. **Prototype this first against a real repo.**
2. **Smudge can't break checkouts** for non-recipients (must degrade to a placeholder, never fail). git-crypt handles this; confirm our behavior matches.
3. **Merge of ciphertext** — two branches editing the same secret produce conflicting ciphertext blobs git can't 3-way merge. Need a documented resolution (decrypt-merge-reencrypt helper, or a merge driver). Known hard spot; scope a `merge driver` later.
4. **Policy distribution** — committed files vs dedicated ref; whichever, it must travel on a normal `git push` with zero extra steps or adoption dies.

## Stack

Go (reuse Haven code directly), `filippo.io/age`, `crypto/ed25519`. Single static binary, installed as `gitsafe` on PATH; `gitsafe init` wires up git config + attributes. No database, no daemon for the core tool.
