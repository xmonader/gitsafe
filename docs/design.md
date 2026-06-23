# gitsafe — Technical Design (overlay architecture)

How gitsafe delivers a secrets + signed-policy engine on top of real git.

## Principles

1. **Operate on a real `.git` repo.** Never replace git plumbing. Integrate through git's documented extension points (filters, attributes, refs, hooks).
2. **Small, focused engine.** Branch-derived recipients, a signed policy chain, and age encryption — nothing more. No object store, no merge engine, no wire protocol.
3. **Offline-first, vendor-free.** The policy verifies with nothing but the repo and a public key. No server is required for the core tool.
4. **Private keys never touch the repo.** Identity lives in `~/.config/gitsafe/`.

## Packages

| Package | Responsibility |
|---------|----------------|
| `internal/policy` | The signed access policy: ed25519-signed chain, keyring, grants, `Eval`, `Recipients`, and the file-based store committed under `.gitsafe/policy/`. |
| `internal/identity` | The user keypair: age (X25519) for receiving secrets, ed25519 for signing policy. |
| `internal/secret` | age multi-recipient encryption/decryption and glob-based path classification. |
| `internal/format` | The on-disk ciphertext envelope and the locked-notice placeholder. |
| `internal/filter` | The pure clean/smudge decision logic, with dependencies injected for testability. |
| `internal/gitx` | Thin wrappers over the few real-git operations gitsafe needs. |
| `cmd/gitsafe` | The CLI: argument parsing and thin I/O adapters over the packages above. |

## Components

### 1. Secret marking — git attributes
Marked paths get a filter via `.gitattributes`:
```
*.env    filter=gitsafe
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
1. Resolves the **current branch** (`HEAD`) and asks the verified policy for that branch's reader recipients.
2. Encrypts stdin with age to those recipients.
3. Writes the ciphertext envelope (a small header — format version + recipient list — plus the age ciphertext) to stdout.

git stores that envelope as the blob. This is the same mechanism git-crypt uses, so it is proven compatible. When the branch is ambiguous (detached HEAD, mid-rebase), clean refuses rather than guess recipients. To avoid spurious diffs from age's randomized output, an unchanged secret with an unchanged reader set is re-emitted byte-for-byte.

### 3. Smudge filter (on checkout) — decrypt
`gitsafe smudge <path>` reads the stored blob from stdin; if the local identity is an authorized recipient, it decrypts and writes plaintext; otherwise it writes a clear locked-notice placeholder (and never errors the checkout). Smudge consults no policy — it only applies the local private key to the ciphertext.

### 4. The signed policy — committed, not in a DB
The policy is stored as committed files under `.gitsafe/policy/`: a `HEAD` pointer plus one content-addressed JSON object per signed version. It travels automatically on a normal `git push`, is visible in diffs, and the chain is ed25519-signed so it verifies offline with nothing but the repo and the pinned root key.

### 5. Recipients = branch readers
`policy.Recipients(resource)` resolves the active readers of a git ref (e.g. `refs/heads/staging`) to their age recipients. Grants map cleanly: `gitsafe grant bob read staging`.

### 6. Rotation
`gitsafe rotate` re-encrypts marked files in the working tree to the current reader set and stages them — in git, re-encrypting is simply a new blob in a normal commit.

### 7. Identity & onboarding
`gitsafe key gen` / `gitsafe key show` manage the keypair. Adding a member = an admin signs a policy extension adding their public keys + grants, then commits it. Verifies offline.

### 8. Trust anchor
Each clone pins the policy root's signing key (`.git/gitsafe/root`, TOFU). The clean filter verifies the chain and that its root matches the pin before trusting any recipient it names.

## MVP scope (and the cut list)

**In:** `init`, `clean`/`smudge` filters, `key gen/show`, `member add/revoke`, `grant`/`revoke`, branch-scoped recipients, `rotate`, `trust`, `access`, `whoami`, `policy show/verify`, default secret marks.

**Cut for MVP (add only if users ask):** groups, restricted/need-to-know tiers beyond read/write, whole-tree (branch) encryption, a hosted policy directory, GUI, non-age backends (KMS/PGP). Ship the wedge, not the platform.

## Known hard spots

1. **Branch-aware clean filter** must be reliable across detached HEAD / rebase / `git stash`. Resolved by refusing when the branch is ambiguous rather than guessing recipients.
2. **Smudge must never break checkouts** for non-recipients — it degrades to a placeholder, matching git-crypt's behavior.
3. **Merge of ciphertext** — two branches editing the same secret produce conflicting blobs git can't 3-way merge. Documented as a manual decrypt-merge-reencrypt for now; a merge driver is future work.
4. **Policy distribution** — committed files travel on a normal `git push` with zero extra steps.

## Stack

Go, `filippo.io/age`, `crypto/ed25519`. Single static binary, installed as `gitsafe` on PATH; `gitsafe init` wires up git config + attributes. No database, no daemon for the core tool.
