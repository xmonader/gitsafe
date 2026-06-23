# gitsafe Threat Model

A precise statement of what gitsafe defends, against whom, and what it explicitly
does not protect. Written to be attacked: if a claim here is false, that's a bug.

## Assets

1. **Secret plaintext** — the contents of marked files (`.env`, keys, …).
2. **The access policy** — who may read which branch; an integrity asset (it must
   not be forgeable), not a confidentiality asset (it holds only public keys).
3. **Private identities** — each user's age + ed25519 private keys.

## Cryptographic primitives

- **Confidentiality:** [age](https://age-encryption.org) with X25519 recipients
  (ChaCha20-Poly1305 under the hood). Multi-recipient: each reader's key can open
  the file.
- **Integrity/authenticity of policy:** Ed25519 signatures over canonical JSON,
  chained by SHA-256 content address (each version names its parent's hash).
- gitsafe implements **no custom cryptography**; it composes vetted primitives.

## Trust boundaries

| Boundary | Controlled by | gitsafe's stance |
|---|---|---|
| Repository **contents** (`.gitsafe/policy/`, `.gitattributes`, blobs) | anyone who can commit/merge/push | **Untrusted.** Verified before use. |
| Your **local `.git/`** (filter config, trust pin, verified cache) | the local user/OS account | **Trusted.** Compromise here is out of scope. |
| **Private identity** file (`~/.config/gitsafe/`) | the local user/OS account | **Trusted.** Its secrecy is assumed. |
| The **transport** (git remote, hosting) | the git host / network | **Untrusted** for integrity; trusted for availability only. |

The central design choice: a repository **cannot vouch for its own
authenticity**, so authenticity is anchored *outside* the repo — in a per-clone
pin in `.git/`, established once (TOFU).

## Adversaries and what gitsafe stops

### A1 — Repository-content attacker (the primary adversary)
Can open a PR, compromise a collaborator's push access, or otherwise alter
committed files, but **cannot write your local `.git/`**.

- **Tampers with a policy object** → its SHA-256 no longer matches its filename /
  its parent link breaks → chain verification fails → `clean` refuses to encrypt.
- **Re-signs a forged version** with a non-admin key → `Verify` rejects (signer
  lacked admin in the parent) → refused.
- **Replaces the entire chain** with a self-consistent one under a new root →
  verifies internally, but the root key ≠ your pinned root → refused with a loud
  mismatch.
- **Goal of all three:** make you encrypt your next secret to *their* key. All
  are blocked on the encrypt path. *(Covered by `TestTrustGate`.)*

### A2 — Passive repository reader (no decryption key)
Has the repo and its history but is not a recipient.

- Sees only age ciphertext; cannot decrypt. `smudge` shows them a locked
  placeholder. They cannot turn the placeholder into a committed plaintext
  (clean detects and preserves the stored ciphertext).

### A3 — Revoked member
Was a reader, then revoked.

- Excluded from **all future** ciphertext after `rotate`. **Not** retroactively
  locked out of history — see Residual Risk R1.

## Assumptions

1. Your OS account and local `.git/` are not compromised.
2. Your private identity file stays secret.
3. The **first** `gitsafe trust` pins the *intended* root — i.e. you verify the
   fingerprint out-of-band, or accept TOFU's first-contact risk (R2).
4. The age and ed25519 implementations are correct.
5. SHA-256 is collision-resistant (relied on for the content-addressed chain).

## Out of scope / residual risks

- **R1 — Read-after-revocation (inherent).** A former reader keeps decryptable
  copies of the ciphertext that existed while they had access (in their clone or
  packfiles). Rotation protects only future blobs. **Mitigation: rotate the
  secret's *value* after offboarding**, as for any credential exposure.
- **R2 — TOFU first-trust.** Pinning detects later root changes but cannot
  authenticate the *initial* root by itself. If you blindly `gitsafe trust` on a
  repo an attacker fully controls from the start, you trust their root.
  **Mitigation: verify the fingerprint out-of-band on first trust**
  (`gitsafe policy verify` / `gitsafe init` print it).
- **R3 — Local `.git/` compromise.** An attacker who can write your `.git/` can
  rewrite the pin, the filter config, or the verified cache. This is total local
  compromise; no client-side tool defends against it.
- **R4 — Write/force enforcement.** `write`/`force` grants are policy metadata,
  not server-side push enforcement. gitsafe is a client-side overlay; it does not
  prevent a push. Use server hooks/branch protection for that.
- **R5 — Metadata leakage.** File names, sizes, the set of recipients (in the
  envelope header), and the policy (members, grants) are intentionally cleartext.
  gitsafe protects secret *contents*, not the existence or shape of secrets.
- **R6 — Ciphertext merge.** Concurrent edits to one secret on two branches
  produce unmergeable blobs; manual decrypt-merge-reencrypt is required.
- **R7 — Post-quantum.** X25519/Ed25519 are not post-quantum secure. A
  harvest-now-decrypt-later adversary against far-future quantum hardware is not
  addressed.

## Verification gates (where the model is enforced in code)

- `clean` (encrypt path) → `trustedPolicy`: full chain verification + root-pin
  match before any recipient is trusted. *Unit-tested in `internal/filter`;
  end-to-end in `TestTrustGate`.*
- `smudge` (decrypt path) consults **no policy** — it only applies your private
  key to the ciphertext, so a tampered policy cannot influence it.
- Policy object integrity: SHA-256 filename check in `loadObject`; signature and
  admin-authority checks in `Policy.Verify`; chain walk in `VerifyChainRoot`.
  *Fuzzed (`FuzzPolicyMethods`, `FuzzStoreVerify`) and unit-tested.*

## Reporting

Found a way to break a claim above? That's a security bug — please report it
privately before disclosure.
