# Changelog

All notable changes to gitsafe are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- The clean filter now refuses to commit a **pre-encrypted envelope on a new
  path whose recipients are not the branch's current readers** — previously such
  a blob passed through verbatim, which could lock the real readers out or commit
  a secret readable by an outsider. Stage plaintext and let gitsafe encrypt it.
- The clean filter now refuses an **edited locked placeholder** (content that
  starts with the placeholder marker but isn't the verbatim placeholder) instead
  of silently restoring the stored blob (dropping the edit) or encrypting the
  placeholder text over the secret. Only the verbatim placeholder restores the
  stored secret; both data-loss outcomes are now explicit errors.
- `gitsafe check` now **warns** when a staged secret is encrypted to a recipient
  who is not a current reader of the branch — surfacing a revoked member who can
  still decrypt until you `rotate`, or a mis-encrypted blob addressed to an
  outsider. Advisory only (it does not fail the check) and quiet for ordinary
  not-yet-rotated state.
- `Recipients` now **skips a member with no encryption key** (empty `enc`)
  instead of emitting `""` into the recipient set, where it would make age fail
  and block encrypting the secret for the whole branch — one malformed keyring
  entry can no longer break encryption for everyone.
- `clone` (used to build each next policy version) now **panics on a
  marshal/unmarshal error** rather than silently returning a half-built policy
  that could then be signed; a `Policy` is pure JSON, so an error there is a
  programming bug, not a runtime condition to swallow.

### Changed
- Ref-glob matching anchors with `\z` (end of text) rather than `$`, so a ref
  with a trailing newline can no longer over-match a grant pattern.
- Identity files are written with restrictive permissions (private key material
  is never left group/world-readable).

### Documentation
- New User Guide section **"Offboarding: removing someone correctly"** — a
  copy-pasteable checklist (revoke → rotate → roll the secret value) explaining
  why rotation is forward-only and what actually ends a leaver's access. Linked
  from the README and tutorial.
- *Secrets in Git, Done Right* — a short, hands-on book under `book/` teaching
  gitsafe from first principles, with exercises and projects.

## [0.1.0] — 2026-06-24

First public release: git-crypt with portable, offline-verifiable access control.

### Added
- `gitsafe init`, `key gen`/`show`, `member add`/`revoke`, `grant`/`revoke`,
  `rotate`, `trust`, `access`, `whoami`, `policy show`/`verify`.
- git clean/smudge filters that encrypt marked files to the current branch's
  authorized readers with [age](https://age-encryption.org).
- Branch-scoped recipients: a secret's decryption recipients are derived from
  who can read its branch.
- Signed, content-addressed policy chain (ed25519) stored under
  `.gitsafe/policy/`, verifiable offline.
- Root-pinned (TOFU) trust anchor with a verified-head cache and a per-clone
  rollback high-water mark.
- Deterministic re-staging and placeholder-safety in the clean filter.
- Compressed object storage at rest with schema versioning and migration.
- Unit, fuzz, race, and real-git end-to-end test suites; CI on every push;
  GoReleaser cross-platform builds.
- Apache-2.0 `LICENSE`.
- `SECURITY.md` vulnerability-disclosure policy.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.
- Passphrase-encrypted identities at rest: `gitsafe key gen --passphrase`,
  `gitsafe key lock` to migrate an existing key, and transparent unlock via the
  `GITSAFE_PASSPHRASE` environment variable or an interactive prompt.
- Ciphertext merge driver: `gitsafe merge` performs a decrypt → 3-way merge →
  re-encrypt so two branches editing the same secret can be merged. Wired up by
  `gitsafe init`.
- Release artifacts are now signed with cosign (keyless) and ship with a syft
  SBOM.
- Key-loss / recovery runbook in the User Guide.
- `gitsafe onboard NAME BRANCH` — add a member, grant read, and rotate in one
  signed step.
- Named groups in the CLI: `gitsafe group add|remove|list` (the policy engine
  already expanded groups; now they're manageable from the command line).
- `gitsafe audit [RESOURCE]` — show how a branch's readers changed across policy
  versions, or the full grant history.
- `gitsafe check` — fail if a marked secret is staged as plaintext; documented as
  a pre-commit hook, with a CI trust-pinning guide in the User Guide.

### Changed
- `member add` and `onboard` now require only `--enc` (the age key); `--sign`
  (ed25519) is optional and needed only for members who administer the policy.
  Read-only teammates send a single key. `--update` preserves an existing sign
  key when not re-supplied, and **reactivates** a revoked member — so it is also
  the un-revoke path.
- Granting `admin` to a member with no signing key is now **refused** (it would
  be unusable) instead of merely warned.
- Trust pin and verified-head cache files are written `0600` in a `0700`
  directory, so another local account cannot tamper with this clone's trust
  anchor.

### Security
- **Plaintext-leak fix:** the clean filter treated any input beginning with the
  9-byte envelope magic as already-encrypted (a prefix-only check), so a
  plaintext or binary secret whose first bytes matched the magic could be
  committed unencrypted (or silently overwrite new content with the stored blob).
  Encryption is now gated on a structurally valid envelope (`format.Parse`); the
  same fix applies to `gitsafe check`.
- **Rollback defense:** a content-only attacker could replay an older,
  still-validly-signed policy HEAD to undo a revocation. Policy versions are now
  enforced monotonic (`version == parent + 1`) and the trust gate refuses any
  policy below the highest version a clone has trusted (`trust --force` re-bases).
- **Lock correctness:** the mtime-based stale-lock steal was a TOCTOU that could
  grant the policy lock to two processes at once (lost-update chain corruption).
  Replaced with an advisory `flock` released by the kernel on process death — safe
  crash recovery with no stealing race.
- `refs/policy` is now implicitly restricted, so a wildcard (`*`) admin grant can
  no longer silently make every member a policy administrator.

### Fixed
- The policy engine refuses any change that would leave no usable admin (an
  active member holding admin with a signing key), preventing a revoke/strip
  from bricking the signed chain.
- `writeAtomic` fsyncs the parent directory after rename, so a policy write
  survives power loss without HEAD pointing at a lost object.
- gitsafe generates `.gitsafe/policy/.gitignore` (excluding the lock and
  atomic-write temp files) so committing the policy chain never stages them.
- The merge driver refuses a locked placeholder as a merge input instead of
  merging the placeholder text into the secret and re-encrypting it (which
  destroyed the file for all readers); its decrypted temporaries are written to
  a private `0700` directory rather than world-readable `/tmp`.
- `gitsafe check` also flags staged files matching the policy `secret_paths`,
  not only `.gitattributes`-marked files.
- `format.Parse` caps the declared envelope header length (corrupt-blob guard),
  and `?` in policy ref globs now matches a single character, consistent with
  path globbing.

[Unreleased]: https://github.com/xmonader/gitsafe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xmonader/gitsafe/releases/tag/v0.1.0
