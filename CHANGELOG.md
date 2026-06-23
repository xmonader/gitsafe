# Changelog

All notable changes to gitsafe are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
  Read-only teammates send a single key. Granting `admin` to a member with no
  sign key warns how to add it; `--update` preserves an existing sign key and
  status when not re-supplied.

## [0.1.0] — unreleased

First working core.

### Added
- `gitsafe init`, `key gen`/`show`, `member add`/`revoke`, `grant`/`revoke`,
  `rotate`, `trust`, `access`, `whoami`, `policy show`/`verify`.
- git clean/smudge filters that encrypt marked files to the current branch's
  authorized readers with [age](https://age-encryption.org).
- Branch-scoped recipients: a secret's decryption recipients are derived from
  who can read its branch.
- Signed, content-addressed policy chain (ed25519) stored under
  `.gitsafe/policy/`, verifiable offline.
- Root-pinned (TOFU) trust anchor with a verified-head cache.
- Deterministic re-staging and placeholder-safety in the clean filter.
- Compressed object storage at rest with schema versioning and migration.
- Unit, fuzz, race, and real-git end-to-end test suites; CI on every push;
  GoReleaser cross-platform builds.

[Unreleased]: https://github.com/xmonader/gitsafe/compare/main...HEAD
[0.1.0]: https://github.com/xmonader/gitsafe/releases/tag/v0.1.0
