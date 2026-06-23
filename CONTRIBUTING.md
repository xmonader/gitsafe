# Contributing to gitsafe

Thanks for your interest. gitsafe is a small, security-focused tool, so the bar
for changes is correctness and clarity over features. This guide is short on
purpose.

## Ground rules

- **Security first.** This is a tool people trust with secrets. A change that
  adds a feature but weakens a guarantee will be rejected. If you're unsure
  whether something touches the security model, read [`docs/threat-model.md`](docs/threat-model.md)
  and ask in an issue first.
- **Found a vulnerability?** Do **not** open a public issue — follow
  [`SECURITY.md`](SECURITY.md).
- **Discuss big changes first.** Open an issue before a large PR so we agree on
  the approach before you spend time on it.

## Development setup

```bash
git clone https://github.com/xmonader/gitsafe
cd gitsafe
make build        # build ./gitsafe
make test         # unit + real-git end-to-end tests
make lint         # go vet
go test -race ./... # race detector
```

You need **Go 1.25+** and `git` on your PATH.

## Before you open a PR

Every PR must pass what CI runs, so run it locally first:

```bash
make build
make test
go vet ./...
go test -race ./...
gofmt -l .        # must print nothing
```

For changes to the ciphertext envelope or policy parsing, also run the fuzzers
for a bit:

```bash
go test ./internal/format -run xxx -fuzz FuzzParse -fuzztime 30s
go test ./internal/policy -run xxx -fuzz FuzzStoreVerify -fuzztime 30s
```

## Coding standards

- **Tests are required for behavioral changes.** A bug fix needs a test that
  fails before the fix and passes after. New behavior needs coverage.
- **Keep the engine small.** The architecture is deliberately minimal (see
  [`docs/design.md`](docs/design.md)). New dependencies need justification —
  each one is attack surface.
- **Follow the existing structure.** Pure logic lives in `internal/*`; the
  `cmd/gitsafe` package is thin I/O adapters. Keep it that way.
- Match the surrounding style; `gofmt` decides formatting disputes.

## Commit and PR conventions

- One logical change per commit. Each commit should build and pass tests.
- Use Conventional Commit prefixes — `feat:`, `fix:`, `docs:`, `test:`,
  `chore:`, `ci:` — they drive the generated changelog.
- Describe **what changed and why** in the PR, and note any security-model
  impact explicitly.

## License

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0 License](LICENSE).
