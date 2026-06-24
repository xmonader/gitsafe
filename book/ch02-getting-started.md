# Chapter 2 — Getting started: your first encrypted secret

In the last chapter you saw the idea: a `.env` that lives happily inside git, encrypted to exactly the people allowed to read the branch, with no server and no second list to maintain. That was the pitch. This chapter is the practice. By the end of it you will have built the whole loop on your own machine — installed the binary, created an identity, turned gitsafe on for a real repository, committed a secret, and *proved* that git stored ciphertext while your working tree still shows the plaintext. Nothing here is hypothetical; every command is one you can copy, run, and watch work.

The reason to do this slowly and deliberately, rather than pasting the four-line quick-start and moving on, is that gitsafe has a small number of moving parts that each do exactly one job. If you understand what `key gen`, `init`, and the two git filters each contribute, the rest of the tool — onboarding teammates, branch-scoped access, offboarding — is just composition. If you skip that understanding, the first time something behaves unexpectedly (a teammate sees a placeholder, a fresh clone shows gibberish) you will have no model to debug against. So we will go one piece at a time, always asking *why* before *how*.

A quick note on the conventions in this chapter. Shell sessions are shown as you would type them; lines beginning with `#` are commentary, not commands you should run. Where a command prints output, that output is shown beneath it. Placeholder values like `age1qz...k7` are truncated real keys — yours will be longer and different. And throughout, "you" means the person at the keyboard, which right now is the founding admin of a brand-new repository.

---

## Installing gitsafe

Before you can encrypt anything you need the `gitsafe` binary on your `PATH`. gitsafe ships as a single static Go binary with no runtime dependencies of its own — there is no service to start, no library to link, no configuration file to pre-create. That simplicity is deliberate: the whole point of the tool is to ride on top of stock git, so installing it should be nothing more than "compile one program and drop it somewhere your shell can find it."

There are exactly two requirements, and they fall on two different sides of the lifecycle. To *build* the binary you need Go 1.25 or newer, because the source uses language and standard-library features from that release. To *run* the binary you need `git` on your `PATH`, because gitsafe is an overlay on git: it reads your repository, registers itself as a git filter, and shells out to git for the operations it doesn't reimplement. You do not need Go installed on machines that only run gitsafe — only on the machine that compiles it — and you do not need anything else at all.

The build itself is driven through the project's `Makefile`, which is the canonical entry point for every build and test task in this codebase. Running `make build` compiles the sources and produces a `gitsafe` executable in the repository root. The second command then copies that executable into a directory on your `PATH` with executable permissions, so that typing `gitsafe` from any directory finds it. `/usr/local/bin` is the conventional home for locally-installed binaries on Linux and macOS; `install -m 0755` both copies the file and sets its mode in one atomic step, which is tidier than a `cp` followed by a `chmod`.

```bash
make build
sudo install -m 0755 gitsafe /usr/local/bin/gitsafe
```

The `sudo` is there only because `/usr/local/bin` is usually root-owned; if you would rather not use `sudo`, install into a directory you own that is on your `PATH` (many people keep a `~/.local/bin` or `~/bin` for exactly this) and drop the `sudo`. Either way the goal is identical: a `gitsafe` you can invoke by name. Once the copy succeeds, confirm the install took by asking the binary to identify itself:

```bash
gitsafe version
```

If that prints a version string, you are done installing. If instead your shell says `gitsafe: command not found`, the binary is not on your `PATH` — most often because the directory you installed into isn't listed in `$PATH`, or because you installed into a fresh `~/.local/bin` that your shell hasn't picked up yet. Open a new shell or check `echo $PATH` and adjust. There is nothing else to configure: no daemon to enable, no first-run wizard. The very next thing you do — creating your identity — is a per-machine setup step, not part of the install, and that distinction matters, so we treat it on its own.

---

## Your identity: who you are to gitsafe

Encryption needs a notion of *you*. When gitsafe encrypts a secret "to the people who can read this branch," it has to turn each of those people into a concrete public key it can encrypt to, and it has to turn *you* into a private key that can decrypt what was encrypted to you. That pair of keys — one half public, one half private — is your **identity**, and creating it is the one setup step you perform per machine rather than per repository. You do it once and then forget about it; every repository on that machine reuses the same identity.

The command to create it is `gitsafe key gen`. It generates a fresh keypair and writes it to a file outside any repository, prints the public halves so you can share them, and refuses to run if an identity already exists at that path so you can never silently clobber the key that other people have already encrypted secrets to.

```bash
gitsafe key gen
```

The single most important property of this file is *where it lives*: outside your repositories, by default at `~/.config/gitsafe/identity`. This is not an arbitrary choice. The private half of your identity is the thing that can decrypt secrets; if it lived inside a repo, it would travel with that repo on every `git push`, and the moment you pushed you would have handed your decryption key to everyone who can clone — which is precisely the disaster gitsafe exists to prevent. Keeping the private key out of the repository is the structural reason the whole scheme is safe. The repository only ever contains *public* keys (in the signed policy) and *ciphertext* (in the secret blobs); the private key that unlocks that ciphertext stays on your machine alone. Treat the file exactly like an SSH private key: it is written with `0600` permissions (owner read/write only), you should back it up somewhere safe, you must never commit it, and you should re-issue it if it is ever exposed.

If the default location doesn't suit you — say you manage several identities, or you're scripting a CI runner — you can override where gitsafe looks. The resolution order is: first the `GITSAFE_IDENTITY` environment variable if set (an explicit file path), then `$XDG_CONFIG_HOME/gitsafe/identity` if `XDG_CONFIG_HOME` is set, and finally the `~/.config/gitsafe/identity` default. We'll lean on `GITSAFE_IDENTITY` in one of this chapter's mini projects to mint a throwaway second identity without disturbing your real one.

### The two public keys, and why there are two

Now look at what `key gen` printed, because the output answers a question that confuses almost everyone at first: *why does my identity have two public keys?* You can re-print them any time with `gitsafe key show`, which reads your existing identity and prints only the public halves — the safe-to-share part.

```bash
gitsafe key show
# enc  (age):      age1qz...k7
# sign (ed25519):  3b9a...e1
```

The two keys exist because gitsafe asks two completely different questions of you, and good cryptographic hygiene answers each with a purpose-built key rather than reusing one key for both. The first key, labelled **`enc`**, is your **age recipient**. It always starts with `age1` and it is the key secrets are *encrypted to* — it is how you receive readable secrets. Every single person who uses gitsafe has one of these, because everyone is at minimum a potential reader. When an admin grants you read access to a branch, what they are really doing is adding your `enc` key to the list of recipients that branch's secrets get encrypted to. This is the key you send when someone onboards you, and it is public: there is no harm in pasting it into Slack, because knowing the recipient key lets someone *encrypt to you*, not *decrypt as you*.

The second key, labelled **`sign`**, is an **ed25519 signing key**, shown as a hex string. It answers a different question entirely: not "can this person read?" but "is this person allowed to *change the rules*?" The policy that says who-can-read-what is a signed document, and only people who administer that policy need to sign it. So the `sign` key is only relevant if you are — or will become — an **admin** who adds members, grants access, and so on. A read-only teammate never needs to share their `sign` key at all; their `enc` key alone is enough to make them a recipient. This asymmetry is worth holding onto, because it shapes every onboarding decision later: *reading* needs only the `enc` key, *administering* additionally needs the `sign` key. When in doubt, the rule of thumb is "give me your `enc` line" — and only ask for the `sign` line when you're deliberately promoting someone to admin.

### Protecting your key at rest

There is a gap in the story so far. By default the identity file is written as plaintext JSON. That is fine against the threat of "someone clones my repo" — the private key was never in the repo. But it does nothing against the threat of "someone reads the file off my disk": a stolen laptop without full-disk encryption, a backup that got synced to a cloud you don't fully trust, or malware running as your user. Anyone who can read that file gets your private decryption key. If that threat is in your model, you want the key encrypted *at rest*.

gitsafe encrypts the identity at rest using age's scrypt mode, which derives an encryption key from a passphrase you choose. At a high level, scrypt deliberately makes each guess of the passphrase slow and memory-hungry, so that even if an attacker steals the encrypted file they cannot cheaply brute-force their way through a list of likely passphrases. The on-disk file becomes opaque ciphertext; without the passphrase it is useless. You can opt into this from the start by generating the key with a passphrase, or you can lock an existing plaintext key in place after the fact:

```bash
gitsafe key gen --passphrase   # new identity, encrypted at rest from birth
gitsafe key lock               # encrypt an existing plaintext identity in place
```

`key gen --passphrase` prompts you for a passphrase (twice, to catch typos) before writing the encrypted file. `key lock` does the same to a key you already created in plaintext, and refuses if the key is already encrypted so you can't double-wrap it by accident. gitsafe auto-detects the format when it loads the identity, so the rest of the tool doesn't care whether your key is locked or not — until it needs the passphrase to actually decrypt it.

And that "until it needs the passphrase" is the catch you must plan for. Most gitsafe commands run in your terminal and can simply *prompt* you for the passphrase on `/dev/tty`. But the git filters — the `clean`, `smudge`, and `merge` programs that git invokes automatically during `git add` and `git checkout` — run with **no terminal attached**. They cannot prompt. So a passphrase-protected identity only works under git if the passphrase is supplied through the environment variable `GITSAFE_PASSPHRASE`. In practice this means exporting `GITSAFE_PASSPHRASE` from your shell profile, or from a keychain helper, so that when git fires the filters the passphrase is already there.

```bash
export GITSAFE_PASSPHRASE='correct horse battery staple'
```

The trade-off is real and worth stating plainly: a passphrase genuinely protects your key on a stolen disk, but you pay for it by having to make `GITSAFE_PASSPHRASE` available to git. If you forget to do that, nothing dangerous happens — your data stays safe — but checkouts of secret files will quietly produce *locked placeholders* instead of plaintext, because the filter couldn't open your key to decrypt them. That failure mode is benign (no secret leaks) but confusing if you don't expect it, so if you choose a passphrase-protected key, decide up front how `GITSAFE_PASSPHRASE` will reach your git environment. For the rest of this chapter we'll assume a plaintext key for simplicity, and revisit the passphrase path in Mini Project 3.

---

## Turning gitsafe on for a repository

You now have a binary and an identity. Neither of those, on its own, changes a single repository — and that's the right design, because most of your repos don't contain secrets and shouldn't pay any gitsafe cost. Enabling gitsafe is a deliberate per-repository act. You do it with `gitsafe init`, run from inside the repository you want to protect.

`init` is the busiest command in the tool because it has to set up everything a repo needs to start encrypting, and it's worth understanding each thing it does, because each one maps onto a concept you'll use later. From inside a fresh repository:

```bash
gitsafe init --user alice
```

The `--user alice` part records your member name for this clone. That name is how the policy refers to you, and it matters for two reasons: it's the label other people will see in `gitsafe policy show`, and — crucially for an admin — it must match the keyring entry your signed policy changes are checked against, or those changes won't verify. If you omit `--user`, gitsafe falls back to git's `user.name`, then to your `$USER`. For a read-only member the name is largely cosmetic; for an admin (which you are about to become) it must line up with your identity, so it's good practice to set it explicitly.

When you run `init` in a repository that has no policy yet, gitsafe does five distinct things, and it's worth walking each one because together they *are* the system:

First, it ensures you have an identity, generating one for you if you somehow skipped `key gen`. Second, it registers the `gitsafe` git filter and stores your `gitsafe.user` name in `.git/config` — this is what wires git up to call gitsafe's `clean` and `smudge` programs automatically. Third, it appends a block of default secret *marks* to `.gitattributes`, declaring which file paths should be run through the filter. Fourth, because there's no policy yet, it **bootstraps** a brand-new signed policy at version 0 (v0) with *you* as the sole admin. And fifth, because you created that policy, you *are* its root of trust, so gitsafe automatically pins your own root key for this clone — no separate `gitsafe trust` step is needed when you're the founder.

That fourth and fifth point deserve emphasis. The policy is a signed, versioned document that records who the members are and what each may do. Version 0 is special: it is self-signed by the founding admin, which is you. And because *you* signed it on *this* machine, gitsafe knows it can trust this root without asking — which is why founding a repo skips the trust ceremony that a *fresh clone* of someone else's repo would require. (That clone-side ceremony is important enough to get its own treatment in Chapter 5; for now, just note that founding is the easy case.)

The third point — the default marks — is what makes gitsafe usable without fiddly per-file configuration. The block written to `.gitattributes` marks these patterns for the `gitsafe` filter out of the box: `.env`, `.env.*`, `*.pem`, `*.key`, and `secrets/**`. Those cover the overwhelmingly common cases: dotenv files, PEM-encoded certificates and private keys, and anything under a `secrets/` directory. The same block also writes a guard line, `.gitsafe/** -filter`, which *exempts* the policy files themselves from encryption — the policy has to stay readable plaintext, because it's how a fresh clone learns who the members are in the first place. You can add your own patterns to this file later (we won't in this chapter), and because `.gitattributes` is committed, your choice of "what counts as a secret" travels with the repo to every teammate automatically.

---

## The payoff: commit a secret, prove it's encrypted

Setup is done. Now for the moment that makes all of it concrete: write an actual secret, commit it the way you commit anything, and then look at what git really stored versus what your working tree shows. This is the demonstration that turns "I followed some setup steps" into "I understand what this tool does."

Create a `.env` file with a secret in it. Because `.env` matches one of the default marks, git will route it through the `gitsafe clean` filter the instant you stage it. Then add and commit exactly as you always would — there is no special gitsafe commit command, which is the whole appeal:

```bash
echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env
git commit -m "enable gitsafe, add .env"
```

Notice that you staged three things, not one. The `.env` is the secret. But you also stage `.gitsafe` — the directory holding your freshly-bootstrapped policy — and `.gitattributes` — the marks that say `.env` is a secret. If you forget those two, your teammates will pull a repo that has an encrypted `.env` but no policy describing who may read it and no marks telling their git to decrypt it; the result is broken for everyone but you. Committing all three together is the habit to build from day one, and we'll return to it as the number-one pitfall at the end of the chapter.

Now the proof. git stores the *cleaned* (encrypted) version of the file as a blob object; your working tree keeps the original plaintext. You can ask git directly what bytes it stored for `.env` at `HEAD`, and compare that to what `cat` shows you on disk:

```bash
git cat-file blob HEAD:.env   # what git actually stored  -> ciphertext
cat .env                      # your working copy         -> still plaintext
```

The first command reaches *past* the smudge filter — `git cat-file` dumps the raw stored blob without re-running any filter — so it shows you the truth of what's committed. You'll see binary garbage beginning with a small marker: the bytes `\x00gitsafe\x00`, the gitsafe "magic," followed by age ciphertext. That marker is how every part of gitsafe recognizes its own envelopes. The second command, plain `cat .env`, shows `DB_PASSWORD=hunter2` — the real password — because your working-tree copy was never encrypted. The encryption happened on the way *into* git, transparently, and the decryption happens on the way *out*. You write and read plaintext; git holds ciphertext. That gap, sitting at the boundary between your working tree and git's object store, is the entire mechanism, and it's worth understanding precisely how it's produced.

---

## How it works: the clean and smudge filters

git has a built-in extension point called *filters*: per-file hooks that transform content as it crosses the boundary between your working tree (the files you edit) and the object store (the blobs git commits). gitsafe registers exactly two of them, named for the direction they run. The **clean** filter runs on the way *in* — when git takes a working-tree file and decides what blob to store. The **smudge** filter runs on the way *out* — when git takes a stored blob and writes it into your working tree. gitsafe's clean filter encrypts; its smudge filter decrypts. That's the whole architecture, and the following diagram is the mental model to keep:

```
                   git add / git commit / git status
                                 │
        working tree             ▼            object store (.git)
   ┌──────────────────┐   gitsafe clean   ┌──────────────────────┐
   │ .env             │ ───────────────▶  │ \x00gitsafe\x00 …     │
   │ DB_PASSWORD=...  │   (encrypt to     │ <age ciphertext>      │
   │   (plaintext)    │    branch readers)│   (encrypted blob)    │
   │                  │ ◀───────────────  │                       │
   └──────────────────┘   gitsafe smudge  └──────────────────────┘
                            (decrypt for
                          git checkout       a reader, else show
                                              a locked placeholder)
```

Read the diagram left-to-right for a commit and right-to-left for a checkout. When you `git add` (or even `git status`, which has to compute whether the file changed), git pipes the plaintext `.env` into `gitsafe clean` on standard input. Clean asks the signed policy a single question — "who can read the current branch?" — turns that set of readers into their `enc` recipient keys, encrypts the plaintext to exactly those keys with age, and emits the gitsafe envelope. *That* envelope is the blob git stores. Right now, on a solo repo, the only reader is you, so the file is encrypted to you alone.

The reverse direction is checkout. When git materializes `.env` into your working tree — on `git checkout`, `git switch`, a clone, or an explicit `git checkout -- .env` — it pipes the stored envelope into `gitsafe smudge`. Smudge looks at your private identity and tries to decrypt. If you're a recipient, it writes back the real plaintext and you see your password. If you're *not* a recipient (no identity, or you weren't granted read on this branch), smudge does not fail the checkout — failing would make the file unusable and the error noisy. Instead it writes a clear **locked placeholder**: a small human-readable stand-in that says, in effect, "this is a gitsafe secret you can't read." Your teammates without access see that placeholder; you see the secret. Same blob in git, different working-tree result depending on who holds the key.

One subtle but important property falls out of this design, and it's the one that surprises people: an unchanged encrypted secret does **not** show up as modified in `git status`. You might expect it to, because age encryption is randomized — encrypt the same plaintext twice and you get two different ciphertexts, which would normally make git think the file changed every time it ran the clean filter. gitsafe avoids that churn deliberately. When clean sees that the working-tree plaintext is unchanged *and* the reader set is unchanged, it re-emits the **existing stored ciphertext byte-for-byte** rather than producing a fresh random encryption. The blob is identical to what's already committed, so git sees no change, and `git status` stays clean. This "deterministic re-staging" is what makes gitsafe livable day to day; without it, every `git status` would scream that all your secrets were modified. If you ever *do* see a secret perpetually showing as modified, that's the tell-tale sign the filter isn't actually configured in that clone — the fix is `gitsafe init`.

There's a second, smaller diagram worth internalizing: where the four pieces of state live, and which ones travel with the repo. This is the map that explains why a fresh clone needs setup but your founding repo didn't.

```
   TRAVELS WITH THE REPO (committed)        LOCAL TO THIS CLONE (in .git/, never pushed)
   ┌───────────────────────────────┐       ┌───────────────────────────────────────────┐
   │ .gitsafe/policy/   (the rules) │       │ .git/config  filter.gitsafe.* + gitsafe.user│
   │ .gitattributes     (the marks) │       │ .git/gitsafe/root   (the trust pin)         │
   │ .env, secrets/…    (ciphertext)│       │ ~/.config/gitsafe/identity  (your private   │
   │                                │       │                              keys — outside │
   │                                │       │                              the repo too)  │
   └───────────────────────────────┘       └───────────────────────────────────────────┘
```

The left column is committed, so the *rules* (who may read), the *marks* (what's a secret), and the *ciphertext* all push and pull automatically. The right column is per-clone and never committed: the filter wiring that makes git call gitsafe, the trust pin that anchors which policy root this clone believes, and — further out still, not even in the repo's `.git` — your private identity. This split is the reason every clone runs `gitsafe init` once: a repository cannot vouch for its own authenticity, so the trust decision has to be made locally, per clone. When you founded the repo you made that decision implicitly by being the author of the root; a teammate cloning later has to make it explicitly, which is the subject of Chapter 5.

---

## Common pitfalls

Two mistakes account for most of the early confusion with gitsafe, and both are easy to avoid once named.

The first is **forgetting to commit `.gitsafe` and `.gitattributes`**. It's a natural slip: you think of the secret as the thing you're committing, so you `git add .env` and move on. But `.env` alone is just an opaque encrypted blob with no accompanying explanation. The `.gitsafe/` directory carries the signed policy — who the members are, who may read what — and `.gitattributes` carries the marks that tell every clone's git to route `.env` through the filter. Without the policy, a teammate's clone has ciphertext and no idea who's allowed to decrypt it; without the marks, their git won't even try to smudge it. Always stage all three together: `git add .gitsafe .gitattributes <secret>`. Build the habit now, while the only person affected is you.

The second is the mirror image, and it bites teammates rather than you: **a fresh clone can't encrypt until it has established trust**. When someone clones a repo that already uses gitsafe, the policy and marks come down with the clone (they're committed), but the filter wiring and the trust pin do *not* (they live in `.git/`, which isn't pushed). So a fresh clone must run `gitsafe init` to wire the filters, and — because it's adopting *someone else's* policy root rather than founding its own — it must then deliberately `gitsafe trust` that root after verifying its fingerprint out of band. gitsafe will refuse to encrypt a new secret until that trust is established, on purpose: without a pinned root, an attacker who could slip a tampered policy into the repo could redirect your next secret's encryption to *their* key. That friction is a feature, and we cover the full clone-and-trust flow in Chapter 5. For now, just know that founding (what you did this chapter) is the frictionless case, and joining is the case that needs the extra trust step.

A small but worthwhile safety net guards against the first pitfall's nastier cousin — committing a marked secret as *plaintext* because the filters weren't active (a clone before `init`, a teammate who skipped setup). The command `gitsafe check` inspects what's staged and fails if any marked file is about to be committed in the clear. Wired as a pre-commit hook, it turns that silent footgun into a hard stop:

```bash
printf '#!/bin/sh\nexec gitsafe check\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Because `.git/hooks/` is per-clone and not committed, each clone installs this for itself (or you point git at a tracked hooks directory for a shared one). It's optional, but it's cheap insurance against the exact mistake that "encrypted files in git" tools are most prone to.

---

## Exercises

Work these in order; they climb from recall to debugging to extension. Each has a full solution and an explanation — but try it yourself before reading on.

### Exercise 1 (recall) — What are the two requirements to build and run gitsafe?

**Problem.** Without scrolling up, state the two software requirements gitsafe has, and say which one applies at build time and which at run time.

**Solution.** Go 1.25 or newer is required to *build* the binary; `git` on your `PATH` is required to *run* it.

**Explanation.** The two requirements sit on opposite ends of the lifecycle, and conflating them is a common source of "but it works on my machine" confusion. Go is only needed where you compile, because gitsafe is distributed as source you build with `make build`; once compiled it's a single static binary with no Go dependency at runtime. git is needed wherever you *use* gitsafe, because gitsafe is an overlay on git — it registers itself as a git filter and shells out to git. A CI runner that only runs a pre-built `gitsafe` therefore needs git but not Go, while your build server needs Go but, strictly, only needs git if it also exercises the tool.

### Exercise 2 (recall) — Which of your two public keys do you send to be granted read access?

**Problem.** A teammate is setting you up as a read-only member of their repo and asks you to "send your key." Which key — `enc` or `sign` — do you send, and why is it safe to send over Slack?

**Solution.** Send the `enc` (age) key, the one starting with `age1`. It is safe to share publicly.

**Explanation.** The `enc` key is your age recipient: it's the key that secrets get *encrypted to*, which is exactly what's needed to make you a reader. It is a public key, so sharing it leaks nothing — knowing it lets someone encrypt *to* you, not decrypt *as* you. The `sign` (ed25519) key is only relevant for administering the policy, which a read-only member never does, so there's no reason to send it for a read grant. The mental rule is "reading needs only `enc`; administering additionally needs `sign`." Getting this wrong is harmless in the send direction but signals a misunderstanding that matters once you start promoting people to admin.

### Exercise 3 (apply) — Generate an identity and print its public keys.

**Problem.** On a machine with no gitsafe identity yet, create one and display both public keys.

**Hint.** Two commands; the second only reads what the first wrote.

**Solution.**

```bash
gitsafe key gen
gitsafe key show
# enc  (age):      age1qz...k7
# sign (ed25519):  3b9a...e1
```

**Explanation.** `key gen` creates the keypair and writes it to `~/.config/gitsafe/identity` (by default), printing the public halves and refusing to overwrite an existing identity so you can't destroy a key others already encrypt to. `key show` is the idempotent read-only sibling: it loads the existing identity and prints only the public keys, which is what you'd run any time you need to copy your `enc` line again. Note that the private keys never appear in either output — only the shareable public halves do. Running `key gen` a second time on this machine would fail by design, which is a feature, not a bug: it protects you from silently replacing the identity your teammates' secrets are encrypted to.

### Exercise 4 (apply) — Bootstrap gitsafe in a brand-new repository as admin "dana".

**Problem.** Inside an empty git repository, turn gitsafe on and become its founding admin under the name `dana`.

**Solution.**

```bash
git init demo && cd demo
gitsafe init --user dana
```

**Explanation.** `git init demo` creates the repo (skip it if you're already in one); `gitsafe init --user dana` does the five-part setup — ensures an identity, wires the `gitsafe` filter and records `gitsafe.user=dana` in `.git/config`, writes the default marks to `.gitattributes`, bootstraps signed policy v0 with `dana` as admin, and auto-pins the root because `dana` *is* the root. The `--user dana` is more than cosmetic here: because `dana` will sign policy changes, the name must match the keyring entry those signatures are checked against. Founding a repo is the one case where no separate `gitsafe trust` is needed, since the founder is the trust anchor. After this, the repo is ready to accept its first encrypted secret.

### Exercise 5 (apply) — Prove a committed `.env` is ciphertext in git but plaintext on disk.

**Problem.** In a gitsafe-enabled repo, commit a `.env` and demonstrate the encrypt-in/decrypt-out behavior with two commands.

**Solution.**

```bash
echo "API_TOKEN=sk_test_42" > .env
git add .gitsafe .gitattributes .env
git commit -m "add .env"

git cat-file blob HEAD:.env   # binary, begins with \x00gitsafe\x00
cat .env                      # API_TOKEN=sk_test_42
```

**Explanation.** Staging `.env` ran it through the clean filter, which encrypted it to the branch's readers (just you) and stored the resulting envelope as the blob. `git cat-file blob HEAD:.env` dumps that *raw stored blob* without re-running smudge, so you see the ciphertext and its `\x00gitsafe\x00` magic prefix. Plain `cat .env` shows your untouched working-tree plaintext, because encryption happens only on the boundary into git, never to the file on disk. The contrast between the two commands is the entire value proposition made visible: git holds ciphertext, you hold plaintext. Staging all three of `.gitsafe`, `.gitattributes`, and `.env` keeps the policy and marks traveling with the secret.

### Exercise 6 (debug) — A secret shows as modified on every `git status`. Why?

**Problem.** A colleague complains that `git status` always lists their `.env` as modified, even when they haven't touched it. What's wrong, and how do you fix it?

**Hint.** Think about which part of the boundary state is per-clone.

**Solution.** The `gitsafe` filter isn't configured in that clone. Run `gitsafe init` (and, if it's someone else's repo, `gitsafe trust`).

**Explanation.** age encryption is randomized, so without help, re-cleaning an unchanged file would produce different ciphertext each time and git would forever see a change. gitsafe prevents this by recognizing an unchanged secret with an unchanged reader set and re-emitting the *existing* stored ciphertext byte-for-byte — but that deterministic re-staging only happens when the filter is actually wired into the clone. The filter wiring lives in `.git/config`, which is per-clone and not committed, so a clone that never ran `gitsafe init` has no filter and falls back to treating the blob as opaque, hence the perpetual "modified." Running `gitsafe init` installs the filter and the churn stops. This symptom is, in fact, the canonical signal that a clone hasn't been set up.

### Exercise 7 (debug) — A teammate's `.env` checks out as a locked placeholder. Name two possible causes.

**Problem.** Bob cloned the repo, ran `init` and `trust`, and on checkout his `.env` is a locked placeholder rather than the secret. Give two distinct reasons this can happen.

**Solution.** Either Bob was never granted read on this branch (so smudge has no key that can decrypt the blob), or he *was* granted but an admin didn't `gitsafe rotate` and commit, so the stored ciphertext was never re-encrypted to include Bob's key. A passphrase-protected identity with no `GITSAFE_PASSPHRASE` in the environment is a third possibility.

**Explanation.** Smudge decrypts using only Bob's private key against the stored ciphertext; if Bob's `enc` key isn't among the recipients that blob was encrypted to, decryption can't succeed and smudge writes the placeholder rather than failing the checkout. There are two ways Bob ends up not being a recipient: the policy never granted him read (a missing grant), or the policy granted him but the *existing blobs* were never re-encrypted to him (a missing rotate — granting changes who's *allowed*, rotating changes what the ciphertext is *encrypted to*). The third cause is mechanical: if Bob's identity is passphrase-locked and the filter environment has no `GITSAFE_PASSPHRASE`, the filter can't open his key at all, so even a correctly-granted Bob gets placeholders until the passphrase is available. Distinguishing these is the everyday diagnostic work of running gitsafe in a team, and `gitsafe access <branch>` plus `gitsafe policy show` are the tools that tell you which one you're in.

### Exercise 8 (create) — Set up a passphrase-protected identity in a non-default location.

**Problem.** Create a *new*, passphrase-encrypted identity at the path `./alt-id` without touching your real `~/.config/gitsafe/identity`, then print its public keys.

**Hint.** `GITSAFE_IDENTITY` overrides the path; it can be set per-command.

**Solution.**

```bash
GITSAFE_IDENTITY=./alt-id gitsafe key gen --passphrase
# (prompts for a passphrase twice)
GITSAFE_IDENTITY=./alt-id gitsafe key show
# enc  (age):      age1...
# sign (ed25519):  ...
```

**Explanation.** Setting `GITSAFE_IDENTITY=./alt-id` as a per-command environment variable redirects gitsafe's identity resolution to that explicit path, which sits first in the resolution order ahead of `XDG_CONFIG_HOME` and the `~/.config` default — so your real identity is untouched. `--passphrase` makes `key gen` prompt for a passphrase and encrypt the file at rest using age's scrypt mode, so the bytes on disk are opaque without the passphrase. `key show` then reads it back; note that *because the file is encrypted*, gitsafe needs the passphrase to load it, which it'll prompt for interactively on the terminal (the git filters, lacking a terminal, would instead need `GITSAFE_PASSPHRASE`). This pattern — an explicit identity path plus a passphrase — is exactly how you'd mint a portable identity for CI without disturbing your personal one.

### Exercise 9 (extend) — Install a pre-commit hook that blocks plaintext secret commits.

**Problem.** Add a hook to a gitsafe repo so that committing a marked secret as plaintext is impossible, and explain when it would actually fire.

**Solution.**

```bash
printf '#!/bin/sh\nexec gitsafe check\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Explanation.** `gitsafe check` inspects the staged tree and exits non-zero if any path marked for the `gitsafe` filter is staged as plaintext rather than as a gitsafe envelope; running it as a pre-commit hook makes git abort the commit in that case. It fires precisely when the filters weren't active at staging time — a fresh clone before `gitsafe init`, an unpinned clone that refused to encrypt, or a misconfigured CI runner — which are exactly the situations where a real secret could otherwise slip into history in the clear. Because `.git/hooks/` is local to each clone and never committed, every clone must install this itself; for a shared, version-controlled hook you'd instead set `core.hooksPath` to a tracked directory and commit the hook there. It's belt-and-braces: the `required = true` on the filter already aborts on filter *failure*, but `check` additionally catches the case where there's no filter at all.

### Exercise 10 (extend) — Without committing, inspect what `init` wrote to `.gitattributes`.

**Problem.** After running `gitsafe init` in a fresh repo, look at the marks block it created and identify the guard line and what it protects.

**Solution.**

```bash
git init demo2 && cd demo2
gitsafe init --user eve
cat .gitattributes
# # gitsafe: encrypt marked secrets
# .env filter=gitsafe merge=gitsafe
# .env.* filter=gitsafe merge=gitsafe
# *.pem filter=gitsafe merge=gitsafe
# *.key filter=gitsafe merge=gitsafe
# secrets/** filter=gitsafe merge=gitsafe
# .gitsafe/** -filter
```

**Explanation.** `init` appends a default marks block declaring which paths get the `gitsafe` filter — dotenv files, PEM and key files, and everything under `secrets/` — which covers the common secret shapes without per-file fiddling. The last line, `.gitsafe/** -filter`, is the guard: it *removes* any filter from the policy directory, ensuring the signed policy files themselves are never encrypted. That matters because the policy must stay plaintext-readable — it's how a fresh clone learns who the members are before it can decrypt anything, so encrypting it would create a chicken-and-egg deadlock. Because `.gitattributes` is committed, this set of marks (and any you add) travels to every clone, keeping "what counts as a secret" consistent across the team. The exact ordering and any prior contents of your `.gitattributes` may differ, but the marks and the guard line are what `init` contributes.

---

## Mini projects

These three projects each build something end to end against a throwaway repository. Delete the directories afterward. Run them in order; each reinforces a different facet of the model.

### Mini Project 1 — Encrypt a whole `secrets/` directory

**Description.** The default marks include `secrets/**`, meaning *every* file under a `secrets/` directory is treated as a secret. You'll create several files there, commit them in one go, and confirm each is independently encrypted in git.

**Concepts practiced.** Default marks and glob patterns; the clean filter operating per-file; verifying ciphertext with `git cat-file`.

**Requirements.** gitsafe installed; an identity (`gitsafe key gen` done once). A scratch directory you can delete.

**Walkthrough.**
1. Create and enter a fresh repo, then bootstrap gitsafe as admin.
2. Create a `secrets/` directory with two different secret files in it.
3. Stage the policy, the marks, and the whole `secrets/` directory, and commit.
4. Confirm both files are ciphertext in git but plaintext on disk.

**Worked solution.**

```bash
cd /tmp && rm -rf mp1 && git init mp1 && cd mp1
gitsafe init --user alice

mkdir secrets
echo "PGPASSWORD=topsecret"        > secrets/db.env
echo "-----BEGIN KEY-----xyz"      > secrets/service.key

git add .gitsafe .gitattributes secrets/
git commit -m "add encrypted secrets directory"

# Each file is independently encrypted in git:
git cat-file blob HEAD:secrets/db.env       # \x00gitsafe\x00 + ciphertext
git cat-file blob HEAD:secrets/service.key  # \x00gitsafe\x00 + ciphertext

# But both are plaintext in your working tree:
cat secrets/db.env       # PGPASSWORD=topsecret
cat secrets/service.key  # -----BEGIN KEY-----xyz
```

**Explanation.** The `secrets/**` default mark uses a `**` glob, which matches across path segments, so anything you drop anywhere under `secrets/` is automatically routed through the clean filter — you didn't have to mark `db.env` or `service.key` individually. The clean filter runs *per file*, encrypting each one separately to the branch's readers, which is why each blob carries its own `\x00gitsafe\x00` envelope rather than the directory being bundled. `service.key` would also have matched the `*.key` mark on its own, illustrating that overlapping patterns are fine. As always, staging `.gitsafe` and `.gitattributes` alongside the secrets keeps the policy and marks traveling with the encrypted content. This project shows that "encrypt a directory of secrets" needs no special command — it's just the default marks doing their job over a glob.

### Mini Project 2 — Prove ciphertext-in-git, plaintext-in-tree rigorously

**Description.** Exercise 5 showed the contrast with two commands. Here you'll make it airtight: show the magic prefix explicitly, show that a *second* `git status` after re-touching the file stays clean (deterministic re-staging), and confirm a re-checkout round-trips the plaintext.

**Concepts practiced.** The gitsafe envelope magic; deterministic re-staging (no spurious diffs); the smudge round-trip on checkout.

**Requirements.** gitsafe installed and an identity; a scratch repo.

**Walkthrough.**
1. Bootstrap a repo and commit a `.env`.
2. Dump the stored blob and observe the `\x00gitsafe\x00` magic at the start.
3. Re-run `git status` to confirm the unchanged secret is *not* flagged modified.
4. Delete and re-checkout the file to confirm smudge restores the plaintext.

**Worked solution.**

```bash
cd /tmp && rm -rf mp2 && git init mp2 && cd mp2
gitsafe init --user alice
echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env && git commit -m "add .env"

# 2. The stored blob begins with the gitsafe magic (shown as octal bytes):
git cat-file blob HEAD:.env | od -c | head -1
# 0000000  \0   g   i   t   s   a   f   e  \0  ...

# 3. Nothing has changed in the working tree, so status is clean
#    despite age being randomized — deterministic re-staging at work:
git status --short
# (no output)

# 4. Smudge round-trips on checkout:
rm .env
git checkout -- .env
cat .env
# DB_PASSWORD=hunter2
```

**Explanation.** Piping the raw blob through `od -c` renders the leading bytes, making the `\0 g i t s a f e \0` magic visible — this is the marker every part of gitsafe uses to recognize its own envelopes, and seeing it confirms the blob really is encrypted, not merely truncated text. The empty `git status --short` is the proof of deterministic re-staging: even though age would produce fresh random ciphertext on each encryption, the clean filter recognized the unchanged plaintext and unchanged reader set and re-emitted the identical stored blob, so git sees no diff. Step 4 demonstrates the smudge half of the boundary: deleting the working file and checking it out forces git to materialize the blob through `gitsafe smudge`, which decrypts (because you're a recipient) and restores the exact plaintext. Together these steps verify both directions of the filter and the no-churn property that makes the tool usable. If step 3 had shown `.env` as modified, that would have told you the filter wasn't configured — a useful negative signal.

### Mini Project 3 — A passphrase-protected identity, used through git

**Description.** Stand up a passphrase-encrypted identity in a throwaway location, wire it into a repo, and exercise the `GITSAFE_PASSPHRASE` path so that git's filters can decrypt without a terminal prompt.

**Concepts practiced.** `key gen --passphrase` / `key lock`; the `GITSAFE_IDENTITY` and `GITSAFE_PASSPHRASE` environment variables; why filters need the passphrase in the environment.

**Requirements.** gitsafe installed. A scratch directory. You'll set environment variables for the session.

**Walkthrough.**
1. Mint a passphrase-protected identity at an explicit path with `GITSAFE_IDENTITY`.
2. Export both `GITSAFE_IDENTITY` and `GITSAFE_PASSPHRASE` so git's filters can find the key and unlock it.
3. Bootstrap a repo using that identity, commit a secret, and verify the encrypt/decrypt round-trip works under the locked key.

**Worked solution.**

```bash
cd /tmp && rm -rf mp3 && mkdir mp3 && cd mp3

# 1. New identity, encrypted at rest, at an explicit path.
#    (prompts for a passphrase twice)
GITSAFE_IDENTITY=./id gitsafe key gen --passphrase

# 2. Make the identity AND its passphrase available to git's filters,
#    which have no terminal and so cannot prompt.
export GITSAFE_IDENTITY="$PWD/id"
export GITSAFE_PASSPHRASE='correct horse battery staple'

# 3. Use it like any identity. The filters now unlock the key from the env.
git init repo && cd repo
gitsafe init --user alice
echo "DB_PASSWORD=hunter2" > .env
git add .gitsafe .gitattributes .env && git commit -m "add .env (locked key)"

git cat-file blob HEAD:.env   # ciphertext, as always
cat .env                      # DB_PASSWORD=hunter2 — smudge unlocked the key via the env

# Tear-down: clear the secrets from your shell.
unset GITSAFE_PASSPHRASE GITSAFE_IDENTITY
```

**Explanation.** Step 1's `--passphrase` encrypts the identity file at rest with age's scrypt mode, so the bytes at `./id` are opaque without the passphrase — protection against a stolen disk, not against a stolen repo (the key was never in the repo anyway). Step 2 is the crux of the project: the `clean` and `smudge` filters that git invokes during `git add` and the implicit smudge on commit run with **no terminal**, so they cannot prompt for a passphrase; the only way they can unlock a passphrase-protected key is to read `GITSAFE_PASSPHRASE` from their environment, and `GITSAFE_IDENTITY` from the environment to find the right file. Because we `export`ed both, the filters inherit them and the whole round-trip works exactly as it would with a plaintext key — `git cat-file` shows ciphertext, `cat` shows plaintext. Had we set the passphrase only interactively (or not at all), the commit's clean step and any checkout's smudge would have failed to unlock the key and you'd see placeholders instead of plaintext, which is the benign-but-confusing degradation the User Guide warns about. The tear-down `unset` clears the passphrase from your shell so it doesn't linger; in real use you'd source it from a keychain helper rather than typing it inline. This project is the template for any environment where a human can't be at the keyboard to type a passphrase — most importantly, CI runners.

---

## Summary

You started this chapter with nothing and finished it with a working encrypted secret: you built and installed the binary, created a private identity that lives safely *outside* any repository, learned why that identity carries two public keys (the `enc` recipient key everyone shares to be a reader, and the `sign` key only admins need), and saw how to protect that identity at rest with a passphrase and the `GITSAFE_PASSPHRASE` environment variable that lets git's terminal-less filters unlock it. You turned gitsafe on for a repo with a single `gitsafe init --user alice`, watching it wire the git filters, write the default marks, bootstrap a signed policy with you as admin, and auto-pin your own root because you were the founder. And you proved the payoff: a `.env` that git stores as ciphertext while your working tree shows the real password, produced by the clean filter on the way in and the smudge filter on the way out, with deterministic re-staging keeping your `git status` quiet.

What you have *not* yet examined is the part doing the deciding. Every encryption in this chapter resolved to the same trivial answer — "the only reader is you" — because you were a solo founding admin. The interesting questions begin the moment there's more than one person: who is allowed to read which branch, how that's expressed as grants and verbs, how the recipient set for a secret is computed from the policy, and why a higher verb like `admin` automatically satisfies `read`. That is the **access model**, and it's the subject of Chapter 3. There you'll learn to read and reason about the signed policy — members, grants, resources, and the verb hierarchy `admin > force > write > read` — so that when you later onboard a teammate or scope a branch to an on-call group, you'll know exactly who ends up able to decrypt what, and why.
