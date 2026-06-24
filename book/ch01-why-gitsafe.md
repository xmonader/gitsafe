# Chapter 1 — Why gitsafe? The problem with secrets in git

Every project you have ever worked on had secrets. A database password. An API
token for the payment provider. A signing key, a webhook secret, the connection
string that ties your service to the outside world. These values are small —
often a single line in a `.env` file — but they are the keys to the kingdom.
Lose control of one and the blast radius is enormous: someone reads your
customers' data, drains an account, or impersonates your service. And yet, almost
every team struggles with the most basic question about these values: *where do
they live, and who can see them?*

You would think this is a solved problem. It is not. The dirty truth is that most
teams handle secrets with a mix of folklore, copy-paste, and quiet anxiety.
Someone pastes the production password into a chat message "just this once."
Someone else keeps a personal `.env` they share by email when a new hire joins.
A staging credential ends up committed to git "temporarily," and three years
later it is still sitting in the history of a public mirror. Nobody set out to be
careless. The tools simply made the safe path harder than the dangerous one, so
the dangerous one won.

This chapter is about that gap — the space between *we know secrets are
sensitive* and *we have no convenient way to keep them both safe and usable*. We
will look at why secrets keep ending up in git, why that is genuinely dangerous
(not just a checkbox on a compliance form), and the two unhappy paths most teams
take to cope. Then we will introduce the mental model behind **gitsafe**, the
tool this book teaches: a way to commit your secrets straight into your repo,
encrypted to exactly the people who are allowed to read that branch — one access
list, no server, no vault. By the end you will understand *why* gitsafe is shaped
the way it is, which makes every command in the chapters that follow feel
obvious instead of arbitrary. We will write almost no commands here. This chapter
builds the map; the rest of the book walks the territory.

---

## Why secrets end up in git in the first place

Let us start with empathy, not blame. Secrets end up in git because git is where
your configuration lives, and secrets *are* configuration. Your application needs
a database URL to start. That URL belongs next to the code that reads it. So a
developer creates a `.env`, the app reads it, everything works, and the natural
next instinct — the same instinct that put every other file under version
control — is to commit it. It is *right there*. It is part of how the app runs.
Committing it makes the project reproducible: clone, run, done.

The convenience is real and it is worth naming clearly, because the whole point
of gitsafe is to keep that convenience while removing the danger. When the secret
lives with the code, a new teammate clones the repo and the project just *works*.
There is no out-of-band ritual, no "ask Sarah for the staging key," no wiki page
that went stale six months ago. The single source of truth is the repository.
That is a genuinely good property. The problem is not the desire to keep secrets
in git — the problem is keeping them there *in plaintext*.

Think of git as a filing cabinet that everyone with a clone carries a perfect
photocopy of. When you commit a plaintext password, you are not putting it in a
locked drawer. You are stapling it to every photocopy that has ever been made and
every one that will be made in the future. That is the mismatch we have to fix:
the instinct to co-locate secrets with code is sound, but the default storage
format — readable text, copied everywhere — is catastrophic.

---

## Why plaintext-in-git is genuinely dangerous

It is tempting to treat "don't commit secrets" as a style rule, like "don't use
tabs." It is not. There are three concrete, mechanical reasons plaintext in git
is dangerous, and understanding them precisely is what makes the rest of this
book click.

### Reason 1: git history is forever

The first thing to internalize is that git does not really "delete." When you
remove a secret from a file and commit the removal, the old value does not
vanish — it moves into history. Every commit is a snapshot, and the snapshot that
contained your password is still sitting in the object database, reachable by its
hash, copied into every clone. Deleting the line in the latest commit is like
crossing out a word with a pen: the word is still there, you just drew a line
next to it.

Here is the shape of the problem, drawn as a timeline of commits:

```
   commit A          commit B          commit C          commit D (HEAD)
   add .env  ─────►  fix typo  ─────►  "remove   ─────►  unrelated
   DB_PASS=          in app.js         secret"           feature
   hunter2                             .env deleted
      │                                    │
      │  the password is STILL here ───────┘
      ▼  (and in every clone, and every fork, forever)
   anyone who runs `git log -p` or `git cat-file` on commit A reads hunter2
```

Read that diagram slowly, because it overturns a very common false belief. The
developer at commit C *thinks* they removed the secret — the file is gone from
the working tree, `cat .env` fails, the PR looks clean. But the value is
permanently recorded at commit A. Anyone who can check out the repository can run
a single command to walk back through history and read it. "Removing" a committed
secret without rewriting history is theater. The only honest responses are to
rewrite every clone's history (painful, often impossible once it is pushed and
forked) or to treat the secret as compromised and change its *value*. Hold onto
that last idea — it returns at the end of this chapter as gitsafe's one big
caveat, and it is not a weakness unique to gitsafe; it is a property of git
itself.

### Reason 2: a clone is a full copy

The second danger is that git is, by design, distributed. There is no central
server that "holds" the repository while everyone else gets a thin window into
it. When someone clones, they receive the *entire* object database — every
commit, every branch, every blob, all of history. That is git's great strength
for collaboration and resilience, and it is exactly what makes a plaintext secret
unrecoverable once it spreads.

Picture the difference between a library and a chain letter:

```
   A SERVER-CENTRIC SECRET STORE          GIT (DISTRIBUTED)

        ┌───────────┐                     dev-laptop-1 ─── full copy
        │  vault /  │                     dev-laptop-2 ─── full copy
        │  server   │  ◄── one place      CI runner    ─── full copy
        └───────────┘      to revoke      ex-employee  ─── full copy (kept!)
              ▲                            a fork on    ─── full copy
       clients hold                         the public
       only a handle                        internet   ─── full copy
                                                 │
                                    revoke "access"? there is no
                                    central place — the data already
                                    left the building, N times over
```

The left side is the model people unconsciously assume they have: a single
authoritative copy where access can be switched off. The right side is what git
actually is. Once a plaintext secret is committed and pushed, it has been copied
to every laptop, every CI cache, every fork, and possibly a public mirror — and
you cannot reach into those copies to claw it back. This is why "we'll just force
a new clone for everyone" does not contain a leak. The data is already out. The
distributed nature you love for code review and offline work is the same property
that turns one careless commit into a permanent, multiplied exposure.

### Reason 3: `.gitignore` is not security

The third danger is the most insidious because it *feels* like a solution. Teams
add `.env` to `.gitignore` and consider the matter closed. But `.gitignore` does
not encrypt anything, does not lock anything, and does not protect anything. All
it does is tell git "don't *suggest* adding this file." It is a politeness
setting, not a security boundary.

The proof is how easily it is defeated, usually by accident. A teammate runs
`git add -f .env` to force-add it. Or the file was committed *before* the ignore
rule existed, so it is already tracked and `.gitignore` is ignored for it
entirely. Or someone renames the file, or adds it from a subdirectory, or a build
script copies it somewhere the pattern does not match. Each of these is a normal,
innocent action, and each one slips a plaintext secret past your "protection."
The mental trap is treating absence-from-the-repo as a guarantee when it is only
a default. A real boundary fails *closed* — when something goes wrong, the secret
stays protected. `.gitignore` fails *open*: the moment the convention is broken,
the secret is exposed with no warning. Security that depends on everyone always
remembering to do the right thing is not security; it is a hope.

---

## The two unhappy paths (and the third one)

Faced with those dangers, teams generally back into one of two coping strategies.
Both are reasonable. Both are unhappy. Understanding *why* they are unhappy is the
clearest way to see what gitsafe is for, because gitsafe is deliberately designed
to be the third path that avoids both sets of problems.

### Unhappy path one: take secrets out of git

The first strategy is to banish secrets from the repository entirely. Put them in
a secrets manager, a vault, a cloud parameter store, a shared password manager, a
pinned chat message — anywhere but git. This is the advice you will hear most
often, and it solves the plaintext-in-history problem cleanly: if the secret was
never committed, it can never leak through history.

But it creates two new problems that are easy to underestimate. The first is
**drift**. The moment your secrets live somewhere other than the code that uses
them, the two can fall out of sync. The app expects a `STRIPE_KEY` the vault no
longer has, or has under a different name, or with a stale value. A fresh clone no
longer "just works" — it works only after a separate, manual, error-prone ritual
of fetching the right secrets from the right place and putting them in the right
shape. The single source of truth has split in two, and the two halves wander
apart.

The second new problem is **a second access list**. Now you have to decide who
can see the secrets *in the vault*, and you maintain that list separately from
who can see the *code in git*. These two lists are supposed to track each other —
the people who work on `staging` should be the people who can read `staging`'s
secrets — but nothing keeps them aligned. Here is the drift, drawn out:

```
   WHO CAN PUSH/READ THE REPO          WHO CAN READ SECRETS (the vault)
   ──────────────────────────          ────────────────────────────────
   alice   (still here)                alice
   bob     (still here)                bob
   carol   (LEFT 6 months ago) ──X     carol   ◄── nobody removed her here
   dave    (joined last week)          ??????  ◄── nobody added him here
                                        ex-contractor ◄── who is this even?

   two lists, two owners, two update rituals → they ALWAYS diverge over time
```

Every offboarding now requires remembering to update *two* systems. Every
onboarding, the same. In practice one of the two always lags, and the gap between
them *is* your security problem: people who left still have vault access, people
who joined cannot get the credentials they need and so get them passed around
insecurely. You traded one risk for a maintenance burden that quietly recreates
the risk.

### Unhappy path two: keep secrets in git as plaintext

The second strategy is to give up on the previous section and just commit the
plaintext, accepting the convenience and hoping for the best. We have already
dissected why this is dangerous — history is forever, clones are full copies,
`.gitignore` is not security. The team that takes this path usually does so not by
decision but by erosion: the "temporary" committed secret that never got cleaned
up, the `.env.example` that slowly accumulated real values. It is the path of
least resistance, and it ends in a leak. There is nothing more to say about it
except that it is the failure mode gitsafe exists to make unnecessary.

### The third path: encrypted-in-git, one list

gitsafe offers a third path that refuses the trade-off. Keep the secret in git —
so there is no drift and a clone still just works — but store it **encrypted**,
readable only by the people who are allowed to read that branch. The repository
stays the single source of truth, *and* the secret is never plaintext in history,
*and* there is only one access list because the list of branch-readers is reused
as the list of decryptors.

```
   PATH 1: secrets OUT of git     → no leak, but DRIFT + a SECOND list
   PATH 2: PLAINTEXT in git       → no drift/second list, but it LEAKS
   PATH 3: gitsafe                → encrypted in git:
                                      • single source of truth (in the repo)
                                      • no plaintext in history → no leak
                                      • ONE list: branch-readers = decryptors
```

The rest of this chapter unpacks how that third path actually works — the
mechanism that lets the right people type `cat .env` and see a password while
everyone else, looking at the very same committed bytes, sees ciphertext.

---

## The core mental model: marked files, encrypted on the way in

Here is the central trick, and once it clicks, gitsafe stops being magic. The
secret is plaintext in your working directory — the file you edit and your app
reads — but it is encrypted the instant it crosses into git, and decrypted the
instant it comes back out. Git only ever *stores* ciphertext. You only ever *see*
plaintext. The conversion happens automatically at the boundary.

Git has a built-in feature designed for exactly this kind of transformation,
called **clean/smudge filters**. A filter is a pair of programs git runs at the
boundary between your working tree and its object store. The `clean` filter runs
when a file goes *in* (on `git add`); the `smudge` filter runs when a file comes
*out* (on checkout). gitsafe registers itself as one of these filters, so
`gitsafe clean` does the encrypting and `gitsafe smudge` does the decrypting.
Crucially, this is stock git — there is no daemon, no wrapper around git, no
server. git itself invokes gitsafe at the right moments because you told it to.

```
   YOUR WORKING TREE                          WHAT GIT STORES
   ────────────────                           ───────────────
   .env                                       blob (committed object)
   DB_PASSWORD=hunter2                         \x00gitsafe\x00 <binary ciphertext>

        │   git add  ──►  [ gitsafe clean ]  ──► encrypt  ──►  stored as ciphertext
        ▲
        └── checkout ◄──  [ gitsafe smudge ] ◄── decrypt  ◄──  read from ciphertext
```

Study the two arrows, because they explain every "how does it know?" question you
will have. Going down (the `add` direction), gitsafe encrypts: the plaintext
`hunter2` never reaches the object database; what gets committed is the encrypted
blob with a small `\x00gitsafe\x00` marker so the tool can recognize its own
work. Going up (the `checkout` direction), gitsafe decrypts — but only if *your*
key can open the envelope. The working tree and the stored blob are two different
representations of the same file, and the filter is the translator between them.

Now, which files get this treatment? Not all of them — you do not want gitsafe
encrypting your source code. You **mark** the files you want protected, using
git's standard `.gitattributes` mechanism, which is just a list of path patterns
and the filters that apply to them. A file marked for gitsafe goes through the
clean/smudge filters; an unmarked file is plain old git. The marks are committed
along with the policy, so the definition of "which files are secret" travels with
the repository — a new clone knows what to protect without anyone configuring it
by hand.

### Recipients are derived from who can read the branch

We have explained *how* a file is encrypted but not the most important part:
encrypted *to whom?* This is where gitsafe makes its defining choice, the one that
collapses two access lists into one. When `gitsafe clean` encrypts a secret, it
does not consult a separate recipients file. It asks the repository's **policy**
a single question: *who is allowed to read the current branch?* — and encrypts the
secret to exactly those people's keys.

The policy is a signed, versioned document committed inside the repo. It holds two
things: a keyring of members (each member's public keys) and a list of grants
that say who may do what on which branch. One of the verbs a grant can confer is
`read`, and **`read` is precisely what determines decryption recipients**. There
is no second concept of "secret reader" separate from "branch reader." They are
the same thing by construction.

```
   THE POLICY (signed, committed in .gitsafe/policy/)
   ─────────────────────────────────────────────────
   members:  alice → (pubkeys)
             bob   → (pubkeys)
             carol → (pubkeys)

   grants:   alice  read  refs/heads/main
             alice  read  refs/heads/staging
             bob    read  refs/heads/staging
             carol  read  refs/heads/main

   ── on branch `staging`, gitsafe encrypts secrets to: { alice, bob }
   ── on branch `main`,    gitsafe encrypts secrets to: { alice, carol }
```

Trace what this buys you. To give bob access to `staging`'s secrets, you grant
bob `read` on `staging` — the very same action that says "bob is allowed to read
this branch." You never touch a second list, because there is no second list. The
people who can read the branch *are* the people who can decrypt its secrets, not
by policy or process, but mechanically, every single time a secret is encrypted.
The drift problem from unhappy-path-one cannot occur here, because the two lists
that drift apart have been fused into one.

### What everyone else sees

The flip side of "the right people just `cat` the file" is what happens to
everyone else. Someone without `read` on the branch — a passerby, a teammate on a
different team, a former member — has the repository, sees the same committed
blob, and runs the same `cat`. They do not get an error and they do not get the
password. The `smudge` filter tries to decrypt with their key, fails because they
are not a recipient, and shows them a harmless **locked placeholder** instead of
the secret. If they look at the raw stored blob directly, they see age ciphertext
they cannot open. The secret's *contents* are confidential to exactly the
recipient set; everything else about the file — that it exists, its name, its
size — is visible, and that is a deliberate and acknowledged trade-off we will
return to in the threat-model section.

---

## How this compares to git-crypt and SOPS

gitsafe is not the first tool to encrypt files in git. The two best-known
predecessors are **git-crypt** and **SOPS**, and the fastest way to understand
gitsafe's design is to see exactly where it diverges from them. The divergence is
not a small feature difference — it is the whole point.

git-crypt encrypts marked files with a single shared symmetric key. Everyone who
is supposed to read the secrets has a copy of that one key (or has their GPG key
authorized to unwrap it). This works, but it has two awkward properties. First,
access is all-or-nothing: holding the key lets you read *every* secret in the
repo, so you cannot easily say "bob may read staging but not production." Second,
removing someone is genuinely hard — they had *the* key, so once they leave, the
correct response is to generate a new key and re-encrypt everything, and there is
no built-in, verifiable record of who was ever supposed to have access.

SOPS takes a different shape: it encrypts each file to a list of recipients (KMS
keys, age keys, PGP keys) that you write into the file or a config. This gives you
per-file, per-recipient control, which is more flexible than git-crypt's single
key. But notice what you now maintain: a **recipients list**, by hand, separate
from anything git knows about who works on the project. That is unhappy-path-one's
"second list" creeping back in — now you keep "who can push to staging" in your
git host and "who can decrypt staging's secrets" in a SOPS config, and you must
keep them aligned yourself.

gitsafe's twist is to make the recipient list *derived* rather than *maintained*,
and to make the source of that derivation a **signed, verifiable file in the repo
itself**:

```
                 WHO IS A DECRYPTOR?              WHERE IS THE ACCESS LIST?
   ───────────   ──────────────────────────      ──────────────────────────
   git-crypt     anyone holding THE shared key    not really a list (one key)
   SOPS          a hand-maintained recipients     a config you edit by hand,
                 list per file/config             separate from repo access
   gitsafe       whoever can READ the branch      a signed policy IN the repo,
                 (one list, reused)               verifiable offline, no server
```

Two things in the bottom row deserve emphasis. First, **branch-readers ==
decryptors**: the allow-list is not a thing you maintain alongside access control,
it *is* your access control. Second, the list lives as a **signed file in the
repo, verifiable offline**. There is no server to call, no vault to be up, no
network round-trip to decide who can read. The policy is committed like any other
file, signed with ed25519 keys, and chained so each version names the hash of the
one before it. Anyone with a clone can verify the whole chain on an airplane with
the wifi off. gitsafe writes *no custom cryptography* to do this — it composes
[age](https://age-encryption.org) for the encryption and ed25519 signatures for
the policy's integrity, both well-studied primitives.

And because the policy is signed and chained, it cannot be quietly forged by
whoever can push to the repo. We will treat the trust model properly in a later
chapter, but the headline is that gitsafe assumes the repository's *contents* are
untrusted — anyone who can open a PR could try to tamper with the policy — and
defends against that by pinning the policy's root key locally in each clone the
first time you trust it. A later change to that root is flagged as a possible
attack. That pin lives in your local `.git/`, the one place gitsafe treats as
trusted, and it is what lets a server-less tool still resist a malicious commit.

---

## A gentle first look at the threat model

It is tempting, when a tool says "encrypts your secrets," to imagine it protects
against everything. It does not, and a good security tool is honest about its
edges. gitsafe ships a written threat model precisely so you can reason about
what you are getting. We will not cover all of it here — that is a later chapter —
but you should leave this one with a correct, if simple, picture of the shape of
the protection.

### What "encrypt secrets in git" protects

The core guarantee is **confidentiality of the file contents** against anyone who
does not hold a decryption key. A passive reader who has your repository and its
entire history — a forked copy, a leaked clone, a curious teammate without
access — sees only age ciphertext. They cannot turn it back into your password.
The `smudge` filter shows them a locked placeholder, and they cannot smuggle a
plaintext back into the repo either, because the `clean` filter detects the
attempt and preserves the stored ciphertext. So the primary thing you buy is: *a
clone is no longer a leak.* The distributed-copy danger from earlier in this
chapter — the property that made plaintext-in-git unrecoverable — is exactly what
encryption neutralizes, because now the copies that spread everywhere are
unreadable copies.

It is just as important to be clear about what gitsafe deliberately leaves in the
open. The encryption protects *contents*, not *shape*. The names of your secret
files, their sizes, the set of people a file is encrypted to, and the policy
itself (the members and grants) are all intentionally cleartext. gitsafe hides
the value of the password, not the fact that a password exists. For most teams
that is exactly the right line — you want collaborators and tooling to *see* that
`.env` is a managed secret — but you should know it is the line, and not assume
the metadata is hidden.

### The one big caveat: removing someone does not scrub history

Now the caveat, and we introduce it early and loudly because it is the single most
important thing to understand about *any* "encrypted files in git" tool, gitsafe
included. **Removing someone from the policy does not retroactively lock them out
of history.** Recall reason one from the start of this chapter: git history is
forever, and a clone is a full copy. Those facts do not stop being true just
because the files are encrypted.

Walk through what actually happens when you offboard a former reader. From the
moment you remove them and rotate, every *future* secret is encrypted to a
recipient set that excludes them — they are locked out going forward. But they
were a recipient of the ciphertext that existed *while they had access*, and they
may have kept a clone or packfile containing those blobs. Their key still opens
those old blobs, because cryptographically nothing changed about them — they were
a valid recipient at the time they were written.

```
   timeline ───────────────────────────────────────────────►

   secret encrypted to {alice, bob}          bob REMOVED, secret rotated,
   bob can decrypt these old blobs ──────►    re-encrypted to {alice}
   (and he kept a clone of them)                   │
                                                    └─ bob CANNOT read new blobs
   ▲                                                   but his clone still holds
   │ rotation protects the FUTURE, not the PAST        the old ciphertext he can
   └── the old ciphertext already left with him        still open
```

So what is the correct response to offboarding? The same response as for *any*
credential exposure: **rotate the secret's value itself.** Change the password,
issue a new API key, regenerate the token. gitsafe's `rotate` re-encrypts the
files to the new recipient set, but you must also change *what* is encrypted —
because the old value, in the old ciphertext, in someone's old clone, is
recoverable by whoever held a key when it was written. This is not a flaw gitsafe
could fix with better code; it is a direct consequence of how git distributes
data, and it is true of git-crypt and SOPS just as much. Treat a departure like a
leak: assume the secret that person could read is now known, and replace its
value. Internalize this now and the offboarding chapter later will hold no
surprises.

---

## What you will be able to do by the end of this book

You have just built the mental model. Let us name what that model will let you
*do* once we start typing commands in the chapters ahead, so you can see where
we are going.

By the end of this book you will be able to take any git repository and turn
secrets-in-git from a liability into a feature. You will encrypt your first
`.env` so the repo stores ciphertext while your working copy stays readable, and
you will be able to *prove* it worked by inspecting the stored blob. You will
onboard a teammate in a single step — adding them, granting them read on a branch,
and re-encrypting the secrets to include them — and you will give different
branches different readers, so `staging` and `production` need not share an
audience. You will join a project someone else set up, trusting its policy
correctly the first time by verifying a fingerprint out of band. You will offboard
a leaver and rotate the affected secrets the right way, with the caveat from this
chapter firmly in mind. You will wire gitsafe into CI and into a pre-commit hook
so a missing filter cannot silently let a plaintext secret slip through. And you
will be able to read the signed policy, verify the trust chain offline, and audit
who can read what — answering, finally and definitively, the question we opened
with: *where do our secrets live, and who can see them?*

Most importantly, you will understand *why* each of those workflows is shaped the
way it is, because every one of them falls out of the model you just learned: one
encrypted file in git, one access list derived from branch-readers, one signed
policy verifiable without a server. The commands are the easy part. The mental
model is the chapter you just read.

---

## Exercises

These exercises are conceptual — there is no CLI to run yet. Work through them on
paper or in your head. Each has a worked solution and an explanation; none are
left to the reader.

### Exercise 1 (recall)

**Problem.** Name the three concrete reasons, given in this chapter, that
plaintext secrets in git are dangerous.

**Solution.** (1) Git history is forever — deleting a secret in a later commit
leaves it readable in the earlier commit that introduced it. (2) A clone is a
full copy — every clone, fork, and CI cache receives the entire history, so a
committed secret spreads to copies you cannot reach. (3) `.gitignore` is not
security — it only suppresses a suggestion to add a file and fails open the moment
the convention is broken (`git add -f`, a pre-existing tracked file, a rename).

**Explanation.** These three reasons are not interchangeable; each attacks a
different false belief. The "history is forever" point dismantles the idea that
deletion equals removal, which is the most common misconception developers hold
about git. The "clone is a full copy" point dismantles the assumption that there
is a central authoritative copy you can sanitize, an assumption imported from
server-centric systems. The "`.gitignore` is not security" point dismantles the
belief that absence-by-default is a guarantee. Holding all three at once is what
justifies the entire premise of gitsafe: if any one of them were false, plaintext
might be salvageable, but together they make it permanently dangerous.

### Exercise 2 (recall)

**Problem.** In gitsafe, what determines who can decrypt a branch's secrets?
State it in one sentence.

**Solution.** Whoever is granted `read` on that branch in the signed policy — the
branch's readers are exactly its decryptors, with no separate recipients list.

**Explanation.** This is the single most important fact in the chapter, so it is
worth being able to state crisply. The phrase "branch-readers == decryptors" is
the design's whole identity. It matters because it eliminates the second access
list that plagues both the take-secrets-out-of-git approach and SOPS. When you
can say this in one sentence without hedging, you understand why granting read and
granting decryption are the same action in gitsafe — they are not two operations
the tool keeps in sync; they are one operation by construction.

### Exercise 3 (apply)

**Problem.** A teammate says: "We're safe — I deleted the `.env` with the
production password and committed the deletion, and I also added `.env` to
`.gitignore`." Are the production credentials safe? Explain.

**Hint.** Think about where the value physically lives after a "delete" commit,
and what `.gitignore` actually controls.

**Solution.** No, the credentials are not safe. Committing the deletion removes
the file from the latest snapshot but leaves the password fully readable in the
earlier commit that introduced it; anyone with the repo can recover it with
`git log -p` or `git cat-file`. Adding `.env` to `.gitignore` does nothing about
the already-committed history and only suppresses future accidental adds, which it
does not even do reliably. The correct response is to treat the production
password as compromised and change its value.

**Explanation.** This scenario combines two of the chapter's dangers and shows how
they reinforce each other. The teammate has confused *working-tree state* with
*repository state* — the file is gone from the tree but immortal in history. They
have also confused a politeness setting with a boundary. The deeper lesson is the
one that recurs throughout the book: once a secret has been committed in
plaintext, no amount of subsequent git hygiene un-leaks it, because the data has
already been copied into every clone. The only real fix is rotation of the value,
which is exactly the offboarding rule gitsafe asks you to follow — making this a
preview of the residual-risk reasoning you will apply repeatedly.

### Exercise 4 (apply)

**Problem.** Map the two-unhappy-paths framing onto a team you have worked on (or
imagine one). Which path were they on, and what specific symptom would you expect
to see?

**Hint.** Path one's symptom is drift plus a second list; path two's symptom is a
leak or a near-miss.

**Solution.** A team on path one (secrets out of git, in a vault or password
manager) would show symptoms like: a fresh clone that does not run until you
manually fetch secrets, mismatches between the secret names the app expects and
what the vault holds, and at least one former employee who still has vault access
because the offboarding updated the git host but not the vault. A team on path two
(plaintext in git) would show symptoms like: a real credential sitting in
`.env.example`, a secret committed "temporarily" months ago, or a credential leak
incident already on record.

**Explanation.** The value of this exercise is making the abstract framing
concrete against lived experience, because the two paths are rarely chosen
explicitly — teams drift into them. Recognizing the *symptoms* is what lets you
diagnose which path a team is on before they would admit to either. Path one's
symptoms cluster around *synchronization failure* (two lists, two sources of
truth), while path two's cluster around *exposure* (the secret is readable). Once
you can name the symptom, the gitsafe pitch writes itself: the third path removes
the symptom's root cause rather than treating the symptom, because it keeps a
single source of truth in the repo and a single derived access list.

### Exercise 5 (apply)

**Problem.** Using the policy sketch from the chapter (alice and carol read
`main`; alice and bob read `staging`), to whom is a secret encrypted when
committed on the `staging` branch? On the `main` branch?

**Solution.** On `staging`, the secret is encrypted to alice and bob (the readers
of `staging`). On `main`, it is encrypted to alice and carol (the readers of
`main`). Carol cannot decrypt `staging`'s secrets and bob cannot decrypt `main`'s
secrets, because each was never granted read on the other's branch.

**Explanation.** This exercise drills the mechanical consequence of "recipients =
branch readers." Notice that the *same file path* (`.env`) can have *different
recipient sets* depending on which branch it was committed on, because the policy
is consulted per-branch at encrypt time. That is what makes per-branch access
control possible — something git-crypt's single shared key cannot express. Alice
appears in both sets because she reads both branches, illustrating that
membership is per-grant, not global. Working this out by hand is the clearest way
to feel why gitsafe never needs a separate recipients file: the answer is fully
determined by the grants you already wrote for access control.

### Exercise 6 (create)

**Problem.** Design, on paper, a branch→reader mapping for a small product team
with four branches — `main`, `staging`, `production`, and `feature/*` — and four
people: a lead, a backend dev, a frontend dev, and an external contractor. Decide
who reads what and justify each choice in terms of least privilege.

**Hint.** The contractor should probably not read `production`. The lead probably
reads everything.

**Solution.** A reasonable mapping: the lead reads `main`, `staging`,
`production`, and `feature/*` (full access; they own the project). The backend and
frontend devs read `main`, `staging`, and `feature/*`, but not `production`
(day-to-day work, but production credentials stay restricted). The external
contractor reads only `feature/*` and perhaps `main` (they need to build and test
features but should never see staging or production secrets). No one but the lead
reads `production`, keeping the most sensitive credential set as narrow as
possible.

**Explanation.** This is a design exercise, so there is no single correct answer —
but every defensible answer applies least privilege: each person reads the
fewest branches needed to do their job, and the most sensitive branch
(`production`) has the smallest reader set. The exercise matters because in
gitsafe this mapping *is* your security posture — there is no separate place where
access is configured, so getting the mapping right is the whole game. Notice how
naturally the design expresses things git-crypt cannot: the contractor reads
feature secrets but not production secrets, which requires per-branch recipients.
Justifying each grant in least-privilege terms is exactly the discipline you will
apply when you write real grants in a later chapter; designing it first on paper
keeps you from over-granting in the heat of setup.

### Exercise 7 (debug)

**Problem.** A colleague reports a "bug": "I cloned the repo, ran `cat .env`, and
got a locked placeholder instead of the password — gitsafe is broken." Walk
through the possible non-bug explanations.

**Hint.** Two very different causes produce a placeholder: you are not a
recipient, or the filters never ran.

**Solution.** There are two main innocent explanations. First, the colleague may
simply not be a recipient — they were never granted read on the branch they
checked out, so `smudge` cannot decrypt with their key and correctly shows the
placeholder. This is gitsafe working exactly as designed, not a bug. Second, the
clean/smudge filters may not be active in their fresh clone yet (a clone before
running the per-repo setup, or an unpinned/untrusted policy), so git never invoked
`gitsafe smudge` to attempt decryption at all. The fix differs by cause: in the
first case they need a read grant; in the second they need to complete the
per-clone setup and trust step.

**Explanation.** Debugging here is really about distinguishing "the protection is
doing its job" from "the protection is not wired up." A placeholder is the
*expected* output for a non-recipient — reporting it as a bug reveals a
misunderstanding of the model, which is why the mental model matters before the
commands. The two causes have opposite remedies, which is a recurring theme in
operating gitsafe: many symptoms are ambiguous between "you lack access" and "the
tooling is not engaged," and resolving them means checking *who you are in the
policy* and *whether the filters ran*. Learning to ask those two questions first
will save you most of the troubleshooting time in later chapters.

### Exercise 8 (extend)

**Problem.** gitsafe protects the *contents* of secret files but intentionally
leaves their names, sizes, and the recipient set in cleartext. Propose a situation
where this metadata leakage actually matters, and a non-gitsafe mitigation.

**Hint.** Think about what a file *name* or a *recipient list* reveals even when
you cannot read the file.

**Solution.** Consider a repo where a file named `aws-prod-root-credentials.env`
exists: an attacker who cannot decrypt it still learns that production root AWS
credentials exist and are managed here, which is reconnaissance value and a
tempting target. Or consider the recipient set on a file revealing that only one
person — clearly the lead — can read it, marking that person's key as the highest
-value thing to steal. Mitigations are out-of-band: use non-descriptive file
names, avoid encoding sensitivity into paths, and keep the *most* sensitive
material out of the repo entirely if even its existence must be hidden.

**Explanation.** This exercise pushes past "encryption hides everything," which is
the naive view, into the more mature understanding that encryption hides
*contents* while shape leaks. The threat model calls this out explicitly because
pretending otherwise would be dishonest. The broader lesson is that every security
tool has a defined boundary, and the metadata boundary is gitsafe's — for most
teams it is the right trade (you *want* collaborators to see that a file is a
managed secret), but for a minority of cases the mere existence of a secret is
itself sensitive, and then gitsafe is the wrong layer for that particular secret.
Reasoning about *what a tool deliberately does not protect* is exactly the
skill the threat-model chapter will develop further.

### Exercise 9 (extend)

**Problem.** Argue for or against this statement: "Because gitsafe rotates and
re-encrypts when I remove someone, I don't need to change my actual passwords
after an offboarding."

**Solution.** Argue *against* it — the statement is false. Rotation re-encrypts
*future* secrets to a recipient set that excludes the departed member, but it does
nothing about the ciphertext that already existed while they had access, which
they may retain in a clone or packfile and which their key can still decrypt. The
old *value* is therefore recoverable by them. The only safe response is to change
the secret's value itself (new password, new key) so the value they can recover
is no longer the live one.

**Explanation.** This is the chapter's central caveat restated as a tempting
falsehood, because the falsehood is genuinely seductive — "the tool rotated, so
I'm covered" feels right. It is wrong because rotation operates on *who can read
new ciphertext*, not on *what old ciphertext already left the building*. The git
properties from the start of the chapter (history is forever, clones are full
copies) are the reason: encryption does not change the fact that a former
recipient holds decryptable copies of what they were always allowed to read.
Internalizing this distinction — re-encryption protects the future, value-rotation
addresses the past — is what separates someone who uses gitsafe correctly from
someone who has a false sense of security after every offboarding.

---

## Mini projects (thought projects and audits)

There is no CLI in this chapter, so these projects are *audits* and *paper
exercises*. They build the diagnostic instincts that make the hands-on chapters
go smoothly. Each has a worked solution; nothing is left open.

### Mini project 1 — Audit a repo's history for committed secrets

**Description.** Take a real git repository you have access to and audit its
*history* for secrets that were ever committed in plaintext — not just what is in
the current tree. The goal is to viscerally experience "git history is forever."

**Concepts practiced.** History-is-forever; deletion-is-not-removal; the
difference between working-tree state and repository state.

**Requirements.** A repo you may inspect; familiarity with `git log` and
`git grep` over history. You are *reading* only — make no changes, and if you
find a live secret, treat it as an incident and rotate it.

**Walkthrough.**
1. List every file path that has ever existed in history, not just the current
   tree — secrets are often deleted later, so the current tree hides them.
2. Search the *entire history* (all commits, all branches) for high-signal
   patterns: `password`, `secret`, `api_key`, `BEGIN PRIVATE KEY`, `.env`,
   connection strings.
3. For each hit, find the commit that introduced it and confirm the value is
   readable there even if a later commit deleted the file.
4. Classify each finding: still-live (rotate it now) versus already-dead (record
   it as evidence of the pattern).
5. Write down, for the worst finding, how many clones and forks likely contain it.

**Worked solution.** Suppose your search surfaces `DB_PASSWORD=hunter2` in a
deleted `.env` introduced eight months ago. You confirm it by checking out — or
inspecting the blob of — that old commit and seeing the value plainly, even
though the file is absent from the current tree. You check whether `hunter2` is
still the live database password; if it is, you treat this as a security incident
and rotate the database credential immediately. You then count: the repo has
twelve contributors and one public fork, so at least thirteen full copies of that
plaintext exist beyond your control. Your audit report concludes that history
rewriting is infeasible (the fork is public) and that value-rotation is the only
real remedy — which is precisely the gitsafe offboarding doctrine.

**Explanation.** This project turns an abstract claim into a felt one. Until you
have personally pulled a "deleted" secret out of history, it is easy to believe
deletion works; after you have done it once, you never trust a delete-commit
again. The classification step (live vs. dead) trains the incident-response
reflex you will need whenever gitsafe's residual risk R1 applies: a recoverable
old value must be rotated regardless of what the tooling did. The clone-counting
step makes the distributed-copy danger concrete — thirteen uncontrollable copies
is a number you cannot un-leak, which is exactly why encrypting *before* commit
(gitsafe's whole premise) beats cleaning up *after*.

### Mini project 2 — Map your team's current secret-access list and find the drift

**Description.** For a team you know, build two lists side by side — *who can
access the repository* and *who can access its secrets today* — and find the
gaps. This makes unhappy-path-one's "second list" drift tangible.

**Concepts practiced.** The two-lists problem; drift; least privilege; why a
single derived list (gitsafe's model) removes the failure.

**Requirements.** Knowledge of the team's git host access (collaborators,
branch permissions) and its current secret storage (vault, password manager,
shared file, chat). No tooling — this is paper or a spreadsheet.

**Walkthrough.**
1. In column A, list everyone who can read/push the repository, and which
   branches.
2. In column B, list everyone who can currently retrieve the secrets, from
   whatever store holds them.
3. Align the two columns by person and highlight every mismatch.
4. For each mismatch, classify it: *over-access* (can read secrets but should not,
   e.g. a leaver) or *under-access* (needs secrets but lacks them, leading to
   insecure sharing).
5. Note who *owns* each list and how often each is updated — the difference in
   ownership is the engine of drift.

**Worked solution.** You find column A has alice, bob, and dave (a new hire);
column B has alice, bob, and carol (who left six months ago) but not dave.
Aligning them surfaces two mismatches: carol is over-access (a former employee who
can still read every secret in the vault — a live risk requiring removal *and*
rotation of what she could see) and dave is under-access (he has been getting the
staging key pasted to him over chat because nobody added him to the vault — an
insecure workaround). You note that column A is owned by the git admin and updated
on every onboarding, while column B is owned by whoever set up the vault and
updated "when someone remembers." That ownership split is why the lists
diverged. Your report's recommendation: collapse the two lists into one by
deriving secret access from repo access — which is exactly what gitsafe does.

**Explanation.** This project is the empirical version of the two-unhappy-paths
section. Almost every team that keeps secrets outside git will find at least one
over-access and one under-access mismatch, because two independently maintained
lists *cannot* stay aligned without constant manual effort. The over-access case
is a direct security risk (and, note, even removing carol from the vault would not
undo what she already copied — the same R1 caveat again). The under-access case
shows how a missing process *creates* insecure behavior: dave's chat-pasted key is
itself a leak. Seeing both in one spreadsheet makes the argument for a single
derived list undeniable, which is the realization gitsafe is built to deliver.

### Mini project 3 — Diagram your repo's branch→reader mapping

**Description.** For a repository you would like to protect with gitsafe, design
and draw the complete branch→reader mapping you *would* configure — before you
ever touch the tool — so that when you reach the hands-on chapters you are
translating a finished design rather than improvising.

**Concepts practiced.** Recipients = branch readers; per-branch access control;
least privilege; mapping people to grants.

**Requirements.** A target repo, its branch structure, and the list of people who
work on it. Paper, a whiteboard, or any diagramming tool.

**Walkthrough.**
1. List the branches that hold meaningful secrets (often `main`, `staging`,
   `production`, and a `feature/*` glob).
2. List the people and their roles.
3. For each branch, write the set of people who legitimately need to read its
   secrets, applying least privilege — start from "no one" and add only the
   necessary.
4. Draw it as a bipartite diagram: branches on the left, people on the right,
   an edge for each read grant.
5. Sanity-check: does the most sensitive branch have the smallest reader set?
   Does anyone have access they cannot justify? Remove unjustified edges.

**Worked solution.** For a four-person team you produce:

```
   BRANCHES                 READERS
   ──────────               ──────────
   feature/*  ──────────►   lead, backend, frontend, contractor
   main       ──────────►   lead, backend, frontend
   staging    ──────────►   lead, backend, frontend
   production ──────────►   lead
```

You confirm the sanity checks: `production` has the smallest reader set (just the
lead), the contractor is confined to `feature/*`, and every edge maps to a real
need you can state in a sentence. This diagram is now a literal specification:
each arrow is a `read` grant you will create later, and each reader set is exactly
the recipient set gitsafe will encrypt that branch's secrets to. You have
designed your security posture before running a single command.

**Explanation.** This project front-loads the thinking so the doing is mechanical.
Because in gitsafe the branch→reader mapping *is* both the access policy and the
encryption recipient list, this diagram is not a planning artifact you throw
away — it is the thing you implement, edge for edge. Designing it cold, before the
pressure of a live setup, is what keeps you from the common mistake of
over-granting (giving everyone read on everything because it is easier in the
moment). The sanity checks encode least privilege as a habit: smallest reader set
on the most sensitive branch, and no edge without a justification. When you reach
the onboarding and grant chapters, you will find you are simply transcribing this
diagram — and that is exactly the experience this chapter set out to give you.

---

## Summary

We began with a question that haunts almost every team — *where do our secrets
live, and who can see them?* — and found that the usual answers are unsatisfying
because the tools made the dangerous path easier than the safe one. Secrets end up
in git because secrets *are* configuration and configuration belongs with code;
the instinct to co-locate them is sound. What is unsound is storing them in
plaintext, and we saw precisely why through three mechanical facts: git history is
forever, so a deleted secret is merely a crossed-out one; a clone is a full copy,
so a committed secret multiplies into copies you cannot reach; and `.gitignore` is
a politeness setting, not a boundary, failing open the moment anyone forgets.
Those three facts together make plaintext-in-git permanently dangerous, not merely
untidy.

Cornered by that danger, teams take one of two unhappy paths — banishing secrets
from git (and inheriting drift plus a second, unsynchronized access list) or
committing plaintext and waiting for the leak. gitsafe offers a third path that
refuses the trade: encrypt the secret in git, so the repo stays the single source
of truth *and* nothing leaks *and* there is only one access list. The mechanism is
stock git's clean/smudge filters, which encrypt a *marked* file on its way into
the object store and decrypt it on the way out, so git only ever holds ciphertext
while you only ever see plaintext. The defining choice is that recipients are
*derived*, not maintained: gitsafe encrypts each branch's secrets to exactly the
people granted `read` on that branch, fusing "who can read the branch" and "who
can decrypt its secrets" into one list. We contrasted this with git-crypt's single
shared key and SOPS's hand-maintained recipients file, and saw gitsafe's twist —
branch-readers equal decryptors, and the allow-list is a signed, chained file
verifiable offline with no server or vault. Finally we took an honest first look
at the threat model: the protection is confidentiality of file *contents* against
anyone without a key (a clone is no longer a leak), while names, sizes, and the
recipient set stay deliberately in the open — and the one caveat to carry
everywhere is that removing someone does not scrub history, so after offboarding
you rotate the secret's *value*, exactly as you would after any leak.

You now hold the complete mental model, and that was the entire job of this
chapter. In Chapter 2 we put it to work. We will get gitsafe installed, create
your private identity once on your machine, turn gitsafe on for a repository, and
protect your very first secret — committing a `.env` and then *proving*, with a
single git command, that the repository stored ciphertext while your working copy
still reads as the real password. Everything we do there will feel inevitable,
because you already understand why it must work the way it does. The map is drawn;
next we start walking.
