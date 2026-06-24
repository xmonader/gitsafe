# Chapter 3 — The access model: members, grants, and branches as readers

The previous chapters showed you how to put a secret into a repository and get
it back out. That is the *mechanism*. This chapter is about the *policy* — the
part of gitsafe that decides, for any given secret, exactly whose keys it gets
encrypted to. Almost every confusing moment you will have with gitsafe traces
back to one question: "who can read this branch?" Once you can answer that
question on paper, by hand, the tool stops being magic and starts being
obvious. So this chapter is deliberately conceptual. We will run commands, but
the commands exist to *illustrate* a model you should be able to reason about
without a terminal in front of you.

Here is the whole model in one sentence, and the rest of the chapter is just
unpacking it: **a member is a name plus public keys, a grant is a capability
(verb) over a ref, and the recipients of any secret are derived — not declared —
from whoever can read the branch that secret lives on.** That last clause is the
idea that makes gitsafe different from a pile of `age` commands. You never write
down "encrypt this file to Alice and Bob." You write down "Alice and Bob can
read `staging`," and gitsafe computes the recipient list for you, every time,
from the policy. One source of truth, not two lists that drift apart.

Let us build that picture from the bottom up.

## The keyring: who exists, and what keys they hold

Before anyone can read or write anything, gitsafe has to know they *exist*. The
reason is simple and worth stating plainly: encryption is to a public key, not
to a name. "Alice" means nothing to `age`; `age1qz...` means something. So the
first thing the policy carries is a **keyring** — a map from human-readable
member names to the public keys gitsafe will use on their behalf. Think of it as
the org chart's cryptographic counterpart. If you are not in the keyring, you
are not a person as far as the policy is concerned, and nothing can be encrypted
to you because gitsafe has no key to encrypt *to*.

Each keyring entry holds **two** public keys, and the distinction between them is
the single most common source of confusion for newcomers, so we will be
pedantic about it. The first key is the **`enc`** key: an age (X25519)
recipient, the thing a secret is encrypted *to* so that the holder of the
matching private key can decrypt it. This is the key that matters for *reading*.
The second key is the **`sign`** key: an ed25519 public key used to verify
signatures on policy changes. This key matters only for *administering* the
policy — for the people who sign new policy versions. The two keys do completely
different jobs and most people only need one of them.

That asymmetry is the practical heart of the keyring. **Most of your teammates
are read-only.** They need to decrypt secrets to do their work, and that is all.
A read-only member therefore needs only an `enc` key. They never sign a policy
change, so they never need a `sign` key, and adding one would be dead weight. So
the everyday onboarding command is the minimal one:

```bash
gitsafe member add alice --enc age1qz9x...examplerecipient...
```

That single line creates a keyring entry named `alice` whose age recipient is the
value you pasted, marks her `active`, and — because adding a member changes the
policy — signs a brand-new policy version with *your* admin key and links it to
the chain. Notice what is *not* there: no `--sign`. Alice cannot sign policy, and
that is correct, because Alice is not an admin. She is simply a person who can
now be granted read access somewhere. The `--enc` value is what she got from
running `gitsafe key show` (or `gitsafe key gen`) on her own machine and sent to
you over some channel you trust; her private key never left her laptop.

The exceptions are the admins — the small number of people who are allowed to
*change* the policy. They need both keys, because they will sign policy versions
(ed25519) and they will also, like everyone else, want to read secrets (age). For
those people you supply both:

```bash
gitsafe member add bob --enc age1lk2...examplerecipient... --sign 3f8a9c...ed25519pubhex...
```

The `--sign` value is the hex-encoded ed25519 public key Bob generated alongside
his age key. Supplying it is what makes it *possible* to later grant Bob the
`admin` verb — and gitsafe enforces that ordering strictly. If you try to grant
`admin` to a member who has no `sign` key on file, gitsafe **refuses**, because
an admin who cannot sign is a contradiction: the grant would be unusable, a dead
capability that looks like power but produces only failed signatures. Add the
signing key first; grant admin second.

One more flag rounds out the command, and it exists because keys change. People
lose laptops, rotate compromised keys, or simply re-issue. When a member already
exists and you need to replace their keys, you pass `--update`:

```bash
gitsafe member add alice --update --enc age1new...replacementrecipient...
```

Without `--update`, `member add` refuses to clobber an existing entry — a
guardrail against accidentally overwriting someone's keys with a typo. *With*
`--update`, gitsafe replaces the supplied keys and, importantly, **preserves a
`sign` key you did not re-supply** (so updating an admin's age key alone does not
silently demote them) and **reactivates** the member. That reactivation detail is
worth filing away: re-adding a revoked member with `--update` is the supported
un-revoke path. We will lean on that in the next chapter when we talk about
lifecycle.

## Grants and verbs: capabilities over refs

The keyring says who exists. It says nothing about what they may *do*. That is
the job of **grants**. A grant is a small, three-part statement of capability,
and the command mirrors the data structure exactly:

```bash
gitsafe grant SUBJECT VERB RESOURCE
```

Read it as a sentence: "grant *SUBJECT* the ability to *VERB* on *RESOURCE*." For
example, `gitsafe grant alice read staging` says "Alice may read the `staging`
branch." Every access decision gitsafe ever makes is the sum of statements
exactly this shape. There is no hidden state, no implicit access, no "owner"
who gets everything for free. If a capability is not written down as a grant (or
implied by one — we will get to implication in a moment), it does not exist.

The **VERB** is drawn from a fixed set of five: `read`, `write`, `force`,
`grant`, and `admin`. They are not five unrelated permissions; they form a
hierarchy, where a stronger verb subsumes the weaker ones below it:

```
admin > force > write > read
```

A higher verb satisfies any lower requirement. So if a check asks "does this
subject have `read`?", anyone holding `write`, `force`, or `admin` on a matching
resource passes — they have *more* than read, so they certainly have read. On top
of that linear chain there is one extra implication you must memorize: **`admin`
also implies `grant`** (the ability to delegate capabilities), and of course
`admin`, being the top of the chain, implies `read` too. The practical
consequences are the ones to internalize:

- **`read` is the verb that determines decryption recipients.** When gitsafe
  encrypts a secret, it asks "who can `read` this branch?" Nothing else feeds the
  recipient set.
- **`admin` is the verb that lets someone change the policy** — add members,
  issue grants, the lot. It is checked against a special reserved resource we
  will meet shortly.
- **`write` and `force` exist mostly as policy metadata.** gitsafe is a
  client-side overlay; it does not sit on your git server enforcing who may push
  or force-push. So do not lean on `write`/`force` for real access control —
  treat them as documentation of intent, not as a gate.

The hierarchy has a consequence people forget and then get surprised by, so let
us say it loudly: because a higher verb satisfies `read`, **granting someone
`write` or `admin` on a ref also makes them a recipient of that ref's secrets.**
There is no way to grant admin "but not let them read." Admins can always read.
If that is not what you want, do not make them an admin.

The **SUBJECT** of a grant can be one of three things, and the flexibility here
is what lets you express both fine-grained and broad policy in the same grammar.
A subject can be a concrete **member name** (`alice`), in which case the grant
applies to exactly that person. It can be a **group name** (we will cover groups
in their own section), in which case the grant applies to everyone in that group
and tracks the group's membership over time. Or it can be the literal **`*`**,
the wildcard, which means *all members* — every active person in the keyring.
The wildcard is how you say "the whole team can read this," and it has subtle
behavior around restricted refs that gets its own section below.

The **RESOURCE** is a git ref, expressed as a glob. gitsafe is generous about
syntax: a bare branch name is shorthand for the full ref path. So `staging`
expands to `refs/heads/staging`, and `main` to `refs/heads/main`. Anything you
write starting with `refs/` is taken verbatim, which is how you express patterns:
`refs/heads/feature/*` matches one segment (`feature/login` but not
`feature/login/v2`), while `refs/heads/**` matches across segments (the whole
branch namespace). The single-star-versus-double-star distinction is standard
glob semantics, and it matters when you write grants that are meant to cover
families of branches.

One small but pleasant property: grants are **idempotent**. Issue the exact same
`grant alice read staging` twice and the second one is a no-op, not an error and
not a duplicate entry. This makes grant commands safe to put in scripts and
onboarding runbooks without worrying about whether they have already run.

## The key idea: recipients are derived from readers

Everything so far has been setup. This section is the payoff, and if you take one
idea away from this chapter, take this one. **The recipients of a secret are not
something you configure. They are computed, on the fly, from whoever can read the
branch.** You maintain *one* list — the access policy — and the recipient list
falls out of it automatically.

Walk through what happens the moment gitsafe encrypts a file. The file lives on
some branch — say you are on `staging`, so the ref is `refs/heads/staging`.
gitsafe does not look for a recipients file. It calls, in effect,
`policy.Recipients("refs/heads/staging")`, and that function does exactly four
things, in order. First, it finds every grant whose resource glob matches
`refs/heads/staging` and whose verb satisfies `read` (remember: `write`,
`force`, and `admin` all satisfy `read`). Second, it collects the subjects of
those grants into a set of member names — expanding `*` to all active members and
expanding any group to its members. Third, it drops anyone whose keyring status
is `revoked`. Fourth, it maps the surviving names to their `enc` (age) keys, and
*that* sorted list is what the file gets encrypted to.

Because this is computed and not stored, you never have a recipient list that
disagrees with your access policy — they are the *same thing* viewed two ways.
Grant Alice read on `staging` and, the next time a `staging` secret is encrypted,
Alice's age key is in the recipient set automatically. Revoke her and she falls
out of it on the next rotation. You will never hunt for "the other place" where
recipients are listed, because there is no other place.

You do not have to take this on faith or read it out of a blob header. gitsafe
gives you a command that resolves the reader set directly, and it is the single
most useful auditing command in the tool:

```bash
gitsafe access staging
```

That prints the active reader *names* for `refs/heads/staging` — already
expanded, so groups are flattened to people, admins are included, and `*` is
resolved to every active member — along with the count of age recipients a secret
on that branch would be encrypted to. When someone asks "who can see the staging
database password?", this is the command that answers them, definitively, from
the signed policy and nothing else.

Here is the mapping drawn out, from raw policy on the left to the cryptographic
recipient list on the right. This is the diagram to keep in your head:

```
   KEYRING (members + keys)            GRANTS (subject verb resource)
   ─────────────────────────          ───────────────────────────────
   alice  enc=age1qz... sign=-         alice  read   refs/heads/staging
   bob    enc=age1lk... sign=3f8a..    bob    admin  refs/policy
   carol  enc=age1mn... sign=-         *      read   refs/heads/main
   dave   enc=age1op... sign=-  REVOKED carol  read   refs/heads/staging
                                       devs   read   refs/heads/staging   (group)

                 │   gitsafe access refs/heads/staging
                 ▼
   READERS of refs/heads/staging  (verb satisfies read, status active)
   ──────────────────────────────────────────────────────────────────
     alice        (direct read grant)
     carol        (direct read grant)
     bob          (admin satisfies read — admins always read)
     <devs>       (group expands to its active members)
     ✗ dave       (dropped: status REVOKED)
                 │   map names → enc keys
                 ▼
   AGE RECIPIENTS of a secret committed on staging
   ──────────────────────────────────────────────────────────────────
     age1qz...   (alice)
     age1mn...   (carol)
     age1lk...   (bob)
     age1...     (each active devs member)
```

Trace the diagram top to bottom and the whole model is visible at once. On the
left, two independent inputs: the keyring (who exists, with which keys) and the
grants (who may do what). gitsafe joins them. The middle band is what `access`
shows you: the *people* who can read `staging`, after applying the verb hierarchy
(Bob gets in through `admin`, not a direct `read` grant), after expanding groups
and `*`, and after dropping revoked Dave. The bottom band is the same set
re-expressed as age keys — and that is, byte for byte, the recipient list the
clean filter hands to `age`. There is no separate recipient configuration
anywhere in that picture. Change anything on the left and the bottom changes with
it on the next rotation.

A few corollaries of this design are worth stating because they trip people up.
**No readers means no encryption, deliberately.** If a branch has *nobody*
granted read, the clean filter does not encrypt to an empty recipient set (which
would lose your data forever); it refuses with `no readers for refs/heads/B`. The
fix is to grant at least yourself read on that branch first. **Admins always
read**, as we said, because `admin` satisfies `read`. **Public means the team,
not the planet** — covered next. And **revocation is forward-only**: removing a
reader changes future encryptions on the next `rotate`; it cannot claw back
ciphertext that person already has a copy of.

## Public versus need-to-know

The wildcard subject `*` deserves careful handling because its name suggests
something more dangerous than it is. A `*` read grant does **not** make a branch
readable by the anonymous public, by the internet, by anyone who clones the repo.
It cannot. Encryption is to keys, and the only keys gitsafe knows about are the
ones in the keyring. So `*` resolves to "every *active member*" — the whole team,
and only the team. It is the right tool when a secret genuinely should be visible
to everyone you have onboarded: a shared service token that every developer
needs, say.

```bash
gitsafe grant '*' read main
```

That grant says "any active member may read `main`." Add a new member to the
keyring tomorrow and they automatically become a reader of `main` on the next
rotation, with no further grant — because `*` is evaluated against the *current*
keyring each time, not frozen at grant time. That is convenient for genuinely
team-wide secrets and exactly wrong for sensitive ones, which brings us to the
other half of the picture.

Some branches should be **need-to-know**: production credentials, customer data
keys, anything where "the whole team" is too wide a blast radius. For those,
gitsafe supports **restricted** refs. The defining property of a restricted ref
is that it **suppresses `*` grants**: when gitsafe resolves the readers of a
restricted branch, the wildcard is ignored, so only the subjects you named
*explicitly* — concrete members and groups — can reach it. The whole-team
shortcut simply does not apply there. This is how you enforce least privilege:
mark the sensitive branch restricted, grant read only to the specific people or
group who must have it, and a stray `* read refs/heads/**` grant elsewhere can
never accidentally pull the whole team into the production secrets.

There is one restricted resource you do not have to configure because gitsafe
reserves it permanently: **`refs/policy` is always restricted.** This is the
resource that governs who may change the policy itself (the next section), and it
would be absurd for "the whole team" to be able to rewrite access rules by
default. So `*` never grants policy-change power; admin over `refs/policy` is
always something an existing admin hands to a *named* person, deliberately.

The mental model to carry: `*` is a convenience that means "everyone we've
onboarded," restricted refs are the override that says "ignore the convenience
here — name names," and `refs/policy` is the one resource that is restricted no
matter what so the keys to the kingdom are never handed out wholesale.

## Groups: managing access by role

Granting to individuals works, but it scales badly. A ten-person backend team
that needs read on five branches is fifty grants to write and, worse, fifty
grants to *remember to update* every time someone joins or leaves. The fix is the
same one every access-control system reaches for: **groups**. A group is a named
bag of members that you can use as the subject of a grant. Grant once, to the
group, and every member of the group inherits it; change the group's membership
and every grant that targets it updates at once.

You build a group by adding members to it; the group is created the first time
you name it:

```bash
gitsafe group add devs alice bob carol
```

That creates a group `devs` containing Alice, Bob, and Carol (all of whom must
already exist in the keyring — a group is a grouping of *known* members, not a
way to invent new ones). A couple of guardrails apply: the members must already
be in the keyring, and a group **may not share a name with a member**, so you
cannot create the confusing situation where `alice` is both a person and a group.
Like other policy changes, this signs a new policy version and requires admin.

Once the group exists, it becomes a first-class grant subject, indistinguishable
from a member name in the `grant` grammar:

```bash
gitsafe grant devs read staging
```

Now all three of Alice, Bob, and Carol can read `staging`, expressed as a single
grant. When Dave joins the team next month, you add him to the keyring and to the
group — `gitsafe group add devs dave` — and he immediately inherits every grant
`devs` holds. You did not touch the `staging` grant at all. That is the entire
point: **groups let you manage access by role instead of by person.** Wherever
access is evaluated — in `Recipients`, in `access`, in `audit` — a group is
expanded to its current members, so the recipient list always reflects today's
roster, not the roster as it was when you wrote the grant.

Removing membership mirrors adding it:

```bash
gitsafe group remove devs carol      # remove Carol from devs
gitsafe group remove devs            # delete the whole group
```

The first form drops the named members from the group; the second form, with no
names, deletes the group entirely. A subtlety worth knowing: a group that becomes
empty is deleted automatically, since an empty group grants access to nobody and
serves no purpose. And because changing group membership changes who can read,
**run `gitsafe rotate` afterward** if the group held read access — otherwise the
already-committed secrets are still encrypted to the old reader set until the next
rotation re-encrypts them. (We will treat rotation in depth in the next chapter;
for now, just remember that membership changes are not retroactive without it.)

To see the current state of your groups at a glance:

```bash
gitsafe group list
```

That prints each defined group and its members — the quick check before you
reason about who can read what.

## Who may change policy

We have talked a lot about reading. The last piece is *writing the policy
itself*: who is allowed to add members, issue grants, and otherwise change the
rules. This is the most security-critical question in the whole system, because
whoever can change the policy can, in principle, grant themselves read on
everything. gitsafe handles it with the same grant grammar you already know, plus
a reserved resource and a cryptographic chain that makes the whole thing
verifiable offline.

The reserved resource is **`refs/policy`**. It is not a real git branch — it is a
synthetic resource that represents "the policy document." Holding the `admin`
verb on `refs/policy` is what it *means* to be an admin. Every policy-changing
command (`member add`, `grant`, `group add`, and the rest) checks that you have
`admin` over `refs/policy` before it will do anything. And as we noted,
`refs/policy` is permanently restricted, so `*` can never confer it; policy power
is always handed to a named person by an existing admin.

But a grant alone is not enough to *change* the policy — you also have to be able
to **sign** the change, and this is where the two-key keyring pays off. Every
policy version after the very first is signed with an ed25519 key, and gitsafe
verifies that signature against the signer's `sign` key in the *parent* version's
keyring. So to administer the policy you need both the `admin` grant *and* a
`sign` key on file. This is exactly why granting `admin` to a member with no
`sign` key is refused: without the key, the grant could never produce a valid
signature, so it would be a lie.

The policy is not a single mutable file; it is a **signed, content-addressed,
versioned chain**, and understanding its shape is what lets you trust it. On
disk, under `.gitsafe/policy/`, there is a `HEAD` file holding the hash of the
current version, and an `objects/` directory holding one JSON file per version,
each named by its own content hash (`objects/<hash>.json`). Each version records
its keyring, its grants, the name of whoever signed it, the ed25519 signature
over its contents, and — the link that makes it a *chain* — the hash of its
parent version. Version 0, the **root**, is self-signed by the founding admin.
Every later version must be signed by someone who held `admin` in the parent
version, and the signature must verify. That is what makes the chain
forgery-resistant: you cannot insert a version you were not authorized to create,
and you cannot tamper with an existing version without changing its content hash
and breaking every signature downstream of it.

Two read-only commands let you inspect all of this. The first shows you the
current state in human-readable form:

```bash
gitsafe policy show
```

It prints the current version number, the keyring (each member's name, status,
and age key), and the list of grants. This is the raw policy — the inputs to
every access decision, laid out so you can read them. The second command checks
the *integrity* of the whole chain:

```bash
gitsafe policy verify
```

This walks every version from root to head, re-checking each signature against
the appropriate keyring, confirming the version numbers increase by exactly one,
and confirming each parent link. It prints the version count, the head hash, and
the root fingerprint. Crucially, it does all of this **offline** — it needs
nothing but the files in the repo and the public keys they contain. There is no
server to call, no certificate authority to reach. That is the design goal stated
back in chapter one made concrete: a policy you can verify on a plane, from a
clone, with the network unplugged. If `verify` passes, you know the access rules
you are reading in `policy show` are exactly the ones an authorized admin signed,
unmodified.

## Putting it together

You now have the complete model. A **member** is a name plus up to two public
keys: an `enc` key (age, for reading) that everyone needs, and a `sign` key
(ed25519, for signing policy) that only admins need. A **grant** is a
*SUBJECT*/*VERB*/*RESOURCE* capability, where verbs form the hierarchy
`admin > force > write > read` (and admin also implies grant), subjects are
members, groups, or `*`, and resources are ref globs with bare branch names as
shorthand. The **recipients** of any secret are derived from whoever can read its
branch — one list, computed, never declared twice. **`*`** means the whole team
but never the public; **restricted** refs suppress `*` for need-to-know secrets,
and `refs/policy` is always restricted. **Groups** let you grant by role. And the
**policy itself** is a signed, versioned chain that only admins (with a sign key)
can extend, verifiable offline. The rest of the chapter drills these until they
are reflexive.

Here is a second diagram, this time of the *trust and authority* relationships
rather than the read path — how authority flows from the root admin outward:

```
        ROOT POLICY (v0, self-signed by founding admin)
                 │  admin on refs/policy
                 ▼
        founding admin  ──signs──▶  v1  ──signs──▶  v2  ──signs──▶  v3 (HEAD)
             │                       │               │
             │ grants admin          │ adds member   │ grants devs
             │ on refs/policy        │ alice (enc)   │ read staging
             ▼                       ▼               ▼
         second admin           alice = reader    devs group = readers
         (has sign key)         (no sign key)     (expands to members)

   verify(): every arrow re-checked against the PARENT version's keyring,
             versions must step +1, parent hashes must link, offline.
```

Read this diagram as the *provenance* of every capability. The root is the only
self-signed version; it bootstraps trust. Every arrow afterward is a signed
extension, and each one is only valid if its signer held `admin` in the version
the arrow starts from. So authority is not ambient — it is a chain you can trace
back to a root you have pinned (the trust model from chapter two). Notice that
`alice` appears with no sign key: she is a reader, a leaf, never a signer, and the
chain never depends on her. The admins, by contrast, are load-bearing — their
signatures are what every downstream version rests on, which is exactly why
chapter four will insist you always keep more than one. `gitsafe policy verify`
is the act of re-walking every arrow in this diagram and confirming each one,
with no network and no trusted third party.

---

## Exercises

These run from recall through application to debugging and extension. Try each
before reading the solution. Every solution uses only real gitsafe commands —
no invented flags.

### Exercise 1 (recall) — The two keys

**Problem.** A keyring entry can hold two public keys. Name both, state which
cryptographic system each belongs to, and say which one a *read-only* teammate
actually needs.

**Solution.** The two keys are the **`enc`** key and the **`sign`** key. The
`enc` key is an **age (X25519)** recipient — the key a secret is encrypted *to*,
used for decryption. The `sign` key is an **ed25519** public key — used to verify
signatures on policy changes. A read-only teammate needs only the **`enc`** key;
they never sign policy, so they need no `sign` key.

**Explanation.** This distinction is the most common source of confusion, so it
is worth being able to recite cold. The two keys do entirely separate jobs: one
participates in encryption and one participates in signing, and the two
cryptosystems (X25519/age versus ed25519) are unrelated. Because the
overwhelming majority of teammates only ever *read* secrets, they only ever need
the `enc` key, which is why the everyday `member add` command takes just `--enc`.
The `sign` key is the privilege marker — it is required to administer the policy
and is the reason gitsafe refuses to grant `admin` to anyone who lacks it.
Getting this right means you will not paste an ed25519 key where an age key
belongs, and you will not waste effort generating signing keys for people who
will never sign anything.

### Exercise 2 (recall) — The verb hierarchy

**Problem.** Write out the verb hierarchy. Then answer: if Bob is granted
`write` on `staging`, can he read a secret committed on `staging`? Why?

**Solution.** The hierarchy is `admin > force > write > read`, and `admin`
additionally implies `grant`. Yes — Bob can read `staging`'s secrets. A higher
verb satisfies a lower requirement, and `write` is higher than `read`, so holding
`write` satisfies the `read` check. Because `read` is what determines decryption
recipients, Bob is included in the recipient set for `staging`.

**Explanation.** The hierarchy is not five independent flags; it is an ordering
where stronger verbs subsume weaker ones. The single most important practical
consequence is the one this exercise targets: anyone with `write`, `force`, or
`admin` on a ref is automatically a *reader* of that ref, because all three
satisfy `read`. People are frequently surprised that they "only gave Bob write"
yet Bob can decrypt — but that is the model working as designed. There is no way
to grant a higher verb while withholding read; if you do not want someone reading
a branch's secrets, you must not grant them any verb on it at all. This is also
why admins can always read everything they administer.

### Exercise 3 (recall) — Resource shorthand and globs

**Problem.** Translate each subject/resource into the full ref gitsafe will use,
and say what `refs/heads/feature/*` matches that `refs/heads/feature/**` does
not. (a) `staging` (b) `refs/heads/**` (c) `main`.

**Solution.** (a) `staging` → `refs/heads/staging`. (b) `refs/heads/**` is used
verbatim — it already starts with `refs/`. (c) `main` → `refs/heads/main`. The
difference: `feature/*` matches a single path segment, so it covers
`refs/heads/feature/login` but **not** `refs/heads/feature/login/v2`; `feature/**`
matches across segments and covers both.

**Explanation.** gitsafe expands a bare branch name to `refs/heads/<name>` as a
convenience, but anything starting with `refs/` is taken exactly as written, which
is how you express patterns. The single-star-versus-double-star distinction is
standard glob semantics and it matters whenever your branches have slashes in
their names. A grant on `refs/heads/feature/*` silently fails to cover nested
feature branches, which can leave secrets on `feature/login/v2` with no readers
(and therefore unencryptable) when you thought you had covered the whole feature
namespace. When in doubt about a namespace, use `**`; when you mean exactly one
level, use `*`.

### Exercise 4 (apply) — Onboard a read-only teammate

**Problem.** Carol sent you her age recipient `age1carol...`. Add her to the
keyring as a read-only member and grant her read on the `staging` branch. Then
verify she shows up as a reader. (Do not worry about rotation here.)

**Hint.** Two `gitsafe` commands to make the change, one to check it.

**Solution.**

```bash
gitsafe member add carol --enc age1carol...examplerecipient...
gitsafe grant carol read staging
gitsafe access staging
```

The first command creates Carol's keyring entry with her age key and no sign key
(read-only). The second grants her read on `refs/heads/staging`. The third prints
the active readers of `staging`, which now include `carol`.

**Explanation.** This is the canonical two-step shape of granting access:
*member add* puts the person in the keyring (so gitsafe has a key to encrypt to),
and *grant* gives them a capability on a resource. Order matters in spirit —
there must be a keyring entry before a grant can be meaningful — though gitsafe
treats grants as statements about names and will accept them either way; the
recipient computation simply skips names with no usable key. Running
`gitsafe access staging` afterward is the habit to build: never assume a change
landed the way you intended, *prove* it by resolving the reader set. Note we
deliberately deferred rotation; in real life you would follow with
`gitsafe rotate` so existing `staging` secrets get re-encrypted to include Carol
— which is exactly what the next exercise and the next chapter address.

### Exercise 5 (apply) — Convert per-person grants to a group

**Problem.** You currently have three separate grants: `alice read staging`,
`bob read staging`, `carol read staging`. Refactor this to use a `devs` group so
that future membership changes are one command. Then confirm the group's members.

**Solution.**

```bash
gitsafe group add devs alice bob carol
gitsafe grant devs read staging
gitsafe group list
```

`group add` creates `devs` containing the three members (they must already be in
the keyring). `grant devs read staging` gives the whole group read on
`refs/heads/staging`. `group list` prints the defined groups and their members so
you can confirm `devs = alice, bob, carol`.

**Explanation.** Granting to a group instead of to individuals is how you manage
access by *role* rather than by *person*, and it pays off the moment the team
changes: adding a fourth developer becomes `gitsafe group add devs dave` with no
new grant, because wherever access is evaluated the group is expanded to its
*current* members. You could now also remove the three original per-person grants
with `gitsafe revoke` if you want the group to be the single source of truth,
though leaving them is harmless since access is a union. After any change to a
group that holds read access you should run `gitsafe rotate` so committed secrets
are re-encrypted to the updated reader set; the grant alone changes future
encryptions but does not rewrite the blobs already in git.

### Exercise 6 (apply) — Make a branch need-to-know

**Problem.** Your repo has a team-wide grant `* read refs/heads/**`, so every
member can read every branch. You are adding a `prod` branch whose secrets must
be readable only by the `devs` group — not the whole team. Describe what property
of `prod` you need and grant `devs` read on it. Then use `access` to argue that
the wildcard does not reach `prod`.

**Hint.** The relevant concept is a *restricted* ref, which suppresses `*`.

**Solution.**

```bash
gitsafe grant devs read prod
gitsafe access prod
```

For `prod` to exclude the team-wide `*` grant, `prod` must be a **restricted**
ref. A restricted ref suppresses `*` grants, so only explicitly-named subjects —
here the `devs` group — resolve as readers. `gitsafe access prod` then lists only
the members of `devs` (plus any admins, since admin satisfies read), and *not*
the full team, proving the wildcard did not reach it.

**Explanation.** The whole purpose of restricted refs is least privilege in the
presence of a broad `*` grant. Without restriction, the `* read refs/heads/**`
grant would match `refs/heads/prod` and pull every active member into the reader
set — exactly the over-exposure you are trying to avoid. Marking `prod`
restricted tells gitsafe to ignore `*` when resolving its readers, so the only
way onto `prod` is to be named directly or through a group. The `access` command
is your proof: if it shows the whole team, restriction is not in effect; if it
shows only `devs` (and admins), you have genuine need-to-know. This is the same
mechanism that protects `refs/policy`, which gitsafe keeps permanently restricted
so `*` can never confer policy-change power.

### Exercise 7 (debug) — "no readers for refs/heads/qa"

**Problem.** A teammate creates a branch `qa`, adds a `.env` secret, and
`git add .env` fails with `no readers for refs/heads/qa`. Diagnose the cause and
give the command that fixes it.

**Hint.** What does the recipient computation do when the reader set is empty?

**Solution.** The cause is that **no member is granted read on `qa`**, so the
recipient set is empty and the clean filter refuses to encrypt (rather than
encrypt to nobody and lose the data). The fix is to grant at least one reader —
yourself, plus anyone else who needs it:

```bash
gitsafe grant <you> read qa
gitsafe access qa        # confirm the reader set is now non-empty
git add .env             # now succeeds
```

**Explanation.** gitsafe deliberately treats "encrypt to an empty recipient set"
as an error, because the result would be a blob nobody — not even you — could
ever decrypt, which is data loss disguised as success. So when `access qa` would
return no one, the clean filter aborts with `no readers for refs/heads/qa`
instead. This almost always means you created a fresh branch and never granted
read on it; the team-wide grants you have elsewhere did not match `qa` (perhaps
they target `staging` or a `feature/*` pattern that does not cover `qa`).
Granting yourself read is the minimum fix; in practice grant whoever needs the
secret. The `access` check before retrying `git add` confirms the fix landed,
turning a confusing filter error into a two-command resolution.

### Exercise 8 (debug) — Admin grant refused

**Problem.** You run `gitsafe grant dave admin refs/policy` to make Dave a policy
admin, and gitsafe refuses the grant. Dave is definitely in the keyring. What is
wrong and how do you fix it?

**Solution.** Dave's keyring entry has **no `sign` key**, and gitsafe refuses to
grant `admin` to a member without one because the grant would be unusable — an
admin must be able to *sign* policy versions. Fix it by adding Dave's ed25519
signing key first (with `--update`, since he already exists), then re-issue the
grant:

```bash
gitsafe member add dave --update --enc age1dave...recipient... --sign 9a1c...ed25519pubhex...
gitsafe grant dave admin refs/policy
```

**Explanation.** Administering the policy means *signing* new versions with an
ed25519 key, and that key is verified against the signer's `sign` entry in the
keyring. A member with no `sign` key literally cannot produce a verifiable policy
version, so an `admin` grant for them would be a dead capability — it would look
like power but every attempt to use it would fail signature verification.
Refusing the grant up front turns a confusing future failure into a clear
immediate one. The fix is to supply the signing key via `member add --update`
(which preserves his existing age key and reactivates him if needed) and then
grant admin on the reserved `refs/policy` resource. Note that `refs/policy` is
always restricted, so this admin authority must be granted to Dave by name — it
could never have come from a `*` grant.

### Exercise 9 (create) — Design a two-tier access policy

**Problem.** Design and write the commands for a team with two tiers: a `devs`
group that may read `staging`, and a smaller `oncall` group that may *additionally*
read a need-to-know `prod` branch the rest of the team must not see. Alice and Bob
are devs; Bob is also oncall. Assume all three members already exist with `--enc`
keys.

**Solution.**

```bash
# Build the groups.
gitsafe group add devs alice bob
gitsafe group add oncall bob

# Tier 1: the dev group reads staging.
gitsafe grant devs read staging

# Tier 2: oncall reads the restricted prod branch (need-to-know).
gitsafe grant oncall read prod

# Prove the tiers.
gitsafe access staging     # expect: alice, bob (+ admins)
gitsafe access prod        # expect: bob only (+ admins) — restricted excludes others
```

For `prod` to be need-to-know, it must be a **restricted** ref so that no `*`
grant (if any exists) and no non-named member can reach it; only `oncall`'s
members resolve as readers.

**Explanation.** This is the bread-and-butter shape of real access design: roles
expressed as groups, capabilities expressed as grants from groups to branches,
and a restricted ref to carve out the sensitive tier. Bob appears in both groups,
so he reads both `staging` (as a dev) and `prod` (as oncall), while Alice reads
only `staging` — exactly the layering you wanted, achieved without a single
per-person grant. The two `access` calls are not optional polish; they are how you
*verify* the design does what you intended, especially that `prod`'s restriction
actually excludes the broader team. Building access this way means future changes
("Carol joins oncall") are one `group add` command, and the restricted `prod`
branch stays need-to-know regardless of how wide your `staging`/`*` grants grow.

### Exercise 10 (extend) — Read a policy and explain it

**Problem.** You inherit a repo and need to understand its access rules and trust
state from scratch. Which two commands do you run, and what does each tell you?

**Solution.**

```bash
gitsafe policy show      # current keyring + grants, human-readable
gitsafe policy verify    # walk the signed chain offline; version count, head hash, root fingerprint
```

`policy show` prints the *content* of the current policy: every member (name,
status, age key) and every grant (subject/verb/resource). `policy verify` checks
the *integrity* of the whole chain — re-verifying each version's signature against
the parent's keyring, confirming versions step by one and parent hashes link, and
reporting the root fingerprint and trust-pin status, all offline.

**Explanation.** `show` and `verify` are the two halves of understanding an
inherited policy: one tells you *what the rules are*, the other tells you *whether
you can trust that those rules are authentic and unmodified*. You want both,
because a beautiful set of grants is worthless if the chain was tampered with, and
a perfectly verified chain is useless if you do not know what it permits. Running
`verify` first (or noting its output) tells you the root fingerprint, which you
would confirm through a trusted channel before pinning — connecting this chapter's
policy model to chapter two's trust model. From `show`, you can reconstruct the
reader-set diagram from this chapter by hand: read off the grants, apply the verb
hierarchy, expand groups and `*`, drop revoked members, and you have the recipient
list — which `gitsafe access <branch>` will confirm.

---

## Mini projects

These are longer, end-to-end exercises. Each gives you a goal, the concepts it
drills, concrete requirements, a step-by-step walkthrough, a complete worked shell
session, and an explanation tying it back to the model. Work them in a scratch
repo where mistakes are free.

### Mini project 1 — Model a two-tier team with a restricted prod branch

**Description.** Build a realistic access policy from an empty repo: a `devs`
group that reads `staging`, a need-to-know `prod` branch readable only by a named
`oncall` group, and a team-wide secret on `main`. End by proving each tier with
`access`.

**Concepts practiced.** Keyring membership, the two key types, groups as grant
subjects, the verb hierarchy, `*` versus restricted refs, and `access` as the
audit query.

**Requirements.**
- A bootstrapped repo where you are the founding admin.
- Three read-only members (alice, bob, carol) plus you.
- `devs = alice, bob`; `oncall = bob`.
- `* read main`, `devs read staging`, `oncall read prod` (prod restricted).
- Proof, via `access`, that `prod` excludes everyone but `oncall` (and admins).

**Walkthrough.**
1. Bootstrap the repo so you are the root admin with both keys.
2. Add the three teammates with their `--enc` keys only.
3. Create the `devs` and `oncall` groups.
4. Issue the three grants, making `prod` need-to-know.
5. Run `access` on each branch and read the results against the model.

**Worked solution.**

```bash
$ gitsafe key gen
generated identity; share with an admin:
  gitsafe member add you --enc age1you...root... --sign 11aa...rootsign...

$ git init demo && cd demo
$ gitsafe init --user you
bootstrapped policy v0; you are admin; root pinned.

$ gitsafe member add alice --enc age1alice...recipient...
$ gitsafe member add bob   --enc age1bob...recipient...
$ gitsafe member add carol --enc age1carol...recipient...

$ gitsafe group add devs alice bob
$ gitsafe group add oncall bob

$ gitsafe grant '*'    read main      # whole team
$ gitsafe grant devs   read staging   # dev tier
$ gitsafe grant oncall read prod      # need-to-know tier (prod restricted)

$ gitsafe access main
readers of refs/heads/main: you, alice, bob, carol   (4 recipients)

$ gitsafe access staging
readers of refs/heads/staging: you, alice, bob        (3 recipients)

$ gitsafe access prod
readers of refs/heads/prod: you, bob                  (2 recipients)
```

**Explanation.** Read the three `access` outputs against the model and every
number should make sense. `main` has the whole team because `* read main` expands
to all active members, plus you (admin always reads). `staging` has you, Alice,
and Bob: the `devs` group expanded to its two members, plus you as admin —
notably *not* Carol, who is not a dev. `prod` has only you and Bob: the `oncall`
group is just Bob, and because `prod` is restricted, the `* read main` grant does
*not* bleed over even if you later widen `*` to `refs/heads/**`. The output count
in parentheses is the age-recipient count — the literal number of public keys any
secret on that branch is encrypted to. You have now expressed a real two-tier
org in six grant/group commands, and you can prove its boundaries at any time
with one command per branch.

### Mini project 2 — Prove a need-to-know branch excludes the wildcard

**Description.** Specifically demonstrate the restricted-ref guarantee: that a
`* read refs/heads/**` grant — as broad as it gets — still does not make a
restricted branch readable by the whole team. This is a focused experiment, the
kind you would run to convince a skeptical security reviewer.

**Concepts practiced.** The `*` subject, restricted refs, and using `access`
before-and-after as a controlled experiment.

**Requirements.**
- A bootstrapped repo with at least two read-only members besides you.
- A team-wide `* read refs/heads/**` grant in place.
- A restricted `prod` branch granted only to one named member.
- `access prod` showing that the wildcard does not reach `prod`, contrasted with
  `access` on a non-restricted branch where it does.

**Walkthrough.**
1. Bootstrap and add two members (alice, bob).
2. Issue the broadest possible grant: `* read refs/heads/**`.
3. Confirm with `access` that a normal branch (`staging`) is wide open.
4. Grant `bob read prod` on a restricted `prod` branch.
5. Confirm with `access` that `prod` shows only Bob and admins — the wildcard is
   suppressed.

**Worked solution.**

```bash
$ gitsafe member add alice --enc age1alice...recipient...
$ gitsafe member add bob   --enc age1bob...recipient...

$ gitsafe grant '*' read 'refs/heads/**'      # broadest possible read

# A normal branch is wide open — the wildcard reaches it.
$ gitsafe access staging
readers of refs/heads/staging: you, alice, bob    (3 recipients)

# Now lock down prod to one named member; prod is restricted.
$ gitsafe grant bob read prod

$ gitsafe access prod
readers of refs/heads/prod: you, bob              (2 recipients)
# ^ alice is absent: the '* read refs/heads/**' grant is SUPPRESSED on a
#   restricted ref. Only the named subject (bob) and admins (you) get in.
```

**Explanation.** The contrast is the whole point. On `staging`, a non-restricted
branch, the `* read refs/heads/**` grant resolves to the entire active team, so
`access` lists everyone. On `prod`, which is restricted, that very same wildcard
grant is *ignored* — the only readers are the explicitly named subject (Bob) and
the admin (you). Alice's absence from `prod`, despite the team-wide grant that
textually matches `refs/heads/prod`, is the guarantee made visible. This is
exactly the protection that keeps `refs/policy` safe: it is permanently
restricted, so no `*` grant, however broad, can ever hand out policy-change power.
If you ever need to convince yourself or a reviewer that need-to-know really holds
under a broad wildcard, this two-`access` experiment is the proof, and it relies
on nothing but the signed policy.

### Mini project 3 — Read a policy with `policy show` and explain every line

**Description.** Take a populated policy and narrate it line by line — keyring and
grants — predicting the reader set of each branch *by hand* from the model, then
checking yourself against `access`. This builds the skill of reasoning about
access without running the tool.

**Concepts practiced.** Reading `policy show` output, the verb hierarchy, member
status, group expansion, and validating a hand-derived reader set with `access`
and `policy verify`.

**Requirements.**
- A repo whose policy already has several members (one revoked), a group, and a
  mix of `*` and named grants.
- A written, by-hand prediction of who reads each branch.
- `access` confirmation of each prediction.
- A `policy verify` run to confirm the chain you are reading is authentic.

**Walkthrough.**
1. Run `policy show` and read the keyring and grants.
2. For each branch, derive the reader set on paper: match grants, apply the verb
   hierarchy, expand groups and `*`, drop revoked members.
3. Run `access` on each branch and compare to your prediction.
4. Run `policy verify` to confirm the policy is signed and intact.

**Worked solution.**

```bash
$ gitsafe policy show
policy version: 5   head: 7c1a9e...   signer: you
keyring:
  you    active   age1you...      (sign: 11aa...)
  alice  active   age1alice...
  bob    active   age1bob...      (sign: 9a1c...)
  carol  active   age1carol...
  dave   revoked  age1dave...
groups:
  devs = alice, carol
grants:
  *      read   refs/heads/main
  devs   read   refs/heads/staging
  bob    admin  refs/policy
  dave   read   refs/heads/staging

# --- by-hand prediction -------------------------------------------------
# main:    '* read main' -> all ACTIVE members -> you, alice, bob, carol
#          (dave is revoked, dropped). 4 readers.
# staging: 'devs read staging' -> alice, carol ; plus 'dave read staging'
#          but dave is REVOKED -> dropped. Admins read everything -> add
#          you and bob (bob holds admin on refs/policy ... but that's a
#          DIFFERENT resource; admin on refs/policy does NOT grant read on
#          staging). So staging = alice, carol, plus YOU as the founding
#          admin only if you hold admin on staging. Check with access.
# refs/policy: 'bob admin refs/policy' + you (root admin). 2 who may sign.
# ------------------------------------------------------------------------

$ gitsafe access main
readers of refs/heads/main: you, alice, bob, carol    (4 recipients)

$ gitsafe access staging
readers of refs/heads/staging: alice, carol           (2 recipients)

$ gitsafe policy verify
chain OK: 6 versions (v0..v5)  head 7c1a9e...  root fp 11aa...  pinned and matches ✓
```

**Explanation.** This project trains the most valuable skill in the chapter:
deriving a reader set from raw policy without the tool, then trusting `access` to
confirm it. The `main` prediction is straightforward — `*` expands to every
*active* member, and the revoked Dave is dropped, giving four. The `staging`
prediction is the instructive one: the `devs` group expands to Alice and Carol,
Dave's direct `read staging` grant is voided by his revoked status, and — the trap
— Bob's `admin` is on `refs/policy`, a *different* resource, so it does **not**
grant him read on `staging`. Grants are scoped to their resource; admin power over
the policy is not a master key to every branch. That is why `access staging`
returns just Alice and Carol. Finally, `policy verify` closes the loop: the six
versions verify, the head hash and root fingerprint match your pin, so you know
the policy you just narrated is the authentic signed chain — not something an
attacker swapped in. Being able to do this read-and-predict exercise means you
can audit any gitsafe repo by eye and use `access` only to confirm, never to
discover.

---

## Summary

This chapter gave you the access model end to end. A **member** is a name plus
public keys, and there are exactly two keys with sharply different jobs: the
`enc` (age) key that everyone needs for reading, and the `sign` (ed25519) key that
only admins need for signing policy. A **grant** is a *SUBJECT/VERB/RESOURCE*
capability; verbs form the hierarchy `admin > force > write > read` (with admin
also implying grant), so a higher verb always satisfies a lower one — which is why
granting write or admin also grants read. Subjects are members, groups, or `*`;
resources are ref globs with bare branch names as a friendly shorthand.

The idea that ties it all together is that **recipients are derived, not
declared**: gitsafe computes who a secret is encrypted to from whoever can read
its branch, so you maintain one access policy and never a separate recipient list.
`gitsafe access RESOURCE` resolves that reader set on demand and is your primary
audit query. The wildcard `*` means the whole onboarded team but never the
anonymous public; **restricted** refs suppress `*` for need-to-know secrets, and
`refs/policy` is permanently restricted so policy-change power is never handed out
wholesale. **Groups** let you grant by role and expand to their current members
everywhere access is evaluated. And the policy itself is a **signed,
content-addressed, versioned chain** under `.gitsafe/policy/` that only admins
with a sign key can extend, and that `gitsafe policy verify` checks **offline**
with nothing but the repo and a public key.

What this chapter did *not* cover is the operational reality of a living team:
people join, keys get lost or compromised, and people leave. Each of those events
moves a member or a grant — and because recipients are derived, each one demands a
follow-up so the *already-committed* ciphertext catches up with the new reader
set. That follow-up is **rotation**, and the choreography around it — onboarding a
new teammate with `onboard`, rotating a compromised key, and revoking a departing
member so they stop being a recipient going forward — is the whole subject of
**Chapter 4: Running a team — onboard, rotate, and revoke.** You now understand
*who can read what*; next you will learn how to keep that answer correct as the
team changes over time.
