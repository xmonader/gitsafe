# Chapter 4 — Running a team: onboarding, rotation, and revocation

The first three chapters were about *you*: generating an identity, wiring gitsafe
into a repository, protecting your first secret. That is the easy part, because
when you are the only reader there is nothing to coordinate. Real projects are
not solo. People join, people leave, one branch needs a wider audience than
another, and a contractor who could read production last month must not be able
to read it next month. This chapter is about the *operational* life of a
gitsafe-protected repository — the handful of commands you will type over and
over for as long as the project lives.

Everything here rests on one idea you already met in Chapter 3, so let me state
it plainly before we touch a single command: in gitsafe, **the people who can
read a branch are the people the branch's secrets get encrypted to.** There is no
separate "recipients list" you maintain by hand. You change *who may read a
branch* by editing the signed policy — adding members, granting them `read`,
revoking them — and then you run a single command, `rotate`, that re-encrypts the
files to match. Onboarding, offboarding, and access changes are all just two
moves in different orders: *change the policy*, then *re-encrypt to the new
reality.* Once that rhythm is in your fingers, the rest of this chapter is detail.

The hardest lesson in the chapter is not a command at all. It is a property of
the medium: git history is append-only, and re-encrypting today does nothing to
the ciphertext already sitting in someone's old clone. Revocation in gitsafe — in
*any* tool that stores encrypted files in git — protects the future, never the
past. I will give that its own diagram and its own worked timeline, because
getting it wrong is how teams convince themselves a leaver is locked out when he
is not. Read that section twice.

---

## Onboarding in one step

Let us start with the most common operation of all: a new teammate joins and
needs to read the secrets on a branch. Before you reach for any command, get the
mental model straight, because it explains the entire shape of the workflow. The
teammate does **not** send you a secret. They send you a *public* key — their
`enc` (age) key — which is the thing you encrypt *to*. Their private key never
leaves their machine, never enters the repo, and is never something you possess.
That asymmetry is the whole point: you can grant someone the ability to decrypt
without ever holding the means to impersonate them. Treat the `enc` string they
send like an SSH public key. It is safe to paste into Slack, email, or a ticket.

So onboarding is a two-party dance. The teammate goes first, on their own
machine. They make an identity if they do not already have one, then print the
public halves so they can send you the one you need:

```bash
gitsafe key gen          # once per machine; refuses to overwrite an existing key
gitsafe key show
# enc  (age):      age1qz...k7      <- send this one
# sign (ed25519):  3b9a...e1        (only if they'll administer policy)
```

Notice the command prints *two* keys but the comment flags only one as the thing
to send. This is the single most important nuance in team management, so I will
belabor it. A **read-only** teammate — the overwhelming majority of people you
will ever onboard — needs only their `enc` key. The `sign` (ed25519) key is for
people who will *change the policy itself*: add other members, issue grants, sign
new versions of the chain. You do not hand out signing authority to let someone
read a `.env` file. You hand it out when you are deliberately promoting someone to
administer the policy, and you do it knowingly with the `--sign` flag. If you find
yourself collecting sign keys from everyone "just in case," stop — you are
widening your trusted set for no reason.

Now your turn, as an admin who already has the repo set up and trusted. You could
do the work in three separate commands, and it is worth seeing them spelled out
once because it shows you the moving parts. You **add** the member to the keyring,
you **grant** them read on the branch, and you **rotate** so the existing
ciphertext is re-encrypted to include them:

```bash
gitsafe member add bob --enc age1qz...k7
gitsafe grant bob read main          # bare name => refs/heads/main
gitsafe rotate                       # re-encrypt secrets to include bob
git add .gitsafe .env
git commit -m "grant bob read on main"
```

Walk through why each step exists, because the separation is deliberate and you
will lean on it later. `member add` appends Bob's public key to the signed
keyring as a brand-new policy version, signed by you — it says "Bob is a member
and here is his key," but it grants him nothing. `grant bob read main` adds a
capability: Bob *may* read `refs/heads/main`. The bare name `main` is shorthand;
gitsafe expands it to `refs/heads/main` for you. But here is the subtlety that
trips up newcomers: at this point Bob is allowed to read the branch, yet the
*files already committed* are still encrypted only to you. The policy and the
ciphertext have drifted apart. `rotate` is what reconciles them — it re-runs the
encryption over every marked file so the stored blobs are now encrypted to *you +
Bob*. Without that third step, Bob would be listed in the policy and still see a
locked placeholder when he checks out the branch.

That three-command sequence is the truth of what happens, and you should
understand it. But for the common case of "add one person to one branch," typing
three commands and remembering to do all three is a footgun: forget the `rotate`
and you have shipped a policy change that does nothing visible, then spent twenty
minutes confused about why Bob still cannot read the file. So gitsafe gives you a
single command that does all three atomically, in one signed policy version, and
cannot be left half-done:

```bash
gitsafe onboard bob main --enc age1qz...k7
git add .gitsafe .env && git commit -m "onboard bob on main"
```

This is the command you will actually use. `onboard NAME BRANCH --enc age1...`
adds (or, with `--update`, updates) the member, grants them `read` on the branch,
and runs `rotate` so the branch's secrets are immediately re-encrypted to include
them — all bundled into one signed step. The flag rules are exactly the same as
`member add`: `--enc` is required and is all a read-only teammate needs; `--sign
HEX` is optional and only for someone you are promoting to administer the policy.
After it runs you still have to `git add` the changed policy and re-encrypted
secrets and commit them, because gitsafe stages the work but lets *you* own the
commit — onboarding is a change to the repo's history and it should look like one
in the log.

Why prefer `onboard` over the longhand if they do the same thing? Atomicity and
honesty. The three-command version can fail or be interrupted between steps,
leaving you with a member who is granted but whose ciphertext was never rotated —
a state that looks fine in `policy show` but does not work in practice. `onboard`
collapses that window: either the member is added, granted, and the files are
rotated, or nothing changed. The longhand still matters when you are doing
something the one-shot does not cover — onboarding someone to *several* branches
at once, or staging a batch of membership changes and rotating a single time at
the end. For that, you add and grant repeatedly and rotate last, which is more
efficient than rotating after every grant.

---

## Rotation: the verb that makes policy real

I have invoked `rotate` three times already without slowing down to explain it,
so let us fix that now, because it is the load-bearing command of the entire
chapter. Here is the core idea, and it is worth memorizing: **changing the policy
changes who is *allowed* to read; rotation changes what the ciphertext is
actually *encrypted to*.** Those are two different facts about the world, and they
can disagree. The policy lives in `.gitsafe/`; the encrypted blobs live in your
secret files. `grant`, `member add`, `member revoke` all edit the first. Only
`rotate` reconciles the second to match.

Mechanically, `gitsafe rotate` re-applies the clean filter to every marked file,
re-encrypting each one to the **current** reader set, and stages the results. It
does not commit — it leaves the changed files staged so you can review and commit
them yourself. It is also considerate about noise: it reports only the files that
actually changed, so if a rotation touches nothing (the reader set was already
correct) you get a quiet result rather than a wall of spurious diffs.

When do you run it? Any time the reader set of a branch changes. That is the rule.
Concretely:

```bash
gitsafe rotate    # after member add + grant (so the new reader can decrypt)
gitsafe rotate    # after member revoke or revoke   (so a former reader is excluded)
gitsafe rotate    # after moving a branch's grants around
```

Those three lines are identical commands — I have repeated them only to drill in
that rotation is the *follow-up* to every policy change, not a thing you do on a
schedule. (`onboard` runs it for you, which is exactly why it exists.) If you
remember nothing else about rotation, remember this: a policy change you did not
rotate is a policy change that has not taken effect on the files.

Rotation has one refusal you must understand, and it is a feature, not a bug.
Rotation **refuses to run if any marked file in your working tree is a locked
placeholder.** Think about why that has to be true. To re-encrypt a file, gitsafe
must first *read* its plaintext. A locked placeholder means you are *not* a reader
of that file — you cannot decrypt it — so you are in no position to re-encrypt it
to anyone. If gitsafe let you "rotate" a placeholder, it would either fail
obscurely or, worse, overwrite a real secret with garbage. So rotation insists on
being run by someone who can actually read every marked file. The practical
consequence: rotation is an admin-and-reader operation. The person rotating must
be a reader of the branches whose secrets they are rotating. If you see `cannot
rotate: X is locked`, you are missing read access to file `X` — fix the grant or
have a full reader do the rotation.

And now the property that earns its own section later but that you must already
have in mind every time you type `rotate`: **rotation is forward-only.** It
changes the blobs from this commit forward. It does not, and cannot, reach back
and rewrite the ciphertext already recorded in git history. Hold that thought; we
return to it with a timeline.

---

## Revoking access

Revocation is where the stakes get real, so I want to separate two operations
that people conflate and that gitsafe treats differently. You can cut *one
specific grant* — "Carol may no longer read production, but she stays a member
and keeps her other access" — or you can revoke *the member entirely* — "Carol is
gone, remove her from everything." Different commands, different blast radius,
and choosing the wrong one is a common mistake.

To remove a single grant, you name it precisely: subject, verb, resource, exactly
as it was granted. This is surgical — it touches one capability and leaves
everything else about the member intact:

```bash
gitsafe revoke carol read production
gitsafe rotate
git add .gitsafe .env && git commit -m "cut carol's production read"
```

`revoke SUBJECT VERB RESOURCE` removes a previously-added grant matching exactly
that triple. If there is no such grant it errors rather than silently doing
nothing — which is the behavior you want, because a "revoke" that quietly
succeeds while removing nothing is how access lingers undetected. The follow-up
`rotate` is mandatory if you removed read access: until you rotate, production's
secrets are still encrypted to Carol's key, grant or no grant. The grant said
"may read"; the ciphertext is what actually lets her read. Remove the grant,
rotate to re-encrypt without her, then commit both.

When someone leaves the project entirely, you do not want to chase down their
individual grants. You revoke the member, which excludes them from every
recipient set in one move:

```bash
gitsafe member revoke carol
gitsafe rotate
git add .gitsafe .env          # plus any other marked files rotate restaged
git commit -m "offboard carol"
git push
```

`member revoke NAME` marks Carol's keyring entry `revoked`. The recipient
computation drops revoked members unconditionally — step three of the recipient
algorithm is literally "drop any member whose status is revoked" — so after the
next `rotate` she is excluded from *every* branch's ciphertext, regardless of how
many grants she had. The grants themselves can stay in the policy; they are
inert because the member behind them is revoked. This is the right tool for
offboarding: one command, total exclusion, no archaeology.

Now the guardrail that will save you from a self-inflicted catastrophe. gitsafe
**refuses to revoke the last usable admin.** A "usable admin" is an active member
who holds `admin` *and* has a signing key — in other words, someone who can
actually sign new policy versions. If you could revoke the last one, you would
strand the policy: there would be nobody left who can sign any further change, so
you could never add members, never rotate the chain forward, never recover. The
policy would be bricked, cryptographically, forever. So the engine checks every
policy change and rejects any that would leave no usable admin. The same logic
blocks stripping the admin grant or signing key from the last one. This is why
the User Guide hammers on having **more than one admin**: not for convenience, but
so that losing or revoking one admin is a recoverable event rather than a dead
repository. If you run a team on gitsafe, promote a second admin early — with
`member add NAME --sign HEX` and a `grant NAME admin refs/policy` — and treat it
as part of bootstrapping, not an afterthought.

---

## The un-revoke path

People come back. A contractor returns for phase two, an employee rejoins, or you
revoked someone in haste and need to undo it. gitsafe does not make you delete
and recreate a member from scratch; revocation is a *status*, not a deletion, and
it is reversible. The keyring entry still exists with status `revoked`; bringing
the person back is a matter of flipping that status and supplying a current key.

The command that does it is `member add` with `--update`:

```bash
gitsafe member add carol --update --enc age1new...key
gitsafe rotate
git add .gitsafe .env && git commit -m "reinstate carol"
```

The `--update` flag is what makes this work. Without it, `member add` refuses to
touch an existing member (it will not silently overwrite a key — a safety
property). *With* `--update`, two things happen: the member's `enc` key is
replaced with whatever you supply, **and the member is reactivated** — status goes
from `revoked` back to `active`. That reactivation is the un-revoke. The reason
the same command handles "rejoin," "I lost my laptop and have a new key," and
"undo an accidental revoke" is that they are mechanically identical: update the
key on file, set the member active, sign a new policy version. If the returning
person is an admin, add `--sign HEX` too; if you omit it on `--update`, an
existing sign key is preserved rather than dropped, so you do not accidentally
demote someone by forgetting the flag.

As always, `member add --update` changes the *policy* — it does not re-encrypt
anything. The follow-up `rotate` is what re-includes the reinstated member in the
current ciphertext so they can actually read again. By now that should feel
automatic: any command that changes who-may-read is followed by `rotate` to make
the ciphertext agree.

---

## The critical caveat: rotation is forward-only

Now the section that matters most, and the one teams get dangerously wrong.
Everything above made it sound like revoking Carol and rotating locks her out.
For *future* secrets, it does. For the secrets that already existed when she had
access, **it does not, and it cannot.** I need you to internalize this, because
the failure mode is silent: you offboard someone, the commands all succeed, the
policy looks clean, and you walk away believing the secret is safe when a copy of
it is sitting decryptable in a clone you do not control.

Here is the mechanism, with no hand-waving. A git repository's history is
append-only. When you committed `.env` last March encrypted to *you + Carol*, that
ciphertext is now a permanent object in the repo's history. Carol cloned the repo.
That clone — every packfile in it — still contains that March blob, and Carol's
key still opens it, because it was encrypted to her at the time. Running `rotate`
today writes a *new* blob at the *current* commit, encrypted to *you* alone. It
does not, and cannot, reach into the historical commit and re-encrypt the old
blob; rewriting history would mean rewriting every commit hash since, breaking
every clone and signature. So the old, Carol-readable ciphertext lives on. She
does not even need network access to read it — it is on her disk.

Let me draw the timeline, because seeing it laid out is what makes it stick:

```
   POLICY / CIPHERTEXT TIMELINE  (what rotation does and does not touch)

   commit A          commit B            commit C  (you run rotate here)
   ───────●──────────────●──────────────────●────────────────▶  history
          │              │                  │
   enc to: you+carol   you+carol          you            <- NEW blob, no carol
          │              │                  │
          ▼              ▼                  ▼
   ┌───────────────────────────────┐   ┌──────────────┐
   │  HISTORICAL blobs (A, B)       │   │ CURRENT blob │
   │  still encrypted to carol      │   │ (C) excludes │
   │  ── rotate does NOT touch ──   │   │ carol        │
   │  carol's old clone decrypts    │   │ carol locked │
   │  them OFFLINE, forever         │   │ out going fwd│
   └───────────────────────────────┘   └──────────────┘
          ▲                                  ▲
          │                                  │
   THE SECRET VALUE is identical in A, B, and C
   ── so reading the OLD blob reveals the value still live in C ──
```

Stare at the bottom line, because it is the part people miss. Rotation excludes
Carol from commit C's blob, yes. But if the *value* of the secret — the actual
database password, the actual API key — is the same in commit C as it was in
commit A, then Carol reading the old commit A blob learns a password that is
*still in use*. The encryption changed; the secret did not. She does not need to
read commit C. She already has the answer.

So the rule, stated as an operational procedure: **after offboarding anyone who
had access to a live secret, change the secret's value itself.** Issue a new
database password and update the secret to hold it. Roll the API key at the
provider and commit the new one. Treat the offboarding exactly as you would treat
a credential leak — because, from the secret's point of view, it *is* one. The
moment Carol had a copy of ciphertext encrypted to her key, the underlying value
was compromised for any future in which that value stays the same. Rotating the
*gitsafe recipients* stops the bleeding going forward; rotating the *secret value*
is what actually closes the exposure.

The full offboarding procedure, then, is not "revoke and rotate." It is four steps,
and skipping the last is the mistake:

```
   CORRECT OFFBOARDING  (the order matters; step 4 is the one people skip)

   1. member revoke carol         <- policy: carol is out
   2. gitsafe rotate              <- ciphertext: current blobs exclude carol
   3. git commit / push           <- the change is now in the repo
   4. CHANGE THE SECRET VALUE:    <- the actual mitigation
        - issue new DB password
        - roll the API key at the provider
        - put the NEW value in .env, then rotate+commit AGAIN
      ── now carol's old clone holds a DEAD secret ──
```

Step 4 is what turns Carol's hoarded historical ciphertext from a live credential
into a worthless string. After you rotate the *value*, her old clone decrypts to
the *old* password — which no longer authenticates anything. That is the
difference between "we revoked her in gitsafe" and "she actually cannot get in."

I want to be clear this is not a gitsafe limitation you could fix by choosing a
different tool. It is inherent to encryption-at-rest layered over an append-only
history. git-crypt, sops-in-git, sealed secrets in a git repo — all of them have
exactly this property, because all of them store the ciphertext in commits that
former readers already pulled. Any tool that tells you revocation retroactively
protects history is lying or confused. gitsafe is honest about it, which is why
the docs, the error messages, and this chapter all push you toward rotating the
value. Build the four-step procedure into your offboarding checklist and you will
never be caught believing a leaver is locked out when he is one `git log` away
from a live password.

---

## Auditing and visibility

You cannot run access control you cannot see. Periodically — and certainly during
a security review or a compliance audit — you need to answer three questions: who
can read this branch *right now*, how did that change *over time*, and what is *my
own* standing. gitsafe answers all three offline, with no server to query,
because the entire policy is in the repo and signed.

Start with the *now* question, which is the one you ask most. `gitsafe access
RESOURCE` resolves the live reader set for a branch — it expands groups, includes
admins (admin implies read), resolves public (`*`) grants to concrete members,
and drops anyone revoked, then prints the result:

```bash
gitsafe access production
# refs/heads/production
#   readers:    alice, carol
#   encrypts to 2 age recipient(s)
```

The value here is that it shows you *effective* access, not raw grants. If you
granted a group, you see the people, not the group name. If an admin has no
explicit read grant, you still see them, because admin satisfies read. The
"encrypts to N recipients" line is your sanity check: it is the number of age keys
the next commit on this branch will be encrypted to, and it should match the
number of names. If you just revoked someone and `access` still lists them, you
forgot to rotate — `access` reads the policy, and the policy already excludes them,
but this is your cue that the *ciphertext* may not yet.

The *over time* question is the compliance one: "who could read production, and
when did that change?" That is what `gitsafe audit` answers. Given a resource, it
replays the signed policy chain and prints the reader set at every version,
flagging the versions where it changed:

```bash
gitsafe audit production
# access history for refs/heads/production
#   v0   by alice          alice          <- changed
#   v5   by alice          alice, carol   <- changed
#   v7   by alice          alice, carol
```

Read that as a story: at v0 only Alice could read production; at v5 Carol was
added (the line is flagged `changed`); at v7 nothing about production's readers
changed even though the policy advanced (some other branch's grant moved). Because
every version is signed and chained, this history is *tamper-evident* — you are
not trusting a log file someone could edit; you are reading the cryptographically
verified chain itself. Run `gitsafe audit` with **no** resource and it prints the
full grant history version by version, which is the broad "what happened to this
policy over its whole life" view.

Finally, the *me* question. `gitsafe whoami` is your self-check before you do
anything as an admin or wonder why you cannot read something:

```bash
gitsafe whoami
```

It prints your configured user name, your local identity's public keys, your
status in the keyring, an integrity check that your local identity actually
matches your keyring entry, and the grants where you are the direct subject. That
integrity check is more useful than it sounds: if your local `gitsafe.user` name
or your identity keys have drifted from what the keyring records, your signed
policy changes will not verify, and `whoami` is where you catch it before it
confuses you mid-operation.

---

## Preventing plaintext leaks

There is one failure mode that no amount of careful policy management protects
against, because it happens *before* gitsafe's encryption ever runs: committing a
marked secret as **plaintext** because the filters were not active. Picture the
scene. Someone clones the repo and, before running `gitsafe init`, edits `.env`
and commits. git has no `gitsafe` clean filter wired up yet in that fresh clone,
so it stores exactly what is in the working tree — plaintext. Or a CI runner is
misconfigured and the filter never engages. Either way, your secret lands in
history in the clear, and every reader of the repo can see it. The encryption
machinery is irrelevant because it never got a turn.

`gitsafe check` exists precisely to catch this. It inspects the staged tree and
**fails** if any gitsafe-marked file is about to be committed as plaintext. It
does not encrypt anything; it just refuses to let an unencrypted secret through.
Because it is a yes/no gate, the natural place for it is a git hook that runs
before every commit:

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
exec gitsafe check
EOF
chmod +x .git/hooks/pre-commit
```

That snippet writes a pre-commit hook that runs `gitsafe check` and lets the
commit proceed only if it passes. The `exec` is a small nicety — it replaces the
shell with `gitsafe check` so the check's exit status becomes the hook's exit
status directly. Now any commit that would stage a marked secret as plaintext is
blocked at the source, on this machine, before it can become history.

But notice the path: `.git/hooks/pre-commit` lives under `.git/`, which is
*per-clone and not committed*. The hook protects *your* clone and nobody else's.
That is the same per-clone reality you met with filters and trust — `.git/` does
not travel. If you want the protection to apply to everyone who clones the repo,
you cannot rely on each person remembering to install a hook. Instead, point git
at a *tracked* hooks directory once, and commit the hook there:

```bash
git config core.hooksPath .githooks
# then commit .githooks/pre-commit containing: #!/bin/sh\nexec gitsafe check
```

`core.hooksPath` tells git to look in `.githooks/` (a normal, committed directory)
instead of `.git/hooks/`. Because that directory is part of the repo, the hook
travels — though each person still runs `git config core.hooksPath .githooks`
once per clone to opt in, since the *config setting* itself lives in `.git/config`
and does not travel. It is a meaningful improvement over per-clone hooks: the hook
*content* is shared and reviewed in the repo, so you are not trusting everyone to
write their own.

The hook defends the human at their keyboard. CI defends the pipeline, and you
should run `gitsafe check` there too, as a belt-and-braces final gate. A CI runner
is just another clone, so the same risk applies — a misconfigured runner that
never wired the filter could push plaintext. After CI sets up its identity, wires
filters, and pins trust, end the setup with a `gitsafe check` so a leak fails the
build instead of merging:

```bash
gitsafe init --user ci-runner
gitsafe trust --fingerprint "$EXPECTED_ROOT_FINGERPRINT"
git checkout -- .
gitsafe check    # belt and braces: fail the build if any marked secret is plaintext
```

Two gates — a local pre-commit hook and a CI check — give you defense in depth.
The hook catches the mistake early, where it is cheapest to fix; the CI check
catches it when the hook was skipped (someone committed with `--no-verify`, or on
a machine where the hook was never installed). Neither replaces the encryption;
both ensure the encryption actually ran.

---

## Exercises

These move from recalling what a command does, through applying the workflow, to
designing and debugging real situations. Work them with a throwaway repo if you
can — the muscle memory is the point.

### Exercise 1 (recall)

**Problem.** A teammate is about to onboard. Which one of their two public keys do
they send you for *read-only* access, and which command do they run to see it?

**Solution.**

```bash
gitsafe key show
# enc  (age):      age1qz...k7   <- send this
# sign (ed25519):  3b9a...e1     <- NOT needed for read-only
```

They send the **`enc` (age)** key. **Explanation.** An identity holds two keys
with two jobs: the age `enc` key *receives* encrypted secrets, and the ed25519
`sign` key *signs* policy changes. Reading a secret means being a recipient, which
requires only the `enc` key. The `sign` key conveys the power to administer the
policy and is supplied with `--sign` only when promoting an admin. Sending the
sign key for a read-only teammate needlessly widens who *could* hold signing
authority, so the discipline is to send the minimum: the `enc` key alone.

### Exercise 2 (recall)

**Problem.** Name the three operations `gitsafe onboard bob main --enc age1...`
performs, and state what you must still do afterward.

**Solution.** It (1) adds Bob to the keyring, (2) grants him `read` on
`refs/heads/main`, and (3) runs `rotate` to re-encrypt the branch's secrets to
include him — all in one signed policy version. Afterward you must `git add
.gitsafe` and the re-encrypted secrets and `git commit`. **Explanation.**
`onboard` is the atomic equivalent of `member add` + `grant ... read main` +
`rotate`, collapsing the window in which you could leave the work half-done.
Crucially it *stages* but does not *commit*: the changed policy and ciphertext
are left staged so you own the commit, since onboarding is a change to history and
should appear as a deliberate commit in the log. Forgetting the commit leaves the
work in your working tree only, where a teammate's pull will never see it.

### Exercise 3 (apply)

**Problem.** Bob and Carol are already members. Grant Bob read on `staging`,
grant Carol read on both `staging` and `production`, then make the ciphertext
reflect it — with a single rotation.

**Hint.** Stage all the grants first; rotate once at the end.

**Solution.**

```bash
gitsafe grant bob   read staging
gitsafe grant carol read staging
gitsafe grant carol read production
gitsafe rotate
git add .gitsafe && git commit -m "branch-scoped read grants"
```

**Explanation.** Each `grant` edits the policy to add one capability; none of them
touch ciphertext. Because rotation reconciles *all* current grants at once, you do
not rotate after every grant — you batch the policy edits and rotate a single
time, which is both faster and produces one clean commit instead of three. This is
exactly the case the longhand serves better than `onboard`: multiple grants across
multiple branches, reconciled in one pass. Note that the recipients are computed
*per branch*, so after this `production`'s blobs encrypt to Alice+Carol while
`staging`'s encrypt to Alice+Bob+Carol — the same filename, different recipients,
depending on the branch you commit from.

### Exercise 4 (apply)

**Problem.** Carol should keep her membership and her `staging` access but lose
access to `production`. Do it correctly.

**Solution.**

```bash
gitsafe revoke carol read production
gitsafe rotate
git add .gitsafe .env && git commit -m "cut carol's production read"
```

**Explanation.** Because you are cutting *one capability* and not the member, you
use `revoke SUBJECT VERB RESOURCE`, naming the grant exactly as it was issued.
`member revoke` would be wrong here — it would remove Carol from *every* branch,
including `staging` where she should remain. The `rotate` is non-optional: until
you rotate, production's committed secrets are still encrypted to Carol's key, so
removing the grant alone changes who is *allowed* but not what the ciphertext
*contains*. And if `production` holds a live secret, this exercise is incomplete
without rotating the secret *value* too — see Exercise 8.

### Exercise 5 (create)

**Problem.** Design and run the full, correct offboarding of Carol, who is leaving
the company and had read access to a production database password. List every step
including the one most people skip.

**Solution.**

```bash
# 1. Remove her from the policy entirely.
gitsafe member revoke carol
# 2. Re-encrypt current ciphertext to exclude her.
gitsafe rotate
# 3. Commit and push the recipient change.
git add .gitsafe .env && git commit -m "offboard carol" && git push
# 4. THE STEP PEOPLE SKIP: change the secret value itself.
#    Issue a new DB password at the provider, then:
echo "DB_PASSWORD=$(new-strong-password)" > .env
gitsafe rotate
git add .env && git commit -m "rotate db password after offboarding" && git push
```

**Explanation.** Steps 1–3 stop Carol from reading *future* ciphertext, but her
old clone still holds the production password encrypted to her key from when she
had access — and rotation is forward-only, so it cannot scrub that historical
blob. As long as the password's *value* is unchanged, that old blob is a live
credential. Step 4 is the actual mitigation: by issuing a new password and
committing it, Carol's hoarded ciphertext now decrypts to a dead value. Treat
every offboarding of a live-secret reader as a credential leak, because that is
precisely what it is.

### Exercise 6 (create)

**Problem.** Carol, whom you revoked last month, is rejoining with a new key
(`age1new...`). Reinstate her with read on `main` and make it effective. She is
read-only.

**Solution.**

```bash
gitsafe member add carol --update --enc age1new...key
# (if her old grants were removed, re-add them; member revoke leaves them inert)
gitsafe rotate
git add .gitsafe .env && git commit -m "reinstate carol on main"
```

**Explanation.** `member add --update` is the un-revoke path: it replaces Carol's
`enc` key *and* flips her status from `revoked` back to `active` in one signed
version. The `--update` flag is required because plain `member add` refuses to
overwrite an existing member — a deliberate guard against silently replacing
someone's key. Because revocation left her grants inert rather than deleting them,
she may regain her old access automatically once active; if you had explicitly
`revoke`d specific grants, re-add them. As always, `rotate` is what re-includes
her in the current ciphertext.

### Exercise 7 (debug)

**Problem.** You ran `gitsafe member revoke carol` and committed. A week later
Carol pings you a screenshot of the production `.env` in plaintext, from her
laptop. You did not rotate the secret value. What happened, and was revocation
broken?

**Solution.** Revocation was not broken. Carol is reading the *historical*
ciphertext in her old clone — a blob that was encrypted to her key back when she
had access — and decrypting it with her still-valid private key. The fix is to
change the secret's value (issue a new password) and commit it, so her old blob
becomes worthless.

**Explanation.** `member revoke` plus `rotate` only changes who *future* blobs are
encrypted to; git history is append-only and the March blob encrypted to Carol is
permanent and on her disk. Her decryption needs no network and no policy access —
her private key alone opens any blob ever encrypted to it. This is the forward-only
property in action, and it is inherent to encrypted-files-in-git, not a gitsafe
bug. The only thing that neutralizes the leak is rotating the secret *value*; the
recipient rotation you already did simply stops the *next* secret from being
exposed.

### Exercise 8 (debug)

**Problem.** You try to offboard a teammate and run `gitsafe rotate`, but it fails
with `cannot rotate: secrets/db.key is locked`. The policy change committed fine.
Why is rotation refusing, and how do you proceed?

**Solution.** Rotation refuses because *you* hold a locked placeholder for
`secrets/db.key` — you are not a reader of that file, so you cannot decrypt it,
and therefore cannot re-encrypt it. Have someone who *is* a reader of every marked
file run the rotation, or grant yourself read on the relevant branch first, then
rotate.

**Explanation.** To re-encrypt a file, gitsafe must read its plaintext; a locked
placeholder means you lack that access. Letting a non-reader "rotate" would risk
overwriting a real secret with placeholder text, so rotation fails closed. The
operational lesson is that whoever performs offboarding rotations must be a full
reader of the affected branches — which is one more reason admins are typically
granted broad read access. Fix the missing grant, or delegate the rotation to a
full reader, then re-run.

### Exercise 9 (extend)

**Problem.** Set up the repo so that *any* commit anywhere — by you or a future
teammate who forgot to run `gitsafe init` — is blocked from staging a marked
secret as plaintext, with the protection shared in the repository.

**Solution.**

```bash
mkdir -p .githooks
printf '#!/bin/sh\nexec gitsafe check\n' > .githooks/pre-commit
chmod +x .githooks/pre-commit
git add .githooks/pre-commit && git commit -m "shared pre-commit: gitsafe check"
git config core.hooksPath .githooks   # each clone runs this once to opt in
```

**Explanation.** A hook in `.git/hooks/` is per-clone and protects only your
machine; committing the hook into a tracked `.githooks/` directory shares its
*content* so it is reviewed and travels with the repo. `gitsafe check` fails the
commit if any marked file is staged as plaintext — the exact footgun that occurs
when filters are inactive in a fresh or misconfigured clone. The one residual
manual step is `git config core.hooksPath .githooks` per clone, because the config
setting lives in `.git/config` and does not travel; you cannot fully eliminate
per-clone setup, but you can reduce it to a single documented line.

### Exercise 10 (extend)

**Problem.** Before a compliance review, produce two artifacts: who can read
`production` *right now*, and how `production`'s readers changed across the
policy's history. Which commands, and how do you trust the output?

**Solution.**

```bash
gitsafe access production    # current effective readers
gitsafe audit production     # reader set at every policy version, changes flagged
gitsafe policy verify        # confirm the chain's signatures and pin match
```

**Explanation.** `access` answers "now" by resolving the live policy — expanding
groups and admins, dropping revoked members — to concrete names plus the
age-recipient count. `audit production` answers "over time" by replaying the
signed chain and printing the reader set at each version, flagging changes, which
is the tamper-evident history an auditor wants. The reason you can *trust* these
outputs is `policy verify`: it walks the chain checking every ed25519 signature
and that each change came from an admin, then reports whether the root matches
your local pin. Together they let you assert, with cryptographic backing rather
than a mutable log, who could read what and when.

---

## Mini Projects

These are end-to-end exercises on a throwaway repo. They use multiple identities
on one machine via the `GITSAFE_IDENTITY` environment variable, which points
gitsafe at a specific identity file — the same mechanism used for CI identities.
Run them in a scratch directory; the goal is to *see* the behavior, not to keep
the repo.

### Mini Project 1 — Onboard two teammates and prove a third is locked out

**Description.** Stand up a repo as Alice, onboard Bob and Carol to `main`, and
demonstrate that an un-onboarded fourth identity (Dave) sees a locked placeholder
instead of the secret. This proves that access is real, not cosmetic.

**Concepts practiced.** `key gen` with `GITSAFE_IDENTITY`, `init` as founding
admin, `onboard`, `access`, and observing a locked placeholder via smudge.

**Requirements.** gitsafe and git on `PATH`. A scratch directory you can delete.

**Walkthrough.** Create four identity files. Bootstrap the repo as Alice. Collect
Bob's and Carol's `enc` keys and onboard each to `main`. Commit a secret. Then,
*as Dave*, check out the file and observe a placeholder; confirm with `access`
that Dave is not a reader.

**Worked solution.**

```bash
mkdir demo1 && cd demo1 && git init -q

# Four separate identities on one machine.
for u in alice bob carol dave; do
  GITSAFE_IDENTITY=./id-$u gitsafe key gen >/dev/null
done

# Grab Bob's and Carol's public enc keys.
BOB_ENC=$(GITSAFE_IDENTITY=./id-bob   gitsafe key show | awk '/enc/{print $3}')
CAR_ENC=$(GITSAFE_IDENTITY=./id-carol gitsafe key show | awk '/enc/{print $3}')

# Alice bootstraps the repo and becomes founding admin.
GITSAFE_IDENTITY=./id-alice gitsafe init --user alice
echo "DB_PASSWORD=hunter2" > .env

# Alice onboards Bob and Carol to main, one signed step each.
GITSAFE_IDENTITY=./id-alice gitsafe onboard bob   main --enc "$BOB_ENC"
GITSAFE_IDENTITY=./id-alice gitsafe onboard carol main --enc "$CAR_ENC"
git add .gitsafe .gitattributes .env && git commit -qm "onboard bob+carol"

# Who can read main now?
GITSAFE_IDENTITY=./id-alice gitsafe access main
# refs/heads/main
#   readers:    alice, bob, carol
#   encrypts to 3 age recipient(s)

# Now act as Dave, who was never onboarded. Re-smudge the file as Dave.
GITSAFE_IDENTITY=./id-dave git checkout -- .env
GITSAFE_IDENTITY=./id-dave cat .env
# >>> gitsafe locked <<<  (a placeholder: Dave is not a recipient)
```

**Explanation.** Each `GITSAFE_IDENTITY=./id-X` invocation makes gitsafe use a
different person's keys, simulating four machines on one. Alice's `init` makes her
the founding admin and pins trust automatically. `onboard` adds each teammate,
grants read on `main`, and rotates — so the committed `.env` is encrypted to three
age recipients, which `access main` confirms. The decisive moment is Dave: his
smudge filter runs with *his* key, finds he is not a recipient, and writes a
locked placeholder rather than failing the checkout. Access is enforced by
cryptography, not by a flag you could flip — Dave literally cannot produce the
plaintext.

### Mini Project 2 — Offboard someone correctly, including rotating the value

**Description.** Continue from a repo where Carol can read `main`. Offboard her
the *right* way: revoke, rotate recipients, then change the secret value and
rotate again. Prove that her old clone reads a dead secret while the live secret
is now something she never saw.

**Concepts practiced.** `member revoke`, forward-only rotation, the four-step
offboarding procedure, and the distinction between rotating *recipients* and
rotating the *value*.

**Requirements.** A repo with Alice (admin) and Carol (reader) on `main`, and a
committed secret. Simulate Carol's old clone by saving the historical ciphertext
before you rotate the value.

**Walkthrough.** Snapshot the secret Carol could read (her "old clone"). Revoke
Carol and rotate. Then change the password and rotate again. Decrypt the snapshot
as Carol to show she gets the *old* value; decrypt the live file as Alice to show
the *new* value. The two differ — that gap is your security margin.

**Worked solution.**

```bash
# Starting point: Carol is a reader of main; .env holds the live password.
GITSAFE_IDENTITY=./id-alice gitsafe access main
# readers: alice, carol

# Carol's "old clone": the ciphertext she already pulled, saved off to the side.
git cat-file blob HEAD:.env > carol-old-clone.blob

# --- Steps 1-3: remove Carol from FUTURE ciphertext. ---
GITSAFE_IDENTITY=./id-alice gitsafe member revoke carol
GITSAFE_IDENTITY=./id-alice gitsafe rotate
git add .gitsafe .env && git commit -qm "offboard carol"

# Carol's old blob STILL decrypts for her — forward-only rotation didn't touch it.
GITSAFE_IDENTITY=./id-carol gitsafe smudge .env < carol-old-clone.blob
# DB_PASSWORD=hunter2     <- the LIVE password, readable by a revoked member!

# --- Step 4: the real fix. Change the secret VALUE. ---
echo "DB_PASSWORD=s3cret-rolled-9f2a" > .env
GITSAFE_IDENTITY=./id-alice gitsafe rotate
git add .env && git commit -qm "rotate db password after offboarding"

# Now Carol's old blob decrypts to a DEAD value...
GITSAFE_IDENTITY=./id-carol gitsafe smudge .env < carol-old-clone.blob
# DB_PASSWORD=hunter2     <- old, no longer authenticates anything

# ...while the live secret is something Carol never had.
GITSAFE_IDENTITY=./id-alice cat .env
# DB_PASSWORD=s3cret-rolled-9f2a
```

**Explanation.** The saved `carol-old-clone.blob` stands in for the packfiles a
real leaver keeps on their disk. After steps 1–3 — revoke, rotate, commit — Carol
is excluded from all *new* ciphertext, yet her saved blob still decrypts to the
live password `hunter2`, because forward-only rotation cannot reach historical
objects. That single line of output is the entire lesson: the offboarding "looked
done" but the secret was still exposed. Step 4 changes the value to
`s3cret-rolled-9f2a`; now Carol's blob decrypts to the *old, dead* password while
the live secret is one she never possessed. The recipient rotation protected the
future; the value rotation closed the past.

### Mini Project 3 — Install a pre-commit hook and catch a simulated leak

**Description.** Wire `gitsafe check` as a pre-commit hook, then simulate the
classic plaintext leak — a clone where the filters are not active — and watch the
hook block the commit.

**Concepts practiced.** `gitsafe check`, pre-commit hooks, and reproducing the
filters-not-active footgun safely.

**Requirements.** A gitsafe repo with a marked secret and at least one reader so
encryption can succeed.

**Walkthrough.** Install the hook. Confirm a normal, properly-encrypted commit
passes. Then simulate an inactive-filter clone by removing the gitsafe filter
config and writing a plaintext secret, stage it, and attempt a commit — the hook
should fail it. Restore the filter and confirm commits pass again.

**Worked solution.**

```bash
# Install the local pre-commit hook.
printf '#!/bin/sh\nexec gitsafe check\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# A normal commit with filters active: check passes, commit succeeds.
echo "API_KEY=live_abc123" > .env
git add .env
git commit -qm "add api key (encrypted)" && echo "OK: committed encrypted"
# OK: committed encrypted

# Simulate a clone where the gitsafe filter is NOT active.
git config --unset filter.gitsafe.clean
git config --unset filter.gitsafe.smudge
echo "API_KEY=this-would-leak-as-plaintext" > .env
git add .env           # no clean filter ran -> staged as PLAINTEXT

# The hook catches it: gitsafe check fails, commit is blocked.
git commit -m "oops, plaintext" || echo "BLOCKED by gitsafe check"
# gitsafe: .env is staged as plaintext but is a marked secret
# BLOCKED by gitsafe check

# Restore the filter and re-stage; now the secret encrypts and the commit passes.
GITSAFE_IDENTITY=./id-alice gitsafe init --user alice
git add .env
git commit -qm "api key (encrypted again)" && echo "OK: re-encrypted"
# OK: re-encrypted
```

**Explanation.** Unsetting `filter.gitsafe.clean/smudge` faithfully reproduces the
real footgun: a fresh or misconfigured clone where `git add` does *not* pipe the
file through gitsafe, so the plaintext secret is staged as-is. Without the hook,
that commit would land a live API key in history. With the hook, `gitsafe check`
inspects the staged tree, sees a marked file staged as plaintext, and exits
non-zero — which aborts the commit. Re-running `gitsafe init` restores the filter,
the next `git add` encrypts properly, and the check passes. This is exactly why
the hook belongs in CI as well: the local hook is per-clone and skippable with
`--no-verify`, so a second `gitsafe check` gate in the pipeline catches what slips
past the keyboard.

---

## Summary

This chapter was the operational core of running gitsafe with other people, and
it reduces to a rhythm you should now feel: every change to *who may read* — an
`onboard`, a `grant`, a `member revoke`, a `revoke`, an un-revoke via `member add
--update` — is followed by a `rotate` to make the ciphertext agree, and then a
commit so the change becomes shared history. `onboard` is the one-shot you will
reach for most because it bundles add, grant, and rotate atomically; the longhand
is there for batch changes across branches. You learned that gitsafe protects you
from bricking the policy by refusing to revoke the last usable admin, which is why
you promote a second admin early.

The lesson to carry above all others is the forward-only nature of rotation.
Re-encrypting excludes a leaver from *future* blobs but cannot touch the history
their old clone already holds, so correct offboarding always ends with rotating
the secret *value itself* — treat a departure like the credential exposure it is.
You also picked up the audit surface — `access` for who can read now, `audit` for
how that changed over time, `whoami` for your own standing — and the two leak
gates, a pre-commit hook running `gitsafe check` and the same check in CI, that
stop a plaintext secret from ever reaching history when the filters are not
active.

Chapter 5 turns from operations to foundations: **trust, security, and recovery.**
We will dig into the trust model you have been pinning with `gitsafe trust` — why
TOFU root pinning works, what a fingerprint mismatch really means, and how the
high-water mark stops an attacker from replaying an old policy to resurrect a
revoked reader. We will lay out the threat boundaries honestly: what gitsafe
defends against (tampered policies, swapped roots, plaintext leaks) and what it
explicitly does not (an attacker inside your `.git/`, server-side push
enforcement, read-after-revocation — the very property this chapter taught you to
mitigate by rotating values). And we will cover the part nobody thinks about until
it is too late: **recovery** — what to do when an identity is lost, why there is
deliberately no escrow key, and how re-enrolment rather than decryption is the
path back. By the end of it you will not just operate gitsafe; you will understand
exactly how much it is promising you, and how to be safe in the gaps it honestly
leaves open.
