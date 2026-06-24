# Chapter 5 — Trust, security, and recovery

This is the capstone. The first four chapters taught you to *use* gitsafe: how
identities work, how the signed policy chain decides who reads which branch, how
the clean and smudge filters turn marked files into branch-scoped ciphertext, and
how rotation moves access forward. That knowledge makes you productive. This
chapter makes you *safe*. By the end you should be able to look at any gitsafe
repository and reason, out loud and correctly, about exactly what it guarantees,
what it does not, and where the sharp edges are.

Security tools fail in a particular and miserable way: they keep working, look
fine, produce no errors, and quietly protect nothing. A backup that silently
stops running. A TLS check that always returns "valid". A policy chain you trust
because it verifies against itself. The entire job of this chapter is to inoculate
you against that class of failure with gitsafe specifically. We will not hand-wave.
Every guarantee gets traced to the mechanism that enforces it, and every gap gets
named in plain language so you can plan around it instead of being surprised by it.

The teaching order is deliberate. We start with the foundational problem — *why a
self-signed policy proves nothing about identity* — because every other defense in
gitsafe is a response to that one inconvenient truth. From there we build outward:
trust-on-first-use pinning (the answer to chain *replacement*), rollback protection
(the answer to chain *replay*), encrypted merges (the place where decryption and
re-encryption meet conflict resolution), key loss and recovery (what happens when a
human loses the one thing that can't be regenerated), and finally an honest, almost
adversarial inventory of what gitsafe deliberately leaves to you.

---

## 5.1 The trust problem: why a signature is not an identity

Before we can appreciate the defense, we have to feel the attack. gitsafe's policy
is a chain of signed versions. Version 0 — the root — is *self-signed* by the
founding admin: the same key that the root names as authoritative is the key that
signed the root. Walk that sentence slowly, because the circularity is the whole
problem. A self-signed root proves *internal consistency*: it proves that whoever
made this chain controlled the key the chain claims to trust, and that nobody has
tampered with the bytes since. It proves the chain is a coherent, untampered
artifact. It proves *absolutely nothing* about *whose* key that root is.

Why does that matter? Because the repository is *untrusted* by design. Anyone who
can open a pull request, who has compromised a collaborator's push access, or who
controls the git host can replace the entire `.gitsafe/policy/` directory with a
*different* chain that is *also* perfectly self-consistent — signed end to end by a
brand-new root key that the attacker generated this morning. Run `gitsafe policy
verify` against that swapped chain and it will pass every structural check: every
signature verifies, every parent link resolves, every version is signed by an admin
of its parent. The chain is valid. It is just not *yours*.

The attacker's goal is rarely to read the chain — it holds only public keys. The
goal is to make *you* encrypt your *next* secret to *their* key. If gitsafe trusted
any internally-consistent chain it found in the repo, here is what would happen: you
edit `.env`, you `git add` it, the clean filter reads the (attacker's) policy, asks
"who can read this branch?", gets back the attacker's age recipient, encrypts your
production database password directly to the attacker, and commits it. No error. No
prompt. The filter did exactly what it was told. This is the threat-model's primary
adversary, A1: the repository-content attacker who cannot write your local `.git/`
but can rewrite everything that travels in the repo.

The central design choice that defends against this is one sentence worth
memorizing: **a repository cannot vouch for its own authenticity.** Authenticity has
to be anchored *outside* the repository, in something the attacker (who only
controls repo contents) cannot touch. In gitsafe that anchor is a per-clone pin
stored in your local `.git/`, established once. The rest of this section is how that
pin works.

### Trust-on-first-use root pinning

The model is `ssh known_hosts`, and the analogy is exact enough to lean on. The very
first time you `ssh` to a host, SSH cannot tell you whether the key it sees is the
real host or an impostor — it has nothing to compare against. So it *shows* you the
fingerprint, asks you to confirm, and *records* the key. From then on, a *changed*
key is a loud, scary warning. SSH cannot authenticate first contact; it can make
every *subsequent* contact verifiable. That is trust-on-first-use, TOFU, and gitsafe
applies it to the policy root.

Two situations produce a pin, and the difference between them is the single most
important operational detail in this chapter.

When you **bootstrap** a brand-new repository — `gitsafe init` with no existing
policy — *you are the root*. You generated the key. There is no out-of-band identity
to verify because the identity is yours. So gitsafe pins your root automatically and
silently; there is nothing to confirm.

When you `gitsafe init` an **existing** policy — that is, a fresh *clone* of a repo
someone else set up — gitsafe does something deliberately different. It wires up the
filters and the merge driver so git knows how to call gitsafe, but it **does not
auto-pin**. Instead it prints the root fingerprint and tells you to pin it
deliberately, *after* you have confirmed that fingerprint through a trusted channel.
You pin with `gitsafe trust`.

```
   FRESH CLONE                  YOU                   TEAMMATE / ADMIN
   ───────────                  ───                   ────────────────
   git clone <repo>
        │
   gitsafe init  ───── wires filters, NO pin ─────────────┐
        │                                                  │
        │   "root fingerprint: 9f3a…c2"                    │
        │                                                  │
        ├──────── verify fingerprint OUT-OF-BAND ──────────┤
        │         (Signal / in person / signed mail)       │
        │                                                  │
        │   they read you 9f3a…c2 too?  ✓ match            │
        │                                                  │
   gitsafe trust  ──── writes .git/gitsafe/root ───────────┘
        │
   now clean will encrypt against this policy
```

The out-of-band step is not bureaucratic theater; it is the *entire* security
value. The pin makes every *future* change to the root detectable. It cannot tell
you whether the root you are pinning *right now* is the legitimate one — that is the
inherent TOFU first-contact gap (residual risk R2 in the threat model). The only
thing that closes that gap is a human comparing the fingerprint gitsafe shows
against the fingerprint the real admin tells them over a channel the repo-content
attacker does not control: a phone call, an in-person reading, a signed message.
Skip that step and "trust on first use" degrades to "trust whatever the repo says,"
which is exactly the attack we started with.

The pin lives in `.git/gitsafe/root`. It is per-clone and it is *never committed* —
it cannot be, because a committed pin would be a pin the attacker controls, which is
no pin at all. This is why every clone, including every CI runner, must run its own
`gitsafe init` and `gitsafe trust`: trust is a relationship between a *human* and a
*clone*, not a property of the repository. The newer releases harden this further —
the pin file is written `0600` inside a `0700` directory, so another local account
on a shared machine cannot quietly rewrite your trust anchor.

Once pinned, the gate is mechanical and lives on the *encrypt* path. Before the
clean filter encrypts any plaintext, it fully verifies the chain *and* checks the
verified root against your pin. If they match, encryption proceeds. If they differ,
clean refuses — loudly:

```
git add .env
# error: policy root changed — REFUSING to use it.
```

That refusal is the system working. If the change is illegitimate, you have just
caught an attack before your secret left your machine. If it is legitimate — a
genuine, intended re-bootstrap, perhaps the team rotated the founding admin key —
you re-pin on purpose:

```
gitsafe trust --fingerprint <hex> --force
```

The `--force` is the difference between "this is fine, I expected it" and "wait,
why did the root change?". gitsafe refuses to make that judgment for you, because it
*can't* — only you know whether your team actually re-bootstrapped. Note the shape
of the safe form: `--fingerprint <hex>` *asserts* the root is exactly that value and
refuses if reality differs, so even your re-pin can't be silently aimed at the wrong
key.

To inspect the relationship at any time:

```
gitsafe policy verify
```

This verifies the entire signed chain offline — version count, head hash, root
fingerprint — and tells you the pin status in plain words: `pinned and matches ✓`,
`NOT PINNED`, or `MISMATCH`. Make a habit of reading the last line. `NOT PINNED` on
a clone you thought you trusted means your secrets are not being encrypted to anyone
yet (clean will refuse), and it means you have not yet done the one human step that
makes this repo trustworthy. `MISMATCH` means stop and investigate before you do
anything else.

---

## 5.2 Rollback protection: catching a replay of your own past

Pinning is a strong defense, but it has a precise shape, and understanding its shape
reveals the *next* attack. Pinning anchors the *root*. It catches a *replacement*
chain — a different root. What it does **not** catch is a *replay*: the attacker
takes an *older version of your own chain* — same root, same valid signatures, the
pin matches perfectly — and restores it. Everything verifies. The pin is happy.

Why would anyone want to do that? Revocation. Picture the sequence: a contractor had
read access to `main`; the contractor offboards; an admin signs a new policy version
that revokes them and rotates the secrets. The chain is now at, say, version 12, and
the contractor is excluded. Then the attacker — or the disgruntled contractor with
push access — overwrites `.gitsafe/policy/HEAD` to point back at version 9, the
last version where the contractor was still an active reader. Version 9 is a real,
admin-signed version of *your* chain. Its root is *your* root, so the pin matches.
If gitsafe only checked the pin, that rollback would silently resurrect a revoked
reader, and your *next* rotation would re-encrypt secrets to them.

The defense is a **high-water mark**. Each clone records the highest policy version
it has ever trusted, in `.git/gitsafe/highwater` (per-clone, never committed, same
`0600`/`0700` hardening as the pin). The trust gate then refuses any policy whose
version is *lower* than that recorded high-water mark. You trusted version 12; a
chain presenting version 9 is refused even though version 9 is genuine, because
*you have already seen further*.

```
        version trusted by this clone over time
        ──────────────────────────────────────────────►

   v0 ─ v1 ─ … ─ v9 ─ v10 ─ v11 ─ v12        highwater = 12
                                    ▲
                                    │ recorded locally in
                                    │ .git/gitsafe/highwater
                                    │
   attacker resets HEAD ──► v9  ◄───┘
                            │
                            └── version 9 < highwater 12  →  REFUSED
                                (even though v9 is validly signed,
                                 same root, pin matches)
```

There is a subtle but essential property that makes the counter trustworthy: the
version number is **cryptographically forced to increase by exactly one per change**.
A policy version is valid only if `version == parent.version + 1`. The attacker
cannot mint a *new* high-numbered version to leapfrog your high-water mark, because
that would require an admin signature they don't have; and they cannot relabel an
old version with a higher number, because the number is part of the signed,
content-addressed bytes — change it and the SHA-256 no longer matches its filename
and the signature breaks. So the counter is not a soft hint that an attacker can
edit; it is welded to the cryptographic chain. (This monotonicity rule was added as
an explicit security fix; before it, a content-only attacker could replay an older
validly-signed HEAD to undo a revocation.)

What about a *legitimate* rollback? Sometimes you really do want to go backward — a
deliberate re-base of the policy, a recovery from a bad change. gitsafe does not
forbid it; it forbids doing it *silently*. `gitsafe trust --force` re-bases the
high-water mark to the current head, the same flag that re-pins a changed root. The
pattern is consistent across the whole trust system: gitsafe never decides on your
behalf whether a backward or sideways move is intended. It refuses by default and
makes you say "yes, I mean it" with `--force`.

Now the honest part, because a security chapter that only lists strengths is selling
you something. The high-water mark protects chains you have *already seen advance*.
It is powerless against a chain you have **never seen before**. On a brand-new clone,
your high-water mark starts empty; whatever version the repo presents on first
contact becomes your baseline. If an attacker controls the repo *from the very
first clone* and presents an already-rolled-back chain, there is no "earlier, higher"
version in your local memory to contradict it. This is not a gitsafe bug — it is the
inherent, irreducible limitation of trust-on-first-use. Rollback protection is a
defense for the *life* of a clone after first trust, not a substitute for verifying
the fingerprint out-of-band at first trust. The two defenses cover different attacks
and you need both.

---

## 5.3 Merging encrypted files: conflict resolution under encryption

Encryption and version control are in quiet tension, and merges are where the
tension surfaces. git's whole model of collaboration rests on the three-way merge:
given a common ancestor (base) and two divergent versions (ours and theirs), git
reconciles line-by-line changes automatically and only bothers you when two sides
edited the *same* lines. But gitsafe-marked files are *ciphertext* in the
repository. age output is opaque and randomized; two versions of the same secret
that differ by one character produce two completely unrelated blobs. git cannot
three-way merge opaque bytes — it would either declare a conflict on every change or,
worse, silently pick one side and discard the other's edits. Neither is acceptable
for a file that holds your secrets.

gitsafe's answer is a **merge driver**, `gitsafe merge`, wired automatically by
`gitsafe init` alongside the filters. When git hits a marked secret it cannot merge,
it hands the driver three inputs — ours, base, and theirs — and the driver does the
obvious-in-hindsight thing: it *decrypts all three to plaintext*, runs a normal git
three-way merge on the *plaintext*, and *re-encrypts the result*. Encryption is
peeled back exactly long enough to do the merge git already knows how to do, then
re-applied. The plaintext temporaries are written to a private `0700` directory, not
world-readable `/tmp` — a fix worth noting, because the easiest way to leak a secret
while protecting it is to spill the cleartext somewhere a bystander can read it.

The re-encryption target deserves a careful sentence, because it is a security
decision and not an accident. The merged result is encrypted to the **current
(target) branch's** readers — the branch the merge is landing *on*. This is
intentional and it is the correct default: the secret now lives on that branch, so it
should be readable by exactly that branch's authorized readers. But internalize the
consequence: merging a secret from a *narrower* branch into a *wider* one makes it
readable by the wider branch's readers — exactly as a normal git merge of any file
would propagate content. gitsafe is not widening access on a whim; it is following
where the content flows, the same way git always has.

Genuine conflicts — both sides edited the same lines — are not swept away. gitsafe
surfaces them the way git always does, with conflict markers (`<<<<<<<`, `=======`,
`>>>>>>>`). The twist is *where* those markers live: **inside the re-encrypted
blob**. The repository never holds plaintext conflict markers. A reader who checks
out the branch runs the smudge filter, decrypts, and sees the conflict markers in
their working copy. They resolve by editing the plaintext and re-staging, at which
point clean re-encrypts the resolved version. Conflict resolution happens entirely in
the reader's working tree, in plaintext, exactly as they expect — but the repository
only ever sees ciphertext.

The limitations are where most of the practical wisdom is, so read them as rules, not
footnotes:

- **You must be a reader to merge.** The driver cannot decrypt what you cannot read.
  A non-reader's merge is *refused* rather than allowed to silently mangle data — a
  hard fix in particular: an earlier version would merge a *locked placeholder* (the
  text a non-reader sees) into the secret and re-encrypt that garbage, destroying the
  file for *all* readers. Now a placeholder is rejected as a merge input outright.
- **Binary secrets can't be line-merged.** A three-way merge needs text. A keystore,
  a binary key file, a `.p12` — if both sides changed it, there are no lines to
  reconcile. Resolve by hand: decide which version you want and stage it.
- **Rebase and detached HEAD fail safe.** The driver needs an unambiguous current
  branch to know whose recipient set to re-encrypt to. During a rebase or on a
  detached HEAD there *is* no defensible current branch, so a secret conflict in that
  state **cannot** be auto-resolved. gitsafe does not guess. It writes nothing, and
  the clean filter likewise refuses, so plaintext can never be staged in that
  ambiguous state. Complete the rebase on a real branch, or merge instead.

That last point is the philosophy of the whole feature in miniature: when gitsafe
cannot determine a *defensible* recipient set, it fails safe — nothing written, no
plaintext exposed — rather than fail *convenient*. A merge that loses your edits is
annoying; a merge that encrypts your secret to the wrong people, or commits it in the
clear, is a breach. gitsafe chooses the annoyance every time.

---

## 5.4 Key loss and recovery: the deliberate absence of a backdoor

Here is the hardest truth in the book, stated without softening: **a lost private key
means lost read access to the ciphertext that was encrypted to that identity, and
nobody can recover it for you.** There is no master key. There is no escrow by
default. If you delete your `~/.config/gitsafe/identity` with no backup, the secrets
that were encrypted only to your age key are, for you, gone.

This is not a missing feature. It is *the* feature. An escrow key — a master key that
can decrypt everything "for recovery" — is a single point of catastrophic compromise:
steal it once and you have everyone's secrets forever. The entire premise of gitsafe
is that confidentiality rests on keys held by individuals and nowhere else. A
backdoor would dissolve that premise. So gitsafe makes the trade explicit: real
confidentiality, at the cost of real responsibility for your key.

Given that, recovery is not *decryption* — you can't decrypt without the key — it is
*re-enrolment*. The procedure is administrative, and it is a two-person dance between
the person who lost the key and an admin who still has theirs:

1. **Generate a fresh identity.** The recovering member runs `gitsafe key gen`
   (optionally `--passphrase`), then `gitsafe key show` to print their *new* public
   keys.
2. **An admin re-adds them with the new key.** The `--update` flag is what makes this
   a replacement rather than a rejected duplicate:

   ```
   gitsafe member add <you> --update --enc age1...
   ```

   The admin adds `--sign <hex>` too if the recovering member is themselves an admin
   who signs policy. `--update` also reactivates a revoked member and preserves an
   existing sign key if it isn't re-supplied. The admin commits the policy change.
3. **An admin rotates** so current secrets are re-encrypted to include the new key:

   ```
   gitsafe rotate
   git add .gitsafe <secrets> && git commit
   ```

4. **After a pull, the recovering member can read *current* secrets again.**

Notice the careful word *current*. Re-enrolment restores access to secrets as they
exist *now*, and to all future secrets. It does **not** retroactively decrypt the
*historical* blobs that were encrypted only to the lost key — those are still
ciphertext to the new identity, because age encryption is not retroactive and gitsafe
has no master key to re-key history. And there is a sharper point hiding here: *lost
is not the same as destroyed*. A key you can no longer find might be a key someone
else found. If the lost key may be compromised rather than merely gone, treat every
secret it could read as *exposed* and **rotate the secret value itself** — issue a
new password, a new API key — not just the gitsafe recipient set. Rotating recipients
stops future leakage; rotating the *value* is the only thing that protects you from a
copy the attacker already made.

The organizational lesson is blunt and it is the one most teams learn too late:
**always keep more than one admin.** Admins are the only members who can re-enrol
people and rotate. If the *last* admin loses their key, the chain cannot be
extended — nobody can sign a new version — and the policy is effectively frozen. You
can still read what you already could, but you can never onboard, offboard, rotate,
or recover anyone. gitsafe even refuses, on the *other* end, any change that would
strip the last usable admin (an active member holding admin *with* a signing key),
precisely so a careless revoke can't brick the chain. But it cannot defend against a
human dropping a laptop in a lake. Two admins, minimum. Three if the stakes are real.

And the cheapest insurance of all: **back the key up before you need to.** Copy
`~/.config/gitsafe/identity` to secure offline storage — a password manager, an
encrypted USB stick. The file is tiny. If you protect it at rest with a passphrase
(`gitsafe key gen --passphrase` or `gitsafe key lock` to migrate an existing key), a
copy is safe to store in *more* places, because a leaked file alone is useless
without the passphrase. The one operational consequence to remember: the git filters
— clean, smudge, merge — have no terminal to prompt on, so a passphrase-protected key
only works under git if `GITSAFE_PASSPHRASE` is set in that environment. Export it
from your shell profile or a keychain helper. Skip that and a locked key degrades
gracefully to placeholders on checkout — your data stays safe, it's just invisible
until the passphrase is available. One more alignment detail that bites people:
for anyone who *signs* policy, the member *name* (`gitsafe init --user NAME`, stored
as `gitsafe.user`) must match their keyring name *and* their identity's public keys
must match that keyring entry, or their signed changes won't verify.

---

## 5.5 What gitsafe does NOT protect — an honest inventory

A security tool earns trust by being precise about its limits, not by implying it
covers everything. Here is the threat boundary, drawn plainly. Study it as carefully
as the guarantees, because the gaps are where *you* have to act.

```
   ┌─────────────────────── PROTECTED ────────────────────────┐
   │                                                           │
   │  • secret file CONTENTS  → age multi-recipient ciphertext │
   │  • policy INTEGRITY      → ed25519 sigs + SHA-256 chain   │
   │  • root REPLACEMENT      → TOFU pin (.git/gitsafe/root)   │
   │  • policy REPLAY/rollback→ high-water mark + monotonicity │
   │  • encrypt-to-attacker   → clean gates encrypt on verify  │
   │                                                           │
   └───────────────────────────────────────────────────────────┘
   ┌───────────────────── NOT PROTECTED ──────────────────────┐
   │                                                           │
   │  • git HISTORY            → rotate the secret VALUE        │
   │  • who can CLONE          → not server-side access control │
   │  • a COMPROMISED admin key→ can rewrite policy legitimately│
   │  • EXISTENCE of a secret  → names, sizes, recipients clear │
   │  • your local .git/       → total local compromise, game over│
   │  • write/force PUSH       → policy metadata, not enforced  │
   │  • POST-QUANTUM           → X25519/Ed25519 not PQ-secure   │
   │                                                           │
   └───────────────────────────────────────────────────────────┘
```

**gitsafe does not scrub git history.** Rotation is *forward-only*: it changes future
blobs, it never rewrites the past. Anyone who already had read access keeps a
decryptable copy of the old ciphertext in their clone and in packfiles forever. This
is residual risk R1, and it has exactly one mitigation: after you offboard someone or
otherwise remove access to a *live* secret, **rotate the secret's value** — new
password, new key. Revoking access stops future leakage of *new* ciphertext; only
changing the underlying secret protects you from the copy a former reader already
holds. Treat revocation and value-rotation as a single offboarding action, never as
one-or-the-other.

**gitsafe is not server-side access control.** It is a *client-side overlay* on stock
git. Anyone who can clone the repository gets the ciphertext — all of it, including
history. Confidentiality rests entirely on the *keys*, not on who can reach the repo.
Relatedly, `write` and `force` grants are *policy metadata*, not push enforcement
(residual risk R4); gitsafe does not and cannot stop a push. If you need to control
who can push or force-push, that is your git host's job — branch protection and
server hooks. Don't lean on gitsafe grants for it.

**A compromised admin key is a legitimate signer.** The chain trusts admin
signatures; an attacker holding an admin's private signing key can sign *valid* policy
changes — add their own key as a reader, rotate, and now legitimately decrypt future
secrets. Nothing about this is a chain forgery; it is authorized misuse. Pinning and
high-water marks do not help, because the change is properly signed and moves the
version *forward*. The defenses are organizational: protect admin keys (passphrase at
rest), keep the admin set small and known, and watch the audit trail. `gitsafe audit`
exists precisely so you can review *how access evolved across the chain* and spot a
grant nobody authorized.

**gitsafe protects contents, not existence.** This is residual risk R5 and it
surprises people. File names, file sizes, and the *set of recipients* (which lives in
the envelope header), along with the entire policy — every member name and grant — are
intentionally cleartext. An observer learns that `prod-database.env` exists, roughly
how big it is, and who can read it. They just can't read *what's inside*. If the mere
*existence* of a secret is sensitive, gitsafe is the wrong layer; you need naming
discipline or a different tool.

**Your local `.git/` is trusted, and that's the boundary.** An attacker who can write
your `.git/` can rewrite the pin, the filter config, the verified cache — total local
compromise (R3). No client-side tool defends against an adversary who already owns
your machine. gitsafe's guarantees begin at the assumption that your OS account and
local `.git/` are yours.

Finally, **X25519 and Ed25519 are not post-quantum** (R7). A harvest-now,
decrypt-later adversary with far-future quantum hardware is explicitly out of scope.
For today's threats this is a non-issue; named here for completeness, because an
honest threat model lists even the risks it has chosen not to address.

The throughline of every item above: gitsafe protects the *cryptographic* core —
contents, policy integrity, the encrypt path — extremely well, and deliberately
leaves *operational* and *organizational* concerns to you, because those are concerns
no client-side tool can solve and pretending otherwise would be the most dangerous
thing it could do.

---

## Exercises

Work these in order; they climb from recall to creation to debugging to extension.
Each has a full solution and an explanation — but try first.

### Exercise 1 (recall) — What does a self-signed root prove?

**Problem.** In one or two sentences, state precisely what gitsafe's self-signed
policy root *does* prove and what it *does not* prove.

**Solution.** It proves *internal consistency*: that whoever created the chain
controlled the key the chain names as authoritative, and that the bytes have not been
tampered with since (the signature still verifies). It does **not** prove *identity*
— it says nothing about *whose* key the root actually is.

**Explanation.** This distinction is the seed of the entire trust model. A signature
binds a message to *a* key; it cannot, by itself, tell you that key belongs to the
person you think it does. Because the repository is untrusted, an attacker can supply
a chain that is perfectly self-consistent under their *own* root. Self-signing
therefore defends against tampering with an *existing* chain but is helpless against
*substitution* of a whole new one. That gap is exactly what TOFU pinning fills, which
is why every other defense in the chapter is downstream of understanding this one
limitation.

### Exercise 2 (recall) — Where does the trust pin live, and why isn't it committed?

**Problem.** Name the file that holds the trust pin and explain in two or three
sentences why committing it would defeat its purpose.

**Solution.** The pin lives in `.git/gitsafe/root`, per-clone. Committing it would
place the trust anchor *inside the repository* — the very thing gitsafe treats as
untrusted — so an attacker who can rewrite repo contents could rewrite the pin to
match their swapped-in root. A committed pin is no pin at all; the anchor must live
outside what the attacker controls.

**Explanation.** The whole TOFU design rests on the axiom that a repository cannot
vouch for its own authenticity. Anything committed travels with the repo and is
subject to the repo-content attacker (A1). The pin's protective power comes precisely
from being *local* — established once by a human in a place (`.git/`) the
repo-content adversary cannot write. This is also why every clone, including every CI
runner, must pin independently: trust is a relationship between a human and a clone,
not a portable property of the repository.

### Exercise 3 (apply) — Read a verify output

**Problem.** You clone a teammate's repo, run `gitsafe init`, then immediately run
`gitsafe policy verify` and the last line says `NOT PINNED`. You try `git add .env`
and it fails. Explain what happened and give the exact commands to fix it correctly.

**Hint.** `init` on an existing policy wires filters but deliberately does *not*
auto-pin.

**Solution.**

```
# 1. Show the fingerprint gitsafe sees
gitsafe policy verify        # note the root fingerprint, e.g. 9f3a…c2

# 2. Confirm that fingerprint OUT-OF-BAND with the real admin
#    (phone call, Signal, in person) — do NOT skip this.

# 3. Pin only after the fingerprint matches
gitsafe trust
# or, scripted/assertive:
gitsafe trust --fingerprint 9f3a...c2
```

**Explanation.** On a fresh clone, `gitsafe init` sets up the filters and merge
driver but leaves the clone *unpinned* on purpose, because the tool cannot know
whether the root it found is legitimate. The clean filter gates encryption on a
matching pin, so `git add` of a plaintext secret refuses until you pin — that refusal
is the system protecting you from encrypting to an unverified policy. The *correct*
fix is not just to run `gitsafe trust` reflexively but to verify the fingerprint
out-of-band first; the trust command is the easy part, the human verification is the
part that actually provides security. Using `--fingerprint HEX` makes the pin an
assertion that fails if reality differs, which is the right form in scripts.

### Exercise 4 (apply) — Predict the merge recipients

**Problem.** Branch `feature/login` grants `read` only to Alice and Bob. Branch
`main` grants `read` to the whole active team. You merge `feature/login` *into*
`main`, and the merge touches a marked secret. To whose keys is the merged secret
re-encrypted? Is that a bug?

**Solution.** It is re-encrypted to **`main`'s** readers — the whole active team —
because `main` is the current (target) branch the merge lands on. This is not a bug;
it is the intended, correct behavior.

**Explanation.** The merge driver always re-encrypts to the *current branch's*
recipient set, because the secret now lives on that branch and should be readable by
exactly that branch's authorized readers. The consequence — that merging a secret
from a narrower branch into a wider one widens who can read it — is identical to how a
normal git merge propagates *any* file's content from one branch to another. gitsafe
is following the content, not making an independent access decision. The practical
takeaway: be deliberate about the *direction* of merges involving secrets, exactly as
you would be about merging any sensitive file, because the target branch's reader set
governs the result.

### Exercise 5 (apply) — Why does a rebase conflict on a secret fail?

**Problem.** Mid-`git rebase`, two commits both edited the same marked secret and git
invokes the merge driver. It fails and writes nothing. Why, and what should you do?

**Solution.** During a rebase (or on a detached HEAD) there is no unambiguous current
branch, so gitsafe cannot determine a defensible recipient set to re-encrypt to. It
fails safe — nothing written, no plaintext staged. Complete the rebase on a real
branch, or use a merge instead of a rebase for that change.

**Explanation.** The merge driver's re-encryption step *requires* a current branch,
because the recipient set is derived from "who can read this branch." A detached HEAD
or in-progress rebase has no branch to answer that question, so any recipient choice
would be a guess — and a wrong guess could encrypt the secret to the wrong people or,
worse, leave plaintext staged. gitsafe refuses rather than guess, and the clean
filter refuses in the same state, so there is no path to staging plaintext. This is
the "fail safe, not fail convenient" philosophy in action: a blocked rebase is an
inconvenience; a misdirected secret is a breach.

### Exercise 6 (create) — Design a safe CI trust step

**Problem.** Write the CI steps for a runner that must *write* secrets back (so it
needs to encrypt). It must never be tricked into trusting a swapped-out policy.
Assume the runner's identity file and (encrypted) passphrase are provided as
variables, and the expected root fingerprint is stored as `EXPECTED_ROOT_FINGERPRINT`.

**Solution.**

```bash
export GITSAFE_IDENTITY="$RUNNER_KEY_FILE"
export GITSAFE_PASSPHRASE="$RUNNER_KEY_PASSPHRASE"   # only if the key is locked

gitsafe init --user ci-runner
gitsafe trust --fingerprint "$EXPECTED_ROOT_FINGERPRINT"   # asserts, never TOFU
git checkout -- .                                          # decrypt what CI may read
gitsafe check                                              # belt and braces
```

**Explanation.** A CI runner is just another clone, so the same TOFU rule applies: it
will refuse to encrypt against an untrusted policy. The critical choice is
`gitsafe trust --fingerprint HEX` rather than a bare `gitsafe trust` — the
fingerprint form *asserts* the root equals the known value and *fails the build* if
the repo's root differs, so a tampered policy can never be silently accepted by an
unattended runner. The expected fingerprint is obtained from `gitsafe policy verify`
on a trusted machine and stored as a CI secret, moving the out-of-band verification
to a place a human controlled once rather than the runner guessing. `gitsafe check`
at the end is a final guard against any marked secret slipping through as plaintext.

### Exercise 7 (debug) — A teammate sees a placeholder, not the secret

**Problem.** You added a new teammate and granted them read on `staging`, committed,
and pushed. They pull and still see a locked placeholder instead of the secret.
Diagnose the two most likely causes and fix it.

**Hint.** What turns a grant into actual decryptable ciphertext?

**Solution.**

```
# On your side, confirm the grant exists:
gitsafe policy show          # is the teammate granted read on staging, active?
gitsafe access staging       # do they appear in the resolved reader set?

# Most likely cause: you granted but never rotated.
gitsafe rotate
git add .gitsafe <secrets> && git commit
git push
# Teammate pulls again → smudge can now decrypt.
```

**Explanation.** A grant changes *who is allowed* to read, but it does not by itself
re-encrypt existing ciphertext. The secret on disk is still encrypted to the *old*
recipient set until you run `gitsafe rotate`, which re-applies the clean filter and
re-encrypts every marked file to the *current* readers. So the two likely causes are
(1) you granted read but never rotated and committed, leaving the new teammate out of
the actual ciphertext, or (2) the grant didn't take — wrong name, wrong branch, or the
member is revoked. `gitsafe access staging` resolves the truth directly, expanding
groups, admins, and public to concrete active members, which tells you immediately
whether the teammate is even in the intended reader set before you rotate.

### Exercise 8 (debug) — `git add` says the root changed

**Problem.** A `git add .env` that worked yesterday now fails with
`policy root changed — REFUSING to use it.` Walk through your response.

**Solution.** Do **not** reflexively `--force`. First, treat it as a possible attack
and investigate:

```
gitsafe policy verify        # what root does the repo present now? does it verify?
```

Then determine *out-of-band* whether your team intentionally re-bootstrapped the
policy (rotated the founding admin key, recreated the chain). Only if you *confirm*
the change was legitimate:

```
gitsafe trust --fingerprint <new-hex> --force
```

If you cannot confirm it, stop and escalate — your secret was about to be encrypted to
an unknown root.

**Explanation.** The mismatch refusal means the repo's verified root differs from your
pinned root — exactly the signature of a chain-*replacement* attack (A1), and also the
signature of a legitimate re-bootstrap. gitsafe cannot tell the two apart, because only
your team knows whether a re-bootstrap was intended; that is why it refuses by default
and forces a deliberate `--force`. Reaching for `--force` without verifying is the one
move that turns the protection off at the exact moment it fired correctly. The right
reflex is to treat the loud error as a *successful* defense, verify intent out-of-band,
and only re-pin once you are certain — using `--fingerprint` so even the re-pin asserts
the value rather than blindly accepting whatever is there.

### Exercise 9 (extend) — Why two admins, and what breaks with one?

**Problem.** Argue, with the specific failure modes, why a team should keep more than
one admin. What exactly cannot be done if the *last* admin loses their key?

**Solution.** Admins are the only members who can sign policy changes — re-enrol
members, grant and revoke, and rotate. If the last admin loses their key, the chain
can no longer be extended: nobody can sign a new version, so the policy is frozen. You
can still read what you already could, but you can never onboard, offboard, rotate,
recover a lost-key member, or change access in any way. A second admin makes every one
of those operations survivable.

**Explanation.** This follows directly from the no-backdoor design: there is no master
key to fall back on, so the *only* way to advance the policy is a valid admin
signature. Lose the last one and the signing capability is gone with it, permanently.
gitsafe protects the *other* edge — it refuses any change that would leave no usable
admin, so a careless revoke can't brick the chain — but it cannot conjure a signature
for a key that no longer exists. The mitigation is purely organizational and must be
done *before* the loss: keep at least two admins, ideally three for high-stakes repos,
and back up admin keys (passphrase-protected) to offline storage. Redundancy here is
not gold-plating; it is the difference between "recover the member" and "abandon the
repo."

### Exercise 10 (extend) — Close the offboarding gap

**Problem.** You revoke a contractor and rotate. A colleague says "great, they can't
read the secrets anymore." Correct them precisely and give the complete offboarding
procedure.

**Solution.** Rotation only protects *future* ciphertext. The contractor still holds
decryptable copies of every secret that existed while they had access — in their clone
and in packfiles — and rotation does not and cannot rewrite that history. Complete
offboarding:

```
gitsafe member revoke <contractor>
gitsafe rotate
git add .gitsafe <secrets> && git commit && git push
# THEN, for every live secret they could read, rotate the VALUE itself:
#   issue a new database password, new API key, etc., and update .env
gitsafe rotate    # re-encrypt the new values to the current readers
git add .gitsafe <secrets> && git commit && git push
```

**Explanation.** This is residual risk R1, read-after-revocation, and it is inherent
to any version-control-based secret store: history is immutable and former readers
keep their copies. Revoking and rotating recipients stops the contractor from reading
*new* ciphertext, but the old ciphertext they already cloned remains decryptable with
the key they still hold. The only thing that actually protects you is rotating the
*underlying secret value* — a new password the old ciphertext doesn't contain — exactly
as you would after any credential exposure. Treat "remove access" and "rotate the
value" as two halves of one offboarding action; doing only the first leaves the door
open.

---

## Mini projects

These three projects exercise the chapter end to end on a real repository. Run them in
a scratch directory. Each lists the concepts it drills, the requirements, a
step-by-step walkthrough, a complete worked shell session, and an explanation.

### Mini project 1 — Clone a repo and establish trust by verifying a fingerprint

**Description.** Stand up a gitsafe repo as one user ("the admin"), then act as a
second user cloning it for the first time and establishing trust *correctly* — by
verifying the fingerprint before pinning.

**Concepts practiced.** Bootstrap vs. clone; auto-pin vs. deliberate pin;
`gitsafe init` on an existing policy; out-of-band fingerprint verification;
`gitsafe trust`; reading `gitsafe policy verify`.

**Requirements.**
- A gitsafe binary on `PATH`.
- Two identities (simulate two users with two `GITSAFE_IDENTITY` files).
- A local "remote" to clone from.

**Walkthrough.**
1. As admin, generate an identity and bootstrap a repo (auto-pin happens here).
2. Add a secret, grant yourself read, rotate, commit.
3. Capture the root fingerprint from `gitsafe policy verify` — this is the "out-of-band"
   truth.
4. As the second user, clone, `gitsafe init` (no auto-pin), and read the printed
   fingerprint.
5. Compare it to the admin's fingerprint, then `gitsafe trust` only on a match.
6. Confirm `gitsafe policy verify` now says pinned-and-matches.

**Worked solution.**

```bash
mkdir -p ~/scratch && cd ~/scratch

# --- ADMIN: bootstrap (auto-pins, because you ARE the root) ---
export GITSAFE_IDENTITY=$PWD/admin.key
gitsafe key gen
git init repo && cd repo
gitsafe init --user admin            # no existing policy → bootstraps v0, pins root
echo "DB_PASSWORD=hunter2" > .env
gitsafe grant admin read main
gitsafe rotate
git add .gitsafe .gitattributes .env && git commit -m "secret"

# Capture the TRUTH fingerprint (this is what you'd read aloud over Signal):
gitsafe policy verify | tee /tmp/admin-verify.txt
# … root fingerprint: 9f3a...c2   pinned and matches ✓

cd ~/scratch

# --- USER 2: fresh clone (init does NOT auto-pin) ---
export GITSAFE_IDENTITY=$PWD/user2.key
gitsafe key gen
git clone repo clone2 && cd clone2
gitsafe init --user user2            # wires filters, prints fingerprint, NO pin
gitsafe policy verify
# … root fingerprint: 9f3a...c2   NOT PINNED

# Compare 9f3a...c2 against the admin's value out-of-band. It matches → pin:
gitsafe trust --fingerprint 9f3a...c2
gitsafe policy verify
# … root fingerprint: 9f3a...c2   pinned and matches ✓
```

**Explanation.** The project makes the bootstrap-vs-clone asymmetry concrete: the
admin's `init` auto-pinned silently because the admin *is* the root, while user 2's
`init` deliberately left the clone unpinned and printed the fingerprint for human
verification. The security value lives entirely in step 5 — comparing the fingerprint
user 2 sees against the one the admin actually published, over a channel the
repo-content attacker doesn't control. Here we faked "out-of-band" by reading the
admin's `policy verify` output, but in reality those fingerprints must reach you by a
trusted path; pinning without that comparison is trusting whatever the repo says.
Using `--fingerprint` for the pin turns it into an assertion that would fail on any
mismatch, which is the habit to build.

### Mini project 2 — Simulate and detect a policy rollback

**Description.** Advance a policy across several versions (including a revocation),
then *replay* an older HEAD by hand and watch the high-water mark refuse it.

**Concepts practiced.** Version monotonicity; the high-water mark; replay vs.
replacement; why a validly-signed old version is still refused; deliberate rollback
with `--force`.

**Requirements.** A trusted clone from Mini project 1 (or any bootstrapped repo with
several policy versions). The ability to edit `.gitsafe/policy/HEAD`.

**Walkthrough.**
1. Advance the policy a few versions: onboard a member, then revoke them and rotate —
   this raises your high-water mark and produces an older HEAD where the revoked
   member was still active.
2. Note the current and an older policy hash.
3. Overwrite `.gitsafe/policy/HEAD` with the *older* hash (the replay).
4. Attempt to encrypt (`git add` a secret) and watch the trust gate refuse the
   lower-versioned policy.
5. Restore HEAD, confirm normal operation resumes. (Show that a *deliberate* rollback
   would require `gitsafe trust --force`.)

**Worked solution.**

```bash
cd ~/scratch/repo
export GITSAFE_IDENTITY=$PWD/../admin.key

# 1. Advance versions: onboard, then revoke + rotate.
gitsafe member add temp --enc age1qqq...placeholder   # v1
gitsafe grant temp read main                          # v2
gitsafe rotate && git add .gitsafe .env && git commit -m "add temp"
gitsafe member revoke temp                             # v3 (temp no longer reader)
gitsafe rotate && git add .gitsafe .env && git commit -m "revoke temp"
gitsafe policy verify
# … versions: 4   head: <HASH_NEW>   ... pinned and matches ✓
#   (clone has now trusted up to this version → high-water mark recorded)

# 2. Find an OLDER object hash (a version where temp was still a reader, e.g. v2):
ls .gitsafe/policy/objects/        # list the chain objects
cat .gitsafe/policy/HEAD           # current head hash = HASH_NEW

# 3. REPLAY: point HEAD back at the older, still-validly-signed version.
echo "<HASH_OLD>" > .gitsafe/policy/HEAD

# 4. Attempt to use it — the high-water mark refuses the lower version:
echo "DB_PASSWORD=hunter3" > .env
git add .env
# error: policy version 2 is below the highest trusted (4) — REFUSING (rollback?).
#        (validly signed, same root, pin matches — refused anyway: it's a replay)

# 5. Restore and resume.
echo "<HASH_NEW>" > .gitsafe/policy/HEAD
git add .env                       # works again

# A DELIBERATE rollback (if you truly meant it) would be:
#   gitsafe trust --force          # re-bases the high-water mark to current head
```

**Explanation.** This is the rollback attack in miniature. The replayed version is a
genuine, admin-signed version of your *own* chain — same root, pin matches perfectly —
so root-pinning alone would happily accept it and silently resurrect the revoked
member `temp` on the next rotation. The high-water mark is what saves you: the clone
recorded that it had trusted version 4, so a policy presenting version 2 is refused
even though it verifies, because *you have already seen further*. The version counter
can't be forged to leapfrog the mark, because each version is cryptographically
forced to be `parent + 1` and the number is part of the signed, content-addressed
bytes. The `--force` path exists for a *deliberate* re-base, keeping with gitsafe's
rule that backward moves are allowed but never silent. (Exact error wording may differ
slightly by version; the refusal-on-lower-version behavior is the point.)

### Mini project 3 — Recover from a lost key as an admin + member pair

**Description.** Simulate a member losing their identity, then perform the full
administrative recovery: new identity, `member add --update`, rotate, regain access.

**Concepts practiced.** No-backdoor recovery as re-enrolment; `gitsafe member add
--update --enc`; rotation to re-encrypt to a new key; current vs. historical access;
the value-rotation caveat when a key may be compromised.

**Requirements.** A repo with an admin and at least one ordinary reader member.

**Walkthrough.**
1. Establish an admin and a member `dev` with read on `main`; rotate so `dev` can
   read the secret. Confirm `dev` can decrypt.
2. Simulate loss: delete `dev`'s identity file. Confirm `dev` now sees a placeholder.
3. `dev` generates a *new* identity and shares the new public enc key.
4. Admin runs `member add dev --update --enc <new>`, commits.
5. Admin `rotate`s and commits; `dev` pulls and regains access to *current* secrets.
6. Note that historical blobs encrypted only to the old key remain unreadable, and
   that if the old key may be *compromised* the secret value itself must be rotated.

**Worked solution.**

```bash
cd ~/scratch && git init recovery-repo && cd recovery-repo

# --- ADMIN sets up; onboard dev as a reader ---
export GITSAFE_IDENTITY=$PWD/../admin.key   # admin identity
gitsafe init --user admin
echo "API_KEY=secret-123" > .env
gitsafe grant admin read main

# dev makes an identity, shares the enc key:
GITSAFE_IDENTITY=$PWD/../dev.key gitsafe key gen
DEV_ENC=$(GITSAFE_IDENTITY=$PWD/../dev.key gitsafe key show | awk '/enc/{print $2}')
gitsafe member add dev --enc "$DEV_ENC"
gitsafe grant dev read main
gitsafe rotate && git add .gitsafe .gitattributes .env && git commit -m "onboard dev"

# dev can read now:
GITSAFE_IDENTITY=$PWD/../dev.key git checkout -- .env && cat .env
# API_KEY=secret-123

# --- LOSS: dev's identity disappears ---
rm $PWD/../dev.key
GITSAFE_IDENTITY=$PWD/../dev.key git checkout -- .env && cat .env
# <gitsafe locked placeholder>     (no key → smudge writes a placeholder)

# --- RECOVERY: dev generates a NEW identity ---
GITSAFE_IDENTITY=$PWD/../dev-new.key gitsafe key gen
DEV_NEW_ENC=$(GITSAFE_IDENTITY=$PWD/../dev-new.key gitsafe key show | awk '/enc/{print $2}')

# Admin re-adds dev with the NEW key (--update is required to replace):
gitsafe member add dev --update --enc "$DEV_NEW_ENC"

# Admin rotates so current secrets are re-encrypted to the new key:
gitsafe rotate && git add .gitsafe .env && git commit -m "recover dev"

# dev (new identity) regains access to CURRENT secrets:
GITSAFE_IDENTITY=$PWD/../dev-new.key git checkout -- .env && cat .env
# API_KEY=secret-123
```

**Explanation.** The project shows recovery for what it is: *re-enrolment*, not
decryption. Nothing recovered the lost key — gitsafe has no master key by design — so
`dev` had to generate a fresh identity and have an admin re-add it with `--update`,
which replaces the keyring entry rather than rejecting the duplicate. Only after
`gitsafe rotate` re-encrypts the marked files to the *current* reader set (now
including the new key) and the admin commits can `dev` read again, and crucially only
the *current* secret values: any historical blob encrypted solely to the lost key
stays ciphertext forever. The hidden lesson is in step 6 — *lost is not destroyed*. If
the old key might have fallen into someone else's hands, re-enrolment is not enough;
you must rotate the *secret's value* (`API_KEY=secret-456`) and rotate again, because
the old ciphertext the attacker may hold still decrypts to `secret-123`. And underlying
the whole exercise: recovery only worked because an *admin* was available to sign — the
case for never having a single point of admin failure.

---

## Summary — the whole book in one page, and the one thing to remember

Step back and see the arc. Across five chapters you have assembled a complete mental
model of gitsafe, and it is worth recapping as a single story, because the parts only
make sense together.

**Chapter 1** introduced the premise: secrets that live *in* your git repository,
encrypted, where access is governed by a portable, offline-verifiable policy rather
than a server's say-so — "git-crypt with real access control." **Chapter 2** built the
foundation: *identity* as a pair of private keys (an age key that receives encrypted
secrets, an ed25519 key that signs policy), held outside the repo and treated like an
SSH key. **Chapter 3** taught the *policy*: a signed, content-addressed, versioned
chain of keyring entries and grants, where the verb hierarchy (`admin > force > write
> read`) and ref-glob resources decide who may do what, and where `read` access on a
branch is what makes someone a *recipient*. **Chapter 4** connected policy to bytes
through the *filters*: clean encrypts marked files to the current branch's readers on
`git add`, smudge decrypts on checkout (or shows a placeholder), and `rotate` moves
the reader set forward — all on stock git, no server, no daemon. And **this chapter**
closed the loop with the part that turns a clever tool into a *trustworthy* one: TOFU
root pinning against chain replacement, the high-water mark against rollback replay,
encrypted merges that fail safe, recovery without a backdoor, and a candid map of the
gaps you must cover yourself.

The threads weave into one idea. gitsafe's confidentiality rests entirely on *keys*,
and its integrity rests entirely on a *signed chain anchored by a per-clone pin*. The
repository is untrusted; your local `.git/` and your identity are trusted; everything
gitsafe does is a consequence of taking that boundary seriously. It protects the
cryptographic core — secret contents, policy integrity, the encrypt path — with real
guarantees you can trace to real mechanisms, and it deliberately leaves the
operational and organizational concerns to you, because no client-side tool can solve
those and pretending otherwise would be the most dangerous thing it could do.

If you remember exactly one thing, remember this: **gitsafe's security lives in the
human steps it cannot do for you — verifying the root fingerprint out-of-band before
you trust, keeping more than one admin, and rotating the secret's *value* (not just
its recipients) whenever someone offboards or a key may be exposed.** The cryptography
is solid and the tool will refuse loudly when something is wrong. But a loud refusal
only helps the person who reads it, verifies before forcing past it, and has planned
ahead for the day a key goes missing. Be that person, and gitsafe will keep your
secrets exactly as well as it claims to.
