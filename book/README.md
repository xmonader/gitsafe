# Secrets in Git, Done Right — A Small Book on gitsafe

This is a short, hands-on book about putting secrets — your `.env`, your private
keys, your TLS certificates — directly into a git repository **without** handing
them to everyone who can clone it. The tool that makes this safe is
[gitsafe](https://github.com/xmonader/gitsafe), and by the end of these five
chapters you will be able to set it up, onboard a team, rotate and revoke access,
and reason clearly about exactly what it protects and what it does not.

You do not need to have used git-crypt, SOPS, Vault, or any other secrets tool
before. You *do* need to be comfortable with everyday git — `add`, `commit`,
`push`, `clone`, branches — and with a Unix shell. Everything else we build up
from first principles.

## Why this book exists

Most teams handle secrets in one of two unhappy ways. Either they keep secrets
*out* of git entirely — in a separate vault, a shared password manager, a
pinned message someone has to remember to update — and pay for it with drift,
"works on my machine," and a second access list that slowly diverges from who is
actually on the team. Or they give up and commit secrets in plaintext, and pay
for it the day the repo leaks.

gitsafe offers a third path: the secret lives in git like any other file, but
git stores *ciphertext*, and the set of people who can decrypt it is derived
from who is allowed to read that branch. One list, not two. No server. This book
teaches you to use that path well — including the sharp edges, because a secrets
tool you half-understand is worse than one you don't use at all.

## How to read it

The chapters are meant to be read in order; each builds on the last. Every
chapter ends with **exercises** (with full solutions and explanations) and
**mini projects** that put the ideas to work on a realistic repository. If you
work through the exercises rather than just reading them, you will retain far
more — secrets management is a muscle, not a fact.

Run the commands as you go. Use a throwaway directory; nothing here touches a
repository you care about unless you point it there.

## Table of contents

1. **[Why gitsafe? The problem with secrets in git](ch01-why-gitsafe.md)**
   What goes wrong when secrets meet version control, the mental model gitsafe
   uses to fix it, and a first look at the threat it defends against.

2. **[Getting started: your first encrypted secret](ch02-getting-started.md)**
   Install gitsafe, generate your identity, turn it on for a repo, and watch a
   plaintext `.env` become ciphertext in git while staying readable in your
   working tree. How the git filters make this invisible.

3. **[The access model: members, grants, and branches as readers](ch03-the-access-model.md)**
   The signed policy: who is in the keyring, the two kinds of keys, the verbs,
   how "read a branch" becomes "decrypt its secrets," groups, and need-to-know
   branches.

4. **[Running a team: onboarding, rotation, and revocation](ch04-running-a-team.md)**
   The daily operations — bringing people in with one command, rotating secrets
   to a new reader set, cutting access, bringing someone back, auditing the
   history, and stopping plaintext leaks with a pre-commit hook and CI gate.

5. **[Trust, security, and recovery](ch05-trust-security-recovery.md)**
   The trust-on-first-use pin, verifying a fingerprint, the rollback defense,
   merging encrypted files, what to do when a key is lost, and an honest account
   of what gitsafe does *not* protect.

## A note on accuracy

Every command in this book is a real gitsafe command, drawn from the project's
own [User Guide](https://github.com/xmonader/gitsafe/blob/main/docs/userguide.md)
and [Tutorial](https://github.com/xmonader/gitsafe/blob/main/docs/tutorial.md).
Where a chapter shows output, it is the output you should actually see. If your
gitsafe behaves differently, you may be on a newer version — check the project
`CHANGELOG.md`.

Let's begin.
