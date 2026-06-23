# gitsafe — Strategy & Go-To-Market

The positioning lesson: a from-scratch VCS is well-engineered but mispositioned — replacing git is an unwinnable, network-effect-locked market. gitsafe keeps the one defensible idea (recipients = branch readers, a portable signed policy) and ships it as a **git-native overlay**, trading the unwinnable VCS war for a winnable plugin niche on top of git's distribution.

## The gating decision (already made): git-native, not a VCS

Reposition from "a VCS" to "a tool that runs on top of real git repos." Keep the valuable engine — **recipients = branch readers**, the **portable ed25519 signed policy chain**, **age encryption**. Discard the parts with no market value — the custom object store, merge engine, and wire protocol.

Why this is non-negotiable:

- **Adoption cost collapses** from "abandon your toolchain" to "add one tool." CI, GitHub, IDEs, and review flow all keep working.
- The comparison set becomes `git-crypt` / `SOPS` (plugins people already adopt freely), not git itself.
- It rides git's distribution instead of fighting git's network effects.

**Consequence of refusing the pivot:** OSS adoption → ~0, revenue → 0. Only the career outcome survives (a from-scratch VCS is a fine portfolio piece regardless). So "keep it a VCS" reduces the four goals below to one.

## Win conditions — all four, sequenced (not parallel)

A solo builder cannot run OSS community-building, enterprise sales, and audit prep at once. These are a **dependency chain**, run in order, with cheap exits:

| Phase | Goal it delivers | Time | Spend |
|------|------------------|------|-------|
| 0 — Validate | De-risk + most of Career | wks 1–4 | ~$0 |
| 1 — OSS launch | Adoption + reputation + rest of Career | mo 2–4 | ~$0 |
| 2 — Revenue | Money | mo 6–18 | audit ~low 5 figures |

Career signal is **guaranteed and cheap** — banked in Phase 0–1 by writing the work up — regardless of whether adoption or revenue ever materialize.

---

## Phase 0 — Validate (weeks 1–4, ~$0)

Cheapest possible go/no-go before writing more code.

- **Landing page** with the one-line pitch + an asciinema demo: `mark .env → git add → it's ciphertext → teammate with read access decrypts automatically → attacker with the repo gets garbage`. Email capture.
- **15–20 customer-discovery calls** with the real user (platform / DevSecOps engineers at 20–500-person companies). Ask what they use today and what they hate. **Do not pitch — listen.**
- **Write up the engineering as you go** (the signed policy chain, branch-derived recipients, the git-overlay filters). These posts are both launch material and the career deliverable.

**Kill criteria (decide now):** if after 20 calls nobody describes the secrets-in-git-with-ACL problem as painful *and* current tools as inadequate, stop and bank the career win. Don't romance a dead thesis.

## Phase 1 — OSS launch (months 2–4) → users + reputation

Developer bottom-up. Free tool, mindshare first.

- **Positioning (canonical copy):** *"git-crypt with access control. Encrypt secrets in your repo to exactly the people who can read the branch — enforced by a signed policy that verifies offline, with no vendor."*
- **Ship one sharp tool, not a platform.** Beat `git-crypt`/SOPS on the single axis they're weak: a portable, signed, offline-verifiable, branch-scoped access policy with key rotation. Cut everything else.
- **Channels, in order:** Show HN → Lobsters → r/devops, r/netsec, r/programming → get into "SOPS vs git-crypt vs …" comparison content → conference/meetup talk ("we built a VCS from scratch; here's the secrets engine that survived").
- **Metric that matters:** weekly **active repos** using it + inbound "can it do X" issues. Not GitHub stars (vanity). 50 real users > 2,000 stars.

**Checkpoint:** if 6–8 weeks post-launch there's no cohort using it on real repos and asking for features, the OSS thesis is weak — fall back to the career bank and stop.

## Phase 2 — Revenue (months 6–18, *only if Phase 1 shows pull*) → money

Do **not** start here. Start a company only after demand is proven. Two routes:

- **Open-core / team layer:** CLI stays free; sell the collaboration layer teams actually pay for — shared policy management, audit logs, rotation automation, a hosted policy/recipient directory. (People pay for the *collaboration layer*, never the tool itself.)
- **Compliance vertical:** narrow to one buyer with budget and a mandate — air-gapped / defense / fintech / healthcare that needs encrypted-at-rest + offline-verifiable ACL and distrusts SaaS secret managers. **Requires a security audit** (the entire pitch is security; an unaudited tool is a non-starter for these buyers). Land 2–3 design partners *before* building anything bespoke.

Honest constraints: revenue almost certainly needs a **co-founder** (can't build + sell + manage audit solo) and the TAM is small. Optional upside, not the plan.

---

## Competitive landscape

| Tool | Encrypts in git | Branch-scoped access | Portable signed policy | Rotation | Vendor-free |
|------|:---:|:---:|:---:|:---:|:---:|
| git-crypt | ✅ | ❌ | ❌ | ❌ | ✅ |
| SOPS | ✅ | ❌ | ❌ | manual | ✅ (age/PGP) |
| sealed-secrets | k8s only | ❌ | ❌ | ⚠️ | ✅ |
| Vault / Doppler / Infisical | ❌ (pulls out) | ⚠️ | ❌ | ✅ | ❌ |
| **gitsafe** | ✅ | ✅ | ✅ | ✅ | ✅ |

The two filled columns no one else has — **branch-scoped access** and **portable signed policy** — are the entire reason to exist. If those don't land in discovery, there is no product.

## First two weeks (concrete)

1. **Commit to the overlay positioning** (or consciously choose portfolio-only and skip to the career write-ups).
2. Stand up the landing page + record the asciinema demo (one day).
3. Book the first 5 discovery calls; ship the first engineering deep-dive post.
4. **Prototype the git clean/smudge integration against a real repo** to prove the overlay is technically sound — the riskiest technical assumption; de-risk it first (see `docs/design.md`).

## Blunt summary

- **Career: guaranteed, cheap, basically already earned.** Bank it by writing up the work now, no matter what.
- **OSS adoption: achievable — but only as a git overlay, and only if discovery confirms the pain.**
- **Revenue: real but a long shot** — needs pull, a vertical, an audit, probably a co-founder. Don't lead with it.
- **Validate: the gate you run first** so the other three aren't built on a guess.

Sequence them. Don't parallelize.
