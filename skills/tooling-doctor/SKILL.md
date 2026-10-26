---
name: tooling-doctor
description: Audits, cleans up and repairs a Claude Code tooling layer itself — .claude/ (skills, commands, rules, docs, agents, hooks, settings) plus an optional .agents/ Codex mirror — with a read-only linter that grades findings P0-P3. Use for "audit the skills", "audit the config", "tooling audit", "clean up .claude", "check my skills", "why isn't my skill loading", "is my config stale", or after retiring an app, service, MCP server or website.
---

# Tooling Doctor

The tooling layer is instructions Claude *obeys*. When it rots, Claude confidently does the
wrong thing — deploys from a deleted tree, routes an app at a retired runtime, quotes a port
nothing binds, or exposes a credential file. This skill treats `.claude/` as a codebase and
lints it.

## Prime directive

**Run the script. Never hand-count.**

```bash
python .claude/skills/tooling-doctor/scripts/doctor.py            # full report
python .claude/skills/tooling-doctor/scripts/doctor.py --quiet    # hide P3
python .claude/skills/tooling-doctor/scripts/doctor.py --only retired
python .claude/skills/tooling-doctor/scripts/doctor.py --json     # for scripting
python .claude/skills/tooling-doctor/scripts/doctor.py --root /path/to/repo --config my.json
```

Run from the repo root (or pass `--root`). Exit 1 if any P0/P1 survives, 2 on setup error.
Python 3.9+, standard library only; `git` is used when present, not required.

Do not restate a number in prose that the script computes — that is exactly how the docs being
audited went stale in the first place. Quote the script's output.

## Setup (optional)

| File | Purpose |
| --- | --- |
| `retired.json` | your retired apps / services / MCP servers / hosts — copy `retired.example.json` |
| `doctor.config.json` | repo layout: archive globs, app-name prefix, ports doc, compose globs, count targets — copy `doctor.config.example.json` |

Without them the doctor runs on defaults. Without `retired.json` the `retired` check covers only
archived app directories, and is skipped when there are none (it never reads the example file). Archived app directories are picked
up from disk automatically (`archived_app_globs`), so never list them in `retired.json`.

## Modes

| Say | Do |
| --- | --- |
| "audit the skills / config", "tooling audit" | **Audit** — run the doctor, triage, report. No edits. |
| "fix it", "clean it up" | **Repair** — audit first, then apply fixes in the order below. |
| "I retired X" / after archiving an app | **Register** — add X to `retired.json`, re-run `--only retired`, fix every hit. |
| "why isn't my skill loading?" | `--only frontmatter`, `--only overrides`, then `--only spec`. Those three explain almost every case. |

## The twelve checks

| Check | Catches | Why it bites |
| --- | --- | --- |
| `frontmatter` | missing/mismatched `name:`, thin or absent `description:` | a skill with a bad description is invisible — it never triggers |
| `overrides` | `skillOverrides` entries naming nothing; skills in `skills/` but forced `off` | dead config hides which skills are really live |
| `collisions` | same name as both a command and a skill; vendored bundles shadowing local skills | one silently wins, the other is unreachable |
| `mirror` | `.agents/` (Codex) content differing from `.claude/` | two agents running different instructions for the same skill |
| `paths` | backticked repo-root paths that do not exist | Claude follows the path, finds nothing, improvises |
| `retired` | live files describing a retired thing with **no caveat near the mention** | the #1 cause of confidently-wrong action |
| `size` | `SKILL.md` over 2500 words | SKILL.md loads **in full** on every trigger; detail belongs in a sidecar |
| `spec` | frontmatter vs the published Agent Skills / Claude Code spec: unknown keys (`args:` instead of `argument-hint:`), bad `name`, description > 1024 chars or description + `when_to_use` > 1536, no "Use when …" cue, first-person voice, XML-tag text, body > 500 lines | an ignored key does nothing and nobody notices; a description with no *when* never triggers |
| `ports` | ports-doc rows nothing binds; bound ports missing from the doc | wrong port = wasted debugging |
| `counts` | "N skills / N apps / N rules" claims contradicting reality | snapshots rot; one wrong count discredits the whole doc |
| `hooks` | hook scripts that do not exist; the same hook registered in two settings files | a duplicate registration fires the hook twice per event |
| `secrets` | files whose **name and body** are both credential-shaped and are tracked or not gitignored | credentials in a tooling dir that may be pushed |

## Triage

Severity is about *what Claude will do wrong*, not tidiness.

- **P0** — a credential is exposed, or an instruction will cause a destructive/irreversible action.
- **P1** — Claude will act on false information (retired thing described as live; missing/broken skill; mirror drift).
- **P2** — Claude will waste effort or give a wrong answer (bad paths, ghost ports, wrong counts, spec violations).
- **P3** — clutter and drift risk. Batch these; never let them crowd out P1.

**Historical files are exempt** — anything under `skills-archive/`, `skills-disabled/`,
`commands-archive/`, or any `history.md` / `CHANGELOG.md` (configurable). Never "fix" a history
log: a past audit that mentions a since-deleted app is *correct*.

## Repair order

Work top-down; each step is safe to stop after.

1. **P0 secrets** — get the file gitignored (or out of the tree), then ask whether the credential is
   still needed. A key for a retired service is a liability, not an asset. If it was ever pushed,
   rotate it — removing it from the tree does not remove it from history.
2. **`retired` hits** — for each file, either correct the claim or add one explicit caveat line. A
   caveat within 3 lines of the mention (or in its section heading) clears it; prefer one accurate
   sentence over rewriting a table.
3. **`frontmatter` + `collisions` + `spec`** — a skill that never loads is 100% wasted. Rename ignored
   keys (`args:` → `argument-hint:`) and add the missing "Use when …" sentence; never shorten a
   description by dropping a rule or a trigger.
4. **`ports` / `counts`** — regenerate from the source of truth (compose files, `ls -d apps/*/`), never
   from another doc. `scripts/gen_ports.py` rewrites the generated block of the ports doc.
5. **`paths`** — read `reference.md` first; app-relative paths are a known false positive.
6. **`mirror`** — copy `.claude/skills/<n>/` → `.agents/skills/<n>/`. Never hand-edit the mirror.
7. **`overrides`** — delete dead entries **only after** confirming no user-global skill or command
   has the name (plugin skills ignore `skillOverrides`; manage them with `/plugin`). For present-but-off skills, pick one: move the folder to `skills-disabled/` **or** drop the
   override.
8. **`size`** — split the body into `reference.md`; keep triggers, the decision table and the prime
   directive in `SKILL.md`.

Deleting anything (skill folder, credential file, archive dir, override) is **ask-first** — the
doctor never deletes, and neither should you without an explicit yes. Back up `settings*.json`
before editing it.

## After any repair

Re-run the doctor and quote the new counts. A repair you did not re-measure is a claim, not a result.

## Extending it

New check → add a function to `CHECKS` in `scripts/doctor.py`, then prove it with a planted positive
and a planted negative control (see `reference.md`). Newly retired thing → one row in `retired.json`;
that row is the entire maintenance cost.

Known false positives, per-check tuning notes and lessons learned live in `reference.md` next to this
file. Read it before dismissing a finding as noise.
