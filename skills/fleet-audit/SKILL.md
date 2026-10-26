---
name: fleet-audit
description: Runs an architecture + security audit across every app in a multi-app repo (a "fleet" of self-hosted Next.js / Python / Docker Compose apps), driven by a fleet config, and grades it P0-P3 with a per-app report card and a fleet grade. Checks stack compliance, Docker hardening, auth patterns, the Prisma 7 adapter, LLM-provider resilience, tests, dependency health against advisory feeds AND vendor security releases, security headers/rate limiting, env hygiene, agent docs and cross-app dependencies. Read-only audit; fixes only on explicit request. Use when the user says "fleet audit", "audit all apps", "audit the fleet", "fleet health", "architecture audit", or before/after fleet-wide dependency, Docker-standard or roster changes.
---

# Fleet Architecture Audit

Audit N apps against shared standards in **12 categories**, produce P0–P3 findings with quoted
evidence, a per-app report card and a fleet grade. This file is the entry point; the full checklists,
templates, gotchas and verification playbooks are in **[reference.md](./reference.md)**. Reproducible
checks are a script: **[scripts/quick-checks.sh](./scripts/quick-checks.sh)**. Per-app grading reuses
the `app-audit` baselines (`.claude/skills/app-audit/baselines/*.json`).

**Read-only by default.** The audit never installs, builds, restarts, pushes or deploys. If the user
asks for fixes afterwards, every fix is followed by a rebuild + health check (see *Post-fix
verification*) — a repinned file is not a fixed fleet.

## Configuration

Copy [`fleet.config.example.json`](./fleet.config.example.json) to `fleet.config.json` at the repo root
(or pass `--config`). It lists `apps_dir`, per-app `scope` (`full` / `source-only` / `reduced` / `skip`),
the `baseline` per app, shared compose dirs, version floors, an optional vendored-auth-core map and
`accepted_risks` (each with a reason and evidence, re-checked every run). Without a config the script
auto-discovers `apps/*`.

> **The roster changes between audits — never trust a hard-coded count.** Regenerate the live list
> first, diff it against the config, and treat any directory not listed as a **first-party full-audit
> target until proven otherwise**. Archive directories are out of scope unless the user scopes them in.

## Core process

1. **Discovery** — run `bash .claude/skills/fleet-audit/scripts/quick-checks.sh --config fleet.config.json`
   (add `--no-net` to skip npm/OSV/docker). Classify every dir. State the denominator.
2. **Per-app scan** — `package.json` + lockfile, compose, every Dockerfile at every build `context:`,
   `AGENTS.md`/`CLAUDE.md`, `src/lib/prisma.ts`, `src/lib/auth*.ts`, `src/proxy.ts` / `src/middleware.ts`,
   `.env.example`, sidecar dirs. Exclude `node_modules`, `.next`, `.venv`, `site-packages`, `dist`, `.git`.
3. **Verify before flagging (REQUIRED)** — every finding quotes the offending line(s); every "missing X"
   shows the search proving absence. Parallel LLM audit agents run a high false-positive rate on
   "missing/broken" claims (expect roughly a third); never grade down or fix on an unverified finding.
4. **Score the 12 categories** (reference.md). Prefer a check the user can re-run in one command; a
   rule with no runnable check behind it rots.
5. **Apply the triage rules** below, THEN aggregate by severity.
6. **Grade** (rubric below).
7. **Compare to the last report** in `reports/` — regressions, improvements, denominator change.
8. **Write the report** → `reports/YYYY-MM-DD-fleet-audit.md` (template in reference.md).
9. **If fixes were applied on request — rebuild and verify.** Report each app as **rebuilt+healthy**,
   **rebuilt+failed**, or **edited-only (not running, unverified)**. Never blur the three.
10. **Re-run the checks after fixing** and paste the new output. "Fixed" is a measurement.

> **Re-check every "held / accepted / do-not-re-flag" pin and every carried severity on EVERY run, in
> both directions.** In-repo hold comments look like settled decisions and nothing re-tests them; a
> confident "outside the CVE range" comment can be wrong because it quoted an article's range instead
> of the advisory's. Equally, some holds are correct — the goal is the fact, not a bias toward bumping.

## Severity & grading

| Severity | Criteria | Response |
| --- | --- | --- |
| **P0** | Credentials exposed **with real exposure** (funded / reachable), auth bypass, data-loss risk, reachable RCE | Fix now |
| **P1** | Privilege escalation, network exposure, missing auth, missing Prisma 7 adapter/config, hand-edited vendored auth, scheduled jobs silently failing | Fix today |
| **P2** | Hardening gap, version below a security floor, missing security-layer tests | Fix this week |
| **P3** | Optimisation, documentation, minor drift | Next session |

**Fleet grade:** A+ = 0 issues · A = 0 P0/P1/P2 · A− = 0 P0/P1 and 1–3 P2 · B+ = 4–6 P2 · B = 1–2 P1 or 7+ P2 ·
C = 1+ P0 or 3+ P1 · D = multiple P0 / systemic failures. Grade COTS/third-party stacks separately so
they do not mask or tank first-party results.

## Triage rules that change severity (apply BEFORE grading)

1. **Is it in the runtime image?** If the Dockerfile's runner stage copies only `.next/standalone` +
   static + prisma (Next.js `output: 'standalone'`), devDependency advisories are build-time only. Say so
   instead of quoting a raw `npm audit` total.
2. **Is npm's proposed fix a downgrade or SemVer-major?** Then it is not a fix. **Never run
   `npm audit fix --force`** — by npm's docs it installs SemVer-major changes (it has proposed Prisma 6
   to clear a Prisma 7 transitive, which would break the mandatory adapter).
3. **Is the vulnerable transitive overridable?** If the fixed version satisfies the parent's declared
   range, an `overrides` entry is the remediation — then exercise the code path that loads it.
4. **Is the credential funded / reachable?** A free-tier key in a `.dockerignore`d local `.env` is
   hygiene, not P0. Re-derive every carried severity from first principles.
5. **Is the advisory DB behind the vendor?** For Next.js / Prisma / Node, read the vendor security page
   (`gh api repos/vercel/next.js/security-advisories`). OSV and the GitHub global DB can lag a vendor
   GHSA by days; `npm audit` cannot see it at all until then.

## Execution strategy

Default = reproducible greps (the script) + targeted reads, **no agent delegation**. Delegate only
behavioural reads (auth flow, CSRF/rate-limit posture, LLM-client fallback, test quality), in 2–3
batches grouped by surface (e.g. apps with Python sidecars / newer JWT apps / desktop + COTS). Each
delegated agent must return quoted evidence. The main thread aggregates and grades. Never trust
`AGENTS.md`, overview docs or port registries over the compose files — ports, subnets and auth
patterns in docs drift.

## Quick diagnostic checks

```bash
bash .claude/skills/fleet-audit/scripts/quick-checks.sh --config fleet.config.json          # all checks
bash .claude/skills/fleet-audit/scripts/quick-checks.sh --config fleet.config.json --no-net # offline
NEXT_FLOOR=16.4.1 bash .claude/skills/fleet-audit/scripts/quick-checks.sh                   # ad-hoc floor
```

Covers: roster vs config, compose files by content, declared vs resolved versions, vendor-floor check,
`0.0.0.0` / IP-less host binds, undigested bases, image-pin census, per-stack hardening presence,
`:-` fallbacks on secrets, `localhost` health checks, Prisma 7 adapter/config, LLM provider defaults +
`extra_hosts`, `npm audit` per lockfile, OSV over every Python pin (`scripts/osv-pins.py`), phantom
imports (`scripts/undeclared-imports.py`), vendored auth drift, test counts at unbounded depth, agent
docs, `.dockerignore` at the real build context, and running-image == built-image for stacks that are up.

## When NOT to use

- One app → `app-audit`. Container/host-runtime hardening deep dive → `docker-audit`.
- Live pentest → the `senior-pentester` agent. Dependency remediation → `app-update`.

## Related

`app-audit` (baselines) · `docker-audit` · `app-update` · [reference.md](./reference.md)
