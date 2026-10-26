---
name: app-audit
description: Audits ONE self-hosted web app (Next.js + Docker + Prisma, or a Python FastAPI service) against a configurable gold-standard baseline JSON and outputs a graded report card with P0-P3 findings, quoted evidence and a remediation plan. Read-only. Use when the user says "audit [app]", "app audit", "grade this app", "how good is [app]", "check this app against the baseline", or after a large change to one app. For many apps at once use fleet-audit; for container-only hardening use docker-audit.
argument-hint: '<path to app dir, e.g. apps/<name>> [--baseline nextjs|api|<path.json>] [--agents]'
---

# App Audit

Grade one application directory against a gold-standard baseline. The baseline is data (JSON), so the
same procedure works for any stack you write a baseline for.

**Read-only.** This skill never edits app code, installs into the app, rebuilds images, restarts
containers or deploys. It may run read-only commands (`npm audit --package-lock-only`, `tsc --noEmit`
in a scratch install, `docker inspect`, SQL `SELECT`). Fixes are handed back as a plan — apply them
with `app-update` or by hand, after the user says so.

## Inputs

| Input | Default | Notes |
| --- | --- | --- |
| App dir | required | e.g. `apps/<name>`. If it does not exist, or sits under an archive dir, stop and say so. |
| Baseline | auto | `--baseline nextjs` / `api` / path to a JSON file. Auto: `next` in package.json → `nextjs.json`; FastAPI/Flask in requirements → `api.json`. |
| Agents add-on | auto | `baselines/agents.json` is added when the app calls an LLM (grep for `LLM_PROVIDER`, model-server URLs, `/generate`, LLM SDK imports). |
| App-specific baseline | optional | `<app>/.audit/gold-standard.json` (or a path in the fleet config). If present, it wins over the domain baseline for overlapping checks. |
| Version floors | `baseline_versions` in the baseline JSON | Placeholders until you set them. Re-verify each run (see *Version floors* below). |

Baselines ship in [`baselines/`](./baselines/): `nextjs.json` (57-check `audit_checklist`), `api.json`
(no checklist — derive checks from `requirements`, `anti_patterns`, `deployment_checklist`),
`agents.json` (20-item `audit_checklist`).

## Process

1. **Resolve the app and baselines.** Print which baseline(s) were loaded and their `version`.
   No app-specific baseline → say "domain baseline only" in the report.
2. **Load the checklist.** Use `audit_checklist` when the baseline has one. Otherwise derive checks from
   `requirements` + `anti_patterns` + `deployment_checklist`. `deployment_checklist`, `anti_patterns`
   and `known_gotchas` are supporting evidence, never a second score.
3. **Read the app's own docs** — `CLAUDE.md` / `AGENTS.md` / `README`. Treat every claim in them as a
   claim to verify, not as evidence.
4. **Stack + versions** — `package.json` AND `package-lock.json` (the range is not what is installed):
   ```bash
   node -e "const p=require('./package-lock.json').packages;for(const k of ['next','react','@prisma/client','typescript','jose','zod'])console.log(k,p['node_modules/'+k]?.version)"
   ```
   Python: every `==` pin in `requirements*.txt`, and which requirements file the Dockerfile actually COPYs.
5. **Docker** — `Dockerfile`(s) at every build context named in compose `context:`, `docker-compose.yml`,
   `.dockerignore` at each context. Grade from the files; a stopped Docker daemon is not a FAIL and you
   do not start it. If containers ARE running, also check DKR-014: `docker inspect <c> -f '{{.Image}}'`
   vs `docker images -q <image>`.
6. **Data layer** — `prisma/schema.prisma`, `prisma.config.ts`, `src/lib/prisma.ts` (adapter mandatory in
   Prisma 7; flag a reintroduced `db.ts`). If the DB is up, `SELECT` the job/run tables for the last
   7 days and `pg_total_relation_size` per table (OBS-006/007). Never write.
7. **Auth + request layer** — `src/lib/auth*.ts`, `src/proxy.ts` / `src/middleware.ts`, login route,
   lockout, rate limiter, CSRF, CSP. If the app vendors a shared auth core, diff it against its source
   (only an auto-generated header may differ). A hand-edited vendored copy or an unexpected auth library
   is a P1.
8. **Tests** — find them at unbounded depth (`find . -name '*.test.*' -not -path '*/node_modules/*'`);
   run them in a scratch copy or with the user's OK. Typecheck needs devDeps:
   `npm install --include=dev` then `node node_modules/typescript/bin/tsc --noEmit` (plain
   `npm install` may omit devDeps; a missing `tsc` reports nothing).
9. **Security sweep** — hardcoded secrets (`rg --hidden -n '(api[_-]?key|secret|password|token)\s*[:=]\s*["'\''][^"'\'']{12,}' -g '!node_modules' -g '!*.lock'`), input validation, rate limits, CSRF, upload limits, sidecar auth.
10. **Dependencies** — `npm audit --package-lock-only`; OSV for every Python pin; and the **vendor
    security page** for the framework (advisory DBs can lag the vendor by days — see below).
11. **Score** every checklist item PASS / PARTIAL / FAIL / N/A, with evidence.

### Evidence rules (non-negotiable)

- Every FAIL/PARTIAL quotes the offending line (`file:line` + the text) or the command output.
- Every "missing X" shows the search that proved absence — and the search must be wide enough.
  Rate-limit modules are named `ratelimit.ts`, `rateLimit.ts`, `rate-limit.ts`, `middleware/rateLimit.ts`;
  **a filename glob is not proof of absence** (Windows also hides case differences that break Linux builds).
- Exclude build output from every walk: `node_modules`, `.next`, `.venv`, `site-packages`, `dist`, `.git`.
  Generated trees contain their own Dockerfiles and old base images and produce phantom findings.
- LLM-driven audits run a high false-positive rate on "missing/broken" claims. Never grade down on an
   unverified finding.
- A "deliberate hold / accepted / do-not-re-flag" comment in the repo is a **claim**. Re-check it against
  the advisory DB every run, in both directions.
- A duplication finding must first check what IMPORTS each copy (an import-free twin can exist so a
  hermetic test runner can load it).

### Version floors

- Floors come from an **advisory range** (OSV `affected[].ranges[].events`) or a **vendor security
  release** — never from a blog post or search summary; articles routinely misquote the affected range.
- Check the vendor directly for the framework: `gh api repos/vercel/next.js/security-advisories`
  (or the vendor's security blog). OSV and the global GitHub DB can miss a vendor GHSA for days.
- `npm view <pkg> dist-tags` before recommending "latest" — a `latest` tag can point at a release-candidate major.
- Never write a version you have not looked up (`npm view <pkg> versions --json`, PyPI JSON API).

## Scoring

PASS = 1, PARTIAL = 0.5, FAIL = 0, N/A excluded from the denominator. Category score = points / applicable × 10.

| Grade | Score | Meaning |
| --- | --- | --- |
| A+ | 95–100 % | Production-ready, exemplary |
| A | 90–94 % | Production-ready |
| A− | 85–89 % | Near production, minor gaps |
| B+ | 80–84 % | Good, some improvements needed |
| B | 70–79 % | Acceptable, notable gaps |
| C | 60–69 % | Needs work |
| D | < 60 % | Significant issues |

**Severity override:** any open P0 caps the grade at C; any open P1 caps it at B, regardless of the percentage.

### Severity (P0–P3)

| Severity | Criteria | Response |
| --- | --- | --- |
| P0 | Credential exposed **with real exposure** (funded/reachable), auth bypass, data-loss risk, RCE in a reachable runtime dependency | Block release |
| P1 | Privilege escalation, network exposure, missing auth, Prisma 7 without adapter/config, hand-edited vendored auth, scheduled job failing silently | This sprint |
| P2 | Hardening gap, version below a security floor, missing tests on the security layer | Backlog (soon) |
| P3 | Optimisation, docs, minor drift | Nice to have |

Triage before assigning severity:
1. **Does it reach the runtime image?** If the runner stage copies only `.next/standalone` + static +
   prisma, devDependency advisories are build-time only — say so instead of quoting a raw `npm audit` total.
2. **Is npm's proposed fix a downgrade or a SemVer-major?** Then it is not a fix. Never `npm audit fix --force`.
3. **Is the vulnerable transitive overridable** within the parent's declared range? Then an `overrides`
   entry is the remediation — and it must be exercised before it counts.
4. **Is the credential funded / reachable?** A free-tier key in a `.dockerignore`d local `.env` is
   hygiene, not P0. Re-derive carried severities; never inherit them from a previous report.

## Output

Write to `reports/YYYY-MM-DD-app-audit-<name>.md` (gitignored) and print the summary.

```markdown
# App Audit: <name> — <date>

## Baselines used
- App-specific: yes/no (version)
- Domain: nextjs|api (version)
- Agents add-on: yes/no (version)
- Floors used: next >= x.y.z (source: <vendor URL / GHSA>), ...

## Report card
| Category      | Score | Pass/Total | Notes |
| ------------- | ----- | ---------- | ----- |
| Security      | /10   | X/Y        |       |
| Stack         | /10   | X/Y        |       |
| Docker        | /10   | X/Y        |       |
| Testing       | /10   | X/Y        |       |
| AI (add-on)   | /10   | X/Y        |       |
| Observability | /10   | X/Y        |       |
| **Overall**   | **Grade** | **X/Y** |      |

## Findings
| Sev | ID | Category | Check | Status | Evidence (file:line / command) |
| --- | -- | -------- | ----- | ------ | ------------------------------ |
| P1  | SEC-006 | Security | CSRF missing-Origin | FAIL | `src/proxy.ts:42  if (!origin) return NextResponse.next()` |

## Remediation plan (copy-paste fixes)
- **P0 (block release):** ...
- **P1 (this sprint):** ...  — include the exact diff/snippet
- **P2 (backlog):** ...
- **P3 (nice to have):** ...

## Verified clean
Short list of the checks that PASSED with the command that proved it.

## Missing from the baseline
Patterns found in the app that the baseline should learn (feedback loop).
```

### Before you hand it over

- Every FAIL/PARTIAL row has evidence; every "missing" has the proving search.
- Re-count Pass/Total from the findings table — the report card must add up.
- Say which checks were N/A and why (e.g. no DB running → OBS-006 not measured, not "passed").
- Say plainly what was NOT verified (tests not run, containers not running).

## Related

- `fleet-audit` — the same baselines across many apps, with cross-app checks and a fleet grade.
- `docker-audit` — deep container/network/host-runtime hardening.
- `app-update` — the fix half: safe dependency patching with verification.
