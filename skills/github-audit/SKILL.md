---
name: github-audit
description: Read-only audit of a GitHub account via the gh CLI. Primary focus is personal-data, banned-term and secret exposure on third-party infrastructure; then stale-repo lifecycle, dependency and CI/CD hygiene (Dependabot, SHA-pinned actions, zizmor). Grades each repo P0-P3 / A-F, account grade = worst repo. Optional pre-push mode scans outgoing commits of a local repo. Use when the user says "github audit", "audit github", "repo audit", "gh audit", "what's on github", "is any personal data on github", "safe to push?" or "audit before push".
---

# GitHub Account & Repository Audit

## Why this skill is ordered the way it is (read first)

A naive repo audit grades on Dependabot alerts and branch protection — and will happily give **Grade A**
to a repo full of therapy notes, health records or bank statements because its dependencies are current.
"Private" on GitHub is not private: the platform operator has access, it is subpoenable and breachable.

**Threats, in priority order:**
1. Personal / family / legal / financial data on GitHub
2. Self-identifying content that breaks the user's own privacy rules
3. Banned-term leakage (locations, company names, registration IDs — from the user's pattern file)
4. Live secrets in code or history (native secret scanning is paid on private repos → scan locally)
5. Stale repos accumulating without lifecycle review
6. *Then* Dependabot alerts, secret/code scanning, CI hardening

Audit in that order. A repo with `THERAPY_NOTES.md` is **F** even if every dependency is current.

**Read-only by default.** The audit never deletes, force-pushes, rewrites history or changes settings.
Remediation is emitted as commands/scripts for the user to run after an explicit per-repo yes.

## Inputs

| Input | How | Default |
| --- | --- | --- |
| Account / org | `$GH_OWNER` env var or the user's message | `gh api user --jq .login` |
| Pattern file | `patterns.local.sh` next to this SKILL.md (gitignored) | **required** — see Setup |
| Report path | `reports/YYYY-MM-DD-github-audit.md` (gitignored) | — |

Auth: `gh auth status` must show a logged-in account. Never ask for a token in chat; `gh` reads its own
credential store or `GH_TOKEN` from the environment. If not logged in, ask the user to run `gh auth login`
in their own terminal (device-flow codes can't be captured by a tool shell).

## Setup — the local pattern file (REQUIRED)

Real match terms live in **`patterns.local.sh`** — gitignored, never committed. This SKILL.md and
`reference.md` carry **no** real terms by design, so a future history scrub of those terms can't rewrite
the scanner into searching for `[REDACTED]` and reporting a false all-clear.

```bash
SK=.claude/skills/github-audit
PF="$SK/patterns.local.sh"
[ -f "$PF" ] || { echo "MISSING $PF — cp $SK/patterns.example.sh $PF and fill in your terms"; exit 1; }
source "$PF"   # exports BANNED HIGH_SIGNAL EXCLUDE NAME PII PERSONAL_PATHS SECRETS
OWNER="${GH_OWNER:-$(gh api user --jq .login)}"
```

If the file is missing, STOP and ask the user to create it from `patterns.example.sh`. Never invent terms.

All snippets are **bash**. On Windows run them in Git Bash / WSL, not PowerShell.

## Two run modes

| Mode | When | What it does |
| --- | --- | --- |
| **A — Pre-push safety** | "safe to push?", before pushing from a local repo | Scans outgoing commits, outgoing diff, working tree and history range for banned terms, PII, personal files and secrets. Snippet → reference.md *Mode A*. |
| **B — Full account audit** | Quarterly; before granting access; "github audit" | Enumerates every repo via `gh`, classifies, scans what is **already** on GitHub, then lifecycle + dependency + CI hygiene. |

Not for: container security → `docker-audit`; app architecture → `app-audit` / `fleet-audit`;
public website leaks → `pii-leak-sweep`.

---

## Mode B — Full account audit (run in this order)

1. **Discover** all repos: `gh repo list "$OWNER" --limit 1000 --json name,isArchived,isFork,pushedAt,description,visibility,defaultBranchRef,diskUsage`
2. **Classify** each repo by content (Category 1) — drives everything else
3. **Personal-data exposure** (Category 2) — P0 findings here
4. **Banned-term leakage** (Category 3) — uses the pattern file
5. **Secret scan** (Category 3b) — scratch clone + gitleaks
6. **Lifecycle review** (Category 4)
7. **Dependency / CI hygiene** (Categories 5-7) — only matters once 1-5 are clean
8. **Report** with explicit DELETE / REDACT recommendations → `reports/YYYY-MM-DD-github-audit.md`
9. **Deletes / rewrites** → output a one-shot script; the user runs it after an explicit per-repo yes

## Category 1: Repo classification (runs first)

Classes: **personal-life** → DELETE unless explicit consent · **mixed** → SPLIT · **financial-leak** →
DELETE or REDACT-then-rotate · **business-code** → keep · **stale-business** (>90 days) → archive/delete ·
**fork-mirror** → delete unless used · **personal-utils** → keep. Classify via
`gh api repos/$OWNER/REPO/contents` against `$PERSONAL_PATHS`. **`personal-life` = automatic F.**
Full table → reference.md Phase 2.

## Category 2: Personal data exposure (P0)

**P0:** 2.1 personal-life / mixed repo on GitHub · 2.2 bank/financial paths (`$PERSONAL_PATHS`) ·
2.3 `cookies.txt` / `*.session` / `auth_*.json` · 2.5 `production-keys*` / `*-keys.txt` / `secrets.txt` ·
2.7 real name (`$NAME`), address, phone (`$PII`), salary in README / CLAUDE.md / package.json (a
deliberate copyright footer is the documented exception). **P1:** 2.4 Postman collections ·
2.6 `test-password*` / hardcoded test creds. Loop + README scan → reference.md Category 2.

## Category 3: Banned-term leakage (P0)

Never inline terms here — they come from the pattern file.

**Primary method = scratch clone of the pushed branches + `rg --hidden`.** GitHub code search is a
best-effort cross-check only: it indexes the default branch only, lags on private repos, and has returned
`0` for identifiers a local grep found dozens of times.

```bash
R="$(mktemp -d)/gh-audit-REPO"
git clone --quiet --no-single-branch --depth 1 "https://github.com/$OWNER/REPO.git" "$R"   # read-only
rg --hidden -inE "$BANNED" "$R" | { [ -n "$EXCLUDE" ] && grep -viE "$EXCLUDE" || cat; } > "$R.hits"
wc -l < "$R.hits"
rg --hidden -inE "$HIGH_SIGNAL" "$R"    # the real P0 signal
rm -rf "$R" "$R.hits"
```

Grade on `$HIGH_SIGNAL` (unambiguous identifiers). Common country/city words appear legitimately in i18n
lists, training data and marketing copy — they inflate the raw count without being a personal leak.
To scan **all history**, not just the tip, use the bare-clone loop in reference.md (`git grep` over
`rev-list --all`).

| Match in | Severity | Action |
| --- | --- | --- |
| Active public-facing repo | **P0** | Redact + history scrub, or delete repo |
| Internal/dev repo | **P1** | Redact in next push |
| Self-identifying name + bio/certs in README (not a copyright footer) | **P0** | Reduce to a copyright-only footer |

## Category 3b: Secret scan (P0) — local, because native scanning is paid on private repos

Native secret scanning + push protection are **free on PUBLIC repos only**; private repos need the paid
**GitHub Secret Protection** add-on (Team / Enterprise Cloud). The line is public-vs-private, not plan tier.
So scan locally:

```bash
B="$(mktemp -d)/REPO.git"
git clone --quiet --bare "https://github.com/$OWNER/REPO.git" "$B"
if command -v gitleaks >/dev/null; then
  gitleaks git --no-banner "$B" || echo "*** gitleaks findings in REPO ***"
else
  git -C "$B" rev-list --all | xargs -r -n 200 git -C "$B" grep -inE "$SECRETS" 2>/dev/null | head -50
fi
rm -rf "$B"
```

`ghp_` / `gho_` / `github_pat_` tokens, `sk-` LLM keys, `AKIA…` AWS keys, `AIza…` Google keys, Slack
`xox*`, PEM private keys → **P0: rotate the credential FIRST**, then scrub history. A force-push leaves the
secret retrievable via per-SHA cached views, PR refs and forks until GitHub Support purges them — history
rewriting is cleanup, not mitigation (playbook in reference.md).

Tooling notes: gitleaks v8.19+ uses `gitleaks git <path>` (history) / `gitleaks dir <path>` (tree);
`detect` / `--source` are deprecated. **Never install Trivy v0.69.4 (binary) or v0.69.5 / v0.69.6 (Docker
Hub images)** — compromised releases, GHSA-69fq-xp46-6x23. Optional PII rule layer for gitleaks →
reference.md.

## Category 4: Lifecycle hygiene

4.1 no commits 90+ days → archive (P2) · 4.2 180+ days → **delete candidate** (P1) · 4.3 archived +
unrelated → delete (P2) · **4.4 archived + personal data → delete now (P0)** · 4.5 description says
deprecated (P2) · 4.6 duplicate of code that lives elsewhere (P2). Query → reference.md.

## Categories 5-7: Repo / security / CI hygiene

Only graded once 1-4 are clean. Full tables + commands in `reference.md`:
**5** README / description / `.gitignore` covers `.env*` / AGENTS.md / branches ·
**6** Dependabot alerts (`--paginate` — default page = 30), secret/code scanning (plan-limited → 3b),
branch protection · **7** workflows **SHA-pinned + least-privilege (automate with zizmor via `uvx`)**,
`dependabot.yml`, stale PRs.

- **7.2b — Trivy Actions referenced by tag/branch = P0.** `aquasecurity/trivy-action` tags 0.0.1–0.34.2
  and all `aquasecurity/setup-trivy` tags were force-pushed to credential-stealing commits
  (GHSA-69fq-xp46-6x23). Any workflow that ran such a ref → rotate every secret it could read.
  Safe pin = trivy-action v0.35.0 `57a97c7e7821a5776cebc9bb87c984fa69cba8f1` (re-verify with
  `git ls-remote --tags https://github.com/aquasecurity/trivy-action`).
- zizmor finding map: template-injection / dangerous-triggers / artipacked = **P1**; unpinned-uses /
  excessive-permissions = **P2**.

## Severity & grading

| Severity | Examples |
| --- | --- |
| **P0** | Personal data on GitHub; banned terms/name/PII in an active repo; live secrets; self-identifying README; hijacked Action ref that ran |
| **P1** | Stale >180 days; high Dependabot; `production-keys` file; `.env` not in `.gitignore`; Actions not SHA-pinned |
| **P2** | Stale 90-180 days; missing SECURITY.md; superseded duplicate repo; failing CI |
| **P3** | Missing topics, no PR template, branch hygiene, version-comment drift on a pinned SHA |

| Grade | Criteria |
| --- | --- |
| **F** | Any P0 |
| **D** | Multiple P1, or 1+ P0 partially mitigated |
| **C** | 3+ P1 |
| **B** | 1-2 P1, no P0 |
| **A-** | P2 only, ≤3 |
| **A** | Zero P0/P1/P2 |

**Account grade = lowest individual repo grade.** No amount of branch protection lifts a repo holding
personal data above F.

## Lessons baked in (don't repeat)

- **Code search lies — never trust a `0`.** Clone + grep is authoritative; code search only sees default
  branches and lags on private repos. Strip regex backslashes for code-search queries (`\.` → HTTP 422) and
  sleep ≥10 s between queries (secondary rate limit).
- **Scrubbing inline terms kills the scanner** → terms live only in the gitignored pattern file.
- **Personal-data check runs FIRST**, before any dependency grading.
- Archived repos are where `production-keys.txt`, `cookies.txt`, statements and Postman collections hide —
  scan them too.
- **`gh api` page size = 30** → always `--paginate` and sum.
- **`delete_repo` scope** is needed for deletes — check `gh auth status`; a refresh
  (`gh auth refresh -h github.com -s delete_repo`) must run in the user's own terminal.
- **Diverged local vs scrubbed remote:** if a remote was cleaned by history rewrite, a stale local clone
  still holds the old history — never force-push it back. Re-clone before any push.

**Full reference:** [reference.md](./reference.md) — discovery, classification, all category tables,
pre-push mode, remediation playbooks, report template, quick commands.
