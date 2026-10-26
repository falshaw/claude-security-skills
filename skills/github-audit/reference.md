# GitHub Audit — Full Reference

> Match terms (banned words, name variants, PII, secret prefixes) are **not** in this file. They live in the
> gitignored `patterns.local.sh` next to it (template: `patterns.example.sh`). Always source it first:
>
> ```bash
> source .claude/skills/github-audit/patterns.local.sh
> OWNER="${GH_OWNER:-$(gh api user --jq .login)}"
> ```

## Contents

- Account context (what to record per run)
- Phase 1 Discovery · Phase 2 Classification
- Categories 2-7 (personal data, banned terms, secret scan + optional PII layer, lifecycle, repo hygiene,
  security posture, CI/CD)
- Mode A — pre-push safety snippet
- Severity & grading · Documented exceptions · Remediation playbooks · Report template · Quick commands ·
  Pitfalls

---

## Account context (record at the top of each report)

| Field | How |
| --- | --- |
| Owner | `$OWNER` |
| Plan | `gh api user --jq .plan.name` (or org: `gh api orgs/$OWNER --jq .plan.name`) |
| Repo counts | active / archived / forks / public / private from Phase 1 |
| Token scopes | `gh auth status` (look for `repo`, `workflow`, `delete_repo`, `security_events`) |
| Token type | classic PAT vs fine-grained — flag broad classic scopes |
| CI | which repos have `.github/workflows/` |

Plan reality: on GitHub Free, private repos have no branch protection on most plans and no native secret
or code scanning (those need **GitHub Secret Protection** / **GitHub Code Security**, the paid products
GHAS was un-bundled into, Team / Enterprise Cloud only). Public repos get secret scanning, push protection,
code scanning and CodeQL free. → On private repos, the local scan in Category 3b is authoritative.

---

## Phase 1: Discovery

```bash
gh auth status
gh repo list "$OWNER" --limit 1000 --no-archived --json name,defaultBranchRef,pushedAt,diskUsage,description,visibility,isFork
gh repo list "$OWNER" --limit 1000 --archived --json name,pushedAt,diskUsage,visibility
gh api --paginate "repos/$OWNER/REPO/branches" --jq '.[].name'     # every pushed branch, per repo
```

## Phase 2: Classify each repo (THE FIRST CHECK)

Fetch top-level entries with `gh api repos/$OWNER/REPO/contents`, match against `$PERSONAL_PATHS`:

| Class | Trigger | Default action |
| --- | --- | --- |
| **personal-life** | matches `$PERSONAL_PATHS` (evidence / legal / finance / therapy / medical / journal / witness / family …) | **DELETE** unless explicit consent |
| **mixed** | personal markers + business code in one repo | **SPLIT**: extract personal, delete the personal half (and its history) |
| **financial-leak** | `Statements/`, `salary*`, `bank*`, Postman collections, `cookies.txt`, test portfolios | **DELETE or REDACT-then-rotate** |
| **business-code** | `package.json` / `pyproject.toml` + product README + no personal markers | Keep, audit normally |
| **stale-business** | business-code, no commits >90 days | Archive or delete |
| **fork-mirror** | cloned upstream, no original work | Delete unless actively used |
| **personal-utils** | tiny utility (<200 KB), no sensitive content | Keep |

Classification drives everything. `personal-life` → automatic F. Top-level listing misses nested dirs —
for business-code repos also run the tree check:

```bash
gh api "repos/$OWNER/REPO/git/trees/HEAD?recursive=1" --jq '.tree[].path' | grep -iE "$PERSONAL_PATHS"
```

---

## Category 2 — Personal data exposure (P0)

| # | Check | How | Severity |
| --- | --- | --- | --- |
| 2.1 | No personal-life / mixed repos | classification | P0 |
| 2.2 | No financial paths | tree + `grep -iE "$PERSONAL_PATHS"` | P0 |
| 2.3 | No `cookies.txt` / `*.session` / `auth_*.json` | tree scan | P0 |
| 2.4 | Postman collections reviewed for tokens | content | P1 |
| 2.5 | No `production-keys*` / `*-keys.txt` / `secrets.txt` | tree scan | P0 |
| 2.6 | No `test-password*` / hardcoded test creds | tree scan | P1 |
| 2.7 | README / CLAUDE.md / package.json free of `$NAME` / `$PII` / salary (copyright footer exempt) | content | P0 |

```bash
for repo in $(gh repo list "$OWNER" --limit 1000 --json name --jq '.[].name'); do
  paths=$(gh api "repos/$OWNER/$repo/git/trees/HEAD?recursive=1" --jq '.tree[].path' 2>/dev/null)
  hits=$(printf '%s\n' "$paths" | grep -iE "$PERSONAL_PATHS|cookies\.txt|\.session$|auth_.*\.json$|-keys\.txt$" | head -5)
  [ -n "$hits" ] && printf '*** P0 *** %s\n%s\n' "$repo" "$hits" || echo "ok    $repo"
done
# README content scan
gh api "repos/$OWNER/REPO/readme" --jq '.content' | base64 -d | grep -inE "$NAME|$PII|salary|€ ?[0-9]+|EUR ?[0-9]+|\\$ ?[0-9]{2,}k"
```

## Category 3 — Banned-term leakage (P0)

**Authoritative method = local clone + grep of what is actually pushed** (all branches, optionally all
history). Code search is a cross-check only — it is default-branch-only and its private-repo index is
incomplete and laggy.

```bash
# Private repos: run `gh auth setup-git` once so these clones use the gh token.
# Tip of every pushed branch
R="$(mktemp -d)/REPO"
git clone --quiet --no-single-branch "https://github.com/$OWNER/REPO.git" "$R"
for b in $(git -C "$R" branch -r | grep -v HEAD); do
  git -C "$R" grep -inE "$BANNED" "$b" -- . | { [ -n "$EXCLUDE" ] && grep -viE "$EXCLUDE" || cat; }
done | tee "$R.hits" | wc -l
git -C "$R" grep -inE "$HIGH_SIGNAL" $(git -C "$R" branch -r | grep -v HEAD) -- .   # real P0 signal

# ALL history (slow on big repos — scope with --since if needed)
git -C "$R" rev-list --all | xargs -r -n 200 git -C "$R" grep -ilE "$HIGH_SIGNAL" | sort -u | head -50
rm -rf "$R" "$R.hits"
```

Optional remote cross-check (best effort, never trust a `0`):

```bash
IFS='|' read -ra TERMS <<< "${BANNED//\\/}"     # strip backslashes — code search 422s on \.
for term in "${TERMS[@]}"; do
  r=$(gh api -X GET search/code -f q="user:$OWNER \"$term\"" --jq '.total_count' 2>/dev/null)
  case "$r" in ''|*message*) echo "  [throttled — rely on clone+grep] $term"; sleep 30;; 0) ;; *) echo "  [$r] $term";; esac
  sleep 10    # secondary rate limit 403s well under the documented 10/min
done
```

> **Interpreting the count:** common country/city words appear legitimately in i18n lists, ML training data
> and market-targeted copy. A raw count can run into the thousands and mean little. Grade on the
> unambiguous `$HIGH_SIGNAL` identifiers (home city, company names + registration IDs, phone, address,
> domains), and use `$EXCLUDE` for known false-positive residue (e.g. an old brand containing a term).

| Where | Severity | Action |
| --- | --- | --- |
| Active public-facing repo | P0 | Redact + history scrub, or delete |
| Self-identifying README (not a copyright footer) | P0 | Reduce to a copyright-only footer |
| Internal/dev repo not deployed | P1 | Redact in next push |

## Category 3b — Secret scan (P0, local)

```bash
B="$(mktemp -d)/REPO.git"
git clone --quiet --bare "https://github.com/$OWNER/REPO.git" "$B"
if command -v gitleaks >/dev/null; then
  gitleaks git --no-banner "$B"
elif command -v trufflehog >/dev/null; then
  trufflehog git "file://$B" --results=verified,unknown
else
  git -C "$B" rev-list --all | xargs -r -n 200 git -C "$B" grep -inE "$SECRETS" 2>/dev/null | head -50
fi
rm -rf "$B"
```

Any verified hit → **rotate the credential first**, then scrub history. Prefixes covered by the example
`$SECRETS`: `gh[pousr]_`, `github_pat_`, `sk-`, `AKIA`, `AIza`, Slack `xox*`, PEM private keys.

Tool notes:
- **gitleaks v8.19+**: verbs are `git` / `dir` / `stdin`; path is positional; `detect` / `--source` are
  deprecated. `git` = committed history, `dir` = working tree. Exit 1 = leaks OR error. Newer versions add
  archive scanning (`--max-archive-depth`) and composite rules (`[[rules.required]]`).
  Install: `scoop install gitleaks`, `brew install gitleaks`, or
  `go install github.com/gitleaks/gitleaks/v8@latest`.
- **trufflehog**: `--only-verified` is undocumented now → use `--results=verified,unknown`.
- **trivy**: `trivy fs --scanners secret,misconfig <dir>` is a usable second pass. **Never v0.69.4
  (binary) or v0.69.5 / v0.69.6 (Docker Hub)** — compromised releases, GHSA-69fq-xp46-6x23. Use v0.69.3 or
  a later verified release.

> **Tokens (fine-grained vs classic):** prefer fine-grained PATs with an expiry, scoped to the needed repos.
> Broad classic PATs (`repo`, `workflow`, `delete_repo`) are the higher-risk pattern — acceptable for an
> interactive solo admin, never embedded anywhere. For a leaked GitHub PAT there is a self-service
> Credential Revocation API in addition to deleting it in Settings, and secret-scanning partner programs
> auto-revoke many provider tokens. Treat any leaked token as actively harvested.

#### Optional PII layer (one pass with the secret scan)

A gitignored `pii.local.toml` next to `patterns.local.sh` lets gitleaks also catch the owner's own phone /
email in the same run:

```toml
[extend]
useDefault = true          # keep the default secret ruleset, add PII on top
[[rules]]
id = "own-phone"
description = "Owner phone number"
regex = '''\+00 ?555 ?0100'''          # replace with your exact number pattern
tags = ["pii","phone"]
[[rules]]
id = "own-email"
description = "Owner personal email"
regex = '''(?i)\bjane\.example@(example\.org|example\.net)\b'''   # replace
tags = ["pii","email"]
```

Run: `gitleaks git --no-banner --config .claude/skills/github-audit/pii.local.toml <repo>`. Go RE2 has
**no lookahead and no multiline-by-default** — scope rules to KNOWN exact values (not a generic "any
phone"), and test on a known sample. Exact-string rules are the right primary method for a finite known
identifier set; NER tools (e.g. Microsoft Presidio) are only worth it for unknown third-party names.
Don't add `detect-secrets` — redundant with gitleaks.

## Category 4 — Lifecycle hygiene

| # | Check | Severity |
| --- | --- | --- |
| 4.1 | Active repo, no commits 90+ days | P2 |
| 4.2 | Active repo, no commits 180+ days | P1 |
| 4.3 | Archived repo unrelated to active work | P2 |
| 4.4 | Archived repo classified personal-life | P0 |
| 4.5 | Description says deprecated / old / legacy / superseded | P2 |
| 4.6 | Two repos doing the same thing (e.g. a standalone copy of code that also lives in a monorepo) | P2 |

```bash
gh repo list "$OWNER" --limit 1000 --json name,pushedAt,isArchived \
  --jq '.[] | select(.pushedAt[:10] < (now - 90*86400 | strftime("%Y-%m-%d"))) | "\(.pushedAt[:10]) \(if .isArchived then "[A]" else "[ ]" end) \(.name)"'
```

## Category 5 — Repo hygiene

| # | Check | Severity | Typical exception |
| --- | --- | --- | --- |
| 5.1 | README.md exists | P3 | — |
| 5.2 | Description set | P3 | — |
| 5.3 | Topics set | P3 | personal-utils |
| 5.4 | `.gitignore` exists | P2 | — |
| 5.5 | `.gitignore` covers `.env*` | P1 | — |
| 5.6 | Default branch consistent | P3 | documented legacy name |
| 5.7 | No stale merged branches >90 days | P3 | — |
| 5.8 | AGENTS.md / CLAUDE.md exists (if AI agents work on it) | P2 | personal-utils, fork-mirror |
| 5.9 | Delete-branch-on-merge enabled | P3 | — |
| 5.10 | LICENSE present on PUBLIC repos | P2 | private repos |

## Category 6 — Security posture

| # | Check | Severity | Note |
| --- | --- | --- | --- |
| 6.1 | No critical Dependabot alerts | P0 | still below personal-data leakage in priority |
| 6.2 | No high Dependabot alerts | P1 | |
| 6.3 | Secret scanning enabled | P1 | plan-limited on private → Category 3b |
| 6.4 | Code scanning enabled | P2 | plan-limited on private |
| 6.5 | Branch protection / rulesets on default | P2 | plan-limited on private |
| 6.6 | SECURITY.md exists | P2 | |
| 6.7 | No open secret-scanning alerts | P0 | |

```bash
gh api --paginate "repos/$OWNER/REPO/dependabot/alerts?state=open&severity=critical" --jq 'length' | awk '{s+=$1} END {print s+0}'

# Triage to what actually has a fix, worst-first (EPSS-sorted):
gh api --paginate -X GET "repos/$OWNER/REPO/dependabot/alerts" \
  -f state=open -f severity=high,critical -f has=patch \
  -f sort=epss_percentage -f direction=desc \
  --jq '.[] | "\(.security_advisory.severity) \(.dependency.package.name) \(.security_advisory.cve_id // "-")"'
```

**Dependabot is free on private repos** across all three layers: **alerts** (on by default), **security
updates** (auto-PRs — opt-in; needs dependency graph + alerts), **version updates** (scheduled bumps —
opt-in via `.github/dependabot.yml`). The Settings sidebar labels these toggles "Advanced Security" — a
label, not a paywall. Classic-PAT scope for the alerts API: `security_events`.

**Native secret-scanning cross-check** (optional, NOT authoritative). On a Free-plan private repo this
returns **HTTP 404** — the expected state, not a finding:

```bash
gh api --paginate "repos/$OWNER/REPO/secret-scanning/alerts" --jq 'length' 2>/dev/null \
  || echo "404 expected — feature off on this private repo (use Category 3b)"
```

**Free local scanners** (no upload):

```bash
osv-scanner scan source -r .                               # dependency CVEs (OSV-Scanner v2)
trivy fs --scanners secret,misconfig --severity HIGH,CRITICAL .   # 2nd secret pass + Dockerfile/compose lint
# grype . — overlaps OSV/Trivy; only if you want a Syft SBOM
```

> **npm supply chain:** npm classic tokens were revoked registry-wide; publish/CI tokens must be granular,
> 2FA-enforced and short-lived — flag a classic `_authToken` in any committed `.npmrc` as dead and a leak
> risk. Self-replicating worms (Shai-Hulud class) harvested GitHub / npm / cloud tokens via postinstall
> scripts and exfiltrated them to **attacker-created public repos** — during the audit, watch for
> unexpected public repos, unfamiliar `.github/workflows/*` files and suspicious `postinstall` scripts.

> **CLI syntax drifts** — run `<tool> --help` once at the start of each run before relying on a flag
> (gitleaks, trufflehog, pinact `/v4` path, osv-scanner `scan source -r`, zizmor flags, EPSS sort params).

## Category 7 — CI/CD & PR hygiene

| # | Check | Severity |
| --- | --- | --- |
| 7.1 | ≥1 workflow exists (for active code repos) | P2 |
| 7.2 | Actions pinned to full commit SHA | P1 |
| 7.2b | `aquasecurity/trivy-action` / `setup-trivy` referenced by tag or branch | P0 if it ran |
| 7.3 | Workflow `permissions:` least-privilege | P2 |
| 7.4 | `dependabot.yml` exists | P2 |
| 7.5 | No stale / disabled workflows lying around | P3 |
| 7.6 | Workflows not consistently failing | P2 |
| 7.7 | No stale PRs (open >30 days) | P2 |
| 7.8 | Dependabot PR backlog <10 | P2 |
| 7.9 | PR / issue templates, CODEOWNERS, labels | P3 |

**7.2b detail:** per GHSA-69fq-xp46-6x23, `aquasecurity/trivy-action` tags 0.0.1–0.34.2 and all
`aquasecurity/setup-trivy` tags (v0.2.0–v0.2.6) were force-pushed to credential-stealing commits; the trivy
v0.69.4 binary and v0.69.5 / v0.69.6 Docker Hub images were malicious too. Safe: trivy-action **v0.35.0 =
`57a97c7e7821a5776cebc9bb87c984fa69cba8f1`**, setup-trivy 0.2.6 (recreated), trivy binary v0.69.2 / v0.69.3.
Verify: `git ls-remote --tags https://github.com/aquasecurity/trivy-action`. If a hijacked ref ever ran,
rotate every secret the workflow could read and review run logs from the compromise window. A correct SHA
with a wrong `# vX.Y.Z` comment = label drift, P3. Disabled workflow files still carrying `@master` refs
must be SHA-pinned before re-enabling.

```bash
# Find tag/branch-pinned uses across a cloned repo
rg -n 'uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)' --pcre2 "$R/.github/workflows"
```

**Automate 7.2 / 7.3 with zizmor** (MIT; runs via `uvx`, no install). zizmor has no dir-exclude flag, so
scope by passing explicit paths:

```bash
mapfile -t WF < <(cd "$R" && git ls-files '*.github/workflows/*.yml' '*.github/workflows/*.yaml' | grep -vE '(^|/)archive/')
(cd "$R" && uvx zizmor --persona=auditor --min-severity=low --format=plain "${WF[@]}")
```

Offline (no token) covers unpinned-uses, excessive-permissions, template-injection, dangerous-triggers,
artipacked, cache-poisoning. Online-only rules (impostor-commit, known-vulnerable-actions, ref-confusion)
need `--gh-token="$(gh auth token)"`. Map: template-injection / dangerous-triggers / artipacked = **P1**;
unpinned-uses / excessive-permissions = **P2**.

Remediation suggestions (for the user to run): `uvx zizmor --fix=safe <paths>` (experimental), or pinact:

```bash
go install github.com/suzuki-shunsuke/pinact/v4/cmd/pinact@latest   # note the /v4/ segment
pinact run            # rewrite tag pins → SHA + "# vX.Y.Z" comment (Dependabot-readable)
pinact run -check     # CI gate (single dash)
```

`actionlint` is an optional syntax pass — complements zizmor, doesn't replace it. CodeQL can also scan
Actions workflows (free on public repos). Out of scope here: artifact attestations, SLSA provenance,
`gh attestation verify`.

---

## Mode A — Pre-push safety (needs a local repo)

```bash
source .claude/skills/github-audit/patterns.local.sh

# 0. WHICH tree am I in, pushing where? (nested repos / case-insensitive repo names can point two
#    local trees at ONE remote — GitHub names are case-insensitive)
git rev-parse --show-toplevel; git remote get-url origin; git rev-parse --abbrev-ref HEAD

# 1. Outgoing commits (what a push would send). No upstream = whole branch unpushed.
UP=$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || echo "")
echo "upstream: ${UP:-<none — branch never pushed>}"
git log --oneline ${UP:+$UP..}HEAD | head -50

# 2. Divergence / re-leak risk (local history vs a scrubbed remote → force-push danger)
[ -n "$UP" ] && git rev-list --left-right --count "$UP"...HEAD   # "behind  ahead"

# 3. Outgoing DIFF: banned terms + PII + name-in-bio
git diff ${UP:+$UP..}HEAD | grep -inE "$BANNED|$PII" && echo "*** P0 in outgoing diff ***"
git diff ${UP:+$UP..}HEAD | grep -inE "$NAME"     # copyright footer = OK, bio/README = finding

# 4. New files in outgoing commits vs personal markers
git diff --name-only --diff-filter=A ${UP:+$UP..}HEAD | grep -iE "$PERSONAL_PATHS" && echo "*** personal file being added ***"

# 5. Working tree + staged + UNTRACKED
git status --porcelain | grep -iE "$PERSONAL_PATHS" && echo "*** untracked/modified personal path ***"
git diff HEAD | grep -inE "$SECRETS" && echo "*** live secret in uncommitted changes ***"

# 6. Secret scan over the outgoing range
if command -v gitleaks >/dev/null; then
  gitleaks git --no-banner --log-opts "${UP:+$UP..}HEAD" . || echo "*** gitleaks history findings ***"
  gitleaks dir --no-banner . || echo "*** gitleaks working-tree findings ***"
elif command -v trufflehog >/dev/null; then
  trufflehog git "file://$(git rev-parse --show-toplevel)" --since-commit "${UP:-HEAD~5}" --results=verified,unknown
else
  git diff ${UP:+$UP..}HEAD | grep -inE "$SECRETS" && echo "*** secret-like string in diff ***"
fi

# 7. Submodules push separately — repeat 1-6 inside each
git submodule status 2>&1
```

**Verdict:** `SAFE TO PUSH` only if 3-6 are clean **and** step 0 shows the intended tree/remote. Any P0 →
block, report file:line, recommend redact-or-drop. Step 2 showing local history rewritten vs remote (or
remote rewritten vs local) → warn that a push/force-push could re-leak scrubbed history; reconcile first.
This mode reports only — it never pushes.

---

## Severity & grading

| Severity | Examples |
| --- | --- |
| **P0** | Personal data on GitHub; banned terms/name/PII in active repo; live secrets; self-identifying README in a public repo; hijacked Action ref that ran |
| **P1** | Stale >180 days; high Dependabot; production-keys file; `.env` not gitignored; separable mixed repo; unpinned Actions |
| **P2** | Stale 90-180 days; missing SECURITY.md; superseded duplicate; failing CI |
| **P3** | Missing topics, no PR template, branch hygiene |

| Grade | Criteria |
| --- | --- |
| **F** | Any P0 |
| **D** | Multiple P1, or 1+ P0 partially mitigated |
| **C** | 3+ P1 |
| **B** | 1-2 P1, no P0 |
| **A-** | P2 only, ≤3 |
| **A** | Zero P0/P1/P2 |

**Account grade = lowest individual repo grade.**

## Documented exceptions (fill in per account — don't flag these)

| Repo / scope | Exception | Reason |
| --- | --- | --- |
| `<repo>` | default branch `master` | historical, many references |
| All private repos | no LICENSE | private, no external contributors |
| All private repos | no branch protection / native secret scanning | plan limit — covered by Category 3b |
| `<small-utility>` | no CI | tiny utility |
| `<public portfolio>` | copyright footer with legal name | deliberate, documented |

Keep this table in the user's local notes (or the gitignored pattern dir) — never hardcode real repo names
into the shipped skill.

---

## Remediation playbooks (emit for the user; never run unasked)

### Delete repos containing personal data (P0)

```bash
# Requires delete_repo scope: gh auth status | grep -q delete_repo || gh auth refresh -h github.com -s delete_repo
for repo in repo1 repo2; do gh repo delete "$OWNER/$repo" --yes && echo "$repo: gone"; done
```

Write it to a dated script for the user to run once, after a per-repo yes. Web fallback:
`https://github.com/<owner>/<repo>/settings` → Danger Zone. Make a local `git clone --mirror` backup first
if any content must be kept (store it off GitHub).

### Redact banned terms / scrub history

```bash
# git-filter-repo 2.47+ (the --sensitive-data-removal flag). Work on a fresh --mirror clone.
git clone --mirror "https://github.com/$OWNER/REPO.git" REPO.git && cd REPO.git
# (a) Replace terms — replacements.txt has one `literal:term==>[REDACTED]` (or `regex:...==>`) per line
git filter-repo --sensitive-data-removal --replace-text ../replacements.txt
# (b) Remove a whole leaked FILE (replace-text won't drop the file itself)
git filter-repo --sensitive-data-removal --invert-paths --path PATH/TO/LEAK
git remote add origin "https://github.com/$OWNER/REPO.git"    # filter-repo drops the remote
git push --force --mirror origin
```

BFG Repo-Cleaner is a faster, simpler alternative for pure file/blob removal.

**A force-push does NOT fully purge a leak from GitHub.** Old commits stay reachable via per-SHA cached
views, PR refs and any clones/forks. For a genuine secret/PII leak: (1) **rotate the credential first**,
(2) clean all local clones + forks, (3) open a **GitHub Support** request to dereference affected PRs, run
server-side GC and purge cached views. Support acts on real secrets/PII it deems unmitigable by rotation.

**Re-leak guard:** after a scrub, every old clone still holds the pre-scrub history. Re-clone everywhere;
never push an old clone or restore an old bundle over the clean remote.

**Never put replacement terms files under version control** — `replacements.txt` contains the very terms
you are removing.

### Pin Actions to SHA (P1)

```bash
gh api repos/actions/checkout/git/ref/tags/v4 --jq '.object.sha'
# annotated tags: dereference with gh api repos/actions/checkout/git/tags/<sha> --jq '.object.sha'
# actions/checkout@v4  →  actions/checkout@<40-char-sha>  # v4.x.y
```

### Add `.env` to `.gitignore` (P1)

```
.env
.env.*
!.env.example
```

### Add SECURITY.md (P2)

```markdown
# Security Policy
## Reporting a Vulnerability
Report privately via GitHub Security Advisories ("Report a vulnerability"). Do NOT open public issues.
```

### Add dependabot.yml (P2)

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "weekly" }
    open-pull-requests-limit: 10
  - package-ecosystem: "docker"
    directory: "/"
    schedule: { interval: "weekly" }
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly" }
```

### Least-privilege workflow permissions (P2)

```yaml
permissions:
  contents: read      # top level; grant more per job only where needed
```

---

## Report template

Save to `reports/YYYY-MM-DD-github-audit.md` (gitignored). Quote evidence as `repo:path:line` but **mask
the matched term** in the report (e.g. `Ex******`) so the report itself doesn't become a leak.

```markdown
# GitHub Audit Report — YYYY-MM-DD — <owner>

## Overview
| Metric | Count | Target |
| --- | --- | --- |
| Active repos | X | — |
| Archived repos | X | 0 |
| **F-grade repos** | X | **0** |
| Total P0 | X | **0** |
| Total P1 | X | <3 |
| Account grade | X | A |

## Per-repo classification
| Repo | Visibility | Class | Personal data? | Banned terms? | Secrets? | Lifecycle | Grade |
| --- | --- | --- | --- | --- | --- | --- | --- |

## P0 findings (fix today)
[repo:path:line (masked) → DELETE / REDACT / ROTATE, with the exact command]

## P1 / P2 / P3 findings
[grouped, each with a copy-paste fix]

## Deletion / scrub plan (user runs after per-repo yes)
| Repo | Reason | Action | Script |
| --- | --- | --- | --- |

## Comparison with previous audit
| Metric | Previous | Current | Delta |
| --- | --- | --- | --- |
```

---

## Quick commands

```bash
source .claude/skills/github-audit/patterns.local.sh
OWNER="${GH_OWNER:-$(gh api user --jq .login)}"

# Auth + scopes
gh auth status
gh auth status 2>&1 | grep -q "delete_repo" && echo "delete_repo: present" || echo "delete_repo: missing"

# Personal-data classification snapshot
for repo in $(gh repo list "$OWNER" --limit 1000 --json name --jq '.[].name'); do
  contents=$(gh api "repos/$OWNER/$repo/contents" --jq '.[].name' 2>/dev/null | tr '\n' ' ')
  echo "$contents" | grep -iqE "$PERSONAL_PATHS" && echo "*** P0 *** $repo" || echo "ok    $repo"
done

# Open Dependabot alerts per repo (paginated)
for repo in $(gh repo list "$OWNER" --limit 1000 --no-archived --json name --jq '.[].name'); do
  count=$(gh api --paginate "repos/$OWNER/$repo/dependabot/alerts?state=open" --jq 'length' 2>/dev/null | awk '{s+=$1} END {print s+0}')
  echo "$repo: $count alerts"
done

# Stale repos (90+ days)
gh repo list "$OWNER" --limit 1000 --json name,pushedAt,isArchived \
  --jq '.[] | select(.pushedAt[:10] < (now - 90*86400 | strftime("%Y-%m-%d"))) | "\(.pushedAt[:10]) \(if .isArchived then "[A]" else "[ ]" end) \(.name)"'
```

---

## Pitfalls learned

- **Inline terms get scrubbed with the data** → the scanner silently searches for `[REDACTED]`. Terms live
  only in the gitignored pattern file.
- **Personal-data check must run FIRST** — a dependency-first audit grades therapy-note repos as A.
- **`gh api` default page size is 30** — `--paginate` and sum.
- **Code search is unreliable — never trust a `0`.** Default branch only, incomplete private-repo index,
  `\.` in a term → HTTP 422, secondary rate limit → sleep ≥10 s.
- **Private-repo secret scanning is a paid add-on**; scan locally with gitleaks / trufflehog.
- **Top-level `contents` misses nested personal dirs** — use the recursive tree API for classification.
- **Archived repos hide the worst files** (keys, cookies, statements, Postman collections).
- **GitHub repo names are case-insensitive** — two local trees with differently-cased remotes can push to
  the same repo on different branches; `gh repo list` won't show it. Check `branches` per repo.
- **"Private" ≠ secure.** Genuinely private content belongs in local or end-to-end-encrypted storage, not
  on any code host.
