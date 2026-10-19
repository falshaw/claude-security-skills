# claude-security-skills

Security and hygiene audit skills for [Claude Code](https://claude.com/claude-code): containers, self-hosted apps, dependencies, GitHub exposure, public-site PII leaks and the `.claude/` tooling layer itself. Each audit grades findings **P0–P3**, quotes evidence (file:line or command output) and ships copy-paste fixes.

## Skills

| Skill | What it does |
| --- | --- |
| `docker-audit` | Audits local Docker Compose stacks: host runtime CVEs, network isolation, container hardening, digest pins, secrets, supply chain, LLM gateway surface. Static audit first, then it verifies findings inside the rebuilt images. |
| `app-audit` | Grades one Next.js / Python / Docker app against a configurable gold-standard baseline (`baselines/nextjs.json`, `api.json`, `agents.json`) and outputs a P0–P3 report card. |
| `fleet-audit` | Multi-app architecture + security audit driven by `fleet.config.json`. Gives a per-app report card and a fleet grade. |
| `app-update` | Patches dependency vulnerabilities in one app. Applies in-range fixes, verifies npm overrides, catches vendor advisories that `npm audit` misses, and asks before any major bump. It then proves the app still typechecks, builds and boots. |
| `github-audit` | Read-only audit of a GitHub account via `gh`: personal data, banned terms and secrets, stale repos, Dependabot, SHA-pinned actions, zizmor. |
| `pii-leak-sweep` | Fetches every sitemap URL (plus `llms.txt`) of a live site and scans it for your banned terms, PII, pricing copy and JSON-LD pricing leaks. |
| `tooling-doctor` | Lints a Claude Code `.claude/` layer (skills, commands, rules, agents, hooks, settings) for broken, stale or oversized items. |

## Agents

| Agent | What it does |
| --- | --- |
| `senior-pentester` | Security assessments, auth/API attack-surface review, hardening recommendations. Authorized targets only. |

## Install

```bash
cp -r skills/* <your-project>/.claude/skills/
cp agents/*    <your-project>/.claude/agents/
```

Then copy each `*.example.*` config/pattern file to its local name and edit it. The local names are gitignored and must never be committed:

| Skill | Example file | Local file |
| --- | --- | --- |
| docker-audit | `audit.config.example.yml` | `audit.config.yml` |
| fleet-audit | `fleet.config.example.json` | `fleet.config.json` |
| github-audit | `patterns.example.sh` | `patterns.local.sh` |
| pii-leak-sweep | `patterns.example.txt` | `patterns.local.txt` |
| tooling-doctor | `retired.example.json`, `doctor.config.example.json` | `retired.json`, `doctor.config.json` |

## Requirements

| Tool | Used by |
| --- | --- |
| `bash`, `curl`, `jq` | all shell scripts, pii-leak-sweep |
| `python3` | fleet-audit helpers, tooling-doctor |
| `docker` (+ Compose v2) | docker-audit, fleet-audit, app-audit |
| `node` / `npm` | app-update, app-audit, fleet-audit (Node apps) |
| `gh` (authenticated) | github-audit |
| `trivy` or `grype` | docker-audit image scans (optional, recommended) |
| `gitleaks` / `trufflehog`, `zizmor` | github-audit secret + workflow scans (optional) |

Secrets such as `GH_TOKEN` are read from environment variables only. Nothing is hardcoded.

## Safety

- **Audits are read-only.** They report findings and fixes; they change nothing unless you explicitly ask.
- **Never auto-push, auto-deploy or auto-delete.** `app-update` asks before any major bump. Destructive GitHub actions (delete repo, history rewrite) are written out as scripts for you to review and run.
- Only audit systems you own or are authorized to test.
- Keep `patterns.local.*`, `.env` and `reports/` out of version control. The provided `.gitignore` covers them.

## License

MIT. See [LICENSE](LICENSE). Created by Nick Falshaw.
