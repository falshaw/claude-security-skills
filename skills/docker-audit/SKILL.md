---
name: docker-audit
description: Audits Docker container security across a set of local compose stacks (listed in audit.config.yml or discovered by content) covering host runtime CVEs, network isolation, container hardening, image and digest-pin currency, secrets, supply chain and the AI/LLM gateway surface. Static audit first, then verification inside rebuilt images; outputs P0-P3 findings with quoted evidence and copy-paste fixes. Use when the user says "docker audit", "audit the containers", "container security", "harden docker", "check image pins", "docker CVE check", or after compose/Dockerfile changes, adding a service, or a container incident. Read-only unless the user explicitly asks for fixes.
---

# Docker Security Audit

## Overview

Audit Docker and network security for every compose stack in scope. Output = P0-P3 findings, each with the offending line **quoted** (`file:line`) and a **copy-paste fix**. This file is the procedure; the catalogue (14 category checklists, CVE floors, playbooks, report templates, gotchas, diagnostic commands) is in **[reference.md](./reference.md)**.

The audit is **read-only by default**: it reads files and inspects images/containers. It never pushes images, deploys, or edits files unless the user asks for remediation in the same session.

## Inputs

1. **`audit.config.yml`** in the repo root or this skill folder (copy [`audit.config.example.yml`](./audit.config.example.yml)). It lists:
   - `roots` — directories to sweep for compose files by content (e.g. `apps/`, `infra/`, `shared/`)
   - `exclude` — globs never to audit (build artifacts like `.next/standalone/`, vendor samples, archived stacks)
   - `accepted_risks` — owner-accepted items with a reason and a re-evaluation trigger (never re-flag these)
   - `restart_exceptions`, `bridge_toggle_vars`, `previous_report` — optional
2. **No config?** Discover by content under the working directory and ask the user once which stacks are in scope before grading.

Derive the live roster every run from the filesystem — never trust a remembered list. Reconcile `docker ps -a` against the discovered compose files: a running container with no source file is itself a finding.

## When to Use

- Periodic container security audit; after significant compose/Dockerfile changes; after adding a service; before any public exposure; investigating a container incident.

### When NOT to Use

- Application-level code security (auth flows, injection) → the `senior-pentester` agent or an app security review.
- Per-app architecture grading → `app-audit` / `fleet-audit`.
- Kubernetes manifests — out of scope.

## Core Process

Copy this checklist into the run and tick it off:

```
- [ ] 0 Host quick-checks (table below) — stop-and-fix on any miss
- [ ] 1 Discovery by content  - [ ] 2 Score 14 categories  - [ ] 3 Verify every finding (3b subnets, 3c in-image)
- [ ] 4 Pin-yank + currency   - [ ] 5 Score  - [ ] 6 Report  - [ ] 7 Baseline compare  - [ ] 8 Attribution
```

1. **Discovery — filesystem-driven, by content.** Keep every `*.yml`/`*.yaml` under the configured roots that contains `^services:` (a `docker-compose*` glob misses files like `infra/shared-redis.yml`). Read every compose file and overlay, every `Dockerfile` including split build contexts (`worker/`, `sidecar/`, `backend/`), every `.dockerignore`, and `.env` vs `.env.example` (**never echo secret values**). Build file lists with `find`, not `rg` alone (`rg` skips dotfiles and gitignored paths unless `--hidden --no-ignore`). **Anchor the `0.0.0.0` check to `ports:`** — `*_HOST=0.0.0.0` env vars are in-container listen addresses, not host publishes.
2. **Assess 14 categories** (checklists in reference.md): Network · Container hardening · Image security · Secrets · Health checks · Logging · Restart policy · Supply chain · Port conflicts · Resource limits · 11 Dependency currency · 12 Digest pinning + CVE scanning · 13 Advanced runtime hardening · 14 AI/LLM + MCP gateway.
3. **Verify before flagging (REQUIRED).** Every finding quotes the offending line; every "missing X" shows the read/grep proving absence. Parallel LLM audit agents produce a high false-positive rate on "missing/broken" claims — re-read disputed lines yourself with `sed -n 'N,Mp' file`. **A severity inherited from a prior audit must be re-derived, not carried.** An in-repo "deliberate hold" comment is a claim to re-check, not evidence.
   - **3b. Subnet-collision check (every run).** Enumerate every `subnet:` and assert uniqueness:
     ```bash
     find $ROOTS \( -name '*.yml' -o -name '*.yaml' \) -not -path '*/node_modules/*' -not -path '*/.next/*' \
       | xargs grep -Hn 'subnet:' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort | uniq -c | sort -rn
     ```
     Any count > 1 is a finding (Docker refuses the second network with `Pool overlaps with other one on this address space`). Also check live external networks with `docker network inspect` — docs about their ranges go stale.
   - **3c. REBUILD, THEN VERIFY INSIDE THE IMAGE.** A Dockerfile bump proves nothing until an image is rebuilt from it. Assert `node -v` / `python -V`, `.Config.User` (non-root) and no `/app/.env` inside the image. **Enumerate distinct base strings first** — a sed that bumps only `-alpine` leaves a `-bookworm-slim` family on the old base. Sweep registries by **content**, never a curated list (a wrapper image like `pgvector/pgvector` bundles its own Postgres and is missed by a `postgres:` sweep). `docker start` reuses the old container — only `docker compose up -d` adopts a rebuilt image. Commands → reference.md → *Verify inside a built image*.
4. **Pin-yank + registry currency.** Confirm every pinned tag still resolves (Hub tag URL; 404 = yanked, P2) **and** whether a newer patch with a security changelog exists. **A registry 404 is point-in-time, never a permanent rule** — re-query each run; never write "version X does not exist" into a doc. Docker Hub rate-limits after ~15 rapid lookups — pace the loop.
5. **Score.** P0 = credentials exposed with real blast radius (funded / reachable) · P1 = privilege-escalation path or LAN exposure · P2 = hardening missing, broken/stale pin with a security changelog · P3 = currency/optimisation. Ask "is it funded / reachable?" BEFORE assigning severity.
6. **Report** — fleet matrix, per-stack grade A-D, issues by severity with quoted evidence and copy-paste fixes (templates in reference.md). Write to `reports/YYYY-MM-DD-docker-security-audit.md` (gitignored).
7. **Compare to baseline** — read the previous report (`previous_report` in config) first; do not re-flag `accepted_risks`.
8. **Two sessions, one tree:** when another audit edits the same tree the same day, attribute fixes by file mtime or VCS diff. After any `npm audit fix --omit=dev`, re-run `npm install --include=dev` and confirm devDependencies survived.

## Host runtime quick-checks (run FIRST — a vulnerable engine makes per-stack hardening moot)

Floors as of 2026-10 (re-check upstream each run):

| Check | Command | Security floor (re-check upstream each run) | Sev if behind |
| --- | --- | --- | --- |
| runc | `docker info \| grep -i runc` | ≥ 1.2.8 / 1.3.3 / 1.4.0 (CVE-2025-31133/52565/52881 escape trio); 1.3.6+ / 1.4.3+ also close CVE-2026-41579 | **P0** |
| Docker Engine | `docker version --format '{{.Server.Version}}'` | ≥ 29.9.1 (29.9.1 containerd pull crashes CVE-2026-95839; 29.8.2 CVE-2026-53493/92542/92543; 29.7.0 CVE-2026-17106 go-archive tar-extraction escape; plus all earlier 29.x fixes) | **P1** |
| BuildKit (daemon, NOT the buildx CLI) | `docker buildx inspect --bootstrap \| grep -i buildkit` | ≥ 0.33.1 (CVE-2026-93315 to -93323 and -93326; earlier 0.31.2 CVE-2026-15788/89/91/92/93) | **P1** |
| Docker Compose | `docker compose version` | ≥ 2.40.2 (CVE-2025-62725 path traversal via remote OCI compose artifact annotations) | **P1** |

- Record the live host numbers in report §1 every run. A newer upstream release that no Docker Desktop build ships yet is a **P3 watch**, not a miss.
- Floors move: before grading, read the Engine / BuildKit / runc / Compose release notes (links in reference.md) and raise a floor when a new CVE fix lands.
- **CIS Docker Benchmark** is the reference baseline (re-check the current version on cisecurity.org); `docker-bench-security` is an optional self-audit and lags the benchmark. Do not cite OWASP CSVS (archived 2023); use CIS + NIST SP 800-190 + the OWASP Docker Security Cheat Sheet.

## Per-stack static checks (condensed — full checklists in reference.md)

| Category | Key check | Sev if missing |
| --- | --- | --- |
| Network | Isolated `/24` per stack; no overlaps (3b) | P1 |
| Network | Ports bound `127.0.0.1` only — never `0.0.0.0`, never bare `"3000:3000"` | P1 |
| Network | No `network_mode: host` without a documented exception | P1 |
| Network | DB/cache on an internal network, no host publish unless needed | P2 |
| Network | `extra_hosts: host.docker.internal:host-gateway` only where a host service (LLM gateway, GPU service) is genuinely needed | P3 if unjustified |
| Container | Non-root `USER` in every runtime image | P1 |
| Container | `cap_drop: [ALL]`; `cap_add` only per the matrix (Postgres: CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID · Redis: CHOWN, DAC_OVERRIDE, SETGID, SETUID · nginx under `USER nginx`: none) | P1 |
| Container | `security_opt: [no-new-privileges:true]`; no `privileged: true` | P1 |
| Container | `read_only: true` + tmpfs `/tmp` (100m), `.next/cache` (200m); nginx tmpfs `uid=101,gid=101` | P2 |
| Container | `deploy.resources.limits` memory + cpus + `pids: 200` (keep ONE pids form — service-level `pids_limit` must be consistent with `deploy.resources.limits.pids`) | P2 |
| Container | `stop_grace_period` on DB / worker / long-running services | P3 |
| Image | `image:tag@sha256:` digest pin; no `:latest`; tag still resolves; newer security patch checked | P2 |
| Image | Multi-stage build: Node 4-stage (`base` + `apk upgrade` → deps → builder → runner), Python 2-stage; `npm ci` only | P2 |
| Image | `.dockerignore` in EVERY build context, root-anchoring aware (`.env` does NOT match `deploy/.env` — list `**/.env*`, `secrets/`, `backups/`, `*.sql`) | P1 |
| Secrets | No hardcoded secrets in compose; `${VAR:?msg}` for every credential; `${VAR:-default}` only for documented non-secret toggles | P0 / P2 |
| Secrets | No `COPY .env`, no secret `ARG`; `RUN rm -f .env` after a Next.js standalone copy; no credentials in build artifacts (`.next/standalone/.env`) | P0 / P2 |
| Health | `127.0.0.1` never `localhost` (Alpine resolves to IPv6); app `wget`, PG `pg_isready -h 127.0.0.1`, Redis `redis-cli -a $$REDIS_PASSWORD ping`; `depends_on: condition: service_healthy` | P1 / P2 |
| Logging | json-file 10m/3 (DB/cache 50m/5) | P3 |
| Restart | Local dev default `"no"`; exceptions only as listed in config. Profile-gated services must be `"no"` | P3 |
| Deps (11) | `npm audit --omit=dev` / `pip-audit` 0 HIGH/CRIT; transitive advisory under an exact-pinning parent = `overrides` entry verified at runtime, never a breaking downgrade; lockfile present. **Also read the framework's own security blog** — advisory DBs can lag vendor advisories by days | P1 / P2 |
| Sign (12) | Digest pin IS the supply-chain control for a no-registry deployment; scan pinned bases (Grype / Trivy / `docker scout cves`) on a cadence. Cosign/SBOM/provenance = SKIP for local-only stacks, not a gap. Never install a compromised scanner release (see reference.md) | P2 / n/a |
| Hard (13) | Compose `secrets:` instead of `environment:` for DB/JWT creds; explicit `apparmor=docker-default`; custom seccomp for high-risk containers; tmpfs `noexec,nosuid,nodev` | P2 / P3 |
| AI (14) | Vector DB api-key + 127.0.0.1; LLM gateway creds = `:ro` FILE mount, never env; `docker.sock` only behind a socket proxy; model provenance; MCP servers vetted + version-locked | P1-P3 |
| Triage | Prioritise by CISA KEV + EPSS, not raw CVSS | n/a |

## Accepted risks

Read `accepted_risks` from the config before reporting. An accepted item is listed in the report's "Accepted / not re-flagged" section with its reason — never as a finding. Re-raise it only if its stated re-evaluation trigger has fired (e.g. "before any public deploy").

## Dispatch plan (optional parallel agents — verify-first)

Run the host quick-checks and step 3b yourself **before** dispatching. Split stacks into 2-4 batches (e.g. A = app stacks with a DB, B = stacks with workers/sidecars, C = shared infrastructure). Each agent reads every compose/Dockerfile/.dockerignore in its batch, scores all 14 categories and returns findings with quoted lines. After agents return: de-duplicate, verify every P1/P2 line yourself, rebuild + verify in-image (3c) before calling any fix done, then write the report.

## Common Mistakes

The full Mistake → Fix table is in **reference.md → Common Mistakes**. Read it before writing any fix.

## Related

- `app-audit` / `fleet-audit` (architecture grading) · `app-update` (dependency patching) · `senior-pentester` agent (app-level security).
