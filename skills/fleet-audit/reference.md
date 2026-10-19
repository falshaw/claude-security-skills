# Fleet Architecture Audit — Full Reference

The entry point is [SKILL.md](./SKILL.md). This file holds the full framework, read on demand.

## Contents

1. Scope classes
2. Audit categories (12) — full checklists
3. Severity · grading · output template
4. Advisory verification (the reproducible way)
5. Known false-positive and false-negative classes
6. Phantom dependencies
7. npm overrides — the correct remediation path
8. Post-fix verification + transient build failures
9. Standing lessons
10. Generic gotchas

---

## 1. Scope classes

Classify every live directory before scoring. Show the denominator from discovery, never a remembered count.

| Scope | Meaning |
| --- | --- |
| Full audit | First-party app — must meet architecture, security and documentation standards |
| Source-only | Runtime lives elsewhere; audit local source/config, never touch that runtime |
| Reduced audit | Vendor/COTS/static/tooling — focus on drift, secrets, exposure, image currency, docs |
| Skip | Archived, duplicate export, backup copy, reference material, no executable surface |

Discover compose files **by content** (`grep -l '^services:'`), then sort them into: **base stacks**
(graded), **overlays** applied with `-f base -f overlay` (inherit `security_opt`/`cap_drop` from the
base — a naive "missing hardening" check reports phantoms), **vendor examples**, **shared infra**, and
**dead recipes** (e.g. a decommissioned server's production compose). Repin across all of them; grade
hardening only on base stacks and shared infra.

---

## 2. Audit categories (12)

### Cat 1 — Stack compliance

- Framework versions from `package.json` AND what the lockfile resolved. Flag major/runtime
  incompatibility, not intentional minor drift.
- Known-incompatible "latest" majors are not findings: if eslint-config-next / typescript-eslint do not
  yet support a new TypeScript or ESLint major, staying one major behind is correct. Verify, then
  document it in the baseline.
- Version skew across apps: for each drift decide intentional / vendor-owned / stale.
- `next.config.*` has `output: "standalone"`; the Dockerfile copies `public` + `.next/static` in.
- Tailwind 4 uses `@import "tailwindcss"`.
- Request validation: zod on Next.js API bodies; Pydantic on FastAPI.
- Python surfaces: FastAPI / uvicorn / starlette pinned; starlette pinned explicitly at or above its
  latest advisory floor (FastAPI's range can allow a vulnerable starlette).

### Cat 2 — Docker security

(Deep dive: `docker-audit`.) Key checks:

- Next.js: 4-stage Dockerfile (base + `apk upgrade` → deps → builder → runner). Python: 2-stage (builder
  with compilers → runner without). Node sidecars: 2-stage, compiled JS only, no tsx in production.
- Non-root user (uid 1001 Node; Python 1000 or 1001 — documented).
- `cap_drop: [ALL]`, `no-new-privileges:true`, `read_only: true` + tmpfs, memory/cpus limits,
  **`deploy.resources.limits.pids`** (not service-level `pids_limit:` when a deploy block exists).
- Postgres/Redis on Alpine with `cap_drop: ALL` need `cap_add: [CHOWN, DAC_OVERRIDE, SETGID, SETUID]` (+`FOWNER` for PG).
- nginx running as `USER nginx` needs tmpfs mounts with `uid=101,gid=101` and no `cap_add`.
- `127.0.0.1:` host binds; isolated, **pinned** /24 subnets; health checks on `127.0.0.1`, never `localhost`.
- Every external base `tag@sha256:digest`; log rotation (`json-file`, `max-size`, `max-file`, `compress`).
- Secrets `${VAR:?msg}`; `:-` only for non-secret feature toggles.
- **A digest pin freezes you to CVE-laden bytes.** Keep checking pinned bases (Postgres, Redis, nginx,
  Caddy, Qdrant, model servers, Node, Python) against advisories each run; check the **bundled base of
  wrapper images** too (e.g. pgvector bundles a Postgres minor).
- **Dormant pins** (profile-gated services nobody starts, retired recipes) are repinned or deleted, not graded as live exposure — state which.

### Cat 3 — Auth pattern

- Record the expected auth pattern per app (custom JWT on a vendored core / standalone JWT by design /
  framework auth / API key / none for local desktop) and check each app matches its declared pattern.
- **Vendored shared core:** each copy must equal the source apart from an auto-generated header; prove it
  by diff (the script does if configured). Never hand-edit a copy — edit the source and re-sync.
  Vendoring (copying) rather than importing keeps each app's `COPY . .` Docker build self-contained.
- JWT: algorithm pinned on verify, secret ≥ 32 chars, weak patterns rejected, cookie names follow a convention.
- CSRF on JWT apps: Origin/Host check on mutating requests; **a missing Origin must fail closed**.
- API-key apps: `hmac.compare_digest` / `timingSafeEqual`.
- Framework auth handlers that can return null under newer Next.js need a wrapper.
- Middleware-only auth: Next.js has shipped advisories where crafted `.rsc` / prefetch URLs bypassed
  middleware/proxy-only guards. Any route protected ONLY by `middleware.ts`/`proxy.ts` must be on a
  patched version; route handlers should re-check the session for sensitive operations.

### Cat 4 — Prisma 7 adapter

- `PrismaPg` adapter in `src/lib/prisma.ts` for every `PrismaClient` (seeds included). Prisma 7 requires
  a driver adapter and removed `url` from the datasource block → a missing adapter or missing
  `prisma.config.ts` is **P1**, not drift.
- `prisma.config.ts` at app root with `defineConfig()`; it imports `dotenv` → `dotenv` must be DECLARED.
- One client file name fleet-wide (`src/lib/prisma.ts`); flag a reintroduced `db.ts`.
- Least-privilege runtime DB role (no superuser, no CREATE).
- `prisma` CLI belongs in devDependencies (build tool in the runtime closure = P3).
- Never install `prisma@latest` unpinned — check `npm view prisma dist-tags`; `latest` can be an RC major.

### Cat 5 — LLM-provider resilience

- Which apps call an LLM, through what (local model server / gateway / hosted SDK), with which compose default.
- **A path that ends at a backend that no longer exists must fail closed and loudly** (clean error +
  health flag), not hang. Check for explicit timeouts and that the breaker counts abort/timeout as failure.
- Retired-backend hostnames surviving as code fallback strings: flag only when the compose default does
  not override them.
- Apps with a data-classification/egress guard that refuses to send certain data to a hosted model: a
  thrown egress error under a hosted provider is correct fail-safe behaviour + an unavailable feature, not a bug.
- RAG: if the embedder is down, new embeddings fail even though stored collections survive — check the
  gateway's `/health` before grading RAG features.
- UI shows "AI unavailable" status rather than an endless spinner.

### Cat 6 — Test coverage

- Unit tests exist (Vitest / pytest / node:test). Count at **unbounded** depth.
- `npm test` actually runs (script present, runner declared in devDependencies).
- Security layer covered: proxy/middleware (CSRF, JWT, CSP, request id, rate limits), lockout, rate limiter.
- Coverage thresholds enforced in config, not just reported.
- E2E for critical paths where the app has more than one user.

### Cat 7 — Dependency health

- **Query the advisory DB, never blog posts.** Floors come from OSV/GHSA ranges or vendor releases (§4).
- **Base images are dependencies too** — audit them in the same pass as npm/pip.
- `npm audit` totals are not severity — apply the triage rules first.
- Record fleet-wide `overrides` and the code path each was verified with.
- Accepted gaps (upstream-unfixable transitives) are listed with evidence and re-verified every run.
- Breaking majors (numpy 1→2, pandas 2→3, redis-py, paramiko, …) are reported, never auto-applied. A
  major whose only advisory has no fixed version buys nothing.
- Phantom dependencies: run `scripts/undeclared-imports.py` (§6).

### Cat 8 — Security headers & rate limiting

- CSP (per-request nonce on signed-in pages); tightening a CSP needs a browser render test first.
- CORS restricted (never wildcard with credentials).
- Rate limiting on all API routes; login throttles per IP and per account. File names vary in case and
  spelling — a filename glob is not evidence of absence.
- Zod/Pydantic on every POST/PUT/PATCH.
- FastAPI security middleware where applicable.
- CSRF missing-Origin fails closed.

### Cat 9 — Agent docs quality

- Every app has `AGENTS.md` and/or `CLAUDE.md` with accurate stack, ports, commands, architecture.
- No stale instructions (retired services, removed features, dead hostnames, old model names).
- References to the baseline patterns where applicable.

### Cat 10 — Environment hygiene

- `.dockerignore` at **every build context** (derive from compose `context:` — sub-dirs like `worker/`,
  `backend/`, `frontend/` have their own); it excludes `.env*`, `.git`, `node_modules`, `.next`, uploads,
  dumps, caches; it must NOT exclude `tsconfig.json` on `@/*`-alias apps.
- No `0.0.0.0` host binds except documented, profile-gated ingress.
- No hardcoded secrets in compose or source (`${VAR:?}`).
- `.env.example` lists every required var with generation commands.
- No `.env` leaves the machine: excluded from every build context and from VCS.

### Cat 11 — Cross-app dependencies

- Inventory shared services (gateway, vector DB, model server, connection pooler, shared Redis,
  monitoring) with their compose file, pin, bind address and auth.
- Shared services reached through their intended API only (e.g. vector DB via the gateway's `/rag/*`).
- External networks declared by app composes must exist (`docker network ls`) or those stacks cannot start.
- Backup coverage: every app with a database appears in the backup script — a missing one is P2.

### Cat 12 — LLM gateway integration (if you run one)

- Compose has `extra_hosts: - "host.docker.internal:host-gateway"` on every service calling a host service.
- Compose passes provider / gateway URL / model / token envs; token via `${VAR:?}`.
- Client file branches on `LLM_PROVIDER` at load time and degrades gracefully when the gateway is down.
- Every call sends the app-name header + auth token; app present in the gateway allowlist.
- Gateway `/health` is the only unauthenticated route; verify it before grading gateway-default apps.
- Never run two instances of the gateway on the same port (e.g. a container AND a host fallback script).

---

## 3. Severity · grading · output template

Severity and grade rubric: see SKILL.md.

### Report template — `reports/YYYY-MM-DD-fleet-audit.md`

```markdown
# Fleet Audit — <date>

## 1. Fleet summary
| Metric | Count | Target |
| --- | --- | --- |
| Apps audited | X/Y (scope classes: full a, reduced b, skip c) | all discovered |
| P0 / P1 / P2 / P3 | a / b / c / d | 0 / 0 / <5 / — |
| Fleet grade | X | A |
| Docker compliance | X/N base stacks | N/N |

## 2. Per-app report card
| App | Stack | Docker | Auth | Prisma | LLM | Tests | Deps | Sec | Docs | Env | Cross | Gateway | Grade |
| --- | ----- | ------ | ---- | ------ | --- | ----- | ---- | --- | ---- | --- | ----- | ------- | ----- |

## 3. Issues by severity
### P0 — <title>
- **App:** <name>  **File:** <path:line>
- **Evidence:** `<quoted line or command output>`
- **Fix (copy-paste):** <diff / command>
- **Verify:** <command that proves the fix>

## 4. Cross-app concerns
- Version skew (major deps), shared-service dependencies, network trust boundaries

## 5. Comparison with previous audit
| Metric | Previous (<date>) | Current | Delta |
State any denominator change explicitly.

## 6. Verified clean (with the command that proved each)
## 7. Not verified (stacks not running, tests not run) — and why
## 8. Top recommendations (ranked, owner: platform vs app, effort)
```

---

## 4. Advisory verification (the reproducible way)

> ⚠️ **OSV / GHSA can lag the vendor.** A framework vendor can publish a security release days before
> the advisory reaches OSV or the global GitHub DB. For Next.js, Prisma and Node also read the vendor
> security page / repo advisories (`gh api repos/<owner>/<repo>/security-advisories`). OSV stays the
> source for *ranges* once it has the record.

```bash
# One package/version -> every advisory + its fixed version
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"name":"transformers","ecosystem":"PyPI"},"version":"4.48.0"}'
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"name":"next","ecosystem":"npm"},"version":"16.0.0"}'

# Every Python pin in one pass (never a curated subset)
python skills/fleet-audit/scripts/osv-pins.py apps/

# Latest-version lookups
npm view <pkg> version
npm view <pkg> dist-tags          # catches "latest" jumping to an RC or a new major
npm view <pkg> versions --json    # does the version you are about to write exist?
curl -s https://pypi.org/pypi/<pkg>/json | python -c "import sys,json;print(json.load(sys.stdin)['info']['version'])"
```

**Never write a version you have not looked up.** A remembered patch version that does not exist costs
two failed rebuild cycles; the existence check is one command. **Existence first, then advisory range, then pin.**

**Image digests:** `docker buildx imagetools inspect` hits Docker Hub's anonymous rate limit (429) after
a dozen-odd lookups. Use the Hub API, and confirm the tag exists first:

```bash
curl -s https://hub.docker.com/v2/repositories/library/postgres/tags/<tag> | python -c "import sys,json;print(json.load(sys.stdin)['digest'])"
curl -s "https://hub.docker.com/v2/repositories/library/redis/tags?page_size=100&name=<prefix>"
```

Upstream can release a version before the `-alpine` tag appears on the registry, and a tag that 404s
today can exist next week. **Never write "version X does not exist" as a standing rule** — re-query.

---

## 5. Known false-positive and false-negative classes

| # | Class | Looks like | Fix |
| --- | --- | --- | --- |
| 1 | Generated build output | `FROM node:15` / old postgres "still in the fleet" | They live in `node_modules/*/Dockerfile` or `.next/standalone/`. Exclude `node_modules`, `.next`, `.venv`, `site-packages`, `dist`, `.git`. |
| 2 | Wrong build context | "missing `.dockerignore`" on a multi-service app | Derive the context from compose `context:`; sub-dirs carry their own file. |
| 3 | Search depth too shallow | "app X has no tests" | Tests live at `src/__tests__/` / `src/test/` (depth 4+). Never `find -maxdepth 3`. |
| 4 | In-container bind read as host exposure | `HOST=0.0.0.0:<port>` "exposes the service" | Bind inside the container's netns. Only compose `ports:` publishes. |
| 5 | Filename-glob absence | "no rate limiting" | `ratelimit.ts` / `rateLimit.ts` / `rate-limit.ts` / `middleware/rateLimit.ts` — grep for usage, not filenames. |
| 6 | Overlay compose graded as a stack | "override file lacks cap_drop" | Overlays inherit from the base. |

**False negatives — worse, because they look like a pass:**

| # | Class | Hides | Fix |
| --- | --- | --- | --- |
| 7 | Compose files not named `docker-compose*.yml` | `shared-redis.yml`, `infra/*.yml` define real services; `--include='docker-compose*.yml'` skips them, so a "fully repinned" report leaves old pins running | Discover by content; after any fleet-wide edit, re-grep for the OLD value and expect zero. |
| 8 | Inherited severity | A "P0" copied through several reports without re-checking exposure | Re-derive every carried severity (funded? reachable? in the runtime image?). |
| 9 | Advisory DB lag | `npm audit` clean while the vendor has published a critical | Vendor-floor check (Cat 7b in the script). |

Deliberate-but-real config is recorded in `accepted_risks` with evidence — e.g. a profile-gated public
reverse proxy bound to `0.0.0.0:80/443`, an import-free twin of a module kept so a hermetic test runner
can load it, `restart: unless-stopped` requested by the owner. Re-check the evidence each run; do not
re-flag a verified accepted risk.

---

## 6. Phantom dependencies

A clean `npm audit` does not mean an honest manifest. An import that resolves only because another
package hoisted it breaks the build the moment that package moves — e.g. removing an unused devDependency
breaks the production build because a component imported `date-fns`, which was only ever a transitive.

```bash
python skills/fleet-audit/scripts/undeclared-imports.py apps/*    # exit 1 on findings
```

The scanner resolves each file to its **nearest** `package.json`, validates names against npm rules,
skips generated trees, matches only import positions, strips comments, and ignores builtins/aliases.
Typical real hits: `dotenv` imported by `prisma.config.ts` but undeclared; `pg` used directly; a test
runner used by `npm test` but not declared.

**Removing a dependency is a two-step job:** remove it, then **rebuild** — the build is the only proof
nothing leaned on it. Drop any `overrides` that existed only to patch the removed package's tree.

---

## 7. npm overrides — the correct remediation path

```bash
npm view <parent> dependencies --json     # what range does the parent declare?
npm view <vulnerable-pkg> version         # what is the fixed version?
npm ls <vulnerable-pkg> --package-lock-only   # provenance
```

If the fixed version satisfies the parent's range (or the bump is API-compatible), add
`"overrides": {"<pkg>": "^<fixed>"}`, regenerate with `npm install --package-lock-only`, then **exercise
the code path that loads it** (e.g. a transitive of the Prisma config loader → `npx prisma validate &&
npx prisma generate`). npm will not let you override a package you also depend on directly unless the
specs match — use the `"$pkg"` self-reference. **An override you have not exercised is a guess.**

`npm audit fix --package-lock-only` sometimes silently fails to restructure a tree while still saying
"run npm audit fix". When a fix does not take, check provenance and use an override.

---

## 8. Post-fix verification + transient build failures

Editing a Dockerfile / compose / requirements file changes **source**; running containers keep the old
bytes until rebuilt. Reporting "fixed" without a rebuild is reporting an intention.

```bash
# 1. What is actually up? Rebuild only what the user runs — do not start dormant stacks.
docker ps --format '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}' | sort -u

# 2. Rebuild + recreate per stack in the BACKGROUND, logging pass/fail
for d in <dirs>; do
  echo "=== BUILD $d ===" >> reports/rebuild.log
  ( cd "$d" && timeout 1500 docker compose up -d --build >> ../../reports/rebuild.log 2>&1 ) \
    && echo "OK $d" >> reports/rebuild.log || echo "FAIL $d" >> reports/rebuild.log
done

# 3. Confirm the NEW image is what runs (not just what is in the file)
docker ps --format '{{.Name}}\t{{.Image}}\t{{.Status}}' | sort
for c in $(docker ps --format '{{.Names}}'); do
  [ "$(docker inspect $c -f '{{.Image}}')" = "$(docker image inspect $(docker inspect $c -f '{{.Config.Image}}') -f '{{.Id}}')" ] || echo "STALE $c"
done
```

**Health is the acceptance test.** Every service with a healthcheck must return to `Up … (healthy)`.
Hard-refresh the browser after a frontend rebuild before judging the UI.

| Symptom | Meaning | Action |
| --- | --- | --- |
| `Hash Sum mismatch` | apt mirror rotated between cached `update` and fetch | Retry; then `--no-cache` for that service |
| `404` on `dists/*/Packages` + `Remote end closed connection` | Distro CDN node degraded — upstream, not your config | Prove it: `docker run --rm python:3-slim sh -c 'apt-get update'`. If that fails too, no change of yours can fix it |
| `429 Too Many Requests` from the registry | Anonymous pull limit | Wait or authenticate |
| `failed to solve: … context canceled` | Timeout on a huge image (CUDA/torch) | Raise the timeout; not a broken app |

Run the bare-container proof **after the second failure, not the sixth**. Prefer
`apt-get -o Acquire::Retries=5 update` over stacking speculative apt flags (some force revalidation
against the failing origin). Stock services can still be updated during an outage:
`docker compose up -d --no-build postgres redis`. **Do not report a transient as a finding.**

---

## 9. Standing lessons

- **A "deliberate hold" comment is a claim, not evidence.** Re-verify every held pin against the
  advisory's own range each run. Articles frequently quote a narrower affected range than the advisory
  (`introduced: 0 → fixed: X` can include versions an article says are safe).
- **Verify holds in both directions.** Some holds are correct (a dependency caps the package below the
  fixed version and the alternative carries the same CVEs plus more).
- **A duplication finding must check what imports each copy** before consolidating.
- **A registry 404 is point-in-time.** A rule that says "version X never existed" will one day roll the fleet backwards.
- **Rank pins against an advisory feed, never against the fleet median** — "newer than the others" is not "safe".
- **Prove the sweep was complete**: after any fleet-wide edit, grep for the old value and expect zero hits outside build output.

---

## 10. Generic gotchas

| Gotcha | Detail |
| --- | --- |
| Alpine `localhost` → IPv6 | Health checks, DB/Redis URLs use `127.0.0.1` |
| `pids_limit` with a deploy block | Use `deploy.resources.limits.pids` |
| Redis/Postgres + `cap_drop: ALL` | Need `CHOWN, DAC_OVERRIDE, SETGID, SETUID` (+`FOWNER` for PG) |
| `.dockerignore` excluding `tsconfig.json` | Breaks `@/*` alias resolution in Docker builds |
| Windows case-insensitivity | Imports that differ in case from the file pass locally and fail on Linux builds |
| Windows dynamic port reservations | Hyper-V/winnat can reserve any port, even high ones; durable fix `netsh int ipv4 add excludedportrange` (admin) |
| Root folder rename | Breaks every bind mount — `docker compose up -d --force-recreate` per stack; named volumes are safe |
| `n_live_tup` lies before `ANALYZE` | Run `ANALYZE;` before trusting table sizes |
| External network pruned | Stacks declaring `external: true` fail `compose up` until it is recreated |
| npm skipping install scripts | Newer npm may not run unapproved postinstall scripts — packages with binaries (electron) install without them |
| Some packages need `--legacy-peer-deps` | Without it `npm install` may exit 0 having changed nothing — verify the lockfile actually moved |
| Docs drift | Overview docs, port registries and `AGENTS.md` drift from compose — the compose files are the truth |
