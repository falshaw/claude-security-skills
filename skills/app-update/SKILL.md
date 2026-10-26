---
name: app-update
description: Safely fixes npm/pip security advisories and updates dependencies for ONE app directory without breaking it. Separates non-breaking in-range patches (auto-apply) from breaking major bumps (ASK-FIRST, refactor + verify), uses verified npm overrides for stuck transitive dependencies, checks vendor security releases that npm audit / OSV may not carry yet, and proves the app still typechecks, builds and boots. Covers Electron, Next.js + Prisma, and Python apps. Use when the user says "update the app", "fix the vulnerabilities", "npm audit", "bump dependencies", "update deps", "upgrade [app]", "patch Next.js", or pastes npm audit / npm outdated / pip output for an app.
---

# App Dependency Update & Vulnerability Fix

## Overview

A repeatable, low-risk workflow for updating ONE app's dependencies and clearing security advisories.
The whole point: **fix what's safe automatically, never silently take a breaking major bump, and always
verify the app still boots before declaring done.**

Assumed layout: each app lives in its own directory (e.g. `apps/<name>/`) with its own `package.json` /
lockfile / `node_modules` (or `requirements*.txt` / `pyproject.toml`). Work **inside the app dir** — never
run npm at a monorepo root that has no `package.json` of its own.

Copy this checklist into the run:

```
- [ ] 0 Scope + read app README/CLAUDE.md + backup manifests
- [ ] 1 npm audit fix (no --force)        - [ ] 1b vendor advisories (framework / ORM / runtime)
- [ ] 2 npm update (in-range)             - [ ] 2b overrides for stuck transitives (verified)
- [ ] 3 majors -> ASK FIRST               - [ ] 4 verify: tsc + build + boot (loop until green)
- [ ] 5 report before/after
```

## When to use

- "update the app" / "fix the vulnerabilities" / "npm audit fix" / "bump deps" / "upgrade X"
- The user pastes `npm audit` or `npm outdated` output for an app
- After an advisory lands on a transitive dependency, or a framework security release ships
  (e.g. a Next.js release on nextjs.org/blog)
- Many apps? Run `fleet-audit` first to find which need it, then this skill once per app.

## Workflow

### 0. Scope to the app

```bash
cd apps/<name>      # ALWAYS. Never run npm at a root with no package.json.
```

Read the app's `README.md` / `CLAUDE.md` / `AGENTS.md` first — stack type (Electron / Next.js / Python
service) and known gotchas. Before the first change, snapshot the manifests:

```bash
B=backups/app-update/<name>-$(date +%F); mkdir -p "$B"
cp package.json package-lock.json "$B"/ 2>/dev/null
cp requirements*.txt *.lock "$B"/ 2>/dev/null
```

If the app is under git, `git status` must be clean (or the user agrees) and you work on a feature branch;
the commit/diff is then the rollback. Either way the snapshot is the diff base for the report.

**`NODE_ENV=production` trap:** if the shell has `NODE_ENV=production` set globally, plain `npm install`
omits devDependencies, so `tsc` / `prisma` silently go missing (a "0 errors" tsc run that never ran).
Check `echo $NODE_ENV`; use `npm install --include=dev` and run the compiler explicitly as
`node node_modules/typescript/bin/tsc --noEmit`.

### 1. Fix vulnerabilities (non-breaking)

```bash
npm audit                 # read the advisories + which dep they're transitive under
npm audit fix             # NON-breaking only — applies in-range fixes
npm audit                 # confirm: should say "found 0 vulnerabilities"
```

- **Never run `npm audit fix --force`** without explicit approval. Per the npm docs, `--force` lets
  `audit fix` "install modules outside your stated dependency range (including SemVer-major changes)".
  If audit says a fix is "available via `npm audit fix --force`", treat that dep as a **major bump** → step 3.
- `--force` can also **downgrade** a framework to an older major to "fix" a transitive (e.g. resolving a
  `mysql2` / `fast-uri` advisory by dropping Prisma 7 back to 6.x). Read what it plans before accepting.
- Most vulns are transitive. `npm audit fix` resolves most cleanly; when it doesn't → 2b.
- After any `npm audit fix --omit=dev`, re-run `npm install --include=dev` and confirm devDeps survived —
  it can prune things like `electron` that the app needs at runtime.

### 1b. Vendor advisories the databases may not carry yet

`npm audit` and OSV only know what is in the advisory database. Framework vendors sometimes publish
security releases days before the GitHub Advisory Database / OSV pick them up — during that window every
affected app reports "found 0 vulnerabilities". Real example: Next.js **GHSA-vcvr-r3jv-pc5j** (critical RCE
in the Node.js `ImageResponse` / `next/og`, affects `>=16.2.0 <16.3.6`, fixed in 16.3.6) was absent from
OSV and the GitHub advisory DB for days after the vendor release.

For each framework / ORM / runtime in the app (Next.js, Prisma, Node, Electron, Django/FastAPI, ...):

1. Read the vendor security page / release blog (e.g. [nextjs.org/blog](https://nextjs.org/blog)).
2. Query the repo's own advisories, which often land first:
   ```bash
   gh api repos/vercel/next.js/security-advisories --jq '.[] | "\(.severity) \(.ghsa_id) \(.summary)"' | head
   ```
3. Compare against what the lockfile actually resolved (not what `package.json` declares):
   ```bash
   node -e "const p=require('./package-lock.json').packages;console.log('next',p['node_modules/next']?.version,'prisma',p['node_modules/@prisma/client']?.version,'electron',p['node_modules/electron']?.version)"
   ```

Keep a **security floor** per framework (the lowest patched version you accept, e.g. "Next.js lockfile
>= 16.4.1"). A lockfile below the current vendor floor is a finding **even at "0 vulnerabilities"**.

A floor bump that crosses the declared range (e.g. `~16.3.x` → `16.4.x`) is a declared-range change:
edit `package.json`, `npm install --include=dev`, typecheck, rebuild. It is still a minor — no ASK for the
edit, but ask before a rebuild/redeploy round if that touches running services. Inside the range → step 2.

### 2. Apply in-range updates (safe)

```bash
npm outdated              # Current / Wanted / Latest per dep
npm update                # bumps everything to "Wanted" (within the package.json SemVer range)
npm audit                 # re-confirm 0 vulns
```

`Wanted` == in-range == safe to apply without asking. `Latest > Wanted` across the first number == a major.
To take one specific patch: `npm install next@16.4.2` (explicit version, stays inside `~16.4.x`).

### 2b. Stuck transitive → `overrides` (verified, never a downgrade)

When the fixed version is inside the parent's declared range but `npm audit fix` won't restructure the tree
(it silently no-ops on some trees):

```bash
npm ls <pkg> --package-lock-only          # who pulls it in
npm view <parent> dependencies --json     # the parent's declared range for <pkg>
npm view <pkg> versions --json            # does the fixed version EXIST? (existence first)
```

Add to `package.json`:

```json
"overrides": { "<pkg>": "^<fixed>" }
```

then `npm install --package-lock-only` (or `npm install --include=dev`) and **exercise the code path** that
uses the package. Example: for a `deepmerge-ts` override under Prisma, run
`npx prisma validate && npx prisma generate`. If you also depend on the package directly, use the
self-reference form `"sharp": "$sharp"` so the override follows your direct version.

Rules for overrides:
- The override target must be **>=** the currently resolved version — never an accidental downgrade.
- It must satisfy (or knowingly widen) the parent's declared range; if it crosses a major of the parent's
  expectation, treat it as a major (step 3).
- An override you have not exercised is a guess. Remove overrides once the parent ships the fix itself.

### 3. Major bumps — ASK FIRST, then refactor + verify

For any dep where `Latest` crosses a major (`Current` and `Latest` differ in the first number), or that is
only fixable via `--force`:

1. **Check how it's imported** — the breaking change is usually the module system or a renamed API:
   ```bash
   grep -rn "<pkg>" main.js src/ lib/ renderer/ app/ 2>/dev/null
   ```
2. **Read the changelog / migration guide** (Context7 or the vendor docs) and list exactly what breaks.
3. **Present the risk and ASK** whether to take the major.
4. If approved: bump, apply the code change, then verify the app boots (step 4).

Known major-bump traps:

| Dependency | Trap | Fix |
|---|---|---|
| `electron-store` v9+ (and other ESM-only libs) | **ESM-only.** `require("electron-store")` throws in a CommonJS app. | Load via dynamic `import()` inside an async init, awaited at the top of `app.whenReady()`. Keep the app CommonJS — don't cascade `"type":"module"` into preload/worker scripts. |
| `@huggingface/transformers` v3→v4 | Major, but the `pipeline` API is stable; usually loaded via dynamic `import()`. | Verify `pipeline` / `env` still export; often no code change. |
| Next.js / React majors | Build, proxy/middleware, caching and RSC changes. | Read the migration guide; run `npm run build` + `tsc --noEmit`; boot and hit key routes. |
| **`prisma` / `@prisma/client`** | The `prisma` CLI `latest` dist-tag can point at a **release candidate of the next major**. `npm install prisma` with no version pulls the RC. | **Always pin an explicit version** and keep CLI, client and adapter identical: `npm install -D prisma@7.x.y && npm install @prisma/client@7.x.y @prisma/adapter-pg@7.x.y`. Check `npm view prisma dist-tags` first. A new Prisma major = ASK FIRST. Prisma 7 needs a driver adapter (e.g. `PrismaPg`) + `prisma.config.ts`. |
| TypeScript / ESLint new majors | npm `latest`, but may crash the framework toolchain (e.g. Next.js lint/build). | Stay on the version range the framework supports; a held major is not a finding. |
| Python (`requirements.txt` / `*.lock`) | npm doesn't apply. | `pip list --outdated`; `pip-audit -r requirements.txt` (or an OSV query per pin); **check the version exists on PyPI before pinning it** (`pip index versions <pkg>`); bump pins AND regenerate any hash lock (`pip-compile --generate-hashes`) if the Dockerfile installs with `--require-hashes`; then `ruff check .` / `mypy .` / `pytest`. |

### 4. Verify it still runs (mandatory — never skip)

The skill is worthless if the app is left broken. Run the check, fix what fails, re-run — **only stop when
it passes.** Pick the check for the stack:

- **Electron app:** `node --check main.js`, then launch `timeout 35 npx electron .` and confirm no unhandled
  rejection / crash. For UI you can't see (tray icon), assert programmatically in the Electron runtime
  (e.g. `nativeImage(...).isEmpty()` must be `false`). After an Electron bump, confirm the binary was
  re-fetched (`node_modules/electron/dist/` exists and `npx electron --version` matches).
- **Next.js app:** `node node_modules/typescript/bin/tsc --noEmit` && `npm run build`. Run `prisma generate`
  first with a dummy `DATABASE_URL`; `next build` may need valid-length dummy secrets
  (e.g. a 32+ char `JWT_SECRET`). Never put real secrets on the command line.
- **Dockerised app:** `docker compose build --no-cache <svc>` then `docker compose up -d --no-deps <svc>`
  (`--no-deps` avoids dragging in shared services) and hit the health endpoint
  (`curl -fsS http://127.0.0.1:<port>/api/health`). Then verify the bumped version **inside the rebuilt
  image**, not just in the host lockfile:
  ```bash
  docker compose exec <svc> node -e "console.log(require('next/package.json').version)"
  ```
  If Docker is not running, say so and mark the app **edited-only (not rebuilt)** — don't start the daemon
  unasked.
- **Prisma migrations on Windows:** some application-control policies (e.g. Smart App Control) block Prisma's
  unsigned `schema-engine-windows.exe` (`spawn UNKNOWN`). Don't bypass the policy — run migrations inside
  the app container or the Postgres container, with a backup first.
- **Python:** `ruff check .` && `pytest` (and `mypy .` if configured).
- After a Docker frontend rebuild, hard-reload the browser (Ctrl+Shift+R) before judging the UI.

### 5. Report honestly

- Vulns before/after (`3 -> 0`), every version bumped (old → new), every override added, every code change.
- Vendor-floor status per framework (lockfile version vs current floor).
- What verification actually ran and its result; mark the app **rebuilt+healthy**, **rebuilt+failed** or
  **edited-only (not rebuilt)**.
- Majors held back, with the reason and what would break — these need a user decision.
- Note that `package-lock.json` / `node_modules` were regenerated; show the version diff against the step-0
  snapshot (or `git diff package.json`). If the app's docs state versions, update that line too.

## Electron gotcha: SVG icons

`nativeImage.createFromBuffer` does **not** decode SVG — it needs encoded PNG/JPEG bytes. An SVG buffer
yields an empty image (invisible tray icon, no error). If an app builds tray/window icons from inline SVG,
pre-rasterise to base64 PNG at build time (a small `scripts/gen-tray-icons.js` using `sharp` writing
`lib/tray-icons.js`) and load with `nativeImage.createFromBuffer(Buffer.from(b64, "base64"))`.

## Hard rules

- Work inside the app dir; never at a root without its own manifest.
- `npm audit fix` (no `--force`) and `npm update` are safe to apply without asking.
- **Never `npm audit fix --force`** without explicit approval.
- **Pin framework/ORM versions explicitly** — never a bare `prisma` / `@latest` (the tag can be an RC).
- Verify the fixed version exists in the registry before pinning or overriding to it.
- Every major bump is ASK-FIRST and must be verified by actually launching the app.
- `npm ci` is the reproducible install path; `npm install <pkg>@<ver>` is correct when intentionally
  changing a version.
- Never commit, push or deploy as part of this skill — leave that to the user.
