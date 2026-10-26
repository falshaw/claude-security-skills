# Docker Security Audit — Full Reference

Companion to `SKILL.md` (procedure). This file holds the catalogue: host CVE detail, the 14 category checklists, severity matrix, remediation playbooks, output templates, execution steps, gotchas, diagnostic commands and supply-chain incident notes. Version numbers are **security floors at the time of writing** — re-check upstream release notes every run and raise a floor when a new fix ships.

## Contents

- Host CVE quick-checks (runc, Compose, Engine 29, BuildKit, CIS benchmark)
- Audit Framework (Phase 1 discovery, Phase 2 categories 1-14)
- Severity Scoring Matrix · Remediation Playbooks · Output Format · Audit Execution Steps
- Common Mistakes · Known Gotchas · Quick Diagnostic Commands
- Supply-chain incidents an auditor should know · Historical pinned-base CVE notes

Throughout, `$ROOTS` = the `roots` list from `audit.config.yml` (e.g. `apps infra shared`).

---

## Host CVE quick-checks (run BEFORE the per-stack audit)

A vulnerable host runtime makes per-stack hardening moot. Treat any miss as **stop-and-fix**, then resume the static audit.

### runc Nov-2025 container-escape trio (P0)

| CVE | Vector | Fixed in |
| --- | --- | --- |
| CVE-2025-31133 | `/dev/null` masking bypass — replaced with a symlink to an attacker-controlled file | runc 1.2.8 / 1.3.3 / 1.4.0-rc.3 |
| CVE-2025-52565 | `/dev/console` bind-mount race — TOCTOU during init | runc 1.2.8 / 1.3.3 / 1.4.0-rc.3 |
| CVE-2025-52881 | `/proc` write redirect — arbitrary writes to `/proc/sysrq-trigger` | runc 1.2.8 / 1.3.3 / 1.4.0-rc.3 |

All three require the attacker to start a container with a custom mount configuration (malicious image or Dockerfile) — highest relevance for any workflow that pulls from public sources (headless-browser workers, GPU images built from upstream clones). runc 1.3.6 / 1.4.3 also close CVE-2026-41579 (malicious image with a `/dev` symlink gains limited host write — low severity).

```bash
docker info | grep -i runc
runc --version        # if installed standalone
```

### Docker Compose CVE-2025-62725 (P1)

Path traversal via OCI artifact `com.docker.compose.file` / `envfile` annotations. Triggered even by **read-only** commands (`docker compose ps`, `docker compose config`) if any project uses `include:` from an OCI registry. CVSS 8.9. Fixed in **v2.40.2** — this is the security floor, not the latest; Compose is on the v5.x line. Anything ≥ 2.40.2 is patched.

```bash
docker compose version   # require >= v2.40.2
```

### Docker Engine 29 patches (P1)

| CVE | What it fixes | Engine |
| --- | --- | --- |
| CVE-2026-17106 / GHSA-hfg8-hc9c-6c3h | moby/go-archive < 0.3.0 — tar extraction uses lexical path validation then OS-resolved operations, so archive symlinks/hardlinks write **outside** the destination (`docker cp`, image-layer extraction). CVSS 7.1 | **29.7.0** |
| CVE-2026-15793 / 15792 / 15791 / 15789 / 15788 | BuildKit v0.30.0-v0.31.1: Git-bundle checkout → host command injection (custom frontend / raw LLB only); malformed frontend params → panic; local-source destination validation bypass; LLB file-op can wipe `/tmp`; WCOW cache mount follows NTFS junctions (Windows containers only). Fixed BuildKit v0.31.2 | **29.6.2** |
| GHSA-mjcv-p78q-w5fw / GHSA-jpcc-p29g-p8mq / GHSA-72x6-4j93-7w86 · GHSA-7236-3392-c5c6 | passwd/group parsing OOM · custom-frontend Seccomp/AppArmor bypass | **29.6.1** |
| CVE-2026-41567 | `docker cp` archive decompressor (xz/unpigz) resolved via container PATH while running as host root → host code exec | **29.5.1** |
| CVE-2026-41568 | `docker cp` TOCTOU — file/dir creation at arbitrary host paths | 29.5.1 |
| CVE-2026-42306 | `docker cp` TOCTOU — bind-mount redirect to arbitrary host paths | 29.5.1 |
| CVE-2026-32288 | DoS — sparse tar in a malicious image pull causes unbounded daemon memory allocation | 29.5.0 |
| CVE-2026-31431 | "copy.fail" — AF_ALG kernel crypto API escape. Mitigated by default seccomp (29.4.2) + AppArmor `deny network alg,` (29.4.3) | 29.4.2 / 29.4.3 |
| CVE-2026-34040 | Engine AuthZ-plugin bypass — request bodies > 1 MB skip the plugin (CVSS 8.8) | 29.3.1 |
| CVE-2026-33997 | `docker plugin install` privilege-validation bypass | 29.3.1 |
| CVE-2026-33747 / 33748 | BuildKit untrusted frontend / Git `#ref:subdir` file write outside state dir | 29.3.1 / BuildKit v0.28.1 |

Newer Engine 29.x releases have also fixed Go-runtime HTTP/2 daemon DoS issues and bundled containerd security fixes (crafted image / malicious registry during pull or import). If the newest Engine is not yet shipped by any Docker Desktop build, grade it as a **P3 watch**.

**Practical host bar: Engine ≥ 29.7.0, BuildKit ≥ 0.31.2, runc ≥ 1.3.3, Compose ≥ 2.40.2.**
Sources: [Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/), [GHSA-hfg8-hc9c-6c3h](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h), [BuildKit releases](https://github.com/moby/buildkit/releases), [runc releases](https://github.com/opencontainers/runc/releases), [Compose releases](https://github.com/docker/compose/releases).

```bash
docker version --format '{{.Server.Version}}'          # require >= 29.7.0
docker buildx version                                   # buildx CLI plugin — NOT the BuildKit daemon
docker buildx inspect --bootstrap | grep -i buildkit    # the BuildKit DAEMON version (floor 0.31.2)
```

> **buildx ≠ BuildKit:** `docker buildx version` reports the CLI plugin; the CVEs live in the **daemon**. On Docker Desktop they ship together; on a standalone builder, check the daemon explicitly.

**AppArmor on Docker Desktop / WSL2:** `docker info` may not report AppArmor on WSL2 kernels — a Desktop behaviour, not a regression. On native Linux hosts it must be listed.

**`docker cp` is a privileged operation** — never `docker cp` from/to an untrusted or running container on an unpatched Engine. If an LLM gateway container mounts host credentials read-only, re-verify `RW=false` under each new Engine.

### CIS Docker Benchmark (re-verify the current version each run)

Use the current CIS Docker Benchmark ([cisecurity.org/benchmark/docker](https://www.cisecurity.org/benchmark/docker)). `docker/docker-bench-security` lags the benchmark — keep it as an optional self-audit only. Its emphasis (non-root, per-container caps/seccomp/no-new-privileges/read-only, loopback binds) matches the OWASP Docker Security Cheat Sheet rules 1-13 (no docker.sock, non-root, `--cap-drop all`, `no-new-privileges`, 127.0.0.1 binds, `--read-only` + tmpfs, memory/CPU/pids limits, signing/provenance). **Do not cite OWASP Container Security Verification Standard (CSVS)** — archived 2023, unmaintained; use CIS + NIST SP 800-190.

---

## Audit Framework

### Phase 1: Discovery

Scan each stack directory for:

```
<root>/<stack>/
  docker-compose*.yml / compose*.yaml / *.yml with services:   # primary + overlays (.override / .dev / deploy/ / lab/)
  Dockerfile*            # image definitions (root, or backend/ + frontend/, worker/, sidecar/)
  .dockerignore          # build exclusions (MUST exist in EVERY build context)
  .env                   # environment (check for secrets — never echo values)
  .env.example           # template (compare keys, not values)
  init-db.sql / init/    # DB initialisation scripts
```

**Extract from compose:** service definitions + image pins (tag@digest); networks (subnets, aliases, `external`); port mappings — must be `127.0.0.1:host:container`; volumes/tmpfs; environment (`${VAR:?msg}` for credentials, `:-` only for documented toggles); `depends_on` (`condition: service_healthy`); `cap_drop`/`cap_add`/`security_opt`/`read_only`/`deploy.resources.limits` (pids under `deploy`); `group_add`; `profiles`; restart policy; health checks (`127.0.0.1`, never `localhost`); logging; `stop_grace_period`; `extra_hosts`; `container_name` collisions across projects (`container_name` is global — `COMPOSE_PROJECT_NAME` does not protect it).

**Extract from Dockerfile:** base image (patch + digest); stages (Node 4-stage base→deps→builder→runner; Python 2-stage); `apk upgrade` / `apt-get upgrade` in base; `USER`; `RUN rm -f .env` for Next.js standalone; exposed ports; remote binary downloads (must be checksum-gated); `git clone` of upstream repos (must be commit-pinned); baked `ENV` with keys/passwords.

**Extract from .dockerignore:** must exclude `.env`, `.env.*`, `**/.env*` (root-anchoring!), `.git`, `node_modules`, `.next`, `secrets/`, `backups/`, `*.sql`. Missing `.dockerignore` in ANY build context = P1.

**Reconcile live state** (only when the daemon is up): `docker ps -a` vs the discovered compose files; stray containers, images built from Dockerfiles with no compose (ad-hoc `docker run`), and orphaned networks are findings or cleanup items.

---

### Phase 2: Security Assessment Categories

#### Category 1: Network Security

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| Isolated subnet per stack | Lateral movement | `networks:` section in compose |
| No `network_mode: host` | Container escape / host stack exposure | grep compose; only with a documented exception |
| Ports bound to `127.0.0.1` only | External / LAN access | `ports: "127.0.0.1:3000:3000"` not `"3000:3000"` |
| Internal-only networks for DB/cache | Exposure | `internal: true` on compose networks |
| Shared external networks joined only where needed | Over-sharing | list consumers of each `external: true` network |
| No subnet overlaps | Routing conflict | step 3b sweep across all roots + `docker network inspect` |
| `extra_hosts` only for host services that are genuinely used | Host reachability | `host.docker.internal:host-gateway` lines |

#### Category 2: Container Hardening

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| Non-root user | Privilege escalation | `USER` in the runtime stage (e.g. `nextjs` uid 1001; Python `appuser`) |
| nginx containers run as uid 101 | Privilege escalation | `USER nginx` + `uid=101,gid=101` on tmpfs mounts |
| Read-only root filesystem | Persistence | `read_only: true` |
| tmpfs for writable dirs | Missing writes | `tmpfs: /tmp:size=100m`, `.next/cache:size=200m` |
| No privileged mode | Full host access | `privileged: true` must not exist |
| Capabilities dropped | Kernel exploits | `cap_drop: [ALL]` (selective `cap_add` for DB/cache only; nginx none under `USER nginx`) |
| No new privileges | Privilege escalation | `security_opt: [no-new-privileges:true]` |
| Resource limits | DoS | `deploy.resources.limits.memory` + `.cpus` |
| PID limits | Fork bomb | `deploy.resources.limits.pids: 200` (consistent with any service-level `pids_limit` — keep one form) |
| Docker socket access | Container escape | only via a socket proxy (e.g. `tecnativa/docker-socket-proxy`); `group_add: ["0"]` NOT `cap_add: DAC_OVERRIDE` |
| Bind mounts vs `read_only` | Writable path despite `read_only` | a rw bind mount defeats `read_only` for that path — prefer named volumes or `:ro` |

Typical documented exceptions (record them in `accepted_risks`): GPU image-generation / inference containers that need root for CUDA or host bind ownership (mitigate with `cap_drop: [ALL]` + `no-new-privileges` + pids limit); an LLM CLI gateway that needs a writable `$HOME` (no `read_only`, everything else applied); a reverse proxy that needs `NET_BIND_SERVICE`.

#### Category 3: Image Security

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| Pinned to patch + digest | Supply chain | `node:24.x-alpine@sha256:…` not `node:latest` or `node:24` |
| Alpine / slim base preferred | Attack surface | `bookworm-slim` only where glibc is required (headless browsers, some CLIs) |
| 4-stage Dockerfile (Node) | Secrets in layers | `base -> deps -> builder -> runner` |
| 2-stage Dockerfile (Python) | Secrets in layers | `base (+ apt upgrade) -> runner` |
| `apk upgrade` / `apt-get upgrade` in base | Known vulns | first stage |
| No secrets in build | Credential leak | no `COPY .env`, no secret `ARG`s; `.dockerignore` root-anchoring |
| `.env` removed if copied | Credential leak | `RUN rm -f .env` in runner for standalone builds |
| Remote binaries checksum-gated; upstream clones commit-pinned | Supply chain | `sha256sum -c` before install (negative-test it); `git checkout --detach <commit>` |

Don't hand-type digests — copy from an existing pinned file or `docker buildx imagetools inspect <tag> --format '{{.Manifest.Digest}}'`.

**Verify-before-pinning rule:** run the pin-yank check + `docker pull <pin>` before bumping. **Pin-yank rule:** prefer `<repo>:<patch>-alpine` over `<repo>:<patch>-alpine3.NN` — the bare form follows the current Alpine base and survives upstream pruning (Alpine-suffixed tags get deleted from Hub).

**Digest-pinning escalation (P2 for high-value images):** databases, vector stores, connection poolers, the LLM gateway base and any image with persistent state must carry `@sha256:`; a tag pin alone does not survive a silent rebuild.

**Wrapper images bundle their own base:** e.g. `pgvector/pgvector:<ext>-pg16` ships its own Postgres minor. A sweep that repins `postgres:` misses it. Check the bundled version in-image (`docker run --rm --entrypoint postgres <image> --version`), not the tag date.

**Held-by-choice major lines** (e.g. Postgres 16, Node LTS, nginx stable vs mainline) are not findings while supported; flag only when the line nears EOL or a patch on that line is missing.

#### Category 4: Secrets Management

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| No hardcoded secrets | Credential exposure | grep compose for keys/passwords |
| `.env` not in image | Credential exposure | `.dockerignore` (root-anchoring aware) + `RUN rm -f .env` |
| `${VAR:?error message}` syntax | Silent misconfiguration | required credentials must use `:?` |
| No secrets in compose / baked `ENV` | VCS exposure | passwords in compose or Dockerfile `ENV` |
| `.env.example` has no real values | Template safety | placeholders only; blank weak template passwords |
| No credential copies in build artifacts | Backup/mirror leak | `.next/standalone/.env`, `secrets/` copies — backup tools mirror them |
| Credential is live/funded before P0 | Mis-severity | ask: billable? reachable? revoked? |

#### Category 5: Health Checks

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| ALL services have health checks | Outage detection | `healthcheck:` on every service |
| Use `127.0.0.1` (NEVER `localhost`) | False failures | Alpine resolves localhost to IPv6 |
| App: `wget -qO- http://127.0.0.1:PORT/` | Wrong tool | Alpine has wget, not curl (FastAPI: `wget -O /dev/null`, not `--spider`) |
| PG: `pg_isready -h 127.0.0.1` | Wrong method | standard readiness check |
| Redis: `redis-cli ping` / `-a $$REDIS_PASSWORD` | Auth failure | authenticated Redis needs the password |
| Caddy: admin `http://127.0.0.1:2019/config/` | Wrong port | not port 80 |
| `depends_on: condition: service_healthy` | Race conditions | never bare `depends_on` |

#### Category 6: Logging

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| App log rotation 10m/3 | Disk exhaustion | `logging.options.max-size/max-file` |
| DB/cache log rotation 50m/5 | Disk exhaustion | larger limits for databases |

#### Category 7: Restart Policy

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| Local dev: `restart: "no"` | Stale containers on boot | compose `restart` |
| Exceptions listed in config | — | `restart_exceptions` |
| `profiles:` + `unless-stopped` | Silent persistence | a profile gates the START only — profile-gated services must be `"no"` |

#### Category 8: Supply Chain Security

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| Trivy/Grype/Scout scan: 0 HIGH/CRITICAL | Known vulnerabilities | scanner over every built + pulled image |
| `npm ci`, never `npm install` (no `npm ci \|\| npm install` fallback) | Non-reproducible | Dockerfile `RUN` |
| Advisory monitoring | Unpatched deps | OSV / GHSA queries, Dependabot if the repo is hosted |
| Lock files copied then installed | Cache invalidation | `COPY package*.json` then `RUN npm ci` |
| Remote binaries checksum-gated | Tampered download | `sha256sum -c` with upstream checksums (document trust-on-first-use if none published) |

#### Category 9: Port Conflict Detection

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| No duplicate app ports | Can't run both | compare all `ports:` |
| No duplicate DB ports | Wrong DB / data corruption | compare DB port mappings |
| No duplicate cache ports | Auth confusion | compare Redis mappings |
| No duplicate `container_name` across projects | Clobbering | `container_name` is global |

On Windows hosts, Hyper-V dynamic port reservations can swallow any port (even 15xxx); `netsh int ipv4 show excludedportrange protocol=tcp` shows them, `netsh int ipv4 add excludedportrange` (admin) is the durable fix.

#### Category 10: Resource Hardening

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| `ulimits.nproc` on app containers | Fork bomb | `ulimits:` |
| `ulimits.nofile` (soft/hard) | FD exhaustion | `ulimits:` |
| `shm_size` limited where shared memory is used | Memory abuse | default 64m; override only if needed |
| `stop_grace_period` appropriate | Data loss on stop | default 10s; increase for DB/long-running |
| No `sysctls` unless documented | Kernel exposure | `sysctls:` |

#### Category 11: Dependency Currency

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| `npm audit --omit=dev` — 0 HIGH/CRITICAL | Known vulnerabilities | `npm audit --omit=dev --json` per Node root |
| `pip-audit` — 0 HIGH/CRITICAL | Known vulnerabilities | `pip-audit -r requirements.txt` or OSV per pinned pair |
| No major version behind on direct deps | Missing security fixes | `npm outdated --json` / `pip list --outdated --format=json` |
| Lock file exists | Non-reproducible | `package-lock.json` / pinned `requirements.txt` / `requirements.lock` |
| Lock file freshness (< 90 days) | Stale deps | `stat -c %Y` |
| Pinned base images scanned | Valid-but-vulnerable pin | `grype` / `trivy image` / `docker scout cves`; bump on HIGH/CRITICAL |
| Transitive advisory under an exact-pinning parent | `npm audit fix` offers a breaking downgrade | `overrides` entry, verified at runtime |
| devDeps survive `--omit=dev` fixes | Broken dev tooling | re-run `npm install --include=dev` |
| Existence check before pinning from memory | Phantom pin | check the registry before writing a version |

**Advisory-DB lag:** vendor advisories (e.g. a Next.js security release announced on the Next.js blog) can be absent from OSV and the GitHub Advisory DB for days, so `npm audit` cannot see them. **Rule:** for Next.js / Prisma / Node / Electron / Django etc., read the vendor security page in addition to OSV / `npm audit`.

**Severity mapping:** HIGH/CRITICAL = P1 · MODERATE = P2 · LOW = P3 · major behind = P2 · minor behind = P3 · missing lock = P2 · lock > 90 days = P3.

```bash
# Node roots — derive the list, then audit all
find $ROOTS -name package-lock.json -not -path '*/node_modules/*' | while read f; do
  d=$(dirname "$f"); echo "=== $d ==="
  (cd "$d" && npm audit --omit=dev --json 2>/dev/null | jq '.metadata.vulnerabilities')
done

# Python roots
find $ROOTS \( -name 'requirements*.txt' -o -name pyproject.toml \) -not -path '*/node_modules/*' | while read f; do
  d=$(dirname "$f"); echo "=== $d ==="
  (cd "$d" && pip-audit -r "$(basename "$f")" 2>/dev/null || echo "pip-audit unavailable / not a requirements file")
done

# Lock file ages
find $ROOTS \( -name package-lock.json -o -name 'requirements*.txt' \) -not -path '*/node_modules/*' | while read f; do
  echo "$f: $(( ($(date +%s) - $(stat -c %Y "$f")) / 86400 )) days old"
done
```

#### Category 12: Supply Chain — digest pinning + local CVE scanning

> **For a local, no-registry, single-operator deployment, signing and attestation are mostly theatre — do NOT flag their absence.** The real, cheap, high-value controls are (1) **digest pinning** and (2) **scanning the pinned bases for CVEs on a cadence and bumping pins**. Digest pinning defends at pull time against compromised scanner images, poisoned Hub tags and backdoored base images.
>
> | Control | Verdict for local stacks | Why |
> | --- | --- | --- |
> | **Digest pinning (`@sha256:`)** | **DO — flag any tag-only pin.** | A pinned digest can't be silently swapped by a re-pushed tag. |
> | **Local CVE scan of pinned bases** (Grype / Trivy / `docker scout cves`), bump on HIGH/CRITICAL | **DO** | A digest freezes you to what you pinned — it can be valid AND vulnerable. |
> | **Cosign / Sigstore signing** | SKIP for local-only | No second party verifies → ceremony. |
> | **SLSA provenance / SBOM attestation** | SKIP for local-only | Attestations exist for registry consumers. **Provenance ≠ integrity** — packages with valid npm OIDC provenance have shipped malware. |
>
> If images are ever pushed to a registry consumed by others, signing + SBOM become real controls. If you adopt Trivy, **pin Trivy itself by digest**. Docker Content Trust / Notary v1 is retired. Docker Hardened Images / Chainguard / distroless are an optional rebase path, not a finding.

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| High-value images pinned by digest | Silent tag-content rebuild | `image:` lines — DB, vector store, pooler, gateway base, every vendor image |
| Pinned bases scanned on a cadence | Valid-but-vulnerable pin | Grype/Trivy/Scout + registry changelog each run |

Reference only (for the day images go to a registry):

```bash
COSIGN_EXPERIMENTAL=1 cosign verify <image>:<tag> \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'

docker buildx create --use --name audit-builder --driver docker-container
docker buildx build --sbom=true --provenance=mode=max --platform linux/amd64 \
  --tag <app>:local --load apps/<app>/
docker buildx imagetools inspect <app>:local --format '{{json .Provenance}}' | jq
docker buildx imagetools inspect <app>:local --format '{{json .SBOM}}' | jq
```

#### Category 13: Advanced Runtime Hardening

Beyond `cap_drop: [ALL]` + `no-new-privileges` + `read_only`. Advisory P2/P3 — needs a coordinated rollout.

| Check | Risk if Fail | How to Check |
| --- | --- | --- |
| Compose `secrets:` for DB/JWT credentials | `environment:` leaks via `docker inspect` / `/proc/<pid>/environ` | top-level `secrets:` + per-service ref |
| `security_opt: apparmor=docker-default` explicit | Distro profile not pinned | `security_opt:` |
| Custom seccomp for high-risk containers (headless browsers, LLM gateways) | Default profile too permissive | `seccomp=path/to/profile.json` (build via `strace -c`) |
| Chainguard / distroless / DHI runtime images | Larger attack surface (shell + package manager) | `FROM`; keep a debug variant in `docker-compose.debug.yml` |
| Builds use local cache, not live Hub pulls | Rate limit / tag-flip surprise | build flow |
| tmpfs `noexec,nosuid,nodev` | Code exec from tmpfs | `tmpfs:` options |
| Rootless / userns-remap on Linux hosts | Daemon root = breakout = host root | n/a on Docker Desktop |

```yaml
secrets:
  jwt_secret:
    file: ./secrets/jwt.txt
  db_password:
    file: ./secrets/db_password.txt

services:
  app:
    secrets: [jwt_secret, db_password]
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - DB_PASSWORD_FILE=/run/secrets/db_password
```

Requires an app change (read `*_FILE`, then the file) + rebuild — pilot one stack first; mark P2 advisory, never auto-apply.

```yaml
services:
  browser-worker:
    security_opt:
      - seccomp=./profiles/browser-worker.seccomp.json
      - apparmor=docker-default
      - no-new-privileges:true
    tmpfs:
      - /tmp:size=100m,uid=1001,gid=1001,mode=1700,noexec,nosuid,nodev
```

After CVE-2026-31431 ("copy.fail"), `docker-default` gained `deny network alg,` — making the profile explicit keeps that mitigation visible on Linux hosts.

#### Category 14: AI/LLM Model Provenance + MCP / Gateway Security

Applies when stacks include a vector DB, a local inference server, an LLM CLI gateway or MCP servers.

| Check | Risk if Fail | How to Check | Sev |
| --- | --- | --- | --- |
| Vector DB bound to `127.0.0.1` only | Unauthenticated API (e.g. Qdrant `/logger` file write, CVE-2026-25628, fixed v1.16.0) | `ports:` — never `0.0.0.0` | P1 if `0.0.0.0` |
| Vector DB API key set | Qdrant ships auth-off + unencrypted | `QDRANT__SERVICE__API_KEY=${QDRANT_API_KEY:?}`; optional read-only key; without TLS keep it loopback-only | P2 |
| Gateway credentials = file, read-only, not env | `docker inspect` / `/proc/<pid>/environ` leak | `:ro` file mount, no `*_API_KEY` env; gateway token `${:?}` fail-fast; code mount `:ro`; metrics endpoint token-gated | P2 |
| Gateway allowlist + token on every consumer | Unbounded paid-plan use | per-consumer allowlist entry; missing token must fail closed (401) | P3 |
| docker.sock consumers fronted by a socket proxy | `:ro` socket is NOT a boundary — full API = host root | proxy with `CONTAINERS=1,POST=0` | P2 |
| Model provenance (trusted namespaces, pinned digests, override chat templates) | Jinja2 chat-template RCE; GGUF parser overflows (CVE-2026-33298 `ggml_nbytes` integer overflow, CVE-2026-27940 `gguf_init_from_file_impl()` overflow, CVE-2026-21869 unvalidated `n_discard`) | inference server version + model source; vLLM ≥ 0.14.1 (CVE-2026-22778) | P2 |
| Inference server on loopback, patched | Unauthenticated model API / memory leak (Ollama CVE-2026-7482, fixed ≥ 0.17.1) | `127.0.0.1:11434`, version vs release notes; a host-native server is outside the container audit but report its version | P1 if exposed |
| MCP servers vetted, version-locked, scanned | Tool poisoning / rug-pull / prompt injection in server instructions | enabled-server list, `mcp-scan`, OWASP MCP Top 10; disable any server whose instructions try to override the agent | P3 |
| CVE triage uses KEV + EPSS | NVD enrichment backlog | PURL-based scanners | n/a |

```yaml
services:
  llm-gateway:
    volumes:
      - ./gateway-code:/app:ro
      - gateway-state:/state
      - ${HOME}/.config/llm-cli/credentials.json:/seed/credentials.json:ro
    environment:
      - GATEWAY_TOKEN=${GATEWAY_TOKEN:?set GATEWAY_TOKEN in .env}
    # AVOID: environment: VENDOR_API_KEY=...   (leaks via docker inspect)

  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:<tag>@sha256:<digest>
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]
    environment: [CONTAINERS=1, POST=0]
    networks: [socket-proxy-net]
  log-shipper:
    environment: [DOCKER_HOST=tcp://docker-socket-proxy:2375]
    networks: [socket-proxy-net]
```

Noted but usually skip for single-host local stacks: eBPF runtime monitoring (Falco/Tetragon); gVisor/Kata.

---

## Severity Scoring Matrix

| Severity | Criteria | Response Time |
| --- | --- | --- |
| **P0 - Critical** | Immediate exploitation possible; **funded/live** credentials exposed; host runtime escape unpatched | Fix immediately |
| **P1 - High** | Privilege-escalation path, LAN/network exposure, missing `.dockerignore`, root runtime | Fix within 24h |
| **P2 - Medium** | Hardening missing, stale/yanked pin with a security changelog, best-practice violation | Fix within 1 week |
| **P3 - Low** | Currency, minor improvements, optimisation | Next maintenance |

Re-derive severity every run — never inherit it from a prior report.

---

## Remediation Playbooks

### Non-Root User — Node.js (P1)

```dockerfile
# runner stage
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs
USER nextjs
```

### Non-Root User — nginx (P1)

```yaml
# compose tmpfs entries (with USER nginx in the Dockerfile — then NO cap_add)
tmpfs:
  - /tmp:size=100m,uid=101,gid=101
  - /var/cache/nginx:size=50m,uid=101,gid=101
  - /run:size=1m,uid=101,gid=101          # nginx.pid
```

Never put a tmpfs on `/etc/nginx/conf.d`: the mount hides the `default.conf` copied in at build time
and nginx starts with no server block. Tmpfs only the cache and run dirs. If the image renders
`/etc/nginx/templates/*.template` at start, point the output at a tmpfs
(`NGINX_ENVSUBST_OUTPUT_DIR=/tmp/conf.d`) and `include /tmp/conf.d/*.conf;` from `nginx.conf`.

### Pin Image Versions (P2)

**Bad:** `image: node:latest` · `image: postgres:16` · `image: redis:7-alpine`
**Good:** `image: postgres:16.<patch>-alpine@sha256:<digest>` — digest from `docker buildx imagetools inspect postgres:16.<patch>-alpine --format '{{.Manifest.Digest}}'`.

### 4-Stage Dockerfile — Node.js / Next.js (P2)

```dockerfile
# Stage 1: base
FROM node:<lts>-alpine@sha256:<digest> AS base
RUN apk upgrade --no-cache

# Stage 2: deps
FROM base AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Stage 3: builder
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx prisma generate && npm run build

# Stage 4: runner
FROM base AS runner
WORKDIR /app
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
RUN rm -f .env
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
```

### 2-Stage Dockerfile — Python (P2)

```dockerfile
# Stage 1: builder — installs dependencies into a venv; pip caches and build tools stay here
FROM python:3.<minor>.<patch>-slim@sha256:<digest> AS builder
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt

# Stage 2: runner — same base digest, only the venv and the app code
FROM python:3.<minor>.<patch>-slim@sha256:<digest> AS runner
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY . .
RUN rm -f .env
USER appuser
EXPOSE 8000
CMD ["python", "main.py"]
```

`--require-hashes` only works on a hash-locked file: every requirement pinned with `==` and carrying
`--hash=sha256:...`, transitive dependencies included (`pip-compile --generate-hashes` or
`uv pip compile --generate-hashes`). A plain `requirements.txt` fails the build. Use the same base
image digest in both stages so the venv's interpreter path matches.

### Container Hardening (P1/P2)

```yaml
services:
  app:
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    read_only: true
    tmpfs:
      - /tmp:size=100m
      - /app/.next/cache:size=200m
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
          pids: 200
```

### Docker Socket Access (P1)

Front the consumer with a socket proxy (Category 14 pattern). If a direct mount is unavoidable: `:ro` + `group_add: ["0"]` + `cap_drop: [ALL]` — **never** `cap_add: [DAC_OVERRIDE]` — and treat it as host root anyway.

### Health Checks (P2)

```yaml
# App
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://127.0.0.1:3000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s

# PostgreSQL
healthcheck:
  test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U $$POSTGRES_USER -d $$POSTGRES_DB"]
  interval: 10s
  timeout: 5s
  retries: 5
  start_period: 30s

# Redis without / with auth
healthcheck:
  test: ["CMD", "redis-cli", "ping"]
healthcheck:
  test: ["CMD-SHELL", "redis-cli -a $$REDIS_PASSWORD ping"]

# Inference server (e.g. Ollama)
healthcheck:
  test: ["CMD", "ollama", "list"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

### Depends On with Health (P2)

```yaml
depends_on:
  db:
    condition: service_healthy
  redis:
    condition: service_healthy
```

### Env Var Validation (P2)

```yaml
environment:
  DATABASE_URL: ${DATABASE_URL:?DATABASE_URL is required}
  REDIS_URL: ${REDIS_URL:?REDIS_URL is required}
  JWT_SECRET: ${JWT_SECRET:?JWT_SECRET is required}
```

### Network Isolation (P1)

```yaml
networks:
  app-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.NN.0.0/24   # pick a FREE /24 — run the 3b sweep first

services:
  app:
    ports: ["127.0.0.1:3000:3000"]
    networks: [app-network]
  db:
    networks: [app-network]      # no host ports
```

### Log Rotation (P3)

```yaml
logging:
  driver: "json-file"
  options: { max-size: "10m", max-file: "3" }   # DB/cache: 50m / 5
```

### Restart Policy (P3)

```yaml
services:
  app:
    restart: "no"   # local dev default; exceptions only via restart_exceptions in config
```

### .dockerignore (P1)

```
.env
.env.*
**/.env
**/.env.*
deploy/.env*
secrets/
backups/
*.sql
.git
.gitignore
node_modules
.next
*.md
docker-compose*.yml
Dockerfile
.vscode
.claude
tests
__tests__
```

Do NOT exclude `tsconfig.json` in Next.js apps that use `@/*` path aliases — the build breaks.

### Resource Hardening (P3)

```yaml
services:
  app:
    ulimits:
      nproc: { soft: 256, hard: 512 }
      nofile: { soft: 65536, hard: 65536 }
    stop_grace_period: 30s
  db:
    shm_size: "256m"
    stop_grace_period: 60s
```

---

## Output Format

### 1. Host + Fleet Overview

```markdown
## Host runtime (read live)
| Component | Version | Floor | Status |
| Engine / BuildKit / runc / Compose / containerd | … | … | OK / BEHIND |

## Fleet Security Summary
(N = stacks discovered this run — show the live denominator, never a hard-coded one)

| Metric                     | Count | Target |
| -------------------------- | ----- | ------ |
| Total stacks audited       | X     | N      |
| P0 / P1 / P2 / P3          | X     | 0/0/<5/- |
| Stacks with non-root       | X/N   | N/N    |
| Stacks with health checks  | X/N   | N/N    |
| Stacks with resource limits| X/N   | N/N    |
| Stacks with pids limit     | X/N   | N/N    |
| Stacks with read_only      | X/N   | N/N    |
| Stacks with valid digest pins | X/N | N/N   |
| Stacks with .dockerignore  | X/N   | N/N    |
| Scanner: 0 HIGH/CRIT       | X/N   | N/N    |
```

### 2. Per-Stack Security Matrix

```markdown
| Stack     | Image Pin | Non-Root | Health | Limits | Pids | ReadOnly | Network  | Secrets | Stages | .dignore | Grade |
| --------- | --------- | -------- | ------ | ------ | ---- | -------- | -------- | ------- | ------ | -------- | ----- |
| app-one   | Y         | Y        | Y      | Y      | Y    | Y        | isolated | env     | 4      | Y        | A     |
```

**Grading:** A = all checks pass · B = 1-2 P2/P3 · C = 1+ P1 · D = any P0.

### 3. Issues by Severity

```markdown
## P0 - Critical (Fix Immediately)
### [Issue title]
- **Stack:** [name] · **File:** `[path:line]` · **Evidence:** `[quoted line]`
- **Issue / Risk / Fix:** … (copy-paste fix block)
## P1 - High … ## P2 - Medium … ## P3 - Low …
## Accepted / not re-flagged (from config)
```

### 4. Port / Subnet Conflict Report

```markdown
| Conflict | Stacks | Port / Subnet | Impact | Status |
| -------- | ------ | ------------- | ------ | ------ |
```

### 5. Baseline Comparison

```markdown
## Progress Since Last Audit
| Metric | Previous | Current | Delta |
| P0 / P1 / P2 / P3 | … | … | … |
| Average grade | … | … | … |
```

---

## Audit Execution Steps

1. **List stacks:** discover compose files by content across `$ROOTS`; apply `exclude`.
2. **Host quick-checks** + **subnet sweep** (3b) + **`docker ps -a` reconciliation** if the daemon is up.
3. **For each stack:** read compose + overlays, every Dockerfile, every `.dockerignore`, `.env` vs `.env.example` (no values echoed); score all 14 categories.
4. **Shared infrastructure:** gateways, vector DBs, poolers, shared caches, GPU services, monitoring, socket proxies.
5. **Pin-yank + registry currency** for every distinct image string (pace Hub lookups).
6. **Dependency currency** (Cat 11) on every Node/Python root — measure, don't sample.
7. **Aggregate** by severity; remediation plan with copy-paste fixes; **rebuild + verify in-image** before calling anything fixed; `docker compose config -q` on every edited compose file.
8. **Write the report** to `reports/YYYY-MM-DD-docker-security-audit.md`.
9. **Compare to baseline** (previous report + `accepted_risks`).
10. **Scanner run if available:** Trivy/Grype/Scout over every image.

---

## Common Mistakes

| Mistake | Fix |
| --- | --- |
| `image: node:latest` / `postgres:16` / `redis:7-alpine` | Pin patch + digest; copy digests from `docker buildx imagetools inspect`, never hand-type |
| `postgres:16.x-alpine3.NN` pinned (later yanked → 404) | Bare `-alpine` suffix + digest survives Alpine-base churn |
| "Version X does not exist" written as a rule | Registry 404 is point-in-time — re-query every run |
| Health check with `localhost` / `curl` | `wget -qO- http://127.0.0.1:PORT/api/health` (Alpine: localhost→IPv6, no curl) |
| Root containers | `USER nextjs` (1001/1001, group `nodejs`); Python `appuser` |
| Bare `depends_on: [db]` | `depends_on: db: condition: service_healthy` |
| `pids_limit:` at service level AND `deploy.resources.limits.pids` | Keep one — the spec requires consistency |
| `${VAR:-default}` for a credential | `${VAR:?error}` fail-fast; `:-` only for non-secret toggles |
| Bare `.env` in `.dockerignore` assumed to cover `deploy/.env` | Patterns match the whole relative path — add `**/.env*`, `deploy/.env*`, `secrets/`, `backups/`, `*.sql` |
| `npm install` in Dockerfile; `npm ci \|\| npm install` fallback | `npm ci` only, lock file committed |
| `cap_add: [CHOWN,SETGID,SETUID]` on nginx running `USER nginx` | Remove — a non-root master cannot switch users; the caps grant privilege for nothing |
| `cap_add: DAC_OVERRIDE` for docker.sock | `group_add: ["0"]` + socket proxy; `:ro` on the socket is NOT a boundary |
| External network recreated from a stale doc | Read the live range with `docker network inspect` first |
| `profiles:` + `restart: unless-stopped` | Profiles gate START only — use `restart: "no"` on profile-gated services |
| `npm audit fix` offering a MAJOR downgrade for a nested advisory | `overrides` entry verified at runtime; after `--omit=dev` re-run `npm install --include=dev` |
| Treating a prior audit's severity / an in-file "hold" comment as evidence | Re-derive: funded? reachable? still true on the registry? |
| Top-level `version:` in compose | Obsolete — Compose warns; drop it |
| Tag-pin only on stateful shared services | DB / vector DB / pooler / gateway base also `@sha256` |
| SBOM / provenance / Cosign flagged as gaps on a local-only deployment | Not a finding |
| Vector DB unauthenticated / on `0.0.0.0` | API key `${:?}` + 127.0.0.1 (`0.0.0.0` = P1) |
| Qdrant CVE-2026-25628 "fixed in v1.15.6" | Wrong — fixed in **v1.16.0** |
| Triaging by CVSS alone | KEV + EPSS; PURL-based scanners |
| Installing Trivy without checking the release | Trivy v0.69.4 binary + v0.69.5/v0.69.6 Docker Hub images and most `trivy-action` tags were malicious in March 2026 ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23), CVE-2026-33634). Use a verified release, checksum-verify, pin Actions by SHA |
| Bumping a Dockerfile and calling it fixed | Rebuild, then `docker compose up -d` (not `docker start`), then verify in-image |

---

## Known Gotchas

| Gotcha | Detail |
| --- | --- |
| Alpine `localhost` resolves to IPv6 | All health checks use `127.0.0.1` |
| Alpine has `wget`, not `curl` | `wget -qO- http://127.0.0.1:PORT/api/health` |
| bcrypt `$` characters in env vars | Never pass through a shell — pipe via stdin from a script |
| `docker exec -f /tmp/file` on Windows / Git Bash | Path gets mangled — set `MSYS_NO_PATHCONV=1` or pipe content via stdin |
| DB/cache need selective `cap_add` | `cap_drop: ALL`, add back only what is needed |
| nginx tmpfs needs `uid=101,gid=101` | otherwise the nginx user can't write; and no `cap_add` under `USER nginx` |
| `.env` leak via Next.js standalone | `next build` copies `.env` into `.next/standalone/` — `RUN rm -f .env` AND delete host-side artifact copies (backup tools mirror them) |
| `.dockerignore` root-anchoring | bare `.env` does NOT match `deploy/.env` |
| `container_name` is global | `COMPOSE_PROJECT_NAME` does not protect it — forks must rename every `container_name` |
| `profiles:` gates START only | `unless-stopped` on a profile-gated service comes back on every boot |
| Bind mounts override `read_only: true` | re-check every new service |
| Pinned `-alpineX.YY` tags get yanked | use bare `-alpine` + digest |
| Two base families of the same runtime | `-alpine` AND `-bookworm-slim` — bump both, verify `node -v` in-image |
| Compose files not named `docker-compose*` | discover by content (`^services:`) |
| `rg` skips dotfiles + ignored paths | filesystem-driven sweeps (`find`), then grep |
| Two audit sessions, one tree | attribute by file mtime or VCS diff |
| LLM audit agents over-report "missing/broken" | quote file evidence before any fix |
| `npm audit fix --omit=dev` prunes devDeps | re-run `npm install --include=dev` |
| `docker start` reuses the old container | only `docker compose up -d` adopts a rebuilt image |
| `docker.sock:ro` is NOT a security boundary | full API = host root — proxy it |
| `environment:` credentials are inspect-readable | Compose `secrets:` pattern (Cat 13) |
| `*_HOST=0.0.0.0` env vars | in-container listen address, not a host publish |
| Windows Hyper-V reserved port ranges | can swallow any host port — `netsh` excluded ranges |
| Host-native inference server | containers reach it via `host.docker.internal:<port>`; `localhost` inside a container is the container |

---

## Quick Diagnostic Commands

```bash
ROOTS="apps infra shared"   # from audit.config.yml

# === Host quick-checks (run FIRST) ===
docker version --format '{{.Server.Version}}'            # >= 29.7.0
docker buildx inspect --bootstrap | grep -i buildkit      # daemon >= 0.31.2
docker compose version                                    # >= 2.40.2
docker info | grep -i runc                                # >= 1.3.3
docker info | grep -iE "(seccomp|apparmor)"               # default seccomp (+ AppArmor on native Linux)

# === Discovery (by content, filesystem-driven) ===
find $ROOTS \( -name '*.yml' -o -name '*.yaml' \) -not -path '*/node_modules/*' -not -path '*/.next/*' | xargs grep -l '^services:' | sort
find $ROOTS \( -name '*.yml' -o -name '*.yaml' -o -name 'Dockerfile*' \) -not -path '*/node_modules/*' -not -path '*/.next/*' \
  | xargs grep -hoE '(image: |FROM )[a-z0-9./_-]+:[A-Za-z0-9._-]+' | sed 's/^\(image: \|FROM \)//' | sort | uniq -c | sort -rn   # distinct image strings
find $ROOTS \( -name '*.yml' -o -name '*.yaml' \) -not -path '*/node_modules/*' -not -path '*/.next/*' \
  | xargs grep -Hn 'subnet:' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort | uniq -c | sort -rn                      # subnet collisions
grep -rnE '^\s*-\s*"?(0\.0\.0\.0:|[0-9]+:[0-9]+"?\s*$)' --include='*.yml' --include='*.yaml' $ROOTS | grep -v '/.next/'      # non-loopback publishes
grep -rn 'localhost' --include='*.yml' --include='*.yaml' $ROOTS | grep -iE 'test:|healthcheck'                                  # must be empty
find $ROOTS -name 'Dockerfile*' -not -path '*/node_modules/*' -exec dirname {} \; | sort -u | while read d; do [ -f "$d/.dockerignore" ] || echo "MISSING .dockerignore: $d"; done

# === Live daemon reconciliation (only when Docker is up) ===
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
docker ps --format "{{.Names}}" | xargs -I {} docker inspect {} --format "{{.Name}}: privileged={{.HostConfig.Privileged}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} pids={{.HostConfig.PidsLimit}} capdrop={{.HostConfig.CapDrop}} capadd={{.HostConfig.CapAdd}} secopt={{.HostConfig.SecurityOpt}}"
docker ps --format "{{.Names}}\t{{.Ports}}" | grep "0.0.0.0"                              # should be empty
docker network ls --format '{{.Name}}' | xargs -I {} docker network inspect {} --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
docker ps --format "{{.Names}}" | xargs -I {} sh -c 'docker inspect {} --format "{{.Name}}: {{range .Mounts}}{{.Source}} {{end}}" | grep -q docker.sock && echo "{} mounts docker.sock"'
docker inspect <gateway-container> --format '{{json .Mounts}}' | jq '.[] | select(.Destination | test("seed|cred")) | {Source,RW}'   # RW must be false
docker inspect <gateway-container> --format '{{json .Config.Env}}' | jq '.[] | select(test("API_KEY|SECRET|TOKEN"))'                  # review; prefer file mounts

# === Verify inside a built image (step 3c) ===
docker run --rm --entrypoint node   <image> -v
docker run --rm --entrypoint python <image> -V
docker run --rm --entrypoint nginx  <image> -v
docker inspect <image> --format '{{.Config.User}}'                                      # must be non-empty and non-root
docker run --rm --entrypoint sh <image> -c 'ls -d /app/.env /app/secrets 2>/dev/null'   # must be empty
docker run --rm --entrypoint postgres <wrapper-image> --version                          # bundled base version (wrapper images)

# === Registry ===
curl -s -o /dev/null -w "%{http_code}\n" https://hub.docker.com/v2/repositories/library/postgres/tags/<tag>   # 200 ok / 404 yanked
docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'

# === Scanners ===
trivy image --severity HIGH,CRITICAL <image>     # pin Trivy itself by digest / verified release
docker scout cves --only-severity critical,high <image>
grype <image>

# === Secrets hygiene ===
grep -rnE '\$\{[A-Z_]+:-' --include='*.yml' --include='*.yaml' $ROOTS | grep -vE "$(echo LLM_PROVIDER LLM_GATEWAY_URL LLM_MODEL | tr ' ' '|')"   # weak defaults (exclude config toggles)
grep -rnE "(JWT_SECRET|DB_PASSWORD|REDIS_PASSWORD|API_KEY)" --include='*.yml' $ROOTS | grep -v "_FILE"   # env-based secrets (Cat 13 candidates)
find $ROOTS -path '*/.next/standalone/*' \( -name '.env*' -o -name 'secrets' \) 2>/dev/null           # must be empty
grep -rnE '^\s*ENV\s+[A-Z_]*(KEY|SECRET|PASSWORD|TOKEN)' --include='Dockerfile*' $ROOTS                 # baked secrets
```

---

## Supply-chain incidents an auditor should know (2026)

Digest pinning (Cat 12) is the defence against all of these *at pull time*.

- **AsyncAPI — npm OIDC provenance is NOT proof of integrity.** Compromised release pipelines shipped an obfuscated dropper that fires **on library load, not on install**, with **valid** npm provenance (the attacker gained push access and let the real CI publish). Provenance attests *where* a build ran, not that the source was trustworthy.
- **Jscrambler npm compromise** — versions published with stolen credentials carrying hidden native binaries that harvest credentials, cloud keys, wallets **and AI coding-assistant files** on dev workstations / CI.
- **"Hades" campaign on PyPI** — Shai-Hulud lineage; packages using **Python startup hooks** (interpreter-start execution, not install time). Relevant to Python images.
- **npm blocking install scripts by default** kills the classic mechanism, but load-time / interpreter-start execution already bypasses it. Plan the upgrade; don't treat it as a fix.
- **Shai-Hulud / "Miasma" npm worm** — self-propagating `preinstall` worm sweeping Docker registry creds, cloud tokens, SSH/GPG keys and `.env` files, then attempting container escape. Any Node image built during the window may have run it — never put registry creds or `.env` in a build context; `npm ci` against a reviewed lock; scan built images.
- **Trivy (Aqua) Docker Hub compromise** — poisoned `aquasec/trivy` 0.69.4/.5/.6, `:latest` pointed at the worst. Pin the scanner by digest.
- **Checkmarx/KICS Docker Hub compromise** + **XZ backdoor still present in some Debian images** — pin public bases by digest, scan after pull.

## Historical pinned-base CVE notes (useful floors, as of 2026-10)

Re-check each vendor page before grading; these floors move.

- **postgres 16.14:** CVE-2026-6638 SQLi via table name in `REFRESH PUBLICATION`, -6637 `refint` stack overflow + SQLi, -6478 MD5 password disclosure via timing, -6477 `libpq` `lo_*` client-stack overwrite, -6475 `pg_basebackup`/`pg_rewind` file overwrite, -6474 `timeofday()` memory disclosure. **postgres 16.15:** 25 CVEs that apply to 16.x (28 across all branches) incl. CVE-2026-19385 `pg_dump` heap overflow → RCE (CVSS 8.8). Flag anything ≤ 16.14.
- **pgvector:** CVE-2026-3172 buffer overflow in parallel HNSW index builds (fixed 0.8.2); also check the bundled Postgres minor in-image. Optional per DB after bump: `ALTER EXTENSION vector UPDATE;`.
- **Qdrant:** CVE-2026-25628 (CVSS 8.8) `/logger` file write, affected 1.9.3 → < **1.16.0** (v1.15.6 was NOT a fix).
- **Ollama:** CVE-2026-7482 unauthenticated GGUF heap read (CVSS 9.1), fixed ≥ 0.17.1; Ollama for Windows auto-updater CVE-2026-42248 (no signature check) / -42249 (path traversal), both CVSS 9.8, affected 0.12.10-0.17.5 — compare the host version with the release notes.
- **nginx:** floor **1.30.6** on the stable line (later 2026 advisories need 1.30.5 / 1.30.6 — see [nginx.org security advisories](https://nginx.org/en/security_advisories.html)). 1.30.4 fixed CVE-2026-42533 buffer overflow with `map` + regex, CVE-2026-60005 `ngx_http_slice_module` memory disclosure, CVE-2026-56434 `ngx_http_ssi_module` UAF; 1.30.3 fixed CVE-2026-42055 proxy_v2/grpc heap overflow and CVE-2026-48142 charset overread; 1.30.1 fixed CVE-2026-42945 (rewrite module overflow, ≤ 1.30.0). Stay on the stable line.
- **caddy 2.11.x:** CVE-2026-30851 `forward_auth copy_headers` header injection (2.10.0-2.11.1, fixed 2.11.2) — unreachable without `forward_auth`; currency only.
- **Node 24.x:** CVE-2026-48933 WebCrypto remote crash, CVE-2026-48618 TLS wildcard auth bypass, CVE-2026-48615 proxy credential leak via `ERR_PROXY_TUNNEL`; later CVE-2026-56846 / -56848 (HTTP/2 retained headers, heap UAF) + CVE-2026-58043 (Permission Model path matching). Note: an image tag can be pushed *before* the security release — check the build date vs the release.
- **Python 3.11.16 / 3.12.14:** CVE-2026-2297 (`SourcelessFileLoader` without `io.open_code()`), CVE-2026-4224 (unbounded C recursion in XML parsing), CVE-2026-3644 (control-char injection in `http.cookies`), `tarfile` symlink-traversal bypass.
- **redis 8.x:** CVE-2026-23479 / -25243 / -23631 / -25588 / -25589 (authenticated RCE paths); 8.10.1 security release: CVE-2026-62356 CMSketch RDB heap OOB write, RDB `SLOT_INFO` out-of-range → RCE, TLS client-cert CN NUL-byte auth bypass. Severity is P2 rather than P1 when Redis is password-protected and loopback-only.
- **Grafana 11.4.5:** CVE-2025-4123 (exploited in the wild — path traversal + open redirect → stored XSS / SSRF with image renderer). Promtail is deprecated upstream → `grafana/alloy`.
- **vLLM:** CVE-2026-22778 (critical RCE via malicious video link) — ≥ 0.14.1.
- **MCP ecosystem:** dozens of CVEs across SDKs (command injection dominant); CVE-2026-33032 "MCPwn" (nginx-ui MCP, CVSS 9.8) exploited in the wild. Audit every MCP server for network exposure + auth, version-lock them, and disable any server whose instructions attempt to override the agent's tools or rules.
