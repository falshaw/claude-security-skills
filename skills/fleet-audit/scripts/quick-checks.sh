#!/usr/bin/env bash
# fleet-audit quick diagnostic checks — READ-ONLY.
#
#   bash skills/fleet-audit/scripts/quick-checks.sh [--config fleet.config.json] [--no-net] [--root <repo-root>]
#
# It never installs, builds, restarts, writes into app dirs, or pushes anything.
# Inputs come from the config file (see fleet.config.example.json) and these env vars:
#   APPS_DIR            override config apps_dir           (default: apps)
#   SHARED_DIRS         space-separated extra compose dirs (default: from config, else none)
#   NEXT_FLOOR          Next.js vendor security floor, e.g. 16.4.1 (default: config floors.next; 0.0.0 = off)
#   PYTHON              python interpreter                  (default: python3, then python)
# No secrets are read or needed. Every path walk excludes build output:
#   node_modules, .next, .venv, site-packages, dist, .git
# (generated trees carry their own Dockerfiles/old base images and produce phantom findings).

set -u
NET=1; CONFIG=""; ROOT="."
while [ $# -gt 0 ]; do
  case "$1" in
    --no-net) NET=0 ;;
    --config) CONFIG="$2"; shift ;;
    --root)   ROOT="$2"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done
cd "$ROOT" || exit 2
[ -z "$CONFIG" ] && [ -f fleet.config.json ] && CONFIG=fleet.config.json

PY="${PYTHON:-}"
if [ -z "$PY" ]; then command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python; fi
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cfg() {  # cfg <dotted.key.path> <default>   (plain key lookup — no code evaluation)
  if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
    "$PY" - "$CONFIG" "$1" "$2" <<'PY'
import json, sys
v = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print(sys.argv[3] if v in (None, "", []) else (" ".join(v) if isinstance(v, list) else v))
PY
  else
    echo "$2"
  fi
}

APPS_DIR="${APPS_DIR:-$(cfg apps_dir apps)}"
SHARED_DIRS="${SHARED_DIRS:-$(cfg shared_compose_dirs '')}"
NEXT_FLOOR="${NEXT_FLOOR:-$(cfg floors.next 0.0.0)}"
EXCLUDES="$(cfg exclude_dirs 'archive')"
export APPS_DIR NEXT_FLOOR EXCLUDES CONFIG

SCAN_DIRS="$APPS_DIR"; for d in $SHARED_DIRS; do [ -d "$d" ] && SCAN_DIRS="$SCAN_DIRS $d"; done
PRUNE=(-not -path '*/node_modules/*' -not -path '*/.next/*' -not -path '*/.venv/*' -not -path '*/site-packages/*' -not -path '*/dist/*' -not -path '*/.git/*')

hdr() { printf '\n=== %s ===\n' "$1"; }
app_dirs() {
  for d in "$APPS_DIR"/*/; do
    b="$(basename "$d")"; skip=0
    for e in $EXCLUDES; do [ "$b" = "$e" ] && skip=1; done
    [ "$skip" = 0 ] && echo "${d%/}"
  done
}

hdr "Cat 0 - live roster (diff against the config / last report EVERY run; an unlisted dir is a full-audit target until proven otherwise)"
app_dirs | while read -r d; do
  [ -f "$d/docker-compose.yml" ] || [ -f "$d/compose.yml" ] && echo "compose:    $(basename "$d")" || echo "NO compose: $(basename "$d")"
done
if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
  "$PY" - <<'PY'
import json, os
c = json.load(open(os.environ["CONFIG"], encoding="utf-8"))
listed = {os.path.basename(a["path"].rstrip("/")) for a in c.get("apps", [])}
ex = set(os.environ["EXCLUDES"].split())
live = {d for d in os.listdir(os.environ["APPS_DIR"]) if os.path.isdir(os.path.join(os.environ["APPS_DIR"], d)) and d not in ex and not d.startswith(".")}
for d in sorted(live - listed): print("NOT IN CONFIG (audit fully):", d)
for d in sorted(listed - live): print("IN CONFIG BUT MISSING ON DISK:", d)
PY
fi

hdr "Cat 0b - every compose file BY CONTENT (filename sweeps miss shared-*.yml recipes; overlays inherit hardening from their base - repin them, do not grade them as stacks)"
find $SCAN_DIRS \( -name '*.yml' -o -name '*.yaml' \) "${PRUNE[@]}" 2>/dev/null | xargs grep -ln '^services:' 2>/dev/null | sort

hdr "Cat 1/7 - declared vs RESOLVED versions (a range is not what is installed)"
"$PY" - <<'PY'
import json, glob, os
ad = os.environ["APPS_DIR"]
for f in sorted(glob.glob(os.path.join(ad, "*", "package.json"))):
    d = json.load(open(f, encoding="utf-8")); dep = {**d.get("devDependencies", {}), **d.get("dependencies", {})}
    lock = os.path.join(os.path.dirname(f), "package-lock.json"); p = {}
    if os.path.exists(lock):
        p = json.load(open(lock, encoding="utf-8")).get("packages", {})
    g = lambda k: p.get("node_modules/" + k, {}).get("version")
    row = []
    for k in ("next", "react", "@prisma/client", "typescript", "jose", "zod", "electron"):
        if k in dep or g(k):
            row.append(f"{k}={dep.get(k)}->{g(k)}")
    print(f"{os.path.basename(os.path.dirname(f)):28s} " + " ".join(row))
PY

hdr "Cat 7b - vendor security floor the advisory DBs may not carry yet (NEXT_FLOOR=$NEXT_FLOOR; 0.0.0 = disabled)"
"$PY" - <<'PY'
import json, glob, os, re
def t(v): return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:3])
floor = t(os.environ.get("NEXT_FLOOR", "0.0.0") or "0.0.0")
if floor == (0, 0, 0):
    print("skipped - set floors.next in the config from the vendor security page (e.g. gh api repos/vercel/next.js/security-advisories)")
else:
    for f in sorted(glob.glob(os.path.join(os.environ["APPS_DIR"], "*", "package-lock.json"))):
        v = json.load(open(f, encoding="utf-8")).get("packages", {}).get("node_modules/next", {}).get("version")
        if v and t(v) < floor:
            print(f"BELOW next {os.environ['NEXT_FLOOR']}: {os.path.basename(os.path.dirname(f))} ({v})")
PY
echo "next/og users (Node runtime unless runtime = \"edge\" is shown) - relevant when an advisory targets ImageResponse:"
grep -rl --include='*.ts' --include='*.tsx' "from ['\"]next/og['\"]" "$APPS_DIR" 2>/dev/null | grep -v node_modules | while read -r f; do
  echo "  $f $(grep -ho 'export const runtime *= *"[a-z]*"' "$f")"
done

hdr "Cat 2/10 - 0.0.0.0 HOST port bindings (only compose ports: entries publish; in-container binds are not exposure)"
grep -rn -B4 -E '^\s*-\s*"?0\.0\.0\.0:' --include='*.yml' --include='*.yaml' $SCAN_DIRS 2>/dev/null | grep -v node_modules
echo "ports: entries with NO host IP (publish on all interfaces):"
grep -rnE '^\s*-\s*"?[0-9]+:[0-9]+"?\s*$' --include='*.yml' --include='*.yaml' $SCAN_DIRS 2>/dev/null | grep -v node_modules

hdr "Cat 2 - external base images not digest-pinned (stage aliases excluded; expect 0)"
grep -rn '^\s*FROM ' --include='Dockerfile*' $SCAN_DIRS 2>/dev/null \
  | grep -v -e node_modules -e '\.next/' -e '\.venv' -e '/dist/' \
  | grep -v '@sha256:' \
  | grep -viE 'FROM (base|deps|builder|runner|installer|prod|production|dev|development|final|release|runtime)\b' \
  | grep -viE 'FROM \$\{?[A-Z_]+'
echo "compose image: lines without a digest (locally built images excepted):"
grep -rnE '^\s*image:\s*\S+' --include='*.yml' --include='*.yaml' $SCAN_DIRS 2>/dev/null \
  | grep -v -e node_modules -e '@sha256:' | grep -vE 'image:\s*[a-z0-9_-]+:(local|dev|latest-local)\b'

hdr "Cat 2/7 - image pin census (spot drift, :latest, two versions of the same image)"
grep -rhoE '(FROM|image:)\s+[^ ]+' --include='Dockerfile*' --include='*.yml' --include='*.yaml' $SCAN_DIRS 2>/dev/null \
  | grep -v node_modules | sed -E 's/^(FROM|image:)\s+//; s/@sha256.*//' | sort | uniq -c | sort -rn

hdr "Cat 2 - compose hardening presence per stack (base stacks only; overlays inherit)"
for d in $(app_dirs); do
  f=""; for n in docker-compose.yml compose.yml; do [ -f "$d/$n" ] && f="$d/$n"; done
  [ -z "$f" ] && continue
  miss=""
  grep -q 'no-new-privileges' "$f" || miss="$miss no-new-privileges"
  grep -qE 'cap_drop' "$f"        || miss="$miss cap_drop"
  grep -q 'read_only'  "$f"       || miss="$miss read_only"
  grep -q 'pids'       "$f"       || miss="$miss pids-limit"
  grep -q 'healthcheck' "$f"      || miss="$miss healthcheck"
  grep -q 'max-size'   "$f"       || miss="$miss log-rotation"
  grep -qE 'subnet:'   "$f"       || miss="$miss pinned-subnet"
  grep -nE '^\s*pids_limit:' "$f" >/dev/null && miss="$miss (service-level pids_limit: use deploy.resources.limits.pids)"
  [ -n "$miss" ] && echo "$(basename "$d"): missing$miss"
done
echo "secrets with a :- fallback (should be :? unless a non-secret toggle):"
grep -rnE '\$\{[A-Z_]*(SECRET|PASSWORD|TOKEN|KEY)[A-Z_]*:-' --include='*.yml' --include='*.yaml' $SCAN_DIRS 2>/dev/null | grep -v node_modules
echo "healthchecks using localhost (Alpine resolves to IPv6 - use 127.0.0.1):"
grep -rn 'localhost' --include='*.yml' --include='*.yaml' --include='Dockerfile*' $SCAN_DIRS 2>/dev/null | grep -iE 'health|wget|curl|urlopen' | grep -v node_modules

hdr "Cat 4 - Prisma 7: reintroduced db.ts / missing prisma.config.ts / PrismaClient without adapter"
ls "$APPS_DIR"/*/src/lib/db.ts 2>/dev/null
for d in $(app_dirs); do [ -d "$d/prisma" ] && [ ! -f "$d/prisma.config.ts" ] && echo "no prisma.config.ts: $d"; done
grep -rnE 'new PrismaClient\(\s*\)' --include='*.ts' $(app_dirs) 2>/dev/null | grep -v node_modules | grep -v '/generated/'

hdr "Cat 5/12 - LLM provider defaults + host-service wiring (extra_hosts needed on Linux for host.docker.internal)"
grep -rnoE 'LLM_PROVIDER[:=] *\$\{LLM_PROVIDER:-[a-z_-]+\}' --include='*.yml' --include='*.yaml' $(app_dirs) 2>/dev/null
for d in $(app_dirs); do
  f=""; for n in docker-compose.yml compose.yml; do [ -f "$d/$n" ] && f="$d/$n"; done
  [ -z "$f" ] && continue
  if grep -q 'host.docker.internal' "$f" && ! grep -q 'host.docker.internal:host-gateway' "$f"; then
    echo "uses host.docker.internal WITHOUT extra_hosts host-gateway: $f"
  fi
done

if [ "$NET" = 1 ]; then
  hdr "Cat 7 - npm advisory posture per lockfile (lockfile-only; cannot see vendor-only advisories - see 7b)"
  find $(app_dirs) -name package-lock.json "${PRUNE[@]}" 2>/dev/null | while read -r l; do
    d="$(dirname "$l")"; echo "$d: $(cd "$d" && npm audit --package-lock-only 2>/dev/null | tail -2 | head -1)"
  done
  hdr "Cat 7 - Python pins against OSV (every == pin, never a curated subset)"
  "$PY" "$SCRIPT_DIR/osv-pins.py" $(app_dirs) || true
fi

hdr "Cat 7 - phantom (undeclared) imports (exit 1 from the scanner = findings)"
"$PY" "$SCRIPT_DIR/undeclared-imports.py" $(app_dirs) || true

hdr "Cat 3 - vendored auth core drift (only if configured)"
if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
  "$PY" - <<'PY'
import json, os
c = json.load(open(os.environ["CONFIG"], encoding="utf-8")).get("shared_auth_core")
if not c:
    print("not configured")
else:
    src = open(c["source"], encoding="utf-8").read().splitlines()
    skip = int(c.get("header_lines_ignored", 0))
    for app in sorted(os.listdir(os.environ["APPS_DIR"])):
        for rel in c.get("copies", []):
            p = os.path.join(os.environ["APPS_DIR"], app, rel)
            if os.path.exists(p):
                body = open(p, encoding="utf-8").read().splitlines()[skip:]
                print(("OK      " if body == src else "DRIFTED ") + p)
PY
fi
echo "auth libraries present (flag any not in your baseline):"
grep -lE '"(next-auth|@auth/core|better-auth|lucia)"' "$APPS_DIR"/*/package.json 2>/dev/null

hdr "Cat 6 - test presence (UNBOUNDED depth - tests live at src/__tests__, src/test, tests/, worker/tests)"
for d in $(app_dirs); do
  n=$(find "$d" \( -name '*.test.*' -o -name '*.spec.*' -o -name 'test_*.py' -o -name '*_test.py' \) "${PRUNE[@]}" 2>/dev/null | wc -l)
  echo "$(basename "$d"): $n test files"
done

hdr "Cat 9 - agent docs present (AGENTS.md or CLAUDE.md)"
for d in $(app_dirs); do [ -f "$d/AGENTS.md" ] || [ -f "$d/CLAUDE.md" ] || echo "missing AGENTS.md/CLAUDE.md: $(basename "$d")"; done

hdr "Cat 10 - .dockerignore at the REAL build context (compose context:, not the app root)"
"$PY" - <<'PY'
import re, pathlib, os
for cf in sorted(pathlib.Path(os.environ["APPS_DIR"]).glob("*/*compose*.y*ml")):
    txt = cf.read_text(encoding="utf-8", errors="ignore")
    for ctx in set(re.findall(r'^\s*context:\s*(\S+)', txt, re.M)):
        d = (cf.parent / ctx.strip('"\'')).resolve()
        if d.is_dir():
            di = d / ".dockerignore"
            if not di.exists():
                print("missing .dockerignore:", d)
            else:
                lines = [l.strip() for l in di.read_text(encoding="utf-8", errors="ignore").splitlines()]
                if not any(l.startswith(".env") for l in lines): print(".dockerignore does not exclude .env*:", di)
                if "tsconfig.json" in lines: print(".dockerignore EXCLUDES tsconfig.json (breaks @/* alias builds):", di)
PY
echo ".env files on disk that a build context could pick up (verify each is ignored):"
find $(app_dirs) -maxdepth 3 -name '.env' "${PRUNE[@]}" 2>/dev/null

if [ "$NET" = 1 ] && command -v docker >/dev/null 2>&1; then
  hdr "Runtime - running image == built image? (only stacks that are UP; never starts anything)"
  docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | while read -r name img; do
    run=$(docker inspect "$name" -f '{{.Image}}' 2>/dev/null); built=$(docker image inspect "$img" -f '{{.Id}}' 2>/dev/null)
    [ -n "$built" ] && [ "$run" != "$built" ] && echo "STALE: $name runs ${run:7:12}, tag $img is ${built:7:12} -> recreate"
  done
fi
exit 0
