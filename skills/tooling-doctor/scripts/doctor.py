#!/usr/bin/env python3
"""tooling-doctor — mechanical health checks for a Claude Code tooling layer.

Audits .claude/ (and an optional .agents/ Codex mirror): skills, commands, rules,
docs, agents, hooks and settings.

Run from the repo root:  python .claude/skills/tooling-doctor/scripts/doctor.py
Options:
  --root <dir>      repo root (default: current directory)
  --config <file>   config JSON (default: doctor.config.json next to SKILL.md, if present)
  --json            machine-readable output
  --only <check>    run one check (see CHECKS keys)
  --quiet           hide P3 findings

Exit: 0 = no P0/P1, 1 = P0/P1 present, 2 = setup error.

Every finding is evidence-backed: file + line + the offending text. The skill text
must never restate a number this script can compute — compute it here.

Read-only by construction: this script never writes, moves or deletes anything.
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_CONFIG = {
    # Directories / files whose contents are historical records, not live instructions.
    "historical": ["skills-archive", "skills-disabled", "commands-archive", "history.md", "CHANGELOG.md"],
    # Repo-root prefixes a backticked path must start with to be checked for existence.
    "repo_prefixes": ["scripts/", "apps/", ".claude/", ".agents/", "docs/", "packages/",
                      "operations/", "shared/", "archive/", "infrastructure/", "deploy/", "src/"],
    # Third-party skill bundles vendored into the repo (checked for name collisions).
    "vendored_skill_dirs": [".claude/vendor/skills"],
    # Archived app directories: each one becomes a retired entity automatically.
    "archived_app_globs": ["archive/*archived-apps/*/"],
    # Prefix stripped to derive the short alias docs actually write ("myorg-billing" -> "billing").
    "app_prefix": "",
    # Short aliases that are ordinary words in your docs — only the full dir name is used for these.
    "generic_aliases": ["fleet", "video", "legal", "tax", "voice", "web", "auth", "api", "app", "core"],
    # Root instruction files swept by the retired check (the most-loaded files in the repo).
    "root_instruction_files": ["CLAUDE.md", "AGENTS.md"],
    # Port inventory doc and the compose files that are its source of truth.
    "ports_doc": ".claude/docs/ports.md",
    "compose_globs": ["apps/*/docker-compose.yml", "apps/*/compose.yml",
                      "operations/**/*.yml", "shared/**/*.yml"],
    # How a port is recognised in the ports doc: ':3000', '| 3000 |', '`3000`'.
    "port_claim_regex": r"(?:(?<=:)|(?<=\|\s)|(?<=,\s)|(?<=`))(\d{4,5})\b",
    "ignore_ports": [],
    # Inventory-count claims ("12 skills", "5 apps") are checked in these files.
    "count_targets": [".claude/TOOLING.md", "CLAUDE.md", ".claude/docs/*.md", ".claude/rules/*.md"],
    "apps_glob": "apps/*/",
    # Retired-entity list. Falls back to retired.example.json only if this is missing.
    "retired_file": "retired.json",
}

PLACEHOLDER = re.compile(r"YYYY|NNNN|MM-DD|0N|[{}<>\[\]]|\.\.\.|\bN\b")

findings: list[dict] = []
CFG: dict = {}
ROOT = CLAUDE = AGENTS = SELF = ""


def rel(path: str) -> str:
    """Repo-relative, forward-slashed — so findings are copy-pasteable."""
    try:
        return os.path.relpath(path, ROOT).replace(os.sep, "/")
    except ValueError:
        return path.replace(os.sep, "/")


def add(sev: str, check: str, msg: str, evidence: str = "") -> None:
    findings.append({"severity": sev, "check": check, "message": msg, "evidence": evidence})


def is_historical(path: str) -> bool:
    p = path.replace(os.sep, "/")
    return any(h in p for h in CFG["historical"])


def is_self(path: str) -> bool:
    """This skill must name retired things to check for them — exempt it from those checks."""
    return os.path.abspath(path).replace(os.sep, "/").startswith(SELF)


def walk_docs(*bases: str):
    """Yield every markdown/script/json file under the given bases, skipping .git."""
    for base in bases:
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
            for fn in filenames:
                if fn.endswith((".md", ".sh", ".js", ".mjs", ".cjs", ".py", ".json")):
                    yield os.path.join(dirpath, fn).replace(os.sep, "/")


def read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def frontmatter(text: str) -> dict:
    """Parse the top-level scalar keys of a YAML frontmatter block (incl. folded/literal scalars)."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    out, key, block = {}, None, []
    for line in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z_-]+):\s*(.*)$", line)
        if m:
            if key:                                   # close the previous block scalar
                out[key] = " ".join(block).strip()
                key, block = None, []
            name, val = m.group(1), m.group(2).strip()
            if val in (">", ">-", "|", "|-", "|+", ">+"):
                key = name                            # YAML folded/literal block follows
            else:
                out[name] = val.strip('"').strip("'")
        elif key and line.strip():
            block.append(line.strip())
    if key:
        out[key] = " ".join(block).strip()
    return out


def load_settings() -> dict:
    for candidate in ("settings.local.json", "settings.json"):
        p = os.path.join(CLAUDE, candidate)
        if os.path.isfile(p):
            try:
                return json.loads(read(p))
            except json.JSONDecodeError as exc:
                add("P1", "config", f".claude/{candidate} is not valid JSON", str(exc))
    return {}


def rglob(pattern: str) -> list[str]:
    return glob.glob(os.path.join(ROOT, pattern), recursive=True)


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #

def check_skill_frontmatter() -> str:
    skills = sorted(glob.glob(os.path.join(CLAUDE, "skills", "*", "")))
    bad = 0
    for d in skills:
        name = os.path.basename(d.rstrip(os.sep))
        sk = os.path.join(d, "SKILL.md")
        if not os.path.isfile(sk):
            add("P1", "frontmatter", f"skill '{name}' has no SKILL.md", rel(d))
            bad += 1
            continue
        fm = frontmatter(read(sk))
        if not fm.get("name"):
            add("P1", "frontmatter", f"skill '{name}': missing name:", rel(sk))
            bad += 1
        elif fm["name"] != name:
            add("P1", "frontmatter", f"skill '{name}': name: is '{fm['name']}' — must match the directory", rel(sk))
            bad += 1
        desc = fm.get("description", "")
        if not desc:
            add("P1", "frontmatter", f"skill '{name}': missing description: — it will never be surfaced", rel(sk))
            bad += 1
        elif len(desc) < 40:
            add("P2", "frontmatter", f"skill '{name}': description is {len(desc)} chars — too thin to trigger on",
                f"{rel(sk)}: {desc!r}")
            bad += 1
    return f"{len(skills)} skills scanned, {bad} frontmatter problems"


def check_skill_overrides() -> str:
    st = load_settings()
    ov = st.get("skillOverrides", {})
    if not ov:
        return "no skillOverrides block"
    local = {os.path.basename(p.rstrip(os.sep)) for p in glob.glob(os.path.join(CLAUDE, "skills", "*", ""))}
    parked = set()
    for sub in ("skills-archive", "skills-disabled"):
        parked |= {os.path.basename(p.rstrip(os.sep)) for p in glob.glob(os.path.join(CLAUDE, sub, "*", ""))}

    # An override also legitimately targets a skill or command that a PLUGIN provides, and
    # those live under ~/.claude/plugins/, not in this repo. Counting only local folders
    # makes installed plugin entries look like dead config; deleting them silently switches
    # those skills back ON. They are not dead — they are the only thing keeping them off.
    home_claude = os.path.join(os.path.expanduser("~"), ".claude")
    for pat in (os.path.join("**", "skills", "*", "SKILL.md"), os.path.join("**", "commands", "**", "*.md")):
        for f in glob.glob(os.path.join(home_claude, "plugins", pat), recursive=True):
            base = os.path.dirname(f) if f.endswith("SKILL.md") else f[:-3]
            parked.add(os.path.basename(base.rstrip(os.sep)))
    # Slash commands can be overridden by name too — project AND user-global. A command in a
    # subdirectory is namespaced with a colon: ~/.claude/commands/ns/analyze.md is "ns:analyze".
    for root in (CLAUDE, home_claude):
        cmd_root = os.path.join(root, "commands")
        for f in glob.glob(os.path.join(cmd_root, "**", "*.md"), recursive=True):
            parked.add(os.path.relpath(f, cmd_root).replace(os.sep, ":")[:-3])
            parked.add(os.path.splitext(os.path.basename(f))[0])
    # User-global skills, plus any user-global parking lot (dated archive folders included).
    for pat in ("skills", "skills-archive*", "skills-disabled*"):
        parked |= {os.path.basename(d.rstrip(os.sep)) for d in glob.glob(os.path.join(home_claude, pat, "*", ""))}

    dead, present_off = [], []
    for k, v in ov.items():
        if v != "off":
            continue
        if k in local:
            present_off.append(k)
        elif k not in parked:
            dead.append(k)
    if dead:
        add("P3", "config", f"{len(dead)} skillOverrides entries match no skill or command on disk "
                            "— local, plugin, or parked. Verify against an installed plugin before deleting: "
                            "an override is the only thing holding a plugin skill OFF", ", ".join(sorted(dead)))
    if present_off:
        add("P2", "config", f"{len(present_off)} skills live in .claude/skills/ but are forced off — "
                            "they still cost disk + drift, and the folder says 'active'", ", ".join(sorted(present_off)))
    return f"{len(ov)} overrides: {len(dead)} dead, {len(present_off)} present-but-off"


def check_name_collisions() -> str:
    cmds = {os.path.splitext(os.path.basename(p))[0] for p in glob.glob(os.path.join(CLAUDE, "commands", "*.md"))}
    skills = {os.path.basename(p.rstrip(os.sep)) for p in glob.glob(os.path.join(CLAUDE, "skills", "*", ""))}
    clash = sorted(cmds & skills)
    for c in clash:
        add("P2", "collision", f"'{c}' exists as BOTH a command and a skill — one of them is shadowed",
            f".claude/commands/{c}.md  vs  .claude/skills/{c}/")
    for vdir in CFG["vendored_skill_dirs"]:
        vendored = os.path.join(ROOT, vdir)
        if os.path.isdir(vendored):
            vnames = {os.path.basename(p.rstrip(os.sep)) for p in glob.glob(os.path.join(vendored, "*", ""))}
            vclash = sorted(vnames & skills)
            if vclash:
                add("P3", "collision", f"{len(vclash)} vendored skill names in {vdir} collide with live skills",
                    ", ".join(vclash))
    return f"{len(clash)} command/skill collisions"


def check_agents_mirror() -> str:
    if not os.path.isdir(os.path.join(AGENTS, "skills")):
        return "no .agents/skills — mirror not in use"
    cl = {os.path.basename(p.rstrip(os.sep)) for p in glob.glob(os.path.join(CLAUDE, "skills", "*", ""))}
    ag = {os.path.basename(p.rstrip(os.sep)) for p in glob.glob(os.path.join(AGENTS, "skills", "*", ""))}
    orphan = sorted(ag - cl)
    drift = []
    for name in sorted(cl & ag):
        a = os.path.join(CLAUDE, "skills", name)
        b = os.path.join(AGENTS, "skills", name)
        for dirpath, dirnames, filenames in os.walk(a):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
            for fn in filenames:
                if ".local" in fn:
                    continue  # local-only data (patterns, keys) is deliberately not mirrored
                pa = os.path.join(dirpath, fn)
                pb = pa.replace(a, b, 1)
                if not os.path.isfile(pb) or read(pa) != read(pb):
                    drift.append(f"{name}/{os.path.relpath(pa, a).replace(os.sep, '/')}")
    if orphan:
        add("P2", "mirror", f"{len(orphan)} skills exist only in .agents/ (deleted from .claude/?)", ", ".join(orphan))
    if drift:
        add("P1", "mirror", f"{len(drift)} mirrored files differ between .claude/ and .agents/ — "
                            "Codex and Claude are running different instructions", "; ".join(drift[:12]))
    unmirrored = sorted(cl - ag)
    if unmirrored:
        add("P3", "mirror", f"{len(unmirrored)} .claude skills have no .agents mirror "
                            "(fine if Claude-only — confirm intent)", ", ".join(unmirrored))
    return f"{len(cl & ag)} mirrored, {len(drift)} drifted, {len(orphan)} orphaned, {len(unmirrored)} unmirrored"


def check_broken_paths() -> str:
    pat = re.compile(r"`([A-Za-z0-9_./*-]+)`")
    # A path a doc names in order to FORBID it is not a dead reference — it is the warning
    # working ("never deploy from apps/old-site-export/"). Same idea as the retired caveat.
    gone = re.compile(r"retir\w*|dead|deleted|deletion|removed|archived|disabled|deprecat|binned|"
                      r"killed|dropped|purged|stale|gone|gitignored|gitignore|dockerignore|"
                      r"no longer|not exist|does ?n.t exist|never existed|missing|"
                      r"do NOT|don.t use|never use|ignore it|was |used to|created at runtime|"
                      r"creates?|generated|written by|scratch|temp file", re.I)
    prefixes = tuple(CFG["repo_prefixes"])
    miss = defaultdict(set)
    for p in walk_docs(CLAUDE, AGENTS):
        if is_historical(p) or is_self(p):
            continue
        here = os.path.dirname(p)
        body = read(p)
        excused = set()
        for line in body.splitlines():
            if gone.search(line):
                excused.update(pat.findall(line))
        for m in set(pat.findall(body)):
            if not m.startswith(prefixes) or PLACEHOLDER.search(m):
                continue
            if glob.glob(os.path.join(ROOT, m)) or os.path.exists(os.path.join(ROOT, m)):
                continue
            local = os.path.join(here, m)          # a skill citing its own scripts/ dir
            if glob.glob(local) or os.path.exists(local):
                continue
            if m in excused:
                continue
            miss[p].add(m)
    total = sum(len(v) for v in miss.values())
    for p in sorted(miss):
        add("P2", "broken-path", f"{len(miss[p])} repo-root paths referenced here do not exist",
            f"{rel(p)}: " + ", ".join(sorted(miss[p])))
    return f"{total} broken repo-root path refs across {len(miss)} live files"


def load_retired() -> list[dict] | None:
    for name in (CFG["retired_file"], "retired.example.json"):
        path = name if os.path.isabs(name) else os.path.join(SKILL_DIR, name)
        if os.path.isfile(path):
            try:
                ents = json.loads(read(path))["entities"]
            except (json.JSONDecodeError, KeyError, TypeError):
                add("P1", "retired", f"{os.path.basename(path)} is malformed — the retirement sweep cannot run", path)
                return None
            if name == "retired.example.json":
                add("P3", "retired", "using retired.example.json (fictional entries) — "
                                     "copy it to retired.json and list YOUR retired things", rel(path))
            return list(ents)
    add("P2", "retired", "no retired.json — the retirement sweep has nothing to check against",
        os.path.join(SKILL_DIR, "retired.json"))
    return None


def check_retired_entities() -> str:
    """Flag live instruction files that mention a retired thing with no retirement caveat."""
    entities = load_retired()
    if entities is None:
        return "SKIPPED"

    # Archived apps are derived from disk, not hand-listed, so this half never goes stale.
    # Docs rarely write the archive directory name — they write the short app name — so
    # derive that alias too. Short names that are ordinary words would drown the check in
    # noise, so only their full directory name is used.
    generic = {g.lower() for g in CFG["generic_aliases"]}
    prefix = CFG["app_prefix"]
    for g in CFG["archived_app_globs"]:
        for d in glob.glob(os.path.join(ROOT, g)):
            if not os.path.isdir(d):
                continue
            name = os.path.basename(d.rstrip(os.sep).rstrip("/"))
            entities.append({"pattern": re.escape(name), "why": "archived app"})
            short = name[len(prefix):] if prefix and name.startswith(prefix) else name
            if short != name and short.lower() not in generic:
                entities.append({"pattern": r"\b" + re.escape(short) + r"\b", "why": "archived app"})

    ack = re.compile(r"retir\w*|dead|deleted|removed|archived|disabled|deprecat|binned|killed|dropped|"
                     r"no longer|do NOT|don't use|never use|cancell?ed|decommission\w*|supersed\w+|"
                     r"replaces the old|\bgone\b|\binert\b", re.I)
    hits = 0
    roots = [os.path.join(ROOT, q) for q in CFG["root_instruction_files"] if os.path.isfile(os.path.join(ROOT, q))]
    for p in list(walk_docs(CLAUDE, AGENTS)) + roots:
        if is_historical(p) or is_self(p) or ".local" in os.path.basename(p):
            continue   # *.local* = local-only data (scan patterns, keys), not instructions
        text = read(p)
        if not text:
            continue
        body = text.splitlines()
        for ent in entities:
            rx = re.compile(ent["pattern"], re.I)
            lines = [(i + 1, ln) for i, ln in enumerate(body) if rx.search(ln)]
            if not lines:
                continue
            # A GOVERNING caveat is a line that says *this thing* is retired: the entity name
            # and a retirement word within 60 characters of each other. One anywhere in the
            # file clears every mention — a doc with a proper banner may then use the name
            # freely in its tables. Proximity keeps it precise: a line naming entity A and,
            # 150 characters later, saying entity B was "removed" does not govern A.
            governing = False
            for ln in body:
                for em in rx.finditer(ln):
                    lo, hi = max(0, em.start() - 60), em.end() + 60
                    if ack.search(ln[lo:hi]):
                        governing = True
                        break
                if governing:
                    break

            def covered(n: int) -> bool:
                # Otherwise a caveat clears a mention when it is on the line, within 3 lines
                # either side, or in the nearest preceding heading ('### Disabled' covers a list).
                if governing:
                    return True
                if any(ack.search(c) for c in body[max(0, n - 4):n + 3]):
                    return True
                for j in range(n - 1, -1, -1):
                    if re.match(r"^#{1,6}\s", body[j]):
                        return bool(ack.search(body[j]))
                return False

            # Judge EVERY mention, not the file as a whole: clearing the entity as soon as one
            # mention is caveated hides a live-looking table a few lines away.
            uncovered = [(n, ln) for n, ln in lines if not covered(n)]
            if not uncovered:
                continue
            hits += 1
            n, first = uncovered[0]
            add("P1", "retired", f"{rel(p)} mentions '{ent['pattern']}' ({ent.get('why', 'retired')}) "
                                 f"{len(uncovered)}x with no retirement caveat (of {len(lines)} mention(s) in the file)",
                f"{rel(p)}:{n}: {first.strip()[:140]}")
    return f"{hits} files carry un-caveated references to retired things"


def check_skill_size() -> str:
    over = []
    for sk in sorted(glob.glob(os.path.join(CLAUDE, "skills", "*", "SKILL.md"))):
        name = os.path.basename(os.path.dirname(sk))
        words = len(read(sk).split())
        sidecars = [f for f in os.listdir(os.path.dirname(sk)) if f != "SKILL.md"]
        if words > 2500:
            sev = "P2" if words > 4000 else "P3"
            add(sev, "size", f"skill '{name}' SKILL.md is {words} words — it loads in full on every trigger; "
                             f"move detail to a sidecar ({len(sidecars)} present)", rel(sk))
            over.append(name)
    return f"{len(over)} SKILL.md files over the 2500-word context budget"


# Frontmatter keys Claude Code reads (code.claude.com/docs/en/skills). Anything else is
# silently ignored — e.g. an `args:` key never produces an autocomplete hint; the
# supported key is `argument-hint:`. Commands accept the same set except name and paths.
# When Anthropic adds a key, add it here — otherwise every use of it is a false P2.
SKILL_KEYS = {
    "name", "description", "when_to_use", "argument-hint", "arguments",
    "disable-model-invocation", "user-invocable", "allowed-tools", "disallowed-tools",
    "model", "effort", "context", "agent", "background", "hooks", "paths", "shell",
    "metadata", "license", "compatibility", "version",
}
COMMAND_KEYS = SKILL_KEYS - {"name", "paths"}
# Agent Skills spec (platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices):
# name <= 64 chars of [a-z0-9-], no reserved words; description non-empty, <= 1024 chars,
# no XML tags. Claude Code truncates description + when_to_use at 1536 chars in the listing.
NAME_MAX, DESC_MAX, LISTING_MAX, BODY_LINES_MAX = 64, 1024, 1536, 500
WHEN_CUE = re.compile(
    r"\buse(s|d)? (it |this |them )?(when|for|at|whenever|after|before|as|on|if|to|with)\b|"
    r"\bwhen (the )?(user|you|asked|working)\b|\btrigger|\bif the user\b|"
    r"\bwhenever\b|\bsays?\b|\binvoke\b|\bfor \"", re.I)
XML_TAG = re.compile(r"<[A-Za-z/][^>]*>")


def check_spec() -> str:
    """Frontmatter against the published Agent Skills / Claude Code spec.

    `frontmatter` answers "will it load at all"; this answers "does it meet the spec" —
    limits the API enforces and Claude Code truncates at.
    """
    probs = 0
    targets = [(p, "skill") for p in sorted(glob.glob(os.path.join(CLAUDE, "skills", "*", "SKILL.md")))]
    targets += [(p, "command") for p in sorted(glob.glob(os.path.join(CLAUDE, "commands", "*.md")))]
    for path, kind in targets:
        text = read(path)
        fm = frontmatter(text)
        if not fm:
            continue
        r = rel(path)
        allowed = SKILL_KEYS if kind == "skill" else COMMAND_KEYS
        unknown = sorted(k for k in fm if k not in allowed)
        if unknown:
            probs += 1
            hint = " (use argument-hint:)" if "args" in unknown else ""
            add("P2", "spec", f"{r}: frontmatter key(s) Claude Code does not read — silently ignored{hint}",
                ", ".join(unknown))
        name, desc = fm.get("name", ""), fm.get("description", "")
        if kind == "skill" and name:
            if len(name) > NAME_MAX or not re.fullmatch(r"[a-z0-9-]+", name) or re.search(r"anthropic|claude", name):
                probs += 1
                add("P2", "spec", f"{r}: name '{name}' breaks the spec — <= {NAME_MAX} chars, "
                                  "lowercase letters/digits/hyphens, no 'anthropic'/'claude'", name)
        if not desc:
            continue
        if len(desc) > DESC_MAX:
            probs += 1
            add("P2", "spec", f"{r}: description is {len(desc)} chars — spec maximum is {DESC_MAX}", desc[:120] + "…")
        listing = len(desc) + len(fm.get("when_to_use", ""))
        if listing > LISTING_MAX:
            probs += 1
            add("P2", "spec", f"{r}: description + when_to_use = {listing} chars — the skill listing "
                              f"truncates at {LISTING_MAX}, so the tail triggers never reach Claude", "")
        if XML_TAG.search(desc) or XML_TAG.search(name):
            probs += 1
            # P3: Claude Code loads it fine; the API / claude.ai upload rejects it.
            add("P3", "spec", f"{r}: XML-tag-shaped text in name/description — the spec forbids it "
                              "(API/claude.ai upload rejects it); write placeholders as [x]",
                XML_TAG.search(desc + " " + name).group(0))
        if re.match(r"\s*(I|I'm|I can|You can|You)\b", desc):
            probs += 1
            add("P3", "spec", f"{r}: description is not third person — it is injected into the "
                              "system prompt, and point-of-view drift hurts discovery", desc[:80])
        if not WHEN_CUE.search(desc):
            probs += 1
            sev = "P2" if kind == "skill" else "P3"   # skills are picked by description alone
            add(sev, "spec", f"{r}: description says what, never WHEN — add 'Use when …' + trigger phrases", desc[:120])
        if kind == "skill":
            body = text[text.find("\n---", 3) + 4:] if text.startswith("---") else text
            n = len(body.strip("\n").splitlines())
            if n > BODY_LINES_MAX:
                probs += 1
                add("P3", "spec", f"{r}: SKILL.md body is {n} lines — the guidance is < {BODY_LINES_MAX}; "
                                  "split into a one-level-deep sidecar", "")
    return f"{len(targets)} skills+commands checked against the spec, {probs} problems"


def bound_ports() -> dict[str, list[str]]:
    """Host ports that compose files actually bind, keyed by app/stack label."""
    files = set()
    for g in CFG["compose_globs"]:
        files |= {f for f in rglob(g) if os.path.isfile(f)}
    rx = re.compile(r"""["']?(?:127\.0\.0\.1|0\.0\.0\.0|\[::1\])?:?(\d{2,5}):\d{2,5}(?:/(?:tcp|udp))?["']?\s*$""")
    actual: dict[str, list[str]] = {}
    for cf in sorted(files):
        ports = set()
        for line in read(cf).splitlines():
            s = line.strip().lstrip("-").strip()
            m = rx.match(s)
            if m:
                ports.add(m.group(1))
        if not ports:
            continue
        label = rel(cf)
        parts = label.split("/")
        if len(parts) >= 3 and parts[0] == "apps":
            label = parts[1]
        actual[label] = sorted(set(actual.get(label, [])) | ports)
    return actual


def check_ports_doc() -> str:
    doc = os.path.join(ROOT, CFG["ports_doc"])
    if not os.path.isfile(doc):
        return f"no {CFG['ports_doc']} — skipped"
    actual = bound_ports()
    live = {p for v in actual.values() for p in v}
    text = read(doc)
    claimed = set(re.findall(CFG["port_claim_regex"], text))
    ignore = {str(p) for p in CFG["ignore_ports"]}
    ghost = sorted(p for p in claimed - live - ignore)
    missing = sorted(p for p in live - claimed - ignore)
    if ghost:
        add("P2", "ports", f"{CFG['ports_doc']} lists {len(ghost)} ports that no compose file binds", ", ".join(ghost))
    if missing:
        add("P2", "ports", f"{len(missing)} bound ports are absent from {CFG['ports_doc']}", ", ".join(missing))
    return f"{len(actual)} stacks bind ports; {len(ghost)} ghost, {len(missing)} missing in the ports doc"


def check_counts() -> str:
    """Any 'N skills/commands/rules/agents/docs/apps' claim in the tooling docs must match reality."""
    real = {
        "skills": len(glob.glob(os.path.join(CLAUDE, "skills", "*", ""))),
        "commands": len(glob.glob(os.path.join(CLAUDE, "commands", "*.md"))),
        "rules": len(glob.glob(os.path.join(CLAUDE, "rules", "*.md"))),
        "agents": len(glob.glob(os.path.join(CLAUDE, "agents", "*.md"))),
        "docs": len(glob.glob(os.path.join(CLAUDE, "docs", "*.md"))),
        "apps": len([d for d in rglob(CFG["apps_glob"]) if os.path.isdir(d)]),
    }
    rx = re.compile(r"\b(\d{1,3})\s+(skill|command|rule|agent|doc|app)s?\b", re.I)
    wrong = 0
    targets = set()
    for g in CFG["count_targets"]:
        targets |= set(rglob(g))
    for p in sorted(targets):
        if not os.path.isfile(p) or is_self(p):
            continue
        for i, line in enumerate(read(p).splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue   # a heading is a title, never an inventory claim
            for num, kind in rx.findall(line):
                key = kind.lower() + "s"
                if key in real and int(num) != real[key]:
                    wrong += 1
                    add("P2", "counts", f"{rel(p)}:{i} claims {num} {key}, actual is {real[key]}", line.strip()[:160])
    return f"actual {real}; {wrong} contradicting claims in docs"


def check_hooks() -> str:
    problems = 0
    seen = defaultdict(list)
    for label, path in (("project-local", os.path.join(CLAUDE, "settings.local.json")),
                        ("project-shared", os.path.join(CLAUDE, "settings.json")),
                        ("global", os.path.join(os.path.expanduser("~"), ".claude", "settings.json"))):
        if not os.path.isfile(path):
            continue
        try:
            data = json.loads(read(path))
        except json.JSONDecodeError:
            continue
        for event, entries in (data.get("hooks") or {}).items():
            for entry in entries:
                for h in entry.get("hooks", []):
                    cmd = h.get("command", "")
                    seen[event].append((label, cmd))
                    for tok in re.findall(r"[/A-Za-z0-9_.$@{}:~-]+\.(?:sh|cjs|mjs|js|ps1|py)", cmd):
                        cand = tok.replace("${CLAUDE_PROJECT_DIR}", ROOT).replace("$CLAUDE_PROJECT_DIR", ROOT)
                        cand = os.path.expanduser(cand)
                        cand = re.sub(r"^/([a-zA-Z])/", lambda m: m.group(1).upper() + ":/", cand)  # /c/... on Windows
                        if not os.path.isabs(cand):
                            cand = os.path.join(ROOT, cand)
                        if not os.path.isfile(cand):
                            problems += 1
                            add("P1", "hooks", f"{label} {event} hook points at a script that is not there",
                                f"{cmd} -> {cand}")
    for event, entries in seen.items():
        tails = defaultdict(list)
        for label, cmd in entries:
            # Strip quotes: the same hook is often bare in one file and quoted in another.
            tail = re.split(r"\s+", cmd.strip())[-1].strip("\"'")
            tails[os.path.basename(tail)].append(label)
        for tail, labels in tails.items():
            if len(labels) > 1:
                problems += 1
                add("P2", "hooks", f"{event} runs '{tail}' {len(labels)}x — registered in {', '.join(labels)}; "
                                   "it fires once per registration", f"{event}: {tail}")
    return f"{sum(len(v) for v in seen.values())} hooks registered, {problems} problems"


_GIT_OK = None


def _git_available() -> bool:
    """True only when the repo root is inside a real git work tree."""
    global _GIT_OK
    if _GIT_OK is None:
        try:
            _GIT_OK = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                                     capture_output=True, cwd=ROOT).returncode == 0
        except OSError:
            _GIT_OK = False
    return _GIT_OK


def _gitignore_matches(relpath: str) -> bool:
    """Minimal .gitignore evaluation for the no-git case: exact paths, globs, dir prefixes, negation."""
    gi = os.path.join(ROOT, ".gitignore")
    if not os.path.exists(gi):
        return False
    relpath = relpath.replace(os.sep, "/").lstrip("/")
    hit = False
    for line in read(gi).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = line[1:] if neg else line
        anchored = pat.startswith("/")
        pat = pat.strip("/")
        if "/" in pat or anchored:
            m = fnmatch.fnmatch(relpath, pat) or relpath.startswith(pat + "/")
        else:
            m = any(fnmatch.fnmatch(part, pat) for part in relpath.split("/"))
        if m:
            hit = not neg
    return hit


def check_secrets() -> str:
    """A file only counts as a credential store if its NAME says so and its BODY proves it.

    Filename alone is a false-positive machine: settings.local.json is config, and a doc
    about design tokens is not a token. Both gates must fire.
    """
    name_pat = re.compile(r"\.local$|\.local\.\w+$|-login\.|secrets?\.|credentials?\.|\.env", re.I)
    exempt = {"settings.local.json", "settings.json"}
    body_pat = re.compile(
        r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*\S|"           # KEY=value
        r"(?:api[_-]?key|secret|password|passwd|token|bearer)\s*[:=]\s*\S",
        re.I | re.M,
    )
    problems = flagged = 0
    for base in (CLAUDE, AGENTS):
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for fn in filenames:
                if fn in exempt or ".example" in fn or not name_pat.search(fn):
                    continue
                p = os.path.join(dirpath, fn).replace(os.sep, "/")
                if not body_pat.search(read(p)):
                    continue                                    # named like one, isn't one
                flagged += 1
                if _git_available():
                    ignored = subprocess.run(["git", "check-ignore", "-q", p], capture_output=True, cwd=ROOT).returncode == 0
                    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", p],
                                             capture_output=True, cwd=ROOT).returncode == 0
                else:
                    # No repo: nothing can be tracked, so the only question is whether
                    # .gitignore would protect the file once a repo exists.
                    ignored = _gitignore_matches(rel(p))
                    tracked = False
                if tracked or not ignored:
                    problems += 1
                    add("P0", "secrets", "credential file in the tooling tree is "
                                         f"{'TRACKED BY GIT' if tracked else 'NOT gitignored'}", rel(p))
                else:
                    add("P3", "secrets", "credential file present (protected) — confirm the service is "
                                         "still in use; a stale key is a liability", rel(p))
    return f"{flagged} real credential files, {problems} unprotected"


CHECKS = {
    "frontmatter": check_skill_frontmatter,
    "overrides": check_skill_overrides,
    "collisions": check_name_collisions,
    "mirror": check_agents_mirror,
    "paths": check_broken_paths,
    "retired": check_retired_entities,
    "size": check_skill_size,
    "spec": check_spec,
    "ports": check_ports_doc,
    "counts": check_counts,
    "hooks": check_hooks,
    "secrets": check_secrets,
}

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def _utf8_stdout() -> None:
    """Windows consoles default to cp1252 and crash on em-dashes/arrows."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cand = path or os.path.join(SKILL_DIR, "doctor.config.json")
    if os.path.isfile(cand):
        try:
            user = json.loads(read(cand))
        except json.JSONDecodeError as exc:
            print(f"ERROR: {cand} is not valid JSON: {exc}", file=sys.stderr)
            sys.exit(2)
        unknown = sorted(k for k in user if k not in DEFAULT_CONFIG and not k.startswith("_"))
        if unknown:
            print(f"WARNING: unknown config keys ignored: {', '.join(unknown)}", file=sys.stderr)
        cfg.update({k: v for k, v in user.items() if k in DEFAULT_CONFIG})
    elif path:
        print(f"ERROR: config file not found: {path}", file=sys.stderr)
        sys.exit(2)
    return cfg


def main() -> int:
    global CFG, ROOT, CLAUDE, AGENTS, SELF
    ap = argparse.ArgumentParser(description="Lint a Claude Code .claude/ tooling layer (read-only).")
    ap.add_argument("--root", default=os.getcwd(), help="repo root (default: cwd)")
    ap.add_argument("--config", help="config JSON (default: doctor.config.json next to SKILL.md)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--only", choices=sorted(CHECKS), help="run a single check")
    ap.add_argument("--quiet", action="store_true", help="hide P3 findings")
    args = ap.parse_args()
    _utf8_stdout()

    CFG = load_config(args.config)
    ROOT = os.path.abspath(args.root)
    CLAUDE = os.path.join(ROOT, ".claude")
    AGENTS = os.path.join(ROOT, ".agents")
    SELF = SKILL_DIR.replace(os.sep, "/")

    if not os.path.isdir(CLAUDE):
        print(f"ERROR: no .claude/ under {ROOT} — run from the repo root or pass --root.", file=sys.stderr)
        return 2

    summaries = {}
    for name, fn in CHECKS.items():
        if args.only and name != args.only:
            continue
        summaries[name] = fn()

    if args.json:
        print(json.dumps({"summaries": summaries, "findings": findings}, indent=2))
        return 1 if any(f["severity"] in ("P0", "P1") for f in findings) else 0

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["check"]))
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    print("=" * 72)
    print("TOOLING DOCTOR")
    print("=" * 72)
    for name, summary in summaries.items():
        print(f"  {name:<12} {summary}")
    print("-" * 72)
    print("  " + "  ".join(f"{s}={counts[s]}" for s in ("P0", "P1", "P2", "P3")))
    print("=" * 72)
    for f in findings:
        if args.quiet and f["severity"] == "P3":
            continue
        print(f"\n[{f['severity']}] {f['check']}: {f['message']}")
        if f["evidence"]:
            print(f"        {f['evidence'][:600]}")
    return 1 if counts["P0"] or counts["P1"] else 0


if __name__ == "__main__":
    sys.exit(main())
