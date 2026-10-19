#!/usr/bin/env python3
"""Regenerate the app/port inventory block in the ports doc from the compose files.

A hand-maintained port list rots: it keeps ports nothing binds any more and misses new
ones. This writes the inventory between two markers; prose outside the markers is
preserved and stays hand-written.

    python .claude/skills/tooling-doctor/scripts/gen_ports.py [--root DIR] [--config FILE] [--check]

--check exits 1 if the block is stale, without writing.
Paths come from doctor.config.json (ports_doc, compose_globs, apps_glob).

This is the one script in the skill that writes, and only to the ports doc, atomically
(temp file + os.replace) — a crash mid-write leaves the original intact.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import os
import re
import sys

BEGIN = "<!-- BEGIN GENERATED: app-ports -->"
END = "<!-- END GENERATED: app-ports -->"
SUBNET = re.compile(r"subnet:\s*([0-9a-fA-F:./]+)")


def load_doctor():
    """Import doctor.py by path (works under `python -I`, which drops the script dir from sys.path)."""
    sys.dont_write_bytecode = True     # never leave a __pycache__ in the skill folder
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "doctor.py")
    spec = importlib.util.spec_from_file_location("tooling_doctor", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scan(doc) -> list[tuple[str, str, str]]:
    bound = doc.bound_ports()
    rows = []
    subnets = {}
    for g in doc.CFG["compose_globs"]:
        for cf in doc.rglob(g):
            if os.path.isfile(cf):
                m = SUBNET.search(doc.read(cf))
                label = doc.rel(cf)
                parts = label.split("/")
                if len(parts) >= 3 and parts[0] == "apps":
                    label = parts[1]
                if m:
                    subnets[label] = m.group(1)
    for label, ports in sorted(bound.items()):
        rows.append((label, ", ".join(ports), subnets.get(label, "—")))
    # An app dir with no compose file is still part of the inventory (CLI tools, desktop apps).
    for d in sorted(doc.rglob(doc.CFG["apps_glob"])):
        if not os.path.isdir(d):
            continue
        app = os.path.basename(d.rstrip(os.sep).rstrip("/"))
        has_compose = any(os.path.isfile(os.path.join(d, n)) for n in ("docker-compose.yml", "compose.yml"))
        if not has_compose and app not in bound:
            rows.append((app, "— (no compose stack)", "—"))
    return sorted(rows)


def block(rows: list[tuple[str, str, str]]) -> str:
    out = [
        BEGIN,
        "",
        "**GENERATED — do not hand-edit.** Rebuilt by "
        "`.claude/skills/tooling-doctor/scripts/gen_ports.py` from the compose files. "
        "Every host port below is one something actually binds.",
        "",
        f"**{len(rows)} entries.**",
        "",
        "| App / stack | Host ports | Subnet |",
        "| --- | --- | --- |",
    ]
    out += [f"| `{a}` | {p} | {s} |" for a, p, s in rows]
    out += ["", END]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Regenerate the port inventory block in the ports doc.")
    ap.add_argument("--root", default=os.getcwd())
    ap.add_argument("--config")
    ap.add_argument("--check", action="store_true", help="exit 1 if stale; do not write")
    args = ap.parse_args()

    doc = load_doctor()
    doc._utf8_stdout()
    doc.CFG = doc.load_config(args.config)
    doc.ROOT = os.path.abspath(args.root)
    target = os.path.join(doc.ROOT, doc.CFG["ports_doc"])
    if not os.path.isfile(target):
        print(f"{target} not found — create it (a '# Ports' heading is enough) or set ports_doc in the config")
        return 2

    text = doc.read(target)
    rows = scan(doc)
    fresh = block(rows)
    if BEGIN in text and END in text:
        start, stop = text.index(BEGIN), text.index(END) + len(END)
        merged = text[:start] + fresh + text[stop:]
    else:
        # First run: insert after the H1 so the generated inventory leads the document.
        lines = text.splitlines(keepends=True)
        cut = 1 if lines and lines[0].startswith("# ") else 0
        merged = "".join(lines[:cut]) + "\n" + fresh + "\n\n" + "".join(lines[cut:])

    if args.check:
        if merged == text:
            print("port inventory block is current")
            return 0
        print("port inventory block is stale — run without --check")
        return 1

    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(merged)
    os.replace(tmp, target)
    print(f"port inventory regenerated ({len(rows)} entries, {len(merged)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
