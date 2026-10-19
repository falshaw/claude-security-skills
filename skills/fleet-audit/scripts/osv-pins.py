#!/usr/bin/env python3
"""Query OSV for EVERY `name==version` pin in requirements*.txt under the given dirs — READ-ONLY.

Usage:  python osv-pins.py <dir> [<dir> ...]
Prints only pins with advisories, plus the lowest fixed version OSV reports for each advisory.
Uses the public OSV API (https://api.osv.dev/v1/querybatch). No credentials needed.

Why every pin: a hand-picked list misses things. Why OSV and not articles: articles routinely
misquote affected ranges; OSV returns the advisory's own introduced/fixed events.
"""
import json
import os
import re
import sys
import urllib.request

SKIP = {"node_modules", ".venv", "site-packages", ".git", "dist"}
PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?==([^\s;#\\]+)")


def pins(roots):
    out = {}
    for r in roots:
        for dp, dns, fns in os.walk(r):
            dns[:] = [d for d in dns if d not in SKIP]
            for fn in fns:
                if fn.startswith("requirements") and fn.endswith((".txt", ".lock", ".in")):
                    p = os.path.join(dp, fn)
                    for line in open(p, encoding="utf-8", errors="ignore"):
                        m = PIN.match(line)
                        if m:
                            out.setdefault((m.group(1).lower(), m.group(2)), set()).add(p)
    return out


def main(argv):
    found = pins(argv[1:] or ["."])
    if not found:
        print("no == pins found")
        return 0
    keys = sorted(found)
    hits = 0
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body, headers={"Content-Type": "application/json"})
        try:
            res = json.load(urllib.request.urlopen(req, timeout=60))
        except Exception as e:  # network down -> report, do not guess
            print(f"OSV query failed: {e}")
            return 2
        for (n, v), r in zip(chunk, res.get("results", [])):
            vulns = r.get("vulns") or []
            if not vulns:
                continue
            hits += 1
            ids = []
            for vu in vulns:
                vid = vu["id"]
                try:
                    full = json.load(urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=30))
                    fixed = sorted({e["fixed"] for a in full.get("affected", []) for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e})
                except Exception:
                    fixed = []
                ids.append(f"{vid}(fixed:{','.join(fixed) or '?'})")
            print(f"{n}=={v}  {len(vulns)} advisories  {' '.join(ids)}")
            for p in sorted(found[(n, v)]):
                print(f"    in {p}")
    print(f"{hits} vulnerable pin(s) of {len(keys)}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
