#!/usr/bin/env python3
"""Find phantom (undeclared) npm imports — READ-ONLY.

An import that resolves only because another package hoisted it is a latent build break: it stays
invisible until that other package moves (e.g. removing an unused devDependency breaks the
production build because a component imported its transitive directly).

Usage:  python undeclared-imports.py <app-dir> [<app-dir> ...]
Exit:   0 = clean, 1 = findings.

Correctness rules:
  * each source file is resolved to its NEAREST package.json (sub-packages like worker/ have their own)
  * specifiers are validated against npm naming rules (a loose regex also matches `${query}` and prose)
  * generated/vendored trees are skipped
  * only matches at an import position (import ... from, import(), require(), export ... from)
  * comments are stripped first (JSDoc `import('x')` type refs are not imports)
  * Node builtins, `node:` specifiers, path aliases (@/, ~/, #) and relative paths are ignored
"""
import json
import os
import re
import sys

SKIP_DIRS = {"node_modules", ".next", "dist", "build", "out", ".git", ".venv", "coverage",
             "generated", ".turbo", ".cache", "site-packages"}
EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto",
    "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
    "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "test",
}
NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
IMPORT_RE = re.compile(
    r"""(?:^|[;\s])(?:import\s+(?:type\s+)?(?:[\w*{}\s,$]+\s+from\s+)?|export\s+[\w*{}\s,$]+\s+from\s+)['"]([^'"]+)['"]"""
    r"""|(?:\bimport|\brequire)\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.M,
)
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"(^|[^:'\"\\])//.*$", re.M)


def pkg_name(spec):
    if spec.startswith((".", "/", "@/", "~/", "#", "node:", "virtual:", "data:", "http:", "https:")):
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    if name in BUILTINS or not NPM_NAME.match(name):
        return None
    return name


def nearest_pkg(path, root, cache):
    d = os.path.dirname(path)
    while True:
        if d in cache:
            return cache[d]
        pj = os.path.join(d, "package.json")
        if os.path.isfile(pj):
            try:
                data = json.load(open(pj, encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            declared = set()
            for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                declared |= set(data.get(k, {}) or {})
            declared.add(data.get("name", ""))
            cache[d] = (pj, declared)
            return cache[d]
        if os.path.abspath(d) == os.path.abspath(root) or os.path.dirname(d) == d:
            cache[d] = (None, set())
            return cache[d]
        d = os.path.dirname(d)


def scan(root):
    findings = []
    cache = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [x for x in dns if x not in SKIP_DIRS]
        for fn in fns:
            if not fn.endswith(EXTS) or fn.endswith(".d.ts"):
                continue
            p = os.path.join(dp, fn)
            try:
                src = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            src = LINE_COMMENT.sub(r"\1", BLOCK_COMMENT.sub("", src))
            pj, declared = nearest_pkg(p, root, cache)
            if pj is None:
                continue
            for m in IMPORT_RE.finditer(src):
                name = pkg_name(m.group(1) or m.group(2))
                if not name or name in declared:
                    continue
                # @types/x satisfies type-only imports of x
                if f"@types/{name.lstrip('@').replace('/', '__')}" in declared and "import type" in m.group(0):
                    continue
                findings.append((pj, name, p))
    return findings


def main(argv):
    roots = argv[1:] or ["."]
    seen = {}
    for r in roots:
        for pj, name, p in scan(r):
            seen.setdefault((pj, name), p)
    for (pj, name), p in sorted(seen.items()):
        print(f"UNDECLARED {name:30s} manifest={pj}  first-use={p}")
    print(f"{len(seen)} undeclared import(s)")
    return 1 if seen else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
