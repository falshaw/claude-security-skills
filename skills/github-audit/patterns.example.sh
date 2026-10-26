#!/usr/bin/env bash
# github-audit — match patterns TEMPLATE (fictional values).
#
# Copy to patterns.local.sh (gitignored) and replace every value with your own:
#   cp patterns.example.sh patterns.local.sh
#
# WHY A SEPARATE LOCAL FILE: if the real terms lived in SKILL.md / reference.md, a
# history-scrub (git filter-repo --replace-text) of those very terms would rewrite the
# scanner itself to "[REDACTED]" — and the scan loops would then search for
# "[REDACTED]" and report a false all-clear. Keep real terms ONLY in patterns.local.sh,
# and never commit or push that file.
#
# Source at run time:  source .claude/skills/github-audit/patterns.local.sh
# Every variable is a POSIX extended-regex alternation (use with grep -iE / git grep -iE / rg -i -e;
# in ripgrep -E is --encoding, not extended regex).

# --- Banned terms: anything that must never appear in a repo (context + identifiers) ---
BANNED='Exampleville|Fictional Holdings|FH-000000|ACME-REG-12345|example-old-company\.test|Northshire'

# --- High-signal UNAMBIGUOUS identifiers (the real P0 subset) ---
# Exclude common country/city words that legitimately appear as product content.
HIGH_SIGNAL='Exampleville|Fictional Holdings|FH-000000|ACME-REG-12345|example-old-company\.test'

# --- Terms to drop from BANNED hits (false-positive residue, e.g. an old brand name
#     that contains a banned substring). Leave empty if unused. ---
EXCLUDE='ExamplevilleAI'

# --- Self-identifying name variants ---
# A hit in a copyright footer you deliberately publish is expected; treat name hits
# as a finding only in bio / README / personal-doc context.
NAME='Jane Q\. Example|Jane Example|J\. Example'

# --- PII: phones, personal emails, street addresses ---
PII='jane\.example@|@janeexample|\+00 ?555 ?0100|Sample Street 42|\+000[0-9 ]'

# --- Personal-life path / filename markers (drive repo classification) ---
# Avoid bare words that collide with code (HEALTH -> /api/health, LEGAL -> legal pages).
PERSONAL_PATHS='Evidence-|THERAPY|MEDICAL|DIARY|journal|witness|PERSONAL_CONTEXT|FINANCE|family/|cookies\.txt|salary|production-keys|secrets\.txt|Statements|Postman_Collection|test-password'

# --- Live secret prefixes (high-signal, low false-positive) ---
SECRETS='gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----'
