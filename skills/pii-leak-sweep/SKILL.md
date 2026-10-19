---
name: pii-leak-sweep
description: Brute-force scans every sitemap URL of a live website (plus llms.txt and llms-full.txt) for a user-configured list of banned terms and real names, personal data (e-mails, phone numbers, street addresses, IDs), pricing copy, JSON-LD pricing schema leaks and localized-route language mismatches, and fails on any hard-rule hit. Use when auditing a public site for content or privacy regressions, for "sweep the site", "scan every page", "brute force scan", "are there leaks anywhere", "is my name still on the site", after a large content merge or rebrand, after an external audit, and before declaring a cleanup done.
---

# PII Leak Sweep

## Why this exists

Sampling audits (home page plus a few pages) miss leaks on the rare pages: legal pages,
whitepapers, FAQ JSON-LD, comparison panels, blog excerpts, AI-facing `llms-full.txt`.
A sampled audit that comes back clean is a false all-clear more often than not. This skill
fetches **every** sitemap URL and greps every live response body for every prohibited
pattern in one deterministic pass.

It scans the **live** site, not the source tree. A fix is not done until the re-sweep of the
deployed site passes.

## When to use

- After any large content merge, redesign, rebrand or pivot rollout
- Before declaring a banned-term / privacy cleanup complete
- After an external or LLM-generated audit — verify its claims and find what it missed
- As a routine monthly check on every public site you own

## When NOT to use

- Core Web Vitals / Lighthouse work
- Schema generation or tone/positioning review — the sweep matches keywords, not tone
- Broken-link checks — it records each URL's own status, not links on the page

## Setup (one-time)

1. `cp patterns.example.txt patterns.local.txt` in this directory.
2. Replace the fictional terms with your own. `patterns.local.*` is gitignored — the list of
   things you do not want public is itself sensitive. **Never commit it.**
3. Keep a backup of `patterns.local.txt` outside the repo. If it is lost, the sweep refuses to
   run (exit 2) rather than silently passing.

Sections (one `grep -E` regex per line, case-insensitive):

| Section | Contents | Gate |
|---|---|---|
| `[BANNED]` | identity, location, affiliation, company-ID, old-brand terms | hard fail |
| `[NAME]` | real name(s) behind a brand-only or pseudonymous site | hard fail (skipped on `NAME_EXEMPT_HOSTS`) |
| `[PII]` | exact known personal data: address, phone, personal e-mail, IBAN | hard fail |
| `[PRICING]` | extra sales/pricing copy for a site that must not show prices | review |
| `[SCHEMA]` | extra structured-data patterns | hard fail (unless `ALLOW_PRICING_SCHEMA=1`) |
| `[ALLOW]` | regexes; a matching hit is dropped (public contact address, etc.) | — |

Built-in patterns are always on: generic e-mail / international phone / street-address
detection (`PII_AUTO`), JSON-LD and microdata pricing (`Offer`, `AggregateOffer`,
`UnitPriceSpecification`, `price`, `priceCurrency`, `itemprop="price"`), and common pricing
copy (`€99/month`, `per seat`, `free trial`, `cancel anytime`).

## What it checks

| Category | Covers | Why it matters |
|---|---|---|
| `BANNED` | your banned-term list | must never appear on a public surface |
| `NAME` | the real name on brand-only sites | name-to-brand linkage is the hardest leak to undo |
| `PII` | your exact personal data | personal-information hard rule |
| `PII_AUTO` | any e-mail / phone / street address | finds data you forgot to list; review (or `STRICT_PII=1`) |
| `SCHEMA` | JSON-LD / microdata pricing | search engines extract prices from structured data even when the visible copy is clean — worse than a visible leak |
| `PRICING` | visible pricing / sales copy | contradicts a portfolio-only or no-pricing positioning |
| `LANG_MISMATCH` | `/de/` URL whose H1 reads English (whole-word heuristic; adapt for other locales) | wrong-language body on a localized route breaks hreflang and duplicates content |
| `HTTP` | every URL's status | non-200s are listed; `000`/`ERR` = never scanned |

## How to run

```bash
bash .claude/skills/pii-leak-sweep/sweep.sh example.com
bash .claude/skills/pii-leak-sweep/sweep.sh example.com docs.example.com
NAME_EXEMPT_HOSTS='^(www\.)?janedoe\.example$' bash .claude/skills/pii-leak-sweep/sweep.sh brand.example janedoe.example
```

Environment: `SWEEP_OUT_DIR` (default `./reports`, gitignored), `SWEEP_WORKERS` (8),
`SWEEP_TIMEOUT` (30 s), `SITEMAP_PATH` (`/sitemap.xml`), `PATTERNS_FILE`, `NAME_EXEMPT_HOSTS`,
`ALLOW_PRICING_SCHEMA=1`, `STRICT_PII=1`. No credentials are needed — the sweep is anonymous
GET requests only.

Output: `reports/pii_sweep_<timestamp>.tsv`, columns `URL  STATUS  CATEGORY  HIT`.

| Exit | Meaning |
|---|---|
| 0 | hard rules PASS, every URL fetched |
| 1 | BANNED / NAME / PII / SCHEMA (or strict PII_AUTO) hit, or a grep error |
| 2 | setup error — missing patterns file, invalid regex (validated **before** any fetch) |
| 3 | INCOMPLETE — some URLs never fetched (`000`/`ERR`). **Not a pass.** Re-run. |

What the sweeper does:

1. Validates every pattern line individually with `grep -E` — an invalid regex aborts with
   exit 2 and the file:line, instead of silently matching nothing. (A classic false PASS: a
   scrub tool replaced terms with `[REDACTED]`, which is a broken character range.)
2. Pulls `<loc>` URLs from `/sitemap.xml`; a `<sitemapindex>` is expanded one level into its
   child sitemaps (an unexpanded index silently shrinks the sweep to a handful of URLs).
   Falls back to `Sitemap:` lines in `robots.txt`.
3. Appends `llms.txt` + `llms-full.txt` per site — not in any sitemap, but fetched and quoted
   by AI crawlers. A bio or client list re-published there leaks while every page is clean.
4. Fetches each URL in parallel batches, following redirects, with 3 retries
   (`--retry-all-errors`: shared hosting resets some parallel TLS connections).
5. Greps each body for every category; one TSV row per unique hit per URL.
6. Prints a summary and gates the exit code.

## Interpreting the report

```bash
R=$(ls -t reports/pii_sweep_*.tsv | head -1)
awk -F'\t' '$3=="BANNED" || $3=="NAME" || $3=="PII"' "$R"     # must be empty
awk -F'\t' '$3=="SCHEMA"' "$R"                                # must be empty on no-pricing sites
awk -F'\t' '$3=="HTTP" && $4!="200"' "$R"                     # non-200s
awk -F'\t' '$3=="PII_AUTO" || $3=="PRICING"' "$R" | sort -t$'\t' -k4 | uniq -f3 -c   # review, grouped by hit
```

For each hard hit, quote the URL and the matched string in the report, then locate it in
source (`grep -rn "<hit>" <site-source>/`). The same leak usually exists in several files
(page body, JSON-LD block, OG/meta description, `llms-full.txt`, RSS feed).

## Known false positives

| Pattern | False-positive context | Action |
|---|---|---|
| `six-figure` | "a six-figure appliance" (describing a third party's cost) | leave |
| `per firewall per month` | a rate metric ("drift events per firewall per month") | leave |
| `free trial` | "free trial of [some unrelated tool]" | read context |
| `PII_AUTO` e-mail | the public contact address | add it to `[ALLOW]` |
| `PII_AUTO` phone | a version string or ID that happens to start with `+` | read context |
| `LANG_MISMATCH` | German H1 made only of loanwords ("Cloud-Exit: Zero Trust") | leave, or add a DE marker word |

A pricing hit is a real regression only when the sentence describes **your own** product's
price or directly compares prices.

## Feedback loop

fix in source → deploy through your normal process → **re-run the sweep on the live site** →
repeat until `Hard rules: PASS` with `Not fetched: 0`. A clean source-tree grep is not proof:
caches, stale deploy trees and generated files (feeds, sitemaps, `llms-full.txt`) leak
independently.

## Verify the verifier

Before trusting a first PASS on a new pattern file, plant a positive control: put one
`[BANNED]` term on a test page (or point the sweep at a page that legitimately contains one of
your patterns) and confirm the category fires. A sweep that has never been shown to catch a
real hit is not evidence of a clean site.

## Safety

- Read-only: GET requests only. It never edits, deploys or deletes anything.
- Keep reports out of version control — they quote the sensitive strings they found
  (`reports/` is gitignored).
