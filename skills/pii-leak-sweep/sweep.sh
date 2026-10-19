#!/usr/bin/env bash
# pii-leak-sweep: brute-force every sitemap URL (plus llms.txt / llms-full.txt) of one or
# more sites and grep each live response body for banned terms, PII, pricing copy,
# JSON-LD pricing schema and localized-route language mismatches.
#
# Usage:   bash sweep.sh SITE [SITE ...]
#          SITE = example.com | https://example.com | https://example.com/blog
#
# Patterns: patterns.local.txt next to this script (gitignored, user-supplied).
#           Copy patterns.example.txt -> patterns.local.txt and replace the fictional terms.
#           Override the location with PATTERNS_FILE=/path/to/file.
#
# Env:     SWEEP_OUT_DIR       report directory          (default: ./reports)
#          SWEEP_WORKERS       parallel fetches          (default: 8)
#          SWEEP_TIMEOUT       per-URL curl timeout, s   (default: 30)
#          SITEMAP_PATH        sitemap path on each site (default: /sitemap.xml)
#          NAME_EXEMPT_HOSTS   regex of hosts where the NAME category is NOT scanned
#                              (e.g. a personal site that shows the name by design)
#          ALLOW_PRICING_SCHEMA=1   demote SCHEMA from hard-fail to review
#          STRICT_PII=1             promote auto-detected PII (PII_AUTO) to hard-fail
#
# Exit:    0 = hard rules PASS
#          1 = BANNED / NAME / PII / SCHEMA hit (hard-rule violation)
#          2 = setup error (missing patterns file, empty or invalid regex) — checked
#              BEFORE any URL is fetched
#          3 = INCOMPLETE: some URLs were never fetched (000 / ERR) — NOT a pass
#
# Read-only: this script only issues GET requests. It never edits or deploys anything.

set -uo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: bash $0 SITE [SITE ...]   (e.g. bash $0 example.com)" >&2
  exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PATTERNS_FILE="${PATTERNS_FILE:-$HERE/patterns.local.txt}"
OUT_DIR="${SWEEP_OUT_DIR:-$PWD/reports}"
WORKERS="${SWEEP_WORKERS:-8}"
TIMEOUT="${SWEEP_TIMEOUT:-30}"
SITEMAP_PATH="${SITEMAP_PATH:-/sitemap.xml}"
NAME_EXEMPT_HOSTS="${NAME_EXEMPT_HOSTS:-}"

mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/pii_sweep_$(date +%Y%m%d_%H%M%S).tsv"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
echo -e "URL\tSTATUS\tCATEGORY\tHIT" > "$OUT"

# --------------------------------------------------------------------------- #
# Built-in patterns (always on; extend via patterns.local.txt)
# --------------------------------------------------------------------------- #
# Auto-detected PII. Contact addresses are normal on most sites, so these are a REVIEW
# category unless STRICT_PII=1. Silence known-good hits with [ALLOW] lines.
AUTO_PII_EMAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
AUTO_PII_PHONE='\+[0-9]{1,3}[ .-]?\(?[0-9]{1,4}\)?([ .-]?[0-9]{2,4}){2,4}'
AUTO_PII_ADDR='\b[0-9]{1,5}[ ]+[A-Z][a-z]+([ ][A-Z][a-z]+)*[ ]+(Street|St\.|Avenue|Ave\.|Road|Rd\.|Lane|Ln\.|Boulevard|Blvd\.?|Drive|Dr\.)|\b[A-Z][a-z]+(strasse|straße|str\.|weg|gasse|platz|allee)[ ]+[0-9]{1,4}[a-z]?\b'
AUTO_PII="${AUTO_PII_EMAIL}|${AUTO_PII_PHONE}|${AUTO_PII_ADDR}"

# JSON-LD / microdata pricing. Search engines extract prices from structured data even
# when the visible copy is clean, so a leak here is worse than one in the body.
AUTO_SCHEMA='"@type"[[:space:]]*:[[:space:]]*"(Offer|AggregateOffer|UnitPriceSpecification|PriceSpecification)"|"price(Currency)?"[[:space:]]*:[[:space:]]*"?[A-Z0-9]|itemprop="price(Currency)?"'

# Visible pricing / sales copy. Many false positives — always REVIEW, never hard-fail.
AUTO_PRICING='(€|\$|£)[ ]?[0-9][0-9,.]*[ ]*(/|per)[ ]*(month|mo|year|yr|user|seat|license)\b|\bfree trial\b|\bcancel anytime\b|\bmoney-back guarantee\b'

# Default allowlist: asset filenames that look like e-mail addresses (logo@2x.png).
AUTO_ALLOW='@[0-9]x\.(png|jpe?g|webp|avif|gif|svg)'

# --------------------------------------------------------------------------- #
# User patterns: patterns.local.txt
#   [BANNED]  terms that must never appear (hard fail)
#   [NAME]    real names / identities       (hard fail; skipped on NAME_EXEMPT_HOSTS)
#   [PII]     known personal data: addresses, phone numbers, IDs (hard fail)
#   [PRICING] extra pricing / sales copy    (review)
#   [SCHEMA]  extra structured-data leaks   (hard fail unless ALLOW_PRICING_SCHEMA=1)
#   [ALLOW]   regexes; a hit matching one is dropped (known-good contact address, etc.)
# One grep -E regex per line; '#' starts a comment line. Case-insensitive matching.
# --------------------------------------------------------------------------- #
if [[ ! -f "$PATTERNS_FILE" ]]; then
  echo "ERROR: patterns file not found: $PATTERNS_FILE" >&2
  echo "Copy patterns.example.txt to patterns.local.txt and fill in your own terms (SKILL.md -> Setup)." >&2
  exit 2
fi

declare -A SECTION=([BANNED]="" [NAME]="" [PII]="" [PRICING]="" [SCHEMA]="" [ALLOW]="")
current=""
lineno=0
while IFS= read -r raw || [[ -n "$raw" ]]; do
  ((lineno++))
  line="${raw%$'\r'}"
  [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
  if [[ "$line" =~ ^\[([A-Z_]+)\][[:space:]]*$ ]]; then
    current="${BASH_REMATCH[1]}"
    if [[ -z "${SECTION[$current]+x}" ]]; then
      echo "ERROR: $PATTERNS_FILE:$lineno unknown section [$current]" >&2
      exit 2
    fi
    continue
  fi
  if [[ -z "$current" ]]; then
    echo "ERROR: $PATTERNS_FILE:$lineno pattern outside a [SECTION]" >&2
    exit 2
  fi
  # Validate each regex on its own BEFORE fetching anything. grep exits 2 on an invalid
  # pattern; inside a scan loop that only reaches stderr and the summary would still
  # print PASS — a silent false-clean. (Classic cause: a privacy scrub replacing terms
  # with "[REDACTED]", which is a valid-looking but broken character range.)
  printf 'x\n' | grep -qiE -- "$line" 2>/dev/null
  if (( $? > 1 )); then
    echo "ERROR: $PATTERNS_FILE:$lineno is not a valid grep -E regex: $line" >&2
    exit 2
  fi
  if [[ -n "${SECTION[$current]}" ]]; then
    SECTION[$current]="${SECTION[$current]}|$line"
  else
    SECTION[$current]="$line"
  fi
done < "$PATTERNS_FILE"

if [[ -z "${SECTION[BANNED]}${SECTION[NAME]}${SECTION[PII]}" ]]; then
  echo "ERROR: $PATTERNS_FILE defines no [BANNED], [NAME] or [PII] patterns — the sweep would prove nothing." >&2
  exit 2
fi

PRICING_RX="$AUTO_PRICING${SECTION[PRICING]:+|${SECTION[PRICING]}}"
SCHEMA_RX="$AUTO_SCHEMA${SECTION[SCHEMA]:+|${SECTION[SCHEMA]}}"
ALLOW_RX="$AUTO_ALLOW${SECTION[ALLOW]:+|${SECTION[ALLOW]}}"
BANNED_RX="${SECTION[BANNED]}"
NAME_RX="${SECTION[NAME]}"
PII_RX="${SECTION[PII]}"

# Built-ins are validated too — a local grep without PCRE-ish class support must fail loudly.
for v in AUTO_PII PRICING_RX SCHEMA_RX ALLOW_RX; do
  printf 'x\n' | grep -qiE -- "${!v}" 2>/dev/null
  if (( $? > 1 )); then
    echo "ERROR: built-in pattern $v is not valid for this grep — use GNU grep" >&2
    exit 2
  fi
done
if [[ -n "$NAME_EXEMPT_HOSTS" ]]; then
  printf 'x\n' | grep -qE -- "$NAME_EXEMPT_HOSTS" 2>/dev/null
  (( $? > 1 )) && { echo "ERROR: NAME_EXEMPT_HOSTS is not a valid regex" >&2; exit 2; }
fi

# --------------------------------------------------------------------------- #
# Build the URL list
# --------------------------------------------------------------------------- #
URLS_FILE="$TMPDIR/urls.txt"
: > "$URLS_FILE"

locs() { sed 's|>|>\n|g' | grep -A1 '<loc>' | grep -oE 'https?://[^<[:space:]]+'; }

expand_sitemap() {   # $1 = sitemap URL; a <sitemapindex> is expanded one level
  local body
  body="$(curl -sSL --max-time "$TIMEOUT" --retry 3 --retry-delay 2 --retry-all-errors "$1" 2>/dev/null)"
  if grep -q '<sitemapindex' <<< "$body"; then
    # An unexpanded index silently shrinks the sweep to a handful of URLs.
    while IFS= read -r child; do
      echo "  child sitemap: $child" >&2
      curl -sSL --max-time "$TIMEOUT" --retry 3 --retry-delay 2 --retry-all-errors "$child" | locs >> "$URLS_FILE"
    done < <(locs <<< "$body")
  else
    locs <<< "$body" >> "$URLS_FILE"
  fi
}

BASES=()
for site in "$@"; do
  [[ "$site" =~ ^https?:// ]] || site="https://$site"
  base="$(grep -oE '^https?://[^/]+' <<< "$site")"
  BASES+=("$base")
  before=$(wc -l < "$URLS_FILE")
  echo "Fetching sitemap: ${base}${SITEMAP_PATH}" >&2
  expand_sitemap "${base}${SITEMAP_PATH}"
  if (( $(wc -l < "$URLS_FILE") == before )); then
    # Fall back to Sitemap: lines in robots.txt
    while IFS= read -r sm; do
      echo "  robots.txt sitemap: $sm" >&2
      expand_sitemap "$sm"
    done < <(curl -sSL --max-time "$TIMEOUT" "${base}/robots.txt" 2>/dev/null | tr -d '\r' \
             | grep -iE '^sitemap:' | sed -E 's/^[Ss]itemap:[[:space:]]*//')
  fi
  if (( $(wc -l < "$URLS_FILE") == before )); then
    echo "WARNING: no sitemap URLs found for $base — only the home page and llms files will be scanned" >&2
    echo "${base}/" >> "$URLS_FILE"
  fi
  # AI-facing files are not in any sitemap but are fetched and quoted by AI crawlers.
  # A bio or client list re-published there is a leak even when every page is clean.
  printf '%s/llms.txt\n%s/llms-full.txt\n' "$base" "$base" >> "$URLS_FILE"
done
sort -u -o "$URLS_FILE" "$URLS_FILE"
URL_COUNT=$(wc -l < "$URLS_FILE")
echo "Sweeping $URL_COUNT URLs across ${#BASES[@]} site(s) with $WORKERS workers..." >&2

# --------------------------------------------------------------------------- #
# Scan one URL
# --------------------------------------------------------------------------- #
scan() {
  local url="$1" file="$2" status
  # --retry-all-errors: shared hosting often resets some parallel TLS connections;
  # without retries those URLs come back 000 and are never scanned.
  status="$(curl -sS -o "$file" -w '%{http_code}' -L --max-time "$TIMEOUT" \
    --retry 3 --retry-delay 2 --retry-all-errors "$url" 2>/dev/null || echo "ERR")"
  echo -e "${url}\t${status}\tHTTP\t${status}" >> "$OUT"
  [[ "$status" == "200" ]] || return 0

  scan_cat() {   # $1 = category, $2 = regex; grep rc: 0 match, 1 none, 2 error
    local cat="$1" pattern="$2" out rc
    [[ -z "$pattern" ]] && return 0
    out="$(grep -oiE -- "$pattern" "$file")"
    rc=$?
    if (( rc > 1 )); then
      echo "ERROR: grep failed for $cat on $url (exit $rc)" >&2
      echo -e "${url}\t${status}\tGREP_ERROR\t${cat}" >> "$OUT"
      return 0
    fi
    [[ -z "$out" ]] && return 0
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      grep -qiE -- "$ALLOW_RX" <<< "$hit" && continue
      echo -e "${url}\t${status}\t${cat}\t${hit}" >> "$OUT"
    done < <(sort -u <<< "$out")
  }

  scan_cat BANNED   "$BANNED_RX"
  scan_cat PII      "$PII_RX"
  scan_cat PII_AUTO "$AUTO_PII"
  scan_cat SCHEMA   "$SCHEMA_RX"
  scan_cat PRICING  "$PRICING_RX"
  local host
  host="$(grep -oE '^https?://[^/]+' <<< "$url" | sed -E 's|^https?://||')"
  if [[ -z "$NAME_EXEMPT_HOSTS" ]] || ! grep -qE -- "$NAME_EXEMPT_HOSTS" <<< "$host"; then
    scan_cat NAME "$NAME_RX"
  fi

  # Localized-route mismatch: a /de/ URL whose H1 reads English. Serving the wrong
  # language on a localized route breaks hreflang and creates duplicate content.
  # Whole-word matching (-w) only: substring tests flag German H1s ("niemand hat"
  # contains "and"). Adapt the marker lists for other locales.
  if [[ "$url" =~ /de(/|$) ]]; then
    local h1
    h1="$(grep -oE '<h1[^>]*>[^<]+' "$file" 2>/dev/null | head -1 | sed 's/<[^>]*>//g')"
    if [[ -n "$h1" ]] \
       && ! grep -qE 'ä|ö|ü|ß|sche|ung' <<< "$h1" \
       && ! grep -qiwE 'für|mit|der|die|das|und|ist|hat|nicht|ein|eine|wie|warum|wer|alle' <<< "$h1" \
       && grep -qiwE 'the|for|and|of|with|how|why|is' <<< "$h1"; then
      echo -e "${url}\t${status}\tLANG_MISMATCH\t${h1}" >> "$OUT"
    fi
  fi
}

i=0
while IFS= read -r url; do
  ((i++))
  scan "$url" "$TMPDIR/page_${i}.html" &
  if (( i % WORKERS == 0 )); then wait; fi
done < "$URLS_FILE"
wait

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
count() { awk -F'\t' -v c="$1" '$3==c' "$OUT" | wc -l | tr -d ' '; }
banned=$(count BANNED); name=$(count NAME); pii=$(count PII); pii_auto=$(count PII_AUTO)
schema=$(count SCHEMA); pricing=$(count PRICING); lang=$(count LANG_MISMATCH); grep_err=$(count GREP_ERROR)
non200=$(awk -F'\t' '$3=="HTTP" && $4!="200"' "$OUT" | wc -l | tr -d ' ')
# Never fetched (000 / ERR) = never scanned. A 404 is an answer; a connection failure
# is a hole in the sweep and must not read as PASS.
unscanned=$(awk -F'\t' '$3=="HTTP" && ($4 ~ /^000/ || $4 ~ /ERR/)' "$OUT" | wc -l | tr -d ' ')

hard_schema=$schema; schema_note="(must be 0)"
if [[ "${ALLOW_PRICING_SCHEMA:-0}" == "1" ]]; then hard_schema=0; schema_note="(review — ALLOW_PRICING_SCHEMA=1)"; fi
hard_pii_auto=0; pii_auto_note="(review — contact addresses are often fine)"
if [[ "${STRICT_PII:-0}" == "1" ]]; then hard_pii_auto=$pii_auto; pii_auto_note="(must be 0 — STRICT_PII=1)"; fi

echo ""
echo "=== Sweep complete ==="
echo "Report: $OUT"
echo ""
echo "URLs listed:      $URL_COUNT"
echo "Non-200:          $non200"
echo "Not fetched:      $unscanned   (must be 0 — else the sweep is INCOMPLETE)"
echo "Grep errors:      $grep_err   (must be 0)"
echo "Banned terms:     $banned   (must be 0)"
echo "Real name:        $name   (must be 0)"
echo "PII (configured): $pii   (must be 0)"
echo "PII (auto):       $pii_auto   $pii_auto_note"
echo "Schema pricing:   $schema   $schema_note"
echo "Pricing copy:     $pricing   (review for false positives)"
echo "Lang mismatch:    $lang   (review)"
echo ""
if (( banned + name + pii + hard_schema + hard_pii_auto + grep_err > 0 )); then
  echo "FAIL — hard-rule violations present"
  exit 1
fi
if (( unscanned > 0 )); then
  echo "INCOMPLETE — $unscanned URL(s) never fetched, so not scanned. Re-run before calling it clean:"
  awk -F'\t' '$3=="HTTP" && ($4 ~ /^000/ || $4 ~ /ERR/){print "  " $1}' "$OUT"
  exit 3
fi
echo "Hard rules: PASS"
exit 0
