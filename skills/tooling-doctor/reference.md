# tooling-doctor — reference

Per-check tuning, known false positives, configuration and lessons learned. Read this before
dismissing a finding as noise — and before adding a check.

## Contents

- Configuration
- Known false positives (`paths`, `retired`, `counts`, `secrets`, `overrides`, `ports`, `spec`)
- Check-by-check notes
- Design rules for this skill
- Lessons learned building the checker

## Configuration

`doctor.config.json` (next to `SKILL.md`, or `--config FILE`). Every key is optional.

| Key | Default | Meaning |
| --- | --- | --- |
| `historical` | `skills-archive`, `skills-disabled`, `commands-archive`, `history.md`, `CHANGELOG.md` | path fragments exempt from `paths`/`retired` |
| `repo_prefixes` | `scripts/`, `apps/`, `.claude/`, `docs/`, … | a backticked path is only existence-checked if it starts with one |
| `vendored_skill_dirs` | `.claude/vendor/skills` | third-party bundles checked for name collisions |
| `archived_app_globs` | `archive/*archived-apps/*/` | every matching dir becomes a retired entity |
| `app_prefix` | `""` | stripped to derive the short alias (`myorg-billing` → `billing`) |
| `generic_aliases` | `fleet`, `video`, `legal`, `tax`, … | short aliases that are ordinary words — not derived |
| `root_instruction_files` | `CLAUDE.md`, `AGENTS.md` | root files swept by `retired` |
| `ports_doc` | `.claude/docs/ports.md` | the port inventory doc |
| `compose_globs` | `apps/*/docker-compose.yml`, `operations/**/*.yml`, `shared/**/*.yml` | the source of truth for bound ports |
| `port_claim_regex` | `:3000`, `\| 3000`, `, 3000`, `` `3000` `` | how a port is recognised in the ports doc |
| `ignore_ports` | `[]` | ports to ignore in both directions (e.g. a documented upstream default) |
| `count_targets` | `.claude/TOOLING.md`, `CLAUDE.md`, `.claude/docs/*.md`, `.claude/rules/*.md` | files checked for inventory claims |
| `apps_glob` | `apps/*/` | what counts as an app for `counts` |
| `retired_file` | `retired.json` | the retired-entity list |

`retired.json` format:

```json
{ "entities": [ { "pattern": "regex, case-insensitive", "why": "one line: what died and what replaced it" } ] }
```

A retired row names **the thing that died** (the container, the server, the deleted tree), never the
category (the runtime). If a self-hosted model server moved from a container to the host, retire
`model-container`, not the model server's name — otherwise every correct mention of the live
replacement fires as P1.

## Known false positives

### `paths` — app-relative paths written without the app prefix

The single biggest source of noise. Skills for one app often write paths relative to that app:

| Written in the skill | Actually lives at |
| --- | --- |
| `scripts/import-statements.ts` | `apps/<name>/scripts/import-statements.ts` |
| `scripts/gen-icons.js` | `apps/<name>/scripts/gen-icons.js` |
| `scripts/generate.py` | `.claude/skills/<skill>/scripts/generate.py` (resolved automatically) |

Before "fixing" one, resolve it: `find . -name "$(basename PATH)" -not -path "*/node_modules/*"`.
If it exists elsewhere, the fix is to **qualify the path in the doc**, not to create the file. If it
exists nowhere, it is a genuine dead reference.

Paths relative to the citing file (a skill naming its own `scripts/`) are resolved automatically.
A path named on a line that also says it is gone / deleted / never to be used is excused — the
warning is working. Note the caveat vocabulary includes `missing`, so a path that itself contains
that word is always excused.

Other benign hits: user-agent strings that look like paths (`GPTBot/1.3`), glob templates, and
paths that point outside the repo by design.

### `retired` — a legitimate "do not use" warning

A rule that exists to stop anyone deploying from an old tree must name that tree. A mention is
cleared when the line itself, the 3 lines either side, or the nearest preceding heading carries a
caveat word (`retired`, `dead`, `deleted`, `removed`, `archived`, `disabled`, `deprecated`, `binned`,
`killed`, `dropped`, `no longer`, `do NOT`, `don't use`, `never use`, `cancelled`, `decommissioned`,
`superseded`, `gone`, `inert`). If a legitimate warning still trips the check, make the warning
explicit — do not widen the regex.

### `retired` — derived short names that are ordinary words

Archived apps each yield a short alias (prefix stripped), because docs write the short name. Short
names that are ordinary English words in your docs (`fleet`, `video`, `legal`, `tax`, `voice`,
`auth`, …) would produce nothing but noise, so list them in `generic_aliases`; only the full
directory name is matched for those.

`*.local*` files are skipped: they are gitignored **data** (scan patterns, keys), not instructions.

### `counts` — prose numbers that are not inventory claims

The regex matches `<number> <skills|commands|rules|agents|docs|apps>`. "3 apps failed the audit" is
not an inventory claim — read the quoted line before editing. Markdown headings are skipped
(`# Next.js 16 + React 19 Rules` is a title, not a claim about `.claude/rules/`).

### `secrets` — two gates, both must fire

Filename *and* body must look like credentials. `settings.local.json`, `settings.json` and any
`*.example*` file are exempt. A design-token doc is excluded because its body has no `KEY=value` or
`password:` pattern. If a real credential file has an unusual name, add the pattern to `name_pat`
rather than loosening the body gate.

**No-git mode.** If the repo root is not a git work tree, `git check-ignore` fails for every file and
would report each protected file as P0. The doctor detects the missing work tree once and falls back
to a minimal `.gitignore` evaluation (exact paths, globs, dir prefixes, `!` negation). "Tracked" is
impossible without a repo.

### `overrides` — check every scope before deleting

**Read this before deleting any override.** "Dead" means the name matches no skill or command on
disk, and that must be checked in several places: `.claude/skills/`, the parking lots,
`.claude/commands/`, `~/.claude/skills/`, `~/.claude/commands/` (user-global — `ns/analyze.md` is
the key `ns:analyze`) and `~/.claude/skills-archive*/`. Miss any of them and legitimate entries look
dead; deleting one switches a user-global skill back **on**. Plugin skills are not affected by
`skillOverrides` at all (manage them through `/plugin`), so an entry naming only a plugin skill is
dead config. Documented values: `on`, `name-only`, `user-invocable-only`, `off`
([code.claude.com/docs/en/skills](https://code.claude.com/docs/en/skills)).

### `ports` — shared services do not live in `apps/`

The bind scan covers every glob in `compose_globs`. Scanning `apps/` alone reports shared services
(a web UI, a vector DB, a monitoring stack under `operations/`) as ghosts while they are deployed.
Ports a doc mentions for an upstream default or a remote host belong in `ignore_ports`.

### `spec` — the "when" cue and placeholder brackets

The *what-but-never-when* rule looks for a trigger cue: `Use when/for/at/…`, `when the user …`,
`trigger`, `whenever`, `says`, `invoke`, or a quoted `for "…"`. A description that names its
triggers some other way can trip it — add a plain `Use when …` sentence rather than widening the
regex. **P2 for skills** (Claude picks a skill by its description alone), **P3 for commands**
(mostly typed by name).

`<site>` / `<app>` placeholders in a description are XML-tag-shaped. Claude Code loads them fine;
the API and the claude.ai upload validator reject any XML tag in `name`/`description`. That is why
it is P3 — write `[site]`.

## Check-by-check notes

**`frontmatter`** — `description:` is the *only* thing Claude reads when deciding whether to trigger
a skill. It must name the trigger phrases a user would actually type. Under 40 chars is treated as
unusable. `name:` must equal the directory name. YAML folded/literal block scalars
(`description: >-`) are parsed.

**`overrides`** — two ways to disable a skill behave the same at runtime but differently for humans:
moving the folder to `skills-disabled/` is visible on disk; `"name": "off"` in
`settings*.json` → `skillOverrides` is invisible unless you open the JSON. Pick one convention per
skill.

**`mirror`** — `.agents/` is a *copy* of `.claude/skills/` for Codex. Editing a mirrored skill means
syncing both. `*.local*` files are excluded from the comparison (secrets are not mirrored). A skill
present in `.claude/` but not `.agents/` is fine when it is Claude-only — confirm intent rather than
mirroring reflexively.

**`size`** — budget 2500 words (P3 over, P2 over 4000). Fix with progressive disclosure: keep
triggers, the decision table and the prime directive in `SKILL.md`; move per-source detail, incident
logs and long tables to `reference.md`.

**`spec`** — sources: Anthropic's Agent Skills best-practices page (name ≤ 64 chars, `[a-z0-9-]`, no
`anthropic`/`claude`; description non-empty, ≤ 1024 chars, no XML tags, third person, says what
**and** when; body < 500 lines) and the Claude Code skills reference (the supported key list —
`SKILL_KEYS` in the script; commands take the same keys except `name` and `paths`; description +
`when_to_use` truncated at 1536 in the listing). When Anthropic adds a key, add it to `SKILL_KEYS` —
otherwise every use of it is a false P2.

**`ports`** — source of truth is host-port bindings in the compose files (`"127.0.0.1:8080:80"`,
`"8080:80"`). Never reconcile the ports doc against another doc. `gen_ports.py` writes a generated
block between `<!-- BEGIN GENERATED: app-ports -->` markers; prose outside stays hand-written.

**`counts`** — prefer deleting a number to updating it: a doc that says "see the inventory file"
cannot go stale.

**`hooks`** — the same hook registered in both global `~/.claude/settings.json` and project
`.claude/settings*.json` fires **twice** per event. Debounce inside the script does not make the
duplicate registration correct; delete one.

## Design rules for this skill

1. **Mechanical checks live in `doctor.py`, never in prose.** Every number in `SKILL.md` or here is
   either computed by the script or a stable threshold.
2. **Historical files are exempt, not stale.**
3. **The doctor never writes.** Read-only by construction. Repairs are a separate, deliberate step;
   deletions are ask-first. (`gen_ports.py` writes one generated block, atomically.)
4. **A caveat beats a rewrite.** For a stale table, one accurate sentence above it is cheaper, safer
   and more durable than editing every row.
5. **Re-measure after repair.** Quote the new output.
6. **Verify the verifier.** A check that reports zero must first be shown to catch a planted positive.

## Lessons learned building the checker

**A checker's first output is a draft.** The first run on a real, drifted tooling layer produced
dozens of P1s, and three whole classes were false positives:

1. `secrets` flagged `settings.local.json` on filename alone → now name **and** body must match.
2. The `retired` caveat vocabulary missed "disabled", and the caveat was tested only on the matching
   line, so a `### Disabled` heading did not clear the bullets under it → wider vocabulary, ±3-line
   window, nearest-heading rule.
3. `frontmatter` reported a 2-character description for a skill using a YAML folded scalar
   (`description: >-`) → block scalars are parsed.

Also: `paths` did not resolve a path relative to the citing file, so every skill that referenced its
own `scripts/` was a false positive.

**…and a clean report can be a false negative.** A later run opened at P0=0 P1=0, which was wrong.
Three bugs were hiding real findings:

1. **`retired` judged files, not mentions.** One caveated mention cleared the entity for the whole
   file, so a rules file could say "X was removed" on one line and list three archived apps as live,
   with live ports, a few lines up. Now every mention is judged on its own, and only a **governing
   caveat** (entity name + retirement word within 60 characters on one line) clears a whole file.
2. **The root `CLAUDE.md` / `AGENTS.md` were never swept** — the two most-loaded instruction files.
3. **Short app aliases were never derived** — docs write the short name, not the archive dir name.

Fixing those three took `retired` from a reported 0 to dozens of real findings.

**Dead-looking overrides can be load-bearing.** An override that names no skill in
`.claude/skills/` may be the only thing keeping a user-global skill or command off. Deleting it
switches that skill back ON. Before removing any `overrides` hit, check user-global skills,
commands and parking lots, and *back up settings before editing them*.

**A retired row must name the dead thing, not the category.** If only a service's *container* was
removed but the service itself still runs elsewhere (say, on the host), a row matching the service
name fires on every rule that correctly describes the new install. Match the container name instead.

**Verify a new check with controls.** For the `spec` check:
- positive control: a planted skill with an uppercase/underscore name containing "claude", an
  `args:` key, a first-person description with an XML tag and no when-cue, and a 520-line body must
  fire all six rules; a planted command with a 1,100+ char description and a `name:` key must fire
  both; a skill with description + `when_to_use` > 1536 chars must fire the listing rule;
- negative control: a compliant skill (`argument-hint`, `disable-model-invocation`) and a compliant
  command (`argument-hint`, `allowed-tools`) must produce nothing.

For `retired`: plant an un-caveated mention of a retired entity (must fire) and a caveated one (must
not). Run both after touching any check.
