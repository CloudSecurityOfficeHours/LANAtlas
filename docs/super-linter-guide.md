# LAN Atlas Repo Overview & Super-Linter Guide (Rough Draft)

> **Who this is for:** you've taken a class or two involving Git/GitHub and
> maybe some SQL or Python, but you haven't worked with this specific repo's
> CI setup before. This doc explains what's here today and what makes the
> "Lint Code Base" GitHub Action pass or fail.

## 1. What is this repo, right now?

LAN Atlas is planned as a small SaaS product: an on-prem "agent" scans a
local network, and a cloud service turns those scans into dashboards and
alerts. That's the long-term vision described in the [README](../README.md).

**Important:** as of this writing, the repo does not contain the actual
application code yet (no `app/` folder, no Python source files). What
exists today is the *planning and scaffolding* layer:

| Path | What it is |
|---|---|
| `README.md` | Project pitch and functional/non-functional requirements |
| `structure.txt` | A sketch of the planned folder layout once the app exists (`lan-atlas/app/models/...`) — this is a plan, not real code yet |
| `dbschema.sql` | The actual SQL schema for the database (SQLite dialect), already written and real |
| `docs/contributor-setup.md` | How a new contributor sets up Python, a virtualenv, and a local `.env` file |
| `docs/requirements.txt` / `docs/requirements-dev.txt` | Python dependency lists for when the app code lands |
| `.env.example` | Template of environment variables (never put real secrets in this file) |
| `.devcontainer/devcontainer.json` | Config so the repo can open in a pre-built Codespace/dev container |
| `.github/workflows/super-linter.yml` | The CI workflow that lints everything on each pull request |
| `.github/linters/` | Linter-specific config files that Super-Linter reads |

So when this doc says "make tests pass," it currently means **make the
Super-Linter GitHub Action pass** — there is no pytest suite running in CI
yet. Once real Python code and tests are added, a separate `pytest`
workflow would need to be added; this guide only covers the linter.

## 2. What is Super-Linter, in plain terms?

[Super-Linter](https://github.com/github/super-linter) is a single GitHub
Action that bundles together *dozens* of linters (one per language/file
type: Python, SQL, YAML, Markdown, JSON, shell, Dockerfile, etc.) and runs
whichever ones match the files in your repo. You don't install each linter
yourself — Super-Linter detects file types and runs the matching tools
inside one Docker container.

Think of it like a strict TA who checks your code style and catches typos
automatically before a human reviewer ever looks at your PR.

## 3. How is it wired up in this repo?

Look at `.github/workflows/super-linter.yml`:

```yaml
on:
  pull_request:
    branches: ["main", "super-linter-actions"]
  workflow_dispatch: null
```

This means the linter runs automatically whenever a pull request targets
`main` or `super-linter-actions`. You can also trigger it manually from
the "Actions" tab (`workflow_dispatch`).

Key settings to know:

- `VALIDATE_ALL_CODEBASE: true` — Super-Linter checks **every file in the
  repo**, not just the files your PR changed. This is stricter than the
  default (which only lints changed files), so a pre-existing style issue
  anywhere in the repo can fail *your* PR even if you didn't touch that
  file.
- `VALIDATE_JSON_PRETTIER: false`, `VALIDATE_MARKDOWN_PRETTIER: false`,
  `VALIDATE_YAML_PRETTIER: false` — these three turn off *only* the
  Prettier-based formatting checks for JSON/Markdown/YAML. The
  non-Prettier linters for those file types (like `yamllint` and
  `markdownlint`) are still active, since they aren't disabled here.
- `SAVE_SUPER_LINTER_OUTPUT` / `SUPER_LINTER_OUTPUT_DIRECTORY_NAME` — saves
  a report as a workflow artifact so you can download exactly what failed
  instead of scrolling through the raw log.
- `ENABLE_GITHUB_ACTIONS_STEP_SUMMARY: true` — writes a human-readable
  summary at the bottom of the Action run in GitHub's UI.

## 4. Which linters actually touch files in this repo today?

Based on what currently exists in the repo:

- **`dbschema.sql`** → checked by `sqlfluff`, configured for the `sqlite`
  dialect via `.github/linters/.sqlfluff` (and a duplicate copy at
  `docs/.sqlfluff` — see the note in section 6).
- **`README.md`, `docs/contributor-setup.md`, this file** → checked by
  `markdownlint` (Prettier's Markdown formatter is off, but markdownlint's
  rules — heading structure, trailing whitespace, etc. — still apply).
- **`super-linter.yml`, `.sqlfluff` files** → checked by `yamllint` (YAML
  syntax and style, e.g. no trailing whitespace, consistent indentation).
- **`.devcontainer/devcontainer.json`** → checked by a JSON validator/linter.
- **`.env.example`** → checked by a dotenv linter (it flags obviously bad
  syntax, not whether your secrets are real).
- Every text file is also scanned for accidentally committed secrets
  (things that look like API keys, AWS credentials, private keys, etc.).

There is currently no Python source code, so `ruff`/`mypy`/`pylint` (listed
as dev dependencies for the *future* app) aren't actually exercising
anything yet — they'll start mattering once `app/` exists.

## 5. Step-by-step: getting a PR to pass Super-Linter

1. **Make your change** as usual (edit SQL, docs, workflow files, etc.).
2. **Check for trailing whitespace and consistent indentation** before you
   commit — these are the single most common yamllint/markdownlint
   failures. Most editors have a "trim trailing whitespace on save"
   setting; turn it on for this repo.
3. **If you touch `dbschema.sql`**, keep the SQLite dialect in mind: no
   `ENUM` types, no `ON UPDATE CURRENT_TIMESTAMP`. Run `sqlfluff` locally
   if you have it installed:
   ```bash
   pip install sqlfluff
   sqlfluff lint dbschema.sql --dialect sqlite
   ```
4. **If you touch a Markdown file**, keep one blank line around headings
   and code fences, and don't leave trailing spaces at line ends (two
   trailing spaces is a Markdown "hard break" and is usually intentional —
   anything else gets flagged).
5. **Open your PR against `main` or `super-linter-actions`** (per the
   `on:` trigger above — a PR against any other base branch won't run this
   workflow at all).
6. **Watch the "Lint Code Base" check** on the PR. If it fails, open the
   run, download the `super-linter-report` artifact (or read the Step
   Summary GitHub renders inline) to see exactly which linter and which
   line failed.
7. **Because `VALIDATE_ALL_CODEBASE` is `true`**, remember a failure might
   point at a file you never touched. Fix it anyway (or flag it to a
   maintainer) — you can't merge past a failing required check just
   because "it wasn't my file."
8. Push your fix; the workflow re-runs automatically on new commits to the
   same PR.

## 6. Known rough edges worth knowing about

- **Duplicate `.sqlfluff` configs**: both `.github/linters/.sqlfluff` and
  `docs/.sqlfluff` exist with the same `dialect = sqlite` content. Having
  two copies means they can silently drift out of sync if someone updates
  one and not the other — worth consolidating to a single source of truth
  later.
- **`super-linter.yml` currently has a trailing-whitespace line** right
  after `statuses: write` (a line that's just spaces, no visible text).
  This is exactly the kind of thing `yamllint` flags — if you see the
  workflow file itself fail lint, this is a likely first place to check.
- **No test workflow yet**: "all tests pass" today effectively means "the
  linter passes," since there's no `pytest` CI job. Once the FastAPI app
  in `structure.txt` becomes real code, a companion workflow (e.g.
  `.github/workflows/tests.yml`) will need to run `pytest` using
  `docs/requirements-dev.txt`.
- **Two requirements files with different pinned versions**
  (`docs/requirements.txt` vs `docs/requirements-dev.txt`) list slightly
  different versions of the same packages (e.g. `pydantic`, `fastapi`).
  Once real code depends on these, mismatched versions between the two
  files could cause confusing "works on my machine" bugs — worth
  reconciling into one file (or a clear prod/dev split with matching
  pins) before that becomes a real problem.

## 7. Running Super-Linter locally (optional, but saves round-trips)

You can run the exact same container GitHub Actions uses, locally, with
Docker:

```bash
docker run --rm \
  -e VALIDATE_ALL_CODEBASE=true \
  -e DEFAULT_BRANCH=main \
  -e RUN_LOCAL=true \
  -v "$(pwd)":/tmp/lint \
  ghcr.io/github/super-linter:v7
```

This lets you catch failures before pushing, instead of waiting for the
Action to run in GitHub's UI.
