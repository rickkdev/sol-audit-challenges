# Ralph Agent Instructions

## Overview

Ralph is an autonomous AI agent loop that runs AI coding tools repeatedly until all PRD items are complete. Each iteration is a fresh instance with clean context.

## Commands

```bash
# Run Ralph with Claude Code
ralph run

# Run Ralph with Codex
ralph run --tool codex

# Run Ralph with a larger iteration cap
ralph run --max 20
```

## Key Files

- `prompt.md` - Instructions given to each AMP instance
- `CLAUDE.md` - Instructions given to each Claude Code instance
- `CODEX.md` - Instructions given to each Codex instance
- `prd.json` - Project PRD and ordered user stories consumed by Ralph

## Patterns

- Each iteration spawns a fresh AI instance with clean context
- Memory persists via git history, `progress.txt`, and `prd.json`
- Stories should be small enough to complete in one context window
- Always update AGENTS.md with discovered patterns for future iterations
- Project CLI code uses a Python `src/sol_audit_challenges/` package layout and exposes the `sol-audit-challenges` console script from `pyproject.toml`
- Keep the Typer root callback in `src/sol_audit_challenges/cli.py`; it prevents the app from collapsing into a single command and preserves subcommand behavior
- Keep JSON schema validation helpers in `src/sol_audit_challenges/validation.py`; CLI validation errors should include the input file path and the failing schema location.
- `prepare-case` writes public snapshots under `<output-dir>/public/<case-id>/source` and draft private oracles under `<output-dir>/private/`; keep this separation when adding bundle, run, or scoring commands.
- Keep sanitization helpers in `src/sol_audit_challenges/sanitize.py`; sanitizer reports may include replacement labels/counts but must not print sensitive replacement `find` strings from private config.
- Keep bundling helpers in `src/sol_audit_challenges/bundle.py`; `bundle-case` writes deterministic public archives at `<output-dir>/bundles/<case-id>.tar.gz`, stores files with a `source/` prefix, and updates public manifests with relative package paths and SHA-256 checksums.
- Keep runner helpers in `src/sol_audit_challenges/run.py`; `run-case` should verify manifest checksums, extract only `source/` plus `public-manifest.json` into an ephemeral workspace, and write persistent metadata/stdout/stderr under `<output-dir>/runs/<case-id>/<run-id>/`.
- Keep submitted finding report validation in `schemas/submitted-report.schema.json` plus the `validate-report` CLI command; public examples under `examples/submitted-reports/` must contain fake data only.
- Keep deterministic scoring helpers in `src/sol_audit_challenges/score.py`; `score-report` outputs maintainer-facing statuses and signals without printing raw private oracle origin/sources or accepted-finding text by default.
- Keep real candidate research and oracle data out of committed paths; use `templates/` as safe placeholders and copy them into ignored `research/local/` or `ground-truth/` paths before adding real incident names, repositories, commits, addresses, or sources.
