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
