# sol-audit-challenges

`sol-audit-challenges` is a Python CLI for building a schema-driven benchmark
harness around sanitized historical Web3 source snapshots. The project packages
public challenge bundles, runs tools against them without oracle leakage, and
scores submitted findings against private records.

## Requirements

- Python 3.12 or newer
- `pip`

## Install Locally

Create a virtual environment and install the CLI with development dependencies:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If your local `python3` already points to Python 3.12 or newer, it can be used
in place of `python3.12`.

## Run The CLI

```bash
sol-audit-challenges --help
sol-audit-challenges version
sol-audit-challenges validate-public examples/challenge-manifest/case-0000.public.json
sol-audit-challenges validate-private path/to/case-0000.private.json
```

During development, the module can also be run directly after installation:

```bash
python -m sol_audit_challenges.cli --help
```

## Run Tests

```bash
python -m pytest
```

## Repository Layout

- `src/sol_audit_challenges/` - CLI package
- `tests/` - pytest suite
- `schemas/` - JSON schemas for public manifests and private oracle records
- `examples/` - fake public examples safe to commit
- `docs/` - benchmark design and operator documentation
