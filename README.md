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
sol-audit-challenges prepare-case --repo path/to/repo --commit abcdef1 --case-id case-0001 --output-dir work/cases
sol-audit-challenges sanitize-case --source-dir work/cases/public/case-0001/source --output-dir work/sanitized/case-0001/source --config sanitize.json
sol-audit-challenges bundle-case --source-dir work/sanitized/case-0001/source --case-id case-0001 --output-dir work/public
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

## Preparing Cases

`prepare-case` exports the requested Git commit into
`<output-dir>/public/<case-id>/source` using `git archive`, which omits Git
history and repository metadata from the snapshot. It also writes a draft
private oracle to `<output-dir>/private/<case-id>.private.json`; keep that
private directory out of public challenge bundles.

## Sanitizing Cases

`sanitize-case` copies a prepared source snapshot to a sanitized output
directory, removes default clue-bearing paths such as README files, docs,
audits, deployments, `broadcast`, `cache`, `out`, and exploit or proof-of-
concept artifacts, then applies optional string replacements.

The optional config file is JSON:

```json
{
  "remove": ["research-notes/**"],
  "replace": [
    {
      "label": "protocol_name",
      "find": "RealProtocol",
      "replace": "ExampleProtocol"
    }
  ]
}
```

The sanitizer report lists removed paths and replacement labels/counts, but it
does not print the sensitive `find` strings from the config.

## Bundling Cases

`bundle-case` packages a sanitized source snapshot as a deterministic
`tar.gz` archive under `<output-dir>/bundles/<case-id>.tar.gz` and writes a
public manifest at `<output-dir>/<case-id>.public.json`. Re-running the command
with unchanged inputs produces the same archive checksum.

The archive contains the snapshot under a `source/` prefix and excludes private
oracle files, local research notes, `.git` metadata, generated reports, and run
outputs. Pass `--manifest path/to/case-0001.public.json` to update an existing
public manifest while preserving fields such as `prompt` and `build`.
