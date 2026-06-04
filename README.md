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
sol-audit-challenges validate-report examples/submitted-reports/case-0000.report.json
sol-audit-challenges prepare-case --repo path/to/repo --commit abcdef1 --case-id case-0001 --output-dir work/cases
sol-audit-challenges sanitize-case --source-dir work/cases/public/case-0001/source --output-dir work/sanitized/case-0001/source --config sanitize.json
sol-audit-challenges bundle-case --source-dir work/sanitized/case-0001/source --case-id case-0001 --output-dir work/public
sol-audit-challenges audit-leakage --target work/public/bundles/case-0001.tar.gz --denylist research/local/case-0001.denylist.json --output work/reports/case-0001.leakage.json
sol-audit-challenges run-case --bundle work/public/bundles/case-0001.tar.gz --manifest work/public/case-0001.public.json --command "python -m tool_under_test source" --output-dir work/reports
sol-audit-challenges score-report --report work/reports/case-0001.report.json --oracle work/private/case-0001.private.json --output work/reports/case-0001.score.json
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
- `templates/` - safe templates to copy into ignored private curator paths
- `docs/` - benchmark design and operator documentation

## Private Candidate Research

Real candidate incidents, source references, vulnerable commits, and oracle
records are private maintainer data. Keep them in ignored paths such as
`research/local/` and `ground-truth/`, or in a separate private curator
repository. Start from the templates in `templates/` and copy them into ignored
paths before adding real data.

See `docs/private-research-workflow.md` for the required candidate intake,
verification, sanitization, and publishing checklist.

## Submitted Finding Reports

Tool outputs are submitted as JSON reports validated by
`schemas/submitted-report.schema.json`. A report names the case id and includes
one or more findings. Each finding must include a title, affected files, root
cause, impact, and proof sketch; reproduction steps are optional.

```bash
sol-audit-challenges validate-report examples/submitted-reports/case-0000.report.json
```

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

## Auditing Leakage

`audit-leakage` scans a source snapshot directory, single file, or tar archive
for answer clues before publishing. It detects `.git` metadata paths,
repository URLs, 40-character commit hashes, audit/incident/exploit filenames,
incident keywords, Ethereum addresses, and transaction hashes. The command
writes a machine-readable JSON report and prints a short human-readable summary.

Pass `--denylist` with a private JSON file for case-specific protocol names,
incident names, repository names, addresses, or other terms:

```json
{
  "terms": [
    {
      "label": "protocol_name",
      "value": "RealProtocol"
    }
  ]
}
```

Private denylist files should stay in ignored locations such as
`research/local/` and may use the ignored `*.denylist.json` suffix.

```bash
sol-audit-challenges audit-leakage \
  --target work/public/bundles/case-0001.tar.gz \
  --denylist research/local/case-0001.denylist.json \
  --output work/reports/case-0001.leakage.json
```

## Running Cases

`run-case` verifies the bundle checksum from the public manifest, extracts the
archive into a temporary workspace, copies only the public manifest into that
workspace as `public-manifest.json`, and runs the configured tool command from
there. Run metadata, stdout, and stderr are written under
`<output-dir>/runs/<case-id>/<run-id>/`; the extracted source snapshot is not
used as the persistent output location.

Local mode is the default:

```bash
sol-audit-challenges run-case \
  --bundle work/public/bundles/case-0001.tar.gz \
  --manifest work/public/case-0001.public.json \
  --command "python -m tool_under_test source" \
  --output-dir work/reports
```

Local mode is a documented fallback for machines without Docker. It limits the
workspace contents to the public source and public manifest, but it does not
enforce an operating-system network namespace. Docker mode runs with
`--network none` and mounts the public workspace read-only:

```bash
sol-audit-challenges run-case \
  --bundle work/public/bundles/case-0001.tar.gz \
  --manifest work/public/case-0001.public.json \
  --command "python -m tool_under_test source" \
  --output-dir work/reports \
  --mode docker \
  --docker-image python:3.12-slim
```

## Scoring Reports

`score-report` compares a submitted finding report to a private oracle with
deterministic location and keyword matching. Results are written as JSON with
one status per submitted finding: `accepted`, `partial`, `duplicate`,
`false_positive`, or `out_of_scope`.

```bash
sol-audit-challenges score-report \
  --report work/reports/case-0001.report.json \
  --oracle work/private/case-0001.private.json \
  --output work/reports/case-0001.score.json
```

The score output is intended for maintainers. It includes status explanations
and matching signals, but it does not print private oracle origin links,
sources, or raw accepted-finding text by default.
