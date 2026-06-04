# Operating Model And Security Boundaries

This document is the operator runbook for creating, publishing, running, and
scoring benchmark cases without leaking private ground truth. It describes which
data belongs in each workspace, how to run evaluated tools with oracle files
withheld, how to classify candidate quality, and what to review before a
challenge bundle is published.

## Repository And Artifact Boundaries

Use three separate trust zones:

- Public repository: CLI source, schemas, docs, fake fixtures, fake submitted
  reports, public manifests, and safe templates.
- Private curator storage: real candidate notes, source references, vulnerable
  commits, fixed commits, denylist terms, and private oracle records. This can
  be an ignored path in a local checkout, such as `research/local/` and
  `ground-truth/`, or a separate private repository.
- Generated public artifacts: sanitized source snapshots, public manifests,
  deterministic bundles, and public leakage reports that have passed review.

The evaluated tool receives only the generated public artifact. It must never
receive private candidate files, private oracle files, denylist files, local
research notes, source reference lists, or scoring outputs.

Recommended local layout:

```text
research/local/                 # ignored private candidate notes and denylists
ground-truth/                   # ignored private oracle records
work/prepared/private/          # draft private oracles from prepare-case
work/prepared/public/           # raw public snapshots before sanitization
work/sanitized/                 # sanitized source snapshots
work/public/                    # public manifests and bundles
work/reports/                   # run outputs, leakage reports, scoring outputs
```

Committed templates under `templates/` are placeholders only. Copy them into an
ignored private path before adding real repository URLs, commits, addresses,
transaction hashes, incident names, protocol names, or source references.

## Case Creation Flow

1. Record candidate details privately using
   `templates/private-candidate.template.json`.
2. Verify the vulnerable source revision and accepted finding criteria.
3. Export the source snapshot with `prepare-case`.
4. Sanitize clue-bearing files and strings with `sanitize-case`.
5. Build a deterministic public archive and manifest with `bundle-case`.
6. Audit the source snapshot and bundle with `audit-leakage`.
7. Run the candidate challenge against a smoke-test tool with `run-case`.
8. Validate public manifests, private oracles, and submitted reports with the
   schema validation commands.
9. Score submitted reports with `score-report` only after the tool run is
   complete.

Command references:

```bash
sol-audit-challenges prepare-case --repo path/to/repo --commit abcdef1 --case-id case-0001 --output-dir work/prepared
sol-audit-challenges sanitize-case --source-dir work/prepared/public/case-0001/source --output-dir work/sanitized/case-0001/source --config research/local/case-0001.sanitize.json
sol-audit-challenges bundle-case --source-dir work/sanitized/case-0001/source --case-id case-0001 --output-dir work/public
sol-audit-challenges audit-leakage --target work/public/bundles/case-0001.tar.gz --denylist research/local/case-0001.denylist.json --output work/reports/case-0001.leakage.json
sol-audit-challenges run-case --bundle work/public/bundles/case-0001.tar.gz --manifest work/public/case-0001.public.json --command "python -m tool_under_test source" --output-dir work/reports --mode docker --docker-image python:3.12-slim
sol-audit-challenges score-report --report work/reports/case-0001.report.json --oracle ground-truth/case-0001.private.json --output work/reports/case-0001.score.json
```

## Network Isolation And Oracle Withholding

Docker mode is the preferred evaluation mode. `run-case --mode docker` runs the
tool command with `--network none` and mounts the temporary public workspace
read-only. The workspace contains only:

- `source/`
- `public-manifest.json`

Local mode is available for machines without Docker, but it is only a fallback.
It constructs the same public-only workspace, but it does not enforce an
operating-system network namespace. Use local mode for development and smoke
tests, not for benchmark measurements that need strict no-network isolation.

Before running evaluated tools:

- Confirm the bundle checksum matches the public manifest.
- Confirm the command points at `source/` inside the runner workspace.
- Confirm private paths such as `ground-truth/`, `research/local/`, and
  sanitizer or denylist configs are not mounted into the tool environment.
- Confirm the tool has no access to source repository history, remotes, branch
  names, tags, postmortems, audit reports, or scoring outputs.

After running evaluated tools:

- Validate submitted JSON with `validate-report`.
- Score only from a maintainer-controlled environment that has access to the
  private oracle.
- Do not publish raw score output if it contains maintainer-only review notes.

## Case Quality Classes

High-quality cases are preferred for benchmark publication:

- The vulnerable source snapshot is reproducible from a known commit or verified
  source package.
- The root cause is visible from source, configuration, compiler behavior, or a
  pinned dependency.
- The accepted finding can be judged from files, symbols, root cause, impact,
  and proof sketch without web access.
- Sanitization can remove clue-bearing names, addresses, hashes, reports, and
  exploit artifacts without breaking meaningful analysis.
- The private oracle has enough detail for consistent maintainer review.

Low-quality cases should usually be rejected or kept out of headline metrics:

- Private-key compromise, phishing, governance capture, or pure operational
  failure.
- Closed-source targets where the vulnerable source cannot be reconstructed.
- Cases where the only evidence is on-chain bytecode with no maintainable
  source package.
- Vulnerabilities that require unavailable off-chain state, privileged keys, or
  hidden infrastructure behavior to evaluate.
- Cases where anonymization removes the information needed to analyze the issue.

Special-handling cases may be useful but should be labeled separately:

- Compiler bugs, optimizer bugs, or dependency-version flaws where the version
  itself is part of the signal.
- Cross-chain or oracle incidents that require external system assumptions.
- Build-system or deployment-configuration bugs where sanitization can easily
  remove required context.
- Multi-bug incidents where one historical event maps to several independent
  accepted findings.

## Publishing Review Checklist

Complete this checklist before distributing a challenge bundle:

- Public manifest validates with
  `sol-audit-challenges validate-public path/to/case.public.json`.
- Private oracle validates with
  `sol-audit-challenges validate-private ground-truth/case.private.json` from a
  private environment.
- Submitted report examples validate with
  `sol-audit-challenges validate-report path/to/report.json`.
- Bundle was created by `bundle-case`, has a stable SHA-256 checksum, and stores
  source files below the `source/` prefix.
- Source snapshot and bundle were scanned by `audit-leakage`.
- Any case-specific denylist file is private and stored under an ignored path.
- Public artifacts contain no `.git` directory, remotes, branches, tags, commit
  history, fix commits, audit reports, postmortems, exploit scripts, transaction
  hashes, real incident names, real protocol names, or research notes.
- Sanitizer reports do not expose replacement `find` strings from private
  config.
- `run-case` succeeds in Docker mode with `--network none`, or the reason for
  using local fallback is recorded.
- The evaluated tool workspace contains only `source/` and
  `public-manifest.json`.
- Scoring uses the private oracle only after a submitted report is produced.
- Public examples and committed fixtures contain fake data only.

## Schemas

Schema files define the public and private data contracts:

- `schemas/public-challenge.schema.json` for public challenge manifests.
- `schemas/private-oracle.schema.json` for private oracle records.
- `schemas/submitted-report.schema.json` for submitted finding reports.

The schemas are intentionally separate because public manifests are part of the
benchmark surface, private oracles are maintainer-only ground truth, and
submitted reports are the only structured output expected from evaluated tools.
