# Benchmark Design

## Objective

Build a benchmark that can answer one question: given only a vulnerable Web3
code snapshot, can an AI security tool identify a real vulnerability that was
present at that point in the project history?

The benchmark must support two sources of cases:

- Historical incidents: exploited protocols, compiler bugs, bridge/router
  failures, oracle issues, access-control failures, and frontend-adjacent
  contract integration bugs.
- Audit findings: prominent audited codebases where public reports describe
  issues that were present at a specific audited commit.

## Threat Model

The evaluated agent may try to use context that is not in the codebase:

- Search the web for incident names, contract addresses, postmortems, or audit
  reports.
- Inspect `.git` history to compare vulnerable and fixed versions.
- Read branch names, tags, remotes, package metadata, deployment addresses, or
  comments that reveal the incident.
- Use vendored PoCs, tests, transaction hashes, or exploit scripts as hints.
- Infer the answer from benchmark file names or public manifest metadata.

The benchmark package must therefore be treated like an exam paper: it should
contain only what the evaluated tool is allowed to inspect.

## Public Challenge Package

Each challenge should be distributed as an archive or container image with:

- An anonymized project id, for example `case-0007`.
- Source files checked out at the vulnerable revision.
- Build and test dependencies pinned enough for local analysis.
- A normalized task prompt, for example `Find security issues in this codebase`.
- Optional harmless smoke tests that validate the project can compile.

Each challenge must exclude:

- `.git`, remotes, branches, tags, and commit metadata.
- Incident names, protocol names, exploited addresses, and transaction hashes
  unless they are required for the code to build.
- Audit reports, postmortems, proof-of-concept tests, and exploit scripts.
- Fix commits or patched files.
- Any public manifest field that maps the case to a known incident.

## Private Oracle

Private oracle records are not committed to this repository. They should include:

- Original repository URL.
- Vulnerable commit.
- Optional fixed commit or patch commit.
- Snapshot build command.
- Vulnerability class and severity.
- Human-readable accepted finding criteria.
- Ground-truth files/functions/lines.
- Optional executable reproduction or regression test.
- Source references used to justify the case.

The oracle is only used by the evaluator after a candidate report is submitted.

## Evaluation Flow

1. Curator verifies a case from public sources and repository history.
2. Curator creates a clean source snapshot at the vulnerable commit.
3. Sanitizer removes Git metadata and obvious incident identifiers.
4. Builder creates a challenge archive or container.
5. Evaluated tool runs in a network-disabled environment against the archive.
6. Tool submits a structured vulnerability report.
7. Evaluator scores the report against the private oracle.

## Scoring

A finding should be accepted when it identifies the same root cause, affected
code path, and plausible exploit impact as the oracle. It should not require the
agent to reproduce the exact historical transaction unless the challenge is
explicitly exploit-synthesis focused.

Suggested statuses:

- `accepted`: same root cause and exploitable impact.
- `partial`: same area but incomplete exploitability or impact.
- `duplicate`: same accepted issue already submitted.
- `false_positive`: not exploitable or not the historical issue.
- `out_of_scope`: depends on infrastructure, keys, governance, or external state
  excluded from the challenge.

## Case Selection Rules

Prefer cases that have:

- Public source code at or before the vulnerable point.
- A reproducible checkout or verified source artifact.
- A root cause located in code, configuration, compiler, or dependency behavior.
- A credible source trail from postmortem, audit report, incident analysis, or
  fix diff.
- A way to validate submitted findings without revealing the answer.

Avoid or mark as low priority:

- Private-key compromises, phishing, social engineering, or pure OPSEC failures.
- Closed-source contracts unless verified source can be reconstructed.
- Cases where the only signal is an on-chain bytecode dump and no maintainable
  source package exists.
- Cases where naming the dependency version immediately gives away the answer,
  unless dependency metadata can be anonymized without breaking analysis.

## Repository Policy

This public repository should contain tooling, schemas, and design docs only.
Concrete incident-to-case mappings belong in ignored private files under
`ground-truth/` or external private storage.
