# sol-audit-challenges

A benchmark harness for evaluating AI security tools against historical Web3
codebases that were vulnerable at a specific point in time.

The core rule is separation:

- Public challenge packages contain only anonymized source snapshots and build
  instructions.
- Private oracle data contains the original repository, vulnerable commit,
  fixed commit, vulnerability class, accepted finding criteria, and regression
  tests.
- Evaluated agents should receive no incident names, audit reports, exploit
  writeups, Git history, remotes, or internet access.

See [docs/benchmark-design.md](docs/benchmark-design.md) for the initial design.

## Implementation Direction

The first implementation should be a Python 3.12 CLI:

- Typer for CLI commands.
- Pydantic/jsonschema for manifest and oracle validation.
- pytest for tests.
- Docker integration for network-disabled benchmark runs.

Python is the best fit for the first phase because most work is repository
export, filesystem sanitization, archive generation, subprocess orchestration,
schema validation, and isolated runner control. A TypeScript or Next.js UI can
be added later on top of the same manifests if needed.

## Ralph

This repo is initialized for Ralph. The user stories live in [prd.json](prd.json).

```bash
ralph run
```
