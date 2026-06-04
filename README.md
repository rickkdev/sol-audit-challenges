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
